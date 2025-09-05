//! UDP and TCP server implementations for DNS

use std::collections::VecDeque;
use std::io::Write;
use std::net::SocketAddr;
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::Builder;

use derive_more::{Display, Error, From};
use rand::random;
extern crate sentry;

use crate::dns::buffer::{BytePacketBuffer, PacketBuffer, StreamPacketBuffer, VectorPacketBuffer};
use crate::dns::context::ServerContext;
use crate::dns::netutil::{read_packet_length, write_packet_length};
use crate::dns::protocol::{DnsPacket, DnsRecord, DnsQuestion, QueryType, ResultCode};
use crate::dns::resolve::DnsResolver;
use crate::dns::logging::{CorrelationContext, DnsQueryLog};
use crate::dns::security::SecurityAction;
use crate::dns::dnssec::DnssecSigner;
use crate::dns::metrics::{THREAD_POOL_THREADS, THREAD_POOL_QUEUE_SIZE, THREAD_POOL_TASKS, THREAD_POOL_UTILIZATION};

#[derive(Debug, Display, From, Error)]
pub enum ServerError {
    Io(std::io::Error),
}

type Result<T> = std::result::Result<T, ServerError>;

macro_rules! return_or_report {
    ( $x:expr, $message:expr ) => {
        match $x {
            Ok(res) => res,
            Err(e) => {
                log::info!($message);
                // Report DNS server error to Sentry
                sentry::configure_scope(|scope| {
                    scope.set_tag("component", "dns_server");
                    scope.set_tag("operation", "server_operation");
                    scope.set_extra("error_details", format!("{:?}", e).into());
                });
                sentry::capture_message(&format!("DNS Server: {}", $message), sentry::Level::Warning);
                return;
            }
        }
    };
}

macro_rules! ignore_or_report {
    ( $x:expr, $message:expr ) => {
        match $x {
            Ok(_) => {}
            Err(e) => {
                log::info!($message);
                // Report DNS server error to Sentry
                sentry::configure_scope(|scope| {
                    scope.set_tag("component", "dns_server");
                    scope.set_tag("operation", "server_operation");
                    scope.set_extra("error_details", format!("{:?}", e).into());
                });
                sentry::capture_message(&format!("DNS Server: {}", $message), sentry::Level::Info);
                return;
            }
        };
    };
}

/// Common trait for DNS servers
pub trait DnsServer {
    /// Initialize the server and start listenening
    ///
    /// This method should _NOT_ block. Rather, servers are expected to spawn a new
    /// thread to handle requests and return immediately.
    fn run_server(self) -> Result<()>;
}

/// Utility function for resolving domains referenced in for example CNAME or SRV
/// records. This usually spares the client from having to perform additional
/// lookups.
fn resolve_cnames(
    lookup_list: &[DnsRecord],
    results: &mut Vec<DnsPacket>,
    resolver: &mut Box<dyn DnsResolver>,
    depth: u16,
) {
    if depth > 10 {
        return;
    }

    for rec in lookup_list {
        match *rec {
            DnsRecord::Cname { ref host, .. } | DnsRecord::Srv { ref host, .. } => {
                if let Ok(result2) = resolver.resolve(host, QueryType::A, true) {
                    let new_unmatched = result2.get_unresolved_cnames();
                    results.push(result2.clone());
                    log::info!("{:?}", result2);
                    resolve_cnames(&new_unmatched, results, resolver, depth + 1);
                }
            }
            _ => {

                log::info!("NO_CNAME_MATCH");

            }
        }
    }
}

/// Perform the actual work for a query
///
/// Incoming requests are validated to make sure they are well formed and adhere
/// to the server configuration. If so, the request will be passed on to the
/// active resolver and a query will be performed. It will also resolve some
/// possible references within the query, such as CNAME hosts.
///
/// Build the initial response packet with common headers
fn build_response_packet(context: &Arc<ServerContext>, request: &DnsPacket) -> DnsPacket {
    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_available = context.allow_recursive;
    packet.header.response = true;
    packet
}

/// Validate the request and return appropriate error code if invalid
fn validate_request(
    context: &Arc<ServerContext>,
    request: &DnsPacket,
) -> Option<ResultCode> {
    if request.header.recursion_desired && !context.allow_recursive {
        log::info!("REFUSED");
        Some(ResultCode::REFUSED)
    } else if request.questions.is_empty() {
        log::info!("FORMERR");
        Some(ResultCode::FORMERR)
    } else {
        None
    }
}

/// Process a valid query and populate the response packet
fn process_valid_query(
    context: Arc<ServerContext>,
    request: &DnsPacket,
    packet: &mut DnsPacket,
) {
    let mut results = Vec::new();
    let question = &request.questions[0];
    packet.questions.push(question.clone());

    log::info!("question.qtype: {:?}", question.qtype);

    let mut resolver = context.create_resolver(context.clone());
    let rescode = resolve_question(
        &mut resolver,
        question,
        request.header.recursion_desired,
        &mut results,
    );

    packet.header.rescode = rescode;
    populate_packet_from_results(packet, results.clone());
    
    // Log the DNS query for storage and display
    store_dns_query_log(&context, question, rescode, &results);
}

/// Resolve a DNS question and handle CNAME resolution
fn resolve_question(
    resolver: &mut Box<dyn DnsResolver>,
    question: &DnsQuestion,
    recursion_desired: bool,
    results: &mut Vec<DnsPacket>,
) -> ResultCode {
    match resolver.resolve(&question.name, question.qtype, recursion_desired) {
        Ok(result) => {
            let rescode = result.header.rescode;
            let unmatched = result.get_unresolved_cnames();
            results.push(result);
            
            resolve_cnames(&unmatched, results, resolver, 0);
            log::info!("resolve_cnames");
            rescode
        }
        Err(err) => {
            log::info!(
                "Failed to resolve {:?} {}: {:?}",
                question.qtype, question.name, err
            );
            ResultCode::SERVFAIL
        }
    }
}

/// Populate the response packet with results from resolution
fn populate_packet_from_results(packet: &mut DnsPacket, results: Vec<DnsPacket>) {
    for result in results {
        packet.answers.extend(result.answers);
        packet.authorities.extend(result.authorities);
        packet.resources.extend(result.resources);
    }
}

/// Validate DNSSEC signatures in a response packet
fn validate_dnssec(context: &Arc<ServerContext>, packet: &DnsPacket) -> std::result::Result<bool, Box<dyn std::error::Error>> {
    // Check if the response contains DNSSEC records
    let has_dnssec = packet.answers.iter().any(|r| matches!(r, 
        DnsRecord::Rrsig { .. } | 
        DnsRecord::Dnskey { .. } |
        DnsRecord::Ds { .. }
    ));
    
    if !has_dnssec {
        return Ok(false); // No DNSSEC records to validate
    }
    
    // Create a DNSSEC signer for validation (reuse signing config)
    let signing_config = crate::dns::dnssec::SigningConfig::default();
    let signer = DnssecSigner::new(signing_config);
    
    // Validate the packet signatures
    signer.validate(packet)
}

/// This function will always return a valid packet, even if the request could not
/// be performed, since we still want to send something back to the client.
pub fn execute_query(context: Arc<ServerContext>, request: &DnsPacket) -> DnsPacket {
    execute_query_with_ip(context, request, None)
}

/// Execute query with client IP for security checks
pub fn execute_query_with_ip(context: Arc<ServerContext>, request: &DnsPacket, client_ip: Option<std::net::IpAddr>) -> DnsPacket {
    let start_time = std::time::Instant::now();
    
    // Create correlation context for this DNS query
    let mut ctx = CorrelationContext::new("dns_server", "execute_query");
    
    // Extract query information for logging
    let (domain, query_type, protocol) = if let Some(question) = request.questions.first() {
        (
            question.name.clone(),
            format!("{:?}", question.qtype),
            "UDP".to_string(), // Default to UDP, caller can specify
        )
    } else {
        ("unknown".to_string(), "UNKNOWN".to_string(), "UDP".to_string())
    };
    
    ctx = ctx.with_metadata("domain", &domain)
           .with_metadata("query_type", &query_type)
           .with_metadata("query_id", &request.header.id.to_string());

    // Add Sentry breadcrumb for DNS query processing
    sentry::add_breadcrumb(sentry::Breadcrumb {
        ty: "dns".to_string(),
        category: Some("dns.query.start".to_string()),
        message: Some(format!("Processing DNS query for {} ({})", domain, query_type)),
        level: sentry::Level::Info,
        timestamp: chrono::Utc::now(),
        data: {
            let mut map = std::collections::BTreeMap::new();
            map.insert("domain".to_string(), domain.clone().into());
            map.insert("query_type".to_string(), query_type.clone().into());
            map.insert("query_id".to_string(), request.header.id.into());
            if let Some(ip) = client_ip {
                map.insert("client_ip".to_string(), ip.to_string().into());
            }
            map
        },
        ..Default::default()
    });
    
    // Perform security checks first if client IP is available
    if let Some(ip) = client_ip {
        let security_result = context.security_manager.check_request(request, ip);
        
        if !security_result.allowed {
            let mut packet = build_response_packet(&context, request);
            
            // Set appropriate response code based on security action
            packet.header.rescode = match security_result.action {
                SecurityAction::BlockNxDomain => ResultCode::NXDOMAIN,
                SecurityAction::BlockRefused => ResultCode::REFUSED,
                SecurityAction::BlockServfail => ResultCode::SERVFAIL,
                SecurityAction::RateLimit => ResultCode::REFUSED,
                SecurityAction::Challenge => ResultCode::REFUSED,
                SecurityAction::Sinkhole(_) => ResultCode::NOERROR,
                _ => ResultCode::REFUSED,
            };
            
            // Report security block to Sentry
            sentry::configure_scope(|scope| {
                scope.set_tag("component", "dns_server");
                scope.set_tag("event_type", "security_block");
                scope.set_tag("security_action", &format!("{:?}", security_result.action));
                scope.set_tag("domain", &domain);
                scope.set_tag("query_type", &query_type);
                scope.set_extra("client_ip", ip.to_string().into());
                scope.set_extra("block_reason", format!("{:?}", security_result.reason).into());
            });
            sentry::capture_message(
                &format!("DNS Security Block: {} from {} ({})", domain, ip, format!("{:?}", security_result.reason)),
                sentry::Level::Warning
            );
            
            // Log security block
            let query_log = DnsQueryLog {
                domain: domain.clone(),
                query_type: query_type.clone(),
                protocol: protocol.clone(),
                response_code: format!("{:?}", packet.header.rescode),
                answer_count: 0,
                cache_hit: false,
                upstream_server: None,
                dnssec_status: None,
                timestamp: chrono::Utc::now(),
            };
            context.logger.log_dns_query(&ctx, query_log);
            
            // Record metrics
            context.metrics.record_dns_query(&protocol, &query_type, &domain);
            context.metrics.record_dns_response(
                &format!("{:?}", packet.header.rescode),
                &protocol,
                &query_type
            );
            
            log::info!("Security blocked query from {:?}: {:?}", ip, security_result.reason);
            
            // Add performance monitoring for security blocked queries
            let elapsed = start_time.elapsed();
            sentry::configure_scope(|scope| {
                scope.set_extra("query_duration_ms", (elapsed.as_millis() as u64).into());
            });
            
            return packet;
        }
    }
    
    let mut packet = build_response_packet(&context, request);
    let mut cache_hit = false;

    if let Some(error_code) = validate_request(&context, request) {
        packet.header.rescode = error_code;
        
        // Report validation error to Sentry
        sentry::configure_scope(|scope| {
            scope.set_tag("component", "dns_server");
            scope.set_tag("event_type", "validation_error");
            scope.set_tag("error_code", &format!("{:?}", error_code));
            scope.set_tag("domain", &domain);
            scope.set_tag("query_type", &query_type);
            if let Some(ip) = client_ip {
                scope.set_extra("client_ip", ip.to_string().into());
            }
        });
        sentry::capture_message(
            &format!("DNS Validation Error: {} - {} ({})", format!("{:?}", error_code), domain, query_type),
            sentry::Level::Warning
        );
        
        // Log error response
        let query_log = DnsQueryLog {
            domain: domain.clone(),
            query_type: query_type.clone(),
            protocol: protocol.clone(),
            response_code: format!("{:?}", error_code),
            answer_count: 0,
            cache_hit: false,
            upstream_server: None,
            dnssec_status: None,
            timestamp: chrono::Utc::now(),
        };
        context.logger.log_dns_query(&ctx, query_log);
    } else {
        // Check cache first
        if let Some(question) = request.questions.first() {
            if let Some(cached_packet) = context.cache.lookup(&question.name, question.qtype) {
                if !cached_packet.answers.is_empty() {
                    cache_hit = true;
                    packet.answers.extend(cached_packet.answers);
                    packet.header.rescode = ResultCode::NOERROR;
                    
                    // Update metrics
                    context.metrics.record_cache_operation("hit", &query_type);
                } else {
                    context.metrics.record_cache_operation("miss", &query_type);
                }
            } else {
                context.metrics.record_cache_operation("miss", &query_type);
            }
        }
        
        if !cache_hit {
            process_valid_query(context.clone(), request, &mut packet);
        }
        
        // Perform DNSSEC validation if requested
        let dnssec_status = if request.header.z && context.dnssec_enabled {
            match validate_dnssec(&context, &packet) {
                Ok(valid) => {
                    if valid {
                        packet.header.authed_data = true; // Set Authenticated Data flag
                        Some("validated".to_string())
                    } else {
                        Some("invalid".to_string())
                    }
                }
                Err(_) => Some("unvalidated".to_string())
            }
        } else {
            None
        };

        // Determine if upstream server was used based on resolution strategy
        let upstream_server = match &context.resolve_strategy {
            crate::dns::context::ResolveStrategy::Forward { host, port } => {
                if cache_hit {
                    None // Cache hit, no upstream used
                } else {
                    Some(format!("{}:{}", host, port))
                }
            }
            crate::dns::context::ResolveStrategy::Recursive => None, // Recursive resolution
        };

        // Log successful response
        let query_log = DnsQueryLog {
            domain: domain.clone(),
            query_type: query_type.clone(),
            protocol: protocol.clone(),
            response_code: format!("{:?}", packet.header.rescode),
            answer_count: packet.answers.len() as u16,
            cache_hit,
            upstream_server,
            dnssec_status,
            timestamp: chrono::Utc::now(),
        };
        context.logger.log_dns_query(&ctx, query_log);
    }
    
    // Record metrics
    context.metrics.record_dns_query(&protocol, &query_type, &domain);
    context.metrics.record_dns_response(
        &format!("{:?}", packet.header.rescode),
        &protocol,
        &query_type
    );
    context.metrics.record_query_duration(
        ctx.elapsed(),
        &protocol,
        &query_type,
        cache_hit
    );

    // Add performance monitoring to Sentry
    let elapsed = start_time.elapsed();
    sentry::configure_scope(|scope| {
        scope.set_tag("query_result", "success");
        scope.set_extra("query_duration_ms", (elapsed.as_millis() as u64).into());
        scope.set_extra("cache_hit", cache_hit.into());
        if elapsed.as_millis() > 100 {
            scope.set_tag("slow_query", "true");
        }
    });
    
    // Report slow queries as warnings
    if elapsed.as_millis() > 500 {
        sentry::capture_message(
            &format!("Slow DNS Query: {} took {}ms ({})", domain, elapsed.as_millis(), query_type),
            sentry::Level::Warning
        );
    }
    
    // Add success breadcrumb
    sentry::add_breadcrumb(sentry::Breadcrumb {
        ty: "dns".to_string(),
        category: Some("dns.query.complete".to_string()),
        message: Some(format!("DNS query completed: {} ({}ms)", domain, elapsed.as_millis())),
        level: sentry::Level::Info,
        timestamp: chrono::Utc::now(),
        data: {
            let mut map = std::collections::BTreeMap::new();
            map.insert("duration_ms".to_string(), (elapsed.as_millis() as u64).into());
            map.insert("cache_hit".to_string(), cache_hit.into());
            map
        },
        ..Default::default()
    });

    packet
}

/// The UDP server
///
/// Accepts DNS queries through UDP, and uses the `ServerContext` to determine
/// how to service the request. Packets are read on a single thread, after which
/// a new thread is spawned to service the request asynchronously.
pub struct DnsUdpServer {
    context: Arc<ServerContext>,
    request_queue: Arc<Mutex<VecDeque<(SocketAddr, DnsPacket)>>>,
    request_cond: Arc<Condvar>,
    thread_count: usize,
}

impl DnsUdpServer {
    pub fn new(context: Arc<ServerContext>, thread_count: usize) -> DnsUdpServer {
        DnsUdpServer {
            context,
            request_queue: Arc::new(Mutex::new(VecDeque::new())),
            request_cond: Arc::new(Condvar::new()),
            thread_count,
        }
    }
}

impl DnsUdpServer {
    /// Process a single DNS request and send the response
    fn process_request(
        socket: &UdpSocket,
        context: Arc<ServerContext>,
        src: std::net::SocketAddr,
        request: &DnsPacket,
    ) {
        let mut size_limit = 512;

        // Check for EDNS
        if request.resources.len() == 1 {
            if let DnsRecord::Opt { packet_len, .. } = request.resources[0] {
                size_limit = packet_len as usize;
            }
        }

        // Create a response buffer, and ask the context for an appropriate resolver
        let mut res_buffer = VectorPacketBuffer::new();

        log::info!("req: {:?}", request.clone());

        let mut packet = execute_query_with_ip(context, request, Some(src.ip()));
        let _ = packet.write(&mut res_buffer, size_limit);

        // Fire off the response
        let len = res_buffer.pos();
        let data = return_or_report!(
            res_buffer.get_range(0, len),
            "Failed to get buffer data"
        );
        ignore_or_report!(
            socket.send_to(data, src),
            "Failed to send response packet"
        );
    }

    /// Spawn a worker thread to handle DNS requests
    fn spawn_request_handler(
        &self,
        thread_id: usize,
        socket: UdpSocket,
    ) -> std::io::Result<()> {
        let context = self.context.clone();
        let request_cond = self.request_cond.clone();
        let request_queue = self.request_queue.clone();

        let name = format!("DnsUdpServer-request-{}", thread_id);
        log::info!("DnsUdpServer-request");
        
        Builder::new().name(name).spawn(move || {
            loop {
                // Acquire lock, and wait on the condition until data is available
                let (src, request) = match request_queue
                    .lock()
                    .ok()
                    .and_then(|x| request_cond.wait(x).ok())
                    .and_then(|mut x| {
                        let result = x.pop_front();
                        // Update queue size metrics after popping
                        THREAD_POOL_QUEUE_SIZE.with_label_values(&["udp_dns"]).set(x.len() as i64);
                        result
                    })
                {
                    Some(x) => x,
                    None => {
                        log::info!("Not expected to happen!");
                        continue;
                    }
                };

                // Update thread activity metrics - mark thread as active
                THREAD_POOL_THREADS.with_label_values(&["udp_dns", "active"]).inc();
                THREAD_POOL_THREADS.with_label_values(&["udp_dns", "idle"]).dec();
                
                Self::process_request(&socket, context.clone(), src, &request);
                
                // Mark task as completed and thread back to idle
                THREAD_POOL_TASKS.with_label_values(&["udp_dns", "completed"]).inc();
                THREAD_POOL_THREADS.with_label_values(&["udp_dns", "active"]).dec();
                THREAD_POOL_THREADS.with_label_values(&["udp_dns", "idle"]).inc();
            }
        })?;
        
        Ok(())
    }

    /// Spawn the main incoming request handler thread
    fn spawn_incoming_handler(self, socket: UdpSocket) -> std::io::Result<()> {
        log::info!("DnsUdpServer-incoming");
        Builder::new()
            .name("DnsUdpServer-incoming".into())
            .spawn(move || {
                loop {
                    let _ = self
                        .context
                        .statistics
                        .udp_query_count
                        .fetch_add(1, Ordering::Release);

                    // Read a query packet
                    let mut req_buffer = BytePacketBuffer::new();
                    let (_, src) = match socket.recv_from(&mut req_buffer.buf) {
                        Ok(x) => x,
                        Err(e) => {
                            log::info!("Failed to read from UDP socket: {:?}", e);
                            continue;
                        }
                    };

                    // Parse it
                    let request = match DnsPacket::from_buffer(&mut req_buffer) {
                        Ok(x) => x,
                        Err(e) => {
                            log::info!("Failed to parse UDP query packet: {:?}", e);
                            continue;
                        }
                    };

                    // Add request to queue and notify waiting threads
                    self.enqueue_request(src, request);
                }
            })?;
        
        Ok(())
    }

    /// Add a request to the queue and notify waiting threads
    fn enqueue_request(&self, src: std::net::SocketAddr, request: DnsPacket) {
        match self.request_queue.lock() {
            Ok(mut queue) => {
                queue.push_back((src, request));
                // Update queue size metrics
                THREAD_POOL_QUEUE_SIZE.with_label_values(&["udp_dns"]).set(queue.len() as i64);
                self.request_cond.notify_one();
            }
            Err(e) => {
                log::info!("Failed to send UDP request for processing: {}", e);
            }
        }
    }
}

impl DnsServer for DnsUdpServer {
    /// Launch the server
    ///
    /// This method takes ownership of the server, preventing the method from
    /// being called multiple times.
    fn run_server(self) -> Result<()> {
        // Bind the socket
        let socket = UdpSocket::bind(("0.0.0.0", self.context.dns_port))?;

        // Spawn worker threads for handling requests
        for thread_id in 0..self.thread_count {
            let socket_clone = match socket.try_clone() {
                Ok(x) => x,
                Err(e) => {
                    log::info!("Failed to clone socket when starting UDP server: {:?}", e);
                    continue;
                }
            };

            self.spawn_request_handler(thread_id, socket_clone)?;
        }

        // Update thread pool metrics
        THREAD_POOL_THREADS.with_label_values(&["udp_dns", "total"]).set(self.thread_count as i64);
        THREAD_POOL_THREADS.with_label_values(&["udp_dns", "idle"]).set(self.thread_count as i64);
        THREAD_POOL_THREADS.with_label_values(&["udp_dns", "active"]).set(0);

        // Start servicing incoming requests
        self.spawn_incoming_handler(socket)?;

        Ok(())
    }
}

/// TCP DNS server
pub struct DnsTcpServer {
    context: Arc<ServerContext>,
    senders: Vec<Sender<TcpStream>>,
    thread_count: usize,
}

impl DnsTcpServer {
    pub fn new(context: Arc<ServerContext>, thread_count: usize) -> DnsTcpServer {
        DnsTcpServer {
            context,
            senders: Vec::new(),
            thread_count,
        }
    }
}

impl DnsServer for DnsTcpServer {
    fn run_server(mut self) -> Result<()> {
        let socket = TcpListener::bind(("0.0.0.0", self.context.dns_port))?;

        // Spawn threads for handling requests, and create the channels
        for thread_id in 0..self.thread_count {
            let (tx, rx) = channel();
            self.senders.push(tx);

            let context = self.context.clone();

            let name = "DnsTcpServer-request-".to_string() + &thread_id.to_string();
            let _ = Builder::new().name(name).spawn(move || {
                loop {
                    let mut stream = match rx.recv() {
                        Ok(x) => x,
                        Err(_) => continue,
                    };

                    let _ = context
                        .statistics
                        .tcp_query_count
                        .fetch_add(1, Ordering::Release);

                    // Update thread activity metrics - mark thread as active
                    THREAD_POOL_THREADS.with_label_values(&["tcp_dns", "active"]).inc();
                    THREAD_POOL_THREADS.with_label_values(&["tcp_dns", "idle"]).dec();

                    // When DNS packets are sent over TCP, they're prefixed with a two byte
                    // length. We don't really need to know the length in advance, so we
                    // just move past it and continue reading as usual
                    ignore_or_report!(
                        read_packet_length(&mut stream),
                        "Failed to read query packet length"
                    );

                    let request = {
                        let mut stream_buffer = StreamPacketBuffer::new(&mut stream);
                        return_or_report!(
                            DnsPacket::from_buffer(&mut stream_buffer),
                            "Failed to read query packet"
                        )
                    };

                    let mut res_buffer = VectorPacketBuffer::new();
                    log::info!("req: {:?}", request.clone());

                    let src_ip = stream.peer_addr().ok().map(|addr| addr.ip());
                    let mut packet = execute_query_with_ip(context.clone(), &request, src_ip);
                    ignore_or_report!(
                        packet.write(&mut res_buffer, 0xFFFF),
                        "Failed to write packet to buffer"
                    );

                    // As is the case for incoming queries, we need to send a 2 byte length
                    // value before handing of the actual packet.
                    let len = res_buffer.pos();
                    ignore_or_report!(
                        write_packet_length(&mut stream, len),
                        "Failed to write packet size"
                    );

                    // Now we can go ahead and write the actual packet
                    let data = return_or_report!(
                        res_buffer.get_range(0, len),
                        "Failed to get packet data"
                    );

                    ignore_or_report!(stream.write_all(data), "Failed to write response packet");

                    ignore_or_report!(stream.shutdown(Shutdown::Both), "Failed to shutdown socket");
                    
                    // Mark task as completed and thread back to idle
                    THREAD_POOL_TASKS.with_label_values(&["tcp_dns", "completed"]).inc();
                    THREAD_POOL_THREADS.with_label_values(&["tcp_dns", "active"]).dec();
                    THREAD_POOL_THREADS.with_label_values(&["tcp_dns", "idle"]).inc();
                }
            })?;
        }

        // Update TCP thread pool metrics
        THREAD_POOL_THREADS.with_label_values(&["tcp_dns", "total"]).set(self.thread_count as i64);
        THREAD_POOL_THREADS.with_label_values(&["tcp_dns", "idle"]).set(self.thread_count as i64);
        THREAD_POOL_THREADS.with_label_values(&["tcp_dns", "active"]).set(0);

        let _ = Builder::new()
            .name("DnsTcpServer-incoming".into())
            .spawn(move || {
                for wrap_stream in socket.incoming() {
                    let stream = match wrap_stream {
                        Ok(stream) => stream,
                        Err(err) => {
                            log::info!("Failed to accept TCP connection: {:?}", err);
                            continue;
                        }
                    };

                    // Hand it off to a worker thread
                    let thread_no = random::<usize>() % self.thread_count;
                    match self.senders[thread_no].send(stream) {
                        Ok(_) => {}
                        Err(e) => {
                            log::info!(
                                "Failed to send TCP request for processing on thread {}: {}",
                                thread_no, e
                            );
                        }
                    }
                }
            })?;

        Ok(())
    }
}

/// Store DNS query information for logging and display
fn store_dns_query_log(
    context: &ServerContext,
    question: &DnsQuestion,
    rescode: ResultCode,
    results: &[DnsPacket]
) {
    use crate::dns::logging::DnsQueryLog;
    
    // Determine if response came from cache
    let cache_hit = match context.cache.lookup(&question.name, question.qtype) {
        Some(_) => true,
        None => false,
    };
    
    // Count answers
    let answer_count = results.iter()
        .map(|packet| packet.answers.len())
        .sum::<usize>() as u16;
    
    // Determine if upstream server was used
    let upstream_server = match &context.resolve_strategy {
        crate::dns::context::ResolveStrategy::Forward { host, port } => {
            if cache_hit {
                None // Cache hit, no upstream used
            } else {
                Some(format!("{}:{}", host, port))
            }
        }
        crate::dns::context::ResolveStrategy::Recursive => None, // Recursive resolution
    };

    // Create query log entry
    let query_log = DnsQueryLog {
        domain: question.name.clone(),
        query_type: format!("{:?}", question.qtype),
        protocol: "UDP/TCP".to_string(), // Could be enhanced to track specific protocol
        response_code: format!("{:?}", rescode),
        answer_count,
        cache_hit,
        upstream_server,
        dnssec_status: None,   // Could be enhanced to track DNSSEC validation
        timestamp: chrono::Utc::now(),
    };
    
    // Store in query log storage
    context.query_log_storage.store_query(query_log);
}

#[cfg(test)]
mod tests {

    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use crate::dns::protocol::{
        DnsPacket, DnsQuestion, DnsRecord, QueryType, ResultCode, TransientTtl,
    };

    use super::*;

    use crate::dns::context::tests::create_test_context;
    use crate::dns::context::ResolveStrategy;

    fn build_query(qname: &str, qtype: QueryType) -> DnsPacket {
        let mut query_packet = DnsPacket::new();
        query_packet.header.recursion_desired = true;

        query_packet
            .questions
            .push(DnsQuestion::new(qname.into(), qtype));

        query_packet
    }

    #[test]
    fn test_execute_query() {
        // Construct a context to execute some queries successfully
        let mut context = create_test_context(Box::new(|qname, qtype, _, _| {
            let mut packet = DnsPacket::new();

            if qname == "google.com" {
                packet.answers.push(DnsRecord::A {
                    domain: "google.com".to_string(),
                    addr: "127.0.0.1".parse::<Ipv4Addr>().unwrap(),
                    ttl: TransientTtl(3600),
                });
            } else if qname == "www.facebook.com" && qtype == QueryType::Cname {
                packet.answers.push(DnsRecord::Cname {
                    domain: "www.facebook.com".to_string(),
                    host: "cdn.facebook.com".to_string(),
                    ttl: TransientTtl(3600),
                });
                packet.answers.push(DnsRecord::A {
                    domain: "cdn.facebook.com".to_string(),
                    addr: "127.0.0.1".parse::<Ipv4Addr>().unwrap(),
                    ttl: TransientTtl(3600),
                });
            } else if qname == "www.microsoft.com" && qtype == QueryType::Cname {
                packet.answers.push(DnsRecord::Cname {
                    domain: "www.microsoft.com".to_string(),
                    host: "cdn.microsoft.com".to_string(),
                    ttl: TransientTtl(3600),
                });
            } else if qname == "cdn.microsoft.com" && qtype == QueryType::A {
                packet.answers.push(DnsRecord::A {
                    domain: "cdn.microsoft.com".to_string(),
                    addr: "127.0.0.1".parse::<Ipv4Addr>().unwrap(),
                    ttl: TransientTtl(3600),
                });
            } else {
                packet.header.rescode = ResultCode::NXDOMAIN;
            }

            Ok(packet)
        }));

        match Arc::get_mut(&mut context) {
            Some(ctx) => {
                ctx.resolve_strategy = ResolveStrategy::Forward {
                    host: "127.0.0.1".to_string(),
                    port: 53,
                };
            }
            None => panic!("Failed to get mutable reference to ServerContext in test"),
        }

        // A successful resolve
        {
            let res = execute_query(context.clone(), &build_query("google.com", QueryType::A));
            assert_eq!(1, res.answers.len());

            match res.answers[0] {
                DnsRecord::A { ref domain, .. } => {
                    assert_eq!("google.com", domain);
                }
                _ => panic!("Expected specific DNS record type but got different type"),
            }
        };

        // A successful resolve, that also resolves a CNAME without recursive lookup
        {
            let res = execute_query(
                context.clone(),
                &build_query("www.facebook.com", QueryType::Cname),
            );
            assert_eq!(2, res.answers.len());

            match res.answers[0] {
                DnsRecord::Cname { ref domain, .. } => {
                    assert_eq!("www.facebook.com", domain);
                }
                _ => panic!("Expected specific DNS record type but got different type"),
            }

            match res.answers[1] {
                DnsRecord::A { ref domain, .. } => {
                    assert_eq!("cdn.facebook.com", domain);
                }
                _ => panic!("Expected specific DNS record type but got different type"),
            }
        };

        // A successful resolve, that also resolves a CNAME through recursive lookup
        {
            let res = execute_query(
                context.clone(),
                &build_query("www.microsoft.com", QueryType::Cname),
            );
            assert_eq!(2, res.answers.len());

            match res.answers[0] {
                DnsRecord::Cname { ref domain, .. } => {
                    assert_eq!("www.microsoft.com", domain);
                }
                _ => panic!("Expected specific DNS record type but got different type"),
            }

            match res.answers[1] {
                DnsRecord::A { ref domain, .. } => {
                    assert_eq!("cdn.microsoft.com", domain);
                }
                _ => panic!("Expected specific DNS record type but got different type"),
            }
        };

        // An unsuccessful resolve, but without any error
        {
            let res = execute_query(context.clone(), &build_query("yahoo.com", QueryType::A));
            assert_eq!(ResultCode::NXDOMAIN, res.header.rescode);
            assert_eq!(0, res.answers.len());
        };

        // Disable recursive resolves to generate a failure
        match Arc::get_mut(&mut context) {
            Some(ctx) => {
                ctx.allow_recursive = false;
            }
            None => panic!("Failed to get mutable reference to ServerContext in test"),
        }

        // This should generate an error code, since recursive resolves are
        // no longer allowed
        {
            let res = execute_query(context.clone(), &build_query("yahoo.com", QueryType::A));
            assert_eq!(ResultCode::REFUSED, res.header.rescode);
            assert_eq!(0, res.answers.len());
        };

        // Send a query without a question, which should fail with an error code
        {
            let query_packet = DnsPacket::new();
            let res = execute_query(context, &query_packet);
            assert_eq!(ResultCode::FORMERR, res.header.rescode);
            assert_eq!(0, res.answers.len());
        };

        // Now construct a context where the dns client will return a failure
        let mut context2 = create_test_context(Box::new(|_, _, _, _| {
            Err(crate::dns::client::ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Fail",
            )))
        }));

        match Arc::get_mut(&mut context2) {
            Some(ctx) => {
                ctx.resolve_strategy = ResolveStrategy::Forward {
                    host: "127.0.0.1".to_string(),
                    port: 53,
                };
            }
            None => panic!("Failed to get mutable reference to ServerContext in test"),
        }

        // We expect this to set the server failure rescode
        {
            let res = execute_query(context2, &build_query("yahoo.com", QueryType::A));
            assert_eq!(ResultCode::SERVFAIL, res.header.rescode);
            assert_eq!(0, res.answers.len());
        };
    }
}
