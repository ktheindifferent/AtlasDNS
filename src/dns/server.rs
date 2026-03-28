//! UDP and TCP server implementations for DNS

use std::collections::VecDeque;
use std::io::Write;
use std::net::SocketAddr;
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::Builder;
use std::time::{Duration, Instant};

use derive_more::{Display, Error, From};
use rand::random;
extern crate sentry;

use crate::dns::buffer::{BytePacketBuffer, PacketBuffer, StreamPacketBuffer, VectorPacketBuffer};
use crate::dns::context::ServerContext;
use crate::dns::netutil::{read_packet_length, write_packet_length};
use crate::dns::protocol::{DnsPacket, DnsRecord, DnsQuestion, QueryType, ResultCode, ValidationStatus};
use crate::dns::resolve::DnsResolver;
use crate::dns::logging::{CorrelationContext, DnsQueryLog};
use crate::dns::security::SecurityAction;
use crate::dns::dnssec::{ChainValidator, ChainValidationResult, ValidationMode};
use crate::dns::metrics::{THREAD_POOL_THREADS, THREAD_POOL_QUEUE_SIZE, THREAD_POOL_TASKS};

/// Errors that can occur while running the DNS server.
#[derive(Debug, Display, From, Error)]
pub enum ServerError {
    Io(std::io::Error),
}

type Result<T> = std::result::Result<T, ServerError>;

/// Socket performance and resource metrics
#[derive(Debug)]
pub struct SocketMetrics {
    /// Total bytes sent
    bytes_sent: u64,
    /// Total bytes received
    bytes_received: u64,
    /// Number of active connections (for TCP)
    active_connections: u32,
    /// Socket errors encountered
    socket_errors: u32,
    /// Last error timestamp
    last_error: Option<Instant>,
    /// Average response time
    avg_response_time: Duration,
    /// Socket creation time
    created_at: Instant,
    /// Last activity timestamp
    last_activity: Instant,
}

/// Information about an active connection
#[derive(Debug)]
pub struct ConnectionInfo {
    /// Connection ID
    id: u64,
    /// Remote address
    remote_addr: SocketAddr,
    /// Connection start time
    connected_at: Instant,
    /// Last activity timestamp
    last_activity: Instant,
    /// Number of queries processed
    queries_processed: u32,
    /// Total bytes transferred
    bytes_transferred: u64,
}

#[allow(dead_code)]
impl ConnectionInfo {
    fn new(id: u64, remote_addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            id,
            remote_addr,
            connected_at: now,
            last_activity: now,
            queries_processed: 0,
            bytes_transferred: 0,
        }
    }
    
    fn update_activity(&mut self, bytes: u64) {
        self.last_activity = Instant::now();
        self.queries_processed += 1;
        self.bytes_transferred += bytes;
    }
}

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
    client_ip: Option<String>,
    latency_ms: u64,
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
    store_dns_query_log(&context, question, rescode, &results, client_ip, latency_ms);
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

/// Validate DNSSEC signatures in a response packet using real crypto.
///
/// Uses the validation mode configured on the server context.  Also checks
/// NSEC/NSEC3 authenticated denial of existence for NXDOMAIN responses,
/// using the original question from `request`.
///
/// Returns `Ok(ChainValidationResult)` reflecting authentication status.
fn validate_dnssec(
    _context: &Arc<ServerContext>,
    _request: &DnsPacket,
    packet: &DnsPacket,
) -> std::result::Result<ChainValidationResult, Box<dyn std::error::Error>> {
    // If the resolver already validated this packet (dnssec_status is set),
    // translate that into a ChainValidationResult so the server layer does
    // not re-validate with a weaker (packet-only) check.
    if let Some(ref status) = packet.dnssec_status {
        return Ok(match status {
            ValidationStatus::Secure => ChainValidationResult::Authenticated,
            ValidationStatus::Bogus  => ChainValidationResult::ValidationFailed,
            _                        => ChainValidationResult::Unsigned,
        });
    }

    // Fallback: the packet did not go through the resolver (e.g. authoritative
    // response).  Use packet-level validation.
    let mode = _context.authority.get_validation_mode();
    let validator = ChainValidator::with_root_ksk(mode);
    Ok(validator.validate_packet_rrsigs(packet))
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
    let mut data = std::collections::BTreeMap::new();
    data.insert("domain".to_string(), domain.clone().into());
    data.insert("query_type".to_string(), query_type.clone().into());
    data.insert("query_id".to_string(), request.header.id.into());
    if let Some(ip) = client_ip {
        data.insert("client_ip".to_string(), ip.to_string().into());
    }
    
    sentry::add_breadcrumb(|| {
        sentry::Breadcrumb {
            ty: "dns".to_string(),
            category: Some("dns.query.start".to_string()),
            message: Some(format!("Processing DNS query for {} ({})", domain, query_type)),
            level: sentry::Level::Info,
            data,
            ..Default::default()
        }
    });
    
    // Check if this node is overloaded and would forward to a peer
    if let Some(ref cm) = context.cluster_manager {
        let total_queries = context.statistics.get_udp_query_count() as u64
            + context.statistics.get_tcp_query_count() as u64;
        cm.check_overload(total_queries);
    }

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
                scope.set_tag("security_action", format!("{:?}", security_result.action));
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
                client_ip: client_ip.map(|ip| ip.to_string()),
                latency_ms: Some(start_time.elapsed().as_millis() as u64),
                response_time_us: start_time.elapsed().as_micros() as u64,
                geo_country_code: None,
                geo_country_name: None,
                geo_city: None,
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

            // Log to query log
            if let Some(ref ql) = context.query_log {
                let ip_str = ip.to_string();
                ql.log_query(&ip_str, &domain, &query_type, None, true, start_time.elapsed().as_millis() as i64);
            }

            // Add performance monitoring for security blocked queries
            let elapsed = start_time.elapsed();
            sentry::configure_scope(|scope| {
                scope.set_extra("query_duration_ms", (elapsed.as_millis() as u64).into());
            });

            return packet;
        }
    }
    
    // ── Anomaly detection ────────────────────────────────────────────────────
    // Analyse the query for DGA, tunneling, and behavioural signals.
    // This runs after security checks so we only score queries we will resolve.
    if let Some(question) = request.questions.first() {
        let anomaly_qtype = crate::dns::query_type::QueryType::from_num(question.qtype.to_num());
        let (anomaly_score, anomaly_reasons) = context.anomaly_detector.analyze_query(
            &question.name,
            &anomaly_qtype,
            client_ip,
        );

        if anomaly_score >= crate::dns::anomaly::THRESHOLD_CRITICAL {
            log::error!(
                "ANOMALY CRITICAL (score={:.2}) {} {:?} from {:?}: {}",
                anomaly_score,
                question.name,
                question.qtype,
                client_ip,
                anomaly_reasons.join("; ")
            );
            context.anomaly_detector.record_anomaly(
                &question.name,
                &format!("{:?}", question.qtype),
                &client_ip.map(|ip| ip.to_string()).unwrap_or_default(),
                anomaly_score,
                anomaly_reasons.clone(),
            );
            // Optional blocking: if enabled, return REFUSED for critical scores.
            if context.anomaly_detector.config.block_on_critical {
                let mut blocked = build_response_packet(&context, request);
                blocked.header.rescode = ResultCode::REFUSED;
                return blocked;
            }
        } else if anomaly_score >= crate::dns::anomaly::THRESHOLD_WARN {
            log::warn!(
                "ANOMALY WARNING (score={:.2}) {} {:?} from {:?}: {}",
                anomaly_score,
                question.name,
                question.qtype,
                client_ip,
                anomaly_reasons.join("; ")
            );
            context.anomaly_detector.record_anomaly(
                &question.name,
                &format!("{:?}", question.qtype),
                &client_ip.map(|ip| ip.to_string()).unwrap_or_default(),
                anomaly_score,
                anomaly_reasons,
            );
        }
    }
    // ── End anomaly detection ────────────────────────────────────────────────

    // ── RPZ DNS firewall: evaluate before upstream resolution ────────────────
    {
        match context.rpz_engine.evaluate(request, client_ip) {
            Ok(Some(rpz_response)) => {
                log::info!("RPZ firewall blocked query for {} from {:?}", domain, client_ip);
                context.metrics.record_dns_query(&protocol, &query_type, &domain);
                context.metrics.record_dns_response(
                    &format!("{:?}", rpz_response.header.rescode), &protocol, &query_type
                );
                if let Some(ref ql) = context.query_log {
                    let ip_str = client_ip.map(|ip| ip.to_string()).unwrap_or_default();
                    ql.log_query(&ip_str, &domain, &query_type, None, true,
                        start_time.elapsed().as_millis() as i64);
                }
                return rpz_response;
            }
            Err(_drop_signal) => {
                // RPZ DROP action: return empty packet (server will not send response)
                log::info!("RPZ firewall dropped query for {} from {:?}", domain, client_ip);
                let mut dropped = build_response_packet(&context, request);
                dropped.header.rescode = ResultCode::REFUSED;
                return dropped;
            }
            Ok(None) => {
                // No RPZ match — continue normal processing
            }
        }
    }
    // ── End RPZ DNS firewall ─────────────────────────────────────────────────

    // ── Split-horizon: synthesise a response for matching rules ─────────────
    if let (Some(client_ip), Some(question)) = (client_ip, request.questions.first()) {
        if let Some(sh_response) = context.split_horizon_manager.lookup(
            &question.name,
            client_ip,
            question.qtype,
        ) {
            let mut packet = build_response_packet(&context, request);
            packet.answers = sh_response.answers;
            packet.header.rescode = ResultCode::NOERROR;
            context.statistics.udp_query_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            context.metrics.record_dns_query(&protocol, &query_type, &domain);
            context.metrics.record_dns_response("NOERROR", &protocol, &query_type);
            if let Some(ref ql) = context.query_log {
                ql.log_query(&client_ip.to_string(), &domain, &query_type, None, false,
                    start_time.elapsed().as_millis() as i64);
            }
            return packet;
        }
    }
    // ── End split-horizon ────────────────────────────────────────────────────

    let mut packet = build_response_packet(&context, request);
    let mut cache_hit = false;

    if let Some(error_code) = validate_request(&context, request) {
        packet.header.rescode = error_code;
        
        // Report validation error to Sentry
        sentry::configure_scope(|scope| {
            scope.set_tag("component", "dns_server");
            scope.set_tag("event_type", "validation_error");
            scope.set_tag("error_code", format!("{:?}", error_code));
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
            client_ip: client_ip.map(|ip| ip.to_string()),
            latency_ms: Some(start_time.elapsed().as_millis() as u64),
            response_time_us: start_time.elapsed().as_micros() as u64,
            geo_country_code: None,
            geo_country_name: None,
            geo_city: None,
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
            process_valid_query(context.clone(), request, &mut packet,
                client_ip.map(|ip| ip.to_string()),
                start_time.elapsed().as_millis() as u64);
        }
        
        // Perform DNSSEC validation (AD/CD/DO bit handling per RFC 4035 §3.2,
        // RFC 3225 §3, and RFC 6840 §5.7).
        //
        // • dnssec_enabled controls whether we validate at all.
        // • checking_disabled (CD bit): client wants raw data; skip validation.
        // • DO bit set in request OPT record: client understands DNSSEC;
        //   BOGUS responses MUST return SERVFAIL (RFC 4035 §5.5).
        // • Strict mode: additionally SERVFAIL for unsigned responses.
        let do_bit_set = request.has_do_bit();
        let dnssec_status = if context.dnssec_enabled && !request.header.checking_disabled {
            let mode = context.authority.get_validation_mode();
            let is_strict = mode == ValidationMode::Strict;

            // On cache hits, use the previously-stored validation status so we
            // don't incorrectly classify cached records (which may lack RRSIGs
            // in the response) as unsigned.
            let (status_str, already_decided) = if cache_hit {
                if let Some(q) = request.questions.first() {
                    if let Some(cached_status) = context.cache.get_dnssec_status(&q.name, q.qtype) {
                        if cached_status == "secure" {
                            packet.header.authed_data = true;
                            log::debug!("DNSSEC: AD bit set from cache ({})", q.name);
                        }
                        (Some(cached_status), true)
                    } else {
                        (None, false)
                    }
                } else {
                    (None, false)
                }
            } else {
                (None, false)
            };

            if already_decided {
                status_str
            } else {
                match validate_dnssec(&context, request, &packet) {
                    Ok(ChainValidationResult::Authenticated) => {
                        packet.header.authed_data = true; // AD bit: authenticated data
                        log::debug!("DNSSEC: AD bit set");
                        // Persist validation status in cache for future hits.
                        if let Some(q) = request.questions.first() {
                            context.cache.store_dnssec_status(&q.name, q.qtype, "secure");
                        }
                        Some("secure".to_string())
                    }
                    Ok(ChainValidationResult::ValidationFailed) => {
                        // RFC 4035 §5.5: a security-aware recursive server MUST
                        // return SERVFAIL when it has proof that the response is
                        // BOGUS.  We enforce this whenever the client set the DO
                        // bit OR the server is running in Strict mode.
                        if is_strict || do_bit_set {
                            log::warn!(
                                "DNSSEC: returning SERVFAIL for BOGUS response \
                                 (do_bit={}, strict={})",
                                do_bit_set, is_strict
                            );
                            packet.header.rescode = ResultCode::SERVFAIL;
                            packet.answers.clear();
                            packet.authorities.clear();
                            packet.resources.clear();
                        } else {
                            log::debug!("DNSSEC opportunistic: BOGUS response passed through");
                        }
                        if let Some(q) = request.questions.first() {
                            context.cache.store_dnssec_status(&q.name, q.qtype, "bogus");
                        }
                        Some("bogus".to_string())
                    }
                    Ok(ChainValidationResult::Unsigned) => {
                        // In Strict mode, an unsigned response is also unacceptable.
                        // If DO bit is set but response is unsigned, that is
                        // permitted (the zone may simply not be DNSSEC-signed);
                        // only Strict mode forces SERVFAIL here.
                        if is_strict {
                            log::warn!("DNSSEC strict: returning SERVFAIL for unsigned response");
                            packet.header.rescode = ResultCode::SERVFAIL;
                            packet.answers.clear();
                            packet.authorities.clear();
                            packet.resources.clear();
                        }
                        if let Some(q) = request.questions.first() {
                            context.cache.store_dnssec_status(&q.name, q.qtype, "insecure");
                        }
                        // Unsigned – AD bit remains clear
                        Some("insecure".to_string())
                    }
                    Err(e) => {
                        log::warn!("DNSSEC validation error: {}", e);
                        Some("error".to_string())
                    }
                }
            }
        } else if context.dnssec_enabled && request.header.checking_disabled {
            // CD bit set: skip validation, honour client's request
            log::debug!("DNSSEC: CD bit set, skipping validation");
            Some("checking_disabled".to_string())
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
            crate::dns::context::ResolveStrategy::DohForward { doh_url, .. } => {
                if cache_hit { None } else { Some(doh_url.clone()) }
            }
            crate::dns::context::ResolveStrategy::Recursive => None,
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
            client_ip: client_ip.map(|ip| ip.to_string()),
            latency_ms: Some(start_time.elapsed().as_millis() as u64),
            response_time_us: start_time.elapsed().as_micros() as u64,
            geo_country_code: None,
            geo_country_name: None,
            geo_city: None,
        };
        context.logger.log_dns_query(&ctx, query_log);
    }

    // Feed NXDOMAIN result back to anomaly detector for per-client rate tracking.
    if let Some(ip) = client_ip {
        let is_nx = packet.header.rescode == ResultCode::NXDOMAIN;
        context.anomaly_detector.record_response(ip, is_nx);
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

    // Record latency analytics
    {
        let response_time_us = start_time.elapsed().as_micros() as u64;
        let upstream_server_str = match &context.resolve_strategy {
            crate::dns::context::ResolveStrategy::Forward { host, port } => {
                if cache_hit { None } else { Some(format!("{}:{}", host, port)) }
            }
            crate::dns::context::ResolveStrategy::DohForward { doh_url, .. } => {
                if cache_hit { None } else { Some(doh_url.clone()) }
            }
            crate::dns::context::ResolveStrategy::Recursive => None,
        };
        context.latency_tracker.record(
            response_time_us,
            &query_type,
            cache_hit,
            upstream_server_str.as_deref(),
        );
    }

    // Log to query log
    if let (Some(ref ql), Some(ip)) = (&context.query_log, client_ip) {
        let ip_str = ip.to_string();
        let resolved = packet.answers.iter().find_map(|r| match r {
            crate::dns::protocol::DnsRecord::A { addr, .. } => Some(addr.to_string()),
            crate::dns::protocol::DnsRecord::Aaaa { addr, .. } => Some(addr.to_string()),
            _ => None,
        });
        ql.log_query(&ip_str, &domain, &query_type, resolved.as_deref(), false, start_time.elapsed().as_millis() as i64);
    }

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
    let mut data = std::collections::BTreeMap::new();
    data.insert("duration_ms".to_string(), (elapsed.as_millis() as u64).into());
    data.insert("cache_hit".to_string(), cache_hit.into());
    
    sentry::add_breadcrumb(|| {
        sentry::Breadcrumb {
            ty: "dns".to_string(),
            category: Some("dns.query.complete".to_string()),
            message: Some(format!("DNS query completed: {} ({}ms)", domain, elapsed.as_millis())),
            level: sentry::Level::Info,
            data,
            ..Default::default()
        }
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
    shutdown_flag: Arc<AtomicBool>,
    socket_metrics: Arc<Mutex<SocketMetrics>>,
}

impl SocketMetrics {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            active_connections: 0,
            socket_errors: 0,
            last_error: None,
            avg_response_time: Duration::default(),
            created_at: now,
            last_activity: now,
        }
    }
}

impl DnsUdpServer {
    /// Create a new `DnsUdpServer` with the given context and worker thread count.
    pub fn new(context: Arc<ServerContext>, thread_count: usize) -> DnsUdpServer {
        let metrics = SocketMetrics::new();
        
        DnsUdpServer {
            context,
            request_queue: Arc::new(Mutex::new(VecDeque::new())),
            request_cond: Arc::new(Condvar::new()),
            thread_count,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            socket_metrics: Arc::new(Mutex::new(metrics)),
        }
    }

    /// Send error response to client
    fn send_error_response(
        &self,
        socket: &UdpSocket,
        src: std::net::SocketAddr,
        query_id: u16,
        error_code: crate::dns::protocol::ResultCode,
    ) {
        use crate::dns::protocol::DnsPacket;
        use crate::dns::buffer::VectorPacketBuffer;

        let mut error_packet = DnsPacket::new();
        error_packet.header.id = query_id;
        error_packet.header.response = true;
        error_packet.header.rescode = error_code;
        
        let mut res_buffer = VectorPacketBuffer::new();
        if error_packet.write(&mut res_buffer, 512).is_ok() {
            let len = res_buffer.pos();
            if let Ok(data) = res_buffer.get_range(0, len) {
                let _ = socket.send_to(data, src);
            }
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

        let mut packet = execute_query_with_ip(context.clone(), request, Some(src.ip()));
        let _ = packet.write(&mut res_buffer, size_limit);

        // Fire off the response
        let len = res_buffer.pos();
        let data = return_or_report!(
            res_buffer.get_range(0, len),
            "Failed to get buffer data"
        );
        
        // Track metrics for this request
        let _bytes_sent = len as u64;
        let _bytes_received = packet.questions.first()
            .map(|q| q.name.len() as u64 + 12) // Approximate query size
            .unwrap_or(12);
        
        match socket.send_to(data, src) {
            Ok(_) => {
                // Update metrics for successful send
                context.metrics.record_dns_response(
                    &format!("{:?}", packet.header.rescode),
                    "UDP",
                    &packet.questions.first().map(|q| format!("{:?}", q.qtype)).unwrap_or("UNKNOWN".to_string())
                );
            }
            Err(e) => {
                log::info!("Failed to send response packet: {:?}", e);
                // Report send error to Sentry
                sentry::configure_scope(|scope| {
                    scope.set_tag("component", "dns_server");
                    scope.set_tag("operation", "udp_send");
                    scope.set_extra("error_details", format!("{:?}", e).into());
                    scope.set_extra("client_addr", src.to_string().into());
                });
                sentry::capture_message(
                    &format!("UDP DNS Response Send Failed: {:?}", e),
                    sentry::Level::Warning
                );
            }
        }
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

    /// Spawn the main incoming request handler thread and block until completion
    fn spawn_incoming_handler(self, socket: UdpSocket) -> std::io::Result<()> {
        log::info!("DnsUdpServer-incoming");
        let join_handle = Builder::new()
            .name("DnsUdpServer-incoming".into())
            .spawn(move || {
                loop {
                    // Check for shutdown signal
                    if self.shutdown_flag.load(Ordering::SeqCst) {
                        log::info!("UDP server received shutdown signal, stopping incoming handler");
                        break;
                    }
                    
                    let _ = self
                        .context
                        .statistics
                        .udp_query_count
                        .fetch_add(1, Ordering::Release);

                    // Read a query packet
                    let mut req_buffer = BytePacketBuffer::new();
                    let (packet_size, src) = match socket.recv_from(&mut req_buffer.buf) {
                        Ok(x) => x,
                        Err(e) => {
                            log::info!("Failed to read from UDP socket: {:?}", e);
                            continue;
                        }
                    };

                    // Validate request size before parsing
                    if let Some(ref request_limiter) = self.context.request_limiter {
                        use crate::dns::request_limits::SizeValidationResult;
                        
                        match request_limiter.validate_dns_udp_request(packet_size, Some(src.ip())) {
                            SizeValidationResult::Valid => {
                                // Request size is acceptable, continue processing
                            }
                            SizeValidationResult::TooLarge { actual_size, limit, request_type } => {
                                log::warn!(
                                    "Rejected oversized UDP DNS request from {}: {} bytes (limit: {} bytes, type: {})",
                                    src.ip(), actual_size, limit, request_type
                                );
                                
                                // Send FORMERR response for oversized requests
                                self.send_error_response(&socket, src, 0, crate::dns::protocol::ResultCode::FORMERR);
                                continue;
                            }
                            SizeValidationResult::ClientBlocked { blocked_until } => {
                                log::warn!(
                                    "Blocked UDP DNS request from {} (blocked until: {:?})",
                                    src.ip(), blocked_until
                                );
                                
                                // Send REFUSED response for blocked clients
                                self.send_error_response(&socket, src, 0, crate::dns::protocol::ResultCode::REFUSED);
                                continue;
                            }
                        }
                    }

                    // Parse it
                    let request = match DnsPacket::from_buffer(&mut req_buffer) {
                        Ok(x) => x,
                        Err(e) => {
                            log::info!("Failed to parse UDP query packet: {:?}", e);
                            continue;
                        }
                    };

                    // Additional content validation
                    if let Some(ref request_limiter) = self.context.request_limiter {
                        let domain_names: Vec<String> = request.questions
                            .iter()
                            .map(|q| q.name.clone())
                            .collect();
                        
                        if let crate::dns::request_limits::SizeValidationResult::TooLarge { 
                            actual_size, limit, request_type 
                        } = request_limiter.validate_dns_packet_content(
                            request.questions.len(), 
                            &domain_names, 
                            Some(src.ip())
                        ) {
                            log::warn!(
                                "Rejected DNS request with invalid content from {}: {} (limit: {}, type: {})",
                                src.ip(), actual_size, limit, request_type
                            );
                            
                            self.send_error_response(&socket, src, request.header.id, 
                                crate::dns::protocol::ResultCode::FORMERR);
                            continue;
                        }
                    }

                    // Add request to queue and notify waiting threads
                    self.enqueue_request(src, request);
                }
            })?;
        
        // Block on the main incoming handler thread - this keeps the DNS server alive
        match join_handle.join() {
            Ok(_) => {
                log::info!("DnsUdpServer incoming handler thread completed");
                Ok(())
            }
            Err(e) => {
                log::error!("DnsUdpServer incoming handler thread panicked: {:?}", e);
                Err(std::io::Error::other("DNS server thread panicked"))
            }
        }
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

    /// Bind UDP socket with retry logic and enhanced error handling
    fn bind_udp_socket_with_retry(&self) -> Result<UdpSocket> {
        const MAX_RETRIES: usize = 5;
        const RETRY_DELAY_MS: u64 = 1000;
        
        for attempt in 1..=MAX_RETRIES {
            match UdpSocket::bind(("0.0.0.0", self.context.dns_port)) {
                Ok(socket) => {
                    // Configure socket options for better performance
                    if let Err(e) = self.configure_udp_socket(&socket) {
                        log::warn!("Failed to configure UDP socket options: {:?}", e);
                    }
                    
                    log::info!("Successfully bound UDP socket to port {} on attempt {}", 
                              self.context.dns_port, attempt);
                    return Ok(socket);
                }
                Err(e) => {
                    let error_msg = match e.kind() {
                        std::io::ErrorKind::AddrInUse => {
                            format!("Port {} is already in use by another process", self.context.dns_port)
                        }
                        std::io::ErrorKind::PermissionDenied => {
                            format!("Permission denied binding to port {} (try running as root or use a port > 1024)", 
                                   self.context.dns_port)
                        }
                        std::io::ErrorKind::AddrNotAvailable => {
                            "The requested address is not available on this system".to_string()
                        }
                        _ => format!("Unknown network error: {}", e)
                    };
                    
                    if attempt == MAX_RETRIES {
                        // Final attempt failed, report to Sentry and return error
                        sentry::configure_scope(|scope| {
                            scope.set_tag("component", "dns_server");
                            scope.set_tag("server_type", "udp");
                            scope.set_tag("error_type", format!("{:?}", e.kind()));
                            scope.set_extra("port", self.context.dns_port.into());
                            scope.set_extra("attempt", attempt.into());
                        });
                        sentry::capture_message(
                            &format!("Failed to bind UDP DNS server after {} attempts: {}", MAX_RETRIES, error_msg),
                            sentry::Level::Error
                        );
                        
                        log::error!("Failed to bind UDP socket after {} attempts: {}", MAX_RETRIES, error_msg);
                        return Err(ServerError::Io(e));
                    }
                    
                    log::warn!("Attempt {} failed to bind UDP socket: {}. Retrying in {}ms...", 
                              attempt, error_msg, RETRY_DELAY_MS);
                    
                    // Wait before retry
                    std::thread::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS));
                }
            }
        }
        
        unreachable!("Loop should have returned or errored")
    }
    
    /// Configure UDP socket with optimal settings
    fn configure_udp_socket(&self, socket: &UdpSocket) -> std::io::Result<()> {
        use std::os::unix::io::AsRawFd;
        use libc::{setsockopt, SOL_SOCKET, SO_REUSEADDR, SO_RCVBUF, SO_SNDBUF};
        
        let fd = socket.as_raw_fd();
        
        // Enable address reuse
        let reuse = 1i32;
        unsafe {
            if setsockopt(
                fd,
                SOL_SOCKET,
                SO_REUSEADDR,
                &reuse as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as u32,
            ) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        
        // Set receive buffer size (64KB)
        let recv_buf_size = 65536i32;
        unsafe {
            if setsockopt(
                fd,
                SOL_SOCKET,
                SO_RCVBUF,
                &recv_buf_size as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as u32,
            ) != 0 {
                log::warn!("Failed to set UDP receive buffer size: {:?}", std::io::Error::last_os_error());
            }
        }
        
        // Set send buffer size (64KB)
        let send_buf_size = 65536i32;
        unsafe {
            if setsockopt(
                fd,
                SOL_SOCKET,
                SO_SNDBUF,
                &send_buf_size as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as u32,
            ) != 0 {
                log::warn!("Failed to set UDP send buffer size: {:?}", std::io::Error::last_os_error());
            }
        }
        
        Ok(())
    }

    /// Update socket metrics with activity
    #[allow(dead_code)]
    fn update_socket_metrics(&self, bytes_received: u64, bytes_sent: u64, had_error: bool) {
        if let Ok(mut metrics) = self.socket_metrics.lock() {
            metrics.bytes_received += bytes_received;
            metrics.bytes_sent += bytes_sent;
            metrics.last_activity = Instant::now();

            if had_error {
                metrics.socket_errors += 1;
                metrics.last_error = Some(Instant::now());
            }
        }
    }
    
    /// Get current socket metrics for monitoring
    pub fn get_socket_metrics(&self) -> Option<SocketMetrics> {
        self.socket_metrics.lock().ok().map(|m| SocketMetrics {
            bytes_sent: m.bytes_sent,
            bytes_received: m.bytes_received,
            active_connections: m.active_connections,
            socket_errors: m.socket_errors,
            last_error: m.last_error,
            avg_response_time: m.avg_response_time,
            created_at: m.created_at,
            last_activity: m.last_activity,
        })
    }
    
    /// Initiate graceful shutdown of the UDP server
    pub fn shutdown(&self) {
        log::info!("Initiating graceful shutdown of UDP DNS server");
        self.shutdown_flag.store(true, Ordering::SeqCst);
        
        // Notify all waiting threads to wake up and check shutdown flag
        self.request_cond.notify_all();
        
        // Log final metrics
        if let Some(metrics) = self.get_socket_metrics() {
            log::info!(
                "UDP Server final metrics - Bytes sent: {}, Bytes received: {}, Errors: {}, Uptime: {:?}",
                metrics.bytes_sent,
                metrics.bytes_received, 
                metrics.socket_errors,
                metrics.last_activity.duration_since(metrics.created_at)
            );
        }
    }
}

impl DnsServer for DnsUdpServer {
    /// Launch the server
    ///
    /// This method takes ownership of the server, preventing the method from
    /// being called multiple times.
    fn run_server(self) -> Result<()> {
        // Bind the socket with enhanced error handling and retry logic
        let socket = self.bind_udp_socket_with_retry()?;

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
    shutdown_flag: Arc<AtomicBool>,
    socket_metrics: Arc<Mutex<SocketMetrics>>,
    active_connections: Arc<Mutex<std::collections::HashMap<u64, ConnectionInfo>>>,
}

impl DnsTcpServer {
    /// Create a new `DnsTcpServer` with the given context and worker thread count.
    pub fn new(context: Arc<ServerContext>, thread_count: usize) -> DnsTcpServer {
        let metrics = SocketMetrics::new();
        
        DnsTcpServer {
            context,
            senders: Vec::new(),
            thread_count,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            socket_metrics: Arc::new(Mutex::new(metrics)),
            active_connections: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Send error response over TCP connection
    fn send_tcp_error_response(
        stream: &mut TcpStream,
        query_id: u16,
        error_code: crate::dns::protocol::ResultCode,
    ) {
        use crate::dns::protocol::DnsPacket;
        use crate::dns::buffer::VectorPacketBuffer;
        use crate::dns::netutil::write_packet_length;
        use std::io::Write;

        let mut error_packet = DnsPacket::new();
        error_packet.header.id = query_id;
        error_packet.header.response = true;
        error_packet.header.rescode = error_code;
        
        let mut res_buffer = VectorPacketBuffer::new();
        if error_packet.write(&mut res_buffer, 0xFFFF).is_ok() {
            let len = res_buffer.pos();
            if write_packet_length(stream, len).is_ok() {
                if let Ok(data) = res_buffer.get_range(0, len) {
                    let _ = stream.write_all(data);
                }
            }
        }
        let _ = stream.shutdown(Shutdown::Both);
    }

    /// Bind TCP socket with retry logic and error reporting
    fn bind_tcp_socket_with_retry(&self) -> Result<TcpListener> {
        const MAX_RETRIES: usize = 5;
        const RETRY_DELAY_MS: u64 = 1000;
        
        for attempt in 1..=MAX_RETRIES {
            match TcpListener::bind(("0.0.0.0", self.context.dns_port)) {
                Ok(listener) => {
                    log::info!("Successfully bound TCP socket to port {} on attempt {}", 
                              self.context.dns_port, attempt);
                    return Ok(listener);
                }
                Err(e) => {
                    let error_msg = match e.kind() {
                        std::io::ErrorKind::AddrInUse => {
                            format!("Port {} is already in use by another process", self.context.dns_port)
                        }
                        std::io::ErrorKind::PermissionDenied => {
                            format!("Permission denied binding to port {} (try running as root or use a port > 1024)", 
                                   self.context.dns_port)
                        }
                        std::io::ErrorKind::AddrNotAvailable => {
                            "The requested address is not available on this system".to_string()
                        }
                        _ => format!("Unknown network error: {}", e)
                    };
                    
                    if attempt == MAX_RETRIES {
                        // Final attempt failed, report to Sentry and return error
                        sentry::configure_scope(|scope| {
                            scope.set_tag("component", "dns_server");
                            scope.set_tag("server_type", "tcp");
                            scope.set_tag("error_type", format!("{:?}", e.kind()));
                            scope.set_extra("port", self.context.dns_port.into());
                            scope.set_extra("attempt", attempt.into());
                        });
                        sentry::capture_message(
                            &format!("Failed to bind TCP DNS server after {} attempts: {}", MAX_RETRIES, error_msg),
                            sentry::Level::Error
                        );
                        
                        log::error!("Failed to bind TCP socket after {} attempts: {}", MAX_RETRIES, error_msg);
                        return Err(ServerError::Io(e));
                    }
                    
                    log::warn!("Attempt {} failed to bind TCP socket: {}. Retrying in {}ms...", 
                              attempt, error_msg, RETRY_DELAY_MS);
                    
                    // Wait before retry
                    std::thread::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS));
                }
            }
        }
        
        // This should never be reached due to the return in the loop
        unreachable!("bind_tcp_socket_with_retry: exceeded retry loop without returning")
    }
    
    /// Track a new TCP connection
    #[allow(dead_code)]
    fn track_connection(&self, stream: &TcpStream) -> Option<u64> {
        let connection_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_nanos() as u64;
        
        if let Ok(remote_addr) = stream.peer_addr() {
            if let Ok(mut connections) = self.active_connections.lock() {
                connections.insert(connection_id, ConnectionInfo::new(connection_id, remote_addr));
                
                // Update active connections count in metrics
                if let Ok(mut metrics) = self.socket_metrics.lock() {
                    metrics.active_connections = connections.len() as u32;
                }
                
                log::debug!("Tracking new TCP connection {} from {}", connection_id, remote_addr);
                return Some(connection_id);
            }
        }
        None
    }
    
    /// Update connection activity
    #[allow(dead_code)]
    fn update_connection_activity(&self, connection_id: u64, bytes_transferred: u64) {
        if let Ok(mut connections) = self.active_connections.lock() {
            if let Some(conn_info) = connections.get_mut(&connection_id) {
                conn_info.update_activity(bytes_transferred);
            }
        }
    }
    
    /// Clean up a finished connection
    #[allow(dead_code)]
    fn cleanup_connection(&self, connection_id: Option<u64>) {
        if let Some(id) = connection_id {
            if let Ok(mut connections) = self.active_connections.lock() {
                if let Some(conn_info) = connections.remove(&id) {
                    let duration = conn_info.last_activity.duration_since(conn_info.connected_at);
                    log::debug!(
                        "Cleaned up TCP connection {} from {} - Duration: {:?}, Queries: {}, Bytes: {}",
                        id,
                        conn_info.remote_addr,
                        duration,
                        conn_info.queries_processed,
                        conn_info.bytes_transferred
                    );
                    
                    // Update metrics
                    if let Ok(mut metrics) = self.socket_metrics.lock() {
                        metrics.active_connections = connections.len() as u32;
                        metrics.bytes_sent += conn_info.bytes_transferred;
                    }
                }
            }
        }
    }

    /// Update socket metrics with activity
    #[allow(dead_code)]
    fn update_socket_metrics(&self, bytes_received: u64, bytes_sent: u64, had_error: bool) {
        if let Ok(mut metrics) = self.socket_metrics.lock() {
            metrics.bytes_received += bytes_received;
            metrics.bytes_sent += bytes_sent;
            metrics.last_activity = Instant::now();
            
            if had_error {
                metrics.socket_errors += 1;
                metrics.last_error = Some(Instant::now());
            }
        }
    }
    
    /// Get current socket metrics for monitoring
    pub fn get_socket_metrics(&self) -> Option<SocketMetrics> {
        self.socket_metrics.lock().ok().map(|m| SocketMetrics {
            bytes_sent: m.bytes_sent,
            bytes_received: m.bytes_received,
            active_connections: m.active_connections,
            socket_errors: m.socket_errors,
            last_error: m.last_error,
            avg_response_time: m.avg_response_time,
            created_at: m.created_at,
            last_activity: m.last_activity,
        })
    }
    
    /// Get information about active connections
    pub fn get_active_connections(&self) -> Vec<ConnectionInfo> {
        self.active_connections
            .lock()
            .map(|conns| {
                conns.values().map(|conn| ConnectionInfo {
                    id: conn.id,
                    remote_addr: conn.remote_addr,
                    connected_at: conn.connected_at,
                    last_activity: conn.last_activity,
                    queries_processed: conn.queries_processed,
                    bytes_transferred: conn.bytes_transferred,
                }).collect()
            })
            .unwrap_or_else(|_| Vec::new())
    }
    
    /// Initiate graceful shutdown of the TCP server
    pub fn shutdown(&self) {
        log::info!("Initiating graceful shutdown of TCP DNS server");
        self.shutdown_flag.store(true, Ordering::SeqCst);
        
        // Log active connections before shutdown
        let active_conns = self.get_active_connections();
        if !active_conns.is_empty() {
            log::info!("Closing {} active TCP connections during shutdown", active_conns.len());
            for conn in &active_conns {
                log::debug!(
                    "Active connection {} from {} - Queries: {}, Duration: {:?}",
                    conn.id,
                    conn.remote_addr,
                    conn.queries_processed,
                    conn.last_activity.duration_since(conn.connected_at)
                );
            }
        }
        
        // Log final metrics
        if let Some(metrics) = self.get_socket_metrics() {
            log::info!(
                "TCP Server final metrics - Bytes sent: {}, Bytes received: {}, Active connections: {}, Errors: {}, Uptime: {:?}",
                metrics.bytes_sent,
                metrics.bytes_received,
                metrics.active_connections,
                metrics.socket_errors,
                metrics.last_activity.duration_since(metrics.created_at)
            );
        }
    }
}

impl DnsServer for DnsTcpServer {
    /// Launch the TCP server, spawning worker threads and blocking until the incoming handler exits.
    fn run_server(mut self) -> Result<()> {
        let socket = self.bind_tcp_socket_with_retry()?;

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
                    
                    // Generate a simple connection ID for tracking
                    let connection_id = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0);

                    let _ = context
                        .statistics
                        .tcp_query_count
                        .fetch_add(1, Ordering::Release);

                    // Update thread activity metrics - mark thread as active
                    THREAD_POOL_THREADS.with_label_values(&["tcp_dns", "active"]).inc();
                    THREAD_POOL_THREADS.with_label_values(&["tcp_dns", "idle"]).dec();

                    // When DNS packets are sent over TCP, they're prefixed with a two byte
                    // length. Read and validate the packet length first
                    let packet_length = return_or_report!(
                        read_packet_length(&mut stream),
                        "Failed to read query packet length"
                    );

                    // Validate request size before parsing
                    let src_ip = stream.peer_addr().ok().map(|addr| addr.ip());
                    if let Some(ref request_limiter) = context.request_limiter {
                        use crate::dns::request_limits::SizeValidationResult;
                        
                        match request_limiter.validate_dns_tcp_request(packet_length as usize, src_ip) {
                            SizeValidationResult::Valid => {
                                // Request size is acceptable, continue processing
                            }
                            SizeValidationResult::TooLarge { actual_size, limit, request_type } => {
                                log::warn!(
                                    "Rejected oversized TCP DNS request from {:?}: {} bytes (limit: {} bytes, type: {})",
                                    src_ip, actual_size, limit, request_type
                                );
                                
                                // Send FORMERR response and close connection
                                Self::send_tcp_error_response(&mut stream, 0, crate::dns::protocol::ResultCode::FORMERR);
                                continue;
                            }
                            SizeValidationResult::ClientBlocked { blocked_until } => {
                                log::warn!(
                                    "Blocked TCP DNS request from {:?} (blocked until: {:?})",
                                    src_ip, blocked_until
                                );
                                
                                // Send REFUSED response and close connection
                                Self::send_tcp_error_response(&mut stream, 0, crate::dns::protocol::ResultCode::REFUSED);
                                continue;
                            }
                        }
                    }

                    let request = {
                        let mut stream_buffer = StreamPacketBuffer::new(&mut stream);
                        return_or_report!(
                            DnsPacket::from_buffer(&mut stream_buffer),
                            "Failed to read query packet"
                        )
                    };

                    // Additional content validation
                    if let Some(ref request_limiter) = context.request_limiter {
                        let domain_names: Vec<String> = request.questions
                            .iter()
                            .map(|q| q.name.clone())
                            .collect();
                        
                        if let crate::dns::request_limits::SizeValidationResult::TooLarge { 
                            actual_size, limit, request_type 
                        } = request_limiter.validate_dns_packet_content(
                            request.questions.len(), 
                            &domain_names, 
                            src_ip
                        ) {
                            log::warn!(
                                "Rejected TCP DNS request with invalid content from {:?}: {} (limit: {}, type: {})",
                                src_ip, actual_size, limit, request_type
                            );
                            
                            Self::send_tcp_error_response(&mut stream, request.header.id, 
                                crate::dns::protocol::ResultCode::FORMERR);
                            continue;
                        }
                    }

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

                    let _bytes_sent = len as u64;
                    let _bytes_received = packet_length as u64;
                    
                    match stream.write_all(data) {
                        Ok(_) => {
                            // Update metrics for successful send
                            context.metrics.record_dns_response(
                                &format!("{:?}", packet.header.rescode),
                                "TCP",
                                &request.questions.first().map(|q| format!("{:?}", q.qtype)).unwrap_or("UNKNOWN".to_string())
                            );
                        }
                        Err(e) => {
                            log::info!("Failed to write response packet: {:?}", e);
                            // Report send error to Sentry
                            sentry::configure_scope(|scope| {
                                scope.set_tag("component", "dns_server");
                                scope.set_tag("operation", "tcp_send");
                                scope.set_extra("error_details", format!("{:?}", e).into());
                                scope.set_extra("connection_id", connection_id.into());
                            });
                            sentry::capture_message(
                                &format!("TCP DNS Response Send Failed: {:?}", e),
                                sentry::Level::Warning
                            );
                        }
                    }

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

        let join_handle = Builder::new()
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

        // Block on the main incoming handler thread - this keeps the TCP DNS server alive
        match join_handle.join() {
            Ok(_) => {
                log::info!("DnsTcpServer incoming handler thread completed");
                Ok(())
            }
            Err(e) => {
                log::error!("DnsTcpServer incoming handler thread panicked: {:?}", e);
                Err(std::io::Error::other("TCP DNS server thread panicked").into())
            }
        }
    }
}

/// Store DNS query information for logging and display
fn store_dns_query_log(
    context: &ServerContext,
    question: &DnsQuestion,
    rescode: ResultCode,
    results: &[DnsPacket],
    client_ip: Option<String>,
    latency_ms: u64,
) {
    use crate::dns::logging::DnsQueryLog;

    // Determine if response came from cache
    let cache_hit = context.cache.lookup(&question.name, question.qtype).is_some();

    // Count answers
    let answer_count = results.iter()
        .map(|packet| packet.answers.len())
        .sum::<usize>() as u16;

    // Determine if upstream server was used
    let upstream_server = match &context.resolve_strategy {
        crate::dns::context::ResolveStrategy::Forward { host, port } => {
            if cache_hit { None } else { Some(format!("{}:{}", host, port)) }
        }
        crate::dns::context::ResolveStrategy::DohForward { doh_url, .. } => {
            if cache_hit { None } else { Some(doh_url.clone()) }
        }
        crate::dns::context::ResolveStrategy::Recursive => None,
    };

    // Perform GeoIP enrichment if available
    let (geo_country_code, geo_country_name, geo_city) = if let (Some(ref geoip), Some(ref cip)) = (&context.geoip, &client_ip) {
        if let Ok(ip) = cip.parse::<std::net::IpAddr>() {
            let info = geoip.lookup(ip);
            (info.country_code, info.country_name, info.city)
        } else {
            (None, None, None)
        }
    } else {
        (None, None, None)
    };

    // Create query log entry
    let query_log = DnsQueryLog {
        domain: question.name.clone(),
        query_type: format!("{:?}", question.qtype),
        protocol: "UDP/TCP".to_string(),
        response_code: format!("{:?}", rescode),
        answer_count,
        cache_hit,
        upstream_server,
        dnssec_status: None,
        timestamp: chrono::Utc::now(),
        client_ip,
        latency_ms: Some(latency_ms),
        response_time_us: latency_ms * 1000,
        geo_country_code,
        geo_country_name,
        geo_city,
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
