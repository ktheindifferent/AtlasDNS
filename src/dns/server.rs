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

use crate::dns::buffer::{BytePacketBuffer, PacketBuffer, StreamPacketBuffer, VectorPacketBuffer};
use crate::dns::context::ServerContext;
use crate::dns::netutil::{read_packet_length, write_packet_length};
use crate::dns::protocol::{DnsPacket, DnsRecord, DnsQuestion, QueryType, ResultCode};
use crate::dns::resolve::DnsResolver;

#[derive(Debug, Display, From, Error)]
pub enum ServerError {
    Io(std::io::Error),
}

type Result<T> = std::result::Result<T, ServerError>;

macro_rules! return_or_report {
    ( $x:expr, $message:expr ) => {
        match $x {
            Ok(res) => res,
            Err(_) => {
                log::info!($message);
                return;
            }
        }
    };
}

macro_rules! ignore_or_report {
    ( $x:expr, $message:expr ) => {
        match $x {
            Ok(_) => {}
            Err(_) => {
                log::info!($message);
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

    for ref rec in lookup_list {
        match **rec {
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
    populate_packet_from_results(packet, results);
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

/// This function will always return a valid packet, even if the request could not
/// be performed, since we still want to send something back to the client.
pub fn execute_query(context: Arc<ServerContext>, request: &DnsPacket) -> DnsPacket {
    log::info!("execute_query");
    let mut packet = build_response_packet(&context, request);

    if let Some(error_code) = validate_request(&context, request) {
        packet.header.rescode = error_code;
    } else {
        process_valid_query(context, request, &mut packet);
    }

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

        let mut packet = execute_query(context, &request);
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
                    .and_then(|mut x| x.pop_front())
                {
                    Some(x) => x,
                    None => {
                        log::info!("Not expected to happen!");
                        continue;
                    }
                };

                Self::process_request(&socket, context.clone(), src, &request);
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

                    let mut packet = execute_query(context.clone(), &request);
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
                }
            })?;
        }

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
            None => panic!(),
        }

        // A successful resolve
        {
            let res = execute_query(context.clone(), &build_query("google.com", QueryType::A));
            assert_eq!(1, res.answers.len());

            match res.answers[0] {
                DnsRecord::A { ref domain, .. } => {
                    assert_eq!("google.com", domain);
                }
                _ => panic!(),
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
                _ => panic!(),
            }

            match res.answers[1] {
                DnsRecord::A { ref domain, .. } => {
                    assert_eq!("cdn.facebook.com", domain);
                }
                _ => panic!(),
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
                _ => panic!(),
            }

            match res.answers[1] {
                DnsRecord::A { ref domain, .. } => {
                    assert_eq!("cdn.microsoft.com", domain);
                }
                _ => panic!(),
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
            None => panic!(),
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
            None => panic!(),
        }

        // We expect this to set the server failure rescode
        {
            let res = execute_query(context2, &build_query("yahoo.com", QueryType::A));
            assert_eq!(ResultCode::SERVFAIL, res.header.rescode);
            assert_eq!(0, res.answers.len());
        };
    }
}
