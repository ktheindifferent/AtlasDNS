//! client for sending DNS queries to other servers

use std::io::Write;
use std::marker::{Send, Sync};
use std::net::{TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{sleep, Builder};
use std::time::Duration as SleepDuration;

use chrono::*;
use derive_more::{Display, Error, From};
extern crate sentry;

use crate::dns::buffer::{BytePacketBuffer, PacketBuffer, StreamPacketBuffer};
use crate::dns::netutil::{read_packet_length, write_packet_length, read_packet_length_generic, write_packet_length_generic};
use crate::dns::protocol::{DnsPacket, DnsQuestion, QueryType};
use crate::dns::connection_pool::{ConnectionPoolManager, PoolConfig};

#[derive(Debug, Display, From, Error)]
pub enum ClientError {
    Protocol(crate::dns::protocol::ProtocolError),
    Io(std::io::Error),
    PoisonedLock,
    LookupFailed,
    TimeOut,
}

type Result<T> = std::result::Result<T, ClientError>;

pub trait DnsClient {
    fn get_sent_count(&self) -> usize;
    fn get_failed_count(&self) -> usize;

    fn run(&self) -> Result<()>;
    fn send_query(
        &self,
        qname: &str,
        qtype: QueryType,
        server: (&str, u16),
        recursive: bool,
    ) -> Result<DnsPacket>;
    
    /// Allow downcasting to specific client types for configuration
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        panic!("as_any_mut not implemented for this client type")
    }
}

/// The UDP client
///
/// This includes a fair bit of synchronization due to the stateless nature of UDP.
/// When many queries are sent in parallell, the response packets can come back
/// in any order. For that reason, we fire off replies on the sending thread, but
/// handle replies on a single thread. A channel is created for every response,
/// and the caller will block on the channel until the a response is received.
pub struct DnsNetworkClient {
    total_sent: Arc<AtomicUsize>,
    total_failed: Arc<AtomicUsize>,

    /// Counter for assigning packet ids
    seq: Arc<AtomicUsize>,

    /// The listener socket
    socket: Arc<UdpSocket>,

    /// Queries in progress
    pending_queries: Arc<Mutex<Vec<PendingQuery>>>,
    
    /// Connection pool for TCP connections
    connection_pool: Option<Arc<ConnectionPoolManager>>,
}

impl Clone for DnsNetworkClient {
    fn clone(&self) -> Self {
        Self {
            total_sent: self.total_sent.clone(),
            total_failed: self.total_failed.clone(),
            seq: self.seq.clone(),
            socket: self.socket.clone(),
            pending_queries: self.pending_queries.clone(),
            connection_pool: self.connection_pool.clone(),
        }
    }
}

/// A query in progress. This struct holds the `id` if the request, and a channel
/// endpoint for returning a response back to the thread from which the query
/// was posed.
struct PendingQuery {
    seq: u16,
    timestamp: DateTime<Local>,
    tx: Sender<Option<DnsPacket>>,
}

unsafe impl Send for DnsNetworkClient {}
unsafe impl Sync for DnsNetworkClient {}

impl DnsNetworkClient {
    pub fn new(port: u16) -> Result<DnsNetworkClient> {
        let socket = UdpSocket::bind(("0.0.0.0", port))
            .map_err(|e| {
                log::error!("Failed to bind UDP socket on port {}: {}", port, e);
                ClientError::Io(std::io::Error::new(std::io::ErrorKind::AddrInUse, 
                    format!("Cannot bind to port {}", port)))
            })?;
        
        // Log the actual bound port (useful when port 0 is used)
        if let Ok(local_addr) = socket.local_addr() {
            if port == 0 {
                log::info!("DNS client bound to dynamically assigned port {}", local_addr.port());
            } else {
                log::debug!("DNS client bound to port {}", local_addr.port());
            }
        }
            
        Ok(DnsNetworkClient {
            total_sent: Arc::new(AtomicUsize::new(0)),
            total_failed: Arc::new(AtomicUsize::new(0)),
            seq: Arc::new(AtomicUsize::new(0)),
            socket: Arc::new(socket),
            pending_queries: Arc::new(Mutex::new(Vec::new())),
            connection_pool: None,
        })
    }
    
    /// Enable connection pooling with the specified configuration
    pub fn enable_connection_pooling(&mut self, config: PoolConfig, metrics: Arc<crate::dns::metrics::MetricsCollector>) {
        self.connection_pool = Some(Arc::new(ConnectionPoolManager::new(config, metrics)));
        log::info!("Connection pooling enabled for DNS client");
    }
    
    /// Enable connection pooling with default configuration
    pub fn enable_default_connection_pooling(&mut self, metrics: Arc<crate::dns::metrics::MetricsCollector>) {
        self.enable_connection_pooling(PoolConfig::default(), metrics);
    }

    /// Send a DNS query using TCP transport
    ///
    /// This is much simpler than using UDP, since the kernel will take care of
    /// packet ordering, connection state, timeouts etc.
    pub fn send_tcp_query(
        &self,
        qname: &str,
        qtype: QueryType,
        server: (&str, u16),
        recursive: bool,
    ) -> Result<DnsPacket> {
        let _ = self.total_sent.fetch_add(1, Ordering::Release);

        // Prepare request
        let mut packet = DnsPacket::new();

        packet.header.id = self.seq.fetch_add(1, Ordering::SeqCst) as u16;
        if packet.header.id + 1 == 0xFFFF {
            let res = self.seq.compare_exchange(0xFFFF, 0, Ordering::SeqCst, Ordering::SeqCst);

            match res {
                Ok(v) => log::info!("DNS_TCP_COMPARE_EXCHANGE: {:?}", v),
                Err(e) => {
                    log::info!("DNS_TCP_COMPARE_EXCHANGE_ERROR: {:?}", e);
                }
            }



        }

        packet.header.questions = 1;
        packet.header.recursion_desired = recursive;

        packet.questions.push(DnsQuestion::new(qname.into(), qtype));

        // Send query
        let mut req_buffer = BytePacketBuffer::new();
        packet.write(&mut req_buffer, 0xFFFF)?;

        // Try to use connection pool if available, otherwise create direct connection
        use std::net::SocketAddr;
        
        // Use connection pool if available
        if let Some(ref pool_manager) = self.connection_pool {
            // Parse server address
            let server_addr: SocketAddr = format!("{}:{}", server.0, server.1)
                .parse()
                .map_err(|e| ClientError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Invalid server address: {}", e)
                )))?;
            
            match pool_manager.get_pool(server_addr) {
                Ok(pool) => {
                    match pool.get_connection() {
                        Ok(mut pooled_conn) => {
                            // Use pooled connection
                            let socket = &mut pooled_conn.stream;
                            write_packet_length_generic(socket, req_buffer.pos())?;
                            socket.write_all(&req_buffer.buf[0..req_buffer.pos])?;
                            socket.flush()?;
                            
                            let _ = read_packet_length_generic(socket)?;
                            let mut stream_buffer = StreamPacketBuffer::new(socket);
                            let packet = DnsPacket::from_buffer(&mut stream_buffer)?;
                            
                            // Connection will be returned to pool when pooled_conn is dropped
                            return Ok(packet);
                        }
                        Err(e) => {
                            log::warn!("Failed to get connection from pool for {}: {}", server_addr, e);
                            // Fall through to create direct connection
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Failed to get connection pool for {}: {}", server_addr, e);
                    // Fall through to create direct connection
                }
            }
        }
        
        // Fallback to direct connection if pool not available or failed
        let mut socket = TcpStream::connect(server).map_err(|e| {
            // Report DNS client connection error to Sentry
            sentry::configure_scope(|scope| {
                scope.set_tag("component", "dns_client");
                scope.set_tag("operation", "tcp_connect");
                scope.set_tag("protocol", "tcp");
                scope.set_tag("server", &format!("{}:{}", server.0, server.1));
                scope.set_tag("query_name", qname);
                scope.set_tag("query_type", &format!("{:?}", qtype));
                scope.set_extra("recursive", recursive.into());
            });
            sentry::capture_message(
                &format!("Failed to connect to DNS server {}:{} for query {}: {}", server.0, server.1, qname, e),
                sentry::Level::Warning
            );
            e
        })?;

        write_packet_length(&mut socket, req_buffer.pos())?;
        socket.write_all(&req_buffer.buf[0..req_buffer.pos])?;
        socket.flush()?;

        let _ = read_packet_length(&mut socket)?;

        let mut stream_buffer = StreamPacketBuffer::new(&mut socket);
        let packet = DnsPacket::from_buffer(&mut stream_buffer)?;

        Ok(packet)
    }

    /// Send a DNS query using UDP transport
    ///
    /// This will construct a query packet, and fire it off to the specified server.
    /// The query is sent from the callee thread, but responses are read on a
    /// worker thread, and returned to this thread through a channel. Thus this
    /// method is thread safe, and can be used from any number of threads in
    /// parallell.
    pub fn send_udp_query(
        &self,
        qname: &str,
        qtype: QueryType,
        server: (&str, u16),
        recursive: bool,
    ) -> Result<DnsPacket> {
        let _ = self.total_sent.fetch_add(1, Ordering::Release);

        // Prepare request
        let mut packet = DnsPacket::new();

        packet.header.id = self.seq.fetch_add(1, Ordering::SeqCst) as u16;
        if packet.header.id + 1 == 0xFFFF {
            let res = self.seq.compare_exchange(0xFFFF, 0, Ordering::SeqCst, Ordering::SeqCst);
            match res {
                Ok(v) => log::info!("DNS_UDP_COMPARE_EXCHANGE: {:?}", v),
                Err(e) => {
                    log::info!("DNS_UDP_COMPARE_EXCHANGE_ERROR: {:?}", e);
                }
            }


        }

        packet.header.questions = 1;
        packet.header.recursion_desired = recursive;

        packet
            .questions
            .push(DnsQuestion::new(qname.to_string(), qtype));

        // Create a return channel, and add a `PendingQuery` to the list of lookups
        // in progress
        let (tx, rx) = channel();
        {
            let mut pending_queries = self
                .pending_queries
                .lock()
                .map_err(|_| ClientError::PoisonedLock)?;
            pending_queries.push(PendingQuery {
                seq: packet.header.id,
                timestamp: Local::now(),
                tx,
            });
        }

        // Send query
        let mut req_buffer = BytePacketBuffer::new();
        packet.write(&mut req_buffer, 512)?;
        self.socket
            .send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

        // Wait for response
        match rx.recv() {
            Ok(Some(qr)) => Ok(qr),
            Ok(None) => {
                let _ = self.total_failed.fetch_add(1, Ordering::Release);
                Err(ClientError::TimeOut)
            }
            Err(_) => {
                let _ = self.total_failed.fetch_add(1, Ordering::Release);
                Err(ClientError::LookupFailed)
            }
        }
    }
}

impl DnsNetworkClient {
    /// Async version of send_query for use with async code
    pub async fn send_query_async(&self, qname: &str, qtype: QueryType) -> Result<DnsPacket> {
        // Use a default DNS server (8.8.8.8) for resolution
        let server = ("8.8.8.8", 53);
        let recursive = true;
        
        // For now, we'll use blocking IO in a spawn_blocking task
        let qname = qname.to_string();
        let client = self.clone();
        
        tokio::task::spawn_blocking(move || {
            DnsClient::send_query(&client, &qname, qtype, server, recursive)
        })
        .await
        .map_err(|e| ClientError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?
    }
}

impl DnsClient for DnsNetworkClient {
    fn get_sent_count(&self) -> usize {
        self.total_sent.load(Ordering::Acquire)
    }

    fn get_failed_count(&self) -> usize {
        self.total_failed.load(Ordering::Acquire)
    }

    /// The run method launches a worker thread. Unless this thread is running, no
    /// responses will ever be generated, and clients will just block indefinitely.
    fn run(&self) -> Result<()> {
        // Start the thread for handling incoming responses
        {
            let socket_copy = self.socket.try_clone()?;
            let pending_queries_lock = self.pending_queries.clone();

            Builder::new()
                .name("DnsNetworkClient-worker-thread".into())
                .spawn(move || {
                    loop {
                        // Read data into a buffer
                        let mut res_buffer = BytePacketBuffer::new();
                        match socket_copy.recv_from(&mut res_buffer.buf) {
                            Ok(_) => {}
                            Err(_) => {
                                continue;
                            }
                        }

                        // Construct a DnsPacket from buffer, skipping the packet if parsing
                        // failed
                        let packet = match DnsPacket::from_buffer(&mut res_buffer) {
                            Ok(packet) => packet,
                            Err(err) => {
                                log::info!(
                                    "DnsNetworkClient failed to parse packet with error: {}",
                                    err
                                );
                                continue;
                            }
                        };

                        // Acquire a lock on the pending_queries list, and search for a
                        // matching PendingQuery to which to deliver the response.
                        if let Ok(mut pending_queries) = pending_queries_lock.lock() {
                            let mut matched_query = None;
                            for (i, pending_query) in pending_queries.iter().enumerate() {
                                if pending_query.seq == packet.header.id {
                                    // Matching query found, send the response
                                    let _ = pending_query.tx.send(Some(packet.clone()));

                                    // Mark this index for removal from list
                                    matched_query = Some(i);

                                    break;
                                }
                            }

                            if let Some(idx) = matched_query {
                                pending_queries.remove(idx);
                            } else {
                                log::info!("Discarding response for: {:?}", packet.questions[0]);
                            }
                        }
                    }
                })?;
        }

        // Start the thread for timing out requests
        {
            let pending_queries_lock = self.pending_queries.clone();

            Builder::new()
                .name("DnsNetworkClient-timeout-thread".into())
                .spawn(move || {
                    let timeout = Duration::seconds(1);
                    loop {
                        if let Ok(mut pending_queries) = pending_queries_lock.lock() {
                            let mut finished_queries = Vec::new();
                            for (i, pending_query) in pending_queries.iter().enumerate() {
                                let expires = pending_query.timestamp + timeout;
                                if expires < Local::now() {
                                    let _ = pending_query.tx.send(None);
                                    finished_queries.push(i);
                                }
                            }

                            // Remove `PendingQuery` objects from the list, in reverse order
                            for idx in finished_queries.iter().rev() {
                                pending_queries.remove(*idx);
                            }
                        }

                        sleep(SleepDuration::from_millis(100));
                    }
                })?;
        }

        Ok(())
    }

    fn send_query(
        &self,
        qname: &str,
        qtype: QueryType,
        server: (&str, u16),
        recursive: bool,
    ) -> Result<DnsPacket> {
        let packet = self.send_udp_query(qname, qtype, server, recursive)?;
        if !packet.header.truncated_message {
            return Ok(packet);
        }

        log::info!("Truncated response - resending as TCP");
        self.send_tcp_query(qname, qtype, server, recursive)
    }
    
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType};

    pub type StubCallback = dyn Fn(&str, QueryType, (&str, u16), bool) -> Result<DnsPacket>;

    pub struct DnsStubClient {
        callback: Box<StubCallback>,
    }

    impl<'a> DnsStubClient {
        pub fn new(callback: Box<StubCallback>) -> DnsStubClient {
            DnsStubClient { callback }
        }
    }

    unsafe impl Send for DnsStubClient {}
    unsafe impl Sync for DnsStubClient {}

    impl DnsClient for DnsStubClient {
        fn get_sent_count(&self) -> usize {
            0
        }

        fn get_failed_count(&self) -> usize {
            0
        }

        fn run(&self) -> Result<()> {
            Ok(())
        }

        fn send_query(
            &self,
            qname: &str,
            qtype: QueryType,
            server: (&str, u16),
            recursive: bool,
        ) -> Result<DnsPacket> {
            (self.callback)(qname, qtype, server, recursive)
        }
    }

    #[test]
    pub fn test_udp_client() {
        let client = DnsNetworkClient::new(31456).expect("Failed to create test client");
        client.run().unwrap();

        let res = client
            .send_udp_query("google.com", QueryType::A, ("8.8.8.8", 53), true)
            .unwrap();

        assert_eq!(res.questions[0].name, "google.com");
        assert!(!res.answers.is_empty());

        match res.answers[0] {
            DnsRecord::A { ref domain, .. } => {
                assert_eq!("google.com", domain);
            }
            _ => panic!(),
        }
    }

    #[test]
    pub fn test_tcp_client() {
        let client = DnsNetworkClient::new(31457).expect("Failed to create test client");
        let res = client
            .send_tcp_query("google.com", QueryType::A, ("8.8.8.8", 53), true)
            .unwrap();

        assert_eq!(res.questions[0].name, "google.com");
        assert!(!res.answers.is_empty());

        match res.answers[0] {
            DnsRecord::A { ref domain, .. } => {
                assert_eq!("google.com", domain);
            }
            _ => panic!(),
        }
    }
}
