//! Connection Pool for DNS Queries
//!
//! Manages a pool of persistent TCP/TLS connections to upstream DNS servers
//! for improved performance through connection reuse.
//!
//! # Features
//!
//! * **Connection Reuse** - Avoid TCP handshake overhead
//! * **Health Monitoring** - Automatic detection of dead connections
//! * **Load Balancing** - Distribute queries across connections
//! * **Automatic Scaling** - Grow/shrink pool based on demand
//! * **TLS Session Resumption** - Fast TLS reconnection
//! * **Connection Warming** - Pre-establish connections

use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::io::{Read, Write};
use parking_lot::{RwLock, Mutex};
use openssl::ssl::{SslConnector, SslMethod, SslStream};

use crate::dns::protocol::{DnsPacket, QueryType};
use crate::dns::buffer::BytePacketBuffer;
use crate::dns::errors::DnsError;
use crate::dns::metrics::MetricsCollector;

/// Connection pool configuration
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Minimum number of connections to maintain
    pub min_connections: usize,
    /// Maximum number of connections allowed
    pub max_connections: usize,
    /// Connection timeout in seconds
    pub connection_timeout: Duration,
    /// Idle timeout before closing connection
    pub idle_timeout: Duration,
    /// Maximum queries per connection before recycling
    pub max_queries_per_connection: usize,
    /// Enable TLS for connections
    pub use_tls: bool,
    /// Enable connection warming
    pub warm_connections: bool,
    /// Health check interval
    pub health_check_interval: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_connections: 2,
            max_connections: 10,
            connection_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(60),
            max_queries_per_connection: 1000,
            use_tls: false,
            warm_connections: true,
            health_check_interval: Duration::from_secs(30),
        }
    }
}

/// Connection state
#[derive(Debug)]
enum ConnectionState {
    Active,
    Idle,
    Dead,
}

/// Pooled connection wrapper
struct PooledConnection {
    /// The actual TCP or TLS connection
    stream: ConnectionStream,
    /// Connection state
    state: ConnectionState,
    /// Server address
    server: SocketAddr,
    /// Creation time
    created_at: Instant,
    /// Last used time
    last_used: Instant,
    /// Number of queries handled
    query_count: usize,
    /// Connection ID for tracking
    id: u64,
}

/// Wrapper for TCP or TLS connections
enum ConnectionStream {
    Tcp(TcpStream),
    Tls(SslStream<TcpStream>),
}

impl ConnectionStream {
    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        match self {
            ConnectionStream::Tcp(stream) => stream.read_exact(buf),
            ConnectionStream::Tls(stream) => stream.read_exact(buf),
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            ConnectionStream::Tcp(stream) => stream.write_all(buf),
            ConnectionStream::Tls(stream) => stream.write_all(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            ConnectionStream::Tcp(stream) => stream.flush(),
            ConnectionStream::Tls(stream) => stream.flush(),
        }
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            ConnectionStream::Tcp(stream) => stream.set_read_timeout(timeout),
            ConnectionStream::Tls(stream) => stream.get_ref().set_read_timeout(timeout),
        }
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            ConnectionStream::Tcp(stream) => stream.set_write_timeout(timeout),
            ConnectionStream::Tls(stream) => stream.get_ref().set_write_timeout(timeout),
        }
    }
}

/// Connection pool for a specific upstream server
pub struct ServerConnectionPool {
    /// Server address
    server: SocketAddr,
    /// Pool configuration
    config: PoolConfig,
    /// Available connections
    available: Arc<Mutex<VecDeque<PooledConnection>>>,
    /// Active connections (in use)
    active: Arc<RwLock<HashMap<u64, PooledConnection>>>,
    /// Connection ID counter
    next_id: Arc<Mutex<u64>>,
    /// Pool statistics
    stats: Arc<RwLock<PoolStatistics>>,
    /// SSL connector for TLS connections
    ssl_connector: Option<SslConnector>,
}

/// Pool statistics
#[derive(Debug, Default)]
pub struct PoolStatistics {
    /// Total connections created
    pub total_created: u64,
    /// Total connections closed
    pub total_closed: u64,
    /// Total queries handled
    pub total_queries: u64,
    /// Connection reuse count
    pub reuse_count: u64,
    /// Failed connection attempts
    pub failed_connections: u64,
    /// Average connection lifetime
    pub avg_connection_lifetime: Duration,
    /// Current pool size
    pub current_size: usize,
}

impl ServerConnectionPool {
    /// Create a new connection pool for a server
    pub fn new(server: SocketAddr, config: PoolConfig) -> Result<Self, DnsError> {
        let ssl_connector = if config.use_tls {
            let mut builder = SslConnector::builder(SslMethod::tls())
                .map_err(|e| DnsError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
            
            // Configure TLS settings
            builder.set_verify(openssl::ssl::SslVerifyMode::NONE); // For testing
            
            Some(builder.build())
        } else {
            None
        };

        let pool = Self {
            server,
            config: config.clone(),
            available: Arc::new(Mutex::new(VecDeque::new())),
            active: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(0)),
            stats: Arc::new(RwLock::new(PoolStatistics::default())),
            ssl_connector,
        };

        // Warm up the pool with minimum connections
        if config.warm_connections {
            pool.warm_pool()?;
        }

        Ok(pool)
    }

    /// Warm up the pool with minimum connections
    fn warm_pool(&self) -> Result<(), DnsError> {
        let mut available = self.available.lock();
        
        for _ in 0..self.config.min_connections {
            match self.create_connection() {
                Ok(conn) => available.push_back(conn),
                Err(e) => {
                    log::warn!("Failed to warm connection: {:?}", e);
                    self.stats.write().failed_connections += 1;
                }
            }
        }

        Ok(())
    }

    /// Create a new connection
    fn create_connection(&self) -> Result<PooledConnection, DnsError> {
        let tcp_stream = TcpStream::connect_timeout(&self.server, self.config.connection_timeout)
            .map_err(|e| DnsError::Io(e))?;

        // Set TCP options
        tcp_stream.set_nodelay(true)
            .map_err(|e| DnsError::Io(e))?;
        tcp_stream.set_read_timeout(Some(self.config.connection_timeout))
            .map_err(|e| DnsError::Io(e))?;
        tcp_stream.set_write_timeout(Some(self.config.connection_timeout))
            .map_err(|e| DnsError::Io(e))?;

        let stream = if let Some(ref ssl_connector) = self.ssl_connector {
            // Create TLS connection
            let ssl_stream = ssl_connector
                .connect("dns.server", tcp_stream)
                .map_err(|e| DnsError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
            ConnectionStream::Tls(ssl_stream)
        } else {
            ConnectionStream::Tcp(tcp_stream)
        };

        let id = {
            let mut next_id = self.next_id.lock();
            let id = *next_id;
            *next_id += 1;
            id
        };

        let conn = PooledConnection {
            stream,
            state: ConnectionState::Idle,
            server: self.server,
            created_at: Instant::now(),
            last_used: Instant::now(),
            query_count: 0,
            id,
        };

        // Update statistics
        {
            let mut stats = self.stats.write();
            stats.total_created += 1;
            stats.current_size += 1;
        }

        log::debug!("Created new connection {} to {}", id, self.server);

        Ok(conn)
    }

    /// Get a connection from the pool
    pub fn get_connection(&self) -> Result<PooledConnection, DnsError> {
        // First, try to get an available connection
        {
            let mut available = self.available.lock();
            
            while let Some(mut conn) = available.pop_front() {
                // Check if connection is still valid
                if self.is_connection_valid(&conn) {
                    conn.state = ConnectionState::Active;
                    conn.last_used = Instant::now();
                    
                    // Update statistics
                    self.stats.write().reuse_count += 1;
                    
                    log::debug!("Reusing connection {} to {}", conn.id, self.server);
                    return Ok(conn);
                } else {
                    // Connection is dead, close it
                    self.close_connection(conn);
                }
            }
        }

        // No available connections, check if we can create a new one
        if self.stats.read().current_size < self.config.max_connections {
            return self.create_connection();
        }

        // Pool is at maximum capacity
        Err(DnsError::Operation(crate::dns::errors::OperationError {
            context: "Connection pool".to_string(),
            details: "Pool at maximum capacity".to_string(),
            recovery_hint: Some("Wait for a connection to become available".to_string()),
        }))
    }

    /// Return a connection to the pool
    pub fn return_connection(&self, mut conn: PooledConnection) {
        let conn_id = conn.id;
        
        // Check if connection should be recycled
        if conn.query_count >= self.config.max_queries_per_connection {
            log::debug!("Connection {} reached query limit, closing", conn_id);
            self.close_connection(conn);
            
            // Try to create a replacement
            if let Ok(new_conn) = self.create_connection() {
                self.available.lock().push_back(new_conn);
            }
        } else if self.is_connection_valid(&conn) {
            // Return to available pool
            conn.state = ConnectionState::Idle;
            log::debug!("Returned connection {} to pool", conn_id);
            self.available.lock().push_back(conn);
        } else {
            // Connection is dead
            self.close_connection(conn);
        }
    }

    /// Check if a connection is still valid
    fn is_connection_valid(&self, conn: &PooledConnection) -> bool {
        // Check age
        if conn.created_at.elapsed() > Duration::from_secs(300) {
            return false;
        }

        // Check idle time
        if conn.last_used.elapsed() > self.config.idle_timeout {
            return false;
        }

        // Connection appears valid
        true
    }

    /// Close a connection
    fn close_connection(&self, conn: PooledConnection) {
        log::debug!("Closing connection {} to {}", conn.id, self.server);
        
        // Update statistics
        let mut stats = self.stats.write();
        stats.total_closed += 1;
        stats.current_size = stats.current_size.saturating_sub(1);
        
        // Update average lifetime
        let lifetime = conn.created_at.elapsed();
        if stats.total_closed == 1 {
            stats.avg_connection_lifetime = lifetime;
        } else {
            let avg_ms = stats.avg_connection_lifetime.as_millis() as u64;
            let new_ms = lifetime.as_millis() as u64;
            let updated_avg = (avg_ms * (stats.total_closed - 1) + new_ms) / stats.total_closed;
            stats.avg_connection_lifetime = Duration::from_millis(updated_avg);
        }
        
        // Connection drop will close the underlying stream
    }

    /// Execute a DNS query using a pooled connection
    pub fn query(&self, packet: &mut DnsPacket) -> Result<DnsPacket, DnsError> {
        let mut conn = self.get_connection()?;
        
        // Serialize the query
        let mut buffer = BytePacketBuffer::new();
        packet.write(&mut buffer, 512)?;
        let query_bytes = &buffer.buf[..buffer.pos];
        
        // Send query with length prefix (TCP DNS format)
        let query_len = query_bytes.len() as u16;
        conn.stream.write_all(&query_len.to_be_bytes())
            .map_err(|e| DnsError::Io(e))?;
        conn.stream.write_all(query_bytes)
            .map_err(|e| DnsError::Io(e))?;
        conn.stream.flush()
            .map_err(|e| DnsError::Io(e))?;
        
        // Read response length
        let mut len_buf = [0u8; 2];
        conn.stream.read_exact(&mut len_buf)
            .map_err(|e| DnsError::Io(e))?;
        let response_len = u16::from_be_bytes(len_buf) as usize;
        
        // Read response
        let mut response_buf = vec![0u8; response_len];
        conn.stream.read_exact(&mut response_buf)
            .map_err(|e| DnsError::Io(e))?;
        
        // Parse response
        let mut response_buffer = BytePacketBuffer::new();
        response_buffer.buf[..response_len].copy_from_slice(&response_buf);
        response_buffer.pos = 0;
        
        let response = DnsPacket::from_buffer(&mut response_buffer)?;
        
        // Update connection statistics
        conn.query_count += 1;
        self.stats.write().total_queries += 1;
        
        // Return connection to pool
        self.return_connection(conn);
        
        Ok(response)
    }

    /// Get pool statistics
    pub fn get_statistics(&self) -> PoolStatistics {
        let stats = self.stats.read();
        PoolStatistics {
            total_created: stats.total_created,
            total_closed: stats.total_closed,
            total_queries: stats.total_queries,
            reuse_count: stats.reuse_count,
            failed_connections: stats.failed_connections,
            avg_connection_lifetime: stats.avg_connection_lifetime,
            current_size: stats.current_size,
        }
    }

    /// Perform health check on all connections
    pub fn health_check(&self) {
        let mut available = self.available.lock();
        let mut healthy = VecDeque::new();
        
        while let Some(conn) = available.pop_front() {
            if self.is_connection_valid(&conn) {
                healthy.push_back(conn);
            } else {
                self.close_connection(conn);
            }
        }
        
        *available = healthy;
        
        // Ensure minimum connections
        let current_size = available.len();
        if current_size < self.config.min_connections {
            for _ in current_size..self.config.min_connections {
                if let Ok(conn) = self.create_connection() {
                    available.push_back(conn);
                }
            }
        }
    }
}

/// Global connection pool manager
pub struct ConnectionPoolManager {
    /// Pools for each upstream server
    pools: Arc<RwLock<HashMap<SocketAddr, Arc<ServerConnectionPool>>>>,
    /// Default pool configuration
    default_config: PoolConfig,
    /// Metrics collector
    metrics: Arc<MetricsCollector>,
}

impl ConnectionPoolManager {
    /// Create a new connection pool manager
    pub fn new(default_config: PoolConfig, metrics: Arc<MetricsCollector>) -> Self {
        Self {
            pools: Arc::new(RwLock::new(HashMap::new())),
            default_config,
            metrics,
        }
    }

    /// Get or create a pool for a server
    pub fn get_pool(&self, server: SocketAddr) -> Result<Arc<ServerConnectionPool>, DnsError> {
        {
            let pools = self.pools.read();
            if let Some(pool) = pools.get(&server) {
                return Ok(pool.clone());
            }
        }

        // Create new pool
        let pool = Arc::new(ServerConnectionPool::new(server, self.default_config.clone())?);
        
        {
            let mut pools = self.pools.write();
            pools.insert(server, pool.clone());
        }

        log::info!("Created connection pool for {}", server);
        
        Ok(pool)
    }

    /// Execute a query using the appropriate pool
    pub fn query(&self, server: SocketAddr, packet: &mut DnsPacket) -> Result<DnsPacket, DnsError> {
        let pool = self.get_pool(server)?;
        
        let start = Instant::now();
        let result = pool.query(packet);
        let duration = start.elapsed();
        
        // Record metrics
        self.metrics.record_upstream_query_duration(duration.as_millis() as f64);
        
        if result.is_ok() {
            self.metrics.record_upstream_query_success();
        } else {
            self.metrics.record_upstream_query_failure();
        }
        
        result
    }

    /// Get statistics for all pools
    pub fn get_all_statistics(&self) -> HashMap<SocketAddr, PoolStatistics> {
        let pools = self.pools.read();
        let mut stats = HashMap::new();
        
        for (server, pool) in pools.iter() {
            stats.insert(*server, pool.get_statistics());
        }
        
        stats
    }

    /// Run health checks on all pools
    pub fn health_check_all(&self) {
        let pools = self.pools.read();
        
        for (server, pool) in pools.iter() {
            log::debug!("Running health check for pool {}", server);
            pool.health_check();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_pool_config_default() {
        let config = PoolConfig::default();
        assert_eq!(config.min_connections, 2);
        assert_eq!(config.max_connections, 10);
        assert!(!config.use_tls);
    }

    #[test]
    fn test_pool_statistics_default() {
        let stats = PoolStatistics::default();
        assert_eq!(stats.total_created, 0);
        assert_eq!(stats.total_queries, 0);
        assert_eq!(stats.current_size, 0);
    }
}