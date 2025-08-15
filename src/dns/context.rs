//! The `ServerContext in this thread holds the common state across the server

use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use derive_more::{Display, Error, From};

use crate::dns::authority::Authority;
use crate::dns::cache::SynchronizedCache;
use crate::dns::client::{DnsClient, DnsNetworkClient};
use crate::dns::resolve::{DnsResolver, ForwardingDnsResolver, RecursiveDnsResolver};
use crate::dns::acme::SslConfig;
use crate::dns::metrics::MetricsCollector;
use crate::dns::logging::{StructuredLogger, LoggerConfig};
use crate::dns::connection_pool::{ConnectionPoolManager, PoolConfig};

#[derive(Debug, Display, From, Error)]
pub enum ContextError {
    Authority(crate::dns::authority::AuthorityError),
    Client(crate::dns::client::ClientError),
    Io(std::io::Error),
}

type Result<T> = std::result::Result<T, ContextError>;

pub struct ServerStatistics {
    pub tcp_query_count: AtomicUsize,
    pub udp_query_count: AtomicUsize,
}

impl ServerStatistics {
    pub fn get_tcp_query_count(&self) -> usize {
        self.tcp_query_count.load(Ordering::Acquire)
    }

    pub fn get_udp_query_count(&self) -> usize {
        self.udp_query_count.load(Ordering::Acquire)
    }
}

/// DNS resolution strategy configuration
#[derive(Clone, Debug, PartialEq)]
pub enum ResolveStrategy {
    /// Perform recursive resolution starting from root servers
    Recursive,
    /// Forward all queries to an upstream DNS server
    Forward { host: String, port: u16 },
}

/// Main server context containing configuration and shared state
/// 
/// This struct holds all the configuration and runtime state needed by the DNS server,
/// including the authority zones, cache, resolution strategy, and server settings.
pub struct ServerContext {
    pub authority: Authority,
    pub cache: SynchronizedCache,
    pub client: Box<dyn DnsClient + Sync + Send>,
    pub dns_port: u16,
    pub api_port: u16,
    pub ssl_api_port: u16,
    pub resolve_strategy: ResolveStrategy,
    pub allow_recursive: bool,
    pub enable_udp: bool,
    pub enable_tcp: bool,
    pub enable_api: bool,
    pub statistics: ServerStatistics,
    pub zones_dir: &'static str,
    pub ssl_config: SslConfig,
    pub metrics: Arc<MetricsCollector>,
    pub logger: Arc<StructuredLogger>,
    pub connection_pool: Option<Arc<ConnectionPoolManager>>,
}

impl Default for ServerContext {
    fn default() -> Self {
        ServerContext::new().expect("Failed to create default ServerContext")
    }
}

impl ServerContext {
    pub fn new() -> Result<ServerContext> {
        let metrics = Arc::new(MetricsCollector::new());
        
        // Initialize structured logger
        let logger_config = LoggerConfig::default();
        let logger = Arc::new(StructuredLogger::init(logger_config)
            .map_err(|e| ContextError::Io(std::io::Error::new(
                std::io::ErrorKind::Other, 
                format!("Failed to initialize logger: {}", e)
            )))?);
        
        Ok(ServerContext {
            authority: Authority::new(),
            cache: SynchronizedCache::new(),
            client: Box::new(DnsNetworkClient::new(0)?), // Use port 0 to let OS choose available port
            dns_port: 53,
            api_port: 5380,
            ssl_api_port: 5343,
            resolve_strategy: ResolveStrategy::Recursive,
            allow_recursive: true,
            enable_udp: true,
            enable_tcp: true,
            enable_api: true,
            statistics: ServerStatistics {
                tcp_query_count: AtomicUsize::new(0),
                udp_query_count: AtomicUsize::new(0),
            },
            zones_dir: "/opt/atlas/zones",
            ssl_config: SslConfig::default(),
            metrics: metrics.clone(),
            logger,
            connection_pool: None,
        })
    }

    pub fn initialize(&mut self) -> Result<()> {
        // Create zones directory if it doesn't exist
        fs::create_dir_all(self.zones_dir)?;

        // Initialize Prometheus metrics
        crate::dns::metrics::initialize_metrics();
        log::info!("Prometheus metrics initialized");

        // Initialize connection pool if using forwarding strategy
        if let ResolveStrategy::Forward { ref host, port } = self.resolve_strategy {
            let pool_config = PoolConfig::default();
            let pool_manager = Arc::new(ConnectionPoolManager::new(
                pool_config,
                self.metrics.clone(),
            ));
            self.connection_pool = Some(pool_manager);
            log::info!("Connection pool initialized for forwarding to {}:{}", host, port);
        }

        // Start UDP client thread
        self.client.run()?;

        // Load authority data
        self.authority.load()?;

        Ok(())
    }

    pub fn create_resolver(&self, ptr: Arc<ServerContext>) -> Box<dyn DnsResolver> {
        match self.resolve_strategy {
            ResolveStrategy::Recursive => Box::new(RecursiveDnsResolver::new(ptr)),
            ResolveStrategy::Forward { ref host, port } => {
                Box::new(ForwardingDnsResolver::new(ptr, (host.clone(), port)))
            }
        }
    }
}

#[cfg(test)]
pub mod tests {

    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    use crate::dns::authority::Authority;
    use crate::dns::cache::SynchronizedCache;

    use crate::dns::client::tests::{DnsStubClient, StubCallback};

    use super::*;

    pub fn create_test_context(callback: Box<StubCallback>) -> Arc<ServerContext> {
        let logger_config = LoggerConfig {
            console_output: false, // Disable console output in tests
            file_output: None,     // No file output in tests
            ..LoggerConfig::default()
        };
        let logger = Arc::new(StructuredLogger::init(logger_config).unwrap());
        
        Arc::new(ServerContext {
            authority: Authority::new(),
            cache: SynchronizedCache::new(),
            client: Box::new(DnsStubClient::new(callback)),
            dns_port: 53,
            api_port: 5380,
            ssl_api_port: 5343,
            resolve_strategy: ResolveStrategy::Recursive,
            allow_recursive: true,
            enable_udp: true,
            enable_tcp: true,
            enable_api: true,
            statistics: ServerStatistics {
                tcp_query_count: AtomicUsize::new(0),
                udp_query_count: AtomicUsize::new(0),
            },
            zones_dir: "/opt/atlas/zones",
            ssl_config: SslConfig::default(),
            metrics: Arc::new(MetricsCollector::new()),
            logger,
            connection_pool: None,
        })
    }
}
