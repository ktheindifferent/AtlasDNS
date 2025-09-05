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
use crate::dns::logging::{StructuredLogger, LoggerConfig, QueryLogStorage};
use crate::dns::connection_pool::{ConnectionPoolManager, PoolConfig};
use crate::dns::security::{SecurityManager, SecurityConfig};
use crate::dns::api_keys::ApiKeyManager;
use crate::dns::geodns::{GeoDnsHandler, GeoDnsConfig};
use crate::dns::geo_loadbalancing::GeoLoadBalancer;
use crate::dns::performance_optimizer::{PerformanceOptimizer, PerformanceConfig};
use crate::dns::memory_pool::{BufferPool, MemoryPoolConfig};
use crate::dns::zone_templates::{ZoneTemplatesHandler, ZoneTemplateConfig};
use crate::dns::health::HealthMonitor;
use crate::dns::health_check_analytics::{HealthCheckAnalyticsHandler, HealthCheckConfig};
use crate::dns::traffic_steering::{TrafficSteeringHandler, TrafficSteeringConfig};
use crate::dns::request_limits::RequestLimiter;
use crate::dns::cache_poisoning::CachePoisonProtection;
use crate::metrics::{MetricsManager};

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
///
/// # Configuration String Management
/// 
/// For configuration strings that may be updated at runtime (like `zones_dir`), 
/// this codebase uses `Arc<str>` instead of `&'static str`. This provides:
/// 
/// - **Shared ownership**: Multiple components can hold references to the same string
/// - **Automatic memory management**: Memory is freed when the last reference is dropped
/// - **No memory leaks**: Unlike `Box::leak`, Arc properly deallocates memory
/// - **Thread safety**: Arc is thread-safe and can be shared across threads
/// 
/// Example:
/// ```ignore
/// // DO: Use Arc<str> for runtime-configurable strings
/// pub struct Config {
///     pub path: Arc<str>,
/// }
/// 
/// // DON'T: Use Box::leak (causes memory leaks)
/// config.path = Box::leak(path.into_boxed_str());
/// 
/// // DO: Convert to Arc<str>
/// config.path = Arc::from(path.as_str());
/// ```
pub struct ServerContext {
    pub authority: Authority,
    pub cache: Arc<SynchronizedCache>,
    pub client: Box<dyn DnsClient + Sync + Send>,
    pub dns_port: u16,
    pub api_port: u16,
    pub ssl_api_port: u16,
    pub resolve_strategy: ResolveStrategy,
    pub allow_recursive: bool,
    pub enable_udp: bool,
    pub enable_tcp: bool,
    pub enable_api: bool,
    pub dnssec_enabled: bool,
    pub statistics: ServerStatistics,
    pub zones_dir: Arc<str>,
    pub ssl_config: SslConfig,
    pub metrics: Arc<MetricsCollector>,
    pub logger: Arc<StructuredLogger>,
    pub query_log_storage: Arc<QueryLogStorage>,
    pub connection_pool: Option<Arc<ConnectionPoolManager>>,
    pub security_manager: Arc<SecurityManager>,
    pub api_key_manager: Arc<ApiKeyManager>,
    pub geodns_handler: Arc<GeoDnsHandler>,
    pub geo_load_balancer: Arc<GeoLoadBalancer>,
    pub enhanced_metrics: Option<Arc<MetricsManager>>,
    pub performance_optimizer: Arc<PerformanceOptimizer>,
    pub zone_templates: Arc<ZoneTemplatesHandler>,
    pub health_monitor: Arc<HealthMonitor>,
    pub health_check_analytics: Arc<HealthCheckAnalyticsHandler>,
    pub traffic_steering: Arc<TrafficSteeringHandler>,
    pub request_limiter: Option<Arc<RequestLimiter>>,
    pub cache_poison_protection: Option<Arc<CachePoisonProtection>>,
}

impl Default for ServerContext {
    fn default() -> Self {
        match ServerContext::new() {
            Ok(context) => context,
            Err(e) => {
                // Log the error and then panic with a clearer message
                // This is better than using expect() because we get more context
                log::error!("Failed to create default ServerContext: {}", e);
                log::error!("This is a critical error that prevents the server from starting");
                log::error!("Please check that all required resources are available");
                panic!("ServerContext initialization failed: {}. The server cannot start without a valid context.", e);
            }
        }
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
        
        // Initialize query log storage (store up to 1000 recent queries)
        let query_log_storage = Arc::new(QueryLogStorage::new(1000));
        
        // Initialize memory pool for performance optimization
        use crate::dns::memory_pool::MemoryPoolConfig;
        let buffer_pool = BufferPool::new(MemoryPoolConfig::default());
        
        // Initialize performance optimizer with shared cache
        let shared_cache = Arc::new(SynchronizedCache::new());
        let performance_config = PerformanceConfig::default();
        let performance_optimizer = Arc::new(PerformanceOptimizer::new(
            performance_config,
            shared_cache.clone(),
            buffer_pool.clone(),
        ));
        
        Ok(ServerContext {
            authority: Authority::new(),
            cache: shared_cache,
            client: Box::new(DnsNetworkClient::new(0)?), // Use port 0 to let OS choose available port
            dns_port: 53,
            api_port: 5380,
            ssl_api_port: 5343,
            resolve_strategy: ResolveStrategy::Recursive,
            allow_recursive: true,
            enable_udp: true,
            enable_tcp: true,
            enable_api: true,
            dnssec_enabled: false,
            statistics: ServerStatistics {
                tcp_query_count: AtomicUsize::new(0),
                udp_query_count: AtomicUsize::new(0),
            },
            zones_dir: Arc::from("/opt/atlas/zones"),
            ssl_config: SslConfig::default(),
            metrics: metrics.clone(),
            logger: logger.clone(),
            query_log_storage: query_log_storage.clone(),
            connection_pool: None,
            security_manager: Arc::new(SecurityManager::new(SecurityConfig::default())),
            api_key_manager: Arc::new(ApiKeyManager::new()),
            geodns_handler: Arc::new(GeoDnsHandler::new(GeoDnsConfig::default())),
            geo_load_balancer: Arc::new(GeoLoadBalancer::new()),
            enhanced_metrics: None, // Will be initialized later if metrics DB is available
            performance_optimizer,
            zone_templates: Arc::new(ZoneTemplatesHandler::new(ZoneTemplateConfig::default())),
            health_monitor: Arc::new(HealthMonitor::new()),
            health_check_analytics: Arc::new(HealthCheckAnalyticsHandler::new(HealthCheckConfig::default())),
            traffic_steering: Arc::new(TrafficSteeringHandler::new(TrafficSteeringConfig::default())),
            request_limiter: None, // Will be initialized based on configuration
            cache_poison_protection: None, // Will be initialized based on configuration
        })
    }

    pub fn initialize(&mut self) -> Result<()> {
        // Create zones directory if it doesn't exist
        fs::create_dir_all(&*self.zones_dir)?;

        // Initialize Prometheus metrics
        crate::dns::metrics::initialize_metrics();
        log::info!("Prometheus metrics initialized");

        // Initialize connection pool if using forwarding strategy
        if let ResolveStrategy::Forward { ref host, port } = self.resolve_strategy {
            let pool_config = PoolConfig::default();
            let pool_manager = Arc::new(ConnectionPoolManager::new(
                pool_config.clone(),
                self.metrics.clone(),
            ));
            self.connection_pool = Some(pool_manager.clone());
            
            // Enable connection pooling in the DNS client
            if let Some(client) = self.client.as_any_mut().downcast_mut::<DnsNetworkClient>() {
                client.enable_connection_pooling(pool_config, self.metrics.clone());
                log::info!("Connection pool enabled for DNS client forwarding to {}:{}", host, port);
            }
            
            log::info!("Connection pool initialized for forwarding to {}:{}", host, port);
        }

        // Start UDP client thread
        self.client.run()?;

        // Load authority data
        self.authority.load(&self.zones_dir)?;

        Ok(())
    }

    /// Enable request size limits with custom configuration
    pub fn enable_request_limits(&mut self, config: crate::dns::request_limits::RequestLimitsConfig) {
        let limiter = Arc::new(RequestLimiter::new(config));
        self.request_limiter = Some(limiter);
        log::info!("Request size limits enabled");
    }

    /// Enable request size limits with default configuration
    pub fn enable_default_request_limits(&mut self) {
        let config = crate::dns::request_limits::RequestLimitsConfig::default();
        self.enable_request_limits(config);
    }

    /// Enable cache poisoning protection with custom configuration
    pub fn enable_cache_poison_protection(&mut self, config: crate::dns::cache_poisoning::PoisonProtectionConfig) {
        let protection = Arc::new(CachePoisonProtection::new(config));
        self.cache_poison_protection = Some(protection);
        log::info!("Cache poisoning protection enabled");
    }

    /// Enable cache poisoning protection with default configuration
    pub fn enable_default_cache_poison_protection(&mut self) {
        let config = crate::dns::cache_poisoning::PoisonProtectionConfig::default();
        self.enable_cache_poison_protection(config);
    }

    /// Initialize enhanced metrics system (async)
    pub async fn initialize_enhanced_metrics(&mut self, db_path: Option<&str>) -> Result<()> {
        let path = db_path.unwrap_or(":memory:");
        
        match MetricsManager::new(path).await {
            Ok(manager) => {
                let manager_arc = Arc::new(manager);
                
                // Start background tasks for metrics processing
                manager_arc.start_background_tasks().await;
                
                self.enhanced_metrics = Some(manager_arc);
                log::info!("Enhanced metrics system initialized with database: {}", path);
            }
            Err(e) => {
                log::warn!("Failed to initialize enhanced metrics system: {}", e);
                log::info!("Continuing with basic metrics only");
            }
        }
        
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

    /// Run health checks with upstream server configuration
    pub async fn run_health_checks(&self) {
        let upstream_config = match &self.resolve_strategy {
            ResolveStrategy::Forward { host, port } => Some((host.clone(), *port)),
            ResolveStrategy::Recursive => None,
        };
        
        // Run upstream health check with proper configuration
        self.health_monitor.check_upstream_dns_with_server(upstream_config).await;
        
        // Run other standard health checks
        self.health_monitor.check_memory_usage();
        self.health_monitor.check_error_rates();
        self.health_monitor.check_cache_performance();
    }
}

#[cfg(test)]
pub mod tests {

    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    use crate::dns::authority::Authority;
    use crate::dns::cache::SynchronizedCache;
    use crate::dns::protocol::DnsPacket;

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
            cache: Arc::new(SynchronizedCache::new()),
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
            zones_dir: Arc::from("/opt/atlas/zones"),
            ssl_config: SslConfig::default(),
            metrics: Arc::new(MetricsCollector::new()),
            logger,
            query_log_storage: Arc::new(QueryLogStorage::new(1000)),
            connection_pool: None,
            security_manager: Arc::new(SecurityManager::new(SecurityConfig::default())),
            api_key_manager: Arc::new(ApiKeyManager::new()),
            geodns_handler: Arc::new(GeoDnsHandler::new(GeoDnsConfig::default())),
            geo_load_balancer: Arc::new(GeoLoadBalancer::new()),
            enhanced_metrics: None,
            performance_optimizer: Arc::new(PerformanceOptimizer::new(
                PerformanceConfig::default(),
                Arc::new(SynchronizedCache::new()),
                BufferPool::new(crate::dns::memory_pool::MemoryPoolConfig::default()),
            )),
            zone_templates: Arc::new(ZoneTemplatesHandler::new(ZoneTemplateConfig::default())),
            health_monitor: Arc::new(HealthMonitor::new()),
        })
    }

    #[test]
    fn test_zones_dir_memory_management() {
        use std::sync::Arc;
        
        // Test that zones_dir uses Arc for shared ownership
        let ctx1 = create_test_context(Box::new(|_, _, _, _| Ok(DnsPacket::new())));
        let zones_dir1 = ctx1.zones_dir.clone();
        
        // Create another reference to the same Arc
        let zones_dir2 = zones_dir1.clone();
        
        // Both should point to the same memory
        assert!(Arc::ptr_eq(&zones_dir1, &zones_dir2));
        
        // Test that we can update zones_dir without leaking memory
        let mut ctx2 = ServerContext::new().unwrap();
        let original_dir = ctx2.zones_dir.clone();
        ctx2.zones_dir = Arc::from("/tmp/new_zones");
        
        // The original Arc will be dropped when no longer referenced
        assert_eq!(&*ctx2.zones_dir, "/tmp/new_zones");
        assert_eq!(&*original_dir, "/opt/atlas/zones");
    }

    #[test]
    fn test_zones_dir_update_from_cmdline() {
        // Test that zones_dir can be updated from command line args
        let mut ctx = ServerContext::new().unwrap();
        assert_eq!(&*ctx.zones_dir, "/opt/atlas/zones");
        
        // Simulate command line update
        let new_dir = String::from("/custom/zones/path");
        ctx.zones_dir = Arc::from(new_dir.as_str());
        assert_eq!(&*ctx.zones_dir, "/custom/zones/path");
        
        // Memory for the old Arc will be automatically freed
    }
}
