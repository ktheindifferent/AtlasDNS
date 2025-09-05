//! DNS-over-TLS (DoT) Server Manager
//!
//! Manages DoT server instances, configuration, and metrics collection.
//! Provides a centralized interface for DoT operations and statistics.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use std::time::{Instant, Duration};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;

use crate::dns::dot::{DotServer, DotConfig};
use crate::dns::context::ServerContext;
use crate::dns::errors::DnsError;

/// DoT server statistics
#[derive(Debug)]
pub struct DotStatistics {
    /// Number of active DoT connections
    pub active_connections: AtomicUsize,
    /// Total DoT queries processed
    pub total_queries: AtomicUsize,
    /// DoT queries per second (moving average)
    pub queries_per_second: AtomicUsize,
    /// Server enabled status
    pub enabled: AtomicBool,
    /// Server port
    pub port: AtomicUsize,
    /// Current TLS version in use
    tls_version: RwLock<String>,
    /// Connection tracking
    connections: RwLock<HashMap<SocketAddr, Instant>>,
    /// Last QPS calculation time
    last_qps_calc: RwLock<Instant>,
    /// Query count at last QPS calculation
    last_query_count: AtomicUsize,
}

impl Default for DotStatistics {
    fn default() -> Self {
        Self {
            active_connections: AtomicUsize::new(0),
            total_queries: AtomicUsize::new(0),
            queries_per_second: AtomicUsize::new(0),
            enabled: AtomicBool::new(false),
            port: AtomicUsize::new(853),
            tls_version: RwLock::new("TLS 1.3".to_string()),
            connections: RwLock::new(HashMap::new()),
            last_qps_calc: RwLock::new(Instant::now()),
            last_query_count: AtomicUsize::new(0),
        }
    }
}

impl DotStatistics {
    /// Create new DoT statistics
    pub fn new(port: u16) -> Self {
        Self {
            port: AtomicUsize::new(port as usize),
            ..Default::default()
        }
    }
    
    /// Record a new DoT connection
    pub fn record_connection(&self, addr: SocketAddr) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.connections.write().insert(addr, Instant::now());
    }
    
    /// Record a disconnection
    pub fn record_disconnection(&self, addr: SocketAddr) {
        let prev_count = self.active_connections.fetch_sub(1, Ordering::Relaxed);
        if prev_count > 0 {
            self.connections.write().remove(&addr);
        }
    }
    
    /// Record a DoT query
    pub fn record_query(&self) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        self.update_qps();
    }
    
    /// Update queries per second calculation
    fn update_qps(&self) {
        let now = Instant::now();
        let mut last_calc = self.last_qps_calc.write();
        
        if now.duration_since(*last_calc) >= Duration::from_secs(1) {
            let current_count = self.total_queries.load(Ordering::Relaxed);
            let last_count = self.last_query_count.load(Ordering::Relaxed);
            
            let elapsed_secs = now.duration_since(*last_calc).as_secs();
            if elapsed_secs > 0 {
                let qps = (current_count - last_count) / elapsed_secs as usize;
                self.queries_per_second.store(qps, Ordering::Relaxed);
            }
            
            *last_calc = now;
            self.last_query_count.store(current_count, Ordering::Relaxed);
        }
    }
    
    /// Enable the DoT server
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
    }
    
    /// Disable the DoT server
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Relaxed);
    }
    
    /// Check if server is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
    
    /// Get active connection count
    pub fn get_active_connections(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }
    
    /// Get total queries processed
    pub fn get_total_queries(&self) -> usize {
        self.total_queries.load(Ordering::Relaxed)
    }
    
    /// Get current queries per second
    pub fn get_qps(&self) -> usize {
        self.queries_per_second.load(Ordering::Relaxed)
    }
    
    /// Get server port
    pub fn get_port(&self) -> u16 {
        self.port.load(Ordering::Relaxed) as u16
    }
    
    /// Get TLS version
    pub fn get_tls_version(&self) -> String {
        self.tls_version.read().clone()
    }
    
    /// Set TLS version
    pub fn set_tls_version(&self, version: String) {
        *self.tls_version.write() = version;
    }
    
    /// Clean up old connections
    pub fn cleanup_connections(&self) {
        let mut connections = self.connections.write();
        let now = Instant::now();
        let timeout = Duration::from_secs(300); // 5 minute timeout
        
        connections.retain(|_, &mut last_seen| {
            now.duration_since(last_seen) < timeout
        });
        
        // Update active connection count
        self.active_connections.store(connections.len(), Ordering::Relaxed);
    }
}

/// DoT Server Manager
pub struct DotManager {
    /// DoT server statistics
    pub statistics: Arc<DotStatistics>,
    /// DoT server configuration
    config: DotConfig,
    /// DoT server instance
    server: Option<Arc<DotServer>>,
}

impl DotManager {
    /// Create a new DoT manager
    pub fn new(config: DotConfig) -> Self {
        let statistics = Arc::new(DotStatistics::new(config.port));
        
        Self {
            statistics,
            config,
            server: None,
        }
    }
    
    /// Initialize DoT server
    pub fn initialize(&mut self, context: Arc<ServerContext>) -> Result<(), DnsError> {
        if self.config.enabled {
            let server = DotServer::new(context, self.config.clone())?;
            self.server = Some(Arc::new(server));
            self.statistics.enable();
            log::info!("DoT server initialized on port {}", self.config.port);
        } else {
            log::info!("DoT server disabled in configuration");
        }
        
        Ok(())
    }
    
    /// Start the DoT server
    pub fn start(&self) -> Result<(), DnsError> {
        if let Some(server) = &self.server {
            if self.statistics.is_enabled() {
                // Start server in a separate thread
                let server_clone = server.clone();
                let stats_clone = self.statistics.clone();
                
                std::thread::spawn(move || {
                    log::info!("Starting DoT server thread");
                    if let Err(e) = server_clone.run() {
                        log::error!("DoT server error: {:?}", e);
                        stats_clone.disable();
                    }
                });
                
                log::info!("DoT server started successfully");
                return Ok(());
            }
        }
        
        Err(DnsError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "DoT server not initialized or disabled"
        )))
    }
    
    /// Stop the DoT server
    pub fn stop(&self) {
        self.statistics.disable();
        log::info!("DoT server stopped");
    }
    
    /// Get server configuration
    pub fn get_config(&self) -> &DotConfig {
        &self.config
    }
    
    /// Update configuration
    pub fn update_config(&mut self, new_config: DotConfig) {
        self.config = new_config;
        self.statistics.port.store(self.config.port as usize, Ordering::Relaxed);
        
        if self.config.enabled {
            self.statistics.enable();
        } else {
            self.statistics.disable();
        }
    }
    
    /// Get statistics
    pub fn get_statistics(&self) -> Arc<DotStatistics> {
        self.statistics.clone()
    }
    
    /// Perform periodic maintenance
    pub fn maintenance(&self) {
        self.statistics.cleanup_connections();
        self.statistics.update_qps();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    #[test]
    fn test_dot_statistics_creation() {
        let stats = DotStatistics::new(853);
        assert_eq!(stats.get_port(), 853);
        assert!(!stats.is_enabled());
        assert_eq!(stats.get_active_connections(), 0);
        assert_eq!(stats.get_total_queries(), 0);
    }
    
    #[test]
    fn test_connection_tracking() {
        let stats = DotStatistics::default();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        
        stats.record_connection(addr);
        assert_eq!(stats.get_active_connections(), 1);
        
        stats.record_disconnection(addr);
        assert_eq!(stats.get_active_connections(), 0);
    }
    
    #[test]
    fn test_query_recording() {
        let stats = DotStatistics::default();
        
        stats.record_query();
        stats.record_query();
        stats.record_query();
        
        assert_eq!(stats.get_total_queries(), 3);
    }
    
    #[test]
    fn test_enable_disable() {
        let stats = DotStatistics::default();
        
        assert!(!stats.is_enabled());
        
        stats.enable();
        assert!(stats.is_enabled());
        
        stats.disable();
        assert!(!stats.is_enabled());
    }
    
    #[test]
    fn test_tls_version() {
        let stats = DotStatistics::default();
        
        assert_eq!(stats.get_tls_version(), "TLS 1.3");
        
        stats.set_tls_version("TLS 1.2".to_string());
        assert_eq!(stats.get_tls_version(), "TLS 1.2");
    }
    
    #[test]
    fn test_dot_manager_creation() {
        let config = DotConfig::default();
        let manager = DotManager::new(config);
        
        assert_eq!(manager.get_config().port, 853);
        assert!(!manager.statistics.is_enabled());
    }
    
    #[test]
    fn test_config_update() {
        let mut config = DotConfig::default();
        let mut manager = DotManager::new(config.clone());
        
        config.enabled = true;
        config.port = 8853;
        
        manager.update_config(config);
        
        assert!(manager.statistics.is_enabled());
        assert_eq!(manager.statistics.get_port(), 8853);
    }
}