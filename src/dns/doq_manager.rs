//! DNS-over-QUIC (DoQ) Server Manager
//!
//! Manages DoQ server instances, configuration, and metrics collection.
//! Provides a centralized interface for DoQ operations and statistics.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use std::time::{Instant, Duration};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;

use crate::dns::doq::{DoqServer, DoqConfig, DoqConnectionStats};
use crate::dns::context::ServerContext;
use crate::dns::errors::DnsError;

/// DoQ server enhanced statistics with atomic operations
#[derive(Debug)]
pub struct DoqStatistics {
    /// Number of active DoQ connections
    pub active_connections: AtomicUsize,
    /// Total DoQ queries processed
    pub total_queries: AtomicUsize,
    /// DoQ queries per second (moving average)
    pub queries_per_second: AtomicUsize,
    /// Server enabled status
    pub enabled: AtomicBool,
    /// Server port
    pub port: AtomicUsize,
    /// Zero-RTT connections established
    pub zero_rtt_connections: AtomicUsize,
    /// Active QUIC streams
    pub active_streams: AtomicUsize,
    /// Packet loss percentage (multiplied by 100 to store as integer)
    pub packet_loss_x100: AtomicUsize,
    /// Average latency in milliseconds
    pub avg_latency_ms: AtomicUsize,
    /// HTTP/3 enabled status
    pub http3_enabled: AtomicBool,
    /// Connection tracking
    connections: RwLock<HashMap<SocketAddr, Instant>>,
    /// Last QPS calculation time
    last_qps_calc: RwLock<Instant>,
    /// Query count at last QPS calculation
    last_query_count: AtomicUsize,
}

impl Default for DoqStatistics {
    fn default() -> Self {
        Self {
            active_connections: AtomicUsize::new(0),
            total_queries: AtomicUsize::new(0),
            queries_per_second: AtomicUsize::new(0),
            enabled: AtomicBool::new(false),
            port: AtomicUsize::new(853),
            zero_rtt_connections: AtomicUsize::new(0),
            active_streams: AtomicUsize::new(0),
            packet_loss_x100: AtomicUsize::new(0),
            avg_latency_ms: AtomicUsize::new(0),
            http3_enabled: AtomicBool::new(false),
            connections: RwLock::new(HashMap::new()),
            last_qps_calc: RwLock::new(Instant::now()),
            last_query_count: AtomicUsize::new(0),
        }
    }
}

impl DoqStatistics {
    /// Create new DoQ statistics
    pub fn new(port: u16) -> Self {
        Self {
            port: AtomicUsize::new(port as usize),
            ..Default::default()
        }
    }
    
    /// Record a new DoQ connection
    pub fn record_connection(&self, addr: SocketAddr, is_zero_rtt: bool) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.connections.write().insert(addr, Instant::now());
        
        if is_zero_rtt {
            self.zero_rtt_connections.fetch_add(1, Ordering::Relaxed);
        }
    }
    
    /// Record a disconnection
    pub fn record_disconnection(&self, addr: SocketAddr) {
        let prev_count = self.active_connections.fetch_sub(1, Ordering::Relaxed);
        if prev_count > 0 {
            self.connections.write().remove(&addr);
        }
    }
    
    /// Record a DoQ query
    pub fn record_query(&self) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        self.update_qps();
    }
    
    /// Update stream count
    pub fn update_stream_count(&self, count: usize) {
        self.active_streams.store(count, Ordering::Relaxed);
    }
    
    /// Update packet loss percentage
    pub fn update_packet_loss(&self, loss_percent: f64) {
        let loss_x100 = (loss_percent * 100.0) as usize;
        self.packet_loss_x100.store(loss_x100, Ordering::Relaxed);
    }
    
    /// Update average latency
    pub fn update_latency(&self, latency_ms: u64) {
        self.avg_latency_ms.store(latency_ms as usize, Ordering::Relaxed);
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
    
    /// Enable the DoQ server
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
    }
    
    /// Disable the DoQ server
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Relaxed);
    }
    
    /// Enable HTTP/3 support
    pub fn enable_http3(&self) {
        self.http3_enabled.store(true, Ordering::Relaxed);
    }
    
    /// Check if server is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
    
    /// Check if HTTP/3 is enabled
    pub fn is_http3_enabled(&self) -> bool {
        self.http3_enabled.load(Ordering::Relaxed)
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
    
    /// Get zero-RTT connection count
    pub fn get_zero_rtt_connections(&self) -> usize {
        self.zero_rtt_connections.load(Ordering::Relaxed)
    }
    
    /// Get active stream count
    pub fn get_active_streams(&self) -> usize {
        self.active_streams.load(Ordering::Relaxed)
    }
    
    /// Get packet loss percentage
    pub fn get_packet_loss_percent(&self) -> f64 {
        self.packet_loss_x100.load(Ordering::Relaxed) as f64 / 100.0
    }
    
    /// Get average latency in milliseconds
    pub fn get_avg_latency_ms(&self) -> u64 {
        self.avg_latency_ms.load(Ordering::Relaxed) as u64
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
    
    /// Update from DoQ server stats
    pub fn update_from_server_stats(&self, stats: &DoqConnectionStats) {
        self.active_connections.store(stats.active_connections as usize, Ordering::Relaxed);
        self.zero_rtt_connections.store(stats.zero_rtt_connections as usize, Ordering::Relaxed);
        self.active_streams.store(stats.active_streams as usize, Ordering::Relaxed);
        self.update_packet_loss(stats.packet_loss_percent);
        self.update_latency(stats.avg_rtt_ms as u64);
    }
}

/// DoQ Server Manager
pub struct DoqManager {
    /// DoQ server statistics
    pub statistics: Arc<DoqStatistics>,
    /// DoQ server configuration
    config: DoqConfig,
    /// DoQ server instance
    server: Option<Arc<DoqServer>>,
}

impl DoqManager {
    /// Create a new DoQ manager
    pub fn new(config: DoqConfig) -> Self {
        let statistics = Arc::new(DoqStatistics::new(config.port));
        
        Self {
            statistics,
            config,
            server: None,
        }
    }
    
    /// Initialize DoQ server
    pub async fn initialize(&mut self, context: Arc<ServerContext>) -> Result<(), DnsError> {
        if self.config.enabled {
            let mut server = DoqServer::new(context, self.config.clone())?;
            server.initialize().await?;
            self.server = Some(Arc::new(server));
            self.statistics.enable();
            log::info!("DoQ server initialized on port {}", self.config.port);
        } else {
            log::info!("DoQ server disabled in configuration");
        }
        
        Ok(())
    }
    
    /// Start the DoQ server
    pub async fn start(&self) -> Result<(), DnsError> {
        if let Some(server) = &self.server {
            if self.statistics.is_enabled() {
                // Start server in a separate task
                let server_clone = server.clone();
                let stats_clone = self.statistics.clone();
                
                tokio::spawn(async move {
                    log::info!("Starting DoQ server task");
                    if let Err(e) = server_clone.start().await {
                        log::error!("DoQ server error: {:?}", e);
                        stats_clone.disable();
                    }
                });
                
                log::info!("DoQ server started successfully");
                return Ok(());
            }
        }
        
        Err(DnsError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "DoQ server not initialized or disabled"
        )))
    }
    
    /// Stop the DoQ server
    pub fn stop(&self) {
        self.statistics.disable();
        log::info!("DoQ server stopped");
    }
    
    /// Get server configuration
    pub fn get_config(&self) -> &DoqConfig {
        &self.config
    }
    
    /// Update configuration
    pub fn update_config(&mut self, new_config: DoqConfig) {
        self.config = new_config;
        self.statistics.port.store(self.config.port as usize, Ordering::Relaxed);
        
        if self.config.enabled {
            self.statistics.enable();
        } else {
            self.statistics.disable();
        }
    }
    
    /// Get statistics
    pub fn get_statistics(&self) -> Arc<DoqStatistics> {
        self.statistics.clone()
    }
    
    /// Perform periodic maintenance
    pub fn maintenance(&self) {
        self.statistics.cleanup_connections();
        self.statistics.update_qps();
        
        // Update from server stats if available
        if let Some(server) = &self.server {
            let server_stats = server.get_stats();
            self.statistics.update_from_server_stats(&server_stats);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    #[test]
    fn test_doq_statistics_creation() {
        let stats = DoqStatistics::new(853);
        assert_eq!(stats.get_port(), 853);
        assert!(!stats.is_enabled());
        assert_eq!(stats.get_active_connections(), 0);
        assert_eq!(stats.get_total_queries(), 0);
        assert_eq!(stats.get_zero_rtt_connections(), 0);
        assert!(!stats.is_http3_enabled());
    }
    
    #[test]
    fn test_connection_tracking() {
        let stats = DoqStatistics::default();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        
        stats.record_connection(addr, true); // 0-RTT connection
        assert_eq!(stats.get_active_connections(), 1);
        assert_eq!(stats.get_zero_rtt_connections(), 1);
        
        stats.record_disconnection(addr);
        assert_eq!(stats.get_active_connections(), 0);
        assert_eq!(stats.get_zero_rtt_connections(), 1); // Count doesn't decrease
    }
    
    #[test]
    fn test_query_recording() {
        let stats = DoqStatistics::default();
        
        stats.record_query();
        stats.record_query();
        stats.record_query();
        
        assert_eq!(stats.get_total_queries(), 3);
    }
    
    #[test]
    fn test_packet_loss_tracking() {
        let stats = DoqStatistics::default();
        
        stats.update_packet_loss(2.5);
        assert_eq!(stats.get_packet_loss_percent(), 2.5);
        
        stats.update_packet_loss(0.0);
        assert_eq!(stats.get_packet_loss_percent(), 0.0);
    }
    
    #[test]
    fn test_latency_tracking() {
        let stats = DoqStatistics::default();
        
        stats.update_latency(15);
        assert_eq!(stats.get_avg_latency_ms(), 15);
        
        stats.update_latency(8);
        assert_eq!(stats.get_avg_latency_ms(), 8);
    }
    
    #[test]
    fn test_enable_disable() {
        let stats = DoqStatistics::default();
        
        assert!(!stats.is_enabled());
        assert!(!stats.is_http3_enabled());
        
        stats.enable();
        stats.enable_http3();
        assert!(stats.is_enabled());
        assert!(stats.is_http3_enabled());
        
        stats.disable();
        assert!(!stats.is_enabled());
        assert!(stats.is_http3_enabled()); // HTTP/3 stays enabled
    }
    
    #[test]
    fn test_doq_manager_creation() {
        let mut config = DoqConfig::default();
        config.enable_0rtt = true;
        let manager = DoqManager::new(config);
        
        assert_eq!(manager.get_config().port, 853);
        assert!(manager.get_config().enable_0rtt);
        assert!(!manager.statistics.is_enabled());
    }
    
    #[test]
    fn test_config_update() {
        let config = DoqConfig::default();
        let mut manager = DoqManager::new(config);
        
        let mut new_config = DoqConfig::default();
        new_config.enabled = true;
        new_config.port = 8853;
        new_config.enable_0rtt = false;
        
        manager.update_config(new_config);
        
        assert!(manager.statistics.is_enabled());
        assert_eq!(manager.statistics.get_port(), 8853);
        assert!(!manager.get_config().enable_0rtt);
    }
}