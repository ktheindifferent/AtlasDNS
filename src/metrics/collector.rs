//! Real-time metrics collection implementation

use super::{DnsQueryMetric, SystemMetric, SecurityEvent};
use crate::metrics::storage::MetricsStorage;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, Instant};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use sysinfo::{System, SystemExt, ProcessExt, NetworkExt, CpuExt};

/// Metrics snapshot at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub timestamp: SystemTime,
    pub query_count: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub avg_response_time_ms: f64,
    pub unique_clients: usize,
    pub query_types: HashMap<String, u64>,
    pub response_codes: HashMap<String, u64>,
    pub protocols: HashMap<String, u64>,
    pub top_domains: Vec<(String, u64)>,
    pub system_metrics: SystemMetricSnapshot,
}

/// System metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetricSnapshot {
    pub cpu_usage: f64,
    pub memory_usage_mb: u64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub active_connections: u32,
    pub cache_entries: u64,
}

/// Sliding window for rate calculations
struct SlidingWindow<T: Clone> {
    window_size: Duration,
    entries: Vec<(Instant, T)>,
}

impl<T: Clone> SlidingWindow<T> {
    fn new(window_size: Duration) -> Self {
        Self {
            window_size,
            entries: Vec::new(),
        }
    }

    fn add(&mut self, value: T) {
        let now = Instant::now();
        self.entries.push((now, value));
        self.cleanup();
    }

    fn cleanup(&mut self) {
        let cutoff = Instant::now() - self.window_size;
        self.entries.retain(|(time, _)| *time > cutoff);
    }

    fn count(&mut self) -> usize {
        self.cleanup();
        self.entries.len()
    }

    fn get_all(&mut self) -> Vec<T> {
        self.cleanup();
        self.entries.iter().map(|(_, v)| v.clone()).collect()
    }
}

/// Real-time metrics collector
pub struct MetricsCollector {
    storage: Arc<MetricsStorage>,
    
    // Real-time counters
    total_queries: Arc<RwLock<u64>>,
    cache_hits: Arc<RwLock<u64>>,
    cache_misses: Arc<RwLock<u64>>,
    
    // Sliding windows for rate calculations
    recent_queries: Arc<RwLock<SlidingWindow<DnsQueryMetric>>>,
    recent_response_times: Arc<RwLock<SlidingWindow<f64>>>,
    
    // Aggregated data
    unique_clients: Arc<RwLock<HashMap<String, Instant>>>,
    query_types: Arc<RwLock<HashMap<String, u64>>>,
    response_codes: Arc<RwLock<HashMap<String, u64>>>,
    protocols: Arc<RwLock<HashMap<String, u64>>>,
    domain_counts: Arc<RwLock<HashMap<String, u64>>>,
    
    // System metrics
    system: Arc<RwLock<System>>,
    network_baseline: Arc<RwLock<(u64, u64)>>,
    
    // Security events
    security_events: Arc<RwLock<Vec<SecurityEvent>>>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(storage: Arc<MetricsStorage>) -> Self {
        let mut system = System::new_all();
        system.refresh_all();
        
        // Get initial network stats
        let (rx, tx) = Self::get_network_stats(&system);
        
        Self {
            storage,
            total_queries: Arc::new(RwLock::new(0)),
            cache_hits: Arc::new(RwLock::new(0)),
            cache_misses: Arc::new(RwLock::new(0)),
            recent_queries: Arc::new(RwLock::new(SlidingWindow::new(Duration::from_secs(300)))),
            recent_response_times: Arc::new(RwLock::new(SlidingWindow::new(Duration::from_secs(60)))),
            unique_clients: Arc::new(RwLock::new(HashMap::new())),
            query_types: Arc::new(RwLock::new(HashMap::new())),
            response_codes: Arc::new(RwLock::new(HashMap::new())),
            protocols: Arc::new(RwLock::new(HashMap::new())),
            domain_counts: Arc::new(RwLock::new(HashMap::new())),
            system: Arc::new(RwLock::new(system)),
            network_baseline: Arc::new(RwLock::new((rx, tx))),
            security_events: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Record a DNS query
    pub async fn record_query(&self, metric: DnsQueryMetric) {
        // Update counters
        *self.total_queries.write().await += 1;
        
        if metric.cache_hit {
            *self.cache_hits.write().await += 1;
        } else {
            *self.cache_misses.write().await += 1;
        }
        
        // Update sliding windows
        self.recent_queries.write().await.add(metric.clone());
        self.recent_response_times.write().await.add(metric.response_time_ms);
        
        // Update unique clients (with 1 hour expiry)
        let mut clients = self.unique_clients.write().await;
        clients.insert(metric.client_ip.clone(), Instant::now());
        let cutoff = Instant::now() - Duration::from_secs(3600);
        clients.retain(|_, time| *time > cutoff);
        
        // Update aggregations
        *self.query_types.write().await.entry(metric.query_type.clone()).or_insert(0) += 1;
        *self.response_codes.write().await.entry(metric.response_code.clone()).or_insert(0) += 1;
        *self.protocols.write().await.entry(metric.protocol.clone()).or_insert(0) += 1;
        *self.domain_counts.write().await.entry(metric.domain.clone()).or_insert(0) += 1;
        
        // Store in database
        let _ = self.storage.store_query_metric(&metric).await;
    }

    /// Record a security event
    pub async fn record_security_event(&self, event: SecurityEvent) {
        self.security_events.write().await.push(event.clone());
        let _ = self.storage.store_security_event(&event).await;
    }

    /// Get current metrics snapshot
    pub async fn get_snapshot(&self) -> Result<MetricsSnapshot, Box<dyn std::error::Error>> {
        // Calculate average response time
        let response_times = self.recent_response_times.read().await;
        let times: Vec<f64> = response_times.entries.iter().map(|(_, t)| *t).collect();
        let avg_response_time = if !times.is_empty() {
            times.iter().sum::<f64>() / times.len() as f64
        } else {
            0.0
        };

        // Get top domains
        let domain_counts = self.domain_counts.read().await;
        let mut top_domains: Vec<(String, u64)> = domain_counts
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        top_domains.sort_by(|a, b| b.1.cmp(&a.1));
        top_domains.truncate(10);

        // Get system metrics
        let system_metrics = self.get_system_metrics().await;

        Ok(MetricsSnapshot {
            timestamp: SystemTime::now(),
            query_count: *self.total_queries.read().await,
            cache_hits: *self.cache_hits.read().await,
            cache_misses: *self.cache_misses.read().await,
            avg_response_time_ms: avg_response_time,
            unique_clients: self.unique_clients.read().await.len(),
            query_types: self.query_types.read().await.clone(),
            response_codes: self.response_codes.read().await.clone(),
            protocols: self.protocols.read().await.clone(),
            top_domains,
            system_metrics,
        })
    }

    /// Get current system metrics
    async fn get_system_metrics(&self) -> SystemMetricSnapshot {
        let mut system = self.system.write().await;
        system.refresh_all();
        
        // Calculate CPU usage
        let cpu_usage = system.global_cpu_info().cpu_usage() as f64;
        
        // Calculate memory usage
        let memory_usage_mb = (system.used_memory() / 1024) as u64;
        
        // Get network stats
        let (rx, tx) = Self::get_network_stats(&system);
        let baseline = self.network_baseline.read().await;
        let network_rx_bytes = rx.saturating_sub(baseline.0);
        let network_tx_bytes = tx.saturating_sub(baseline.1);
        
        SystemMetricSnapshot {
            cpu_usage,
            memory_usage_mb,
            network_rx_bytes,
            network_tx_bytes,
            active_connections: 0, // Will be updated from connection pool
            cache_entries: 0, // Will be updated from cache
        }
    }

    /// Get network statistics from system
    fn get_network_stats(system: &System) -> (u64, u64) {
        let mut total_rx = 0u64;
        let mut total_tx = 0u64;
        
        for (_, network) in system.networks() {
            total_rx += network.received();
            total_tx += network.transmitted();
        }
        
        (total_rx, total_tx)
    }

    /// Update active connection count
    pub async fn update_active_connections(&self, count: u32) {
        // This will be called by the connection pool
    }

    /// Update cache entry count
    pub async fn update_cache_entries(&self, count: u64) {
        // This will be called by the cache manager
    }

    /// Get percentile response times
    pub async fn get_response_time_percentiles(&self) -> HashMap<String, f64> {
        let mut times = self.recent_response_times.write().await.get_all();
        if times.is_empty() {
            return HashMap::new();
        }

        times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        
        let mut percentiles = HashMap::new();
        let len = times.len();
        
        percentiles.insert("p50".to_string(), times[len * 50 / 100]);
        percentiles.insert("p90".to_string(), times[len * 90 / 100]);
        percentiles.insert("p95".to_string(), times[len * 95 / 100]);
        percentiles.insert("p99".to_string(), times[len * 99 / 100]);
        
        percentiles
    }

    /// Get query rate (queries per second) over the last minute
    pub async fn get_query_rate(&self) -> f64 {
        let count = self.recent_queries.write().await.count();
        count as f64 / 60.0
    }

    /// Get cache hit rate
    pub async fn get_cache_hit_rate(&self) -> f64 {
        let hits = *self.cache_hits.read().await;
        let misses = *self.cache_misses.read().await;
        let total = hits + misses;
        
        if total > 0 {
            (hits as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    }

    /// Get recent security events
    pub async fn get_recent_security_events(&self, limit: usize) -> Vec<SecurityEvent> {
        let events = self.security_events.read().await;
        let start = events.len().saturating_sub(limit);
        events[start..].to_vec()
    }

    /// Clear old data from memory (but not from storage)
    pub async fn cleanup_memory(&self) {
        // Clean up unique clients older than 1 hour
        let cutoff = Instant::now() - Duration::from_secs(3600);
        self.unique_clients.write().await.retain(|_, time| *time > cutoff);
        
        // Keep only recent security events in memory (last 1000)
        let mut events = self.security_events.write().await;
        if events.len() > 1000 {
            let start = events.len() - 1000;
            *events = events[start..].to_vec();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_collector() {
        let storage = Arc::new(MetricsStorage::new(":memory:").await.unwrap());
        let collector = MetricsCollector::new(storage);

        // Record a query
        let metric = DnsQueryMetric {
            timestamp: SystemTime::now(),
            domain: "example.com".to_string(),
            query_type: "A".to_string(),
            client_ip: "192.168.1.1".to_string(),
            response_code: "NOERROR".to_string(),
            response_time_ms: 10.5,
            cache_hit: true,
            protocol: "UDP".to_string(),
            upstream_server: None,
            dnssec_validated: None,
        };

        collector.record_query(metric).await;

        // Check snapshot
        let snapshot = collector.get_snapshot().await.unwrap();
        assert_eq!(snapshot.query_count, 1);
        assert_eq!(snapshot.cache_hits, 1);
        assert_eq!(snapshot.unique_clients, 1);
    }

    #[tokio::test]
    async fn test_cache_hit_rate() {
        let storage = Arc::new(MetricsStorage::new(":memory:").await.unwrap());
        let collector = MetricsCollector::new(storage);

        // Record some hits and misses
        for i in 0..7 {
            let metric = DnsQueryMetric {
                timestamp: SystemTime::now(),
                domain: format!("example{}.com", i),
                query_type: "A".to_string(),
                client_ip: "192.168.1.1".to_string(),
                response_code: "NOERROR".to_string(),
                response_time_ms: 10.0,
                cache_hit: i < 5, // 5 hits, 2 misses
                protocol: "UDP".to_string(),
                upstream_server: None,
                dnssec_validated: None,
            };
            collector.record_query(metric).await;
        }

        let hit_rate = collector.get_cache_hit_rate().await;
        assert!((hit_rate - 71.4).abs() < 1.0); // ~71.4% hit rate
    }
}