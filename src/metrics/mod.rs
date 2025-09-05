//! Real-time Metrics Collection and Analytics System
//!
//! This module provides comprehensive metrics collection, storage, and analytics
//! for the Atlas DNS server. It replaces mock data with real operational metrics.

pub mod collector;
pub mod storage;
pub mod aggregator;
pub mod streaming;
pub mod geoip;

pub use collector::{MetricsCollector, MetricsSnapshot};
pub use storage::{MetricsStorage, TimeSeriesData};
pub use aggregator::{MetricsAggregator, AggregatedMetrics, TimeRange, AggregationInterval};
pub use streaming::{MetricsStream, MetricsSubscriber};
pub use geoip::{GeoIpAnalyzer, GeographicDistribution};

use std::sync::Arc;
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};

/// Centralized metrics manager that coordinates all metrics operations
pub struct MetricsManager {
    collector: Arc<MetricsCollector>,
    storage: Arc<MetricsStorage>,
    aggregator: Arc<MetricsAggregator>,
    stream: Arc<MetricsStream>,
    geoip: Arc<GeoIpAnalyzer>,
}

impl MetricsManager {
    /// Create a new metrics manager with default configuration
    pub async fn new(db_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let storage = Arc::new(MetricsStorage::new(db_path).await?);
        let collector = Arc::new(MetricsCollector::new(storage.clone()));
        let aggregator = Arc::new(MetricsAggregator::new(storage.clone()));
        let stream = Arc::new(MetricsStream::new());
        let geoip = Arc::new(GeoIpAnalyzer::new()?);

        Ok(Self {
            collector,
            storage,
            aggregator,
            stream,
            geoip,
        })
    }

    /// Get the metrics collector for recording metrics
    pub fn collector(&self) -> Arc<MetricsCollector> {
        self.collector.clone()
    }

    /// Get the metrics aggregator for analytics
    pub fn aggregator(&self) -> Arc<MetricsAggregator> {
        self.aggregator.clone()
    }

    /// Get the metrics stream for real-time updates
    pub fn stream(&self) -> Arc<MetricsStream> {
        self.stream.clone()
    }

    /// Get the GeoIP analyzer for geographic analytics
    pub fn geoip(&self) -> Arc<GeoIpAnalyzer> {
        self.geoip.clone()
    }

    /// Start background tasks for metrics processing
    pub async fn start_background_tasks(&self) {
        let storage = self.storage.clone();
        let stream = self.stream.clone();
        let collector = self.collector.clone();

        // Task for periodic metric aggregation (every 10 seconds)
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                match collector.get_snapshot().await {
                    Ok(snapshot) => {
                        let _ = storage.store_snapshot(&snapshot).await;
                        stream.broadcast_update(&snapshot).await;
                    }
                    Err(_) => {
                        // Log error or handle it appropriately
                    }
                }
            }
        });

        // Task for periodic cleanup (every hour)
        let storage_cleanup = self.storage.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600));
            loop {
                interval.tick().await;
                let _ = storage_cleanup.cleanup_old_data().await;
            }
        });
    }
}

/// DNS query metric data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryMetric {
    pub timestamp: SystemTime,
    pub domain: String,
    pub query_type: String,
    pub client_ip: String,
    pub response_code: String,
    pub response_time_ms: f64,
    pub cache_hit: bool,
    pub protocol: String,
    pub upstream_server: Option<String>,
    pub dnssec_validated: Option<bool>,
}

/// System metric data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetric {
    pub timestamp: SystemTime,
    pub cpu_usage: f64,
    pub memory_usage_mb: u64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub active_connections: u32,
    pub cache_entries: u64,
}

/// Query type distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryTypeDistribution {
    pub query_type: String,
    pub count: u64,
    pub percentage: f64,
}

/// Response code distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseCodeDistribution {
    pub response_code: String,
    pub count: u64,
    pub percentage: f64,
}

/// Top queried domain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopDomain {
    pub domain: String,
    pub query_count: u64,
    pub unique_clients: u32,
}

/// Security event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp: SystemTime,
    pub event_type: String,
    pub source_ip: String,
    pub target_domain: Option<String>,
    pub action_taken: String,
    pub severity: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_manager_creation() {
        let manager = MetricsManager::new(":memory:").await.unwrap();
        assert!(Arc::strong_count(&manager.collector) > 0);
    }
}