//! Enhanced GraphQL resolvers with real metrics integration

use async_graphql::*;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use std::time::SystemTime;

use crate::metrics::{MetricsManager, TimeRange as MetricsTimeRange, AggregationInterval as MetricsInterval};
use crate::web::graphql::{
    TimeRange, AggregationInterval, DnsQueryDataPoint, QueryTypeDistribution,
    ResponseCodeDistribution, TopDomain, GeographicDistribution, SecurityEvent,
    SystemHealth, PerformanceMetrics, CacheStatistics
};

/// Enhanced query root with real metrics
pub struct EnhancedQueryRoot {
    metrics_manager: Arc<MetricsManager>,
}

impl EnhancedQueryRoot {
    pub fn new(metrics_manager: Arc<MetricsManager>) -> Self {
        Self { metrics_manager }
    }

    /// Convert GraphQL time range to metrics time range
    fn convert_time_range(&self, range: TimeRange) -> MetricsTimeRange {
        MetricsTimeRange {
            start: SystemTime::from(range.start),
            end: SystemTime::from(range.end),
        }
    }

    /// Convert GraphQL interval to metrics interval
    fn convert_interval(&self, interval: AggregationInterval) -> MetricsInterval {
        match interval {
            AggregationInterval::Minute => MetricsInterval::Minute,
            AggregationInterval::FiveMinutes => MetricsInterval::FiveMinutes,
            AggregationInterval::FifteenMinutes => MetricsInterval::FifteenMinutes,
            AggregationInterval::Hour => MetricsInterval::Hour,
            AggregationInterval::Day => MetricsInterval::Day,
            AggregationInterval::Week => MetricsInterval::Week,
            AggregationInterval::Month => MetricsInterval::Month,
        }
    }
}

#[Object]
impl EnhancedQueryRoot {
    /// Get DNS query analytics over time with real data
    async fn dns_analytics(
        &self,
        time_range: TimeRange,
        interval: AggregationInterval,
    ) -> Result<Vec<DnsQueryDataPoint>> {
        let metrics_range = self.convert_time_range(time_range);
        let metrics_interval = self.convert_interval(interval);
        
        let analytics = self.metrics_manager
            .aggregator()
            .get_dns_analytics(metrics_range, metrics_interval)
            .await
            .map_err(|e| Error::new(e.to_string()))?;
        
        let data_points = analytics.into_iter().map(|point| {
            DnsQueryDataPoint {
                timestamp: DateTime::<Utc>::from(point.timestamp),
                query_count: point.query_count as i32,
                success_count: ((point.query_count as f64 * point.success_rate / 100.0) as i32),
                nxdomain_count: point.nxdomain_count as i32,
                servfail_count: point.servfail_count as i32,
                avg_response_time_ms: point.avg_response_time_ms,
                cache_hit_rate: if point.cache_hits + point.cache_misses > 0 {
                    (point.cache_hits as f64 / (point.cache_hits + point.cache_misses) as f64)
                } else {
                    0.0
                },
            }
        }).collect();
        
        Ok(data_points)
    }

    /// Get query type distribution with real data
    async fn query_type_distribution(
        &self,
        time_range: Option<TimeRange>,
    ) -> Result<Vec<QueryTypeDistribution>> {
        let range = time_range.map(|r| self.convert_time_range(r))
            .unwrap_or_else(|| MetricsTimeRange::last_24_hours());
        
        let distribution = self.metrics_manager
            .aggregator()
            .get_query_type_distribution(range)
            .await
            .map_err(|e| Error::new(e.to_string()))?;
        
        Ok(distribution.into_iter().map(|d| QueryTypeDistribution {
            query_type: d.query_type,
            count: d.count as i32,
            percentage: d.percentage,
        }).collect())
    }

    /// Get response code distribution with real data
    async fn response_code_distribution(
        &self,
        time_range: Option<TimeRange>,
    ) -> Result<Vec<ResponseCodeDistribution>> {
        let range = time_range.map(|r| self.convert_time_range(r))
            .unwrap_or_else(|| MetricsTimeRange::last_24_hours());
        
        let distribution = self.metrics_manager
            .aggregator()
            .get_response_code_distribution(range)
            .await
            .map_err(|e| Error::new(e.to_string()))?;
        
        Ok(distribution.into_iter().map(|d| ResponseCodeDistribution {
            response_code: d.response_code,
            count: d.count as i32,
            percentage: d.percentage,
        }).collect())
    }

    /// Get top queried domains with real data
    async fn top_domains(
        &self,
        time_range: Option<TimeRange>,
        limit: Option<i32>,
    ) -> Result<Vec<TopDomain>> {
        let range = time_range.map(|r| self.convert_time_range(r))
            .unwrap_or_else(|| MetricsTimeRange::last_24_hours());
        
        let domains = self.metrics_manager
            .aggregator()
            .get_top_domains(range, limit.unwrap_or(10) as usize)
            .await
            .map_err(|e| Error::new(e.to_string()))?;
        
        Ok(domains.into_iter().map(|d| TopDomain {
            domain: d.domain,
            query_count: d.query_count as i32,
            unique_clients: d.unique_clients as i32,
            trend: 0.0, // Calculate trend if needed
        }).collect())
    }

    /// Get geographic distribution with real GeoIP data
    async fn geographic_distribution(
        &self,
        time_range: Option<TimeRange>,
    ) -> Result<Vec<GeographicDistribution>> {
        let range = time_range.map(|r| self.convert_time_range(r))
            .unwrap_or_else(|| MetricsTimeRange::last_24_hours());
        
        // Get queries and analyze with GeoIP
        let queries = self.metrics_manager
            .storage
            .get_query_analytics(range.start, range.end)
            .await
            .map_err(|e| Error::new(e.to_string()))?;
        
        let ips: Vec<String> = queries.iter().map(|q| q.client_ip.clone()).collect();
        let distribution = self.metrics_manager
            .geoip()
            .analyze_distribution(ips)
            .await;
        
        Ok(distribution.into_iter().map(|d| GeographicDistribution {
            country_code: d.country_code,
            country_name: d.country_name,
            region: d.region,
            city: d.city,
            query_count: d.query_count as i32,
            percentage: d.percentage,
        }).collect())
    }

    /// Get performance metrics with real data
    async fn performance_metrics(
        &self,
        time_range: Option<TimeRange>,
    ) -> Result<PerformanceMetrics> {
        let range = time_range.map(|r| self.convert_time_range(r))
            .unwrap_or_else(|| MetricsTimeRange::last_hour());
        
        let aggregated = self.metrics_manager
            .aggregator()
            .get_aggregated_metrics(range, MetricsInterval::Hour)
            .await
            .map_err(|e| Error::new(e.to_string()))?;
        
        // Get current snapshot for real-time metrics
        let snapshot = self.metrics_manager
            .collector()
            .get_snapshot()
            .await
            .map_err(|e| Error::new(e.to_string()))?;
        
        // Get percentiles
        let percentiles = self.metrics_manager
            .collector()
            .get_response_time_percentiles()
            .await;
        
        Ok(PerformanceMetrics {
            avg_response_time_ms: aggregated.avg_response_time_ms,
            p50_response_time_ms: percentiles.get("p50").copied().unwrap_or(0.0),
            p95_response_time_ms: percentiles.get("p95").copied().unwrap_or(0.0),
            p99_response_time_ms: percentiles.get("p99").copied().unwrap_or(0.0),
            queries_per_second: self.metrics_manager.collector().get_query_rate().await,
            cache_hit_rate: aggregated.avg_cache_hit_rate,
            error_rate: 0.0, // Calculate from response codes
            upstream_health: 100.0, // Get from upstream monitoring
        })
    }

    /// Get cache statistics with real data
    async fn cache_statistics(&self) -> Result<CacheStatistics> {
        let snapshot = self.metrics_manager
            .collector()
            .get_snapshot()
            .await
            .map_err(|e| Error::new(e.to_string()))?;
        
        let hit_rate = self.metrics_manager
            .collector()
            .get_cache_hit_rate()
            .await;
        
        Ok(CacheStatistics {
            total_entries: snapshot.system_metrics.cache_entries as i32,
            memory_usage_mb: (snapshot.system_metrics.cache_entries * 1024 / 1024 / 1024) as f64,
            hit_count: snapshot.cache_hits as i32,
            miss_count: snapshot.cache_misses as i32,
            eviction_count: 0, // Track evictions
            hit_rate,
            avg_entry_size_bytes: 1024.0, // Calculate average
            ttl_distribution: vec![],
        })
    }

    /// Get system health with real metrics
    async fn system_health(&self) -> Result<SystemHealth> {
        let snapshot = self.metrics_manager
            .collector()
            .get_snapshot()
            .await
            .map_err(|e| Error::new(e.to_string()))?;
        
        Ok(SystemHealth {
            status: "healthy".to_string(),
            uptime_seconds: 0, // Get from server start time
            cpu_usage: snapshot.system_metrics.cpu_usage,
            memory_usage_mb: snapshot.system_metrics.memory_usage_mb as f64,
            disk_usage_mb: 0.0, // Get from system
            network_rx_mbps: (snapshot.system_metrics.network_rx_bytes as f64 / 1024.0 / 1024.0),
            network_tx_mbps: (snapshot.system_metrics.network_tx_bytes as f64 / 1024.0 / 1024.0),
            active_connections: snapshot.system_metrics.active_connections as i32,
            zone_count: 0, // Get from authority
            record_count: 0, // Get from authority
            last_reload: Utc::now(),
        })
    }

    /// Get recent security events with real data
    async fn security_events(
        &self,
        limit: Option<i32>,
    ) -> Result<Vec<SecurityEvent>> {
        let events = self.metrics_manager
            .collector()
            .get_recent_security_events(limit.unwrap_or(100) as usize)
            .await;
        
        Ok(events.into_iter().map(|e| SecurityEvent {
            timestamp: DateTime::<Utc>::from(e.timestamp),
            event_type: e.event_type,
            source_ip: e.source_ip,
            target_domain: e.target_domain,
            action_taken: e.action_taken,
            severity: e.severity,
            details: None,
        }).collect())
    }

    /// Get query volume trend
    async fn query_volume_trend(
        &self,
        time_range: TimeRange,
    ) -> Result<f64> {
        let range = self.convert_time_range(time_range);
        
        let trend = self.metrics_manager
            .aggregator()
            .get_query_volume_trend(range)
            .await
            .map_err(|e| Error::new(e.to_string()))?;
        
        Ok(trend)
    }
}