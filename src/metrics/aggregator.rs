//! Metrics aggregation for analytics

use super::storage::MetricsStorage;
use super::{QueryTypeDistribution, ResponseCodeDistribution, TopDomain};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Time range for queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: SystemTime,
    pub end: SystemTime,
}

impl TimeRange {
    pub fn last_hour() -> Self {
        let end = SystemTime::now();
        let start = end - Duration::from_secs(3600);
        Self { start, end }
    }

    pub fn last_24_hours() -> Self {
        let end = SystemTime::now();
        let start = end - Duration::from_secs(24 * 3600);
        Self { start, end }
    }

    pub fn last_7_days() -> Self {
        let end = SystemTime::now();
        let start = end - Duration::from_secs(7 * 24 * 3600);
        Self { start, end }
    }

    pub fn last_30_days() -> Self {
        let end = SystemTime::now();
        let start = end - Duration::from_secs(30 * 24 * 3600);
        Self { start, end }
    }
}

/// Aggregation interval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AggregationInterval {
    Minute,
    FiveMinutes,
    FifteenMinutes,
    Hour,
    Day,
    Week,
    Month,
}

impl AggregationInterval {
    pub fn duration(&self) -> Duration {
        match self {
            Self::Minute => Duration::from_secs(60),
            Self::FiveMinutes => Duration::from_secs(5 * 60),
            Self::FifteenMinutes => Duration::from_secs(15 * 60),
            Self::Hour => Duration::from_secs(3600),
            Self::Day => Duration::from_secs(24 * 3600),
            Self::Week => Duration::from_secs(7 * 24 * 3600),
            Self::Month => Duration::from_secs(30 * 24 * 3600),
        }
    }
}

/// Aggregated DNS analytics data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnalyticsDataPoint {
    pub timestamp: SystemTime,
    pub query_count: u64,
    pub unique_clients: u32,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub avg_response_time_ms: f64,
    pub p50_response_time_ms: f64,
    pub p95_response_time_ms: f64,
    pub p99_response_time_ms: f64,
    pub success_rate: f64,
    pub nxdomain_count: u64,
    pub servfail_count: u64,
}

/// Aggregated metrics result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedMetrics {
    pub time_range: TimeRange,
    pub data_points: Vec<DnsAnalyticsDataPoint>,
    pub query_type_distribution: Vec<QueryTypeDistribution>,
    pub response_code_distribution: Vec<ResponseCodeDistribution>,
    pub top_domains: Vec<TopDomain>,
    pub total_queries: u64,
    pub total_unique_clients: u32,
    pub avg_cache_hit_rate: f64,
    pub avg_response_time_ms: f64,
}

/// Metrics aggregator
pub struct MetricsAggregator {
    storage: Arc<MetricsStorage>,
}

impl MetricsAggregator {
    /// Create a new metrics aggregator
    pub fn new(storage: Arc<MetricsStorage>) -> Self {
        Self { storage }
    }

    /// Get aggregated DNS analytics
    pub async fn get_dns_analytics(
        &self,
        time_range: TimeRange,
        interval: AggregationInterval,
    ) -> Result<Vec<DnsAnalyticsDataPoint>, Box<dyn std::error::Error>> {
        let mut data_points = Vec::new();
        let interval_duration = interval.duration();
        
        let mut current = time_range.start;
        while current < time_range.end {
            let interval_end = std::cmp::min(current + interval_duration, time_range.end);
            
            // Get queries for this interval
            let queries = self.storage.get_query_analytics(current, interval_end).await?;
            
            if !queries.is_empty() {
                // Calculate metrics for this interval
                let query_count = queries.len() as u64;
                
                // Count unique clients
                let unique_clients: std::collections::HashSet<_> = 
                    queries.iter().map(|q| q.client_ip.clone()).collect();
                
                // Count cache hits/misses
                let cache_hits = queries.iter().filter(|q| q.cache_hit).count() as u64;
                let cache_misses = query_count - cache_hits;
                
                // Calculate response times
                let mut response_times: Vec<f64> = queries.iter()
                    .map(|q| q.response_time_ms)
                    .collect();
                response_times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                
                let avg_response_time = response_times.iter().sum::<f64>() / response_times.len() as f64;
                let p50 = percentile(&response_times, 50.0);
                let p95 = percentile(&response_times, 95.0);
                let p99 = percentile(&response_times, 99.0);
                
                // Count response codes
                let nxdomain_count = queries.iter()
                    .filter(|q| q.response_code == "NXDOMAIN")
                    .count() as u64;
                let servfail_count = queries.iter()
                    .filter(|q| q.response_code == "SERVFAIL")
                    .count() as u64;
                let success_count = queries.iter()
                    .filter(|q| q.response_code == "NOERROR")
                    .count() as u64;
                
                let success_rate = if query_count > 0 {
                    (success_count as f64 / query_count as f64) * 100.0
                } else {
                    0.0
                };
                
                data_points.push(DnsAnalyticsDataPoint {
                    timestamp: current,
                    query_count,
                    unique_clients: unique_clients.len() as u32,
                    cache_hits,
                    cache_misses,
                    avg_response_time_ms: avg_response_time,
                    p50_response_time_ms: p50,
                    p95_response_time_ms: p95,
                    p99_response_time_ms: p99,
                    success_rate,
                    nxdomain_count,
                    servfail_count,
                });
            } else {
                // No data for this interval, add zero point
                data_points.push(DnsAnalyticsDataPoint {
                    timestamp: current,
                    query_count: 0,
                    unique_clients: 0,
                    cache_hits: 0,
                    cache_misses: 0,
                    avg_response_time_ms: 0.0,
                    p50_response_time_ms: 0.0,
                    p95_response_time_ms: 0.0,
                    p99_response_time_ms: 0.0,
                    success_rate: 100.0,
                    nxdomain_count: 0,
                    servfail_count: 0,
                });
            }
            
            current = interval_end;
        }
        
        Ok(data_points)
    }

    /// Get query type distribution
    pub async fn get_query_type_distribution(
        &self,
        time_range: TimeRange,
    ) -> Result<Vec<QueryTypeDistribution>, Box<dyn std::error::Error>> {
        let queries = self.storage.get_query_analytics(time_range.start, time_range.end).await?;
        
        let mut type_counts: HashMap<String, u64> = HashMap::new();
        for query in &queries {
            *type_counts.entry(query.query_type.clone()).or_insert(0) += 1;
        }
        
        let total = queries.len() as f64;
        let mut distribution: Vec<QueryTypeDistribution> = type_counts
            .into_iter()
            .map(|(query_type, count)| QueryTypeDistribution {
                query_type,
                count,
                percentage: if total > 0.0 {
                    (count as f64 / total) * 100.0
                } else {
                    0.0
                },
            })
            .collect();
        
        distribution.sort_by(|a, b| b.count.cmp(&a.count));
        Ok(distribution)
    }

    /// Get response code distribution
    pub async fn get_response_code_distribution(
        &self,
        time_range: TimeRange,
    ) -> Result<Vec<ResponseCodeDistribution>, Box<dyn std::error::Error>> {
        let queries = self.storage.get_query_analytics(time_range.start, time_range.end).await?;
        
        let mut code_counts: HashMap<String, u64> = HashMap::new();
        for query in &queries {
            *code_counts.entry(query.response_code.clone()).or_insert(0) += 1;
        }
        
        let total = queries.len() as f64;
        let mut distribution: Vec<ResponseCodeDistribution> = code_counts
            .into_iter()
            .map(|(response_code, count)| ResponseCodeDistribution {
                response_code,
                count,
                percentage: if total > 0.0 {
                    (count as f64 / total) * 100.0
                } else {
                    0.0
                },
            })
            .collect();
        
        distribution.sort_by(|a, b| b.count.cmp(&a.count));
        Ok(distribution)
    }

    /// Get top queried domains
    pub async fn get_top_domains(
        &self,
        time_range: TimeRange,
        limit: usize,
    ) -> Result<Vec<TopDomain>, Box<dyn std::error::Error>> {
        let top_domains = self.storage.get_top_domains(time_range.start, time_range.end, limit).await?;
        
        let mut results = Vec::new();
        for (domain, count) in top_domains {
            // Get unique clients for this domain
            let queries = self.storage.get_query_analytics(time_range.start, time_range.end).await?;
            let unique_clients: std::collections::HashSet<_> = queries
                .iter()
                .filter(|q| q.domain == domain)
                .map(|q| q.client_ip.clone())
                .collect();
            
            results.push(TopDomain {
                domain,
                query_count: count,
                unique_clients: unique_clients.len() as u32,
            });
        }
        
        Ok(results)
    }

    /// Get geographic distribution of queries
    pub async fn get_geographic_distribution(
        &self,
        time_range: TimeRange,
    ) -> Result<Vec<super::GeographicDistribution>, Box<dyn std::error::Error>> {
        // This will be implemented when we add GeoIP support
        Ok(Vec::new())
    }

    /// Get comprehensive aggregated metrics
    pub async fn get_aggregated_metrics(
        &self,
        time_range: TimeRange,
        interval: AggregationInterval,
    ) -> Result<AggregatedMetrics, Box<dyn std::error::Error>> {
        // Get time-series data points
        let data_points = self.get_dns_analytics(time_range.clone(), interval).await?;
        
        // Get distributions
        let query_type_distribution = self.get_query_type_distribution(time_range.clone()).await?;
        let response_code_distribution = self.get_response_code_distribution(time_range.clone()).await?;
        let top_domains = self.get_top_domains(time_range.clone(), 10).await?;
        
        // Calculate overall metrics
        let total_queries: u64 = data_points.iter().map(|dp| dp.query_count).sum();
        let total_cache_hits: u64 = data_points.iter().map(|dp| dp.cache_hits).sum();
        let total_cache_misses: u64 = data_points.iter().map(|dp| dp.cache_misses).sum();
        
        let avg_cache_hit_rate = if total_queries > 0 {
            (total_cache_hits as f64 / (total_cache_hits + total_cache_misses) as f64) * 100.0
        } else {
            0.0
        };
        
        let avg_response_time_ms = if !data_points.is_empty() {
            data_points.iter().map(|dp| dp.avg_response_time_ms).sum::<f64>() / data_points.len() as f64
        } else {
            0.0
        };
        
        let total_unique_clients = self.storage.get_unique_clients(time_range.start, time_range.end).await? as u32;
        
        Ok(AggregatedMetrics {
            time_range,
            data_points,
            query_type_distribution,
            response_code_distribution,
            top_domains,
            total_queries,
            total_unique_clients,
            avg_cache_hit_rate,
            avg_response_time_ms,
        })
    }

    /// Get query volume trend (percentage change)
    pub async fn get_query_volume_trend(
        &self,
        time_range: TimeRange,
    ) -> Result<f64, Box<dyn std::error::Error>> {
        let duration = time_range.end.duration_since(time_range.start)?;
        let previous_range = TimeRange {
            start: time_range.start - duration,
            end: time_range.start,
        };
        
        let current_queries = self.storage.get_query_analytics(time_range.start, time_range.end).await?;
        let previous_queries = self.storage.get_query_analytics(previous_range.start, previous_range.end).await?;
        
        let current_count = current_queries.len() as f64;
        let previous_count = previous_queries.len() as f64;
        
        if previous_count > 0.0 {
            Ok(((current_count - previous_count) / previous_count) * 100.0)
        } else if current_count > 0.0 {
            Ok(100.0)
        } else {
            Ok(0.0)
        }
    }

    /// Get security events summary
    pub async fn get_security_summary(
        &self,
        time_range: TimeRange,
    ) -> Result<HashMap<String, u64>, Box<dyn std::error::Error>> {
        // This will be implemented when we have security event tracking
        Ok(HashMap::new())
    }
}

/// Calculate percentile from sorted values
fn percentile(sorted_values: &[f64], p: f64) -> f64 {
    if sorted_values.is_empty() {
        return 0.0;
    }
    
    let idx = ((sorted_values.len() - 1) as f64 * p / 100.0) as usize;
    sorted_values[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_time_range() {
        let range = TimeRange::last_hour();
        let duration = range.end.duration_since(range.start).unwrap();
        assert_eq!(duration.as_secs(), 3600);
    }

    #[tokio::test]
    async fn test_aggregation_interval() {
        assert_eq!(AggregationInterval::Minute.duration().as_secs(), 60);
        assert_eq!(AggregationInterval::Hour.duration().as_secs(), 3600);
        assert_eq!(AggregationInterval::Day.duration().as_secs(), 86400);
    }

    #[test]
    fn test_percentile_calculation() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        assert_eq!(percentile(&values, 50.0), 5.0);
        assert_eq!(percentile(&values, 90.0), 9.0);
        assert_eq!(percentile(&values, 100.0), 10.0);
    }
}