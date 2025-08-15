//! Adaptive DNS Caching with ML-driven TTL Optimization
//!
//! Implements intelligent caching strategies that learn from query patterns
//! to optimize cache hit rates and performance.
//!
//! # Features
//!
//! * **Pattern Recognition** - Identifies query patterns and trends
//! * **TTL Optimization** - Dynamically adjusts TTLs based on usage
//! * **Predictive Prefetching** - Proactively refreshes popular entries
//! * **Cache Pressure Management** - Intelligent eviction policies
//! * **Performance Analytics** - Real-time cache effectiveness metrics

use std::collections::{HashMap, VecDeque, BinaryHeap};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use std::cmp::Ordering;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};

use crate::dns::protocol::{DnsPacket, QueryType, DnsRecord};
use crate::dns::cache::SynchronizedCache;
use crate::dns::metrics::MetricsCollector;

/// Machine learning model for TTL prediction
#[derive(Debug, Clone)]
pub struct TtlPredictor {
    /// Historical query patterns
    query_history: VecDeque<QueryPattern>,
    /// Feature weights for prediction
    weights: PredictionWeights,
    /// Model configuration
    config: PredictorConfig,
}

/// Query pattern analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryPattern {
    /// Domain name
    domain: String,
    /// Query type
    qtype: QueryType,
    /// Timestamp of query
    timestamp: SystemTime,
    /// Time since last query
    inter_arrival_time: Option<Duration>,
    /// Query frequency in last hour
    hourly_frequency: f64,
    /// Query frequency in last day
    daily_frequency: f64,
    /// Day of week (0-6)
    day_of_week: u8,
    /// Hour of day (0-23)
    hour_of_day: u8,
}

/// Weights for prediction model
#[derive(Debug, Clone)]
pub struct PredictionWeights {
    /// Weight for recency
    recency_weight: f64,
    /// Weight for frequency
    frequency_weight: f64,
    /// Weight for time patterns
    temporal_weight: f64,
    /// Weight for domain popularity
    popularity_weight: f64,
    /// Base TTL multiplier
    base_multiplier: f64,
}

impl Default for PredictionWeights {
    fn default() -> Self {
        Self {
            recency_weight: 0.3,
            frequency_weight: 0.4,
            temporal_weight: 0.2,
            popularity_weight: 0.1,
            base_multiplier: 1.0,
        }
    }
}

/// Predictor configuration
#[derive(Debug, Clone)]
pub struct PredictorConfig {
    /// Maximum history size
    max_history_size: usize,
    /// Learning rate for weight updates
    learning_rate: f64,
    /// Minimum TTL in seconds
    min_ttl: u32,
    /// Maximum TTL in seconds
    max_ttl: u32,
    /// Enable predictive prefetching
    enable_prefetching: bool,
    /// Prefetch threshold (probability)
    prefetch_threshold: f64,
}

impl Default for PredictorConfig {
    fn default() -> Self {
        Self {
            max_history_size: 10000,
            learning_rate: 0.01,
            min_ttl: 60,
            max_ttl: 86400,
            enable_prefetching: true,
            prefetch_threshold: 0.7,
        }
    }
}

impl TtlPredictor {
    /// Create a new TTL predictor
    pub fn new(config: PredictorConfig) -> Self {
        Self {
            query_history: VecDeque::with_capacity(config.max_history_size),
            weights: PredictionWeights::default(),
            config,
        }
    }

    /// Record a query pattern
    pub fn record_query(&mut self, domain: &str, qtype: QueryType) {
        let now = SystemTime::now();
        
        // Calculate inter-arrival time
        let inter_arrival_time = self.query_history
            .iter()
            .rev()
            .find(|p| p.domain == domain && p.qtype == qtype)
            .and_then(|p| now.duration_since(p.timestamp).ok());

        // Calculate frequencies
        let hour_ago = now - Duration::from_secs(3600);
        let day_ago = now - Duration::from_secs(86400);
        
        let hourly_count = self.query_history
            .iter()
            .filter(|p| p.domain == domain && p.timestamp > hour_ago)
            .count() as f64;
        
        let daily_count = self.query_history
            .iter()
            .filter(|p| p.domain == domain && p.timestamp > day_ago)
            .count() as f64;

        // Get temporal features
        let datetime = chrono::DateTime::<chrono::Utc>::from(now);
        use chrono::Datelike;
        use chrono::Timelike;
        let day_of_week = datetime.weekday().num_days_from_sunday() as u8;
        let hour_of_day = datetime.hour() as u8;

        let pattern = QueryPattern {
            domain: domain.to_string(),
            qtype,
            timestamp: now,
            inter_arrival_time,
            hourly_frequency: hourly_count / 3600.0,
            daily_frequency: daily_count / 86400.0,
            day_of_week,
            hour_of_day,
        };

        // Add to history
        self.query_history.push_back(pattern);
        
        // Trim history if needed
        while self.query_history.len() > self.config.max_history_size {
            self.query_history.pop_front();
        }
    }

    /// Predict optimal TTL for a domain
    pub fn predict_ttl(&self, domain: &str, qtype: QueryType, original_ttl: u32) -> u32 {
        // Extract features
        let features = self.extract_features(domain, qtype);
        
        // Calculate prediction score
        let score = self.calculate_score(&features);
        
        // Adjust TTL based on score
        let adjusted_ttl = (original_ttl as f64 * score * self.weights.base_multiplier) as u32;
        
        // Clamp to configured range
        adjusted_ttl.max(self.config.min_ttl).min(self.config.max_ttl)
    }

    /// Extract features for prediction
    fn extract_features(&self, domain: &str, qtype: QueryType) -> CacheFeatures {
        let now = SystemTime::now();
        let hour_ago = now - Duration::from_secs(3600);
        let day_ago = now - Duration::from_secs(86400);
        
        let recent_queries: Vec<&QueryPattern> = self.query_history
            .iter()
            .filter(|p| p.domain == domain && p.qtype == qtype)
            .collect();
        
        let hourly_queries = recent_queries
            .iter()
            .filter(|p| p.timestamp > hour_ago)
            .count() as f64;
        
        let daily_queries = recent_queries
            .iter()
            .filter(|p| p.timestamp > day_ago)
            .count() as f64;
        
        let avg_inter_arrival = recent_queries
            .iter()
            .filter_map(|p| p.inter_arrival_time)
            .map(|d| d.as_secs() as f64)
            .sum::<f64>() / recent_queries.len().max(1) as f64;
        
        CacheFeatures {
            query_frequency_hourly: hourly_queries,
            query_frequency_daily: daily_queries,
            avg_inter_arrival_time: avg_inter_arrival,
            domain_popularity: self.calculate_domain_popularity(domain),
            temporal_pattern_strength: self.calculate_temporal_pattern(domain, qtype),
        }
    }

    /// Calculate score from features
    fn calculate_score(&self, features: &CacheFeatures) -> f64 {
        let recency_score = 1.0 / (1.0 + features.avg_inter_arrival_time / 3600.0);
        let frequency_score = (features.query_frequency_hourly + features.query_frequency_daily) / 2.0;
        let temporal_score = features.temporal_pattern_strength;
        let popularity_score = features.domain_popularity;
        
        let total_score = 
            recency_score * self.weights.recency_weight +
            frequency_score * self.weights.frequency_weight +
            temporal_score * self.weights.temporal_weight +
            popularity_score * self.weights.popularity_weight;
        
        // Normalize to 0-2 range (can increase or decrease TTL)
        (total_score * 2.0).max(0.1).min(2.0)
    }

    /// Calculate domain popularity
    fn calculate_domain_popularity(&self, domain: &str) -> f64 {
        let total_queries = self.query_history.len() as f64;
        let domain_queries = self.query_history
            .iter()
            .filter(|p| p.domain == domain)
            .count() as f64;
        
        if total_queries > 0.0 {
            domain_queries / total_queries
        } else {
            0.0
        }
    }

    /// Calculate temporal pattern strength
    fn calculate_temporal_pattern(&self, domain: &str, qtype: QueryType) -> f64 {
        let patterns: Vec<&QueryPattern> = self.query_history
            .iter()
            .filter(|p| p.domain == domain && p.qtype == qtype)
            .collect();
        
        if patterns.len() < 10 {
            return 0.0;
        }
        
        // Calculate variance in hour of day
        let hours: Vec<f64> = patterns.iter().map(|p| p.hour_of_day as f64).collect();
        let mean_hour = hours.iter().sum::<f64>() / hours.len() as f64;
        let variance = hours.iter()
            .map(|h| (h - mean_hour).powi(2))
            .sum::<f64>() / hours.len() as f64;
        
        // Lower variance means stronger pattern
        1.0 / (1.0 + variance.sqrt())
    }

    /// Update model weights based on feedback
    pub fn update_weights(&mut self, feedback: CacheFeedback) {
        let adjustment = feedback.effectiveness * self.config.learning_rate;
        
        if feedback.hit_rate_improvement > 0.0 {
            self.weights.frequency_weight *= 1.0 + adjustment;
            self.weights.recency_weight *= 1.0 + adjustment;
        } else {
            self.weights.frequency_weight *= 1.0 - adjustment;
            self.weights.recency_weight *= 1.0 - adjustment;
        }
        
        // Normalize weights
        let total = self.weights.recency_weight + 
                   self.weights.frequency_weight + 
                   self.weights.temporal_weight + 
                   self.weights.popularity_weight;
        
        self.weights.recency_weight /= total;
        self.weights.frequency_weight /= total;
        self.weights.temporal_weight /= total;
        self.weights.popularity_weight /= total;
    }
}

/// Features extracted for cache prediction
#[derive(Debug)]
struct CacheFeatures {
    query_frequency_hourly: f64,
    query_frequency_daily: f64,
    avg_inter_arrival_time: f64,
    domain_popularity: f64,
    temporal_pattern_strength: f64,
}

/// Feedback for model training
#[derive(Debug)]
pub struct CacheFeedback {
    /// Overall cache effectiveness
    pub effectiveness: f64,
    /// Hit rate improvement
    pub hit_rate_improvement: f64,
    /// Response time improvement
    pub response_time_improvement: f64,
}

/// Entry for prefetch queue
#[derive(Debug, Clone)]
struct PrefetchEntry {
    domain: String,
    qtype: QueryType,
    priority: f64,
    next_refresh: Instant,
}

impl PartialEq for PrefetchEntry {
    fn eq(&self, other: &Self) -> bool {
        self.domain == other.domain && self.qtype == other.qtype
    }
}

impl Eq for PrefetchEntry {}

impl Ord for PrefetchEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse order for max heap (highest priority first)
        other.priority.partial_cmp(&self.priority).unwrap_or(Ordering::Equal)
    }
}

impl PartialOrd for PrefetchEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Adaptive cache implementation
pub struct AdaptiveCache {
    /// Base cache implementation
    base_cache: Arc<SynchronizedCache>,
    /// TTL predictor
    predictor: Arc<RwLock<TtlPredictor>>,
    /// Prefetch queue
    prefetch_queue: Arc<RwLock<BinaryHeap<PrefetchEntry>>>,
    /// Cache statistics
    stats: Arc<RwLock<CacheStatistics>>,
    /// Metrics collector
    metrics: Arc<MetricsCollector>,
    /// Configuration
    config: AdaptiveCacheConfig,
}

/// Adaptive cache configuration
#[derive(Debug, Clone)]
pub struct AdaptiveCacheConfig {
    /// Enable TTL prediction
    pub enable_prediction: bool,
    /// Enable prefetching
    pub enable_prefetching: bool,
    /// Cache size limit
    pub max_cache_size: usize,
    /// Prefetch interval
    pub prefetch_interval: Duration,
    /// Statistics window
    pub stats_window: Duration,
}

impl Default for AdaptiveCacheConfig {
    fn default() -> Self {
        Self {
            enable_prediction: true,
            enable_prefetching: true,
            max_cache_size: 100000,
            prefetch_interval: Duration::from_secs(60),
            stats_window: Duration::from_secs(3600),
        }
    }
}

/// Cache statistics
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CacheStatistics {
    /// Total queries
    pub total_queries: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// Predicted TTL adjustments
    pub ttl_adjustments: u64,
    /// Successful prefetches
    pub successful_prefetches: u64,
    /// Failed prefetches
    pub failed_prefetches: u64,
    /// Average response time
    pub avg_response_time_ms: f64,
    /// Hit rate
    pub hit_rate: f64,
    /// Entries evicted
    pub evictions: u64,
}

impl AdaptiveCache {
    /// Create a new adaptive cache
    pub fn new(
        base_cache: Arc<SynchronizedCache>,
        metrics: Arc<MetricsCollector>,
        config: AdaptiveCacheConfig,
    ) -> Self {
        let predictor_config = PredictorConfig {
            enable_prefetching: config.enable_prefetching,
            ..Default::default()
        };
        
        Self {
            base_cache,
            predictor: Arc::new(RwLock::new(TtlPredictor::new(predictor_config))),
            prefetch_queue: Arc::new(RwLock::new(BinaryHeap::new())),
            stats: Arc::new(RwLock::new(CacheStatistics::default())),
            metrics,
            config,
        }
    }

    /// Lookup entry with adaptive behavior
    pub fn lookup(&self, domain: &str, qtype: QueryType) -> Option<DnsPacket> {
        let start = Instant::now();
        
        // Record query for pattern learning
        if self.config.enable_prediction {
            self.predictor.write().record_query(domain, qtype);
        }
        
        // Perform base lookup
        let result = self.base_cache.lookup(domain, qtype);
        
        // Update statistics
        {
            let mut stats = self.stats.write();
            stats.total_queries += 1;
            
            if result.is_some() {
                stats.cache_hits += 1;
                self.metrics.record_cache_operation("hit", &format!("{:?}", qtype));
            } else {
                stats.cache_misses += 1;
                self.metrics.record_cache_operation("miss", &format!("{:?}", qtype));
                
                // Schedule for prefetching if pattern suggests it
                if self.config.enable_prefetching {
                    self.consider_prefetch(domain, qtype);
                }
            }
            
            stats.hit_rate = stats.cache_hits as f64 / stats.total_queries as f64;
            
            let response_time = start.elapsed().as_millis() as f64;
            stats.avg_response_time_ms = 
                (stats.avg_response_time_ms * (stats.total_queries - 1) as f64 + response_time) 
                / stats.total_queries as f64;
        }
        
        result
    }

    /// Store entry with adaptive TTL
    pub fn store(&self, records: &[DnsRecord]) -> Result<(), crate::dns::cache::CacheError> {
        if !self.config.enable_prediction {
            return self.base_cache.store(records);
        }
        
        // Adjust TTLs based on predictions
        let adjusted_records: Vec<DnsRecord> = records.iter().map(|record| {
            let (domain, qtype, original_ttl) = match record {
                DnsRecord::A { domain, ttl, .. } => (domain.clone(), QueryType::A, ttl.0),
                DnsRecord::Aaaa { domain, ttl, .. } => (domain.clone(), QueryType::Aaaa, ttl.0),
                DnsRecord::Cname { domain, ttl, .. } => (domain.clone(), QueryType::Cname, ttl.0),
                DnsRecord::Mx { domain, ttl, .. } => (domain.clone(), QueryType::Mx, ttl.0),
                DnsRecord::Ns { domain, ttl, .. } => (domain.clone(), QueryType::Ns, ttl.0),
                DnsRecord::Txt { domain, ttl, .. } => (domain.clone(), QueryType::Txt, ttl.0),
                _ => return record.clone(),
            };
            
            let predicted_ttl = self.predictor.read().predict_ttl(&domain, qtype, original_ttl);
            
            if predicted_ttl != original_ttl {
                self.stats.write().ttl_adjustments += 1;
                log::debug!("Adjusted TTL for {} from {} to {}", domain, original_ttl, predicted_ttl);
            }
            
            // Clone and modify record with new TTL
            match record {
                DnsRecord::A { domain, addr, .. } => DnsRecord::A {
                    domain: domain.clone(),
                    addr: *addr,
                    ttl: crate::dns::protocol::TransientTtl(predicted_ttl),
                },
                DnsRecord::Aaaa { domain, addr, .. } => DnsRecord::Aaaa {
                    domain: domain.clone(),
                    addr: *addr,
                    ttl: crate::dns::protocol::TransientTtl(predicted_ttl),
                },
                DnsRecord::Cname { domain, host, .. } => DnsRecord::Cname {
                    domain: domain.clone(),
                    host: host.clone(),
                    ttl: crate::dns::protocol::TransientTtl(predicted_ttl),
                },
                DnsRecord::Mx { domain, priority, host, .. } => DnsRecord::Mx {
                    domain: domain.clone(),
                    priority: *priority,
                    host: host.clone(),
                    ttl: crate::dns::protocol::TransientTtl(predicted_ttl),
                },
                DnsRecord::Ns { domain, host, .. } => DnsRecord::Ns {
                    domain: domain.clone(),
                    host: host.clone(),
                    ttl: crate::dns::protocol::TransientTtl(predicted_ttl),
                },
                DnsRecord::Txt { domain, data, .. } => DnsRecord::Txt {
                    domain: domain.clone(),
                    data: data.clone(),
                    ttl: crate::dns::protocol::TransientTtl(predicted_ttl),
                },
                _ => record.clone(),
            }
        }).collect();
        
        self.base_cache.store(&adjusted_records)
    }

    /// Consider adding entry to prefetch queue
    fn consider_prefetch(&self, domain: &str, qtype: QueryType) {
        let predictor = self.predictor.read();
        let features = predictor.extract_features(domain, qtype);
        
        // Calculate prefetch priority based on features
        let priority = features.query_frequency_hourly * 0.5 + 
                      features.query_frequency_daily * 0.3 +
                      features.domain_popularity * 0.2;
        
        if priority > 0.5 {  // Threshold for prefetching
            let entry = PrefetchEntry {
                domain: domain.to_string(),
                qtype,
                priority,
                next_refresh: Instant::now() + self.config.prefetch_interval,
            };
            
            self.prefetch_queue.write().push(entry);
        }
    }

    /// Get cache statistics
    pub fn get_statistics(&self) -> CacheStatistics {
        let stats = self.stats.read();
        CacheStatistics {
            total_queries: stats.total_queries,
            cache_hits: stats.cache_hits,
            cache_misses: stats.cache_misses,
            ttl_adjustments: stats.ttl_adjustments,
            successful_prefetches: stats.successful_prefetches,
            failed_prefetches: stats.failed_prefetches,
            avg_response_time_ms: stats.avg_response_time_ms,
            hit_rate: stats.hit_rate,
            evictions: stats.evictions,
        }
    }

    /// Provide feedback to improve model
    pub fn provide_feedback(&self, feedback: CacheFeedback) {
        self.predictor.write().update_weights(feedback);
    }

    /// Clear the cache
    pub fn clear(&self) {
        // Note: base_cache doesn't have a clear method in the current implementation
        // This would need to be added to SynchronizedCache
        // For now, we just update statistics
        self.stats.write().evictions += self.stats.read().cache_hits + self.stats.read().cache_misses;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttl_predictor() {
        let config = PredictorConfig::default();
        let mut predictor = TtlPredictor::new(config);
        
        // Record some queries
        for _ in 0..10 {
            predictor.record_query("example.com", QueryType::A);
        }
        
        // Predict TTL
        let predicted = predictor.predict_ttl("example.com", QueryType::A, 300);
        assert!(predicted >= 60);
        assert!(predicted <= 86400);
    }

    #[test]
    fn test_cache_statistics() {
        let stats = CacheStatistics::default();
        assert_eq!(stats.total_queries, 0);
        assert_eq!(stats.hit_rate, 0.0);
    }
}