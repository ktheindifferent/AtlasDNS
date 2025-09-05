//! CNAME Flattening Implementation
//!
//! Provides CNAME flattening at the apex domain level, allowing CNAME-like
//! behavior for root domains while maintaining RFC compliance.
//!
//! # Features
//!
//! * **Apex CNAME Support** - Use CNAME-like records at zone apex
//! * **Automatic Resolution** - Resolves target to A/AAAA records
//! * **TTL Management** - Intelligent TTL selection
//! * **IPv4/IPv6 Support** - Flattens to both A and AAAA records
//! * **Caching** - Caches flattened results for performance
//! * **Health Checking** - Monitors target availability
//! * **Fallback Support** - Backup targets for resilience

use std::sync::Arc;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};

use crate::dns::protocol::{DnsRecord, QueryType, DnsQuestion, TransientTtl};
use crate::dns::client::DnsNetworkClient;
use crate::dns::errors::DnsError;

/// CNAME flattening configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlatteningConfig {
    /// Enable CNAME flattening
    pub enabled: bool,
    /// Cache TTL for flattened records (seconds)
    pub cache_ttl: u32,
    /// Minimum TTL for responses
    pub min_ttl: u32,
    /// Maximum TTL for responses
    pub max_ttl: u32,
    /// Enable health checking
    pub health_check: bool,
    /// Health check interval (seconds)
    pub health_check_interval: u32,
    /// Maximum resolution depth
    pub max_depth: u8,
    /// Resolution timeout
    pub resolution_timeout: Duration,
    /// Enable fallback targets
    pub enable_fallback: bool,
}

impl Default for FlatteningConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_ttl: 300,  // 5 minutes
            min_ttl: 60,
            max_ttl: 3600,
            health_check: true,
            health_check_interval: 60,
            max_depth: 10,
            resolution_timeout: Duration::from_secs(5),
            enable_fallback: true,
        }
    }
}

/// Flattened CNAME record
#[derive(Debug, Clone)]
pub struct FlattenedRecord {
    /// Original CNAME target
    pub target: String,
    /// Resolved A records
    pub a_records: Vec<Ipv4Addr>,
    /// Resolved AAAA records
    pub aaaa_records: Vec<Ipv6Addr>,
    /// TTL for the flattened records
    pub ttl: u32,
    /// Time when cached
    pub cached_at: Instant,
    /// Health status
    pub healthy: bool,
    /// Fallback target (if configured)
    pub fallback_target: Option<String>,
}

/// CNAME flattening target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlatteningTarget {
    /// Domain name to flatten
    pub domain: String,
    /// Target CNAME
    pub target: String,
    /// Fallback targets
    pub fallbacks: Vec<String>,
    /// Custom TTL override
    pub ttl_override: Option<u32>,
    /// Enable for this target
    pub enabled: bool,
}

/// Health check result
#[derive(Debug, Clone)]
struct HealthCheckResult {
    /// Target domain
    target: String,
    /// Is healthy
    healthy: bool,
    /// A record count
    a_count: usize,
    /// AAAA record count
    aaaa_count: usize,
    /// Last check time
    last_check: Instant,
    /// Response time
    response_time: Duration,
}

/// Flattening statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FlatteningStats {
    /// Total flattening requests
    pub total_requests: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// Failed resolutions
    pub failed_resolutions: u64,
    /// Fallback activations
    pub fallback_activations: u64,
    /// Average resolution time (ms)
    pub avg_resolution_time_ms: f64,
}

/// CNAME flattening handler
pub struct CnameFlatteningHandler {
    /// Configuration
    config: Arc<RwLock<FlatteningConfig>>,
    /// DNS client for resolution
    client: Arc<DnsNetworkClient>,
    /// Flattening targets
    targets: Arc<RwLock<HashMap<String, FlatteningTarget>>>,
    /// Cache of flattened records
    cache: Arc<RwLock<HashMap<String, FlattenedRecord>>>,
    /// Health check results
    health_checks: Arc<RwLock<HashMap<String, HealthCheckResult>>>,
    /// Statistics
    stats: Arc<RwLock<FlatteningStats>>,
}

impl CnameFlatteningHandler {
    /// Create new CNAME flattening handler
    pub fn new(config: FlatteningConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            client: Arc::new(DnsNetworkClient::new(0).expect("Failed to create DNS client")),
            targets: Arc::new(RwLock::new(HashMap::new())),
            cache: Arc::new(RwLock::new(HashMap::new())),
            health_checks: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(FlatteningStats::default())),
        }
    }

    /// Add flattening target
    pub fn add_target(&self, target: FlatteningTarget) {
        self.targets.write().insert(target.domain.clone(), target);
    }

    /// Remove flattening target
    pub fn remove_target(&self, domain: &str) {
        self.targets.write().remove(domain);
        self.cache.write().remove(domain);
    }

    /// Process query with flattening
    pub async fn process_query(
        &self,
        question: &DnsQuestion,
    ) -> Result<Vec<DnsRecord>, DnsError> {
        let config = self.config.read();
        
        if !config.enabled {
            return Ok(Vec::new());
        }

        // Check if this domain needs flattening
        let targets = self.targets.read();
        let target = match targets.get(&question.name) {
            Some(t) if t.enabled => t.clone(),
            _ => return Ok(Vec::new()),
        };
        drop(targets);

        self.stats.write().total_requests += 1;

        // Check cache
        if let Some(flattened) = self.get_cached(&question.name) {
            self.stats.write().cache_hits += 1;
            return Ok(self.create_response_records(&question.name, &flattened, question.qtype));
        }

        self.stats.write().cache_misses += 1;

        // Perform flattening
        let start = Instant::now();
        let flattened = self.flatten_cname(&target).await?;
        
        let duration = start.elapsed();
        self.update_avg_resolution_time(duration);

        // Cache the result
        self.cache_result(&question.name, flattened.clone());

        Ok(self.create_response_records(&question.name, &flattened, question.qtype))
    }

    /// Flatten CNAME to A/AAAA records
    async fn flatten_cname(&self, target: &FlatteningTarget) -> Result<FlattenedRecord, DnsError> {
        // Try primary target
        match self.resolve_target(&target.target, 0).await {
            Ok(mut flattened) => {
                flattened.fallback_target = None;
                if let Some(ttl) = target.ttl_override {
                    flattened.ttl = self.clamp_ttl(ttl);
                }
                Ok(flattened)
            }
            Err(_) if self.config.read().enable_fallback => {
                // Try fallback targets
                for fallback in &target.fallbacks {
                    if let Ok(mut flattened) = self.resolve_target(fallback, 0).await {
                        flattened.fallback_target = Some(fallback.clone());
                        self.stats.write().fallback_activations += 1;
                        return Ok(flattened);
                    }
                }
                self.stats.write().failed_resolutions += 1;
                Err(DnsError::NoRecordsFound)
            }
            Err(e) => {
                self.stats.write().failed_resolutions += 1;
                Err(e)
            }
        }
    }

    /// Resolve target to IP addresses
    fn resolve_target<'a>(&'a self, target: &'a str, depth: u8) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<FlattenedRecord, DnsError>> + Send + 'a>> {
        Box::pin(async move {
            let max_depth;
            let max_ttl;
            {
                let config = self.config.read();
                max_depth = config.max_depth;
                max_ttl = config.max_ttl;
            }
            
            if depth > max_depth {
                return Err(DnsError::RecursionLimit);
            }

            let mut a_records = Vec::new();
            let mut aaaa_records = Vec::new();
            let mut min_ttl = max_ttl;

            // Resolve A records
            let a_packet = self.client.send_query_async(target, QueryType::A).await?;
            for record in &a_packet.answers {
                match record {
                    DnsRecord::A { addr, ttl, .. } => {
                        a_records.push(*addr);
                        min_ttl = min_ttl.min(ttl.0);
                    }
                    DnsRecord::Cname { host, ttl, .. } => {
                        // Follow CNAME chain
                        min_ttl = min_ttl.min(ttl.0);
                        let nested = self.resolve_target(host, depth + 1).await?;
                        a_records.extend(nested.a_records);
                        aaaa_records.extend(nested.aaaa_records);
                        min_ttl = min_ttl.min(nested.ttl);
                    }
                    _ => {}
                }
            }

            // Resolve AAAA records
            let aaaa_packet = self.client.send_query_async(target, QueryType::Aaaa).await?;
            for record in &aaaa_packet.answers {
                if let DnsRecord::Aaaa { addr, ttl, .. } = record {
                    aaaa_records.push(*addr);
                    min_ttl = min_ttl.min(ttl.0);
                }
            }

            if a_records.is_empty() && aaaa_records.is_empty() {
                return Err(DnsError::NoRecordsFound);
            }

            Ok(FlattenedRecord {
                target: target.to_string(),
                a_records,
                aaaa_records,
                ttl: self.clamp_ttl(min_ttl),
                cached_at: Instant::now(),
                healthy: true,
                fallback_target: None,
            })
        })
    }

    /// Get cached flattened record
    fn get_cached(&self, domain: &str) -> Option<FlattenedRecord> {
        let cache = self.cache.read();
        let config = self.config.read();
        
        cache.get(domain).and_then(|record| {
            let age = record.cached_at.elapsed();
            if age < Duration::from_secs(config.cache_ttl as u64) {
                Some(record.clone())
            } else {
                None
            }
        })
    }

    /// Cache flattened result
    fn cache_result(&self, domain: &str, record: FlattenedRecord) {
        self.cache.write().insert(domain.to_string(), record);
        
        // Clean old entries periodically
        if self.cache.read().len() > 1000 {
            self.clean_cache();
        }
    }

    /// Clean expired cache entries
    fn clean_cache(&self) {
        let config = self.config.read();
        let max_age = Duration::from_secs(config.cache_ttl as u64);
        
        self.cache.write().retain(|_, record| {
            record.cached_at.elapsed() < max_age
        });
    }

    /// Create DNS response records
    fn create_response_records(
        &self,
        domain: &str,
        flattened: &FlattenedRecord,
        qtype: QueryType,
    ) -> Vec<DnsRecord> {
        let mut records = Vec::new();
        let ttl = TransientTtl(flattened.ttl);

        match qtype {
            QueryType::A => {
                for addr in &flattened.a_records {
                    records.push(DnsRecord::A {
                        domain: domain.to_string(),
                        addr: *addr,
                        ttl,
                    });
                }
            }
            QueryType::Aaaa => {
                for addr in &flattened.aaaa_records {
                    records.push(DnsRecord::Aaaa {
                        domain: domain.to_string(),
                        addr: *addr,
                        ttl,
                    });
                }
            }
            _ => {
                // Return both A and AAAA for other query types
                for addr in &flattened.a_records {
                    records.push(DnsRecord::A {
                        domain: domain.to_string(),
                        addr: *addr,
                        ttl,
                    });
                }
                for addr in &flattened.aaaa_records {
                    records.push(DnsRecord::Aaaa {
                        domain: domain.to_string(),
                        addr: *addr,
                        ttl,
                    });
                }
            }
        }

        records
    }

    /// Perform health check
    pub async fn health_check(&self, domain: &str) -> Result<bool, DnsError> {
        let targets = self.targets.read();
        let target = targets.get(domain).ok_or(DnsError::NoRecordsFound)?;
        let target = target.clone();
        drop(targets);

        let start = Instant::now();
        
        match self.resolve_target(&target.target, 0).await {
            Ok(flattened) => {
                let result = HealthCheckResult {
                    target: target.target.clone(),
                    healthy: true,
                    a_count: flattened.a_records.len(),
                    aaaa_count: flattened.aaaa_records.len(),
                    last_check: Instant::now(),
                    response_time: start.elapsed(),
                };
                
                self.health_checks.write().insert(domain.to_string(), result);
                Ok(true)
            }
            Err(_) => {
                let result = HealthCheckResult {
                    target: target.target.clone(),
                    healthy: false,
                    a_count: 0,
                    aaaa_count: 0,
                    last_check: Instant::now(),
                    response_time: start.elapsed(),
                };
                
                self.health_checks.write().insert(domain.to_string(), result);
                Ok(false)
            }
        }
    }

    /// Run periodic health checks
    pub async fn run_health_checks(&self) {
        let targets = self.targets.read();
        let domains: Vec<String> = targets.keys().cloned().collect();
        drop(targets);

        for domain in domains {
            let _ = self.health_check(&domain).await;
        }
    }

    /// Clamp TTL to configured bounds
    fn clamp_ttl(&self, ttl: u32) -> u32 {
        let config = self.config.read();
        ttl.max(config.min_ttl).min(config.max_ttl)
    }

    /// Update average resolution time
    fn update_avg_resolution_time(&self, duration: Duration) {
        let mut stats = self.stats.write();
        let n = stats.total_requests;
        let new_time = duration.as_millis() as f64;
        
        if n == 1 {
            stats.avg_resolution_time_ms = new_time;
        } else {
            stats.avg_resolution_time_ms = 
                ((stats.avg_resolution_time_ms * (n - 1) as f64) + new_time) / n as f64;
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> FlatteningStats {
        self.stats.read().clone()
    }

    /// Clear cache
    pub fn clear_cache(&self) {
        self.cache.write().clear();
    }

    /// Get health status
    pub fn get_health_status(&self) -> HashMap<String, bool> {
        self.health_checks.read()
            .iter()
            .map(|(domain, result)| (domain.clone(), result.healthy))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttl_clamping() {
        let config = FlatteningConfig {
            min_ttl: 60,
            max_ttl: 3600,
            ..Default::default()
        };
        
        let handler = CnameFlatteningHandler::new(config);
        
        assert_eq!(handler.clamp_ttl(30), 60);    // Below min
        assert_eq!(handler.clamp_ttl(300), 300);   // Within bounds
        assert_eq!(handler.clamp_ttl(7200), 3600); // Above max
    }

    #[test]
    fn test_cache_expiration() {
        let mut config = FlatteningConfig::default();
        config.cache_ttl = 1; // 1 second cache
        
        let handler = CnameFlatteningHandler::new(config);
        
        let record = FlattenedRecord {
            target: "example.com".to_string(),
            a_records: vec![Ipv4Addr::new(192, 168, 1, 1)],
            aaaa_records: vec![],
            ttl: 300,
            cached_at: Instant::now() - Duration::from_secs(2), // Expired
            healthy: true,
            fallback_target: None,
        };
        
        handler.cache.write().insert("test.com".to_string(), record);
        
        // Should return None due to expiration
        assert!(handler.get_cached("test.com").is_none());
    }
}