//! Enhanced Rate Limiter with multiple algorithms

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
extern crate sentry;

use crate::dns::protocol::DnsPacket;
use crate::dns::errors::DnsError;
use super::{SecurityCheckResult, SecurityAction, SecurityEvent, ThreatLevel, SecurityComponent};

/// Enhanced rate limiter with multiple algorithms
pub struct EnhancedRateLimiter {
    config: Arc<RwLock<RateLimitConfig>>,
    client_limiters: Arc<RwLock<HashMap<IpAddr, ClientRateLimiter>>>,
    global_limiter: Arc<RwLock<GlobalRateLimiter>>,
    query_type_limiters: Arc<RwLock<HashMap<String, TypeRateLimiter>>>,
    metrics: Arc<RwLock<RateLimitMetrics>>,
    cleanup_interval: Duration,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub algorithm: RateLimitAlgorithm,
    pub per_client_qps: u32,
    pub per_client_burst: u32,
    pub global_qps: u32,
    pub global_burst: u32,
    pub window_size: Duration,
    pub enable_adaptive: bool,
    pub adaptive_threshold: f64,
    pub throttle_duration: Duration,
    pub ban_duration: Duration,
    pub ban_threshold: u32,
    pub query_type_limits: HashMap<String, u32>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        let mut query_type_limits = HashMap::new();
        query_type_limits.insert("ANY".to_string(), 10);
        query_type_limits.insert("TXT".to_string(), 50);
        query_type_limits.insert("DNSKEY".to_string(), 20);

        RateLimitConfig {
            enabled: true,
            algorithm: RateLimitAlgorithm::TokenBucket,
            per_client_qps: 100,
            per_client_burst: 200,
            global_qps: 10000,
            global_burst: 20000,
            window_size: Duration::from_secs(1),
            enable_adaptive: true,
            adaptive_threshold: 0.8,
            throttle_duration: Duration::from_secs(60),
            ban_duration: Duration::from_secs(3600),
            ban_threshold: 5,
            query_type_limits,
        }
    }
}

/// Rate limiting algorithm
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum RateLimitAlgorithm {
    TokenBucket,
    SlidingWindow,
    FixedWindow,
    LeakyBucket,
    Adaptive,
}

/// Client rate limiter
struct ClientRateLimiter {
    algorithm: Box<dyn RateLimitAlgorithmImpl>,
    throttled_until: Option<Instant>,
    banned_until: Option<Instant>,
    violation_count: u32,
    last_seen: Instant,
    total_queries: u64,
    blocked_queries: u64,
}

/// Global rate limiter
struct GlobalRateLimiter {
    algorithm: Box<dyn RateLimitAlgorithmImpl>,
    current_qps: u32,
    peak_qps: u32,
    adaptive_limit: u32,
}

/// Query type rate limiter
struct TypeRateLimiter {
    query_type: String,
    limit: u32,
    current: u32,
    window_start: Instant,
}

/// Rate limit metrics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RateLimitMetrics {
    pub total_queries: u64,
    pub throttled_queries: u64,
    pub blocked_queries: u64,
    pub throttled_clients: usize,
    pub banned_clients: usize,
    pub current_qps: u32,
    pub peak_qps: u32,
    pub algorithm_efficiency: f64,
}

/// Rate limiting algorithm trait
trait RateLimitAlgorithmImpl: Send + Sync {
    fn check(&mut self, limit: u32, burst: u32) -> bool;
    fn record(&mut self);
    fn reset(&mut self);
    fn metrics(&self) -> serde_json::Value;
}

/// Token bucket algorithm
struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(limit: u32, burst: u32) -> Self {
        TokenBucket {
            tokens: burst as f64,
            max_tokens: burst as f64,
            refill_rate: limit as f64,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let tokens_to_add = elapsed * self.refill_rate;
        
        self.tokens = (self.tokens + tokens_to_add).min(self.max_tokens);
        self.last_refill = now;
    }
}

impl RateLimitAlgorithmImpl for TokenBucket {
    fn check(&mut self, _limit: u32, _burst: u32) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            true
        } else {
            false
        }
    }

    fn record(&mut self) {
        self.tokens -= 1.0;
    }

    fn reset(&mut self) {
        self.tokens = self.max_tokens;
        self.last_refill = Instant::now();
    }

    fn metrics(&self) -> serde_json::Value {
        serde_json::json!({
            "algorithm": "TokenBucket",
            "tokens": self.tokens,
            "max_tokens": self.max_tokens,
            "refill_rate": self.refill_rate,
        })
    }
}

/// Sliding window algorithm
struct SlidingWindow {
    window: VecDeque<Instant>,
    window_size: Duration,
}

impl SlidingWindow {
    fn new(window_size: Duration) -> Self {
        SlidingWindow {
            window: VecDeque::new(),
            window_size,
        }
    }

    fn cleanup(&mut self) {
        let cutoff = Instant::now() - self.window_size;
        while let Some(&front) = self.window.front() {
            if front < cutoff {
                self.window.pop_front();
            } else {
                break;
            }
        }
    }
}

impl RateLimitAlgorithmImpl for SlidingWindow {
    fn check(&mut self, limit: u32, _burst: u32) -> bool {
        self.cleanup();
        self.window.len() < limit as usize
    }

    fn record(&mut self) {
        self.window.push_back(Instant::now());
    }

    fn reset(&mut self) {
        self.window.clear();
    }

    fn metrics(&self) -> serde_json::Value {
        serde_json::json!({
            "algorithm": "SlidingWindow",
            "window_size": self.window.len(),
            "window_duration_secs": self.window_size.as_secs(),
        })
    }
}

/// Fixed window algorithm
struct FixedWindow {
    count: u32,
    window_start: Instant,
    window_size: Duration,
}

impl FixedWindow {
    fn new(window_size: Duration) -> Self {
        FixedWindow {
            count: 0,
            window_start: Instant::now(),
            window_size,
        }
    }

    fn check_window(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= self.window_size {
            self.count = 0;
            self.window_start = now;
        }
    }
}

impl RateLimitAlgorithmImpl for FixedWindow {
    fn check(&mut self, limit: u32, _burst: u32) -> bool {
        self.check_window();
        self.count < limit
    }

    fn record(&mut self) {
        self.count += 1;
    }

    fn reset(&mut self) {
        self.count = 0;
        self.window_start = Instant::now();
    }

    fn metrics(&self) -> serde_json::Value {
        serde_json::json!({
            "algorithm": "FixedWindow",
            "count": self.count,
            "window_start": self.window_start.elapsed().as_secs(),
        })
    }
}

/// Leaky bucket algorithm
struct LeakyBucket {
    water_level: f64,
    capacity: f64,
    leak_rate: f64,
    last_leak: Instant,
}

impl LeakyBucket {
    fn new(limit: u32, burst: u32) -> Self {
        LeakyBucket {
            water_level: 0.0,
            capacity: burst as f64,
            leak_rate: limit as f64,
            last_leak: Instant::now(),
        }
    }

    fn leak(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_leak).as_secs_f64();
        let leaked = elapsed * self.leak_rate;
        
        self.water_level = (self.water_level - leaked).max(0.0);
        self.last_leak = now;
    }
}

impl RateLimitAlgorithmImpl for LeakyBucket {
    fn check(&mut self, _limit: u32, _burst: u32) -> bool {
        self.leak();
        self.water_level < self.capacity
    }

    fn record(&mut self) {
        self.water_level += 1.0;
    }

    fn reset(&mut self) {
        self.water_level = 0.0;
        self.last_leak = Instant::now();
    }

    fn metrics(&self) -> serde_json::Value {
        serde_json::json!({
            "algorithm": "LeakyBucket",
            "water_level": self.water_level,
            "capacity": self.capacity,
            "leak_rate": self.leak_rate,
        })
    }
}

/// Adaptive rate limiter
struct AdaptiveRateLimiter {
    base_algorithm: Box<dyn RateLimitAlgorithmImpl>,
    current_limit: u32,
    min_limit: u32,
    max_limit: u32,
    adjustment_factor: f64,
    success_rate: f64,
    total_requests: u64,
    successful_requests: u64,
}

impl AdaptiveRateLimiter {
    fn new(base_limit: u32, burst: u32) -> Self {
        AdaptiveRateLimiter {
            base_algorithm: Box::new(TokenBucket::new(base_limit, burst)),
            current_limit: base_limit,
            min_limit: base_limit / 2,
            max_limit: base_limit * 2,
            adjustment_factor: 0.1,
            success_rate: 1.0,
            total_requests: 0,
            successful_requests: 0,
        }
    }

    fn adjust_limit(&mut self) {
        if self.total_requests > 100 {
            self.success_rate = self.successful_requests as f64 / self.total_requests as f64;
            
            if self.success_rate > 0.95 {
                // Increase limit
                self.current_limit = ((self.current_limit as f64) * (1.0 + self.adjustment_factor))
                    .min(self.max_limit as f64) as u32;
            } else if self.success_rate < 0.8 {
                // Decrease limit
                self.current_limit = ((self.current_limit as f64) * (1.0 - self.adjustment_factor))
                    .max(self.min_limit as f64) as u32;
            }
            
            // Reset counters
            self.total_requests = 0;
            self.successful_requests = 0;
        }
    }
}

impl RateLimitAlgorithmImpl for AdaptiveRateLimiter {
    fn check(&mut self, _limit: u32, burst: u32) -> bool {
        self.total_requests += 1;
        self.adjust_limit();
        
        let allowed = self.base_algorithm.check(self.current_limit, burst);
        if allowed {
            self.successful_requests += 1;
        }
        allowed
    }

    fn record(&mut self) {
        self.base_algorithm.record();
    }

    fn reset(&mut self) {
        self.base_algorithm.reset();
        self.total_requests = 0;
        self.successful_requests = 0;
    }

    fn metrics(&self) -> serde_json::Value {
        serde_json::json!({
            "algorithm": "Adaptive",
            "current_limit": self.current_limit,
            "success_rate": self.success_rate,
            "base_metrics": self.base_algorithm.metrics(),
        })
    }
}

/// Helper function to safely get Unix timestamp
fn safe_unix_timestamp() -> u64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(e) => {
            // Report system time error to Sentry
            sentry::configure_scope(|scope| {
                scope.set_tag("component", "security");
                scope.set_tag("operation", "get_unix_timestamp");
                scope.set_tag("error_type", "system_time_error");
            });
            sentry::capture_message(
                &format!("System time error in rate limiter: {}", e),
                sentry::Level::Error
            );
            // Fallback to epoch time (0) - this should never happen in practice
            0
        }
    }
}

impl EnhancedRateLimiter {
    /// Create a new enhanced rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        let limiter = EnhancedRateLimiter {
            config: Arc::new(RwLock::new(config.clone())),
            client_limiters: Arc::new(RwLock::new(HashMap::new())),
            global_limiter: Arc::new(RwLock::new(GlobalRateLimiter {
                algorithm: Self::create_algorithm(&config.algorithm, config.global_qps, config.global_burst),
                current_qps: 0,
                peak_qps: 0,
                adaptive_limit: config.global_qps,
            })),
            query_type_limiters: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(RateLimitMetrics::default())),
            cleanup_interval: Duration::from_secs(60),
        };

        // Start cleanup thread
        limiter.start_cleanup_thread();
        limiter
    }

    /// Check if a query should be rate limited
    pub fn check_rate_limit(&self, packet: &DnsPacket, client_ip: IpAddr) -> SecurityCheckResult {
        let config = self.config.read();
        if !config.enabled {
            return SecurityCheckResult {
                allowed: true,
                action: SecurityAction::Allow,
                reason: None,
                threat_level: ThreatLevel::None,
                events: Vec::new(),
            };
        }

        let mut metrics = self.metrics.write();
        metrics.total_queries += 1;

        // Check global rate limit
        let mut global = self.global_limiter.write();
        if !global.algorithm.check(config.global_qps, config.global_burst) {
            metrics.blocked_queries += 1;
            return SecurityCheckResult {
                allowed: false,
                action: SecurityAction::RateLimit,
                reason: Some("Global rate limit exceeded".to_string()),
                threat_level: ThreatLevel::Low,
                events: vec![SecurityEvent::GlobalRateLimitExceeded {
                    current_qps: global.current_qps,
                    limit: config.global_qps,
                }],
            };
        }
        global.algorithm.record();
        global.current_qps += 1;
        drop(global);

        // Check per-client rate limit
        let mut client_limiters = self.client_limiters.write();
        let client_limiter = client_limiters.entry(client_ip).or_insert_with(|| {
            ClientRateLimiter {
                algorithm: Self::create_algorithm(&config.algorithm, config.per_client_qps, config.per_client_burst),
                throttled_until: None,
                banned_until: None,
                violation_count: 0,
                last_seen: Instant::now(),
                total_queries: 0,
                blocked_queries: 0,
            }
        });

        client_limiter.total_queries += 1;
        client_limiter.last_seen = Instant::now();

        // Check if client is banned
        if let Some(banned_until) = client_limiter.banned_until {
            if Instant::now() < banned_until {
                client_limiter.blocked_queries += 1;
                metrics.blocked_queries += 1;
                return SecurityCheckResult {
                    allowed: false,
                    action: SecurityAction::BlockRefused,
                    reason: Some(format!("Client {} is banned", client_ip)),
                    threat_level: ThreatLevel::High,
                    events: vec![SecurityEvent::ClientBanned {
                        client_ip,
                        until: banned_until.duration_since(std::time::Instant::now()).as_secs() + safe_unix_timestamp(),
                    }],
                };
            } else {
                client_limiter.banned_until = None;
                client_limiter.violation_count = 0;
            }
        }

        // Check if client is throttled
        if let Some(throttled_until) = client_limiter.throttled_until {
            if Instant::now() < throttled_until {
                client_limiter.blocked_queries += 1;
                metrics.throttled_queries += 1;
                return SecurityCheckResult {
                    allowed: false,
                    action: SecurityAction::RateLimit,
                    reason: Some(format!("Client {} is throttled", client_ip)),
                    threat_level: ThreatLevel::Medium,
                    events: vec![SecurityEvent::ClientThrottled {
                        client_ip,
                        until: throttled_until.duration_since(std::time::Instant::now()).as_secs() + safe_unix_timestamp(),
                    }],
                };
            } else {
                client_limiter.throttled_until = None;
            }
        }

        // Check client rate limit
        if !client_limiter.algorithm.check(config.per_client_qps, config.per_client_burst) {
            client_limiter.violation_count += 1;
            client_limiter.blocked_queries += 1;
            metrics.throttled_queries += 1;

            // Check if client should be banned
            if client_limiter.violation_count >= config.ban_threshold {
                client_limiter.banned_until = Some(Instant::now() + config.ban_duration);
                metrics.banned_clients += 1;
                return SecurityCheckResult {
                    allowed: false,
                    action: SecurityAction::BlockRefused,
                    reason: Some(format!("Client {} exceeded ban threshold", client_ip)),
                    threat_level: ThreatLevel::High,
                    events: vec![SecurityEvent::ClientBanned {
                        client_ip,
                        until: client_limiter.banned_until.unwrap().duration_since(std::time::Instant::now()).as_secs() + safe_unix_timestamp(),
                    }],
                };
            }

            // Throttle the client
            client_limiter.throttled_until = Some(Instant::now() + config.throttle_duration);
            metrics.throttled_clients += 1;
            
            return SecurityCheckResult {
                allowed: false,
                action: SecurityAction::RateLimit,
                reason: Some(format!("Client {} rate limit exceeded", client_ip)),
                threat_level: ThreatLevel::Medium,
                events: vec![SecurityEvent::ClientRateLimitExceeded {
                    client_ip,
                    queries_per_second: config.per_client_qps,
                }],
            };
        }

        client_limiter.algorithm.record();

        // Check query type rate limits
        if let Some(question) = packet.questions.first() {
            let query_type = format!("{:?}", question.qtype);
            if let Some(&limit) = config.query_type_limits.get(&query_type) {
                let mut type_limiters = self.query_type_limiters.write();
                let type_limiter = type_limiters.entry(query_type.clone()).or_insert_with(|| {
                    TypeRateLimiter {
                        query_type: query_type.clone(),
                        limit,
                        current: 0,
                        window_start: Instant::now(),
                    }
                });

                // Reset window if needed
                if Instant::now().duration_since(type_limiter.window_start) >= config.window_size {
                    type_limiter.current = 0;
                    type_limiter.window_start = Instant::now();
                }

                if type_limiter.current >= type_limiter.limit {
                    metrics.throttled_queries += 1;
                    return SecurityCheckResult {
                        allowed: false,
                        action: SecurityAction::RateLimit,
                        reason: Some(format!("Query type {} rate limit exceeded", query_type)),
                        threat_level: ThreatLevel::Medium,
                        events: vec![SecurityEvent::QueryTypeRateLimitExceeded {
                            query_type,
                            limit,
                        }],
                    };
                }

                type_limiter.current += 1;
            }
        }

        SecurityCheckResult {
            allowed: true,
            action: SecurityAction::Allow,
            reason: None,
            threat_level: ThreatLevel::None,
            events: Vec::new(),
        }
    }

    /// Create algorithm instance based on configuration
    fn create_algorithm(algorithm: &RateLimitAlgorithm, limit: u32, burst: u32) -> Box<dyn RateLimitAlgorithmImpl> {
        match algorithm {
            RateLimitAlgorithm::TokenBucket => Box::new(TokenBucket::new(limit, burst)),
            RateLimitAlgorithm::SlidingWindow => Box::new(SlidingWindow::new(Duration::from_secs(1))),
            RateLimitAlgorithm::FixedWindow => Box::new(FixedWindow::new(Duration::from_secs(1))),
            RateLimitAlgorithm::LeakyBucket => Box::new(LeakyBucket::new(limit, burst)),
            RateLimitAlgorithm::Adaptive => Box::new(AdaptiveRateLimiter::new(limit, burst)),
        }
    }

    /// Start cleanup thread
    fn start_cleanup_thread(&self) {
        let client_limiters = Arc::clone(&self.client_limiters);
        let cleanup_interval = self.cleanup_interval;

        std::thread::spawn(move || {
            loop {
                std::thread::sleep(cleanup_interval);
                
                let mut limiters = client_limiters.write();
                let cutoff = Instant::now() - Duration::from_secs(300);
                limiters.retain(|_, limiter| limiter.last_seen > cutoff);
            }
        });
    }

    /// Get rate limiter metrics
    pub fn get_metrics(&self) -> RateLimitMetrics {
        let metrics = self.metrics.read();
        let mut result = metrics.clone();
        
        let client_limiters = self.client_limiters.read();
        result.throttled_clients = client_limiters.iter()
            .filter(|(_, l)| l.throttled_until.is_some())
            .count();
        result.banned_clients = client_limiters.iter()
            .filter(|(_, l)| l.banned_until.is_some())
            .count();
        
        let global = self.global_limiter.read();
        result.current_qps = global.current_qps;
        result.peak_qps = global.peak_qps;
        
        result
    }

    /// Reset all rate limiters
    pub fn reset_all(&self) {
        self.client_limiters.write().clear();
        self.global_limiter.write().algorithm.reset();
        self.query_type_limiters.write().clear();
        *self.metrics.write() = RateLimitMetrics::default();
    }

    /// Unblock a specific client
    pub fn unblock_client(&self, client_ip: IpAddr) {
        if let Some(limiter) = self.client_limiters.write().get_mut(&client_ip) {
            limiter.throttled_until = None;
            limiter.banned_until = None;
            limiter.violation_count = 0;
        }
    }
}

impl SecurityComponent for EnhancedRateLimiter {
    fn check(&self, packet: &DnsPacket, client_ip: IpAddr) -> SecurityCheckResult {
        self.check_rate_limit(packet, client_ip)
    }

    fn metrics(&self) -> serde_json::Value {
        serde_json::to_value(self.get_metrics()).unwrap_or(serde_json::Value::Null)
    }

    fn reset(&self) {
        self.reset_all();
    }

    fn config(&self) -> serde_json::Value {
        serde_json::to_value(&*self.config.read()).unwrap_or(serde_json::Value::Null)
    }

    fn update_config(&self, config: serde_json::Value) -> Result<(), DnsError> {
        let new_config: RateLimitConfig = serde_json::from_value(config)
            .map_err(|_| DnsError::InvalidInput)?;
        *self.config.write() = new_config;
        Ok(())
    }
}

