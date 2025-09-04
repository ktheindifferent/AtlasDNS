/// Enhanced Rate Limiting for Web API
/// 
/// Provides per-IP and per-user rate limiting with configurable limits,
/// time windows, and automatic cleanup of expired entries.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};

/// Rate limit error types
#[derive(Debug, Clone, Serialize)]
pub enum RateLimitError {
    IpLimitExceeded {
        ip: String,
        limit: u32,
        window: Duration,
        retry_after: u64,
    },
    UserLimitExceeded {
        user: String,
        limit: u32,
        window: Duration,
        retry_after: u64,
    },
    GlobalLimitExceeded {
        limit: u32,
        window: Duration,
        retry_after: u64,
    },
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateLimitError::IpLimitExceeded { ip, limit, window, retry_after } => {
                write!(f, "Rate limit exceeded for IP {}: {} requests per {:?}. Retry after {} seconds", 
                    ip, limit, window, retry_after)
            }
            RateLimitError::UserLimitExceeded { user, limit, window, retry_after } => {
                write!(f, "Rate limit exceeded for user {}: {} requests per {:?}. Retry after {} seconds", 
                    user, limit, window, retry_after)
            }
            RateLimitError::GlobalLimitExceeded { limit, window, retry_after } => {
                write!(f, "Global rate limit exceeded: {} requests per {:?}. Retry after {} seconds", 
                    limit, window, retry_after)
            }
        }
    }
}

impl std::error::Error for RateLimitError {}

/// Rate limiter configuration
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimiterConfig {
    /// Per-IP limits for unauthenticated requests
    pub ip_limits: Vec<RateLimit>,
    /// Per-user limits for authenticated requests
    pub user_limits: Vec<RateLimit>,
    /// Global rate limits
    pub global_limits: Vec<RateLimit>,
    /// Enable automatic cleanup
    pub auto_cleanup: bool,
    /// Cleanup interval
    pub cleanup_interval: Duration,
    /// Enable adaptive rate limiting
    pub adaptive: bool,
    /// Whitelist of IPs that bypass rate limiting
    pub ip_whitelist: Vec<IpAddr>,
    /// Blacklist of IPs that are always blocked
    pub ip_blacklist: Vec<IpAddr>,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            ip_limits: vec![
                RateLimit {
                    requests: 10,
                    window: Duration::from_secs(1),
                    burst: Some(20),
                },
                RateLimit {
                    requests: 100,
                    window: Duration::from_secs(60),
                    burst: Some(150),
                },
                RateLimit {
                    requests: 1000,
                    window: Duration::from_secs(3600),
                    burst: None,
                },
            ],
            user_limits: vec![
                RateLimit {
                    requests: 30,
                    window: Duration::from_secs(1),
                    burst: Some(50),
                },
                RateLimit {
                    requests: 500,
                    window: Duration::from_secs(60),
                    burst: Some(750),
                },
                RateLimit {
                    requests: 10000,
                    window: Duration::from_secs(3600),
                    burst: None,
                },
            ],
            global_limits: vec![
                RateLimit {
                    requests: 1000,
                    window: Duration::from_secs(1),
                    burst: Some(2000),
                },
                RateLimit {
                    requests: 50000,
                    window: Duration::from_secs(60),
                    burst: None,
                },
            ],
            auto_cleanup: true,
            cleanup_interval: Duration::from_secs(300),
            adaptive: false,
            ip_whitelist: vec![],
            ip_blacklist: vec![],
        }
    }
}

/// Individual rate limit configuration
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimit {
    /// Number of requests allowed
    pub requests: u32,
    /// Time window for the limit
    pub window: Duration,
    /// Optional burst allowance
    pub burst: Option<u32>,
}

/// Sliding window counter for rate limiting
#[derive(Debug, Clone)]
struct SlidingWindow {
    /// Request timestamps
    timestamps: Vec<Instant>,
    /// Token bucket for burst handling
    tokens: f64,
    /// Last token refill time
    last_refill: Instant,
}

impl SlidingWindow {
    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
            tokens: 0.0,
            last_refill: Instant::now(),
        }
    }

    /// Check if request is allowed under the given limit
    fn check(&mut self, limit: &RateLimit) -> Result<(), Duration> {
        let now = Instant::now();
        
        // Clean old timestamps
        let cutoff = now - limit.window;
        self.timestamps.retain(|&t| t > cutoff);
        
        // Handle burst with token bucket
        if let Some(burst) = limit.burst {
            // Refill tokens
            let elapsed = now.duration_since(self.last_refill);
            let refill_rate = limit.requests as f64 / limit.window.as_secs_f64();
            self.tokens = (self.tokens + elapsed.as_secs_f64() * refill_rate).min(burst as f64);
            self.last_refill = now;
            
            // Check if we have tokens available
            if self.tokens >= 1.0 {
                self.tokens -= 1.0;
                self.timestamps.push(now);
                return Ok(());
            }
        }
        
        // Check standard rate limit
        if self.timestamps.len() < limit.requests as usize {
            self.timestamps.push(now);
            Ok(())
        } else {
            // Calculate retry after
            let oldest = self.timestamps.first().copied().unwrap_or(now);
            let retry_after = (oldest + limit.window).saturating_duration_since(now);
            Err(retry_after)
        }
    }

    /// Record a successful request
    fn record(&mut self, now: Instant) {
        self.timestamps.push(now);
    }
}

/// Enhanced rate limiter for web API
pub struct WebRateLimiter {
    /// Per-IP rate limiting
    ip_windows: Arc<RwLock<HashMap<IpAddr, Vec<SlidingWindow>>>>,
    /// Per-user rate limiting
    user_windows: Arc<RwLock<HashMap<String, Vec<SlidingWindow>>>>,
    /// Global rate limiting
    global_windows: Arc<RwLock<Vec<SlidingWindow>>>,
    /// Configuration
    config: RateLimiterConfig,
    /// Statistics
    stats: Arc<RwLock<RateLimiterStats>>,
}

/// Rate limiter statistics
#[derive(Debug, Clone, Default, Serialize)]
pub struct RateLimiterStats {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub unique_ips: usize,
    pub unique_users: usize,
    pub blacklisted_attempts: u64,
}

impl WebRateLimiter {
    /// Create a new web rate limiter
    pub fn new(config: RateLimiterConfig) -> Self {
        let limiter = Self {
            ip_windows: Arc::new(RwLock::new(HashMap::new())),
            user_windows: Arc::new(RwLock::new(HashMap::new())),
            global_windows: Arc::new(RwLock::new(
                vec![SlidingWindow::new(); config.global_limits.len()]
            )),
            config: config.clone(),
            stats: Arc::new(RwLock::new(RateLimiterStats::default())),
        };

        // Start cleanup thread if enabled
        if config.auto_cleanup {
            limiter.start_cleanup_thread();
        }

        limiter
    }

    /// Check if a request is allowed
    pub fn check_request(
        &self,
        ip: IpAddr,
        user: Option<&str>,
    ) -> Result<(), RateLimitError> {
        // Update stats
        if let Ok(mut stats) = self.stats.write() {
            stats.total_requests += 1;
        }

        // Check blacklist
        if self.config.ip_blacklist.contains(&ip) {
            if let Ok(mut stats) = self.stats.write() {
                stats.blacklisted_attempts += 1;
                stats.blocked_requests += 1;
            }
            return Err(RateLimitError::IpLimitExceeded {
                ip: ip.to_string(),
                limit: 0,
                window: Duration::from_secs(3600),
                retry_after: 3600,
            });
        }

        // Skip rate limiting for whitelisted IPs
        if self.config.ip_whitelist.contains(&ip) {
            return Ok(());
        }

        // Check global limits
        self.check_global_limits()?;

        // Check user limits if authenticated
        if let Some(user_id) = user {
            self.check_user_limits(user_id)?;
        } else {
            // Check IP limits for unauthenticated requests
            self.check_ip_limits(ip)?;
        }

        Ok(())
    }

    /// Record a successful request
    pub fn record_request(&self, ip: IpAddr, user: Option<&str>) {
        let now = Instant::now();

        // Record in global windows
        if let Ok(mut windows) = self.global_windows.write() {
            for window in windows.iter_mut() {
                window.record(now);
            }
        }

        // Record for user or IP
        if let Some(user_id) = user {
            if let Ok(mut users) = self.user_windows.write() {
                let windows = users.entry(user_id.to_string()).or_insert_with(|| {
                    vec![SlidingWindow::new(); self.config.user_limits.len()]
                });
                for window in windows.iter_mut() {
                    window.record(now);
                }
                
                // Update stats
                if let Ok(mut stats) = self.stats.write() {
                    stats.unique_users = users.len();
                }
            }
        } else {
            if let Ok(mut ips) = self.ip_windows.write() {
                let windows = ips.entry(ip).or_insert_with(|| {
                    vec![SlidingWindow::new(); self.config.ip_limits.len()]
                });
                for window in windows.iter_mut() {
                    window.record(now);
                }
                
                // Update stats
                if let Ok(mut stats) = self.stats.write() {
                    stats.unique_ips = ips.len();
                }
            }
        }
    }

    /// Check global rate limits
    fn check_global_limits(&self) -> Result<(), RateLimitError> {
        if let Ok(mut windows) = self.global_windows.write() {
            for (i, window) in windows.iter_mut().enumerate() {
                if let Some(limit) = self.config.global_limits.get(i) {
                    if let Err(retry_after) = window.check(limit) {
                        if let Ok(mut stats) = self.stats.write() {
                            stats.blocked_requests += 1;
                        }
                        return Err(RateLimitError::GlobalLimitExceeded {
                            limit: limit.requests,
                            window: limit.window,
                            retry_after: retry_after.as_secs(),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Check IP-based rate limits
    fn check_ip_limits(&self, ip: IpAddr) -> Result<(), RateLimitError> {
        if let Ok(mut ips) = self.ip_windows.write() {
            let windows = ips.entry(ip).or_insert_with(|| {
                vec![SlidingWindow::new(); self.config.ip_limits.len()]
            });
            
            for (i, window) in windows.iter_mut().enumerate() {
                if let Some(limit) = self.config.ip_limits.get(i) {
                    if let Err(retry_after) = window.check(limit) {
                        if let Ok(mut stats) = self.stats.write() {
                            stats.blocked_requests += 1;
                        }
                        return Err(RateLimitError::IpLimitExceeded {
                            ip: ip.to_string(),
                            limit: limit.requests,
                            window: limit.window,
                            retry_after: retry_after.as_secs(),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Check user-based rate limits
    fn check_user_limits(&self, user: &str) -> Result<(), RateLimitError> {
        if let Ok(mut users) = self.user_windows.write() {
            let windows = users.entry(user.to_string()).or_insert_with(|| {
                vec![SlidingWindow::new(); self.config.user_limits.len()]
            });
            
            for (i, window) in windows.iter_mut().enumerate() {
                if let Some(limit) = self.config.user_limits.get(i) {
                    if let Err(retry_after) = window.check(limit) {
                        if let Ok(mut stats) = self.stats.write() {
                            stats.blocked_requests += 1;
                        }
                        return Err(RateLimitError::UserLimitExceeded {
                            user: user.to_string(),
                            limit: limit.requests,
                            window: limit.window,
                            retry_after: retry_after.as_secs(),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Start background cleanup thread
    fn start_cleanup_thread(&self) {
        let ip_windows = self.ip_windows.clone();
        let user_windows = self.user_windows.clone();
        let interval = self.config.cleanup_interval;
        
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(interval);
                
                // Cleanup old IP entries
                if let Ok(mut ips) = ip_windows.write() {
                    let now = Instant::now();
                    ips.retain(|_, windows| {
                        // Keep entries with recent activity
                        windows.iter().any(|w| {
                            w.timestamps.iter().any(|&t| 
                                now.duration_since(t) < Duration::from_secs(3600)
                            )
                        })
                    });
                }
                
                // Cleanup old user entries
                if let Ok(mut users) = user_windows.write() {
                    let now = Instant::now();
                    users.retain(|_, windows| {
                        windows.iter().any(|w| {
                            w.timestamps.iter().any(|&t| 
                                now.duration_since(t) < Duration::from_secs(3600)
                            )
                        })
                    });
                }
                
                log::debug!("Rate limiter cleanup completed");
            }
        });
    }

    /// Get current statistics
    pub fn get_stats(&self) -> RateLimiterStats {
        self.stats.read()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        if let Ok(mut stats) = self.stats.write() {
            *stats = RateLimiterStats::default();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_sliding_window() {
        let mut window = SlidingWindow::new();
        let limit = RateLimit {
            requests: 3,
            window: Duration::from_secs(1),
            burst: Some(5),
        };

        // Should allow first 3 requests
        assert!(window.check(&limit).is_ok());
        assert!(window.check(&limit).is_ok());
        assert!(window.check(&limit).is_ok());
        
        // 4th request should use burst
        assert!(window.check(&limit).is_ok());
        
        // Eventually should be rate limited
        for _ in 0..10 {
            let _ = window.check(&limit);
        }
        assert!(window.check(&limit).is_err());
    }

    #[test]
    fn test_rate_limiter() {
        let config = RateLimiterConfig::default();
        let limiter = WebRateLimiter::new(config);
        
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        
        // Should allow initial requests
        assert!(limiter.check_request(ip, None).is_ok());
        limiter.record_request(ip, None);
        
        // Test with authenticated user
        assert!(limiter.check_request(ip, Some("user123")).is_ok());
        limiter.record_request(ip, Some("user123"));
        
        // Stats should be updated
        let stats = limiter.get_stats();
        assert!(stats.total_requests > 0);
        assert_eq!(stats.unique_ips, 1);
        assert_eq!(stats.unique_users, 1);
    }

    #[test]
    fn test_blacklist() {
        let mut config = RateLimiterConfig::default();
        let blacklisted_ip = IpAddr::from_str("10.0.0.1").unwrap();
        config.ip_blacklist.push(blacklisted_ip);
        
        let limiter = WebRateLimiter::new(config);
        
        // Blacklisted IP should always be blocked
        assert!(limiter.check_request(blacklisted_ip, None).is_err());
        
        let stats = limiter.get_stats();
        assert_eq!(stats.blacklisted_attempts, 1);
    }

    #[test]
    fn test_whitelist() {
        let mut config = RateLimiterConfig::default();
        let whitelisted_ip = IpAddr::from_str("10.0.0.2").unwrap();
        config.ip_whitelist.push(whitelisted_ip);
        config.ip_limits = vec![RateLimit {
            requests: 1,
            window: Duration::from_secs(60),
            burst: None,
        }];
        
        let limiter = WebRateLimiter::new(config);
        
        // Whitelisted IP should bypass all limits
        for _ in 0..100 {
            assert!(limiter.check_request(whitelisted_ip, None).is_ok());
            limiter.record_request(whitelisted_ip, None);
        }
    }
}