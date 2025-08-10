//! Rate limiting for DNS queries to prevent abuse and DoS attacks

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Rate limiter for DNS queries
pub struct RateLimiter {
    /// Per-client rate limits
    clients: Arc<Mutex<HashMap<IpAddr, ClientRateLimit>>>,
    /// Global rate limit
    global: Arc<Mutex<GlobalRateLimit>>,
    /// Configuration
    config: RateLimitConfig,
}

#[derive(Clone)]
pub struct RateLimitConfig {
    /// Maximum queries per client per window
    pub client_limit: u32,
    /// Time window for client rate limiting
    pub client_window: Duration,
    /// Maximum global queries per window
    pub global_limit: u32,
    /// Time window for global rate limiting
    pub global_window: Duration,
    /// Enable adaptive rate limiting based on load
    pub adaptive: bool,
    /// Cleanup interval for expired entries
    pub cleanup_interval: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            client_limit: 100,
            client_window: Duration::from_secs(1),
            global_limit: 10000,
            global_window: Duration::from_secs(1),
            adaptive: true,
            cleanup_interval: Duration::from_secs(60),
        }
    }
}

struct ClientRateLimit {
    queries: Vec<Instant>,
    blocked_until: Option<Instant>,
}

struct GlobalRateLimit {
    queries: Vec<Instant>,
    current_limit: u32,
}

impl RateLimiter {
    /// Create a new rate limiter with the given configuration
    pub fn new(config: RateLimitConfig) -> Self {
        let limiter = RateLimiter {
            clients: Arc::new(Mutex::new(HashMap::new())),
            global: Arc::new(Mutex::new(GlobalRateLimit {
                queries: Vec::new(),
                current_limit: config.global_limit,
            })),
            config: config.clone(),
        };

        // Start cleanup thread
        limiter.start_cleanup_thread();
        limiter
    }

    /// Check if a query from the given client is allowed
    pub fn check_allowed(&self, client: IpAddr) -> Result<(), RateLimitExceeded> {
        // Check global rate limit first
        self.check_global_limit()?;
        
        // Then check per-client limit
        self.check_client_limit(client)?;
        
        Ok(())
    }

    /// Record a query from the given client
    pub fn record_query(&self, client: IpAddr) {
        let now = Instant::now();
        
        // Record in global counter
        if let Ok(mut global) = self.global.lock() {
            global.queries.push(now);
            // Keep only recent queries
            let cutoff = now - self.config.global_window;
            global.queries.retain(|&t| t > cutoff);
        }
        
        // Record in per-client counter
        if let Ok(mut clients) = self.clients.lock() {
            let entry = clients.entry(client).or_insert_with(|| ClientRateLimit {
                queries: Vec::new(),
                blocked_until: None,
            });
            
            entry.queries.push(now);
            // Keep only recent queries
            let cutoff = now - self.config.client_window;
            entry.queries.retain(|&t| t > cutoff);
        }
    }

    fn check_global_limit(&self) -> Result<(), RateLimitExceeded> {
        let now = Instant::now();
        
        if let Ok(mut global) = self.global.lock() {
            // Clean old entries
            let cutoff = now - self.config.global_window;
            global.queries.retain(|&t| t > cutoff);
            
            // Adaptive rate limiting
            if self.config.adaptive {
                self.adjust_global_limit(&mut global);
            }
            
            if global.queries.len() >= global.current_limit as usize {
                return Err(RateLimitExceeded::Global {
                    limit: global.current_limit,
                    window: self.config.global_window,
                    retry_after: self.config.global_window,
                });
            }
        }
        
        Ok(())
    }

    fn check_client_limit(&self, client: IpAddr) -> Result<(), RateLimitExceeded> {
        let now = Instant::now();
        
        if let Ok(mut clients) = self.clients.lock() {
            let entry = clients.entry(client).or_insert_with(|| ClientRateLimit {
                queries: Vec::new(),
                blocked_until: None,
            });
            
            // Check if client is temporarily blocked
            if let Some(blocked_until) = entry.blocked_until {
                if now < blocked_until {
                    return Err(RateLimitExceeded::Client {
                        client: client.to_string(),
                        limit: self.config.client_limit,
                        window: self.config.client_window,
                        retry_after: blocked_until - now,
                    });
                } else {
                    entry.blocked_until = None;
                }
            }
            
            // Clean old entries
            let cutoff = now - self.config.client_window;
            entry.queries.retain(|&t| t > cutoff);
            
            if entry.queries.len() >= self.config.client_limit as usize {
                // Block client temporarily
                let block_duration = self.calculate_block_duration(entry.queries.len());
                entry.blocked_until = Some(now + block_duration);
                
                return Err(RateLimitExceeded::Client {
                    client: client.to_string(),
                    limit: self.config.client_limit,
                    window: self.config.client_window,
                    retry_after: block_duration,
                });
            }
        }
        
        Ok(())
    }

    fn adjust_global_limit(&self, global: &mut GlobalRateLimit) {
        // Simple adaptive algorithm: increase limit if we're consistently below 80%
        // and decrease if we're consistently above 95%
        let usage_ratio = global.queries.len() as f32 / global.current_limit as f32;
        
        if usage_ratio < 0.8 && global.current_limit < self.config.global_limit * 2 {
            global.current_limit = (global.current_limit as f32 * 1.1) as u32;
        } else if usage_ratio > 0.95 && global.current_limit > self.config.global_limit / 2 {
            global.current_limit = (global.current_limit as f32 * 0.9) as u32;
        }
    }

    fn calculate_block_duration(&self, query_count: usize) -> Duration {
        // Exponential backoff based on how much the limit was exceeded
        let excess_ratio = query_count as f32 / self.config.client_limit as f32;
        let base_duration = self.config.client_window;
        
        if excess_ratio > 2.0 {
            base_duration * 4
        } else if excess_ratio > 1.5 {
            base_duration * 2
        } else {
            base_duration
        }
    }

    fn start_cleanup_thread(&self) {
        let clients = self.clients.clone();
        let interval = self.config.cleanup_interval;
        let window = self.config.client_window;
        
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(interval);
                
                if let Ok(mut clients_map) = clients.lock() {
                    let now = Instant::now();
                    clients_map.retain(|_, entry| {
                        // Keep entries that have recent queries or are still blocked
                        !entry.queries.is_empty() || 
                        entry.blocked_until.map_or(false, |until| until > now)
                    });
                    
                    // Clean old queries from remaining entries
                    for entry in clients_map.values_mut() {
                        let cutoff = now - window;
                        entry.queries.retain(|&t| t > cutoff);
                    }
                }
            }
        });
    }
}

#[derive(Debug)]
pub enum RateLimitExceeded {
    Client {
        client: String,
        limit: u32,
        window: Duration,
        retry_after: Duration,
    },
    Global {
        limit: u32,
        window: Duration,
        retry_after: Duration,
    },
}

impl std::fmt::Display for RateLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateLimitExceeded::Client { client, limit, window, retry_after } => {
                write!(f, "Client {} exceeded rate limit of {} queries per {:?}. Retry after {:?}",
                       client, limit, window, retry_after)
            }
            RateLimitExceeded::Global { limit, window, retry_after } => {
                write!(f, "Global rate limit of {} queries per {:?} exceeded. Retry after {:?}",
                       limit, window, retry_after)
            }
        }
    }
}

impl std::error::Error for RateLimitExceeded {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_rate_limiter_client_limit() {
        let config = RateLimitConfig {
            client_limit: 5,
            client_window: Duration::from_millis(100),
            ..Default::default()
        };
        
        let limiter = RateLimiter::new(config);
        let client = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // First 5 queries should succeed
        for _ in 0..5 {
            assert!(limiter.check_allowed(client).is_ok());
            limiter.record_query(client);
        }
        
        // 6th query should fail
        assert!(limiter.check_allowed(client).is_err());
        
        // After waiting for the window, should succeed again
        std::thread::sleep(Duration::from_millis(101));
        assert!(limiter.check_allowed(client).is_ok());
    }

    #[test]
    fn test_rate_limiter_multiple_clients() {
        let config = RateLimitConfig {
            client_limit: 2,
            client_window: Duration::from_millis(100),
            ..Default::default()
        };
        
        let limiter = RateLimiter::new(config);
        let client1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let client2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        
        // Both clients should be able to make queries independently
        for _ in 0..2 {
            assert!(limiter.check_allowed(client1).is_ok());
            limiter.record_query(client1);
            assert!(limiter.check_allowed(client2).is_ok());
            limiter.record_query(client2);
        }
        
        // Both should be rate limited
        assert!(limiter.check_allowed(client1).is_err());
        assert!(limiter.check_allowed(client2).is_err());
    }

    #[test]
    fn test_global_rate_limit() {
        let config = RateLimitConfig {
            client_limit: 100,
            client_window: Duration::from_secs(1),
            global_limit: 10,
            global_window: Duration::from_millis(100),
            adaptive: false,
            cleanup_interval: Duration::from_secs(60),
        };
        
        let limiter = RateLimiter::new(config);
        let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        
        // Should allow up to global limit
        for _ in 0..10 {
            assert!(limiter.check_allowed(client).is_ok());
            limiter.record_query(client);
        }
        
        // Should fail when global limit exceeded
        match limiter.check_allowed(client) {
            Err(RateLimitExceeded::Global { limit, .. }) => {
                assert_eq!(limit, 10);
            }
            _ => panic!("Expected global rate limit error"),
        }
    }

    #[test]
    fn test_ipv6_client() {
        let config = RateLimitConfig {
            client_limit: 3,
            client_window: Duration::from_millis(100),
            ..Default::default()
        };
        
        let limiter = RateLimiter::new(config);
        let client = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        
        // IPv6 clients should work the same as IPv4
        for _ in 0..3 {
            assert!(limiter.check_allowed(client).is_ok());
            limiter.record_query(client);
        }
        
        assert!(limiter.check_allowed(client).is_err());
    }

    #[test]
    fn test_block_duration_calculation() {
        let config = RateLimitConfig {
            client_limit: 2,
            client_window: Duration::from_millis(100),
            ..Default::default()
        };
        
        let limiter = RateLimiter::new(config);
        let client = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        
        // Exceed limit significantly
        for _ in 0..5 {
            limiter.record_query(client);
        }
        
        match limiter.check_allowed(client) {
            Err(RateLimitExceeded::Client { retry_after, .. }) => {
                // Should have exponential backoff
                assert!(retry_after > Duration::from_millis(100));
            }
            _ => panic!("Expected client rate limit error"),
        }
    }

    #[test]
    fn test_adaptive_rate_limiting() {
        let config = RateLimitConfig {
            client_limit: 100,
            client_window: Duration::from_secs(1),
            global_limit: 20,
            global_window: Duration::from_millis(100),
            adaptive: true,
            cleanup_interval: Duration::from_secs(60),
        };
        
        let limiter = RateLimiter::new(config);
        let client = IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10));
        
        // Make some queries but stay under 80% usage
        for _ in 0..10 {
            assert!(limiter.check_allowed(client).is_ok());
            limiter.record_query(client);
        }
        
        // Wait for window to reset
        std::thread::sleep(Duration::from_millis(101));
        
        // Adaptive algorithm should adjust limits
        // Make more queries to test adjusted limit
        for _ in 0..15 {
            limiter.record_query(client);
        }
        
        // Should still have room due to adaptive adjustment
        assert!(limiter.global.lock().unwrap().current_limit >= 20);
    }

    #[test]
    fn test_error_display() {
        let client_err = RateLimitExceeded::Client {
            client: "192.168.1.1".to_string(),
            limit: 100,
            window: Duration::from_secs(1),
            retry_after: Duration::from_millis(500),
        };
        
        let display = format!("{}", client_err);
        assert!(display.contains("192.168.1.1"));
        assert!(display.contains("100"));
        
        let global_err = RateLimitExceeded::Global {
            limit: 1000,
            window: Duration::from_secs(1),
            retry_after: Duration::from_millis(200),
        };
        
        let display = format!("{}", global_err);
        assert!(display.contains("Global"));
        assert!(display.contains("1000"));
    }

    #[test]
    fn test_default_config() {
        let config = RateLimitConfig::default();
        assert_eq!(config.client_limit, 100);
        assert_eq!(config.client_window, Duration::from_secs(1));
        assert_eq!(config.global_limit, 10000);
        assert_eq!(config.global_window, Duration::from_secs(1));
        assert!(config.adaptive);
        assert_eq!(config.cleanup_interval, Duration::from_secs(60));
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;
        
        let config = RateLimitConfig {
            client_limit: 50,
            client_window: Duration::from_millis(500),
            global_limit: 200,
            global_window: Duration::from_millis(500),
            ..Default::default()
        };
        
        let limiter = Arc::new(RateLimiter::new(config));
        let mut handles = vec![];
        
        // Spawn multiple threads accessing the rate limiter
        for i in 0..4 {
            let limiter_clone = Arc::clone(&limiter);
            let handle = thread::spawn(move || {
                let client = IpAddr::V4(Ipv4Addr::new(192, 168, 1, i));
                let mut allowed = 0;
                let mut denied = 0;
                
                for _ in 0..30 {
                    match limiter_clone.check_allowed(client) {
                        Ok(_) => {
                            allowed += 1;
                            limiter_clone.record_query(client);
                        }
                        Err(_) => denied += 1,
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                
                (allowed, denied)
            });
            handles.push(handle);
        }
        
        // Wait for all threads and check results
        for handle in handles {
            let (allowed, denied) = handle.join().unwrap();
            // Each thread should have some allowed and possibly some denied
            assert!(allowed > 0);
            // Total should be 30 attempts
            assert_eq!(allowed + denied, 30);
        }
    }

    #[test]
    fn test_cleanup_old_entries() {
        let config = RateLimitConfig {
            client_limit: 5,
            client_window: Duration::from_millis(50),
            cleanup_interval: Duration::from_millis(100),
            ..Default::default()
        };
        
        let limiter = RateLimiter::new(config);
        let client1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let client2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        
        // Add queries for both clients
        limiter.record_query(client1);
        limiter.record_query(client2);
        
        // Wait for cleanup to run
        std::thread::sleep(Duration::from_millis(200));
        
        // Old entries should be cleaned up
        let clients = limiter.clients.lock().unwrap();
        // Clients with old queries should be removed or have empty query lists
        for entry in clients.values() {
            let now = Instant::now();
            for &query_time in &entry.queries {
                assert!(now.duration_since(query_time) < Duration::from_millis(50));
            }
        }
    }
}