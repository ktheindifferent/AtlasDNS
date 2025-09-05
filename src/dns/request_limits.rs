//! Request Size Limits and DoS Protection
//!
//! Provides configurable request size limits for both DNS and HTTP requests
//! to prevent DoS attacks through oversized requests.
//!
//! # Features
//!
//! * **DNS Packet Size Limits** - Configurable limits for UDP/TCP DNS requests
//! * **HTTP Request Size Limits** - Body size and header limits for web requests
//! * **Early Rejection** - Reject oversized requests before processing
//! * **Metrics and Logging** - Track rejected requests and attack patterns
//! * **Per-Client Rate Limiting** - Additional protection against abuse

use std::collections::HashMap;
use std::sync::Arc;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};


/// Request size limits configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLimitsConfig {
    /// Enable request size limiting
    pub enabled: bool,
    
    // DNS Request Limits
    /// Maximum DNS packet size over UDP (bytes)
    pub dns_udp_max_size: usize,
    /// Maximum DNS packet size over TCP (bytes)  
    pub dns_tcp_max_size: usize,
    /// Maximum number of questions per DNS packet
    pub dns_max_questions: usize,
    /// Maximum domain name length
    pub dns_max_domain_length: usize,
    
    // HTTP Request Limits
    /// Maximum HTTP request body size (bytes)
    pub http_max_body_size: u64,
    /// Maximum HTTP header size (bytes)
    pub http_max_header_size: usize,
    /// Maximum number of HTTP headers
    pub http_max_headers: usize,
    /// Maximum URL length
    pub http_max_url_length: usize,
    
    // DoS Protection
    /// Enable per-client tracking
    pub enable_client_tracking: bool,
    /// Maximum oversized requests per client per window
    pub max_oversized_per_client: u32,
    /// Time window for tracking oversized requests (seconds)
    pub tracking_window_seconds: u64,
    /// Block duration for abusive clients (seconds)
    pub block_duration_seconds: u64,
}

impl Default for RequestLimitsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            
            // DNS limits based on RFC recommendations
            dns_udp_max_size: 512,     // Standard UDP DNS limit
            dns_tcp_max_size: 65535,   // Maximum TCP DNS message size
            dns_max_questions: 1,       // Most DNS queries have single question
            dns_max_domain_length: 253, // RFC 1035 limit
            
            // HTTP limits - reasonable defaults
            http_max_body_size: 10 * 1024 * 1024, // 10MB
            http_max_header_size: 8192,            // 8KB per header
            http_max_headers: 100,                 // Maximum headers
            http_max_url_length: 2048,             // 2KB URL length
            
            // DoS protection
            enable_client_tracking: true,
            max_oversized_per_client: 5,     // 5 oversized requests per window
            tracking_window_seconds: 300,    // 5 minute window
            block_duration_seconds: 3600,    // 1 hour block
        }
    }
}

/// Client tracking for DoS protection
#[derive(Debug, Clone)]
struct ClientTracker {
    /// Number of oversized requests
    oversized_count: u32,
    /// Window start time
    window_start: Instant,
    /// Block expiration time (if blocked)
    blocked_until: Option<Instant>,
    /// Last violation timestamp
    last_violation: Instant,
}

impl ClientTracker {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            oversized_count: 0,
            window_start: now,
            blocked_until: None,
            last_violation: now,
        }
    }

    /// Check if client is currently blocked
    fn is_blocked(&self) -> bool {
        self.blocked_until
            .map(|until| Instant::now() < until)
            .unwrap_or(false)
    }

    /// Reset tracking window if expired
    fn maybe_reset_window(&mut self, window_duration: Duration) {
        if self.window_start.elapsed() >= window_duration {
            self.oversized_count = 0;
            self.window_start = Instant::now();
        }
    }

    /// Record an oversized request
    fn record_oversized(&mut self, config: &RequestLimitsConfig) -> bool {
        let window_duration = Duration::from_secs(config.tracking_window_seconds);
        self.maybe_reset_window(window_duration);
        
        self.oversized_count += 1;
        self.last_violation = Instant::now();
        
        // Check if client should be blocked
        if self.oversized_count > config.max_oversized_per_client {
            self.blocked_until = Some(
                Instant::now() + Duration::from_secs(config.block_duration_seconds)
            );
            return true; // Client is now blocked
        }
        
        false
    }
}

/// Request size validation result
#[derive(Debug)]
pub enum SizeValidationResult {
    /// Request size is acceptable
    Valid,
    /// Request exceeds size limits
    TooLarge { 
        actual_size: usize, 
        limit: usize, 
        request_type: String 
    },
    /// Client is blocked due to repeated violations
    ClientBlocked { 
        blocked_until: Instant 
    },
}

/// Statistics for request size limiting
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RequestLimitsStats {
    /// Total requests checked
    pub requests_checked: u64,
    /// DNS requests rejected (UDP)
    pub dns_udp_rejected: u64,
    /// DNS requests rejected (TCP)
    pub dns_tcp_rejected: u64,
    /// HTTP requests rejected
    pub http_rejected: u64,
    /// Clients currently blocked
    pub clients_blocked: u64,
    /// Total violations by type
    pub violations_by_type: HashMap<String, u64>,
}

/// Request size limits enforcement
pub struct RequestLimiter {
    /// Configuration
    config: Arc<RwLock<RequestLimitsConfig>>,
    /// Per-client tracking
    client_trackers: Arc<RwLock<HashMap<IpAddr, ClientTracker>>>,
    /// Statistics
    stats: Arc<RwLock<RequestLimitsStats>>,
}

impl RequestLimiter {
    /// Create new request limiter
    pub fn new(config: RequestLimitsConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            client_trackers: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(RequestLimitsStats::default())),
        }
    }

    /// Validate DNS packet size (UDP)
    pub fn validate_dns_udp_request(
        &self,
        packet_size: usize,
        client_ip: Option<IpAddr>,
    ) -> SizeValidationResult {
        let config = self.config.read();
        
        if !config.enabled {
            return SizeValidationResult::Valid;
        }

        self.stats.write().requests_checked += 1;

        // Check size limit
        if packet_size > config.dns_udp_max_size {
            self.stats.write().dns_udp_rejected += 1;
            self.record_violation("dns_udp", client_ip, &config);
            
            return SizeValidationResult::TooLarge {
                actual_size: packet_size,
                limit: config.dns_udp_max_size,
                request_type: "DNS UDP".to_string(),
            };
        }

        // Check if client is blocked
        if let Some(ip) = client_ip {
            if config.enable_client_tracking {
                let trackers = self.client_trackers.read();
                if let Some(tracker) = trackers.get(&ip) {
                    if tracker.is_blocked() {
                        return SizeValidationResult::ClientBlocked {
                            blocked_until: tracker.blocked_until.unwrap(),
                        };
                    }
                }
            }
        }

        SizeValidationResult::Valid
    }

    /// Validate DNS packet size (TCP)
    pub fn validate_dns_tcp_request(
        &self,
        packet_size: usize,
        client_ip: Option<IpAddr>,
    ) -> SizeValidationResult {
        let config = self.config.read();
        
        if !config.enabled {
            return SizeValidationResult::Valid;
        }

        self.stats.write().requests_checked += 1;

        // Check size limit
        if packet_size > config.dns_tcp_max_size {
            self.stats.write().dns_tcp_rejected += 1;
            self.record_violation("dns_tcp", client_ip, &config);
            
            return SizeValidationResult::TooLarge {
                actual_size: packet_size,
                limit: config.dns_tcp_max_size,
                request_type: "DNS TCP".to_string(),
            };
        }

        // Check if client is blocked
        if let Some(ip) = client_ip {
            if config.enable_client_tracking {
                let trackers = self.client_trackers.read();
                if let Some(tracker) = trackers.get(&ip) {
                    if tracker.is_blocked() {
                        return SizeValidationResult::ClientBlocked {
                            blocked_until: tracker.blocked_until.unwrap(),
                        };
                    }
                }
            }
        }

        SizeValidationResult::Valid
    }

    /// Validate HTTP request size
    pub fn validate_http_request(
        &self,
        body_size: u64,
        header_size: usize,
        header_count: usize,
        url_length: usize,
        client_ip: Option<IpAddr>,
    ) -> SizeValidationResult {
        let config = self.config.read();
        
        if !config.enabled {
            return SizeValidationResult::Valid;
        }

        self.stats.write().requests_checked += 1;

        // Check body size limit
        if body_size > config.http_max_body_size {
            self.stats.write().http_rejected += 1;
            self.record_violation("http_body", client_ip, &config);
            
            return SizeValidationResult::TooLarge {
                actual_size: body_size as usize,
                limit: config.http_max_body_size as usize,
                request_type: "HTTP Body".to_string(),
            };
        }

        // Check header size limit
        if header_size > config.http_max_header_size {
            self.stats.write().http_rejected += 1;
            self.record_violation("http_headers", client_ip, &config);
            
            return SizeValidationResult::TooLarge {
                actual_size: header_size,
                limit: config.http_max_header_size,
                request_type: "HTTP Headers".to_string(),
            };
        }

        // Check header count limit
        if header_count > config.http_max_headers {
            self.stats.write().http_rejected += 1;
            self.record_violation("http_header_count", client_ip, &config);
            
            return SizeValidationResult::TooLarge {
                actual_size: header_count,
                limit: config.http_max_headers,
                request_type: "HTTP Header Count".to_string(),
            };
        }

        // Check URL length limit
        if url_length > config.http_max_url_length {
            self.stats.write().http_rejected += 1;
            self.record_violation("http_url", client_ip, &config);
            
            return SizeValidationResult::TooLarge {
                actual_size: url_length,
                limit: config.http_max_url_length,
                request_type: "HTTP URL".to_string(),
            };
        }

        // Check if client is blocked
        if let Some(ip) = client_ip {
            if config.enable_client_tracking {
                let trackers = self.client_trackers.read();
                if let Some(tracker) = trackers.get(&ip) {
                    if tracker.is_blocked() {
                        return SizeValidationResult::ClientBlocked {
                            blocked_until: tracker.blocked_until.unwrap(),
                        };
                    }
                }
            }
        }

        SizeValidationResult::Valid
    }

    /// Record a size violation
    fn record_violation(
        &self,
        violation_type: &str,
        client_ip: Option<IpAddr>,
        config: &RequestLimitsConfig,
    ) {
        // Update violation statistics
        {
            let mut stats = self.stats.write();
            let count = stats.violations_by_type
                .entry(violation_type.to_string())
                .or_insert(0);
            *count += 1;
        }

        // Track per-client violations if enabled
        if let Some(ip) = client_ip {
            if config.enable_client_tracking {
                let mut trackers = self.client_trackers.write();
                let tracker = trackers.entry(ip).or_insert_with(ClientTracker::new);
                
                let was_blocked = tracker.is_blocked();
                let now_blocked = tracker.record_oversized(config);
                
                // Update blocked clients count
                if now_blocked && !was_blocked {
                    self.stats.write().clients_blocked += 1;
                    
                    log::warn!(
                        "Client {} blocked due to repeated oversized requests (type: {})",
                        ip, violation_type
                    );
                }
            }
        }

        log::info!(
            "Request size violation: type={}, client={:?}, total={}",
            violation_type,
            client_ip,
            self.stats.read().violations_by_type.get(violation_type).unwrap_or(&0)
        );
    }

    /// Validate DNS packet content limits
    pub fn validate_dns_packet_content(
        &self,
        question_count: usize,
        domain_names: &[String],
        client_ip: Option<IpAddr>,
    ) -> SizeValidationResult {
        let config = self.config.read();
        
        if !config.enabled {
            return SizeValidationResult::Valid;
        }

        // Check question count
        if question_count > config.dns_max_questions {
            self.record_violation("dns_questions", client_ip, &config);
            
            return SizeValidationResult::TooLarge {
                actual_size: question_count,
                limit: config.dns_max_questions,
                request_type: "DNS Questions".to_string(),
            };
        }

        // Check domain name lengths
        for domain in domain_names {
            if domain.len() > config.dns_max_domain_length {
                self.record_violation("dns_domain_length", client_ip, &config);
                
                return SizeValidationResult::TooLarge {
                    actual_size: domain.len(),
                    limit: config.dns_max_domain_length,
                    request_type: "DNS Domain Length".to_string(),
                };
            }
        }

        SizeValidationResult::Valid
    }

    /// Clean up old client tracking data
    pub fn cleanup_old_trackers(&self) {
        let config = self.config.read();
        let cleanup_age = Duration::from_secs(config.tracking_window_seconds * 2);
        
        self.client_trackers.write().retain(|_, tracker| {
            // Keep if still blocked or recently active
            tracker.is_blocked() || tracker.last_violation.elapsed() < cleanup_age
        });

        // Update blocked clients count
        let blocked_count = self.client_trackers
            .read()
            .values()
            .filter(|t| t.is_blocked())
            .count() as u64;
        
        self.stats.write().clients_blocked = blocked_count;
    }

    /// Get current statistics
    pub fn get_stats(&self) -> RequestLimitsStats {
        let stats = self.stats.read();
        RequestLimitsStats {
            requests_checked: stats.requests_checked,
            dns_udp_rejected: stats.dns_udp_rejected,
            dns_tcp_rejected: stats.dns_tcp_rejected,
            http_rejected: stats.http_rejected,
            clients_blocked: stats.clients_blocked,
            violations_by_type: stats.violations_by_type.clone(),
        }
    }

    /// Update configuration
    pub fn update_config(&self, new_config: RequestLimitsConfig) {
        *self.config.write() = new_config;
        log::info!("Request limits configuration updated");
    }

    /// Get current configuration
    pub fn get_config(&self) -> RequestLimitsConfig {
        self.config.read().clone()
    }

    /// Check if client is blocked
    pub fn is_client_blocked(&self, client_ip: IpAddr) -> bool {
        let config = self.config.read();
        if !config.enabled || !config.enable_client_tracking {
            return false;
        }

        self.client_trackers
            .read()
            .get(&client_ip)
            .map(|tracker| tracker.is_blocked())
            .unwrap_or(false)
    }

    /// Manually unblock a client (for administrative purposes)
    pub fn unblock_client(&self, client_ip: IpAddr) -> bool {
        let mut trackers = self.client_trackers.write();
        if let Some(tracker) = trackers.get_mut(&client_ip) {
            if tracker.is_blocked() {
                tracker.blocked_until = None;
                tracker.oversized_count = 0;
                tracker.window_start = Instant::now();
                
                log::info!("Manually unblocked client: {}", client_ip);
                return true;
            }
        }
        false
    }

    /// Get list of currently blocked clients
    pub fn get_blocked_clients(&self) -> Vec<(IpAddr, Instant)> {
        self.client_trackers
            .read()
            .iter()
            .filter_map(|(ip, tracker)| {
                if tracker.is_blocked() {
                    Some((*ip, tracker.blocked_until.unwrap()))
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_dns_udp_size_validation() {
        let config = RequestLimitsConfig {
            enabled: true,
            dns_udp_max_size: 512,
            ..Default::default()
        };
        let limiter = RequestLimiter::new(config);
        
        // Valid request
        let result = limiter.validate_dns_udp_request(256, None);
        assert!(matches!(result, SizeValidationResult::Valid));
        
        // Oversized request
        let result = limiter.validate_dns_udp_request(1024, None);
        assert!(matches!(result, SizeValidationResult::TooLarge { .. }));
    }

    #[test]
    fn test_http_size_validation() {
        let config = RequestLimitsConfig {
            enabled: true,
            http_max_body_size: 1024,
            http_max_header_size: 512,
            http_max_headers: 10,
            http_max_url_length: 256,
            ..Default::default()
        };
        let limiter = RequestLimiter::new(config);
        
        // Valid request
        let result = limiter.validate_http_request(512, 256, 5, 128, None);
        assert!(matches!(result, SizeValidationResult::Valid));
        
        // Oversized body
        let result = limiter.validate_http_request(2048, 256, 5, 128, None);
        assert!(matches!(result, SizeValidationResult::TooLarge { .. }));
    }

    #[test]
    fn test_client_blocking() {
        let mut config = RequestLimitsConfig::default();
        config.max_oversized_per_client = 2;
        config.enable_client_tracking = true;
        
        let limiter = RequestLimiter::new(config);
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        
        // First violation - should not block
        let result = limiter.validate_dns_udp_request(1024, Some(client_ip));
        assert!(matches!(result, SizeValidationResult::TooLarge { .. }));
        assert!(!limiter.is_client_blocked(client_ip));
        
        // Second violation - should not block yet
        let result = limiter.validate_dns_udp_request(1024, Some(client_ip));
        assert!(matches!(result, SizeValidationResult::TooLarge { .. }));
        assert!(!limiter.is_client_blocked(client_ip));
        
        // Third violation - should block
        let result = limiter.validate_dns_udp_request(1024, Some(client_ip));
        assert!(matches!(result, SizeValidationResult::TooLarge { .. }));
        assert!(limiter.is_client_blocked(client_ip));
        
        // Subsequent requests should be blocked
        let result = limiter.validate_dns_udp_request(256, Some(client_ip));
        assert!(matches!(result, SizeValidationResult::ClientBlocked { .. }));
    }

    #[test]
    fn test_dns_content_validation() {
        let config = RequestLimitsConfig {
            enabled: true,
            dns_max_questions: 1,
            dns_max_domain_length: 253,
            ..Default::default()
        };
        let limiter = RequestLimiter::new(config);
        
        // Valid content
        let domains = vec!["example.com".to_string()];
        let result = limiter.validate_dns_packet_content(1, &domains, None);
        assert!(matches!(result, SizeValidationResult::Valid));
        
        // Too many questions
        let result = limiter.validate_dns_packet_content(2, &domains, None);
        assert!(matches!(result, SizeValidationResult::TooLarge { .. }));
        
        // Domain too long
        let long_domain = "a".repeat(300);
        let domains = vec![long_domain];
        let result = limiter.validate_dns_packet_content(1, &domains, None);
        assert!(matches!(result, SizeValidationResult::TooLarge { .. }));
    }

    #[test]
    fn test_statistics_tracking() {
        let limiter = RequestLimiter::new(RequestLimitsConfig::default());
        
        // Generate some violations
        limiter.validate_dns_udp_request(1024, None);
        limiter.validate_http_request(1024 * 1024 * 20, 256, 5, 128, None);
        
        let stats = limiter.get_stats();
        assert!(stats.requests_checked >= 2);
        assert!(stats.dns_udp_rejected >= 1);
        assert!(stats.http_rejected >= 1);
        assert!(!stats.violations_by_type.is_empty());
    }
}