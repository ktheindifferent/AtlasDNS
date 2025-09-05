//! Example of implementing comprehensive DNS security
//!
//! This example demonstrates how to configure and use the Atlas DNS server
//! with comprehensive security features including:
//! 
//! - Request size limits and DoS protection
//! - Cache poisoning protection with multiple defense layers
//! - Enhanced logging and monitoring
//!
//! # Usage
//!
//! ```rust
//! use std::sync::Arc;
//! use atlas_dns::dns::context::ServerContext;
//! use atlas_dns::dns::request_limits::{RequestLimiter, RequestLimitsConfig};
//! use atlas_dns::dns::cache_poisoning::{CachePoisonProtection, PoisonProtectionConfig};
//!
//! // Initialize server context with security features
//! let mut context = ServerContext::new().expect("Failed to create context");
//!
//! // Enable request size limits
//! context.enable_default_request_limits();
//!
//! // Enable cache poisoning protection
//! context.enable_default_cache_poison_protection();
//!
//! // Initialize the server
//! context.initialize().expect("Failed to initialize server");
//! ```

use std::sync::Arc;
use std::time::Duration;
use std::net::{IpAddr, SocketAddr};
use crate::dns::context::ServerContext;
use crate::dns::request_limits::RequestLimitsConfig;
use crate::dns::cache_poisoning::PoisonProtectionConfig;
use crate::dns::protocol::DnsPacket;

/// Example configuration for production security settings
pub fn create_secure_dns_server() -> Result<Arc<ServerContext>, Box<dyn std::error::Error>> {
    let mut context = ServerContext::new()?;
    
    // Configure request size limits for production
    let request_limits_config = RequestLimitsConfig {
        enabled: true,
        
        // DNS limits - conservative for security
        dns_udp_max_size: 512,        // Standard UDP limit
        dns_tcp_max_size: 4096,       // Reasonable TCP limit (not max)
        dns_max_questions: 1,         // Single question per query
        dns_max_domain_length: 253,   // RFC limit
        
        // HTTP limits - reasonable for web interface
        http_max_body_size: 1024 * 1024, // 1MB
        http_max_header_size: 4096,       // 4KB per header
        http_max_headers: 50,             // 50 headers max
        http_max_url_length: 1024,        // 1KB URL
        
        // DoS protection - aggressive settings
        enable_client_tracking: true,
        max_oversized_per_client: 3,      // Only 3 strikes
        tracking_window_seconds: 300,     // 5 minute window
        block_duration_seconds: 1800,     // 30 minute block
    };
    
    // Configure cache poisoning protection
    let poison_protection_config = PoisonProtectionConfig {
        enabled: true,
        
        // Enhanced randomization
        port_randomization: true,
        port_range: (32768, 65535),       // Large ephemeral port range
        bit_0x20: true,                   // Enable 0x20 encoding
        
        // Strict validation
        dnssec_validation: true,
        bailiwick_check: true,
        
        // Conservative TTL limits
        max_ttl: 86400,                   // 24 hours max
        min_ttl: 0,                       // Allow 0 TTL
        
        // Timing constraints
        response_window_ms: 3000,         // 3 second response window
        max_retries: 2,                   // Limited retries
    };
    
    // Apply security configurations
    context.enable_request_limits(request_limits_config);
    context.enable_cache_poison_protection(poison_protection_config);
    
    // Initialize the context
    context.initialize()?;
    
    log::info!("Secure DNS server initialized with comprehensive protection");
    
    Ok(Arc::new(context))
}

/// Example of validating a DNS request with all security checks
pub fn validate_dns_request_example(
    context: &ServerContext,
    packet_data: &[u8],
    client_addr: SocketAddr,
) -> Result<bool, Box<dyn std::error::Error>> {
    let client_ip = client_addr.ip();
    
    // 1. Check request size limits
    if let Some(ref request_limiter) = context.request_limiter {
        use crate::dns::request_limits::SizeValidationResult;
        
        match request_limiter.validate_dns_udp_request(packet_data.len(), Some(client_ip)) {
            SizeValidationResult::Valid => {
                log::debug!("Request size validation passed for {}", client_ip);
            }
            SizeValidationResult::TooLarge { actual_size, limit, request_type } => {
                log::warn!(
                    "Rejected oversized {} request from {}: {} bytes (limit: {})",
                    request_type, client_ip, actual_size, limit
                );
                return Ok(false);
            }
            SizeValidationResult::ClientBlocked { blocked_until } => {
                log::warn!(
                    "Blocked request from {} until {:?}",
                    client_ip, blocked_until
                );
                return Ok(false);
            }
        }
    }
    
    // 2. Parse the DNS packet
    use crate::dns::buffer::BytePacketBuffer;
    let mut buffer = BytePacketBuffer::new();
    buffer.buf[..packet_data.len()].copy_from_slice(packet_data);
    
    let packet = match DnsPacket::from_buffer(&mut buffer) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("Failed to parse DNS packet from {}: {:?}", client_ip, e);
            return Ok(false);
        }
    };
    
    // 3. Validate packet content
    if let Some(ref request_limiter) = context.request_limiter {
        let domain_names: Vec<String> = packet.questions
            .iter()
            .map(|q| q.name.clone())
            .collect();
        
        if let crate::dns::request_limits::SizeValidationResult::TooLarge { 
            actual_size, limit, request_type 
        } = request_limiter.validate_dns_packet_content(
            packet.questions.len(), 
            &domain_names, 
            Some(client_ip)
        ) {
            log::warn!(
                "Invalid DNS content from {}: {} exceeds {} limit of {}",
                client_ip, request_type, actual_size, limit
            );
            return Ok(false);
        }
    }
    
    log::info!(
        "DNS request validated successfully: {} questions from {}",
        packet.questions.len(),
        client_ip
    );
    
    Ok(true)
}

/// Example of validating a DNS response for cache poisoning
pub fn validate_dns_response_example(
    context: &ServerContext,
    response_packet: &DnsPacket,
    source_addr: SocketAddr,
) -> Result<bool, Box<dyn std::error::Error>> {
    if let Some(ref poison_protection) = context.cache_poison_protection {
        use crate::dns::cache_poisoning::ValidationResult;
        
        match poison_protection.validate_response(response_packet, source_addr) {
            ValidationResult::Valid => {
                log::debug!("DNS response validation passed from {}", source_addr);
                return Ok(true);
            }
            ValidationResult::Suspicious(reason) => {
                log::warn!(
                    "Suspicious DNS response from {}: {}",
                    source_addr, reason
                );
                
                // Log suspicious activity but may still cache with reduced TTL
                context.metrics.record_error("dns_security", "suspicious_response");
                return Ok(true); // Still accept but with caution
            }
            ValidationResult::Invalid(reason) => {
                log::error!(
                    "Invalid DNS response from {}: {}",
                    source_addr, reason
                );
                
                // Reject invalid responses completely
                context.metrics.record_error("dns_security", "invalid_response");
                return Ok(false);
            }
        }
    }
    
    Ok(true)
}

/// Example of monitoring security metrics
pub fn monitor_security_metrics(context: &ServerContext) -> SecurityMetrics {
    let mut metrics = SecurityMetrics::default();
    
    // Collect request limiter statistics
    if let Some(ref request_limiter) = context.request_limiter {
        let stats = request_limiter.get_stats();
        metrics.requests_checked = stats.requests_checked;
        metrics.dns_requests_rejected = stats.dns_udp_rejected + stats.dns_tcp_rejected;
        metrics.http_requests_rejected = stats.http_rejected;
        metrics.clients_blocked = stats.clients_blocked;
        metrics.blocked_clients = request_limiter.get_blocked_clients();
    }
    
    // Collect cache poisoning protection statistics
    if let Some(ref poison_protection) = context.cache_poison_protection {
        let stats = poison_protection.get_stats();
        metrics.queries_protected = stats.queries_protected;
        metrics.suspicious_responses = stats.suspicious_responses;
        metrics.invalid_responses = stats.invalid_responses;
        metrics.dnssec_failures = stats.dnssec_failures;
        metrics.resistance_score = poison_protection.calculate_resistance_score();
    }
    
    metrics
}

/// Security monitoring metrics
#[derive(Debug, Default)]
pub struct SecurityMetrics {
    // Request limiter metrics
    pub requests_checked: u64,
    pub dns_requests_rejected: u64,
    pub http_requests_rejected: u64,
    pub clients_blocked: u64,
    pub blocked_clients: Vec<(IpAddr, std::time::Instant)>,
    
    // Cache poisoning protection metrics
    pub queries_protected: u64,
    pub suspicious_responses: u64,
    pub invalid_responses: u64,
    pub dnssec_failures: u64,
    pub resistance_score: f64,
}

impl SecurityMetrics {
    /// Generate a security report
    pub fn generate_report(&self) -> String {
        format!(
            "=== Atlas DNS Security Report ===\n\
            \n\
            Request Limiting:\n\
            - Total requests checked: {}\n\
            - DNS requests rejected: {}\n\
            - HTTP requests rejected: {}\n\
            - Clients currently blocked: {}\n\
            \n\
            Cache Poisoning Protection:\n\
            - Queries protected: {}\n\
            - Suspicious responses detected: {}\n\
            - Invalid responses blocked: {}\n\
            - DNSSEC validation failures: {}\n\
            - Poisoning resistance score: {:.1}%\n\
            \n\
            Security Status: {}\n",
            self.requests_checked,
            self.dns_requests_rejected,
            self.http_requests_rejected,
            self.clients_blocked,
            self.queries_protected,
            self.suspicious_responses,
            self.invalid_responses,
            self.dnssec_failures,
            self.resistance_score,
            if self.resistance_score > 80.0 { "EXCELLENT" }
            else if self.resistance_score > 60.0 { "GOOD" }
            else if self.resistance_score > 40.0 { "FAIR" }
            else { "NEEDS IMPROVEMENT" }
        )
    }
}

/// Example cleanup task for security components
pub async fn security_cleanup_task(context: Arc<ServerContext>) {
    let mut interval = tokio::time::interval(Duration::from_secs(300)); // Every 5 minutes
    
    loop {
        interval.tick().await;
        
        // Clean up old request tracking data
        if let Some(ref request_limiter) = context.request_limiter {
            request_limiter.cleanup_old_trackers();
        }
        
        // Clean up old query tracking data
        if let Some(ref poison_protection) = context.cache_poison_protection {
            poison_protection.cleanup_old_queries();
        }
        
        log::debug!("Security cleanup completed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    
    #[test]
    fn test_secure_server_creation() {
        let context = create_secure_dns_server().unwrap();
        assert!(context.request_limiter.is_some());
        assert!(context.cache_poison_protection.is_some());
    }
    
    #[tokio::test]
    async fn test_security_metrics_collection() {
        let context = create_secure_dns_server().unwrap();
        let metrics = monitor_security_metrics(&context);
        
        // Metrics should be initialized
        assert_eq!(metrics.requests_checked, 0);
        assert!(metrics.resistance_score > 0.0);
    }
    
    #[test]
    fn test_dns_request_validation() {
        let context = create_secure_dns_server().unwrap();
        
        // Create a simple DNS query packet
        let mut packet = DnsPacket::new();
        packet.questions.push(crate::dns::protocol::DnsQuestion::new(
            "example.com".to_string(),
            crate::dns::protocol::QueryType::A,
        ));
        
        use crate::dns::buffer::VectorPacketBuffer;
        let mut buffer = VectorPacketBuffer::new();
        packet.write(&mut buffer, 512).unwrap();
        let data = buffer.get_range(0, buffer.pos()).unwrap();
        
        let client_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            12345
        );
        
        let result = validate_dns_request_example(&context, data, client_addr);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}