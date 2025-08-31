//! Unified DNS Security Module
//!
//! Provides comprehensive security features including firewall, rate limiting,
//! and DDoS protection with unified management and configuration.

pub mod firewall;
pub mod rate_limiter;
pub mod ddos_protection;
pub mod manager;

use std::net::IpAddr;
use serde::{Serialize, Deserialize};
use crate::dns::protocol::DnsPacket;
use crate::dns::errors::DnsError;

pub use firewall::{DnsFirewall, FirewallConfig, FirewallAction, FirewallRule};
pub use rate_limiter::{EnhancedRateLimiter, RateLimitConfig, RateLimitAlgorithm};
pub use ddos_protection::{DDoSProtection, DDoSConfig, ThreatLevel, AttackType};
pub use manager::{SecurityManager, SecurityConfig, SecurityEvent};

#[cfg(test)]
mod tests;

/// Security check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCheckResult {
    /// Whether the request is allowed
    pub allowed: bool,
    /// Action to take if blocked
    pub action: SecurityAction,
    /// Reason for blocking (if applicable)
    pub reason: Option<String>,
    /// Threat level detected
    pub threat_level: ThreatLevel,
    /// Security events triggered
    pub events: Vec<SecurityEvent>,
}

/// Security action to take
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SecurityAction {
    /// Allow the request
    Allow,
    /// Block with NXDOMAIN
    BlockNxDomain,
    /// Block with REFUSED
    BlockRefused,
    /// Block with SERVFAIL
    BlockServfail,
    /// Redirect to sinkhole
    Sinkhole(IpAddr),
    /// Rate limit the client
    RateLimit,
    /// Challenge with DNS cookie
    Challenge,
}

/// Security metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityMetrics {
    /// Total queries processed
    pub total_queries: u64,
    /// Queries blocked by firewall
    pub firewall_blocked: u64,
    /// Queries rate limited
    pub rate_limited: u64,
    /// DDoS attacks detected
    pub ddos_attacks_detected: u64,
    /// Current threat level
    pub threat_level: ThreatLevel,
    /// Active security rules
    pub active_rules: usize,
    /// Blocked IPs
    pub blocked_ips: usize,
    /// Throttled clients
    pub throttled_clients: usize,
}

/// Security alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    /// Alert ID
    pub id: String,
    /// Alert timestamp
    pub timestamp: u64, // Unix timestamp
    /// Alert severity
    pub severity: AlertSeverity,
    /// Alert type
    pub alert_type: AlertType,
    /// Alert message
    pub message: String,
    /// Related client IP
    pub client_ip: Option<IpAddr>,
    /// Related domain
    pub domain: Option<String>,
    /// Additional metadata
    pub metadata: serde_json::Value,
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    High,
    Critical,
}

/// Alert types
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AlertType {
    /// Firewall rule triggered
    FirewallBlock,
    /// Rate limit exceeded
    RateLimitExceeded,
    /// DDoS attack detected
    DDoSAttack,
    /// Suspicious pattern detected
    SuspiciousPattern,
    /// DNS amplification attempt
    AmplificationAttempt,
    /// Cache poisoning attempt
    CachePoisoningAttempt,
    /// Tunnel detection
    TunnelDetected,
    /// Malware domain accessed
    MalwareDomain,
    /// Phishing domain accessed
    PhishingDomain,
}

/// Security event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEvent {
    FirewallBlock {
        domain: Option<String>,
        client_ip: IpAddr,
        reason: String,
    },
    RuleTriggered {
        rule_id: String,
        rule_name: String,
    },
    MaliciousPattern {
        pattern: String,
        threat_type: firewall::ThreatCategory,
    },
    RpzPolicy {
        zone: String,
        action: String,
    },
    GlobalRateLimitExceeded {
        current_qps: u32,
        limit: u32,
    },
    ClientRateLimitExceeded {
        client_ip: IpAddr,
        queries_per_second: u32,
    },
    ClientThrottled {
        client_ip: IpAddr,
        until: u64, // Unix timestamp
    },
    ClientBanned {
        client_ip: IpAddr,
        until: u64, // Unix timestamp
    },
    QueryTypeRateLimitExceeded {
        query_type: String,
        limit: u32,
    },
    ConnectionLimitExceeded {
        client_ip: IpAddr,
        connections: u32,
    },
    AmplificationAttackDetected {
        client_ip: IpAddr,
        amplification_factor: f64,
    },
    RandomSubdomainAttack {
        domain: String,
        entropy: f64,
    },
    DnsCookieRequired {
        client_ip: IpAddr,
    },
    SuspiciousPatternDetected {
        pattern_type: String,
        client_ip: IpAddr,
    },
    AttackDetected {
        attack_type: ddos_protection::AttackType,
        severity: ThreatLevel,
    },
}

/// Common trait for security components
pub trait SecurityComponent: Send + Sync {
    /// Check if a request should be allowed
    fn check(&self, packet: &DnsPacket, client_ip: IpAddr) -> SecurityCheckResult;
    
    /// Get component metrics
    fn metrics(&self) -> serde_json::Value;
    
    /// Reset component state
    fn reset(&self);
    
    /// Get component configuration
    fn config(&self) -> serde_json::Value;
    
    /// Update component configuration
    fn update_config(&self, config: serde_json::Value) -> Result<(), DnsError>;
}