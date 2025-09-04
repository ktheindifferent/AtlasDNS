//! DNS Firewall Implementation
//!
//! Provides advanced DNS query filtering for security and content control.
//! Blocks malware, phishing, and other threats at the DNS level.
//!
//! # Features
//!
//! * **Threat Intelligence Integration** - Real-time threat feeds
//! * **Category-based Filtering** - Block by content categories
//! * **Custom Block Lists** - User-defined domain blocking
//! * **Response Policy Zones (RPZ)** - Industry-standard filtering
//! * **Sinkhole Responses** - Redirect malicious queries
//! * **Logging & Analytics** - Track blocked threats

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use parking_lot::RwLock;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use regex::Regex;

use crate::dns::protocol::{DnsPacket, QueryType, ResultCode, DnsRecord, TransientTtl};
use crate::dns::context::ServerContext;
use crate::dns::logging::{CorrelationContext, SecurityEventLog};

/// Firewall action to take on matched queries
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum FirewallAction {
    /// Allow the query to proceed
    Allow,
    /// Block with NXDOMAIN response
    BlockNxDomain,
    /// Block with REFUSED response
    BlockRefused,
    /// Redirect to a sinkhole IP
    Sinkhole,
    /// Log but allow the query
    Monitor,
    /// Rate limit the client
    RateLimit,
}

/// Threat category classification
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Hash, Eq)]
pub enum ThreatCategory {
    Malware,
    Phishing,
    Botnet,
    CryptoMining,
    Ransomware,
    Spyware,
    Adware,
    Adult,
    Gambling,
    Violence,
    Drugs,
    Custom,
}

/// Firewall rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    /// Unique rule ID
    pub id: String,
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Is rule enabled
    pub enabled: bool,
    /// Rule priority (lower = higher priority)
    pub priority: u32,
    /// Match criteria
    pub match_criteria: MatchCriteria,
    /// Action to take when matched
    pub action: FirewallAction,
    /// Categories this rule applies to
    pub categories: Vec<ThreatCategory>,
    /// Expiration time (if temporary rule)
    pub expires_at: Option<DateTime<Utc>>,
    /// Statistics
    pub stats: RuleStatistics,
}

/// Match criteria for firewall rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchCriteria {
    /// Domain patterns to match (exact, wildcard, or regex)
    pub domains: Vec<DomainPattern>,
    /// Client IP addresses or ranges
    pub client_ips: Vec<IpRange>,
    /// Query types to match
    pub query_types: Vec<QueryType>,
    /// Time-based restrictions
    pub time_restrictions: Option<TimeRestriction>,
}

/// Domain matching pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DomainPattern {
    /// Exact domain match
    Exact(String),
    /// Wildcard pattern (*.example.com)
    Wildcard(String),
    /// Regular expression pattern
    Regex(String),
    /// Suffix match (.example.com matches any subdomain)
    Suffix(String),
}

/// IP address range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpRange {
    /// Single IP address
    Single(IpAddr),
    /// CIDR range (e.g., 192.168.1.0/24)
    Cidr { base: IpAddr, prefix_len: u8 },
    /// IP range (start to end)
    Range { start: IpAddr, end: IpAddr },
}

/// Time-based access restriction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRestriction {
    /// Days of week (0 = Sunday, 6 = Saturday)
    pub days_of_week: Vec<u8>,
    /// Start time (hour and minute)
    pub start_time: (u8, u8),
    /// End time (hour and minute)
    pub end_time: (u8, u8),
    /// Timezone
    pub timezone: String,
}

/// Rule statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleStatistics {
    /// Total matches
    pub total_matches: u64,
    /// Matches in last hour
    pub recent_matches: u64,
    /// Last match time
    pub last_match: Option<DateTime<Utc>>,
    /// Top blocked domains
    pub top_domains: HashMap<String, u64>,
    /// Top client IPs
    pub top_clients: HashMap<IpAddr, u64>,
}

/// Threat intelligence feed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeed {
    /// Feed identifier
    pub id: String,
    /// Feed name
    pub name: String,
    /// Feed URL or source
    pub source: String,
    /// Feed type
    pub feed_type: FeedType,
    /// Categories covered by this feed
    pub categories: Vec<ThreatCategory>,
    /// Update frequency in seconds
    pub update_frequency: u64,
    /// Last update time
    pub last_updated: Option<DateTime<Utc>>,
    /// Is feed enabled
    pub enabled: bool,
}

/// Type of threat feed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeedType {
    /// Plain text domain list
    DomainList,
    /// Response Policy Zone format
    RPZ,
    /// JSON threat intelligence
    JsonThreat,
    /// CSV format
    Csv,
}

/// DNS Firewall implementation
pub struct DnsFirewall {
    /// Firewall rules
    rules: Arc<RwLock<Vec<FirewallRule>>>,
    /// Blocked domains cache
    blocked_domains: Arc<RwLock<HashSet<String>>>,
    /// Category mappings
    category_domains: Arc<RwLock<HashMap<ThreatCategory, HashSet<String>>>>,
    /// Threat feeds
    threat_feeds: Arc<RwLock<Vec<ThreatFeed>>>,
    /// Sinkhole configuration
    sinkhole_config: SinkholeConfig,
    /// Compiled regex patterns cache
    regex_cache: Arc<RwLock<HashMap<String, Regex>>>,
    /// Statistics
    stats: Arc<RwLock<FirewallStatistics>>,
}

/// Sinkhole configuration
#[derive(Debug, Clone)]
pub struct SinkholeConfig {
    /// IPv4 sinkhole address
    pub ipv4_address: Ipv4Addr,
    /// IPv6 sinkhole address
    pub ipv6_address: Ipv6Addr,
    /// Custom sinkhole message
    pub message: Option<String>,
}

impl Default for SinkholeConfig {
    fn default() -> Self {
        Self {
            ipv4_address: Ipv4Addr::new(0, 0, 0, 0),
            ipv6_address: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
            message: Some("This domain has been blocked by DNS Firewall".to_string()),
        }
    }
}

/// Firewall statistics
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FirewallStatistics {
    /// Total queries processed
    pub total_queries: u64,
    /// Total queries blocked
    pub total_blocked: u64,
    /// Queries blocked by category
    pub blocked_by_category: HashMap<ThreatCategory, u64>,
    /// Queries blocked by action
    pub blocked_by_action: HashMap<String, u64>,
    /// Top blocked domains
    pub top_blocked_domains: Vec<(String, u64)>,
    /// Top threat sources
    pub top_threat_sources: Vec<(IpAddr, u64)>,
    /// Performance metrics
    pub avg_check_time_us: u64,
}

impl DnsFirewall {
    /// Create a new DNS firewall
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            blocked_domains: Arc::new(RwLock::new(HashSet::new())),
            category_domains: Arc::new(RwLock::new(HashMap::new())),
            threat_feeds: Arc::new(RwLock::new(Vec::new())),
            sinkhole_config: SinkholeConfig::default(),
            regex_cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(FirewallStatistics::default())),
        }
    }

    /// Load default threat intelligence feeds
    pub fn load_default_feeds(&mut self) {
        let default_feeds = vec![
            ThreatFeed {
                id: "malware-domains".to_string(),
                name: "Malware Domain List".to_string(),
                source: "https://malwaredomainlist.com/hostslist/hosts.txt".to_string(),
                feed_type: FeedType::DomainList,
                categories: vec![ThreatCategory::Malware],
                update_frequency: 3600,
                last_updated: None,
                enabled: true,
            },
            ThreatFeed {
                id: "phishing-domains".to_string(),
                name: "PhishTank Feed".to_string(),
                source: "https://phishtank.com/feeds".to_string(),
                feed_type: FeedType::JsonThreat,
                categories: vec![ThreatCategory::Phishing],
                update_frequency: 1800,
                last_updated: None,
                enabled: true,
            },
        ];

        let mut feeds = self.threat_feeds.write();
        feeds.extend(default_feeds);
    }

    /// Check if a query should be blocked
    pub fn check_query(
        &self,
        packet: &DnsPacket,
        client_ip: IpAddr,
        context: &Arc<ServerContext>,
    ) -> FirewallDecision {
        let start_time = std::time::Instant::now();
        
        // Get query details
        if packet.questions.is_empty() {
            return FirewallDecision::allow();
        }
        
        let question = &packet.questions[0];
        let domain = &question.name;
        let qtype = question.qtype;
        
        // Update statistics
        {
            let mut stats = self.stats.write();
            stats.total_queries += 1;
        }
        
        // Check against blocked domains cache first (fast path)
        if self.is_domain_blocked(domain) {
            self.record_blocked(domain, client_ip, ThreatCategory::Custom, FirewallAction::BlockNxDomain);
            return FirewallDecision::block(FirewallAction::BlockNxDomain, Some("Domain is on block list".to_string()));
        }
        
        // Check firewall rules
        let rules = self.rules.read();
        let mut matched_rule: Option<&FirewallRule> = None;
        
        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }
            
            // Check expiration
            if let Some(expires) = rule.expires_at {
                if Utc::now() > expires {
                    continue;
                }
            }
            
            // Check match criteria
            if self.matches_criteria(&rule.match_criteria, domain, client_ip, qtype) {
                matched_rule = Some(rule);
                break;
            }
        }
        
        // Record check time
        let check_time = start_time.elapsed().as_micros() as u64;
        {
            let mut stats = self.stats.write();
            stats.avg_check_time_us = (stats.avg_check_time_us * 9 + check_time) / 10;
        }
        
        // Apply matched rule
        if let Some(rule) = matched_rule {
            self.record_rule_match(rule, domain, client_ip);
            
            // Log security event
            if rule.action != FirewallAction::Allow {
                let security_log = SecurityEventLog {
                    event_type: "dns_firewall_block".to_string(),
                    severity: match rule.action {
                        FirewallAction::BlockNxDomain | FirewallAction::BlockRefused => "high".to_string(),
                        FirewallAction::Sinkhole => "medium".to_string(),
                        _ => "low".to_string(),
                    },
                    action: format!("{:?}", rule.action),
                    source_ip: client_ip.to_string(),
                    threat_details: Some(HashMap::from([
                        ("domain".to_string(), serde_json::Value::String(domain.clone())),
                        ("rule_id".to_string(), serde_json::Value::String(rule.id.clone())),
                        ("categories".to_string(), serde_json::Value::String(
                            rule.categories.iter().map(|c| format!("{:?}", c)).collect::<Vec<_>>().join(", ")
                        )),
                    ])),
                    rate_limit_info: None,
                };
                
                let ctx = CorrelationContext::new("dns_firewall", "check_query");
                context.logger.log_security_event(&ctx, security_log);
            }
            
            return FirewallDecision {
                action: rule.action,
                reason: Some(rule.description.clone()),
                matched_rule: Some(rule.id.clone()),
                categories: rule.categories.clone(),
            };
        }
        
        FirewallDecision::allow()
    }

    /// Check if a domain is in the blocked list
    fn is_domain_blocked(&self, domain: &str) -> bool {
        let blocked = self.blocked_domains.read();
        
        // Check exact match
        if blocked.contains(domain) {
            return true;
        }
        
        // Check parent domains
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let parent = parts[i..].join(".");
            if blocked.contains(&parent) {
                return true;
            }
        }
        
        false
    }

    /// Check if criteria matches
    fn matches_criteria(
        &self,
        criteria: &MatchCriteria,
        domain: &str,
        client_ip: IpAddr,
        qtype: QueryType,
    ) -> bool {
        // Check domain patterns
        if !criteria.domains.is_empty() {
            let mut domain_match = false;
            for pattern in &criteria.domains {
                if self.matches_domain_pattern(pattern, domain) {
                    domain_match = true;
                    break;
                }
            }
            if !domain_match {
                return false;
            }
        }
        
        // Check client IPs
        if !criteria.client_ips.is_empty() {
            let mut ip_match = false;
            for range in &criteria.client_ips {
                if self.ip_in_range(client_ip, range) {
                    ip_match = true;
                    break;
                }
            }
            if !ip_match {
                return false;
            }
        }
        
        // Check query types
        if !criteria.query_types.is_empty() && !criteria.query_types.contains(&qtype) {
            return false;
        }
        
        // Check time restrictions
        if let Some(ref time_restriction) = criteria.time_restrictions {
            if !self.matches_time_restriction(time_restriction) {
                return false;
            }
        }
        
        true
    }

    /// Check if domain matches pattern
    fn matches_domain_pattern(&self, pattern: &DomainPattern, domain: &str) -> bool {
        match pattern {
            DomainPattern::Exact(exact) => domain == exact,
            DomainPattern::Wildcard(wildcard) => {
                // Convert wildcard to regex pattern
                let regex_pattern = wildcard.replace(".", r"\.").replace("*", ".*");
                self.matches_regex(&regex_pattern, domain)
            }
            DomainPattern::Regex(regex) => self.matches_regex(regex, domain),
            DomainPattern::Suffix(suffix) => domain.ends_with(suffix),
        }
    }

    /// Check if string matches regex pattern
    fn matches_regex(&self, pattern: &str, text: &str) -> bool {
        let mut cache = self.regex_cache.write();
        let regex = cache.entry(pattern.to_string()).or_insert_with(|| {
            Regex::new(pattern).unwrap_or_else(|_| Regex::new("^$").unwrap())
        });
        regex.is_match(text)
    }

    /// Check if IP is in range
    fn ip_in_range(&self, ip: IpAddr, range: &IpRange) -> bool {
        match range {
            IpRange::Single(single) => ip == *single,
            IpRange::Cidr { base, prefix_len } => {
                // Simplified CIDR check
                match (ip, base) {
                    (IpAddr::V4(ip4), IpAddr::V4(base4)) => {
                        let ip_bits = u32::from_be_bytes(ip4.octets());
                        let base_bits = u32::from_be_bytes(base4.octets());
                        let mask = !((1 << (32 - prefix_len)) - 1);
                        (ip_bits & mask) == (base_bits & mask)
                    }
                    _ => false,
                }
            }
            IpRange::Range { start, end } => {
                match (ip, start, end) {
                    (IpAddr::V4(ip4), IpAddr::V4(start4), IpAddr::V4(end4)) => {
                        ip4 >= *start4 && ip4 <= *end4
                    }
                    (IpAddr::V6(ip6), IpAddr::V6(start6), IpAddr::V6(end6)) => {
                        ip6 >= *start6 && ip6 <= *end6
                    }
                    _ => false,
                }
            }
        }
    }

    /// Check if current time matches restriction
    fn matches_time_restriction(&self, restriction: &TimeRestriction) -> bool {
        // Simplified time check (would need proper timezone handling in production)
        use chrono::Timelike;
        use chrono::Datelike;
        
        let now = Utc::now();
        let weekday = now.weekday().num_days_from_sunday() as u8;
        
        if !restriction.days_of_week.contains(&weekday) {
            return false;
        }
        
        let current_hour = now.hour() as u8;
        let current_minute = now.minute() as u8;
        let current_time = (current_hour, current_minute);
        
        // Check if current time is within range
        if restriction.start_time <= restriction.end_time {
            current_time >= restriction.start_time && current_time <= restriction.end_time
        } else {
            // Handle overnight ranges
            current_time >= restriction.start_time || current_time <= restriction.end_time
        }
    }

    /// Record blocked query
    fn record_blocked(&self, domain: &str, client_ip: IpAddr, category: ThreatCategory, action: FirewallAction) {
        let mut stats = self.stats.write();
        stats.total_blocked += 1;
        *stats.blocked_by_category.entry(category).or_insert(0) += 1;
        *stats.blocked_by_action.entry(format!("{:?}", action)).or_insert(0) += 1;
    }

    /// Record rule match
    fn record_rule_match(&self, rule: &FirewallRule, _domain: &str, _client_ip: IpAddr) {
        // Update rule statistics (would need mutable access in production)
        // This is simplified for the example
    }

    /// Add a domain to the block list
    pub fn block_domain(&mut self, domain: String) {
        let mut blocked = self.blocked_domains.write();
        blocked.insert(domain);
    }

    /// Remove a domain from the block list
    pub fn unblock_domain(&mut self, domain: &str) {
        let mut blocked = self.blocked_domains.write();
        blocked.remove(domain);
    }

    /// Add a firewall rule
    pub fn add_rule(&mut self, rule: FirewallRule) {
        let mut rules = self.rules.write();
        rules.push(rule);
        rules.sort_by_key(|r| r.priority);
    }

    /// Get firewall statistics
    pub fn get_statistics(&self) -> FirewallStatistics {
        let stats = self.stats.read();
        FirewallStatistics {
            total_queries: stats.total_queries,
            total_blocked: stats.total_blocked,
            blocked_by_category: stats.blocked_by_category.clone(),
            blocked_by_action: stats.blocked_by_action.clone(),
            top_blocked_domains: stats.top_blocked_domains.clone(),
            top_threat_sources: stats.top_threat_sources.clone(),
            avg_check_time_us: stats.avg_check_time_us,
        }
    }

    /// Get the count of active threat feeds
    pub fn get_threat_feed_count(&self) -> usize {
        let feeds = self.threat_feeds.read();
        feeds.iter().filter(|f| f.enabled).count()
    }

    /// Create a sinkhole response
    pub fn create_sinkhole_response(&self, packet: &DnsPacket, qtype: QueryType) -> DnsPacket {
        let mut response = DnsPacket::new();
        response.header.id = packet.header.id;
        response.header.response = true;
        response.header.rescode = ResultCode::NOERROR;
        
        if !packet.questions.is_empty() {
            response.questions = packet.questions.clone();
            
            let domain = &packet.questions[0].name;
            
            match qtype {
                QueryType::A => {
                    response.answers.push(DnsRecord::A {
                        domain: domain.clone(),
                        addr: self.sinkhole_config.ipv4_address,
                        ttl: TransientTtl(300),
                    });
                }
                QueryType::Aaaa => {
                    response.answers.push(DnsRecord::Aaaa {
                        domain: domain.clone(),
                        addr: self.sinkhole_config.ipv6_address,
                        ttl: TransientTtl(300),
                    });
                }
                _ => {
                    response.header.rescode = ResultCode::NXDOMAIN;
                }
            }
        }
        
        response
    }
}

/// Firewall decision result
#[derive(Debug, Clone)]
pub struct FirewallDecision {
    /// Action to take
    pub action: FirewallAction,
    /// Reason for the decision
    pub reason: Option<String>,
    /// Matched rule ID
    pub matched_rule: Option<String>,
    /// Threat categories
    pub categories: Vec<ThreatCategory>,
}

impl FirewallDecision {
    /// Create an allow decision
    pub fn allow() -> Self {
        Self {
            action: FirewallAction::Allow,
            reason: None,
            matched_rule: None,
            categories: Vec::new(),
        }
    }

    /// Create a block decision
    pub fn block(action: FirewallAction, reason: Option<String>) -> Self {
        Self {
            action,
            reason,
            matched_rule: None,
            categories: Vec::new(),
        }
    }

    /// Check if query should be blocked
    pub fn should_block(&self) -> bool {
        !matches!(self.action, FirewallAction::Allow | FirewallAction::Monitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_firewall_creation() {
        let firewall = DnsFirewall::new();
        let stats = firewall.get_statistics();
        assert_eq!(stats.total_queries, 0);
        assert_eq!(stats.total_blocked, 0);
    }

    #[test]
    fn test_domain_blocking() {
        let mut firewall = DnsFirewall::new();
        firewall.block_domain("malware.com".to_string());
        assert!(firewall.is_domain_blocked("malware.com"));
        assert!(firewall.is_domain_blocked("sub.malware.com"));
        assert!(!firewall.is_domain_blocked("safe.com"));
    }

    #[test]
    fn test_ip_range_matching() {
        let firewall = DnsFirewall::new();
        let range = IpRange::Cidr {
            base: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
            prefix_len: 24,
        };
        
        assert!(firewall.ip_in_range(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            &range
        ));
        assert!(!firewall.ip_in_range(
            IpAddr::V4(Ipv4Addr::new(192, 168, 2, 100)),
            &range
        ));
    }
}