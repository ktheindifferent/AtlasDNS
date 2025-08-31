//! Enhanced DNS Firewall with advanced filtering capabilities

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use regex::Regex;
use serde::{Serialize, Deserialize};
use ipnetwork::IpNetwork;

use crate::dns::protocol::{DnsPacket, QueryType};
use crate::dns::errors::DnsError;
use super::{SecurityCheckResult, SecurityAction, ThreatLevel, SecurityComponent, SecurityEvent};

/// DNS Firewall with advanced filtering
pub struct DnsFirewall {
    config: Arc<RwLock<FirewallConfig>>,
    rules: Arc<RwLock<Vec<FirewallRule>>>,
    blocklists: Arc<RwLock<BlocklistManager>>,
    allowlists: Arc<RwLock<AllowlistManager>>,
    rpz_zones: Arc<RwLock<RpzManager>>,
    pattern_matcher: Arc<RwLock<PatternMatcher>>,
    metrics: Arc<RwLock<FirewallMetrics>>,
}

/// Firewall configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    pub enabled: bool,
    pub default_action: FirewallAction,
    pub enable_rpz: bool,
    pub enable_regex_matching: bool,
    pub enable_threat_feeds: bool,
    pub log_blocked_queries: bool,
    pub sinkhole_ipv4: Ipv4Addr,
    pub sinkhole_ipv6: Ipv6Addr,
    pub update_interval: Duration,
    pub max_rules: usize,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        FirewallConfig {
            enabled: true,
            default_action: FirewallAction::Allow,
            enable_rpz: true,
            enable_regex_matching: true,
            enable_threat_feeds: true,
            log_blocked_queries: true,
            sinkhole_ipv4: Ipv4Addr::new(127, 0, 0, 2),
            sinkhole_ipv6: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2),
            update_interval: Duration::from_secs(3600),
            max_rules: 10000,
        }
    }
}

/// Firewall action
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum FirewallAction {
    Allow,
    BlockNxDomain,
    BlockRefused,
    BlockServfail,
    Sinkhole,
    RateLimit,
    Monitor,
}

/// Firewall rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub priority: u32,
    pub action: FirewallAction,
    pub match_type: MatchType,
    pub match_value: String,
    pub categories: Vec<ThreatCategory>,
    pub source_ips: Vec<IpNetwork>,
    pub query_types: Vec<QueryType>,
    pub expires_at: Option<u64>, // Unix timestamp
    pub hit_count: u64,
}

/// Match type for rules
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum MatchType {
    ExactDomain,
    WildcardDomain,
    RegexPattern,
    IpAddress,
    QueryType,
    ResponseCode,
}

/// Threat category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatCategory {
    Malware,
    Phishing,
    Botnet,
    CryptoMining,
    Ransomware,
    Spyware,
    Adware,
    Tracking,
    Adult,
    Gambling,
    Violence,
    Custom,
}

/// Blocklist manager
struct BlocklistManager {
    domains: HashSet<String>,
    wildcards: Vec<WildcardPattern>,
    ips: HashSet<IpAddr>,
    threat_feeds: HashMap<String, ThreatFeed>,
    last_update: u64, // Unix timestamp
}

/// Allowlist manager
struct AllowlistManager {
    domains: HashSet<String>,
    wildcards: Vec<WildcardPattern>,
    ips: HashSet<IpAddr>,
    client_ips: HashSet<IpAddr>,
}

/// RPZ (Response Policy Zone) manager
struct RpzManager {
    zones: HashMap<String, RpzZone>,
    policies: Vec<RpzPolicy>,
}

/// Pattern matcher for regex-based filtering
struct PatternMatcher {
    patterns: Vec<CompiledPattern>,
    malicious_patterns: Vec<Regex>,
    suspicious_patterns: Vec<Regex>,
}

/// Compiled pattern for efficient matching
struct CompiledPattern {
    pattern: Regex,
    action: FirewallAction,
    category: ThreatCategory,
}

/// Wildcard pattern
struct WildcardPattern {
    pattern: String,
    prefix: Option<String>,
    suffix: Option<String>,
}

/// Threat feed
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThreatFeed {
    name: String,
    url: String,
    category: ThreatCategory,
    format: FeedFormat,
    enabled: bool,
    last_update: u64, // Unix timestamp
    update_interval: Duration,
    entries: usize,
}

/// Feed format
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
enum FeedFormat {
    HostsFile,
    DomainList,
    IpList,
    Json,
    Rpz,
}

/// RPZ zone
#[derive(Debug, Clone)]
struct RpzZone {
    name: String,
    policies: HashMap<String, RpzPolicy>,
}

/// RPZ policy
#[derive(Debug, Clone)]
struct RpzPolicy {
    domain: String,
    action: RpzAction,
    data: Option<Vec<u8>>,
}

/// RPZ action
#[derive(Debug, Clone, Copy, PartialEq)]
enum RpzAction {
    Given,
    Disabled,
    Passthru,
    Drop,
    TcpOnly,
    Nxdomain,
    Nodata,
    Cname,
}

/// Firewall metrics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FirewallMetrics {
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub allowed_queries: u64,
    pub monitored_queries: u64,
    pub active_rules: usize,
    pub rules_triggered: HashMap<String, u64>,
    pub categories_blocked: HashMap<ThreatCategory, u64>,
    pub top_blocked_domains: Vec<(String, u64)>,
    pub top_blocked_clients: Vec<(IpAddr, u64)>,
}

impl DnsFirewall {
    /// Create a new DNS firewall
    pub fn new(config: FirewallConfig) -> Self {
        DnsFirewall {
            config: Arc::new(RwLock::new(config)),
            rules: Arc::new(RwLock::new(Vec::new())),
            blocklists: Arc::new(RwLock::new(BlocklistManager {
                domains: HashSet::new(),
                wildcards: Vec::new(),
                ips: HashSet::new(),
                threat_feeds: HashMap::new(),
                last_update: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            })),
            allowlists: Arc::new(RwLock::new(AllowlistManager {
                domains: HashSet::new(),
                wildcards: Vec::new(),
                ips: HashSet::new(),
                client_ips: HashSet::new(),
            })),
            rpz_zones: Arc::new(RwLock::new(RpzManager {
                zones: HashMap::new(),
                policies: Vec::new(),
            })),
            pattern_matcher: Arc::new(RwLock::new(PatternMatcher {
                patterns: Vec::new(),
                malicious_patterns: Vec::new(),
                suspicious_patterns: Vec::new(),
            })),
            metrics: Arc::new(RwLock::new(FirewallMetrics::default())),
        }
    }

    /// Check if a query should be allowed
    pub fn check_query(&self, packet: &DnsPacket, client_ip: IpAddr) -> SecurityCheckResult {
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

        // Check allowlist first
        if self.is_allowlisted(packet, client_ip) {
            metrics.allowed_queries += 1;
            return SecurityCheckResult {
                allowed: true,
                action: SecurityAction::Allow,
                reason: None,
                threat_level: ThreatLevel::None,
                events: Vec::new(),
            };
        }

        // Check blocklist
        if let Some(reason) = self.is_blocklisted(packet, client_ip) {
            metrics.blocked_queries += 1;
            return SecurityCheckResult {
                allowed: false,
                action: SecurityAction::BlockNxDomain,
                reason: Some(reason.clone()),
                threat_level: ThreatLevel::Medium,
                events: vec![SecurityEvent::FirewallBlock {
                    domain: self.get_query_domain(packet),
                    client_ip,
                    reason,
                }],
            };
        }

        // Check firewall rules
        if let Some((rule, action)) = self.check_rules(packet, client_ip) {
            if action != FirewallAction::Allow {
                metrics.blocked_queries += 1;
                return SecurityCheckResult {
                    allowed: false,
                    action: self.convert_action(action),
                    reason: Some(format!("Blocked by rule: {}", rule.name)),
                    threat_level: ThreatLevel::Medium,
                    events: vec![SecurityEvent::RuleTriggered {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                    }],
                };
            }
        }

        // Check RPZ policies
        if config.enable_rpz {
            if let Some(policy) = self.check_rpz(packet) {
                return self.apply_rpz_policy(policy, packet, client_ip);
            }
        }

        // Check regex patterns
        if config.enable_regex_matching {
            if let Some((pattern, threat)) = self.check_patterns(packet) {
                metrics.blocked_queries += 1;
                return SecurityCheckResult {
                    allowed: false,
                    action: SecurityAction::BlockNxDomain,
                    reason: Some(format!("Matched malicious pattern: {:?}", threat)),
                    threat_level: ThreatLevel::High,
                    events: vec![SecurityEvent::MaliciousPattern {
                        pattern: pattern.to_string(),
                        threat_type: threat,
                    }],
                };
            }
        }

        // Default allow
        metrics.allowed_queries += 1;
        SecurityCheckResult {
            allowed: true,
            action: SecurityAction::Allow,
            reason: None,
            threat_level: ThreatLevel::None,
            events: Vec::new(),
        }
    }

    /// Add a firewall rule
    pub fn add_rule(&self, rule: FirewallRule) -> Result<(), DnsError> {
        let mut rules = self.rules.write();
        let config = self.config.read();
        
        if rules.len() >= config.max_rules {
            return Err(DnsError::InvalidInput);
        }

        rules.push(rule);
        rules.sort_by_key(|r| r.priority);
        Ok(())
    }

    /// Remove a firewall rule
    pub fn remove_rule(&self, rule_id: &str) -> Result<(), DnsError> {
        let mut rules = self.rules.write();
        rules.retain(|r| r.id != rule_id);
        Ok(())
    }

    /// Load blocklist from file or URL
    pub fn load_blocklist(&self, source: &str, category: ThreatCategory) -> Result<(), DnsError> {
        // Implementation would load and parse blocklist
        Ok(())
    }

    /// Load allowlist from file or URL
    pub fn load_allowlist(&self, source: &str) -> Result<(), DnsError> {
        // Implementation would load and parse allowlist
        Ok(())
    }

    /// Load RPZ zone
    pub fn load_rpz_zone(&self, zone_data: &str) -> Result<(), DnsError> {
        // Implementation would parse and load RPZ zone
        Ok(())
    }

    /// Add regex pattern
    pub fn add_pattern(&self, pattern: &str, action: FirewallAction, category: ThreatCategory) -> Result<(), DnsError> {
        let regex = Regex::new(pattern).map_err(|_| DnsError::InvalidInput)?;
        
        let mut matcher = self.pattern_matcher.write();
        matcher.patterns.push(CompiledPattern {
            pattern: regex,
            action,
            category,
        });
        
        Ok(())
    }

    /// Get firewall metrics
    pub fn get_metrics(&self) -> FirewallMetrics {
        self.metrics.read().clone()
    }

    /// Internal helper methods
    
    fn is_allowlisted(&self, packet: &DnsPacket, client_ip: IpAddr) -> bool {
        let allowlists = self.allowlists.read();
        
        // Check client IP allowlist
        if allowlists.client_ips.contains(&client_ip) {
            return true;
        }

        // Check domain allowlist
        if let Some(domain) = self.get_query_domain(packet) {
            if allowlists.domains.contains(&domain) {
                return true;
            }

            // Check wildcard patterns
            for pattern in &allowlists.wildcards {
                if self.matches_wildcard(&domain, pattern) {
                    return true;
                }
            }
        }

        false
    }

    fn is_blocklisted(&self, packet: &DnsPacket, client_ip: IpAddr) -> Option<String> {
        let blocklists = self.blocklists.read();

        // Check IP blocklist
        if blocklists.ips.contains(&client_ip) {
            return Some(format!("IP {} is blocklisted", client_ip));
        }

        // Check domain blocklist
        if let Some(domain) = self.get_query_domain(packet) {
            if blocklists.domains.contains(&domain) {
                return Some(format!("Domain {} is blocklisted", domain));
            }

            // Check wildcard patterns
            for pattern in &blocklists.wildcards {
                if self.matches_wildcard(&domain, pattern) {
                    return Some(format!("Domain {} matches blocklist pattern", domain));
                }
            }
        }

        None
    }

    fn check_rules(&self, packet: &DnsPacket, client_ip: IpAddr) -> Option<(FirewallRule, FirewallAction)> {
        let rules = self.rules.read();
        
        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }

            if let Some(expires_ts) = rule.expires_at {
                let now_ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                if now_ts > expires_ts {
                    continue;
                }
            }

            if self.rule_matches(rule, packet, client_ip) {
                return Some((rule.clone(), rule.action));
            }
        }

        None
    }

    fn rule_matches(&self, rule: &FirewallRule, packet: &DnsPacket, client_ip: IpAddr) -> bool {
        // Check source IP
        if !rule.source_ips.is_empty() {
            let mut ip_match = false;
            for network in &rule.source_ips {
                if network.contains(client_ip) {
                    ip_match = true;
                    break;
                }
            }
            if !ip_match {
                return false;
            }
        }

        // Check query type
        if !rule.query_types.is_empty() {
            if let Some(question) = packet.questions.first() {
                if !rule.query_types.contains(&question.qtype) {
                    return false;
                }
            }
        }

        // Check match type
        match rule.match_type {
            MatchType::ExactDomain => {
                if let Some(domain) = self.get_query_domain(packet) {
                    domain == rule.match_value
                } else {
                    false
                }
            }
            MatchType::WildcardDomain => {
                if let Some(domain) = self.get_query_domain(packet) {
                    self.matches_wildcard_string(&domain, &rule.match_value)
                } else {
                    false
                }
            }
            MatchType::RegexPattern => {
                if let Some(domain) = self.get_query_domain(packet) {
                    if let Ok(regex) = Regex::new(&rule.match_value) {
                        regex.is_match(&domain)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn check_rpz(&self, packet: &DnsPacket) -> Option<RpzPolicy> {
        let rpz = self.rpz_zones.read();
        
        if let Some(domain) = self.get_query_domain(packet) {
            for policy in &rpz.policies {
                if domain == policy.domain || domain.ends_with(&format!(".{}", policy.domain)) {
                    return Some(policy.clone());
                }
            }
        }

        None
    }

    fn check_patterns(&self, packet: &DnsPacket) -> Option<(String, ThreatCategory)> {
        let matcher = self.pattern_matcher.read();
        
        if let Some(domain) = self.get_query_domain(packet) {
            for pattern in &matcher.patterns {
                if pattern.pattern.is_match(&domain) {
                    return Some((pattern.pattern.as_str().to_string(), pattern.category));
                }
            }

            // Check for known malicious patterns
            for pattern in &matcher.malicious_patterns {
                if pattern.is_match(&domain) {
                    return Some((pattern.as_str().to_string(), ThreatCategory::Malware));
                }
            }
        }

        None
    }

    fn apply_rpz_policy(&self, policy: RpzPolicy, packet: &DnsPacket, client_ip: IpAddr) -> SecurityCheckResult {
        let action = match policy.action {
            RpzAction::Nxdomain => SecurityAction::BlockNxDomain,
            RpzAction::Nodata => SecurityAction::BlockServfail,
            RpzAction::Drop => SecurityAction::BlockRefused,
            RpzAction::Passthru => SecurityAction::Allow,
            _ => SecurityAction::BlockNxDomain,
        };

        SecurityCheckResult {
            allowed: action == SecurityAction::Allow,
            action,
            reason: Some(format!("RPZ policy: {:?}", policy.action)),
            threat_level: if action == SecurityAction::Allow { ThreatLevel::None } else { ThreatLevel::Medium },
            events: vec![SecurityEvent::RpzPolicy {
                zone: policy.domain.clone(),
                action: format!("{:?}", policy.action),
            }],
        }
    }

    fn get_query_domain(&self, packet: &DnsPacket) -> Option<String> {
        packet.questions.first().map(|q| q.name.clone())
    }

    fn matches_wildcard(&self, domain: &str, pattern: &WildcardPattern) -> bool {
        if let Some(prefix) = &pattern.prefix {
            if !domain.starts_with(prefix) {
                return false;
            }
        }

        if let Some(suffix) = &pattern.suffix {
            if !domain.ends_with(suffix) {
                return false;
            }
        }

        true
    }

    fn matches_wildcard_string(&self, domain: &str, pattern: &str) -> bool {
        if pattern.starts_with("*.") {
            let suffix = &pattern[2..];
            domain == suffix || domain.ends_with(&format!(".{}", suffix))
        } else if pattern.ends_with(".*") {
            let prefix = &pattern[..pattern.len()-2];
            domain == prefix || domain.starts_with(&format!("{}.", prefix))
        } else {
            domain == pattern
        }
    }

    fn convert_action(&self, action: FirewallAction) -> SecurityAction {
        match action {
            FirewallAction::Allow => SecurityAction::Allow,
            FirewallAction::BlockNxDomain => SecurityAction::BlockNxDomain,
            FirewallAction::BlockRefused => SecurityAction::BlockRefused,
            FirewallAction::BlockServfail => SecurityAction::BlockServfail,
            FirewallAction::Sinkhole => {
                let config = self.config.read();
                SecurityAction::Sinkhole(IpAddr::V4(config.sinkhole_ipv4))
            }
            FirewallAction::RateLimit => SecurityAction::RateLimit,
            FirewallAction::Monitor => SecurityAction::Allow,
        }
    }
}

impl SecurityComponent for DnsFirewall {
    fn check(&self, packet: &DnsPacket, client_ip: IpAddr) -> SecurityCheckResult {
        self.check_query(packet, client_ip)
    }

    fn metrics(&self) -> serde_json::Value {
        serde_json::to_value(&*self.metrics.read()).unwrap_or(serde_json::Value::Null)
    }

    fn reset(&self) {
        *self.metrics.write() = FirewallMetrics::default();
    }

    fn config(&self) -> serde_json::Value {
        serde_json::to_value(&*self.config.read()).unwrap_or(serde_json::Value::Null)
    }

    fn update_config(&self, config: serde_json::Value) -> Result<(), DnsError> {
        let new_config: FirewallConfig = serde_json::from_value(config)
            .map_err(|_| DnsError::InvalidInput)?;
        *self.config.write() = new_config;
        Ok(())
    }
}

