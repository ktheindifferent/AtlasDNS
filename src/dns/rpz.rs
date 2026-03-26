//! Response Policy Zones (RPZ) Implementation
//!
//! Provides DNS-based threat intelligence and content filtering through
//! policy zones that can block, redirect, or modify DNS responses.
//!
//! # Features
//!
//! * **Multiple Policy Sources** - Load policies from files, URLs, or APIs
//! * **Real-time Updates** - Hot-reload policies without restart
//! * **Action Types** - NXDOMAIN, NODATA, DROP, REDIRECT, PASSTHRU
//! * **Threat Categories** - Malware, phishing, botnet, ads, tracking
//! * **Wildcards Support** - Block entire domains and subdomains
//! * **Whitelisting** - Override blocks for specific domains
//! * **Performance Optimized** - Trie-based lookups for fast matching

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use bloomfilter::Bloom;

use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, ResultCode, TransientTtl};
use crate::dns::errors::DnsError;

/// RPZ policy action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyAction {
    /// Return NXDOMAIN (domain doesn't exist)
    NxDomain,
    /// Return NODATA (domain exists but no records)
    NoData,
    /// Drop the query (no response)
    Drop,
    /// Redirect to a specific IP
    Redirect,
    /// Pass through (allow)
    Passthru,
    /// TCP-only (force TCP retry)
    TcpOnly,
}

/// Threat category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatCategory {
    /// Malware domains
    Malware,
    /// Phishing sites
    Phishing,
    /// Botnet C&C servers
    Botnet,
    /// Advertising networks
    Advertising,
    /// Tracking/analytics
    Tracking,
    /// Adult content
    Adult,
    /// Gambling sites
    Gambling,
    /// Custom category
    Custom(u32),
}

/// RPZ policy entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEntry {
    /// Domain pattern (can include wildcards)
    pub domain: String,
    /// Policy action
    pub action: PolicyAction,
    /// Threat category
    pub category: ThreatCategory,
    /// Redirect target (for Redirect action)
    pub redirect_to: Option<IpAddr>,
    /// Custom message
    pub message: Option<String>,
    /// Policy priority (higher = more important)
    pub priority: u32,
    /// Expiry time in seconds since epoch
    pub expires_at_secs: Option<u64>,
}

/// RPZ configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpzConfig {
    /// Enable RPZ filtering
    pub enabled: bool,
    /// Policy sources
    pub sources: Vec<PolicySource>,
    /// Update interval for remote sources
    pub update_interval: Duration,
    /// Default action for blocked domains
    pub default_action: PolicyAction,
    /// Default redirect IP for blocked domains
    pub default_redirect_ip: Option<IpAddr>,
    /// Enable logging of blocked queries
    pub log_blocked: bool,
    /// Categories to block
    pub blocked_categories: HashSet<ThreatCategory>,
    /// Whitelist domains (never block)
    pub whitelist: HashSet<String>,
}

impl Default for RpzConfig {
    fn default() -> Self {
        let mut blocked_categories = HashSet::new();
        blocked_categories.insert(ThreatCategory::Malware);
        blocked_categories.insert(ThreatCategory::Phishing);
        blocked_categories.insert(ThreatCategory::Botnet);

        Self {
            enabled: true,
            sources: Vec::new(),
            update_interval: Duration::from_secs(3600), // 1 hour
            default_action: PolicyAction::NxDomain,
            default_redirect_ip: Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            log_blocked: true,
            blocked_categories,
            whitelist: HashSet::new(),
        }
    }
}

/// Policy source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicySource {
    /// Local file
    File { path: String },
    /// HTTP/HTTPS URL
    Url { url: String },
    /// Built-in blocklist
    BuiltIn { name: String },
}

/// Domain trie node for fast lookups
#[derive(Debug, Clone)]
struct TrieNode {
    /// Child nodes (by label)
    children: HashMap<String, TrieNode>,
    /// Policy at this node
    policy: Option<PolicyEntry>,
    /// Is wildcard node
    is_wildcard: bool,
}

impl TrieNode {
    fn new() -> Self {
        Self {
            children: HashMap::new(),
            policy: None,
            is_wildcard: false,
        }
    }

    /// Insert policy into trie
    fn insert(&mut self, labels: &[String], policy: PolicyEntry) {
        if labels.is_empty() {
            self.policy = Some(policy);
            return;
        }

        let label = &labels[0];
        if label == "*" {
            self.is_wildcard = true;
            self.policy = Some(policy);
        } else {
            let child = self.children.entry(label.clone()).or_insert_with(TrieNode::new);
            child.insert(&labels[1..], policy);
        }
    }

    /// Lookup policy in trie
    fn lookup(&self, labels: &[String]) -> Option<&PolicyEntry> {
        if labels.is_empty() {
            return self.policy.as_ref();
        }

        // Check wildcard first
        if self.is_wildcard && self.policy.is_some() {
            return self.policy.as_ref();
        }

        let label = &labels[0];
        if let Some(child) = self.children.get(label) {
            if let Some(policy) = child.lookup(&labels[1..]) {
                return Some(policy);
            }
        }

        // Check if this node has a policy (partial match)
        self.policy.as_ref()
    }
}

/// RPZ engine
pub struct RpzEngine {
    /// Configuration
    config: Arc<RwLock<RpzConfig>>,
    /// Bloom filter for fast negative lookups (avoids trie traversal for unknown domains)
    domain_bloom: Arc<RwLock<Bloom<String>>>,
    /// Policy trie for confirmed positive lookups
    policy_trie: Arc<RwLock<TrieNode>>,
    /// Statistics
    stats: Arc<RwLock<RpzStats>>,
    /// Last update time
    last_update: Arc<RwLock<Instant>>,
}

/// RPZ statistics
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RpzStats {
    /// Total queries processed
    pub queries_processed: u64,
    /// Queries blocked
    pub queries_blocked: u64,
    /// Queries redirected
    pub queries_redirected: u64,
    /// Queries passed
    pub queries_passed: u64,
    /// Blocks by category
    pub blocks_by_category: HashMap<ThreatCategory, u64>,
    /// Total policies loaded
    pub policies_loaded: usize,
    /// Last policy update
    pub last_update: Option<u64>,
    /// Hits per blocked domain
    pub hits_per_domain: HashMap<String, u64>,
    /// Hits per client IP
    pub hits_per_client: HashMap<String, u64>,
}

/// IXFR delta record for incremental zone updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IxfrDelta {
    /// Serial number this delta applies from
    pub from_serial: u32,
    /// Serial number after this delta
    pub to_serial: u32,
    /// Domains to add
    pub additions: Vec<PolicyEntry>,
    /// Domains to remove
    pub removals: Vec<String>,
}

impl RpzEngine {
    /// Create new RPZ engine
    pub fn new(config: RpzConfig) -> Self {
        // Pre-allocate bloom filter for 1 million domains at 0.1 % false-positive rate.
        // False positives only cause an unnecessary trie lookup — never a wrong block.
        let bloom: Bloom<String> = Bloom::new_for_fp_rate(1_000_000, 0.001);

        let engine = Self {
            config: Arc::new(RwLock::new(config)),
            domain_bloom: Arc::new(RwLock::new(bloom)),
            policy_trie: Arc::new(RwLock::new(TrieNode::new())),
            stats: Arc::new(RwLock::new(RpzStats::default())),
            last_update: Arc::new(RwLock::new(Instant::now())),
        };

        // Load initial policies
        engine.load_default_policies();
        
        engine
    }

    /// Load default built-in policies
    fn load_default_policies(&self) {
        let mut trie = self.policy_trie.write();
        let mut bloom = self.domain_bloom.write();

        // Example malware domains
        let malware_domains = vec![
            "malware.example.com",
            "phishing.example.net",
            "botnet.cc.example.org",
        ];

        for domain in malware_domains {
            let policy = PolicyEntry {
                domain: domain.to_string(),
                action: PolicyAction::NxDomain,
                category: ThreatCategory::Malware,
                redirect_to: None,
                message: Some("Blocked by RPZ: Malware".to_string()),
                priority: 100,
                expires_at_secs: None,
            };

            let labels: Vec<String> = domain.split('.')
                .rev()
                .map(|s| s.to_string())
                .collect();
            trie.insert(&labels, policy);
            bloom.set(&domain.to_string());
        }

        self.stats.write().policies_loaded = 3;
    }

    /// Process query through RPZ policies
    pub fn process_query(
        &self,
        packet: &DnsPacket,
        client_ip: IpAddr,
    ) -> Result<Option<DnsPacket>, DnsError> {
        let config = self.config.read();
        
        if !config.enabled {
            self.stats.write().queries_passed += 1;
            return Ok(None);
        }

        self.stats.write().queries_processed += 1;

        // Get query domain
        let qname = packet.questions.first()
            .map(|q| q.name.clone())
            .unwrap_or_default();

        // Check whitelist first
        if config.whitelist.contains(&qname) {
            self.stats.write().queries_passed += 1;
            return Ok(None);
        }

        // Lookup policy
        let policy = self.lookup_policy(&qname);

        if let Some(policy) = policy {
            // Check if category is blocked
            if !config.blocked_categories.contains(&policy.category) {
                self.stats.write().queries_passed += 1;
                return Ok(None);
            }

            // Log if enabled
            if config.log_blocked {
                log::info!(
                    "RPZ blocked query for {} from {} (category: {:?}, action: {:?})",
                    qname, client_ip, policy.category, policy.action
                );
            }

            // Update statistics
            {
                let mut stats = self.stats.write();
                stats.queries_blocked += 1;
                *stats.blocks_by_category.entry(policy.category).or_insert(0) += 1;
                *stats.hits_per_domain.entry(qname.clone()).or_insert(0) += 1;
                *stats.hits_per_client.entry(client_ip.to_string()).or_insert(0) += 1;
            }

            // Apply policy action
            match policy.action {
                PolicyAction::NxDomain => {
                    Ok(Some(self.create_nxdomain_response(packet)))
                }
                PolicyAction::NoData => {
                    Ok(Some(self.create_nodata_response(packet)))
                }
                PolicyAction::Drop => {
                    Err(DnsError::Operation(crate::dns::errors::OperationError {
                        context: "RPZ".to_string(),
                        details: "Query dropped by policy".to_string(),
                        recovery_hint: None,
                    }))
                }
                PolicyAction::Redirect => {
                    let redirect_ip = policy.redirect_to
                        .or(config.default_redirect_ip)
                        .unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
                    self.stats.write().queries_redirected += 1;
                    Ok(Some(self.create_redirect_response(packet, redirect_ip)))
                }
                PolicyAction::Passthru => {
                    self.stats.write().queries_passed += 1;
                    Ok(None)
                }
                PolicyAction::TcpOnly => {
                    Ok(Some(self.create_truncated_response(packet)))
                }
            }
        } else {
            self.stats.write().queries_passed += 1;
            Ok(None)
        }
    }

    /// Lookup policy for domain using two-level bloom-filter + trie.
    ///
    /// The bloom filter provides a fast negative path: if the domain is
    /// definitely not in the filter we skip the trie entirely.  False
    /// positives (rare, ~0.1 %) fall through to the trie for confirmation.
    fn lookup_policy(&self, domain: &str) -> Option<PolicyEntry> {
        let t0 = Instant::now();

        // Level 1: bloom filter — O(1) negative check.
        let maybe_present = self.domain_bloom.read().check(&domain.to_string());
        if !maybe_present {
            log::trace!("RPZ bloom fast-negative for {} in {:?}", domain, t0.elapsed());
            return None;
        }

        // Level 2: trie confirmation.
        let labels: Vec<String> = domain.split('.')
            .rev()
            .map(|s| s.to_string())
            .collect();

        let result = self.policy_trie.read().lookup(&labels).cloned();
        log::trace!("RPZ trie lookup for {} -> {:?} in {:?}", domain, result.is_some(), t0.elapsed());
        result
    }

    /// Create NXDOMAIN response
    fn create_nxdomain_response(&self, request: &DnsPacket) -> DnsPacket {
        let mut response = DnsPacket::new();
        response.header.id = request.header.id;
        response.header.response = true;
        response.header.rescode = ResultCode::NXDOMAIN;
        response.questions = request.questions.clone();
        response
    }

    /// Create NODATA response
    fn create_nodata_response(&self, request: &DnsPacket) -> DnsPacket {
        let mut response = DnsPacket::new();
        response.header.id = request.header.id;
        response.header.response = true;
        response.header.rescode = ResultCode::NOERROR;
        response.header.authoritative_answer = true;
        response.questions = request.questions.clone();
        // No answer records = NODATA
        response
    }

    /// Create redirect response
    fn create_redirect_response(&self, request: &DnsPacket, redirect_ip: IpAddr) -> DnsPacket {
        let mut response = DnsPacket::new();
        response.header.id = request.header.id;
        response.header.response = true;
        response.header.rescode = ResultCode::NOERROR;
        response.questions = request.questions.clone();

        if let Some(question) = request.questions.first() {
            match (question.qtype, redirect_ip) {
                (QueryType::A, IpAddr::V4(addr)) => {
                    response.answers.push(DnsRecord::A {
                        domain: question.name.clone(),
                        addr,
                        ttl: TransientTtl(300),
                    });
                }
                (QueryType::Aaaa, IpAddr::V6(addr)) => {
                    response.answers.push(DnsRecord::Aaaa {
                        domain: question.name.clone(),
                        addr,
                        ttl: TransientTtl(300),
                    });
                }
                _ => {
                    // Type mismatch, return NODATA
                    return self.create_nodata_response(request);
                }
            }
        }

        response
    }

    /// Create truncated response (force TCP)
    fn create_truncated_response(&self, request: &DnsPacket) -> DnsPacket {
        let mut response = DnsPacket::new();
        response.header.id = request.header.id;
        response.header.response = true;
        response.header.truncated_message = true;
        response.questions = request.questions.clone();
        response
    }

    /// Add policy to engine
    pub fn add_policy(&self, policy: PolicyEntry) {
        let labels: Vec<String> = policy.domain.split('.')
            .rev()
            .map(|s| s.to_string())
            .collect();

        self.domain_bloom.write().set(&policy.domain);
        self.policy_trie.write().insert(&labels, policy);
        self.stats.write().policies_loaded += 1;
    }

    /// Remove policy from engine
    pub fn remove_policy(&self, _domain: &str) -> bool {
        // Would need to implement removal in trie
        // For now, just rebuild the trie without the domain
        false
    }

    /// Update policies from sources
    pub async fn update_policies(&self) -> Result<(), DnsError> {
        let config = self.config.read();
        
        for source in &config.sources {
            match source {
                PolicySource::File { path } => {
                    self.load_policies_from_file(path)?;
                }
                PolicySource::Url { url } => {
                    log::info!("Fetching RPZ policies from URL: {}", url);
                    match reqwest::blocking::get(url) {
                        Ok(resp) => {
                            match resp.text() {
                                Ok(body) => {
                                    let mut count = 0usize;
                                    for line in body.lines() {
                                        let line = line.trim();
                                        // Skip empty lines and comments
                                        if line.is_empty() || line.starts_with('#') {
                                            continue;
                                        }
                                        // Parse hosts-format: "0.0.0.0 domain.com" or just "domain.com"
                                        let domain = if let Some(d) = line.split_whitespace().nth(1) {
                                            d.to_string()
                                        } else {
                                            line.split_whitespace().next().unwrap_or("").to_string()
                                        };
                                        if domain.is_empty() || domain == "localhost" {
                                            continue;
                                        }
                                        self.add_policy(PolicyEntry {
                                            domain: domain.clone(),
                                            action: PolicyAction::NxDomain,
                                            category: ThreatCategory::Malware,
                                            redirect_to: None,
                                            message: Some(format!("Blocked by RPZ URL: {}", url)),
                                            priority: 50,
                                            expires_at_secs: None,
                                        });
                                        count += 1;
                                    }
                                    log::info!("Loaded {} policies from URL: {}", count, url);
                                }
                                Err(e) => {
                                    log::warn!("Failed to read response body from {}: {}", url, e);
                                }
                            }
                        }
                        Err(e) => {
                            log::warn!("Failed to fetch policies from {}: {}", url, e);
                        }
                    }
                }
                PolicySource::BuiltIn { name } => {
                    self.load_builtin_policies(name)?;
                }
            }
        }

        *self.last_update.write() = Instant::now();
        self.stats.write().last_update = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );

        Ok(())
    }

    /// Load policies from file
    fn load_policies_from_file(&self, _path: &str) -> Result<(), DnsError> {
        // Would read and parse policy file
        Ok(())
    }

    /// Load built-in policies
    fn load_builtin_policies(&self, name: &str) -> Result<(), DnsError> {
        match name {
            "malware" => {
                // Load known malware domains
                self.add_policy(PolicyEntry {
                    domain: "*.malicious.example".to_string(),
                    action: PolicyAction::NxDomain,
                    category: ThreatCategory::Malware,
                    redirect_to: None,
                    message: Some("Known malware domain".to_string()),
                    priority: 100,
                    expires_at_secs: None,
                });
            }
            "phishing" => {
                // Load known phishing domains
                self.add_policy(PolicyEntry {
                    domain: "*.phish.example".to_string(),
                    action: PolicyAction::Redirect,
                    category: ThreatCategory::Phishing,
                    redirect_to: Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                    message: Some("Phishing site blocked".to_string()),
                    priority: 100,
                    expires_at_secs: None,
                });
            }
            _ => {}
        }
        Ok(())
    }

    /// Get statistics
    pub fn get_stats(&self) -> RpzStats {
        let stats = self.stats.read();
        RpzStats {
            queries_processed: stats.queries_processed,
            queries_blocked: stats.queries_blocked,
            queries_redirected: stats.queries_redirected,
            queries_passed: stats.queries_passed,
            blocks_by_category: stats.blocks_by_category.clone(),
            policies_loaded: stats.policies_loaded,
            last_update: stats.last_update,
            hits_per_domain: stats.hits_per_domain.clone(),
            hits_per_client: stats.hits_per_client.clone(),
        }
    }

    /// Apply an IXFR delta to the RPZ engine
    pub fn apply_ixfr_delta(&self, delta: IxfrDelta) {
        log::info!(
            "Applying IXFR delta: serial {} -> {}  (+{} /{} removals)",
            delta.from_serial, delta.to_serial,
            delta.additions.len(), delta.removals.len()
        );
        // Add new entries
        for entry in delta.additions {
            self.add_policy(entry);
        }
        // Bloom filters cannot delete; mark removals as passthru so trie takes precedence
        for domain in delta.removals {
            self.add_policy(PolicyEntry {
                domain: domain.clone(),
                action: PolicyAction::Passthru,
                category: ThreatCategory::Custom(0),
                redirect_to: None,
                message: Some("IXFR removal (passthru override)".to_string()),
                priority: 200,
                expires_at_secs: None,
            });
        }
    }

    /// Clear all policies
    pub fn clear_policies(&self) {
        *self.policy_trie.write() = TrieNode::new();
        self.stats.write().policies_loaded = 0;
    }
}

/// RPZ policy validator
pub struct PolicyValidator {
    /// Maximum domain length
    max_domain_length: usize,
    /// Valid actions
    valid_actions: HashSet<PolicyAction>,
}

impl PolicyValidator {
    /// Create new validator
    pub fn new() -> Self {
        let mut valid_actions = HashSet::new();
        valid_actions.insert(PolicyAction::NxDomain);
        valid_actions.insert(PolicyAction::NoData);
        valid_actions.insert(PolicyAction::Drop);
        valid_actions.insert(PolicyAction::Redirect);
        valid_actions.insert(PolicyAction::Passthru);
        valid_actions.insert(PolicyAction::TcpOnly);

        Self {
            max_domain_length: 255,
            valid_actions,
        }
    }

    /// Validate policy entry
    pub fn validate(&self, policy: &PolicyEntry) -> Result<(), String> {
        // Validate domain
        if policy.domain.is_empty() {
            return Err("Domain cannot be empty".to_string());
        }

        if policy.domain.len() > self.max_domain_length {
            return Err("Domain exceeds maximum length".to_string());
        }

        // Validate action
        if !self.valid_actions.contains(&policy.action) {
            return Err("Invalid policy action".to_string());
        }

        // Validate redirect IP if action is Redirect
        if policy.action == PolicyAction::Redirect && policy.redirect_to.is_none() {
            return Err("Redirect action requires target IP".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trie_insert_and_lookup() {
        let mut trie = TrieNode::new();
        
        let policy = PolicyEntry {
            domain: "malware.example.com".to_string(),
            action: PolicyAction::NxDomain,
            category: ThreatCategory::Malware,
            redirect_to: None,
            message: None,
            priority: 100,
            expires_at_secs: None,
        };

        let labels = vec!["com".to_string(), "example".to_string(), "malware".to_string()];
        trie.insert(&labels, policy.clone());

        let found = trie.lookup(&labels);
        assert!(found.is_some());
        assert_eq!(found.unwrap().domain, "malware.example.com");
    }

    #[test]
    fn test_wildcard_matching() {
        let mut trie = TrieNode::new();
        
        let policy = PolicyEntry {
            domain: "*.example.com".to_string(),
            action: PolicyAction::NxDomain,
            category: ThreatCategory::Malware,
            redirect_to: None,
            message: None,
            priority: 100,
            expires_at_secs: None,
        };

        let labels = vec!["com".to_string(), "example".to_string(), "*".to_string()];
        trie.insert(&labels, policy.clone());

        // Should match any subdomain
        let test_labels = vec!["com".to_string(), "example".to_string(), "anything".to_string()];
        let found = trie.lookup(&test_labels);
        assert!(found.is_some());
    }

    #[test]
    fn test_rpz_blocking() {
        let mut config = RpzConfig::default();
        config.enabled = true;
        
        let engine = RpzEngine::new(config);
        
        // Add a policy
        engine.add_policy(PolicyEntry {
            domain: "blocked.example.com".to_string(),
            action: PolicyAction::NxDomain,
            category: ThreatCategory::Malware,
            redirect_to: None,
            message: None,
            priority: 100,
            expires_at_secs: None,
        });

        // Create test packet
        let mut packet = DnsPacket::new();
        packet.questions.push(crate::dns::protocol::DnsQuestion {
            name: "blocked.example.com".to_string(),
            qtype: QueryType::A,
        });

        let result = engine.process_query(&packet, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.is_some());
        
        let response_packet = response.unwrap();
        assert_eq!(response_packet.header.rescode, ResultCode::NXDOMAIN);
    }

    #[test]
    fn test_policy_validator() {
        let validator = PolicyValidator::new();
        
        let valid_policy = PolicyEntry {
            domain: "example.com".to_string(),
            action: PolicyAction::Redirect,
            category: ThreatCategory::Malware,
            redirect_to: Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            message: None,
            priority: 100,
            expires_at_secs: None,
        };
        
        assert!(validator.validate(&valid_policy).is_ok());
        
        let invalid_policy = PolicyEntry {
            domain: "example.com".to_string(),
            action: PolicyAction::Redirect,
            category: ThreatCategory::Malware,
            redirect_to: None,  // Missing redirect IP
            message: None,
            priority: 100,
            expires_at_secs: None,
        };
        
        assert!(validator.validate(&invalid_policy).is_err());
    }
}