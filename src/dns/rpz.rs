//! Response Policy Zones (RPZ) DNS Firewall Engine
//!
//! Implements RFC-style RPZ with:
//! - Multiple RPZ zones with priority-based precedence
//! - Trigger types: QNAME, CLIENT-IP, NSDNAME
//! - Action types: NXDOMAIN, NODATA, PASSTHRU, DROP, TCP-only, Redirect
//! - Zone loading from local RPZ zone files and remote AXFR zone transfers
//! - Runtime rule management via admin API
//! - Bloom-filter accelerated lookups per zone

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use bloomfilter::Bloom;

use crate::dns::buffer::PacketBuffer as PacketBufferTrait;
use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, ResultCode, TransientTtl};

// ─── Action types ────────────────────────────────────────────────────────────

/// RPZ policy action applied when a trigger matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RpzAction {
    /// Return NXDOMAIN (domain does not exist)
    NxDomain,
    /// Return NODATA (domain exists but no matching records)
    NoData,
    /// Silently drop the query (no response sent)
    Drop,
    /// Redirect the query to a local IP address
    Redirect,
    /// Allow the query through (overrides lower-priority blocks)
    Passthru,
    /// Force the client to retry over TCP (truncated response)
    TcpOnly,
}

impl fmt::Display for RpzAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RpzAction::NxDomain => write!(f, "NXDOMAIN"),
            RpzAction::NoData => write!(f, "NODATA"),
            RpzAction::Drop => write!(f, "DROP"),
            RpzAction::Redirect => write!(f, "REDIRECT"),
            RpzAction::Passthru => write!(f, "PASSTHRU"),
            RpzAction::TcpOnly => write!(f, "TCP-ONLY"),
        }
    }
}

// ─── Trigger types ───────────────────────────────────────────────────────────

/// The type of trigger that caused the RPZ rule to match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RpzTriggerType {
    /// Match against the queried domain name (QNAME trigger)
    QName,
    /// Match against the client source IP address (CLIENT-IP trigger)
    ClientIp,
    /// Match against the authoritative nameserver name (NSDNAME trigger)
    NsDName,
}

impl fmt::Display for RpzTriggerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RpzTriggerType::QName => write!(f, "QNAME"),
            RpzTriggerType::ClientIp => write!(f, "CLIENT-IP"),
            RpzTriggerType::NsDName => write!(f, "NSDNAME"),
        }
    }
}

// ─── Threat categories ───────────────────────────────────────────────────────

/// Threat category for classification and reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatCategory {
    Malware,
    Phishing,
    Botnet,
    Advertising,
    Tracking,
    Adult,
    Gambling,
    Custom(u32),
}

// ─── RPZ rule ────────────────────────────────────────────────────────────────

/// A single RPZ rule within a zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpzRule {
    /// The trigger value: a domain pattern for QNAME/NSDNAME, or CIDR for CLIENT-IP
    pub trigger_value: String,
    /// Trigger type
    pub trigger_type: RpzTriggerType,
    /// Action to apply
    pub action: RpzAction,
    /// Redirect target IP (only for Redirect action)
    pub redirect_to: Option<IpAddr>,
    /// Threat category
    pub category: ThreatCategory,
    /// Human-readable description
    pub description: Option<String>,
}

// ─── RPZ Zone ────────────────────────────────────────────────────────────────

/// Source from which an RPZ zone is loaded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpzZoneSource {
    /// Local zone file on disk
    File { path: String },
    /// Remote zone transfer (AXFR) from a primary server
    Axfr { server: String, port: u16, zone_name: String },
    /// Inline / runtime-managed (rules added via API)
    Inline,
}

/// A single RPZ zone containing rules and metadata.
pub struct RpzZone {
    /// Unique zone name (e.g. "threat-intel", "custom-blocks")
    pub name: String,
    /// Priority: higher value = evaluated first, wins on conflict
    pub priority: u32,
    /// Whether this zone is currently active
    pub enabled: bool,
    /// Where the zone was loaded from
    pub source: RpzZoneSource,
    /// QNAME trigger rules: domain -> rule (reverse-label trie)
    qname_trie: TrieNode,
    /// CLIENT-IP trigger rules: IP string -> rule
    client_ip_rules: HashMap<IpAddr, RpzRule>,
    /// CLIENT-IP CIDR rules for subnet matching
    client_cidr_rules: Vec<(IpNet, RpzRule)>,
    /// NSDNAME trigger rules: nameserver domain -> rule
    nsdname_trie: TrieNode,
    /// Bloom filter for fast QNAME negative lookups
    qname_bloom: Bloom<String>,
    /// Total number of rules in this zone
    pub rule_count: usize,
    /// SOA serial (for zone transfers)
    pub serial: u32,
}

/// Simple CIDR representation for CLIENT-IP matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpNet {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl IpNet {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(host)) => {
                if self.prefix_len == 0 { return true; }
                if self.prefix_len >= 32 { return net == host; }
                let mask = !0u32 << (32 - self.prefix_len);
                (u32::from(net) & mask) == (u32::from(host) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(host)) => {
                if self.prefix_len == 0 { return true; }
                if self.prefix_len >= 128 { return net == host; }
                let net_bits = u128::from(net);
                let host_bits = u128::from(host);
                let mask = !0u128 << (128 - self.prefix_len);
                (net_bits & mask) == (host_bits & mask)
            }
            _ => false,
        }
    }

    /// Parse "192.168.1.0/24" or "10.0.0.1" (implicit /32 or /128).
    pub fn parse(s: &str) -> Option<IpNet> {
        if let Some((addr_s, len_s)) = s.split_once('/') {
            let addr: IpAddr = addr_s.parse().ok()?;
            let prefix_len: u8 = len_s.parse().ok()?;
            Some(IpNet { addr, prefix_len })
        } else {
            let addr: IpAddr = s.parse().ok()?;
            let prefix_len = if addr.is_ipv4() { 32 } else { 128 };
            Some(IpNet { addr, prefix_len })
        }
    }
}

impl RpzZone {
    pub fn new(name: String, priority: u32, source: RpzZoneSource) -> Self {
        Self {
            name,
            priority,
            enabled: true,
            source,
            qname_trie: TrieNode::new(),
            client_ip_rules: HashMap::new(),
            client_cidr_rules: Vec::new(),
            nsdname_trie: TrieNode::new(),
            qname_bloom: Bloom::new_for_fp_rate(1_000_000, 0.001),
            rule_count: 0,
            serial: 0,
        }
    }

    /// Add a rule to this zone.
    pub fn add_rule(&mut self, rule: RpzRule) {
        match rule.trigger_type {
            RpzTriggerType::QName => {
                self.qname_bloom.set(&rule.trigger_value);
                let labels = domain_to_labels(&rule.trigger_value);
                self.qname_trie.insert(&labels, rule);
            }
            RpzTriggerType::ClientIp => {
                if let Some(net) = IpNet::parse(&rule.trigger_value) {
                    // Exact host match vs subnet
                    let is_host = (net.addr.is_ipv4() && net.prefix_len == 32)
                        || (net.addr.is_ipv6() && net.prefix_len == 128);
                    if is_host {
                        self.client_ip_rules.insert(net.addr, rule);
                    } else {
                        self.client_cidr_rules.push((net, rule));
                    }
                }
            }
            RpzTriggerType::NsDName => {
                let labels = domain_to_labels(&rule.trigger_value);
                self.nsdname_trie.insert(&labels, rule);
            }
        }
        self.rule_count += 1;
    }

    /// Remove a rule by trigger value and type. Returns true if found.
    pub fn remove_rule(&mut self, trigger_value: &str, trigger_type: RpzTriggerType) -> bool {
        match trigger_type {
            RpzTriggerType::QName => {
                let labels = domain_to_labels(trigger_value);
                let removed = self.qname_trie.remove(&labels);
                if removed { self.rule_count = self.rule_count.saturating_sub(1); }
                removed
            }
            RpzTriggerType::ClientIp => {
                if let Ok(addr) = trigger_value.parse::<IpAddr>() {
                    if self.client_ip_rules.remove(&addr).is_some() {
                        self.rule_count = self.rule_count.saturating_sub(1);
                        return true;
                    }
                }
                let before = self.client_cidr_rules.len();
                self.client_cidr_rules.retain(|(_net, r)| r.trigger_value != trigger_value);
                let removed = self.client_cidr_rules.len() < before;
                if removed { self.rule_count = self.rule_count.saturating_sub(1); }
                removed
            }
            RpzTriggerType::NsDName => {
                let labels = domain_to_labels(trigger_value);
                let removed = self.nsdname_trie.remove(&labels);
                if removed { self.rule_count = self.rule_count.saturating_sub(1); }
                removed
            }
        }
    }

    /// Lookup a QNAME trigger.
    fn lookup_qname(&self, domain: &str) -> Option<&RpzRule> {
        if !self.qname_bloom.check(&domain.to_string()) {
            return None;
        }
        let labels = domain_to_labels(domain);
        self.qname_trie.lookup(&labels)
    }

    /// Lookup a CLIENT-IP trigger.
    fn lookup_client_ip(&self, ip: IpAddr) -> Option<&RpzRule> {
        // Exact match first
        if let Some(rule) = self.client_ip_rules.get(&ip) {
            return Some(rule);
        }
        // CIDR match (most specific prefix wins)
        let mut best: Option<(u8, &RpzRule)> = None;
        for (net, rule) in &self.client_cidr_rules {
            if net.contains(ip) {
                match best {
                    Some((prev_len, _)) if net.prefix_len <= prev_len => {}
                    _ => best = Some((net.prefix_len, rule)),
                }
            }
        }
        best.map(|(_, r)| r)
    }

    /// Lookup an NSDNAME trigger.
    fn lookup_nsdname(&self, ns_domain: &str) -> Option<&RpzRule> {
        let labels = domain_to_labels(ns_domain);
        self.nsdname_trie.lookup(&labels)
    }

    /// Clear all rules in this zone.
    pub fn clear(&mut self) {
        self.qname_trie = TrieNode::new();
        self.client_ip_rules.clear();
        self.client_cidr_rules.clear();
        self.nsdname_trie = TrieNode::new();
        self.qname_bloom = Bloom::new_for_fp_rate(1_000_000, 0.001);
        self.rule_count = 0;
    }
}

// ─── Domain label helpers ────────────────────────────────────────────────────

fn domain_to_labels(domain: &str) -> Vec<String> {
    domain.split('.').rev().map(|s| s.to_lowercase()).collect()
}

// ─── Trie for domain matching ────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct TrieNode {
    children: HashMap<String, TrieNode>,
    rule: Option<RpzRule>,
    is_wildcard: bool,
}

impl TrieNode {
    fn new() -> Self {
        Self { children: HashMap::new(), rule: None, is_wildcard: false }
    }

    fn insert(&mut self, labels: &[String], rule: RpzRule) {
        if labels.is_empty() {
            self.rule = Some(rule);
            return;
        }
        if labels[0] == "*" {
            self.is_wildcard = true;
            self.rule = Some(rule);
        } else {
            self.children.entry(labels[0].clone())
                .or_insert_with(TrieNode::new)
                .insert(&labels[1..], rule);
        }
    }

    fn lookup(&self, labels: &[String]) -> Option<&RpzRule> {
        if labels.is_empty() {
            return self.rule.as_ref();
        }
        // Exact child match
        if let Some(child) = self.children.get(&labels[0]) {
            if let Some(rule) = child.lookup(&labels[1..]) {
                return Some(rule);
            }
        }
        // Wildcard match at this level covers all remaining labels
        if self.is_wildcard {
            return self.rule.as_ref();
        }
        None
    }

    fn remove(&mut self, labels: &[String]) -> bool {
        if labels.is_empty() {
            let had = self.rule.is_some();
            self.rule = None;
            return had;
        }
        if labels[0] == "*" {
            let had = self.is_wildcard;
            self.is_wildcard = false;
            self.rule = None;
            return had;
        }
        if let Some(child) = self.children.get_mut(&labels[0]) {
            let removed = child.remove(&labels[1..]);
            // Prune empty children
            if child.rule.is_none() && !child.is_wildcard && child.children.is_empty() {
                self.children.remove(&labels[0]);
            }
            return removed;
        }
        false
    }
}

// ─── Match result ────────────────────────────────────────────────────────────

/// Result of evaluating a query against the RPZ engine.
#[derive(Debug, Clone, Serialize)]
pub struct RpzMatch {
    /// The zone that matched
    pub zone_name: String,
    /// Zone priority
    pub zone_priority: u32,
    /// The matching rule
    pub trigger_type: RpzTriggerType,
    pub trigger_value: String,
    pub action: RpzAction,
    pub redirect_to: Option<IpAddr>,
    pub category: ThreatCategory,
}

// ─── RPZ Engine ──────────────────────────────────────────────────────────────

/// RPZ statistics.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RpzStats {
    pub queries_processed: u64,
    pub queries_blocked: u64,
    pub queries_redirected: u64,
    pub queries_dropped: u64,
    pub queries_passthru: u64,
    pub queries_tcp_only: u64,
    pub total_rules: usize,
    pub zone_count: usize,
    pub hits_by_zone: HashMap<String, u64>,
    pub hits_by_trigger: HashMap<String, u64>,
    pub hits_by_action: HashMap<String, u64>,
}

/// The main RPZ firewall engine managing multiple zones with priority precedence.
pub struct RpzEngine {
    /// Zones ordered by priority (highest first). Protected by RwLock for runtime updates.
    zones: RwLock<BTreeMap<u32, Vec<RpzZone>>>,
    /// Global enabled flag
    enabled: RwLock<bool>,
    /// Statistics
    stats: RwLock<RpzStats>,
    /// Whitelist domains that are never blocked
    whitelist: RwLock<HashSet<String>>,
}

impl RpzEngine {
    /// Create a new RPZ engine.
    pub fn new() -> Self {
        Self {
            zones: RwLock::new(BTreeMap::new()),
            enabled: RwLock::new(true),
            stats: RwLock::new(RpzStats::default()),
            whitelist: RwLock::new(HashSet::new()),
        }
    }

    /// Enable or disable the engine globally.
    pub fn set_enabled(&self, enabled: bool) {
        *self.enabled.write() = enabled;
    }

    pub fn is_enabled(&self) -> bool {
        *self.enabled.read()
    }

    /// Add a domain to the global whitelist (never blocked).
    pub fn add_whitelist(&self, domain: &str) {
        self.whitelist.write().insert(domain.to_lowercase());
    }

    /// Remove a domain from the whitelist.
    pub fn remove_whitelist(&self, domain: &str) -> bool {
        self.whitelist.write().remove(&domain.to_lowercase())
    }

    /// Get the whitelist.
    pub fn get_whitelist(&self) -> Vec<String> {
        self.whitelist.read().iter().cloned().collect()
    }

    // ── Zone management ──────────────────────────────────────────────────────

    /// Add a new RPZ zone. If a zone with the same name exists, it is replaced.
    pub fn add_zone(&self, zone: RpzZone) {
        let mut zones = self.zones.write();
        let priority = zone.priority;
        // Remove any existing zone with same name
        for bucket in zones.values_mut() {
            bucket.retain(|z| z.name != zone.name);
        }
        // Remove empty buckets
        zones.retain(|_, v| !v.is_empty());
        // Insert at correct priority
        zones.entry(priority).or_insert_with(Vec::new).push(zone);
        self.update_stats_count();
    }

    /// Remove a zone by name. Returns true if found.
    pub fn remove_zone(&self, name: &str) -> bool {
        let mut zones = self.zones.write();
        let mut found = false;
        for bucket in zones.values_mut() {
            let before = bucket.len();
            bucket.retain(|z| z.name != name);
            if bucket.len() < before { found = true; }
        }
        zones.retain(|_, v| !v.is_empty());
        if found { self.update_stats_count(); }
        found
    }

    /// List all zones with metadata.
    pub fn list_zones(&self) -> Vec<RpzZoneInfo> {
        let zones = self.zones.read();
        let mut result = Vec::new();
        // Iterate in reverse priority order (highest first)
        for (priority, bucket) in zones.iter().rev() {
            for zone in bucket {
                result.push(RpzZoneInfo {
                    name: zone.name.clone(),
                    priority: *priority,
                    enabled: zone.enabled,
                    rule_count: zone.rule_count,
                    serial: zone.serial,
                    source: format!("{:?}", zone.source),
                });
            }
        }
        result
    }

    /// Enable or disable a zone by name.
    pub fn set_zone_enabled(&self, name: &str, enabled: bool) -> bool {
        let mut zones = self.zones.write();
        for bucket in zones.values_mut() {
            for zone in bucket.iter_mut() {
                if zone.name == name {
                    zone.enabled = enabled;
                    return true;
                }
            }
        }
        false
    }

    // ── Rule management within a zone ────────────────────────────────────────

    /// Add a rule to a named zone. Returns false if zone not found.
    pub fn add_rule_to_zone(&self, zone_name: &str, rule: RpzRule) -> bool {
        let mut zones = self.zones.write();
        for bucket in zones.values_mut() {
            for zone in bucket.iter_mut() {
                if zone.name == zone_name {
                    zone.add_rule(rule);
                    drop(zones);
                    self.update_stats_count();
                    return true;
                }
            }
        }
        false
    }

    /// Remove a rule from a named zone. Returns false if zone/rule not found.
    pub fn remove_rule_from_zone(
        &self, zone_name: &str, trigger_value: &str, trigger_type: RpzTriggerType,
    ) -> bool {
        let mut zones = self.zones.write();
        for bucket in zones.values_mut() {
            for zone in bucket.iter_mut() {
                if zone.name == zone_name {
                    let removed = zone.remove_rule(trigger_value, trigger_type);
                    if removed {
                        drop(zones);
                        self.update_stats_count();
                    }
                    return removed;
                }
            }
        }
        false
    }

    fn update_stats_count(&self) {
        let zones = self.zones.read();
        let mut total = 0;
        let mut zcount = 0;
        for bucket in zones.values() {
            for zone in bucket {
                total += zone.rule_count;
                zcount += 1;
            }
        }
        let mut stats = self.stats.write();
        stats.total_rules = total;
        stats.zone_count = zcount;
    }

    // ── Query evaluation ─────────────────────────────────────────────────────

    /// Evaluate a DNS query against all RPZ zones.
    ///
    /// Returns `Some(DnsPacket)` if an RPZ action should override normal resolution,
    /// or `None` if the query should proceed normally.
    ///
    /// For `Drop` actions, returns `Err` to signal the server should send no response.
    pub fn evaluate(
        &self,
        request: &DnsPacket,
        client_ip: Option<IpAddr>,
    ) -> Result<Option<DnsPacket>, RpzDropSignal> {
        if !*self.enabled.read() {
            return Ok(None);
        }

        self.stats.write().queries_processed += 1;

        let qname = request.questions.first()
            .map(|q| q.name.to_lowercase())
            .unwrap_or_default();

        // Whitelist check
        if self.whitelist.read().contains(&qname) {
            self.stats.write().queries_passthru += 1;
            return Ok(None);
        }

        // Evaluate zones in priority order (highest first)
        let zones = self.zones.read();
        for (_priority, bucket) in zones.iter().rev() {
            for zone in bucket {
                if !zone.enabled { continue; }

                // 1. CLIENT-IP trigger (checked first per RPZ spec)
                if let Some(ip) = client_ip {
                    if let Some(rule) = zone.lookup_client_ip(ip) {
                        return self.apply_match(request, zone, rule);
                    }
                }

                // 2. QNAME trigger
                if !qname.is_empty() {
                    if let Some(rule) = zone.lookup_qname(&qname) {
                        return self.apply_match(request, zone, rule);
                    }
                }

                // 3. NSDNAME trigger — checked against authority section NS records
                // (typically used post-resolution, but we check request authority)
                for auth in &request.authorities {
                    if let DnsRecord::Ns { ref host, .. } = auth {
                        if let Some(rule) = zone.lookup_nsdname(host) {
                            return self.apply_match(request, zone, rule);
                        }
                    }
                }
            }
        }

        self.stats.write().queries_passthru += 1;
        Ok(None)
    }

    /// Evaluate NSDNAME triggers against a set of nameserver names.
    /// Called after we discover the authoritative NS for a domain.
    pub fn evaluate_nsdname(
        &self,
        request: &DnsPacket,
        nameservers: &[String],
    ) -> Result<Option<DnsPacket>, RpzDropSignal> {
        if !*self.enabled.read() {
            return Ok(None);
        }

        let zones = self.zones.read();
        for (_priority, bucket) in zones.iter().rev() {
            for zone in bucket {
                if !zone.enabled { continue; }
                for ns in nameservers {
                    if let Some(rule) = zone.lookup_nsdname(ns) {
                        return self.apply_match(request, zone, rule);
                    }
                }
            }
        }
        Ok(None)
    }

    fn apply_match(
        &self,
        request: &DnsPacket,
        zone: &RpzZone,
        rule: &RpzRule,
    ) -> Result<Option<DnsPacket>, RpzDropSignal> {
        log::info!(
            "RPZ match: zone={} trigger={}:{} action={} category={:?}",
            zone.name, rule.trigger_type, rule.trigger_value, rule.action, rule.category
        );

        // Update stats
        {
            let mut stats = self.stats.write();
            *stats.hits_by_zone.entry(zone.name.clone()).or_insert(0) += 1;
            *stats.hits_by_trigger.entry(rule.trigger_type.to_string()).or_insert(0) += 1;
            *stats.hits_by_action.entry(rule.action.to_string()).or_insert(0) += 1;
        }

        match rule.action {
            RpzAction::NxDomain => {
                self.stats.write().queries_blocked += 1;
                Ok(Some(self.build_nxdomain(request)))
            }
            RpzAction::NoData => {
                self.stats.write().queries_blocked += 1;
                Ok(Some(self.build_nodata(request)))
            }
            RpzAction::Drop => {
                self.stats.write().queries_dropped += 1;
                Err(RpzDropSignal)
            }
            RpzAction::Redirect => {
                self.stats.write().queries_redirected += 1;
                let ip = rule.redirect_to
                    .unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
                Ok(Some(self.build_redirect(request, ip)))
            }
            RpzAction::Passthru => {
                self.stats.write().queries_passthru += 1;
                Ok(None)
            }
            RpzAction::TcpOnly => {
                self.stats.write().queries_tcp_only += 1;
                Ok(Some(self.build_truncated(request)))
            }
        }
    }

    // ── Response builders ────────────────────────────────────────────────────

    fn build_nxdomain(&self, request: &DnsPacket) -> DnsPacket {
        let mut r = DnsPacket::new();
        r.header.id = request.header.id;
        r.header.response = true;
        r.header.rescode = ResultCode::NXDOMAIN;
        r.questions = request.questions.clone();
        r
    }

    fn build_nodata(&self, request: &DnsPacket) -> DnsPacket {
        let mut r = DnsPacket::new();
        r.header.id = request.header.id;
        r.header.response = true;
        r.header.rescode = ResultCode::NOERROR;
        r.header.authoritative_answer = true;
        r.questions = request.questions.clone();
        r
    }

    fn build_redirect(&self, request: &DnsPacket, ip: IpAddr) -> DnsPacket {
        let mut r = DnsPacket::new();
        r.header.id = request.header.id;
        r.header.response = true;
        r.header.rescode = ResultCode::NOERROR;
        r.questions = request.questions.clone();
        if let Some(q) = request.questions.first() {
            match (q.qtype, ip) {
                (QueryType::A, IpAddr::V4(addr)) => {
                    r.answers.push(DnsRecord::A {
                        domain: q.name.clone(),
                        addr,
                        ttl: TransientTtl(60),
                    });
                }
                (QueryType::Aaaa, IpAddr::V6(addr)) => {
                    r.answers.push(DnsRecord::Aaaa {
                        domain: q.name.clone(),
                        addr,
                        ttl: TransientTtl(60),
                    });
                }
                _ => {
                    // Type mismatch: NODATA
                    return self.build_nodata(request);
                }
            }
        }
        r
    }

    fn build_truncated(&self, request: &DnsPacket) -> DnsPacket {
        let mut r = DnsPacket::new();
        r.header.id = request.header.id;
        r.header.response = true;
        r.header.truncated_message = true;
        r.questions = request.questions.clone();
        r
    }

    // ── Zone loading ─────────────────────────────────────────────────────────

    /// Load an RPZ zone from a local file.
    ///
    /// Supports the standard RPZ zone file format:
    /// ```text
    /// ; RPZ zone file
    /// $ORIGIN rpz.example.com.
    /// ; QNAME triggers
    /// malware.example.com CNAME .          ; NXDOMAIN
    /// ads.example.com     CNAME *.         ; NODATA
    /// tracker.example.com CNAME rpz-passthru. ; PASSTHRU
    /// redirect.example.com A 10.0.0.1      ; Redirect
    /// ; CLIENT-IP triggers
    /// 32.1.168.192.rpz-client-ip CNAME .   ; Block 192.168.1.0/32
    /// 24.0.0.10.rpz-client-ip CNAME .      ; Block 10.0.0.0/24
    /// ; NSDNAME triggers
    /// evil-ns.example.com.rpz-nsdname CNAME . ; Block NS
    /// ```
    ///
    /// Also supports a simplified hosts-like format:
    /// ```text
    /// # comment
    /// 0.0.0.0 malware.example.com
    /// malware2.example.com
    /// ```
    pub fn load_zone_from_file(
        &self,
        name: &str,
        priority: u32,
        path: &str,
    ) -> Result<usize, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read RPZ file {}: {}", path, e))?;

        let mut zone = RpzZone::new(
            name.to_string(),
            priority,
            RpzZoneSource::File { path: path.to_string() },
        );

        let count = Self::parse_zone_content(&mut zone, &content);
        log::info!("RPZ: loaded {} rules from file {} into zone '{}'", count, path, name);

        self.add_zone(zone);
        Ok(count)
    }

    /// Parse zone file content into an RpzZone. Returns the number of rules loaded.
    fn parse_zone_content(zone: &mut RpzZone, content: &str) -> usize {
        let mut count = 0;

        for line in content.lines() {
            let line = line.trim();
            // Skip empty lines, comments, directives
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') || line.starts_with('$') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() { continue; }

            // Try RPZ zone format first: "owner TYPE RDATA"
            if parts.len() >= 3 {
                let owner = parts[0].trim_end_matches('.');
                let rtype = parts[1].to_uppercase();
                let rdata = parts[2].trim_end_matches('.');

                // Detect trigger type from owner name
                if owner.ends_with("rpz-client-ip") {
                    // CLIENT-IP trigger: "prefix.rpz-client-ip"
                    if let Some(rule) = Self::parse_client_ip_trigger(owner, &rtype, rdata) {
                        zone.add_rule(rule);
                        count += 1;
                    }
                } else if owner.ends_with("rpz-nsdname") {
                    // NSDNAME trigger
                    let ns_name = owner.trim_end_matches(".rpz-nsdname")
                        .trim_end_matches("rpz-nsdname");
                    let ns_name = ns_name.trim_end_matches('.');
                    if !ns_name.is_empty() {
                        let action = Self::rdata_to_action(&rtype, rdata);
                        zone.add_rule(RpzRule {
                            trigger_value: ns_name.to_string(),
                            trigger_type: RpzTriggerType::NsDName,
                            action: action.0,
                            redirect_to: action.1,
                            category: ThreatCategory::Custom(0),
                            description: None,
                        });
                        count += 1;
                    }
                } else if rtype == "CNAME" || rtype == "A" || rtype == "AAAA" {
                    // QNAME trigger
                    let action = Self::rdata_to_action(&rtype, rdata);
                    zone.add_rule(RpzRule {
                        trigger_value: owner.to_string(),
                        trigger_type: RpzTriggerType::QName,
                        action: action.0,
                        redirect_to: action.1,
                        category: ThreatCategory::Custom(0),
                        description: None,
                    });
                    count += 1;
                }
            } else if parts.len() == 2 {
                // Hosts-file format: "0.0.0.0 domain" or "127.0.0.1 domain"
                let first = parts[0];
                let second = parts[1];
                if first == "0.0.0.0" || first == "127.0.0.1" || first == "::1" || first == "::" {
                    if second != "localhost" && !second.is_empty() {
                        zone.add_rule(RpzRule {
                            trigger_value: second.to_string(),
                            trigger_type: RpzTriggerType::QName,
                            action: RpzAction::NxDomain,
                            redirect_to: None,
                            category: ThreatCategory::Custom(0),
                            description: None,
                        });
                        count += 1;
                    }
                } else {
                    // Could be "domain CNAME" without RDATA — treat first token as domain
                    let action = Self::rdata_to_action(&second.to_uppercase(), ".");
                    zone.add_rule(RpzRule {
                        trigger_value: first.trim_end_matches('.').to_string(),
                        trigger_type: RpzTriggerType::QName,
                        action: action.0,
                        redirect_to: action.1,
                        category: ThreatCategory::Custom(0),
                        description: None,
                    });
                    count += 1;
                }
            } else if parts.len() == 1 {
                // Bare domain
                let domain = parts[0].trim_end_matches('.');
                if !domain.is_empty() && domain != "localhost" {
                    zone.add_rule(RpzRule {
                        trigger_value: domain.to_string(),
                        trigger_type: RpzTriggerType::QName,
                        action: RpzAction::NxDomain,
                        redirect_to: None,
                        category: ThreatCategory::Custom(0),
                        description: None,
                    });
                    count += 1;
                }
            }
        }

        count
    }

    /// Parse CLIENT-IP trigger owner name.
    /// Format: "prefixlen.reversed-ip.rpz-client-ip"
    /// e.g. "32.1.168.192.rpz-client-ip" -> 192.168.1.0/32
    fn parse_client_ip_trigger(owner: &str, rtype: &str, rdata: &str) -> Option<RpzRule> {
        let stripped = owner.trim_end_matches(".rpz-client-ip")
            .trim_end_matches("rpz-client-ip");
        let stripped = stripped.trim_end_matches('.');

        let parts: Vec<&str> = stripped.split('.').collect();
        if parts.len() < 2 { return None; }

        // First part is the prefix length
        let prefix_len: u8 = parts[0].parse().ok()?;
        // Remaining parts are the IP in reverse
        let ip_parts: Vec<&str> = parts[1..].iter().rev().copied().collect();
        let ip_str = ip_parts.join(".");

        // Pad to full IP if needed
        let full_ip = if ip_parts.len() <= 4 {
            // IPv4
            let mut octets = ip_parts.clone();
            while octets.len() < 4 { octets.push("0"); }
            octets.join(".")
        } else {
            ip_str
        };

        let addr: IpAddr = full_ip.parse().ok()?;
        let action = Self::rdata_to_action(rtype, rdata);

        Some(RpzRule {
            trigger_value: format!("{}/{}", addr, prefix_len),
            trigger_type: RpzTriggerType::ClientIp,
            action: action.0,
            redirect_to: action.1,
            category: ThreatCategory::Custom(0),
            description: None,
        })
    }

    /// Map RPZ RDATA to an action.
    fn rdata_to_action(rtype: &str, rdata: &str) -> (RpzAction, Option<IpAddr>) {
        match rtype {
            "CNAME" => match rdata {
                "." | "" => (RpzAction::NxDomain, None),
                "*." | "*" => (RpzAction::NoData, None),
                "rpz-passthru" | "rpz-passthru." => (RpzAction::Passthru, None),
                "rpz-drop" | "rpz-drop." => (RpzAction::Drop, None),
                "rpz-tcp-only" | "rpz-tcp-only." => (RpzAction::TcpOnly, None),
                _ => (RpzAction::NxDomain, None),
            },
            "A" => {
                if let Ok(addr) = rdata.parse::<Ipv4Addr>() {
                    (RpzAction::Redirect, Some(IpAddr::V4(addr)))
                } else {
                    (RpzAction::NxDomain, None)
                }
            }
            "AAAA" => {
                if let Ok(addr) = rdata.parse::<Ipv6Addr>() {
                    (RpzAction::Redirect, Some(IpAddr::V6(addr)))
                } else {
                    (RpzAction::NxDomain, None)
                }
            }
            _ => (RpzAction::NxDomain, None),
        }
    }

    /// Load a zone from remote AXFR zone transfer.
    /// Performs a DNS AXFR query and parses the resulting records.
    pub fn load_zone_from_axfr(
        &self,
        name: &str,
        priority: u32,
        server: &str,
        port: u16,
        zone_name: &str,
    ) -> Result<usize, String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::time::Duration;

        log::info!("RPZ: initiating AXFR from {}:{} for zone {}", server, port, zone_name);

        let addr = format!("{}:{}", server, port);
        let mut stream = TcpStream::connect_timeout(
            &addr.parse().map_err(|e| format!("Invalid server address: {}", e))?,
            Duration::from_secs(10),
        ).map_err(|e| format!("AXFR connect failed: {}", e))?;

        stream.set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| format!("Set timeout failed: {}", e))?;

        // Build AXFR query packet
        let mut query = DnsPacket::new();
        query.header.id = rand::random::<u16>();
        query.header.recursion_desired = false;
        query.questions.push(crate::dns::protocol::DnsQuestion {
            name: zone_name.to_string(),
            qtype: QueryType::Axfr,
        });

        // Serialize and send with TCP length prefix
        let mut buf = crate::dns::buffer::VectorPacketBuffer::new();
        query.write(&mut buf, 0xFFFF).map_err(|e| format!("Failed to serialize AXFR query: {}", e))?;
        let data_len = buf.pos;
        let data = buf.get_range(0, data_len).map_err(|e| format!("Buffer error: {}", e))?;
        let len = data.len() as u16;
        let data_copy = data.to_vec();
        stream.write_all(&len.to_be_bytes()).map_err(|e| format!("Write failed: {}", e))?;
        stream.write_all(&data_copy).map_err(|e| format!("Write failed: {}", e))?;

        // Read response(s) — AXFR may span multiple TCP messages
        let mut zone = RpzZone::new(
            name.to_string(),
            priority,
            RpzZoneSource::Axfr { server: server.to_string(), port, zone_name: zone_name.to_string() },
        );
        let mut count = 0;
        let mut soa_count = 0;

        loop {
            // Read 2-byte length prefix
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).is_err() { break; }
            let msg_len = u16::from_be_bytes(len_buf) as usize;
            if msg_len == 0 { break; }

            let mut msg_buf = vec![0u8; msg_len];
            if stream.read_exact(&mut msg_buf).is_err() { break; }

            // Parse the DNS response using VectorPacketBuffer
            let mut pkt_buf = crate::dns::buffer::VectorPacketBuffer {
                buffer: msg_buf,
                pos: 0,
                label_lookup: std::collections::BTreeMap::new(),
            };
            let response = match DnsPacket::from_buffer(&mut pkt_buf) {
                Ok(pkt) => pkt,
                Err(_) => break,
            };

            // Process answer records
            for record in &response.answers {
                match record {
                    DnsRecord::Soa { .. } => {
                        soa_count += 1;
                        // Second SOA marks end of AXFR
                        if soa_count >= 2 {
                            break;
                        }
                    }
                    DnsRecord::Cname { domain, host, .. } => {
                        // Standard RPZ CNAME encoding
                        let host_lower = host.to_lowercase();
                        let action = Self::rdata_to_action("CNAME", &host_lower);
                        zone.add_rule(RpzRule {
                            trigger_value: domain.clone(),
                            trigger_type: RpzTriggerType::QName,
                            action: action.0,
                            redirect_to: action.1,
                            category: ThreatCategory::Custom(0),
                            description: None,
                        });
                        count += 1;
                    }
                    DnsRecord::A { domain, addr, .. } => {
                        zone.add_rule(RpzRule {
                            trigger_value: domain.clone(),
                            trigger_type: RpzTriggerType::QName,
                            action: RpzAction::Redirect,
                            redirect_to: Some(IpAddr::V4(*addr)),
                            category: ThreatCategory::Custom(0),
                            description: None,
                        });
                        count += 1;
                    }
                    DnsRecord::Aaaa { domain, addr, .. } => {
                        zone.add_rule(RpzRule {
                            trigger_value: domain.clone(),
                            trigger_type: RpzTriggerType::QName,
                            action: RpzAction::Redirect,
                            redirect_to: Some(IpAddr::V6(*addr)),
                            category: ThreatCategory::Custom(0),
                            description: None,
                        });
                        count += 1;
                    }
                    _ => {}
                }
            }

            if soa_count >= 2 { break; }
        }

        log::info!("RPZ: loaded {} rules from AXFR {} into zone '{}'", count, zone_name, name);
        self.add_zone(zone);
        Ok(count)
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    pub fn get_stats(&self) -> RpzStats {
        self.stats.read().clone()
    }

    pub fn reset_stats(&self) {
        let mut stats = self.stats.write();
        let total_rules = stats.total_rules;
        let zone_count = stats.zone_count;
        *stats = RpzStats::default();
        stats.total_rules = total_rules;
        stats.zone_count = zone_count;
    }
}

/// Signal that the query should be silently dropped (no response).
#[derive(Debug)]
pub struct RpzDropSignal;

/// Zone info returned by list_zones.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpzZoneInfo {
    pub name: String,
    pub priority: u32,
    pub enabled: bool,
    pub rule_count: usize,
    pub serial: u32,
    pub source: String,
}

// ─── Backward compatibility aliases ──────────────────────────────────────────

/// Alias for backward compatibility with existing code that uses `PolicyAction`.
pub type PolicyAction = RpzAction;
/// Alias for backward compatibility.
pub type PolicyEntry = RpzRule;
/// Alias for backward compatibility.
pub type RpzConfig = ();

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::protocol::DnsQuestion;

    fn make_query(name: &str) -> DnsPacket {
        let mut pkt = DnsPacket::new();
        pkt.questions.push(DnsQuestion { name: name.to_string(), qtype: QueryType::A });
        pkt
    }

    #[test]
    fn test_qname_exact_match() {
        let engine = RpzEngine::new();
        let mut zone = RpzZone::new("test".into(), 100, RpzZoneSource::Inline);
        zone.add_rule(RpzRule {
            trigger_value: "malware.example.com".into(),
            trigger_type: RpzTriggerType::QName,
            action: RpzAction::NxDomain,
            redirect_to: None,
            category: ThreatCategory::Malware,
            description: None,
        });
        engine.add_zone(zone);

        let pkt = make_query("malware.example.com");
        let result = engine.evaluate(&pkt, None);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.is_some());
        assert_eq!(response.unwrap().header.rescode, ResultCode::NXDOMAIN);
    }

    #[test]
    fn test_qname_wildcard() {
        let engine = RpzEngine::new();
        let mut zone = RpzZone::new("test".into(), 100, RpzZoneSource::Inline);
        zone.add_rule(RpzRule {
            trigger_value: "*.bad.com".into(),
            trigger_type: RpzTriggerType::QName,
            action: RpzAction::NoData,
            redirect_to: None,
            category: ThreatCategory::Malware,
            description: None,
        });
        engine.add_zone(zone);

        let pkt = make_query("anything.bad.com");
        let result = engine.evaluate(&pkt, None).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().header.rescode, ResultCode::NOERROR);
    }

    #[test]
    fn test_client_ip_exact() {
        let engine = RpzEngine::new();
        let mut zone = RpzZone::new("test".into(), 100, RpzZoneSource::Inline);
        zone.add_rule(RpzRule {
            trigger_value: "192.168.1.100".into(),
            trigger_type: RpzTriggerType::ClientIp,
            action: RpzAction::NxDomain,
            redirect_to: None,
            category: ThreatCategory::Botnet,
            description: None,
        });
        engine.add_zone(zone);

        let pkt = make_query("example.com");
        let blocked_ip = "192.168.1.100".parse().unwrap();
        let allowed_ip = "10.0.0.1".parse().unwrap();

        assert!(engine.evaluate(&pkt, Some(blocked_ip)).unwrap().is_some());
        assert!(engine.evaluate(&pkt, Some(allowed_ip)).unwrap().is_none());
    }

    #[test]
    fn test_client_ip_cidr() {
        let engine = RpzEngine::new();
        let mut zone = RpzZone::new("test".into(), 100, RpzZoneSource::Inline);
        zone.add_rule(RpzRule {
            trigger_value: "10.0.0.0/8".into(),
            trigger_type: RpzTriggerType::ClientIp,
            action: RpzAction::Drop,
            redirect_to: None,
            category: ThreatCategory::Custom(1),
            description: None,
        });
        engine.add_zone(zone);

        let pkt = make_query("example.com");
        let result = engine.evaluate(&pkt, Some("10.5.3.2".parse().unwrap()));
        assert!(result.is_err()); // Drop signal
    }

    #[test]
    fn test_priority_precedence() {
        let engine = RpzEngine::new();

        // Lower priority zone blocks
        let mut low = RpzZone::new("low".into(), 10, RpzZoneSource::Inline);
        low.add_rule(RpzRule {
            trigger_value: "example.com".into(),
            trigger_type: RpzTriggerType::QName,
            action: RpzAction::NxDomain,
            redirect_to: None,
            category: ThreatCategory::Malware,
            description: None,
        });
        engine.add_zone(low);

        // Higher priority zone passes through
        let mut high = RpzZone::new("high".into(), 100, RpzZoneSource::Inline);
        high.add_rule(RpzRule {
            trigger_value: "example.com".into(),
            trigger_type: RpzTriggerType::QName,
            action: RpzAction::Passthru,
            redirect_to: None,
            category: ThreatCategory::Custom(0),
            description: None,
        });
        engine.add_zone(high);

        let pkt = make_query("example.com");
        // High-priority PASSTHRU should win
        let result = engine.evaluate(&pkt, None).unwrap();
        assert!(result.is_none()); // Passthru = no override
    }

    #[test]
    fn test_redirect_action() {
        let engine = RpzEngine::new();
        let mut zone = RpzZone::new("test".into(), 50, RpzZoneSource::Inline);
        zone.add_rule(RpzRule {
            trigger_value: "ads.example.com".into(),
            trigger_type: RpzTriggerType::QName,
            action: RpzAction::Redirect,
            redirect_to: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            category: ThreatCategory::Advertising,
            description: None,
        });
        engine.add_zone(zone);

        let pkt = make_query("ads.example.com");
        let result = engine.evaluate(&pkt, None).unwrap().unwrap();
        assert_eq!(result.header.rescode, ResultCode::NOERROR);
        assert_eq!(result.answers.len(), 1);
        if let DnsRecord::A { addr, .. } = &result.answers[0] {
            assert_eq!(*addr, Ipv4Addr::new(10, 0, 0, 1));
        } else {
            panic!("Expected A record");
        }
    }

    #[test]
    fn test_tcp_only_action() {
        let engine = RpzEngine::new();
        let mut zone = RpzZone::new("test".into(), 50, RpzZoneSource::Inline);
        zone.add_rule(RpzRule {
            trigger_value: "large.example.com".into(),
            trigger_type: RpzTriggerType::QName,
            action: RpzAction::TcpOnly,
            redirect_to: None,
            category: ThreatCategory::Custom(0),
            description: None,
        });
        engine.add_zone(zone);

        let pkt = make_query("large.example.com");
        let result = engine.evaluate(&pkt, None).unwrap().unwrap();
        assert!(result.header.truncated_message);
    }

    #[test]
    fn test_whitelist_overrides() {
        let engine = RpzEngine::new();
        let mut zone = RpzZone::new("test".into(), 100, RpzZoneSource::Inline);
        zone.add_rule(RpzRule {
            trigger_value: "safe.example.com".into(),
            trigger_type: RpzTriggerType::QName,
            action: RpzAction::NxDomain,
            redirect_to: None,
            category: ThreatCategory::Malware,
            description: None,
        });
        engine.add_zone(zone);
        engine.add_whitelist("safe.example.com");

        let pkt = make_query("safe.example.com");
        assert!(engine.evaluate(&pkt, None).unwrap().is_none());
    }

    #[test]
    fn test_remove_rule() {
        let engine = RpzEngine::new();
        let mut zone = RpzZone::new("test".into(), 100, RpzZoneSource::Inline);
        zone.add_rule(RpzRule {
            trigger_value: "temp.example.com".into(),
            trigger_type: RpzTriggerType::QName,
            action: RpzAction::NxDomain,
            redirect_to: None,
            category: ThreatCategory::Malware,
            description: None,
        });
        engine.add_zone(zone);

        let pkt = make_query("temp.example.com");
        assert!(engine.evaluate(&pkt, None).unwrap().is_some());

        engine.remove_rule_from_zone("test", "temp.example.com", RpzTriggerType::QName);
        assert!(engine.evaluate(&pkt, None).unwrap().is_none());
    }

    #[test]
    fn test_disabled_engine() {
        let engine = RpzEngine::new();
        let mut zone = RpzZone::new("test".into(), 100, RpzZoneSource::Inline);
        zone.add_rule(RpzRule {
            trigger_value: "blocked.com".into(),
            trigger_type: RpzTriggerType::QName,
            action: RpzAction::NxDomain,
            redirect_to: None,
            category: ThreatCategory::Malware,
            description: None,
        });
        engine.add_zone(zone);
        engine.set_enabled(false);

        let pkt = make_query("blocked.com");
        assert!(engine.evaluate(&pkt, None).unwrap().is_none());
    }

    #[test]
    fn test_zone_file_parsing() {
        let content = r#"
; RPZ zone file
$ORIGIN rpz.example.com.
malware.example.com CNAME .
ads.example.com CNAME *.
safe.example.com CNAME rpz-passthru.
redir.example.com A 10.0.0.1
drop.example.com CNAME rpz-drop.
tcp.example.com CNAME rpz-tcp-only.
"#;
        let mut zone = RpzZone::new("test".into(), 100, RpzZoneSource::Inline);
        let count = RpzEngine::parse_zone_content(&mut zone, content);
        assert_eq!(count, 6);
    }

    #[test]
    fn test_hosts_file_parsing() {
        let content = r#"
# Hosts file
0.0.0.0 malware1.com
127.0.0.1 malware2.com
tracking.com
0.0.0.0 localhost
"#;
        let mut zone = RpzZone::new("test".into(), 100, RpzZoneSource::Inline);
        let count = RpzEngine::parse_zone_content(&mut zone, content);
        assert_eq!(count, 3); // localhost is skipped
    }

    #[test]
    fn test_nsdname_trigger() {
        let engine = RpzEngine::new();
        let mut zone = RpzZone::new("test".into(), 100, RpzZoneSource::Inline);
        zone.add_rule(RpzRule {
            trigger_value: "evil-ns.example.com".into(),
            trigger_type: RpzTriggerType::NsDName,
            action: RpzAction::NxDomain,
            redirect_to: None,
            category: ThreatCategory::Botnet,
            description: None,
        });
        engine.add_zone(zone);

        let result = engine.evaluate_nsdname(
            &make_query("anything.com"),
            &["evil-ns.example.com".to_string()],
        );
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_ipnet_contains() {
        let net = IpNet::parse("192.168.1.0/24").unwrap();
        assert!(net.contains("192.168.1.50".parse().unwrap()));
        assert!(net.contains("192.168.1.255".parse().unwrap()));
        assert!(!net.contains("192.168.2.1".parse().unwrap()));
        assert!(!net.contains("10.0.0.1".parse().unwrap()));
    }
}
