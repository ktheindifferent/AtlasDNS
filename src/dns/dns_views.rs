//! DNS Views Implementation
//!
//! Conditional DNS responses based on client attributes with support for
//! multiple views, complex matching rules, and view-specific zones.
//!
//! # Features
//!
//! * **Multiple Views** - Unlimited named views with priority ordering
//! * **Client Matching** - IP, subnet, geographic, time-based, and custom rules
//! * **View-Specific Zones** - Different zone data per view
//! * **Recursive Views** - Views can inherit from other views
//! * **Dynamic Views** - Runtime view creation and modification
//! * **View Statistics** - Per-view query and match statistics
//! * **EDNS Client Subnet** - Honor ECS for accurate view selection

use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Local, Timelike, Datelike};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};

/// DNS Views configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsViewsConfig {
    /// Enable DNS views
    pub enabled: bool,
    /// Default view name
    pub default_view: String,
    /// Enable view caching
    pub cache_views: bool,
    /// Cache TTL
    pub cache_ttl: Duration,
    /// Enable EDNS Client Subnet
    pub edns_client_subnet: bool,
    /// Maximum views
    pub max_views: usize,
    /// Enable view statistics
    pub enable_stats: bool,
    /// View selection timeout
    pub selection_timeout: Duration,
}

impl Default for DnsViewsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_view: "default".to_string(),
            cache_views: true,
            cache_ttl: Duration::from_secs(300),
            edns_client_subnet: true,
            max_views: 100,
            enable_stats: true,
            selection_timeout: Duration::from_millis(100),
        }
    }
}

/// DNS View definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsView {
    /// View ID
    pub id: String,
    /// View name
    pub name: String,
    /// Description
    pub description: String,
    /// Priority (lower = higher priority)
    pub priority: u32,
    /// Match rules
    pub match_rules: Vec<MatchRule>,
    /// Parent view (for inheritance)
    pub parent: Option<String>,
    /// View-specific zones
    pub zones: HashMap<String, ViewZone>,
    /// Recursion settings
    pub recursion: RecursionSettings,
    /// Forwarding settings
    pub forwarding: Option<ForwardingSettings>,
    /// Access control
    pub access_control: AccessControl,
    /// Enabled flag
    pub enabled: bool,
    /// Tags
    pub tags: HashMap<String, String>,
}

/// Match rule for view selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchRule {
    /// Rule type
    pub rule_type: MatchRuleType,
    /// Rule operator
    pub operator: MatchOperator,
    /// Rule parameters
    pub parameters: HashMap<String, String>,
    /// Negate rule
    pub negate: bool,
}

/// Match rule type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MatchRuleType {
    /// Match by source IP
    SourceIp,
    /// Match by destination IP
    DestinationIp,
    /// Match by source network
    SourceNetwork,
    /// Match by geographic location
    Geographic,
    /// Match by time of day
    TimeOfDay,
    /// Match by day of week
    DayOfWeek,
    /// Match by query type
    QueryType,
    /// Match by query name pattern
    QueryName,
    /// Match by EDNS Client Subnet
    ClientSubnet,
    /// Match by transport protocol
    Transport,
    /// Match by TSIG key
    TsigKey,
    /// Custom match function
    Custom,
}

/// Match operator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchOperator {
    Equals,
    NotEquals,
    Contains,
    NotContains,
    GreaterThan,
    LessThan,
    InRange,
    NotInRange,
    Matches,
    NotMatches,
}

/// View-specific zone configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewZone {
    /// Zone name
    pub name: String,
    /// Zone type
    pub zone_type: ViewZoneType,
    /// Zone data source
    pub source: ZoneSource,
    /// Override TTL
    pub ttl_override: Option<u32>,
    /// Transform rules
    pub transforms: Vec<ZoneTransform>,
}

/// View zone type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViewZoneType {
    Primary,
    Secondary,
    Forward,
    Stub,
    Static,
    Redirect,
}

/// Zone data source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZoneSource {
    /// Load from file
    File(String),
    /// Load from database
    Database(String),
    /// In-memory zone data
    Memory(Vec<ZoneRecord>),
    /// Delegate to another view
    Delegate(String),
    /// Dynamic generation
    Dynamic,
}

/// Zone record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneRecord {
    pub name: String,
    pub record_type: String,
    pub ttl: u32,
    pub value: String,
}

/// Zone transform rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneTransform {
    /// Transform type
    pub transform_type: TransformType,
    /// Transform parameters
    pub parameters: HashMap<String, String>,
}

/// Transform type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransformType {
    /// Replace IP addresses
    ReplaceIp,
    /// Add prefix to names
    AddPrefix,
    /// Remove suffix from names
    RemoveSuffix,
    /// Modify TTL
    ModifyTtl,
    /// Filter records
    FilterRecords,
    /// Custom transform
    Custom,
}

/// Recursion settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecursionSettings {
    /// Enable recursion
    pub enabled: bool,
    /// Maximum recursion depth
    pub max_depth: u32,
    /// Recursion timeout
    pub timeout: Duration,
    /// Allowed networks for recursion
    pub allowed_networks: Vec<IpNetwork>,
}

/// Forwarding settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardingSettings {
    /// Forwarding servers
    pub servers: Vec<String>,
    /// Forward only (no recursion)
    pub forward_only: bool,
    /// Forward timeout
    pub timeout: Duration,
}

/// Access control settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControl {
    /// Allow queries from
    pub allow_query: Vec<IpNetwork>,
    /// Allow recursion from
    pub allow_recursion: Vec<IpNetwork>,
    /// Allow zone transfer from
    pub allow_transfer: Vec<IpNetwork>,
    /// Deny queries from
    pub deny_query: Vec<IpNetwork>,
    /// Rate limit per client
    pub rate_limit: Option<u32>,
}

/// View selection result
#[derive(Debug, Clone)]
pub struct ViewSelection {
    /// Selected view
    pub view: Arc<DnsView>,
    /// Match score
    pub score: f64,
    /// Matched rules
    pub matched_rules: Vec<String>,
    /// Selection time
    pub selection_time: Duration,
    /// Cache hit
    pub cache_hit: bool,
}

/// View statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ViewStats {
    /// Total queries
    pub total_queries: u64,
    /// Queries per view
    pub queries_by_view: HashMap<String, u64>,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// Average selection time (microseconds)
    pub avg_selection_time_us: f64,
    /// Rule match counts
    pub rule_matches: HashMap<String, u64>,
}

/// View cache entry
#[derive(Debug, Clone)]
struct ViewCacheEntry {
    /// Selected view ID
    view_id: String,
    /// Cached at
    cached_at: Instant,
}

/// DNS Views handler
pub struct DnsViewsHandler {
    /// Configuration
    config: Arc<RwLock<DnsViewsConfig>>,
    /// Views
    views: Arc<RwLock<HashMap<String, Arc<DnsView>>>>,
    /// View cache
    view_cache: Arc<RwLock<HashMap<String, ViewCacheEntry>>>,
    /// Statistics
    stats: Arc<RwLock<ViewStats>>,
    /// View index by priority
    priority_index: Arc<RwLock<Vec<String>>>,
}

impl DnsViewsHandler {
    /// Create new DNS views handler
    pub fn new(config: DnsViewsConfig) -> Self {
        let handler = Self {
            config: Arc::new(RwLock::new(config)),
            views: Arc::new(RwLock::new(HashMap::new())),
            view_cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ViewStats::default())),
            priority_index: Arc::new(RwLock::new(Vec::new())),
        };
        
        // Create default view
        handler.create_default_view();
        
        handler
    }

    /// Create default view
    fn create_default_view(&self) {
        let default_view = DnsView {
            id: "default".to_string(),
            name: "Default View".to_string(),
            description: "Default view for all clients".to_string(),
            priority: 9999,
            match_rules: vec![
                MatchRule {
                    rule_type: MatchRuleType::SourceNetwork,
                    operator: MatchOperator::InRange,
                    parameters: [
                        ("network".to_string(), "0.0.0.0/0".to_string()),
                    ].iter().cloned().collect(),
                    negate: false,
                },
            ],
            parent: None,
            zones: HashMap::new(),
            recursion: RecursionSettings {
                enabled: true,
                max_depth: 10,
                timeout: Duration::from_secs(5),
                allowed_networks: vec![
                    "0.0.0.0/0".parse().unwrap(),
                    "::/0".parse().unwrap(),
                ],
            },
            forwarding: None,
            access_control: AccessControl {
                allow_query: vec!["0.0.0.0/0".parse().unwrap()],
                allow_recursion: vec!["0.0.0.0/0".parse().unwrap()],
                allow_transfer: vec![],
                deny_query: vec![],
                rate_limit: Some(1000),
            },
            enabled: true,
            tags: HashMap::new(),
        };
        
        self.add_view(default_view);
    }

    /// Add view
    pub fn add_view(&self, view: DnsView) -> Result<(), String> {
        let config = self.config.read();
        
        // Check maximum views
        if self.views.read().len() >= config.max_views {
            return Err(format!("Maximum views ({}) reached", config.max_views));
        }
        
        // Validate view
        self.validate_view(&view)?;
        
        // Add to views
        let view_id = view.id.clone();
        let view_arc = Arc::new(view);
        self.views.write().insert(view_id.clone(), view_arc);
        
        // Update priority index
        self.update_priority_index();
        
        Ok(())
    }

    /// Remove view
    pub fn remove_view(&self, view_id: &str) -> Result<(), String> {
        if view_id == "default" {
            return Err("Cannot remove default view".to_string());
        }
        
        self.views.write().remove(view_id);
        self.update_priority_index();
        
        // Clear cache entries for this view
        self.view_cache.write().retain(|_, entry| entry.view_id != view_id);
        
        Ok(())
    }

    /// Update view
    pub fn update_view(&self, view: DnsView) -> Result<(), String> {
        self.validate_view(&view)?;
        
        let view_id = view.id.clone();
        let view_arc = Arc::new(view);
        self.views.write().insert(view_id.clone(), view_arc);
        
        self.update_priority_index();
        
        // Clear cache for this view
        self.view_cache.write().retain(|_, entry| entry.view_id != view_id);
        
        Ok(())
    }

    /// Select view for client
    pub fn select_view(
        &self,
        client_ip: IpAddr,
        query_name: &str,
        query_type: &str,
        metadata: HashMap<String, String>,
    ) -> ViewSelection {
        let start = Instant::now();
        let config = self.config.read();
        
        if !config.enabled {
            return self.get_default_view_selection();
        }
        
        // Update statistics
        if config.enable_stats {
            self.stats.write().total_queries += 1;
        }
        
        // Check cache
        let cache_key = format!("{}:{}:{}", client_ip, query_name, query_type);
        if config.cache_views {
            if let Some(cached) = self.get_cached_view(&cache_key) {
                if config.enable_stats {
                    self.stats.write().cache_hits += 1;
                }
                return cached;
            }
        }
        
        if config.enable_stats {
            self.stats.write().cache_misses += 1;
        }
        
        // Evaluate views in priority order
        let priority_index = self.priority_index.read();
        let views = self.views.read();
        
        let mut best_match: Option<(Arc<DnsView>, f64, Vec<String>)> = None;
        
        for view_id in priority_index.iter() {
            if let Some(view) = views.get(view_id) {
                if !view.enabled {
                    continue;
                }
                
                let (matches, score, matched_rules) = self.evaluate_view(
                    view,
                    client_ip,
                    query_name,
                    query_type,
                    &metadata,
                );
                
                if matches {
                    // Update rule match statistics
                    if config.enable_stats {
                        for rule in &matched_rules {
                            *self.stats.write().rule_matches.entry(rule.clone()).or_insert(0) += 1;
                        }
                    }
                    
                    if best_match.is_none() || score > best_match.as_ref().unwrap().1 {
                        best_match = Some((view.clone(), score, matched_rules));
                    }
                    
                    // If we have a perfect match (score >= 1.0), use it
                    if score >= 1.0 {
                        break;
                    }
                }
            }
        }
        
        // Use best match or default
        let (selected_view, score, matched_rules) = best_match
            .unwrap_or_else(|| {
                let default_view = views.get(&config.default_view)
                    .cloned()
                    .unwrap_or_else(|| views.values().next().unwrap().clone());
                (default_view, 0.0, vec![])
            });
        
        // Cache the selection
        if config.cache_views {
            self.cache_view_selection(&cache_key, &selected_view.id);
        }
        
        // Update statistics
        let selection_time = start.elapsed();
        if config.enable_stats {
            let mut stats = self.stats.write();
            *stats.queries_by_view.entry(selected_view.id.clone()).or_insert(0) += 1;
            
            // Update average selection time
            let n = stats.total_queries;
            let new_time = selection_time.as_micros() as f64;
            stats.avg_selection_time_us = 
                ((stats.avg_selection_time_us * (n - 1) as f64) + new_time) / n as f64;
        }
        
        ViewSelection {
            view: selected_view,
            score,
            matched_rules,
            selection_time,
            cache_hit: false,
        }
    }

    /// Evaluate view against client attributes
    fn evaluate_view(
        &self,
        view: &DnsView,
        client_ip: IpAddr,
        query_name: &str,
        query_type: &str,
        metadata: &HashMap<String, String>,
    ) -> (bool, f64, Vec<String>) {
        let mut matched_rules = Vec::new();
        let mut total_score = 0.0;
        let mut rule_count = 0;
        
        for rule in &view.match_rules {
            let matches = self.evaluate_rule(rule, client_ip, query_name, query_type, metadata);
            
            if matches {
                matched_rules.push(format!("{:?}", rule.rule_type));
                total_score += 1.0;
            } else if !rule.negate {
                // If a non-negated rule doesn't match, view doesn't match
                return (false, 0.0, vec![]);
            }
            
            rule_count += 1;
        }
        
        let avg_score = if rule_count > 0 {
            total_score / rule_count as f64
        } else {
            0.0
        };
        
        (true, avg_score, matched_rules)
    }

    /// Evaluate single rule
    fn evaluate_rule(
        &self,
        rule: &MatchRule,
        client_ip: IpAddr,
        query_name: &str,
        query_type: &str,
        metadata: &HashMap<String, String>,
    ) -> bool {
        let result = match rule.rule_type {
            MatchRuleType::SourceIp => {
                self.match_source_ip(rule, client_ip)
            }
            MatchRuleType::SourceNetwork => {
                self.match_source_network(rule, client_ip)
            }
            MatchRuleType::Geographic => {
                self.match_geographic(rule, client_ip)
            }
            MatchRuleType::TimeOfDay => {
                self.match_time_of_day(rule)
            }
            MatchRuleType::DayOfWeek => {
                self.match_day_of_week(rule)
            }
            MatchRuleType::QueryType => {
                self.match_query_type(rule, query_type)
            }
            MatchRuleType::QueryName => {
                self.match_query_name(rule, query_name)
            }
            MatchRuleType::ClientSubnet => {
                self.match_client_subnet(rule, metadata)
            }
            MatchRuleType::Transport => {
                self.match_transport(rule, metadata)
            }
            MatchRuleType::TsigKey => {
                self.match_tsig_key(rule, metadata)
            }
            _ => false,
        };
        
        if rule.negate {
            !result
        } else {
            result
        }
    }

    /// Match source IP
    fn match_source_ip(&self, rule: &MatchRule, client_ip: IpAddr) -> bool {
        if let Some(ip_str) = rule.parameters.get("ip") {
            match rule.operator {
                MatchOperator::Equals => {
                    ip_str.parse::<IpAddr>().ok() == Some(client_ip)
                }
                MatchOperator::NotEquals => {
                    ip_str.parse::<IpAddr>().ok() != Some(client_ip)
                }
                _ => false,
            }
        } else {
            false
        }
    }

    /// Match source network
    fn match_source_network(&self, rule: &MatchRule, client_ip: IpAddr) -> bool {
        if let Some(network_str) = rule.parameters.get("network") {
            if let Ok(network) = network_str.parse::<IpNetwork>() {
                match rule.operator {
                    MatchOperator::InRange => network.contains(client_ip),
                    MatchOperator::NotInRange => !network.contains(client_ip),
                    _ => false,
                }
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Match geographic location
    fn match_geographic(&self, rule: &MatchRule, _client_ip: IpAddr) -> bool {
        // Would integrate with GeoIP database
        if let Some(country) = rule.parameters.get("country") {
            // Simplified - would lookup actual country
            match rule.operator {
                MatchOperator::Equals => country == "US",
                MatchOperator::NotEquals => country != "US",
                _ => false,
            }
        } else {
            false
        }
    }

    /// Match time of day
    fn match_time_of_day(&self, rule: &MatchRule) -> bool {
        let now = Local::now();
        let current_hour = now.hour();
        
        if let (Some(start_str), Some(end_str)) = 
            (rule.parameters.get("start"), rule.parameters.get("end")) {
            if let (Ok(start), Ok(end)) = (start_str.parse::<u32>(), end_str.parse::<u32>()) {
                match rule.operator {
                    MatchOperator::InRange => {
                        if start <= end {
                            current_hour >= start && current_hour <= end
                        } else {
                            // Wraps around midnight
                            current_hour >= start || current_hour <= end
                        }
                    }
                    MatchOperator::NotInRange => {
                        if start <= end {
                            current_hour < start || current_hour > end
                        } else {
                            current_hour < start && current_hour > end
                        }
                    }
                    _ => false,
                }
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Match day of week
    fn match_day_of_week(&self, rule: &MatchRule) -> bool {
        let now = Local::now();
        let current_day = now.weekday().num_days_from_monday(); // 0 = Monday
        
        if let Some(days_str) = rule.parameters.get("days") {
            let days: Vec<u32> = days_str.split(',')
                .filter_map(|d| d.trim().parse().ok())
                .collect();
            
            match rule.operator {
                MatchOperator::Contains => days.contains(&current_day),
                MatchOperator::NotContains => !days.contains(&current_day),
                _ => false,
            }
        } else {
            false
        }
    }

    /// Match query type
    fn match_query_type(&self, rule: &MatchRule, query_type: &str) -> bool {
        if let Some(types_str) = rule.parameters.get("types") {
            let types: Vec<&str> = types_str.split(',').map(|t| t.trim()).collect();
            
            match rule.operator {
                MatchOperator::Contains => types.contains(&query_type),
                MatchOperator::NotContains => !types.contains(&query_type),
                _ => false,
            }
        } else {
            false
        }
    }

    /// Match query name
    fn match_query_name(&self, rule: &MatchRule, query_name: &str) -> bool {
        if let Some(pattern) = rule.parameters.get("pattern") {
            match rule.operator {
                MatchOperator::Equals => query_name == pattern,
                MatchOperator::NotEquals => query_name != pattern,
                MatchOperator::Contains => query_name.contains(pattern),
                MatchOperator::NotContains => !query_name.contains(pattern),
                MatchOperator::Matches => {
                    // Would use regex matching
                    query_name.ends_with(pattern)
                }
                _ => false,
            }
        } else {
            false
        }
    }

    /// Match client subnet (EDNS)
    fn match_client_subnet(&self, rule: &MatchRule, metadata: &HashMap<String, String>) -> bool {
        if let Some(subnet_str) = metadata.get("client_subnet") {
            if let Some(expected) = rule.parameters.get("subnet") {
                match rule.operator {
                    MatchOperator::Equals => subnet_str == expected,
                    MatchOperator::NotEquals => subnet_str != expected,
                    _ => false,
                }
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Match transport protocol
    fn match_transport(&self, rule: &MatchRule, metadata: &HashMap<String, String>) -> bool {
        if let Some(transport) = metadata.get("transport") {
            if let Some(expected) = rule.parameters.get("protocol") {
                match rule.operator {
                    MatchOperator::Equals => transport == expected,
                    MatchOperator::NotEquals => transport != expected,
                    _ => false,
                }
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Match TSIG key
    fn match_tsig_key(&self, rule: &MatchRule, metadata: &HashMap<String, String>) -> bool {
        if let Some(tsig_key) = metadata.get("tsig_key") {
            if let Some(expected) = rule.parameters.get("key") {
                match rule.operator {
                    MatchOperator::Equals => tsig_key == expected,
                    MatchOperator::NotEquals => tsig_key != expected,
                    _ => false,
                }
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Get cached view
    fn get_cached_view(&self, cache_key: &str) -> Option<ViewSelection> {
        let cache = self.view_cache.read();
        let config = self.config.read();
        
        if let Some(entry) = cache.get(cache_key) {
            if entry.cached_at.elapsed() < config.cache_ttl {
                if let Some(view) = self.views.read().get(&entry.view_id) {
                    return Some(ViewSelection {
                        view: view.clone(),
                        score: 1.0,
                        matched_rules: vec!["cached".to_string()],
                        selection_time: Duration::from_micros(0),
                        cache_hit: true,
                    });
                }
            }
        }
        
        None
    }

    /// Cache view selection
    fn cache_view_selection(&self, cache_key: &str, view_id: &str) {
        let entry = ViewCacheEntry {
            view_id: view_id.to_string(),
            cached_at: Instant::now(),
        };
        
        self.view_cache.write().insert(cache_key.to_string(), entry);
        
        // Clean cache if too large
        if self.view_cache.read().len() > 10000 {
            self.clean_cache();
        }
    }

    /// Clean expired cache entries
    fn clean_cache(&self) {
        let config = self.config.read();
        let cache_ttl = config.cache_ttl;
        
        self.view_cache.write().retain(|_, entry| {
            entry.cached_at.elapsed() < cache_ttl
        });
    }

    /// Validate view
    fn validate_view(&self, view: &DnsView) -> Result<(), String> {
        // Check for duplicate view ID
        if view.id.is_empty() {
            return Err("View ID cannot be empty".to_string());
        }
        
        // Check for circular parent reference
        if let Some(parent) = &view.parent {
            if parent == &view.id {
                return Err("View cannot be its own parent".to_string());
            }
        }
        
        // Validate match rules
        for rule in &view.match_rules {
            self.validate_match_rule(rule)?;
        }
        
        Ok(())
    }

    /// Validate match rule
    fn validate_match_rule(&self, rule: &MatchRule) -> Result<(), String> {
        match rule.rule_type {
            MatchRuleType::SourceNetwork | MatchRuleType::ClientSubnet => {
                if let Some(network) = rule.parameters.get("network") {
                    network.parse::<IpNetwork>()
                        .map_err(|e| format!("Invalid network: {}", e))?;
                }
            }
            MatchRuleType::TimeOfDay => {
                if let (Some(start), Some(end)) = 
                    (rule.parameters.get("start"), rule.parameters.get("end")) {
                    let start_hour = start.parse::<u32>()
                        .map_err(|_| "Invalid start hour".to_string())?;
                    let end_hour = end.parse::<u32>()
                        .map_err(|_| "Invalid end hour".to_string())?;
                    
                    if start_hour > 23 || end_hour > 23 {
                        return Err("Hour must be 0-23".to_string());
                    }
                }
            }
            _ => {}
        }
        
        Ok(())
    }

    /// Update priority index
    fn update_priority_index(&self) {
        let views = self.views.read();
        let mut index: Vec<(String, u32)> = views.iter()
            .map(|(id, view)| (id.clone(), view.priority))
            .collect();
        
        // Sort by priority (lower value = higher priority)
        index.sort_by_key(|(_, priority)| *priority);
        
        let sorted_ids: Vec<String> = index.into_iter()
            .map(|(id, _)| id)
            .collect();
        
        *self.priority_index.write() = sorted_ids;
    }

    /// Get default view selection
    fn get_default_view_selection(&self) -> ViewSelection {
        let config = self.config.read();
        let views = self.views.read();
        
        let view = views.get(&config.default_view)
            .cloned()
            .unwrap_or_else(|| views.values().next().unwrap().clone());
        
        ViewSelection {
            view,
            score: 0.0,
            matched_rules: vec!["default".to_string()],
            selection_time: Duration::from_micros(0),
            cache_hit: false,
        }
    }

    /// Get view by ID
    pub fn get_view(&self, view_id: &str) -> Option<Arc<DnsView>> {
        self.views.read().get(view_id).cloned()
    }

    /// List all views
    pub fn list_views(&self) -> Vec<Arc<DnsView>> {
        self.views.read().values().cloned().collect()
    }

    /// Get statistics
    pub fn get_stats(&self) -> ViewStats {
        self.stats.read().clone()
    }

    /// Clear cache
    pub fn clear_cache(&self) {
        self.view_cache.write().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_view_creation() {
        let config = DnsViewsConfig::default();
        let handler = DnsViewsHandler::new(config);
        
        let view = DnsView {
            id: "internal".to_string(),
            name: "Internal View".to_string(),
            description: "View for internal clients".to_string(),
            priority: 10,
            match_rules: vec![
                MatchRule {
                    rule_type: MatchRuleType::SourceNetwork,
                    operator: MatchOperator::InRange,
                    parameters: [
                        ("network".to_string(), "192.168.0.0/16".to_string()),
                    ].iter().cloned().collect(),
                    negate: false,
                },
            ],
            parent: None,
            zones: HashMap::new(),
            recursion: RecursionSettings {
                enabled: true,
                max_depth: 10,
                timeout: Duration::from_secs(5),
                allowed_networks: vec!["192.168.0.0/16".parse().unwrap()],
            },
            forwarding: None,
            access_control: AccessControl {
                allow_query: vec!["192.168.0.0/16".parse().unwrap()],
                allow_recursion: vec!["192.168.0.0/16".parse().unwrap()],
                allow_transfer: vec![],
                deny_query: vec![],
                rate_limit: Some(1000),
            },
            enabled: true,
            tags: HashMap::new(),
        };
        
        assert!(handler.add_view(view).is_ok());
        assert_eq!(handler.list_views().len(), 2); // default + internal
    }

    #[test]
    fn test_view_selection() {
        let config = DnsViewsConfig::default();
        let handler = DnsViewsHandler::new(config);
        
        // Add internal view
        let internal_view = DnsView {
            id: "internal".to_string(),
            name: "Internal".to_string(),
            description: "Internal".to_string(),
            priority: 10,
            match_rules: vec![
                MatchRule {
                    rule_type: MatchRuleType::SourceNetwork,
                    operator: MatchOperator::InRange,
                    parameters: [
                        ("network".to_string(), "192.168.0.0/16".to_string()),
                    ].iter().cloned().collect(),
                    negate: false,
                },
            ],
            parent: None,
            zones: HashMap::new(),
            recursion: RecursionSettings {
                enabled: true,
                max_depth: 10,
                timeout: Duration::from_secs(5),
                allowed_networks: vec!["192.168.0.0/16".parse().unwrap()],
            },
            forwarding: None,
            access_control: AccessControl {
                allow_query: vec!["192.168.0.0/16".parse().unwrap()],
                allow_recursion: vec!["192.168.0.0/16".parse().unwrap()],
                allow_transfer: vec![],
                deny_query: vec![],
                rate_limit: Some(1000),
            },
            enabled: true,
            tags: HashMap::new(),
        };
        
        handler.add_view(internal_view).unwrap();
        
        // Test internal IP
        let selection = handler.select_view(
            IpAddr::from([192, 168, 1, 1]),
            "example.com",
            "A",
            HashMap::new(),
        );
        assert_eq!(selection.view.id, "internal");
        
        // Test external IP
        let selection = handler.select_view(
            IpAddr::from([8, 8, 8, 8]),
            "example.com",
            "A",
            HashMap::new(),
        );
        assert_eq!(selection.view.id, "default");
    }
}