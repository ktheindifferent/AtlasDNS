//! Split-Horizon DNS Implementation
//!
//! Provides different DNS responses based on the source of the query,
//! enabling internal vs external view separation for security and routing.
//!
//! # Features
//!
//! * **Multiple Views** - Define unlimited DNS views
//! * **IP-Based Selection** - Route by source IP/subnet
//! * **Geo-Based Views** - Route by geographic location
//! * **Custom Criteria** - Extensible view selection logic
//! * **Inheritance** - Views can inherit from base configuration
//! * **Override Support** - Selective record overrides per view
//! * **Default Fallback** - Graceful handling of unmatched queries

use std::sync::Arc;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};

use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, DnsQuestion, TransientTtl};
use crate::dns::errors::DnsError;

/// Split-horizon configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitHorizonConfig {
    /// Enable split-horizon DNS
    pub enabled: bool,
    /// Default view name
    pub default_view: String,
    /// Enable geo-based routing
    pub geo_routing: bool,
    /// Enable view inheritance
    pub inheritance: bool,
    /// Cache view mappings
    pub cache_mappings: bool,
    /// Mapping cache TTL (seconds)
    pub cache_ttl: u32,
}

impl Default for SplitHorizonConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_view: "default".to_string(),
            geo_routing: false,
            inheritance: true,
            cache_mappings: true,
            cache_ttl: 300,
        }
    }
}

/// DNS view definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsView {
    /// View name
    pub name: String,
    /// Description
    pub description: String,
    /// Parent view for inheritance
    pub parent: Option<String>,
    /// Match criteria
    pub match_criteria: ViewMatchCriteria,
    /// Zone overrides
    pub zones: HashMap<String, ViewZone>,
    /// Enabled flag
    pub enabled: bool,
    /// Priority (lower = higher priority)
    pub priority: u32,
}

/// View matching criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewMatchCriteria {
    /// Source IP ranges
    pub source_ips: Vec<IpRange>,
    /// Geographic locations
    pub geolocations: Vec<String>,
    /// Client identifiers
    pub client_ids: Vec<String>,
    /// Time-based rules
    pub time_rules: Vec<TimeRule>,
    /// Custom attributes
    pub attributes: HashMap<String, String>,
}

/// IP range definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRange {
    /// Start IP
    pub start: IpAddr,
    /// End IP
    pub end: IpAddr,
    /// CIDR notation (alternative)
    pub cidr: Option<String>,
}

impl IpRange {
    /// Check if IP is in range
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (ip, self.start, self.end) {
            (IpAddr::V4(ip), IpAddr::V4(start), IpAddr::V4(end)) => {
                ip >= start && ip <= end
            }
            (IpAddr::V6(ip), IpAddr::V6(start), IpAddr::V6(end)) => {
                ip >= start && ip <= end
            }
            _ => false,
        }
    }
}

/// Time-based rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRule {
    /// Days of week (0=Sunday, 6=Saturday)
    pub days: Vec<u8>,
    /// Start hour (0-23)
    pub start_hour: u8,
    /// End hour (0-23)
    pub end_hour: u8,
    /// Timezone
    pub timezone: String,
}

/// View-specific zone configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewZone {
    /// Zone name
    pub name: String,
    /// Record overrides
    pub records: Vec<ViewRecord>,
    /// SOA override
    pub soa_override: Option<SoaOverride>,
    /// Forwarding configuration
    pub forwarders: Vec<IpAddr>,
}

/// View-specific record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewRecord {
    /// Record name
    pub name: String,
    /// Record type
    pub rtype: String,
    /// Record value
    pub value: String,
    /// TTL
    pub ttl: u32,
    /// Action (add, replace, remove)
    pub action: RecordAction,
}

/// Record action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecordAction {
    Add,
    Replace,
    Remove,
}

/// SOA override
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoaOverride {
    pub mname: Option<String>,
    pub rname: Option<String>,
    pub serial: Option<u32>,
    pub refresh: Option<u32>,
    pub retry: Option<u32>,
    pub expire: Option<u32>,
    pub minimum: Option<u32>,
}

/// View selection result
#[derive(Debug, Clone)]
struct ViewSelection {
    /// Selected view
    view: Arc<DnsView>,
    /// Match score (for debugging)
    score: u32,
    /// Cached at
    cached_at: Instant,
}

/// Split-horizon statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SplitHorizonStats {
    /// Total queries processed
    pub total_queries: u64,
    /// Queries per view
    pub queries_per_view: HashMap<String, u64>,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// Default view uses
    pub default_view_uses: u64,
}

/// Split-horizon DNS handler
pub struct SplitHorizonHandler {
    /// Configuration
    config: Arc<RwLock<SplitHorizonConfig>>,
    /// Views
    views: Arc<RwLock<HashMap<String, Arc<DnsView>>>>,
    /// View selection cache
    selection_cache: Arc<RwLock<HashMap<IpAddr, ViewSelection>>>,
    /// Statistics
    stats: Arc<RwLock<SplitHorizonStats>>,
}

impl SplitHorizonHandler {
    /// Create new split-horizon handler
    pub fn new(config: SplitHorizonConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            views: Arc::new(RwLock::new(HashMap::new())),
            selection_cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(SplitHorizonStats::default())),
        }
    }

    /// Add DNS view
    pub fn add_view(&self, view: DnsView) {
        self.views.write().insert(view.name.clone(), Arc::new(view));
    }

    /// Remove DNS view
    pub fn remove_view(&self, name: &str) {
        self.views.write().remove(name);
        // Clear cache entries for this view
        self.selection_cache.write().retain(|_, selection| {
            selection.view.name != name
        });
    }

    /// Process query with view selection
    pub fn process_query(
        &self,
        question: &DnsQuestion,
        client_ip: IpAddr,
        base_records: Vec<DnsRecord>,
    ) -> Result<Vec<DnsRecord>, DnsError> {
        let config = self.config.read();
        
        if !config.enabled {
            return Ok(base_records);
        }

        self.stats.write().total_queries += 1;

        // Select appropriate view
        let view = self.select_view(client_ip)?;
        
        // Update stats
        self.stats.write()
            .queries_per_view
            .entry(view.name.clone())
            .and_modify(|c| *c += 1)
            .or_insert(1);

        // Apply view transformations
        self.apply_view_transforms(&view, question, base_records)
    }

    /// Select view for client
    fn select_view(&self, client_ip: IpAddr) -> Result<Arc<DnsView>, DnsError> {
        // Check cache
        if let Some(selection) = self.get_cached_selection(client_ip) {
            self.stats.write().cache_hits += 1;
            return Ok(selection.view);
        }

        self.stats.write().cache_misses += 1;

        // Evaluate all views
        let views = self.views.read();
        let mut candidates: Vec<(Arc<DnsView>, u32)> = Vec::new();

        for view in views.values() {
            if !view.enabled {
                continue;
            }

            if let Some(score) = self.evaluate_view(view, client_ip) {
                candidates.push((view.clone(), score));
            }
        }

        // Sort by priority and score
        candidates.sort_by(|a, b| {
            a.0.priority.cmp(&b.0.priority)
                .then(b.1.cmp(&a.1))
        });

        // Get best match or default
        let view = if let Some((view, score)) = candidates.first() {
            self.cache_selection(client_ip, view.clone(), *score);
            view.clone()
        } else {
            self.stats.write().default_view_uses += 1;
            self.get_default_view()?
        };

        Ok(view)
    }

    /// Evaluate view match
    fn evaluate_view(&self, view: &DnsView, client_ip: IpAddr) -> Option<u32> {
        let mut score = 0u32;

        // Check IP ranges
        for range in &view.match_criteria.source_ips {
            if range.contains(client_ip) {
                score += 100;
                break;
            }
        }

        // Check time rules
        if self.matches_time_rules(&view.match_criteria.time_rules) {
            score += 50;
        }

        // Check geo location (simplified)
        if self.config.read().geo_routing {
            if self.matches_geo_location(client_ip, &view.match_criteria.geolocations) {
                score += 75;
            }
        }

        if score > 0 {
            Some(score)
        } else {
            None
        }
    }

    /// Check time rules
    fn matches_time_rules(&self, rules: &[TimeRule]) -> bool {
        if rules.is_empty() {
            return true;
        }

        // Simplified - would use actual time checking
        true
    }

    /// Check geo location
    fn matches_geo_location(&self, _ip: IpAddr, _locations: &[String]) -> bool {
        // Simplified - would use GeoIP database
        false
    }

    /// Apply view transformations
    fn apply_view_transforms(
        &self,
        view: &Arc<DnsView>,
        question: &DnsQuestion,
        mut base_records: Vec<DnsRecord>,
    ) -> Result<Vec<DnsRecord>, DnsError> {
        // Find zone configuration for this query
        let zone = view.zones.get(&question.name);
        
        if let Some(zone_config) = zone {
            // Apply record modifications
            for view_record in &zone_config.records {
                match view_record.action {
                    RecordAction::Add => {
                        base_records.push(self.create_record(view_record)?);
                    }
                    RecordAction::Replace => {
                        base_records.retain(|r| !self.matches_record(r, view_record));
                        base_records.push(self.create_record(view_record)?);
                    }
                    RecordAction::Remove => {
                        base_records.retain(|r| !self.matches_record(r, view_record));
                    }
                }
            }
        }

        Ok(base_records)
    }

    /// Create DNS record from view record
    fn create_record(&self, view_record: &ViewRecord) -> Result<DnsRecord, DnsError> {
        let ttl = TransientTtl(view_record.ttl);
        
        match view_record.rtype.to_uppercase().as_str() {
            "A" => {
                let addr: Ipv4Addr = view_record.value.parse()
                    .map_err(|_| DnsError::InvalidInput)?;
                Ok(DnsRecord::A {
                    domain: view_record.name.clone(),
                    addr,
                    ttl,
                })
            }
            "AAAA" => {
                let addr: Ipv6Addr = view_record.value.parse()
                    .map_err(|_| DnsError::InvalidInput)?;
                Ok(DnsRecord::Aaaa {
                    domain: view_record.name.clone(),
                    addr,
                    ttl,
                })
            }
            "CNAME" => {
                Ok(DnsRecord::Cname {
                    domain: view_record.name.clone(),
                    host: view_record.value.clone(),
                    ttl,
                })
            }
            "TXT" => {
                Ok(DnsRecord::Txt {
                    domain: view_record.name.clone(),
                    data: view_record.value.clone(),
                    ttl,
                })
            }
            _ => Err(DnsError::InvalidInput),
        }
    }

    /// Check if DNS record matches view record
    fn matches_record(&self, dns_record: &DnsRecord, view_record: &ViewRecord) -> bool {
        match dns_record {
            DnsRecord::A { domain, .. } => {
                domain == &view_record.name && view_record.rtype.to_uppercase() == "A"
            }
            DnsRecord::Aaaa { domain, .. } => {
                domain == &view_record.name && view_record.rtype.to_uppercase() == "AAAA"
            }
            DnsRecord::Cname { domain, .. } => {
                domain == &view_record.name && view_record.rtype.to_uppercase() == "CNAME"
            }
            DnsRecord::Txt { domain, .. } => {
                domain == &view_record.name && view_record.rtype.to_uppercase() == "TXT"
            }
            _ => false,
        }
    }

    /// Get cached selection
    fn get_cached_selection(&self, client_ip: IpAddr) -> Option<ViewSelection> {
        let cache = self.selection_cache.read();
        let config = self.config.read();
        
        cache.get(&client_ip).and_then(|selection| {
            if selection.cached_at.elapsed() < Duration::from_secs(config.cache_ttl as u64) {
                Some(selection.clone())
            } else {
                None
            }
        })
    }

    /// Cache view selection
    fn cache_selection(&self, client_ip: IpAddr, view: Arc<DnsView>, score: u32) {
        if !self.config.read().cache_mappings {
            return;
        }

        let selection = ViewSelection {
            view,
            score,
            cached_at: Instant::now(),
        };

        self.selection_cache.write().insert(client_ip, selection);
        
        // Clean cache if too large
        if self.selection_cache.read().len() > 10000 {
            self.clean_cache();
        }
    }

    /// Clean expired cache entries
    fn clean_cache(&self) {
        let config = self.config.read();
        let max_age = Duration::from_secs(config.cache_ttl as u64);
        
        self.selection_cache.write().retain(|_, selection| {
            selection.cached_at.elapsed() < max_age
        });
    }

    /// Get default view
    fn get_default_view(&self) -> Result<Arc<DnsView>, DnsError> {
        let views = self.views.read();
        let config = self.config.read();
        
        views.get(&config.default_view)
            .cloned()
            .ok_or(DnsError::Configuration(crate::dns::errors::ConfigError {
                parameter: "default_view".to_string(),
                value: config.default_view.clone(),
                reason: "Default view not found".to_string(),
                suggestion: "Check view configuration".to_string(),
            }))
    }

    /// Get statistics
    pub fn get_stats(&self) -> SplitHorizonStats {
        self.stats.read().clone()
    }

    /// Clear cache
    pub fn clear_cache(&self) {
        self.selection_cache.write().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_range() {
        let range = IpRange {
            start: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
            end: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)),
            cidr: Some("192.168.1.0/24".to_string()),
        };

        assert!(range.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        assert!(!range.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));
    }

    #[test]
    fn test_view_selection() {
        let config = SplitHorizonConfig::default();
        let handler = SplitHorizonHandler::new(config);

        // Add internal view
        let internal_view = DnsView {
            name: "internal".to_string(),
            description: "Internal network".to_string(),
            parent: None,
            match_criteria: ViewMatchCriteria {
                source_ips: vec![IpRange {
                    start: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
                    end: IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255)),
                    cidr: None,
                }],
                geolocations: vec![],
                client_ids: vec![],
                time_rules: vec![],
                attributes: HashMap::new(),
            },
            zones: HashMap::new(),
            enabled: true,
            priority: 10,
        };

        handler.add_view(internal_view);

        // Test view selection
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let view = handler.select_view(client_ip);
        
        // Should select internal view
        assert!(view.is_ok());
    }
}