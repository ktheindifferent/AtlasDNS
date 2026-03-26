//! Threat Intelligence Feed Integration
//!
//! Integrates with free, public threat intelligence feeds to maintain a live
//! database of known-malicious and suspicious domains and IP blocks:
//!
//! | Feed | Source | Category |
//! |------|--------|----------|
//! | URLhaus hostfile | abuse.ch | Malware download / C2 |
//! | ThreatFox IOC hostfile | abuse.ch | Multi-category IOCs |
//! | Spamhaus DROP | spamhaus.org | Botnet C2 / spam IP blocks |
//! | Spamhaus EDROP | spamhaus.org | Extended IP block list |
//! | OpenPhish | openphish.com | Phishing |
//! | Phishing Army | phishing.army | Phishing |
//! | Disconnect.me malvertising | disconnect.me | Malvertising/tracking |
//!
//! Features:
//! - Per-domain reputation scores (0–100) and tags (malicious / suspicious / clean)
//! - IP-level blocking via Spamhaus DROP/EDROP CIDR lists (`check_ip()`)
//! - Incremental feed refresh on a configurable schedule
//! - Recent-hits log with optional webhook alerts
//! - `check_domain()` checks exact match AND parent domains

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use ipnetwork::IpNetwork;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

// ---------------------------------------------------------------------------
// ThreatCategory
// ---------------------------------------------------------------------------

/// Threat category assigned by a feed or manual tagging.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatCategory {
    MalwareC2,
    Phishing,
    Botnet,
    Spam,
    MalwareDownload,
    Malvertising,
    Unknown,
}

impl std::fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatCategory::MalwareC2 => write!(f, "malware_c2"),
            ThreatCategory::Phishing => write!(f, "phishing"),
            ThreatCategory::Botnet => write!(f, "botnet"),
            ThreatCategory::Spam => write!(f, "spam"),
            ThreatCategory::MalwareDownload => write!(f, "malware_download"),
            ThreatCategory::Malvertising => write!(f, "malvertising"),
            ThreatCategory::Unknown => write!(f, "unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// ReputationLevel
// ---------------------------------------------------------------------------

/// High-level reputation classification derived from the numeric score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReputationLevel {
    /// Score 0–29: known malicious, block immediately.
    Malicious,
    /// Score 30–69: suspicious, log and optionally block.
    Suspicious,
    /// Score 70–100: no known threat intel matches.
    Clean,
}

impl std::fmt::Display for ReputationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReputationLevel::Malicious => write!(f, "malicious"),
            ReputationLevel::Suspicious => write!(f, "suspicious"),
            ReputationLevel::Clean => write!(f, "clean"),
        }
    }
}

// ---------------------------------------------------------------------------
// DomainReputation
// ---------------------------------------------------------------------------

/// Full reputation record returned by `query_reputation()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainReputation {
    /// The queried domain (lowercased).
    pub domain: String,
    /// Reputation score 0 (worst) – 100 (best).
    pub score: u8,
    /// Qualitative classification.
    pub level: ReputationLevel,
    /// Number of distinct threat feeds that flagged this domain.
    pub feed_hits: usize,
    /// Threat categories found across all feeds.
    pub categories: Vec<ThreatCategory>,
    /// Feed source names that flagged this domain.
    pub sources: Vec<String>,
    /// Tags extracted from feed metadata.
    pub tags: Vec<String>,
    /// When this domain was first observed in any feed.
    pub first_seen: Option<DateTime<Utc>>,
    /// Whether this was a subdomain match (parent domain was flagged).
    pub is_parent_match: bool,
    /// If `is_parent_match`, the actual parent domain that matched.
    pub matched_domain: Option<String>,
}

// ---------------------------------------------------------------------------
// ThreatEntry (internal storage)
// ---------------------------------------------------------------------------

/// A known malicious domain from threat intelligence feeds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEntry {
    pub domain: String,
    pub category: ThreatCategory,
    /// Feed identifier (e.g. "urlhaus", "threatfox", "openphish").
    pub source: String,
    pub first_seen: DateTime<Utc>,
    pub tags: Vec<String>,
}

// ---------------------------------------------------------------------------
// ThreatIntelHit (hit log)
// ---------------------------------------------------------------------------

/// A threat intel hit log entry produced when `check_domain()` matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelHit {
    pub timestamp: DateTime<Utc>,
    pub domain: String,
    pub client_ip: String,
    pub category: ThreatCategory,
    pub source: String,
}

// ---------------------------------------------------------------------------
// FeedDescriptor
// ---------------------------------------------------------------------------

/// Descriptor for a single threat intelligence feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedDescriptor {
    /// Machine-readable identifier, e.g. `"urlhaus"`.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Download URL.
    pub url: String,
    /// Default category for domains from this feed.
    pub default_category: ThreatCategory,
    /// Number of domains loaded from this feed.
    pub domains_loaded: usize,
    /// Unix timestamp of the last successful fetch.
    pub last_updated: Option<u64>,
}

// ---------------------------------------------------------------------------
// BlockAction
// ---------------------------------------------------------------------------

/// Action to take when a threat intel match is found.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BlockAction {
    /// Return NXDOMAIN (default).
    Nxdomain,
    /// Return a synthesized A record pointing to this IP address.
    RedirectIp(String),
}

impl Default for BlockAction {
    fn default() -> Self {
        BlockAction::Nxdomain
    }
}

// ---------------------------------------------------------------------------
// CustomFeed
// ---------------------------------------------------------------------------

/// A user-supplied custom threat intelligence feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomFeed {
    /// Machine-readable identifier (must be unique, no spaces).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Download URL.
    pub url: String,
    /// Default threat category for entries from this feed.
    pub category: ThreatCategory,
}

// ---------------------------------------------------------------------------
// ThreatIntelConfig
// ---------------------------------------------------------------------------

/// Threat intelligence configuration.
#[derive(Debug, Clone)]
pub struct ThreatIntelConfig {
    /// Enable threat intelligence blocking.
    pub enabled: bool,
    /// Webhook URL for alerts (`None` = no webhook).
    pub webhook_url: Option<String>,
    /// How often to refresh all feeds (default: 3 600 s = 1 hour).
    pub update_interval: Duration,
    /// Maximum total domains to hold in memory.
    pub max_domains: usize,
    /// Block action: return NXDOMAIN or redirect to an IP.
    pub block_action: BlockAction,
    /// Feed IDs to disable (builtin feeds can be selectively turned off).
    pub disabled_feeds: Vec<String>,
    /// Additional user-supplied feeds.
    pub custom_feeds: Vec<CustomFeed>,
    /// Path for flat-file persistence cache (JSON). `None` = no disk cache.
    pub cache_path: Option<String>,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            webhook_url: None,
            update_interval: Duration::from_secs(3600),
            max_domains: 500_000,
            block_action: BlockAction::Nxdomain,
            disabled_feeds: vec![],
            custom_feeds: vec![],
            cache_path: None,
        }
    }
}

// ---------------------------------------------------------------------------
// IpBlockEntry (internal storage for CIDR-based feeds)
// ---------------------------------------------------------------------------

/// A CIDR block from a threat intelligence feed (e.g. Spamhaus DROP/EDROP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpBlockEntry {
    /// The CIDR network, stored as a string for serde compatibility.
    pub cidr: String,
    /// Feed identifier (e.g. "spamhaus_drop", "spamhaus_edrop").
    pub source: String,
    pub category: ThreatCategory,
    pub first_seen: DateTime<Utc>,
    /// Optional free-text description from the feed (e.g. SBL reference).
    pub description: String,
}

// ---------------------------------------------------------------------------
// Internal per-feed state
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FeedState {
    domains: HashMap<String, ThreatEntry>,
    /// CIDR blocks from IP-based feeds.
    ip_blocks: Vec<(IpNetwork, IpBlockEntry)>,
    last_updated: Option<Instant>,
    last_updated_ts: Option<u64>,
    domains_loaded: usize,
}

// ---------------------------------------------------------------------------
// ThreatIntelManager
// ---------------------------------------------------------------------------

/// Manages multiple threat intelligence feeds and a unified domain→entry lookup.
pub struct ThreatIntelManager {
    config: ThreatIntelConfig,
    /// domain → ThreatEntry (merged from all feeds).
    domains: Arc<RwLock<HashMap<String, ThreatEntry>>>,
    /// CIDR IP blocks from IP-based feeds (e.g. Spamhaus DROP/EDROP).
    ip_blocks: Arc<RwLock<Vec<(IpNetwork, IpBlockEntry)>>>,
    /// Per-feed state (keyed by feed id).
    feed_states: Arc<RwLock<HashMap<String, FeedState>>>,
    /// Recent hits log (capped at 10 000).
    hits: Arc<RwLock<Vec<ThreatIntelHit>>>,
}

impl ThreatIntelManager {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Create a new manager with the given configuration.
    pub fn new(config: ThreatIntelConfig) -> Self {
        let mut feed_states = HashMap::new();
        for feed in Self::builtin_feeds() {
            feed_states.insert(feed.id.clone(), FeedState::default());
        }
        for feed in &config.custom_feeds {
            feed_states.insert(feed.id.clone(), FeedState::default());
        }
        Self {
            config,
            domains: Arc::new(RwLock::new(HashMap::new())),
            ip_blocks: Arc::new(RwLock::new(Vec::new())),
            feed_states: Arc::new(RwLock::new(feed_states)),
            hits: Arc::new(RwLock::new(Vec::new())),
        }
    }

    // -----------------------------------------------------------------------
    // Built-in feed catalogue
    // -----------------------------------------------------------------------

    /// Return descriptors for all built-in feeds (stats populated lazily).
    pub fn builtin_feeds() -> Vec<FeedDescriptor> {
        vec![
            FeedDescriptor {
                id: "urlhaus".to_string(),
                name: "abuse.ch URLhaus – active malware hosting".to_string(),
                url: "https://urlhaus.abuse.ch/downloads/hostfile/".to_string(),
                default_category: ThreatCategory::MalwareDownload,
                domains_loaded: 0,
                last_updated: None,
            },
            FeedDescriptor {
                id: "threatfox".to_string(),
                name: "abuse.ch ThreatFox – multi-category IOC domains".to_string(),
                url: "https://threatfox.abuse.ch/downloads/hostfile/".to_string(),
                default_category: ThreatCategory::MalwareC2,
                domains_loaded: 0,
                last_updated: None,
            },
            FeedDescriptor {
                id: "spamhaus_drop".to_string(),
                name: "Spamhaus DROP – Don't Route Or Peer (IP CIDR blocks)".to_string(),
                url: "https://www.spamhaus.org/drop/drop.txt".to_string(),
                default_category: ThreatCategory::Spam,
                domains_loaded: 0,
                last_updated: None,
            },
            FeedDescriptor {
                id: "spamhaus_edrop".to_string(),
                name: "Spamhaus EDROP – Extended DROP list (IP CIDR blocks)".to_string(),
                url: "https://www.spamhaus.org/drop/edrop.txt".to_string(),
                default_category: ThreatCategory::Spam,
                domains_loaded: 0,
                last_updated: None,
            },
            FeedDescriptor {
                id: "openphish".to_string(),
                name: "OpenPhish – active phishing URLs".to_string(),
                url: "https://openphish.com/feed.txt".to_string(),
                default_category: ThreatCategory::Phishing,
                domains_loaded: 0,
                last_updated: None,
            },
            FeedDescriptor {
                id: "phishing_army".to_string(),
                name: "Phishing Army – extended phishing blocklist".to_string(),
                url: "https://phishing.army/download/phishing_army_blocklist_extended.txt".to_string(),
                default_category: ThreatCategory::Phishing,
                domains_loaded: 0,
                last_updated: None,
            },
            FeedDescriptor {
                id: "disconnect_malvertising".to_string(),
                name: "Disconnect.me – malvertising domains".to_string(),
                url: "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt".to_string(),
                default_category: ThreatCategory::Malvertising,
                domains_loaded: 0,
                last_updated: None,
            },
        ]
    }

    /// Returns true if the given feed ID carries CIDR IP blocks rather than domain names.
    fn is_ip_feed(feed_id: &str) -> bool {
        matches!(feed_id, "spamhaus_drop" | "spamhaus_edrop")
    }

    /// Return the list of active feeds (builtin minus disabled, plus custom).
    pub fn active_feeds(&self) -> Vec<FeedDescriptor> {
        let mut feeds: Vec<FeedDescriptor> = Self::builtin_feeds()
            .into_iter()
            .filter(|f| !self.config.disabled_feeds.contains(&f.id))
            .collect();
        for cf in &self.config.custom_feeds {
            feeds.push(FeedDescriptor {
                id: cf.id.clone(),
                name: cf.name.clone(),
                url: cf.url.clone(),
                default_category: cf.category.clone(),
                domains_loaded: 0,
                last_updated: None,
            });
        }
        feeds
    }

    /// Return feed descriptors enriched with live stats from `feed_states`.
    pub fn list_feeds(&self) -> Vec<FeedDescriptor> {
        let states = self.feed_states.read();
        self.active_feeds()
            .into_iter()
            .map(|mut f| {
                if let Some(state) = states.get(&f.id) {
                    f.domains_loaded = state.domains_loaded;
                    f.last_updated = state.last_updated_ts;
                }
                f
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // Domain reputation
    // -----------------------------------------------------------------------

    /// Query the full reputation record for a domain.
    ///
    /// Checks exact match first, then walks up the parent labels.
    pub fn query_reputation(&self, domain: &str) -> DomainReputation {
        let lower = domain.trim_end_matches('.').to_lowercase();
        let domains = self.domains.read();

        // Exact match
        if let Some(entry) = domains.get(&lower) {
            return Self::build_reputation(&lower, entry, false, None);
        }

        // Parent-domain match
        let parts: Vec<&str> = lower.split('.').collect();
        for i in 1..parts.len().saturating_sub(1) {
            let parent = parts[i..].join(".");
            if let Some(entry) = domains.get(&parent) {
                return Self::build_reputation(&lower, entry, true, Some(parent));
            }
        }

        // Clean
        DomainReputation {
            domain: lower,
            score: 100,
            level: ReputationLevel::Clean,
            feed_hits: 0,
            categories: vec![],
            sources: vec![],
            tags: vec![],
            first_seen: None,
            is_parent_match: false,
            matched_domain: None,
        }
    }

    fn build_reputation(
        queried: &str,
        entry: &ThreatEntry,
        is_parent: bool,
        matched: Option<String>,
    ) -> DomainReputation {
        // Score: malware C2 / phishing / botnet → 5; other malware → 15; spam/malvertising → 40
        let score = match &entry.category {
            ThreatCategory::MalwareC2 | ThreatCategory::Phishing | ThreatCategory::Botnet => 5,
            ThreatCategory::MalwareDownload => 15,
            ThreatCategory::Spam | ThreatCategory::Malvertising => 40,
            ThreatCategory::Unknown => 50,
        };
        // Bump score slightly if it's a parent (subdomain of a known-bad domain)
        let score = if is_parent { score + 10 } else { score } as u8;
        let level = if score < 30 {
            ReputationLevel::Malicious
        } else if score < 70 {
            ReputationLevel::Suspicious
        } else {
            ReputationLevel::Clean
        };

        DomainReputation {
            domain: queried.to_string(),
            score,
            level,
            feed_hits: 1,
            categories: vec![entry.category.clone()],
            sources: vec![entry.source.clone()],
            tags: entry.tags.clone(),
            first_seen: Some(entry.first_seen),
            is_parent_match: is_parent,
            matched_domain: matched,
        }
    }

    // -----------------------------------------------------------------------
    // check_domain (simple boolean check used by the DNS resolver)
    // -----------------------------------------------------------------------

    /// Return the matching `ThreatEntry` if the domain (or a parent) is known-bad.
    pub fn check_domain(&self, domain: &str) -> Option<ThreatEntry> {
        if !self.config.enabled {
            return None;
        }
        let rep = self.query_reputation(domain);
        if rep.level == ReputationLevel::Clean {
            return None;
        }
        // Re-fetch the underlying entry for caller convenience
        let domains = self.domains.read();
        let lower = domain.trim_end_matches('.').to_lowercase();
        if let Some(e) = domains.get(&lower) {
            return Some(e.clone());
        }
        let parts: Vec<&str> = lower.split('.').collect();
        for i in 1..parts.len().saturating_sub(1) {
            let parent = parts[i..].join(".");
            if let Some(e) = domains.get(&parent) {
                return Some(e.clone());
            }
        }
        None
    }

    /// Return the matching `IpBlockEntry` if the IP falls within any blocked CIDR.
    pub fn check_ip(&self, ip: IpAddr) -> Option<IpBlockEntry> {
        if !self.config.enabled {
            return None;
        }
        let blocks = self.ip_blocks.read();
        for (network, entry) in blocks.iter() {
            if network.contains(ip) {
                return Some(entry.clone());
            }
        }
        None
    }

    /// Total number of CIDR IP blocks currently loaded.
    pub fn total_ip_blocks(&self) -> usize {
        self.ip_blocks.read().len()
    }

    // -----------------------------------------------------------------------
    // Hit logging
    // -----------------------------------------------------------------------

    /// Record a threat intel hit and optionally fire a webhook.
    pub fn record_hit(&self, domain: &str, client_ip: &str, entry: &ThreatEntry) {
        let hit = ThreatIntelHit {
            timestamp: Utc::now(),
            domain: domain.to_string(),
            client_ip: client_ip.to_string(),
            category: entry.category.clone(),
            source: entry.source.clone(),
        };

        log::warn!(
            "[THREAT-INTEL] Blocked query: domain={} client={} category={} source={}",
            domain, client_ip, entry.category, entry.source
        );

        {
            let mut hits = self.hits.write();
            hits.push(hit.clone());
            if hits.len() > 10_000 {
                let drain = hits.len() - 10_000;
                hits.drain(0..drain);
            }
        }

        if let Some(webhook_url) = &self.config.webhook_url {
            let url = webhook_url.clone();
            let hit_clone = hit;
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                if let Ok(rt) = rt {
                    rt.block_on(async move {
                        let _ = Self::send_webhook_alert(&url, &hit_clone).await;
                    });
                }
            });
        }
    }

    async fn send_webhook_alert(
        url: &str,
        hit: &ThreatIntelHit,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        let payload = serde_json::json!({
            "event": "threat_intel_hit",
            "timestamp": hit.timestamp.to_rfc3339(),
            "domain": hit.domain,
            "client_ip": hit.client_ip,
            "category": hit.category.to_string(),
            "source": hit.source,
        });
        let resp = client
            .post(url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;
        if !resp.status().is_success() {
            log::warn!("[THREAT-INTEL] Webhook returned {}", resp.status());
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Feed refresh
    // -----------------------------------------------------------------------

    /// Refresh all feeds, skipping any that were updated more recently than
    /// `min_age`.  Returns a map of `feed_id → Result<count>`.
    pub async fn refresh_all(&self) -> HashMap<String, Result<usize, String>> {
        let mut results = HashMap::new();
        for feed in self.active_feeds() {
            let res = self.refresh_feed_descriptor(&feed).await;
            results.insert(feed.id, res);
        }
        results
    }

    /// Refresh a single feed by ID (looks in both builtin and custom feeds).
    pub async fn refresh_feed(&self, feed_id: &str) -> Result<usize, String> {
        // Find in active feeds
        let feed = self.active_feeds()
            .into_iter()
            .find(|f| f.id == feed_id)
            .ok_or_else(|| format!("Unknown feed: {}", feed_id))?;
        self.refresh_feed_descriptor(&feed).await
    }

    /// Refresh using a pre-resolved feed descriptor (used by refresh_all).
    async fn refresh_feed_descriptor(&self, feed: &FeedDescriptor) -> Result<usize, String> {
        log::info!("[THREAT-INTEL] Fetching feed '{}' from {}", feed.id, feed.url);

        let text = Self::fetch_url(&feed.url).await?;

        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let count = if Self::is_ip_feed(&feed.id) {
            let new_blocks = self.parse_cidr_feed(feed, &text);
            let count = new_blocks.len();
            {
                let mut ip_blocks = self.ip_blocks.write();
                ip_blocks.retain(|(_, e)| e.source != feed.id);
                ip_blocks.extend(new_blocks.clone());
            }
            {
                let mut states = self.feed_states.write();
                let state = states.entry(feed.id.clone()).or_default();
                state.ip_blocks = new_blocks;
                state.last_updated = Some(Instant::now());
                state.last_updated_ts = Some(now_ts);
                state.domains_loaded = count;
            }
            log::info!("[THREAT-INTEL] Feed '{}' refreshed: {} CIDR blocks", feed.id, count);
            count
        } else {
            let new_entries = self.parse_feed_text(feed, &text);
            let count = new_entries.len();
            {
                let mut domains = self.domains.write();
                domains.retain(|_, e| e.source != feed.id);
                for (domain, entry) in &new_entries {
                    if domains.len() >= self.config.max_domains {
                        break;
                    }
                    domains.insert(domain.clone(), entry.clone());
                }
            }
            {
                let mut states = self.feed_states.write();
                let state = states.entry(feed.id.clone()).or_default();
                state.domains = new_entries;
                state.last_updated = Some(Instant::now());
                state.last_updated_ts = Some(now_ts);
                state.domains_loaded = count;
            }
            log::info!("[THREAT-INTEL] Feed '{}' refreshed: {} domains", feed.id, count);
            count
        };

        // Persist to flat-file cache
        if let Some(ref path) = self.config.cache_path {
            self.save_cache(path);
        }

        Ok(count)
    }

    // -----------------------------------------------------------------------
    // Feed text parsing (multi-format)
    // -----------------------------------------------------------------------

    fn parse_feed_text(
        &self,
        feed: &FeedDescriptor,
        text: &str,
    ) -> HashMap<String, ThreatEntry> {
        let mut map = HashMap::new();
        let now = Utc::now();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            let domain_raw: &str = if line.starts_with("0.0.0.0 ") || line.starts_with("127.0.0.1 ") {
                // Hosts file format: "0.0.0.0 evil.com"
                match line.split_whitespace().nth(1) {
                    Some(d) => d,
                    None => continue,
                }
            } else if line.starts_with("||") {
                // ABP format: ||evil.com^
                let inner = line.trim_start_matches("||");
                inner.split('^').next().unwrap_or(inner).split('/').next().unwrap_or(inner)
            } else if line.starts_with("http://") || line.starts_with("https://") {
                // Plain URL – extract domain
                let stripped = line
                    .trim_start_matches("https://")
                    .trim_start_matches("http://");
                stripped.split('/').next().unwrap_or("").split(':').next().unwrap_or("")
            } else if line.contains(' ') || line.contains('\t') {
                // Space-separated, take first token if it looks like a domain
                match line.split_whitespace().next() {
                    Some(d) if d.contains('.') => d,
                    _ => continue,
                }
            } else {
                // Plain domain
                line
            };

            let domain = domain_raw.trim_end_matches('.').to_lowercase();
            if domain.is_empty() || !is_valid_domain(&domain) {
                continue;
            }

            // Deduplicate: keep the entry that was inserted first (earliest first_seen)
            map.entry(domain.clone()).or_insert_with(|| ThreatEntry {
                domain,
                category: feed.default_category.clone(),
                source: feed.id.clone(),
                first_seen: now,
                tags: vec![],
            });

            if map.len() >= self.config.max_domains {
                break;
            }
        }

        map
    }

    // -----------------------------------------------------------------------
    // CIDR feed parsing (Spamhaus DROP / EDROP format)
    // -----------------------------------------------------------------------

    /// Parse a Spamhaus-style CIDR feed.
    ///
    /// Format (each line):
    /// ```text
    /// ; comment
    /// 1.10.16.0/20 ; SBL123456
    /// ```
    fn parse_cidr_feed(
        &self,
        feed: &FeedDescriptor,
        text: &str,
    ) -> Vec<(IpNetwork, IpBlockEntry)> {
        let mut blocks = Vec::new();
        let now = Utc::now();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }

            // Strip inline comment
            let parts: Vec<&str> = line.splitn(2, ';').collect();
            let cidr_str = parts[0].trim();
            let description = parts.get(1).map(|s| s.trim()).unwrap_or("").to_string();

            match cidr_str.parse::<IpNetwork>() {
                Ok(network) => {
                    let entry = IpBlockEntry {
                        cidr: cidr_str.to_string(),
                        source: feed.id.clone(),
                        category: feed.default_category.clone(),
                        first_seen: now,
                        description,
                    };
                    blocks.push((network, entry));
                }
                Err(_) => {
                    log::debug!("[THREAT-INTEL] Skipping invalid CIDR '{}' in feed '{}'", cidr_str, feed.id);
                }
            }

            if blocks.len() >= self.config.max_domains {
                break;
            }
        }

        blocks
    }

    // -----------------------------------------------------------------------
    // HTTP fetch
    // -----------------------------------------------------------------------

    async fn fetch_url(url: &str) -> Result<String, String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent("AtlasDNS/1.0 (threat-intel)")
            .build()
            .map_err(|e| format!("HTTP client build error: {}", e))?;

        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("HTTP GET {}: {}", url, e))?;

        if !resp.status().is_success() {
            return Err(format!("HTTP {} for {}", resp.status(), url));
        }

        resp.text()
            .await
            .map_err(|e| format!("Failed to read response body: {}", e))
    }

    // -----------------------------------------------------------------------
    // Flat-file cache (JSON persistence)
    // -----------------------------------------------------------------------

    /// Serialize and save the current domain + IP block data to a JSON file.
    fn save_cache(&self, path: &str) {
        let domains = self.domains.read();
        let ip_blocks = self.ip_blocks.read();
        let ip_blocks_serializable: Vec<&IpBlockEntry> = ip_blocks.iter().map(|(_, e)| e).collect();
        let payload = serde_json::json!({
            "saved_at": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            "domains": domains.values().collect::<Vec<_>>(),
            "ip_blocks": ip_blocks_serializable,
        });
        match serde_json::to_string(&payload) {
            Ok(text) => {
                if let Err(e) = std::fs::write(path, text) {
                    log::warn!("[THREAT-INTEL] Failed to write cache to {}: {}", path, e);
                } else {
                    log::debug!("[THREAT-INTEL] Cache written to {}", path);
                }
            }
            Err(e) => log::warn!("[THREAT-INTEL] Cache serialization failed: {}", e),
        }
    }

    /// Load the flat-file cache if it exists and is not older than `max_age`.
    /// Returns `true` if data was loaded successfully.
    pub fn load_cache(&self, path: &str, max_age: std::time::Duration) -> bool {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(_) => return false, // No cache file
        };
        let value: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("[THREAT-INTEL] Cache parse error: {}", e);
                return false;
            }
        };

        let saved_at = value["saved_at"].as_u64().unwrap_or(0);
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now_secs.saturating_sub(saved_at) > max_age.as_secs() {
            log::info!("[THREAT-INTEL] Cache at {} is expired, will fetch fresh.", path);
            return false;
        }

        let mut loaded_domains = 0usize;
        if let Some(arr) = value["domains"].as_array() {
            let mut domains = self.domains.write();
            for item in arr {
                if let Ok(entry) = serde_json::from_value::<ThreatEntry>(item.clone()) {
                    domains.insert(entry.domain.clone(), entry);
                    loaded_domains += 1;
                }
            }
        }

        let mut loaded_blocks = 0usize;
        if let Some(arr) = value["ip_blocks"].as_array() {
            let mut ip_blocks = self.ip_blocks.write();
            for item in arr {
                if let Ok(entry) = serde_json::from_value::<IpBlockEntry>(item.clone()) {
                    if let Ok(network) = entry.cidr.parse::<IpNetwork>() {
                        ip_blocks.push((network, entry));
                        loaded_blocks += 1;
                    }
                }
            }
        }

        log::info!(
            "[THREAT-INTEL] Loaded {} domains + {} IP blocks from cache {}",
            loaded_domains, loaded_blocks, path
        );
        true
    }

    /// Return the configured block action.
    pub fn block_action(&self) -> &BlockAction {
        &self.config.block_action
    }

    // -----------------------------------------------------------------------
    // Manual domain management
    // -----------------------------------------------------------------------

    /// Manually add a domain to the threat intelligence database.
    pub fn add_domain(&self, domain: String, category: ThreatCategory, source: String) {
        let entry = ThreatEntry {
            domain: domain.clone(),
            category,
            source,
            first_seen: Utc::now(),
            tags: vec![],
        };
        self.domains.write().insert(domain, entry);
    }

    // -----------------------------------------------------------------------
    // Stats / query API
    // -----------------------------------------------------------------------

    /// Return the last N hits.
    pub fn get_recent_hits(&self, limit: usize) -> Vec<ThreatIntelHit> {
        let hits = self.hits.read();
        let start = hits.len().saturating_sub(limit);
        hits[start..].to_vec()
    }

    /// Total number of domains currently in the combined threat database.
    pub fn total_domains(&self) -> usize {
        self.domains.read().len()
    }

    /// Total number of recorded hits.
    pub fn total_hits(&self) -> usize {
        self.hits.read().len()
    }

    /// Aggregate statistics as a JSON value.
    pub fn get_stats(&self) -> serde_json::Value {
        let feeds = self.list_feeds();
        let feed_stats: Vec<serde_json::Value> = feeds
            .iter()
            .map(|f| {
                serde_json::json!({
                    "id": f.id,
                    "name": f.name,
                    "domains_loaded": f.domains_loaded,
                    "last_updated": f.last_updated,
                })
            })
            .collect();

        serde_json::json!({
            "enabled": self.config.enabled,
            "total_domains": self.total_domains(),
            "total_ip_blocks": self.total_ip_blocks(),
            "total_hits": self.total_hits(),
            "update_interval_secs": self.config.update_interval.as_secs(),
            "feeds": feed_stats,
        })
    }

    /// Return whether any feed is overdue for a refresh.
    pub fn needs_update(&self) -> bool {
        let states = self.feed_states.read();
        states.values().any(|s| match s.last_updated {
            None => true,
            Some(t) => t.elapsed() >= self.config.update_interval,
        })
    }

    // -----------------------------------------------------------------------
    // Background auto-update task
    // -----------------------------------------------------------------------

    /// Spawn a tokio task that refreshes all feeds on the configured interval.
    pub fn start_auto_update(self: Arc<Self>) {
        if !self.config.enabled {
            log::info!("[THREAT-INTEL] Auto-update disabled (enabled=false).");
            return;
        }
        let interval = self.config.update_interval;
        tokio::spawn(async move {
            // Initial fetch on startup
            let results = self.refresh_all().await;
            for (id, res) in &results {
                match res {
                    Ok(n) => log::info!("[THREAT-INTEL] Startup: feed '{}' loaded {} domains", id, n),
                    Err(e) => log::warn!("[THREAT-INTEL] Startup: feed '{}' failed: {}", id, e),
                }
            }

            loop {
                tokio::time::sleep(interval).await;
                let results = self.refresh_all().await;
                for (id, res) in &results {
                    match res {
                        Ok(n) => log::info!("[THREAT-INTEL] Refresh: feed '{}' → {} domains", id, n),
                        Err(e) => log::warn!("[THREAT-INTEL] Refresh: feed '{}' failed: {}", id, e),
                    }
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    // Must contain at least one dot
    if !domain.contains('.') {
        return false;
    }
    for c in domain.chars() {
        if !c.is_ascii_alphanumeric() && c != '.' && c != '-' && c != '_' {
            return false;
        }
    }
    true
}
