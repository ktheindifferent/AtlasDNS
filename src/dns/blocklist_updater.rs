//! Automatic blocklist fetching and periodic update scheduler.
//!
//! [`BlocklistUpdater`] runs a background tokio task that periodically re-fetches
//! configured URL-based blocklists, diffs the result against the previously loaded
//! set, and applies incremental adds/removes to the [`SecurityManager`] firewall.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::dns::security::{SecurityManager, firewall::ThreatCategory};

// ---------------------------------------------------------------------------
// BlocklistPreset
// ---------------------------------------------------------------------------

/// Well-known, curated blocklist sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BlocklistPreset {
    /// Hagezi Pro – ads, tracking, and privacy threats
    Hagezi,
    /// Hagezi Light – minimal ad and tracking blocking
    HageziLight,
    /// OISD Full – comprehensive blocklist (wildcard format)
    OISDFull,
    /// OISD Basic – everyday blocking (wildcard format)
    OISDBasic,
    /// Steven Black unified hosts – ads and malware
    StevenBlack,
    /// Steven Black Extended – adds fake news, gambling, and adult content
    StevenBlackExtended,
    /// URLhaus Abuse.ch – active malware hosting domains
    URLhausAbuse,
}

impl BlocklistPreset {
    /// Canonical download URL for this preset.
    pub fn url(self) -> &'static str {
        match self {
            BlocklistPreset::Hagezi => "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt",
            BlocklistPreset::HageziLight => "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/light.txt",
            BlocklistPreset::OISDFull => "https://big.oisd.nl/domainswild",
            BlocklistPreset::OISDBasic => "https://basic.oisd.nl/domainswild",
            BlocklistPreset::StevenBlack => "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            BlocklistPreset::StevenBlackExtended => "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts",
            BlocklistPreset::URLhausAbuse => "https://urlhaus.abuse.ch/downloads/hostfile/",
        }
    }

    /// Human-readable description of this preset.
    pub fn description(self) -> &'static str {
        match self {
            BlocklistPreset::Hagezi => "Hagezi DNS Blocklist Pro – ads, tracking, and privacy threats",
            BlocklistPreset::HageziLight => "Hagezi DNS Blocklist Light – minimal ad and tracking blocking",
            BlocklistPreset::OISDFull => "OISD Full – comprehensive multi-category blocklist",
            BlocklistPreset::OISDBasic => "OISD Basic – everyday blocking for home/office",
            BlocklistPreset::StevenBlack => "Steven Black hosts – unified hosts file for ads and malware",
            BlocklistPreset::StevenBlackExtended => "Steven Black Extended – adds fake news, gambling, and adult content",
            BlocklistPreset::URLhausAbuse => "URLhaus Abuse.ch – active malware hosting domains",
        }
    }

    /// Default threat category for this preset.
    pub fn category(self) -> ThreatCategory {
        match self {
            BlocklistPreset::Hagezi | BlocklistPreset::HageziLight => ThreatCategory::Adware,
            BlocklistPreset::OISDFull | BlocklistPreset::OISDBasic => ThreatCategory::Tracking,
            BlocklistPreset::StevenBlack | BlocklistPreset::StevenBlackExtended => ThreatCategory::Adware,
            BlocklistPreset::URLhausAbuse => ThreatCategory::Malware,
        }
    }

    /// Return all available presets.
    pub fn all() -> Vec<BlocklistPreset> {
        vec![
            BlocklistPreset::Hagezi,
            BlocklistPreset::HageziLight,
            BlocklistPreset::OISDFull,
            BlocklistPreset::OISDBasic,
            BlocklistPreset::StevenBlack,
            BlocklistPreset::StevenBlackExtended,
            BlocklistPreset::URLhausAbuse,
        ]
    }
}

// ---------------------------------------------------------------------------
// BlocklistBundle
// ---------------------------------------------------------------------------

/// Pre-configured bundles of blocklists for common home-network use cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlocklistBundle {
    /// Hagezi Light + StevenBlack ads — minimal blocking, low false-positive risk.
    HomeBasic,
    /// Hagezi Pro + StevenBlack + URLhaus — comprehensive ad/tracking/malware blocking.
    HomePlus,
    /// All available lists including gambling and adult-content categories.
    Strict,
}

impl BlocklistBundle {
    /// Return the constituent presets for this bundle.
    pub fn presets(self) -> Vec<BlocklistPreset> {
        match self {
            BlocklistBundle::HomeBasic => vec![
                BlocklistPreset::HageziLight,
                BlocklistPreset::StevenBlack,
            ],
            BlocklistBundle::HomePlus => vec![
                BlocklistPreset::Hagezi,
                BlocklistPreset::StevenBlack,
                BlocklistPreset::URLhausAbuse,
            ],
            BlocklistBundle::Strict => vec![
                BlocklistPreset::Hagezi,
                BlocklistPreset::OISDFull,
                BlocklistPreset::StevenBlackExtended,
                BlocklistPreset::URLhausAbuse,
            ],
        }
    }

    /// Human-readable description of this bundle.
    pub fn description(self) -> &'static str {
        match self {
            BlocklistBundle::HomeBasic => "Home Basic: Hagezi Light + StevenBlack – minimal ad blocking",
            BlocklistBundle::HomePlus => "Home Plus: Hagezi Pro + StevenBlack + URLhaus – comprehensive ad/tracking/malware protection",
            BlocklistBundle::Strict => "Strict: All lists including gambling and adult content",
        }
    }

    /// All available bundles.
    pub fn all() -> Vec<BlocklistBundle> {
        vec![
            BlocklistBundle::HomeBasic,
            BlocklistBundle::HomePlus,
            BlocklistBundle::Strict,
        ]
    }
}

// ---------------------------------------------------------------------------
// BlocklistEntry (public, serialisable state)
// ---------------------------------------------------------------------------

/// A configured blocklist source with its current statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistEntry {
    /// Unique identifier for this entry.
    pub id: String,
    /// Download URL.
    pub url: String,
    /// Threat category applied when domains are added to the firewall.
    pub category: ThreatCategory,
    /// How often to re-fetch this list (hours).
    pub update_interval_hours: u64,
    /// Unix timestamp of the last successful fetch (`None` = never fetched).
    pub last_updated: Option<u64>,
    /// Number of domains currently loaded from this source.
    pub domains_count: usize,
    /// Original preset, if this entry was created from one.
    pub preset: Option<BlocklistPreset>,
}

// ---------------------------------------------------------------------------
// Internal per-entry state
// ---------------------------------------------------------------------------

struct EntryState {
    domains: HashSet<String>,
}

// ---------------------------------------------------------------------------
// BlocklistUpdater
// ---------------------------------------------------------------------------

/// Manages URL-based blocklists and schedules periodic background refreshes.
pub struct BlocklistUpdater {
    entries: Arc<RwLock<Vec<BlocklistEntry>>>,
    entry_states: Arc<RwLock<HashMap<String, EntryState>>>,
    security_manager: Arc<SecurityManager>,
}

impl BlocklistUpdater {
    /// Create a new updater backed by the given security manager.
    pub fn new(security_manager: Arc<SecurityManager>) -> Self {
        Self {
            entries: Arc::new(RwLock::new(Vec::new())),
            entry_states: Arc::new(RwLock::new(HashMap::new())),
            security_manager,
        }
    }

    /// Add a custom URL-based blocklist entry.  Returns the new entry's ID.
    pub fn add_entry(
        &self,
        url: String,
        category: ThreatCategory,
        update_interval_hours: u64,
        preset: Option<BlocklistPreset>,
    ) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        self.entries.write().push(BlocklistEntry {
            id: id.clone(),
            url,
            category,
            update_interval_hours,
            last_updated: None,
            domains_count: 0,
            preset,
        });
        id
    }

    /// Add a preset blocklist using its default URL, category, and a 24-hour refresh.
    pub fn add_preset(&self, preset: BlocklistPreset) -> String {
        self.add_entry(preset.url().to_string(), preset.category(), 24, Some(preset))
    }

    /// Remove an entry by ID, also clearing the cached domain set.
    pub fn remove_entry(&self, id: &str) {
        self.entries.write().retain(|e| e.id != id);
        self.entry_states.write().remove(id);
    }

    /// Return a snapshot of all configured entries (with stats).
    pub fn list_entries(&self) -> Vec<BlocklistEntry> {
        self.entries.read().clone()
    }

    /// Force an immediate re-fetch for the entry with the given ID.
    ///
    /// Returns the total number of domains loaded, or an error string.
    pub fn refresh_entry(&self, id: &str) -> Result<usize, String> {
        let entry = self
            .entries
            .read()
            .iter()
            .find(|e| e.id == id)
            .cloned();

        match entry {
            Some(e) => self.do_refresh(&e),
            None => Err(format!("Blocklist entry '{}' not found", id)),
        }
    }

    /// Apply a pre-configured bundle by adding all its constituent presets.
    ///
    /// Returns the list of newly created entry IDs (one per preset).
    pub fn apply_bundle(&self, bundle: BlocklistBundle) -> Vec<String> {
        bundle.presets().into_iter().map(|p| self.add_preset(p)).collect()
    }

    // -----------------------------------------------------------------------
    // Background scheduler
    // -----------------------------------------------------------------------

    /// Start the background tokio task that periodically refreshes all entries.
    ///
    /// The task wakes up every 5 minutes, checks which entries are due for a
    /// refresh, and spawns a `spawn_blocking` worker for each one.
    pub fn start_background_updates(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let entries: Vec<BlocklistEntry> = self.entries.read().clone();
                for entry in entries {
                    let due = match entry.last_updated {
                        None => true,
                        Some(last) => now.saturating_sub(last) >= entry.update_interval_hours * 3600,
                    };

                    if due {
                        let updater = Arc::clone(&self);
                        let entry_clone = entry.clone();
                        tokio::task::spawn_blocking(move || {
                            match updater.do_refresh(&entry_clone) {
                                Ok(n) => log::info!(
                                    "Blocklist '{}' updated: {} domains loaded",
                                    entry_clone.url, n
                                ),
                                Err(e) => log::warn!(
                                    "Blocklist '{}' update failed: {}",
                                    entry_clone.url, e
                                ),
                            }
                        });
                    }
                }
            }
        });
    }

    // -----------------------------------------------------------------------
    // Core refresh logic
    // -----------------------------------------------------------------------

    fn do_refresh(&self, entry: &BlocklistEntry) -> Result<usize, String> {
        let text = Self::fetch_url(&entry.url)?;
        let new_domains = Self::parse_blocklist_text(&text);

        let old_domains: HashSet<String> = {
            let states = self.entry_states.read();
            states
                .get(&entry.id)
                .map(|s| s.domains.clone())
                .unwrap_or_default()
        };

        let added: Vec<String> = new_domains.difference(&old_domains).cloned().collect();
        let removed: Vec<String> = old_domains.difference(&new_domains).cloned().collect();

        log::info!(
            "Blocklist '{}': +{} added, -{} removed (total: {})",
            entry.url,
            added.len(),
            removed.len(),
            new_domains.len()
        );

        if !added.is_empty() {
            self.security_manager
                .add_domains_to_blocklist(&added, entry.category)
                .map_err(|e| format!("Failed to add domains to firewall: {}", e))?;
        }
        if !removed.is_empty() {
            self.security_manager
                .remove_from_blocklist(&removed)
                .map_err(|e| format!("Failed to remove domains from firewall: {}", e))?;
        }

        let total = new_domains.len();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Persist updated domain set
        self.entry_states
            .write()
            .insert(entry.id.clone(), EntryState { domains: new_domains });

        // Update entry metadata
        {
            let mut entries = self.entries.write();
            if let Some(e) = entries.iter_mut().find(|e| e.id == entry.id) {
                e.last_updated = Some(now);
                e.domains_count = total;
            }
        }

        Ok(total)
    }

    // -----------------------------------------------------------------------
    // HTTP fetch (runs on a dedicated thread to stay runtime-agnostic)
    // -----------------------------------------------------------------------

    fn fetch_url(url: &str) -> Result<String, String> {
        let url = url.to_string();
        std::thread::spawn(move || {
            reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .user_agent("AtlasDNS/1.0 blocklist-updater")
                .build()
                .and_then(|c| c.get(&url).send())
                .and_then(|r| r.text())
        })
        .join()
        .map_err(|_| "Fetch thread panicked".to_string())?
        .map_err(|e| format!("HTTP error: {}", e))
    }

    // -----------------------------------------------------------------------
    // Multi-format blocklist parser
    // -----------------------------------------------------------------------

    /// Parse a downloaded blocklist text into a set of lowercase domain strings.
    ///
    /// Supported formats:
    /// - **Hosts file**: `0.0.0.0 domain.com` or `127.0.0.1 domain.com`
    /// - **Plain domain list**: one domain per line
    /// - **ABP/Adblock Plus**: `||domain.com^`
    /// - **RPZ zone file**: first label of each non-comment RR
    pub fn parse_blocklist_text(text: &str) -> HashSet<String> {
        let mut domains = HashSet::new();

        for line in text.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            let domain: &str = if line.starts_with("||") {
                // ABP/Adblock Plus: ||domain.com^ or ||domain.com^$...
                let inner = line.trim_start_matches("||");
                let inner = inner.split('^').next().unwrap_or(inner);
                inner.split('/').next().unwrap_or(inner)
            } else if line.starts_with("0.0.0.0 ") || line.starts_with("127.0.0.1 ") {
                // Hosts file
                match line.split_whitespace().nth(1) {
                    Some(d) => d,
                    None => continue,
                }
            } else if line.contains(' ') || line.contains('\t') {
                // RPZ or other space-separated – first token if it looks like a domain
                match line.split_whitespace().next() {
                    Some(d) if d.contains('.') => d,
                    _ => continue,
                }
            } else {
                // Plain domain list
                line
            };

            // Strip trailing FQDN dot
            let domain = domain.trim_end_matches('.');

            if !domain.is_empty() && is_valid_domain(domain) {
                domains.insert(domain.to_ascii_lowercase());
            }
        }

        domains
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
    for c in domain.chars() {
        if !c.is_ascii_alphanumeric() && c != '.' && c != '-' && c != '_' {
            return false;
        }
    }
    domain.contains('.')
}
