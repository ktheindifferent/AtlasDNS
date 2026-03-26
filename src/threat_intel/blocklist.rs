//! In-memory blocklist with periodic refresh from threat intelligence feeds.
//!
//! The [`Blocklist`] aggregates domains from multiple sources (URLhaus, custom
//! feeds, etc.) into a single `HashSet` protected by a read-write lock for
//! concurrent access from DNS worker threads.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::RwLock;

use super::feeds;

/// Blocklist configuration matching the `threat_intel.*` config namespace.
#[derive(Debug, Clone)]
pub struct BlocklistConfig {
    /// Master enable switch.
    pub enabled: bool,
    /// Fetch domains from URLhaus text_online feed.
    pub urlhaus_enabled: bool,
    /// Check resolved IPs against Spamhaus ZEN DNSBL.
    pub spamhaus_enabled: bool,
    /// How often to refresh feeds (seconds).
    pub refresh_interval_secs: u64,
    /// Response to return for blocked domains: `"nxdomain"` or `"refused"`.
    pub block_response: BlockResponse,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            urlhaus_enabled: true,
            spamhaus_enabled: false,
            refresh_interval_secs: 3600,
            block_response: BlockResponse::Nxdomain,
        }
    }
}

/// The DNS response to synthesize when a query matches the blocklist.
#[derive(Debug, Clone, PartialEq)]
pub enum BlockResponse {
    Nxdomain,
    Refused,
}

impl BlockResponse {
    pub fn from_str_config(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "refused" => BlockResponse::Refused,
            _ => BlockResponse::Nxdomain,
        }
    }
}

/// Thread-safe, in-memory domain blocklist with automatic periodic refresh.
pub struct Blocklist {
    domains: Arc<RwLock<HashSet<String>>>,
    config: BlocklistConfig,
    /// Total number of DNS queries blocked since startup.
    domains_blocked: Arc<AtomicU64>,
}

impl Blocklist {
    /// Create a new empty blocklist with the given configuration.
    pub fn new(config: BlocklistConfig) -> Self {
        Self {
            domains: Arc::new(RwLock::new(HashSet::new())),
            config,
            domains_blocked: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Check if a domain (or any of its parent domains) is in the blocklist.
    pub fn contains(&self, domain: &str) -> bool {
        let lower = domain.trim_end_matches('.').to_lowercase();
        let domains = self.domains.read();

        // Exact match
        if domains.contains(&lower) {
            return true;
        }

        // Walk parent domains: for "sub.evil.com", also check "evil.com"
        let parts: Vec<&str> = lower.split('.').collect();
        for i in 1..parts.len().saturating_sub(1) {
            let parent = parts[i..].join(".");
            if domains.contains(&parent) {
                return true;
            }
        }

        false
    }

    /// Record a blocked query (increments the counter).
    pub fn record_block(&self) {
        self.domains_blocked.fetch_add(1, Ordering::Relaxed);
    }

    /// Total domains currently in the blocklist.
    pub fn len(&self) -> usize {
        self.domains.read().len()
    }

    /// Whether the blocklist is empty.
    pub fn is_empty(&self) -> bool {
        self.domains.read().is_empty()
    }

    /// Number of queries blocked since startup.
    pub fn domains_blocked_count(&self) -> u64 {
        self.domains_blocked.load(Ordering::Relaxed)
    }

    /// The configured block response type.
    pub fn block_response(&self) -> &BlockResponse {
        &self.config.block_response
    }

    /// Whether Spamhaus DNSBL checks are enabled.
    pub fn spamhaus_enabled(&self) -> bool {
        self.config.spamhaus_enabled
    }

    /// Replace the entire domain set (used during refresh).
    pub fn replace_domains(&self, new_domains: HashSet<String>) {
        let mut domains = self.domains.write();
        *domains = new_domains;
    }

    /// Add domains to the existing set (merges, does not replace).
    pub fn add_domains(&self, new_domains: HashSet<String>) {
        let mut domains = self.domains.write();
        domains.extend(new_domains);
    }

    /// Return a snapshot of the blocklist stats.
    pub fn stats(&self) -> BlocklistStats {
        BlocklistStats {
            enabled: self.config.enabled,
            total_domains: self.len(),
            domains_blocked: self.domains_blocked_count(),
            urlhaus_enabled: self.config.urlhaus_enabled,
            spamhaus_enabled: self.config.spamhaus_enabled,
            refresh_interval_secs: self.config.refresh_interval_secs,
            block_response: match self.config.block_response {
                BlockResponse::Nxdomain => "nxdomain".to_string(),
                BlockResponse::Refused => "refused".to_string(),
            },
        }
    }

    /// Perform a one-shot refresh of all enabled feeds.
    pub async fn refresh(&self) -> Result<usize, String> {
        let mut all_domains = HashSet::new();

        if self.config.urlhaus_enabled {
            match feeds::fetch_urlhaus_domains().await {
                Ok(domains) => {
                    log::info!(
                        "[BLOCKLIST] URLhaus refresh: {} domains fetched",
                        domains.len()
                    );
                    all_domains.extend(domains);
                }
                Err(e) => {
                    log::warn!("[BLOCKLIST] URLhaus refresh failed: {}", e);
                }
            }
        }

        let count = all_domains.len();
        self.replace_domains(all_domains);
        Ok(count)
    }

    /// Spawn a background tokio task that refreshes feeds on the configured
    /// interval.  The task runs forever (until the runtime shuts down).
    pub fn start_periodic_refresh(self: Arc<Self>) {
        if !self.config.enabled {
            log::info!("[BLOCKLIST] Periodic refresh disabled (enabled=false).");
            return;
        }

        let interval = Duration::from_secs(self.config.refresh_interval_secs);
        tokio::spawn(async move {
            // Initial fetch
            match self.refresh().await {
                Ok(n) => log::info!("[BLOCKLIST] Initial load: {} domains", n),
                Err(e) => log::warn!("[BLOCKLIST] Initial load failed: {}", e),
            }

            loop {
                tokio::time::sleep(interval).await;
                match self.refresh().await {
                    Ok(n) => log::info!("[BLOCKLIST] Refresh complete: {} domains", n),
                    Err(e) => log::warn!("[BLOCKLIST] Refresh failed: {}", e),
                }
            }
        });
    }
}

/// Serializable stats snapshot for the blocklist.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BlocklistStats {
    pub enabled: bool,
    pub total_domains: usize,
    pub domains_blocked: u64,
    pub urlhaus_enabled: bool,
    pub spamhaus_enabled: bool,
    pub refresh_interval_secs: u64,
    pub block_response: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_blocklist() -> Blocklist {
        Blocklist::new(BlocklistConfig {
            enabled: true,
            ..BlocklistConfig::default()
        })
    }

    #[test]
    fn contains_exact_match() {
        let bl = make_blocklist();
        let mut domains = HashSet::new();
        domains.insert("evil.com".to_string());
        bl.replace_domains(domains);

        assert!(bl.contains("evil.com"));
        assert!(bl.contains("Evil.Com"));
        assert!(!bl.contains("good.com"));
    }

    #[test]
    fn contains_parent_match() {
        let bl = make_blocklist();
        let mut domains = HashSet::new();
        domains.insert("evil.com".to_string());
        bl.replace_domains(domains);

        assert!(bl.contains("sub.evil.com"));
        assert!(bl.contains("deep.sub.evil.com"));
    }

    #[test]
    fn block_counter() {
        let bl = make_blocklist();
        assert_eq!(bl.domains_blocked_count(), 0);
        bl.record_block();
        bl.record_block();
        assert_eq!(bl.domains_blocked_count(), 2);
    }

    #[test]
    fn replace_clears_old() {
        let bl = make_blocklist();
        let mut d1 = HashSet::new();
        d1.insert("old.com".to_string());
        bl.replace_domains(d1);
        assert!(bl.contains("old.com"));

        let mut d2 = HashSet::new();
        d2.insert("new.com".to_string());
        bl.replace_domains(d2);
        assert!(!bl.contains("old.com"));
        assert!(bl.contains("new.com"));
    }

    #[test]
    fn stats_snapshot() {
        let bl = make_blocklist();
        let s = bl.stats();
        assert!(s.enabled);
        assert_eq!(s.total_domains, 0);
        assert_eq!(s.domains_blocked, 0);
    }

    #[test]
    fn block_response_from_str() {
        assert_eq!(BlockResponse::from_str_config("nxdomain"), BlockResponse::Nxdomain);
        assert_eq!(BlockResponse::from_str_config("refused"), BlockResponse::Refused);
        assert_eq!(BlockResponse::from_str_config("REFUSED"), BlockResponse::Refused);
        assert_eq!(BlockResponse::from_str_config("anything"), BlockResponse::Nxdomain);
    }
}
