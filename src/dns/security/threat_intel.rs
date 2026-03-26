//! Threat Intelligence Integration
//!
//! Integrates with free threat intelligence feeds to block known malicious domains:
//! - Abuse.ch URLhaus: malware distribution URLs
//! - MalwareBazaar: malware hash database
//! Auto-updates every hour. Logs hits separately from regular blocklist hits.
//! Sends webhook alerts when a query matches threat intel.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Threat category from intelligence feed
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatCategory {
    MalwareC2,
    Phishing,
    Botnet,
    Spam,
    MalwareDownload,
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
            ThreatCategory::Unknown => write!(f, "unknown"),
        }
    }
}

/// A known malicious domain from threat intelligence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEntry {
    pub domain: String,
    pub category: ThreatCategory,
    pub source: String,
    pub first_seen: DateTime<Utc>,
    pub tags: Vec<String>,
}

/// A threat intel hit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelHit {
    pub timestamp: DateTime<Utc>,
    pub domain: String,
    pub client_ip: String,
    pub category: ThreatCategory,
    pub source: String,
}

/// Threat intelligence configuration
#[derive(Debug, Clone)]
pub struct ThreatIntelConfig {
    /// Enable threat intelligence blocking
    pub enabled: bool,
    /// Webhook URL for alerts (None = no webhook)
    pub webhook_url: Option<String>,
    /// How often to update feeds (default: 3600 seconds = 1 hour)
    pub update_interval: Duration,
    /// URLhaus API endpoint
    pub urlhaus_api: String,
    /// Maximum domains to store
    pub max_domains: usize,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            webhook_url: None,
            update_interval: Duration::from_secs(3600),
            urlhaus_api: "https://urlhaus-api.abuse.ch/v1/urls/recent/".to_string(),
            max_domains: 100_000,
        }
    }
}

/// URLhaus API response URL entry
#[derive(Debug, Deserialize)]
struct UrlhausEntry {
    url: String,
    url_status: String,
    tags: Option<Vec<String>>,
    threat: Option<String>,
}

/// URLhaus API response
#[derive(Debug, Deserialize)]
struct UrlhausResponse {
    query_status: String,
    urls: Option<Vec<UrlhausEntry>>,
}

/// Threat intelligence manager
pub struct ThreatIntelManager {
    config: ThreatIntelConfig,
    /// domain -> ThreatEntry
    domains: Arc<RwLock<HashMap<String, ThreatEntry>>>,
    /// Recent hits log
    hits: Arc<RwLock<Vec<ThreatIntelHit>>>,
    last_update: Arc<RwLock<Option<Instant>>>,
    /// Total domains loaded
    total_loaded: Arc<RwLock<usize>>,
}

impl ThreatIntelManager {
    pub fn new(config: ThreatIntelConfig) -> Self {
        Self {
            config,
            domains: Arc::new(RwLock::new(HashMap::new())),
            hits: Arc::new(RwLock::new(Vec::new())),
            last_update: Arc::new(RwLock::new(None)),
            total_loaded: Arc::new(RwLock::new(0)),
        }
    }

    /// Check if a domain is in the threat intel database.
    /// Returns the threat entry if found.
    pub fn check_domain(&self, domain: &str) -> Option<ThreatEntry> {
        if !self.config.enabled {
            return None;
        }
        let domains = self.domains.read();
        // Check exact match and parent domains
        let lower = domain.to_lowercase();
        if let Some(entry) = domains.get(&lower) {
            return Some(entry.clone());
        }
        // Check subdomains: for "sub.evil.com" also check "evil.com"
        let parts: Vec<&str> = lower.split('.').collect();
        for i in 1..parts.len().saturating_sub(1) {
            let parent = parts[i..].join(".");
            if let Some(entry) = domains.get(&parent) {
                return Some(entry.clone());
            }
        }
        None
    }

    /// Record a threat intel hit and optionally fire a webhook
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
            // Keep last 10000 hits
            if hits.len() > 10_000 {
                let drain_count = hits.len() - 10_000;
                hits.drain(0..drain_count);
            }
        }

        // Fire webhook asynchronously if configured
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

    /// Send a webhook alert for a threat intel hit
    async fn send_webhook_alert(url: &str, hit: &ThreatIntelHit) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

        let resp = client.post(url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if !resp.status().is_success() {
            log::warn!("[THREAT-INTEL] Webhook returned {}", resp.status());
        }

        Ok(())
    }

    /// Parse a domain from a URL string
    fn url_to_domain(url: &str) -> Option<String> {
        let url = url.trim_start_matches("http://").trim_start_matches("https://");
        let domain = url.split('/').next()?;
        let domain = domain.split(':').next()?; // strip port
        if domain.is_empty() || domain.contains(' ') {
            return None;
        }
        Some(domain.to_lowercase())
    }

    /// Fetch latest threat intel from URLhaus
    pub async fn fetch_urlhaus(&self) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("AtlasDNS/1.0 (threat-intel)")
            .build()?;

        log::info!("[THREAT-INTEL] Fetching URLhaus feed from {}", self.config.urlhaus_api);

        let resp = client
            .post(&self.config.urlhaus_api)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body("limit=1000")
            .send()
            .await?;

        let data: UrlhausResponse = resp.json().await?;

        if data.query_status != "ok" && data.query_status != "is_inactive" {
            log::warn!("[THREAT-INTEL] URLhaus returned status: {}", data.query_status);
        }

        let mut count = 0;
        if let Some(urls) = data.urls {
            let mut domains = self.domains.write();
            for entry in urls {
                if entry.url_status != "online" && entry.url_status != "unknown" {
                    continue;
                }
                if let Some(domain) = Self::url_to_domain(&entry.url) {
                    let category = match entry.threat.as_deref() {
                        Some("malware_download") => ThreatCategory::MalwareDownload,
                        Some("botnet_cc") => ThreatCategory::MalwareC2,
                        Some("phishing") => ThreatCategory::Phishing,
                        _ => ThreatCategory::MalwareDownload,
                    };
                    domains.insert(domain.clone(), ThreatEntry {
                        domain,
                        category,
                        source: "urlhaus".to_string(),
                        first_seen: Utc::now(),
                        tags: entry.tags.unwrap_or_default(),
                    });
                    count += 1;
                    if domains.len() >= self.config.max_domains {
                        break;
                    }
                }
            }
            *self.total_loaded.write() = domains.len();
        }

        *self.last_update.write() = Some(Instant::now());
        log::info!("[THREAT-INTEL] URLhaus update complete: {} new domains, {} total", count, *self.total_loaded.read());
        Ok(count)
    }

    /// Manually add a domain to threat intel
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

    /// Get recent threat intel hits
    pub fn get_recent_hits(&self, limit: usize) -> Vec<ThreatIntelHit> {
        let hits = self.hits.read();
        let start = hits.len().saturating_sub(limit);
        hits[start..].to_vec()
    }

    /// Get statistics
    pub fn get_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "enabled": self.config.enabled,
            "total_domains": *self.total_loaded.read(),
            "total_hits": self.hits.read().len(),
            "last_update": self.last_update.read().map(|t| t.elapsed().as_secs()),
            "update_interval_secs": self.config.update_interval.as_secs(),
        })
    }

    /// Check if an update is due
    pub fn needs_update(&self) -> bool {
        match *self.last_update.read() {
            None => true,
            Some(t) => t.elapsed() >= self.config.update_interval,
        }
    }

    /// Start background auto-update task
    pub fn start_auto_update(self: Arc<Self>) {
        if !self.config.enabled {
            return;
        }
        let interval = self.config.update_interval;
        tokio::spawn(async move {
            loop {
                if let Err(e) = self.fetch_urlhaus().await {
                    log::error!("[THREAT-INTEL] Auto-update failed: {}", e);
                }
                tokio::time::sleep(interval).await;
            }
        });
    }
}
