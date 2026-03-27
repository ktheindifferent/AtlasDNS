//! DNS Anomaly Detection
//!
//! Heuristic + entropy-based anomaly scoring for DNS queries.
//! No external ML dependencies — everything is pure Rust math.
//!
//! # Scoring dimensions
//! * **DGA** — Shannon entropy, long labels, consonant-cluster ratio, digit ratio
//! * **Tunneling** — TXT/NULL/ANY queries, long total domain names
//! * **TLD rarity** — unusual top-level domains
//! * **Client behaviour** — per-IP rolling 60-second window tracking queries/min,
//!   unique-domains/min, NXDOMAIN rate
//!
//! Each dimension yields a partial score 0.0–1.0. They are blended into a
//! final composite score.  Score ≥ 0.7 → `log::warn!`, score ≥ 0.9 → `log::error!`
//! (and optional blocking when `block_on_critical` is set).

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::dns::query_type::QueryType;

// ─── tunables ────────────────────────────────────────────────────────────────

/// Rolling window length for per-client statistics (seconds).
const WINDOW_SECS: u64 = 60;

/// Maximum number of anomaly events kept in the ring buffer.
const MAX_ANOMALY_LOG: usize = 1000;

/// Anomaly score threshold for a `warn!` log line.
pub const THRESHOLD_WARN: f32 = 0.7;

/// Anomaly score threshold for an `error!` log line (and optional block).
pub const THRESHOLD_CRITICAL: f32 = 0.9;

// ─── well-known "normal" TLDs ─────────────────────────────────────────────────

static COMMON_TLDS: &[&str] = &[
    "com", "net", "org", "edu", "gov", "io", "co", "uk", "de", "fr",
    "nl", "au", "ca", "jp", "ru", "cn", "br", "in", "it", "es",
    "se", "no", "fi", "dk", "pl", "cz", "ch", "at", "be", "pt",
    "nz", "mx", "za", "us", "info", "biz", "tech", "app", "dev",
    "online", "site", "website", "store", "shop", "cloud", "local",
    "internal", "lan", "home", "arpa", "int", "mil",
];

// ─── per-client rolling window ────────────────────────────────────────────────

#[derive(Debug)]
struct QueryRecord {
    ts: Instant,
    domain: String,
    is_nxdomain: bool,
}

#[derive(Debug, Default)]
struct ClientWindow {
    records: VecDeque<QueryRecord>,
}

impl ClientWindow {
    /// Remove records older than `WINDOW_SECS`.
    fn prune(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(WINDOW_SECS);
        while self.records.front().map(|r| r.ts < cutoff).unwrap_or(false) {
            self.records.pop_front();
        }
    }

    fn push(&mut self, domain: String) {
        self.prune();
        self.records.push_back(QueryRecord {
            ts: Instant::now(),
            domain,
            is_nxdomain: false,
        });
    }

    /// Mark the most-recently-added record as an NXDOMAIN response.
    fn mark_last_nxdomain(&mut self) {
        if let Some(r) = self.records.back_mut() {
            r.is_nxdomain = true;
        }
    }

    fn queries_per_minute(&self) -> usize {
        self.records.len()
    }

    fn unique_domains_per_minute(&self) -> usize {
        let mut seen = HashSet::new();
        for r in &self.records {
            // Strip the last label (TLD) to count distinct registered domains.
            let key: Vec<&str> = r.domain.splitn(2, '.').collect();
            seen.insert(key.last().copied().unwrap_or(&r.domain));
        }
        seen.len()
    }

    fn nxdomain_rate(&self) -> f32 {
        if self.records.is_empty() {
            return 0.0;
        }
        let nx = self.records.iter().filter(|r| r.is_nxdomain).count();
        nx as f32 / self.records.len() as f32
    }
}

// ─── public types ─────────────────────────────────────────────────────────────

/// A single high-scoring anomaly event recorded in the ring buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyEvent {
    pub domain: String,
    pub client_ip: String,
    pub query_type: String,
    pub score: f32,
    pub reasons: Vec<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Per-client rolling statistics (snapshot for the API / dashboard).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientAnomalyStats {
    pub client_ip: String,
    pub queries_per_minute: usize,
    pub unique_domains_per_minute: usize,
    pub nxdomain_rate_pct: f32,
}

// ─── detector ─────────────────────────────────────────────────────────────────

/// Configuration for the anomaly detector.
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct AnomalyConfig {
    /// If `true`, queries that score ≥ `THRESHOLD_CRITICAL` are blocked
    /// (the caller must check the returned score and act accordingly).
    pub block_on_critical: bool,
}


/// Main anomaly detector.  Cheap to clone (all state is behind `Arc`).
pub struct DnsAnomalyDetector {
    pub config: AnomalyConfig,
    client_windows: Arc<Mutex<HashMap<IpAddr, ClientWindow>>>,
    recent_anomalies: Arc<Mutex<VecDeque<AnomalyEvent>>>,
}

impl Default for DnsAnomalyDetector {
    fn default() -> Self {
        Self::new(AnomalyConfig::default())
    }
}

impl DnsAnomalyDetector {
    pub fn new(config: AnomalyConfig) -> Self {
        DnsAnomalyDetector {
            config,
            client_windows: Arc::new(Mutex::new(HashMap::new())),
            recent_anomalies: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    // ── private scoring helpers ───────────────────────────────────────────────

    /// Shannon entropy of `s` in bits-per-character.
    fn shannon_entropy(s: &str) -> f32 {
        if s.is_empty() {
            return 0.0;
        }
        let mut counts = [0u32; 256];
        for b in s.bytes() {
            counts[b as usize] += 1;
        }
        let len = s.len() as f32;
        let mut h = 0.0f32;
        for &c in &counts {
            if c > 0 {
                let p = c as f32 / len;
                h -= p * p.log2();
            }
        }
        h
    }

    /// Score DGA-like patterns (returns score ∈ [0,1] and human reasons).
    fn score_dga(domain: &str) -> (f32, Vec<String>) {
        let mut score = 0.0f32;
        let mut reasons = Vec::new();

        let labels: Vec<&str> = domain.split('.').collect();
        let label_count = labels.len();

        // Examine each label except the TLD.
        for label in labels.iter().take(label_count.saturating_sub(1)) {
            let len = label.len();
            if len == 0 {
                continue;
            }

            // Long-label heuristic (DGA domains often > 20 chars per label).
            if len > 30 {
                score += 0.35;
                reasons.push(format!("unusually long subdomain label ({} chars)", len));
            } else if len > 20 {
                score += 0.15;
                reasons.push(format!("long subdomain label ({} chars)", len));
            }

            // Shannon entropy.
            let entropy = Self::shannon_entropy(label);
            if entropy > 3.8 {
                score += 0.30;
                reasons.push(format!(
                    "high domain entropy ({:.2} bits/char, DGA indicator)",
                    entropy
                ));
            } else if entropy > 3.2 {
                score += 0.12;
                reasons.push(format!("elevated domain entropy ({:.2} bits/char)", entropy));
            }

            // Consonant-cluster ratio (random strings lack vowels).
            let lc = label.to_ascii_lowercase();
            let consonants = lc.chars()
                .filter(|c| "bcdfghjklmnpqrstvwxyz".contains(*c))
                .count();
            if len > 5 && consonants as f32 / len as f32 > 0.75 {
                score += 0.15;
                reasons.push(format!(
                    "high consonant ratio in label ({:.0}%)",
                    consonants as f32 / len as f32 * 100.0
                ));
            }

            // High digit ratio.
            let digits = label.chars().filter(|c| c.is_ascii_digit()).count();
            if len > 5 && digits as f32 / len as f32 > 0.40 {
                score += 0.10;
                reasons.push(format!(
                    "high digit ratio in label ({:.0}%)",
                    digits as f32 / len as f32 * 100.0
                ));
            }
        }

        // Deep subdomain nesting.
        if label_count > 5 {
            score += 0.10;
            reasons.push(format!("deep subdomain nesting ({} labels)", label_count));
        }

        (score.min(0.95), reasons)
    }

    /// Score DNS-tunneling indicators.
    fn score_tunneling(domain: &str, qtype: &QueryType) -> (f32, Vec<String>) {
        let mut score = 0.0f32;
        let mut reasons = Vec::new();

        match qtype {
            QueryType::Txt => {
                let entropy = Self::shannon_entropy(domain);
                if entropy > 3.5 {
                    score += 0.45;
                    reasons.push(
                        "TXT query with high-entropy domain (DNS tunnel indicator)".to_string(),
                    );
                } else {
                    score += 0.12;
                    reasons.push("TXT record query (common tunneling vector)".to_string());
                }
            }
            QueryType::Unknown(t) if *t == 10 || *t == 255 => {
                // NULL (10) or ANY (255) – rarely legitimate.
                score += 0.20;
                reasons.push(format!("unusual query type {} (tunnel/recon indicator)", t));
            }
            _ => {}
        }

        // Total domain name length – tunnels carry data in the name itself.
        let dlen = domain.len();
        if dlen > 100 {
            score += 0.35;
            reasons.push(format!(
                "total domain name {} bytes (DNS tunnel large-payload indicator)",
                dlen
            ));
        } else if dlen > 60 {
            score += 0.15;
            reasons.push(format!("long domain name ({} bytes)", dlen));
        }

        (score.min(0.90), reasons)
    }

    /// Score TLD rarity.
    fn score_tld_rarity(domain: &str) -> (f32, Vec<String>) {
        let tld = domain.split('.').next_back().unwrap_or("").to_ascii_lowercase();
        if !tld.is_empty() && !COMMON_TLDS.contains(&tld.as_str()) {
            (
                0.10,
                vec![format!("rare TLD '.{}' (unusual for legitimate traffic)", tld)],
            )
        } else {
            (0.0, vec![])
        }
    }

    /// Score per-client behavioural anomalies from the rolling window.
    /// Must be called while *not* holding the window lock (takes it internally).
    fn score_client_behavior(&self, client_ip: IpAddr) -> (f32, Vec<String>) {
        let mut score = 0.0f32;
        let mut reasons = Vec::new();

        let windows = self.client_windows.lock().unwrap();
        if let Some(window) = windows.get(&client_ip) {
            let qpm = window.queries_per_minute();
            let udpm = window.unique_domains_per_minute();
            let nx_rate = window.nxdomain_rate();

            // Query rate.
            if qpm > 500 {
                score += 0.45;
                reasons.push(format!(
                    "very high query rate: {} queries/min from {}",
                    qpm, client_ip
                ));
            } else if qpm > 200 {
                score += 0.25;
                reasons.push(format!(
                    "high query rate: {} queries/min from {}",
                    qpm, client_ip
                ));
            } else if qpm > 100 {
                score += 0.10;
                reasons.push(format!(
                    "elevated query rate: {} queries/min from {}",
                    qpm, client_ip
                ));
            }

            // Unique domain rate (DGA enumerates many distinct names).
            if udpm > 100 {
                score += 0.35;
                reasons.push(format!(
                    "very high unique-domain rate: {} distinct domains/min",
                    udpm
                ));
            } else if udpm > 50 {
                score += 0.20;
                reasons.push(format!(
                    "high unique-domain rate: {} distinct domains/min",
                    udpm
                ));
            }

            // NXDOMAIN rate (DGA or C2 beaconing).
            if nx_rate > 0.70 && qpm > 5 {
                score += 0.35;
                reasons.push(format!("high NXDOMAIN rate: {:.0}%", nx_rate * 100.0));
            } else if nx_rate > 0.50 && qpm > 10 {
                score += 0.20;
                reasons.push(format!("elevated NXDOMAIN rate: {:.0}%", nx_rate * 100.0));
            }
        }

        (score.min(0.95), reasons)
    }

    // ── public API ────────────────────────────────────────────────────────────

    /// Analyse a DNS query and return `(composite_score, reasons)`.
    ///
    /// Also records the query in the per-client rolling window so that
    /// subsequent calls for the same IP see updated statistics.
    ///
    /// Call [`record_response`] after resolution to feed NXDOMAIN data back.
    pub fn analyze_query(
        &self,
        domain: &str,
        qtype: &QueryType,
        client_ip: Option<IpAddr>,
    ) -> (f32, Vec<String>) {
        let (dga_score, dga_reasons) = Self::score_dga(domain);
        let (tunnel_score, tunnel_reasons) = Self::score_tunneling(domain, qtype);
        let (tld_score, tld_reasons) = Self::score_tld_rarity(domain);

        // Behavioural score is read *before* the new query is pushed so that the
        // current query's rate contribution appears in the next call, not this one.
        let (client_score, client_reasons) = if let Some(ip) = client_ip {
            self.score_client_behavior(ip)
        } else {
            (0.0, vec![])
        };

        // Push the new query into the rolling window.
        if let Some(ip) = client_ip {
            let mut windows = self.client_windows.lock().unwrap();
            windows
                .entry(ip)
                .or_default()
                .push(domain.to_string());
        }

        // Weighted blend: DGA 40%, tunneling 30%, behaviour 25%, TLD 5%.
        let composite = (dga_score * 0.40
            + tunnel_score * 0.30
            + client_score * 0.25
            + tld_score * 0.05)
            .min(1.0);

        let mut all_reasons = Vec::new();
        all_reasons.extend(dga_reasons);
        all_reasons.extend(tunnel_reasons);
        all_reasons.extend(client_reasons);
        all_reasons.extend(tld_reasons);

        (composite, all_reasons)
    }

    /// Feed back the DNS response code so NXDOMAIN rates stay accurate.
    pub fn record_response(&self, client_ip: IpAddr, is_nxdomain: bool) {
        if is_nxdomain {
            if let Ok(mut windows) = self.client_windows.lock() {
                if let Some(w) = windows.get_mut(&client_ip) {
                    w.mark_last_nxdomain();
                }
            }
        }
    }

    /// Persist an anomaly event in the ring buffer.
    /// Called by the DNS server when `composite ≥ THRESHOLD_WARN`.
    pub fn record_anomaly(
        &self,
        domain: &str,
        query_type: &str,
        client_ip: &str,
        score: f32,
        reasons: Vec<String>,
    ) {
        let event = AnomalyEvent {
            domain: domain.to_string(),
            client_ip: client_ip.to_string(),
            query_type: query_type.to_string(),
            score,
            reasons,
            timestamp: chrono::Utc::now(),
        };
        let mut buf = self.recent_anomalies.lock().unwrap();
        buf.push_back(event);
        if buf.len() > MAX_ANOMALY_LOG {
            buf.pop_front();
        }
    }

    /// Return up to `limit` most-recent anomaly events (newest first).
    pub fn get_recent_anomalies(&self, limit: usize) -> Vec<AnomalyEvent> {
        self.recent_anomalies
            .lock()
            .unwrap()
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Return a snapshot of per-client rolling stats (pruned to current window).
    pub fn get_client_stats(&self) -> Vec<ClientAnomalyStats> {
        let mut windows = self.client_windows.lock().unwrap();
        for w in windows.values_mut() {
            w.prune();
        }
        windows
            .iter()
            .filter(|(_, w)| !w.records.is_empty())
            .map(|(ip, w)| ClientAnomalyStats {
                client_ip: ip.to_string(),
                queries_per_minute: w.queries_per_minute(),
                unique_domains_per_minute: w.unique_domains_per_minute(),
                nxdomain_rate_pct: w.nxdomain_rate() * 100.0,
            })
            .collect()
    }

    /// Total number of anomaly events recorded since startup.
    pub fn total_anomaly_count(&self) -> usize {
        self.recent_anomalies.lock().unwrap().len()
    }
}
