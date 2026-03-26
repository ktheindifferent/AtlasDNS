//! Local network device query tracking.
//!
//! [`DeviceTracker`] records every DNS query handled by the server so operators
//! can see which local IPs are querying which domains.  Data is stored in an
//! in-memory ring-buffer, capped at a configurable maximum.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// One DNS query event recorded by the tracker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryLogEntry {
    /// Monotonically increasing entry ID.
    pub id: u64,
    /// Source IP address of the querying client.
    pub client_ip: String,
    /// Domain that was queried (lowercased).
    pub domain: String,
    /// Query type string (e.g. "A", "AAAA").
    pub query_type: String,
    /// Unix timestamp of the query.
    pub timestamp: u64,
    /// Whether this query was blocked by the firewall.
    pub blocked: bool,
}

/// Aggregate statistics for a single client IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientStats {
    /// Client IP address.
    pub client_ip: String,
    /// Total queries seen from this client.
    pub query_count: u64,
    /// Number of those queries that were blocked.
    pub blocked_count: u64,
    /// Top 10 most-queried domains (domain, count).
    pub top_domains: Vec<(String, u64)>,
    /// Unix timestamp of the most recent query.
    pub last_seen: u64,
}

// ---------------------------------------------------------------------------
// DeviceTracker
// ---------------------------------------------------------------------------

/// In-memory DNS query log with per-client statistics.
pub struct DeviceTracker {
    entries: RwLock<VecDeque<QueryLogEntry>>,
    max_entries: usize,
    next_id: AtomicU64,
}

impl DeviceTracker {
    /// Create a new tracker that retains at most `max_entries` log entries.
    pub fn new(max_entries: usize) -> Arc<Self> {
        Arc::new(Self {
            entries: RwLock::new(VecDeque::new()),
            max_entries,
            next_id: AtomicU64::new(1),
        })
    }

    /// Record a DNS query from a client.
    pub fn log_query(&self, client_ip: &str, domain: &str, query_type: &str, blocked: bool) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entry = QueryLogEntry {
            id,
            client_ip: client_ip.to_string(),
            domain: domain.to_ascii_lowercase(),
            query_type: query_type.to_string(),
            timestamp,
            blocked,
        };

        let mut entries = self.entries.write();
        if entries.len() >= self.max_entries {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Return the most recent log entries, newest first.
    ///
    /// Optionally filter to a single `client_ip`.
    pub fn get_log(&self, limit: usize, client_filter: Option<&str>) -> Vec<QueryLogEntry> {
        let entries = self.entries.read();
        entries
            .iter()
            .rev()
            .filter(|e| client_filter.map_or(true, |ip| e.client_ip == ip))
            .take(limit)
            .cloned()
            .collect()
    }

    /// Return aggregate statistics for every client IP seen.
    pub fn get_clients(&self) -> Vec<ClientStats> {
        let entries = self.entries.read();

        // ip → (total, blocked, domain_counts, last_seen)
        let mut map: HashMap<String, (u64, u64, HashMap<String, u64>, u64)> = HashMap::new();

        for entry in entries.iter() {
            let rec = map
                .entry(entry.client_ip.clone())
                .or_insert((0, 0, HashMap::new(), 0));
            rec.0 += 1;
            if entry.blocked {
                rec.1 += 1;
            }
            *rec.2.entry(entry.domain.clone()).or_insert(0) += 1;
            if entry.timestamp > rec.3 {
                rec.3 = entry.timestamp;
            }
        }

        let mut clients: Vec<ClientStats> = map
            .into_iter()
            .map(|(ip, (count, blocked, domains, last_seen))| {
                let mut top: Vec<(String, u64)> = domains.into_iter().collect();
                top.sort_by(|a, b| b.1.cmp(&a.1));
                top.truncate(10);
                ClientStats {
                    client_ip: ip,
                    query_count: count,
                    blocked_count: blocked,
                    top_domains: top,
                    last_seen,
                }
            })
            .collect();

        clients.sort_by(|a, b| b.query_count.cmp(&a.query_count));
        clients
    }

    /// Total number of entries currently in the ring buffer.
    pub fn total_entries(&self) -> u64 {
        self.entries.read().len() as u64
    }

    /// All entries with a timestamp ≥ `since` (unix seconds).
    pub fn queries_since(&self, since: u64) -> Vec<QueryLogEntry> {
        let entries = self.entries.read();
        entries
            .iter()
            .filter(|e| e.timestamp >= since)
            .cloned()
            .collect()
    }

    /// Top blocked domains across all clients (limit results to `n`).
    pub fn top_blocked_domains(&self, n: usize) -> Vec<(String, u64)> {
        let entries = self.entries.read();
        let mut counts: HashMap<String, u64> = HashMap::new();
        for entry in entries.iter().filter(|e| e.blocked) {
            *counts.entry(entry.domain.clone()).or_insert(0) += 1;
        }
        let mut sorted: Vec<(String, u64)> = counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(n);
        sorted
    }

    /// Query volume bucketed by hour for the last `hours` hours.
    ///
    /// Returns a `Vec` of `(hour_start_timestamp, count)` pairs, oldest first.
    pub fn timeline_by_hour(&self, hours: u64) -> Vec<(u64, u64)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let window_start = now.saturating_sub(hours * 3600);

        // Align to hour boundaries
        let first_bucket = (window_start / 3600) * 3600;
        let bucket_count = hours as usize + 1;

        let mut buckets = vec![0u64; bucket_count];
        let entries = self.entries.read();

        for entry in entries.iter().filter(|e| e.timestamp >= window_start) {
            let bucket_idx = ((entry.timestamp / 3600) * 3600)
                .saturating_sub(first_bucket) / 3600;
            if (bucket_idx as usize) < bucket_count {
                buckets[bucket_idx as usize] += 1;
            }
        }

        (0..bucket_count)
            .map(|i| (first_bucket + i as u64 * 3600, buckets[i]))
            .collect()
    }
}
