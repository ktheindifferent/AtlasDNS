//! DNS Latency Analytics Module
//!
//! Tracks per-query response times in microseconds, computes percentile
//! latencies (p50/p95/p99) broken down by query type and resolver source
//! (cache hit vs upstream), and records per-upstream-server health stats.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

/// Maximum number of latency samples to retain per bucket.
const MAX_SAMPLES: usize = 10_000;

/// Aggregated percentile stats returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PercentileStats {
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
    pub min: u64,
    pub max: u64,
    pub count: u64,
    pub avg: u64,
}

/// Latency breakdown by query type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryTypeLatency {
    pub query_type: String,
    pub stats: PercentileStats,
}

/// Latency breakdown by resolver source (cache vs upstream).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverLatency {
    pub resolver: String, // "cache_hit" or "upstream"
    pub stats: PercentileStats,
}

/// Full latency stats response for GET /api/v1/stats/latency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStatsResponse {
    pub overall: PercentileStats,
    pub by_query_type: Vec<QueryTypeLatency>,
    pub by_resolver: Vec<ResolverLatency>,
}

/// Per-upstream server health stats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamStats {
    pub server: String,
    pub avg_latency_us: u64,
    pub total_queries: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub success_rate: f64,
    pub last_error: Option<String>,
    pub last_error_time: Option<String>,
}

/// Full upstream stats response for GET /api/v1/stats/upstream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamStatsResponse {
    pub upstreams: Vec<UpstreamStats>,
}

/// Internal mutable state for upstream tracking.
struct UpstreamState {
    latencies: Vec<u64>,
    success_count: u64,
    failure_count: u64,
    last_error: Option<String>,
    last_error_time: Option<Instant>,
}

impl UpstreamState {
    fn new() -> Self {
        Self {
            latencies: Vec::new(),
            success_count: 0,
            failure_count: 0,
            last_error: None,
            last_error_time: None,
        }
    }
}

/// Thread-safe latency tracker collecting per-query response times.
pub struct LatencyTracker {
    /// All samples (ring buffer style).
    all_samples: RwLock<Vec<u64>>,
    /// Per-query-type samples.
    by_query_type: RwLock<HashMap<String, Vec<u64>>>,
    /// Cache-hit samples.
    cache_samples: RwLock<Vec<u64>>,
    /// Upstream (non-cache) samples.
    upstream_samples: RwLock<Vec<u64>>,
    /// Per-upstream-server state.
    upstream_state: RwLock<HashMap<String, UpstreamState>>,
}

impl LatencyTracker {
    pub fn new() -> Self {
        Self {
            all_samples: RwLock::new(Vec::with_capacity(MAX_SAMPLES)),
            by_query_type: RwLock::new(HashMap::new()),
            cache_samples: RwLock::new(Vec::with_capacity(MAX_SAMPLES)),
            upstream_samples: RwLock::new(Vec::with_capacity(MAX_SAMPLES)),
            upstream_state: RwLock::new(HashMap::new()),
        }
    }

    /// Record a query latency.
    ///
    /// * `response_time_us` – response time in microseconds
    /// * `query_type` – e.g. "A", "AAAA", "MX"
    /// * `cache_hit` – whether the response came from cache
    /// * `upstream_server` – upstream server address if used (e.g. "8.8.8.8:53")
    pub fn record(
        &self,
        response_time_us: u64,
        query_type: &str,
        cache_hit: bool,
        upstream_server: Option<&str>,
    ) {
        // All samples
        push_sample(&self.all_samples, response_time_us);

        // By query type
        {
            let mut map = self.by_query_type.write().unwrap();
            let v = map.entry(query_type.to_string()).or_insert_with(|| Vec::with_capacity(MAX_SAMPLES));
            if v.len() >= MAX_SAMPLES {
                v.drain(..MAX_SAMPLES / 2);
            }
            v.push(response_time_us);
        }

        // By resolver source
        if cache_hit {
            push_sample(&self.cache_samples, response_time_us);
        } else {
            push_sample(&self.upstream_samples, response_time_us);
        }

        // Per-upstream tracking
        if let Some(server) = upstream_server {
            let mut map = self.upstream_state.write().unwrap();
            let state = map.entry(server.to_string()).or_insert_with(UpstreamState::new);
            if state.latencies.len() >= MAX_SAMPLES {
                state.latencies.drain(..MAX_SAMPLES / 2);
            }
            state.latencies.push(response_time_us);
            state.success_count += 1;
        }
    }

    /// Record an upstream failure.
    pub fn record_upstream_failure(&self, server: &str, error: &str) {
        let mut map = self.upstream_state.write().unwrap();
        let state = map.entry(server.to_string()).or_insert_with(UpstreamState::new);
        state.failure_count += 1;
        state.last_error = Some(error.to_string());
        state.last_error_time = Some(Instant::now());
    }

    /// Compute full latency stats for the API.
    pub fn get_latency_stats(&self) -> LatencyStatsResponse {
        let overall = compute_percentiles(&self.all_samples.read().unwrap());

        let by_query_type = {
            let map = self.by_query_type.read().unwrap();
            let mut result: Vec<QueryTypeLatency> = map.iter().map(|(qt, samples)| {
                QueryTypeLatency {
                    query_type: qt.clone(),
                    stats: compute_percentiles(samples),
                }
            }).collect();
            result.sort_by(|a, b| a.query_type.cmp(&b.query_type));
            result
        };

        let by_resolver = {
            let mut resolvers = Vec::new();
            let cache = self.cache_samples.read().unwrap();
            if !cache.is_empty() {
                resolvers.push(ResolverLatency {
                    resolver: "cache_hit".to_string(),
                    stats: compute_percentiles(&cache),
                });
            }
            let upstream = self.upstream_samples.read().unwrap();
            if !upstream.is_empty() {
                resolvers.push(ResolverLatency {
                    resolver: "upstream".to_string(),
                    stats: compute_percentiles(&upstream),
                });
            }
            resolvers
        };

        LatencyStatsResponse {
            overall,
            by_query_type,
            by_resolver,
        }
    }

    /// Compute per-upstream stats for the API.
    pub fn get_upstream_stats(&self) -> UpstreamStatsResponse {
        let map = self.upstream_state.read().unwrap();
        let mut upstreams: Vec<UpstreamStats> = map.iter().map(|(server, state)| {
            let total = state.success_count + state.failure_count;
            let avg = if state.latencies.is_empty() {
                0
            } else {
                state.latencies.iter().sum::<u64>() / state.latencies.len() as u64
            };
            let success_rate = if total > 0 {
                state.success_count as f64 / total as f64
            } else {
                1.0
            };
            let last_error_time_str = state.last_error_time.map(|t| {
                let elapsed = t.elapsed();
                format!("{}s ago", elapsed.as_secs())
            });
            UpstreamStats {
                server: server.clone(),
                avg_latency_us: avg,
                total_queries: total,
                success_count: state.success_count,
                failure_count: state.failure_count,
                success_rate,
                last_error: state.last_error.clone(),
                last_error_time: last_error_time_str,
            }
        }).collect();
        upstreams.sort_by(|a, b| a.server.cmp(&b.server));
        UpstreamStatsResponse { upstreams }
    }

    /// Return histogram buckets for the dashboard (ASCII chart data).
    /// Returns (bucket_label, count) pairs.
    pub fn get_histogram_buckets(&self) -> Vec<(String, u64)> {
        let samples = self.all_samples.read().unwrap();
        if samples.is_empty() {
            return Vec::new();
        }

        // Fixed buckets in microseconds
        let bucket_edges: &[(u64, &str)] = &[
            (100, "<0.1ms"),
            (500, "0.1-0.5ms"),
            (1_000, "0.5-1ms"),
            (5_000, "1-5ms"),
            (10_000, "5-10ms"),
            (50_000, "10-50ms"),
            (100_000, "50-100ms"),
            (500_000, "100-500ms"),
            (u64::MAX, ">500ms"),
        ];

        let mut counts = vec![0u64; bucket_edges.len()];
        for &val in samples.iter() {
            for (i, &(edge, _)) in bucket_edges.iter().enumerate() {
                if val <= edge {
                    counts[i] += 1;
                    break;
                }
            }
        }

        bucket_edges.iter().zip(counts.iter())
            .map(|(&(_, label), &count)| (label.to_string(), count))
            .collect()
    }
}

impl Default for LatencyTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Push a sample into a ring-buffer-style vec.
fn push_sample(lock: &RwLock<Vec<u64>>, val: u64) {
    let mut v = lock.write().unwrap();
    if v.len() >= MAX_SAMPLES {
        v.drain(..MAX_SAMPLES / 2);
    }
    v.push(val);
}

/// Compute p50/p95/p99/min/max/count/avg from a slice of microsecond values.
fn compute_percentiles(samples: &[u64]) -> PercentileStats {
    if samples.is_empty() {
        return PercentileStats {
            p50: 0, p95: 0, p99: 0, min: 0, max: 0, count: 0, avg: 0,
        };
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let n = sorted.len();
    let sum: u64 = sorted.iter().sum();
    PercentileStats {
        p50: sorted[n * 50 / 100],
        p95: sorted[n * 95 / 100],
        p99: sorted[n.saturating_sub(1).min(n * 99 / 100)],
        min: sorted[0],
        max: sorted[n - 1],
        count: n as u64,
        avg: sum / n as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_tracking() {
        let tracker = LatencyTracker::new();
        tracker.record(100, "A", false, Some("8.8.8.8:53"));
        tracker.record(200, "A", true, None);
        tracker.record(300, "AAAA", false, Some("1.1.1.1:53"));

        let stats = tracker.get_latency_stats();
        assert_eq!(stats.overall.count, 3);
        assert_eq!(stats.by_query_type.len(), 2);
        assert_eq!(stats.by_resolver.len(), 2); // cache_hit + upstream
    }

    #[test]
    fn test_upstream_stats() {
        let tracker = LatencyTracker::new();
        tracker.record(500, "A", false, Some("8.8.8.8:53"));
        tracker.record(600, "A", false, Some("8.8.8.8:53"));
        tracker.record_upstream_failure("8.8.8.8:53", "timeout");

        let stats = tracker.get_upstream_stats();
        assert_eq!(stats.upstreams.len(), 1);
        assert_eq!(stats.upstreams[0].success_count, 2);
        assert_eq!(stats.upstreams[0].failure_count, 1);
        assert_eq!(stats.upstreams[0].last_error.as_deref(), Some("timeout"));
    }

    #[test]
    fn test_percentiles() {
        let vals: Vec<u64> = (1..=100).collect();
        let stats = compute_percentiles(&vals);
        assert_eq!(stats.p50, 51); // index 50 in 0-based sorted [1..=100]
        assert_eq!(stats.p95, 96);
        assert_eq!(stats.min, 1);
        assert_eq!(stats.max, 100);
        assert_eq!(stats.count, 100);
    }

    #[test]
    fn test_histogram_buckets() {
        let tracker = LatencyTracker::new();
        tracker.record(50, "A", false, None);      // <0.1ms
        tracker.record(300, "A", false, None);      // 0.1-0.5ms
        tracker.record(5000, "A", false, None);     // 1-5ms
        tracker.record(1_000_000, "A", false, None); // >500ms

        let buckets = tracker.get_histogram_buckets();
        assert!(!buckets.is_empty());
    }
}
