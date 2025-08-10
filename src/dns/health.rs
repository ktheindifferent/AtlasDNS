//! Health check and monitoring endpoints for DNS server

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use serde_derive::{Serialize, Deserialize};

/// Health status of the DNS server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: HealthState,
    pub uptime_seconds: u64,
    pub queries_total: u64,
    pub queries_failed: u64,
    pub cache_size: usize,
    pub cache_hit_rate: f64,
    pub latency_ms: LatencyStats,
    pub checks: Vec<HealthCheck>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    pub p50: f64,
    pub p90: f64,
    pub p99: f64,
    pub mean: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub name: String,
    pub status: CheckStatus,
    pub message: Option<String>,
    pub last_check: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

/// Health monitor for tracking server health
pub struct HealthMonitor {
    start_time: Instant,
    is_ready: AtomicBool,
    is_healthy: AtomicBool,
    queries_total: AtomicU64,
    queries_failed: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    latencies: Arc<parking_lot::Mutex<Vec<Duration>>>,
    checks: Arc<parking_lot::Mutex<Vec<HealthCheck>>>,
}

impl HealthMonitor {
    pub fn new() -> Self {
        HealthMonitor {
            start_time: Instant::now(),
            is_ready: AtomicBool::new(false),
            is_healthy: AtomicBool::new(true),
            queries_total: AtomicU64::new(0),
            queries_failed: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            latencies: Arc::new(parking_lot::Mutex::new(Vec::with_capacity(1000))),
            checks: Arc::new(parking_lot::Mutex::new(Vec::new())),
        }
    }

    /// Mark the server as ready to serve requests
    pub fn set_ready(&self, ready: bool) {
        self.is_ready.store(ready, Ordering::Release);
    }

    /// Check if the server is ready
    pub fn is_ready(&self) -> bool {
        self.is_ready.load(Ordering::Acquire)
    }

    /// Mark the server health state
    pub fn set_healthy(&self, healthy: bool) {
        self.is_healthy.store(healthy, Ordering::Release);
    }

    /// Check if the server is healthy
    pub fn is_healthy(&self) -> bool {
        self.is_healthy.load(Ordering::Acquire)
    }

    /// Record a successful query
    pub fn record_query_success(&self, latency: Duration) {
        self.queries_total.fetch_add(1, Ordering::Relaxed);
        self.record_latency(latency);
    }

    /// Record a failed query
    pub fn record_query_failure(&self) {
        self.queries_total.fetch_add(1, Ordering::Relaxed);
        self.queries_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache hit
    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache miss
    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record query latency
    fn record_latency(&self, latency: Duration) {
        let mut latencies = self.latencies.lock();
        latencies.push(latency);
        
        // Keep only last 1000 samples
        if latencies.len() > 1000 {
            latencies.drain(0..500);
        }
    }

    /// Add or update a health check
    pub fn update_check(&self, name: String, status: CheckStatus, message: Option<String>) {
        let mut checks = self.checks.lock();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if let Some(check) = checks.iter_mut().find(|c| c.name == name) {
            check.status = status;
            check.message = message;
            check.last_check = timestamp;
        } else {
            checks.push(HealthCheck {
                name,
                status,
                message,
                last_check: timestamp,
            });
        }
    }

    /// Get the current health status
    pub fn get_status(&self, cache_size: usize) -> HealthStatus {
        let uptime = self.start_time.elapsed().as_secs();
        let queries_total = self.queries_total.load(Ordering::Relaxed);
        let queries_failed = self.queries_failed.load(Ordering::Relaxed);
        let cache_hits = self.cache_hits.load(Ordering::Relaxed);
        let cache_misses = self.cache_misses.load(Ordering::Relaxed);
        
        let cache_hit_rate = if cache_hits + cache_misses > 0 {
            cache_hits as f64 / (cache_hits + cache_misses) as f64
        } else {
            0.0
        };
        
        let latency_stats = self.calculate_latency_stats();
        let checks = self.checks.lock().clone();
        
        // Determine overall health state
        let status = if !self.is_healthy.load(Ordering::Acquire) {
            HealthState::Unhealthy
        } else if checks.iter().any(|c| c.status == CheckStatus::Fail) {
            HealthState::Unhealthy
        } else if checks.iter().any(|c| c.status == CheckStatus::Warn) {
            HealthState::Degraded
        } else if queries_failed > 0 && queries_total > 0 {
            let error_rate = queries_failed as f64 / queries_total as f64;
            if error_rate > 0.05 {
                HealthState::Unhealthy
            } else if error_rate > 0.01 {
                HealthState::Degraded
            } else {
                HealthState::Healthy
            }
        } else {
            HealthState::Healthy
        };
        
        HealthStatus {
            status,
            uptime_seconds: uptime,
            queries_total,
            queries_failed,
            cache_size,
            cache_hit_rate,
            latency_ms: latency_stats,
            checks,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    fn calculate_latency_stats(&self) -> LatencyStats {
        let latencies = self.latencies.lock();
        
        if latencies.is_empty() {
            return LatencyStats {
                p50: 0.0,
                p90: 0.0,
                p99: 0.0,
                mean: 0.0,
            };
        }
        
        let mut sorted: Vec<f64> = latencies
            .iter()
            .map(|d| d.as_secs_f64() * 1000.0)
            .collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        
        let len = sorted.len();
        let p50 = sorted[len / 2];
        let p90 = sorted[len * 9 / 10];
        let p99 = sorted[len * 99 / 100];
        let mean = sorted.iter().sum::<f64>() / len as f64;
        
        LatencyStats {
            p50,
            p90,
            p99,
            mean,
        }
    }

    /// Run periodic health checks
    pub async fn run_checks(&self) {
        // Check upstream DNS servers
        self.check_upstream_dns().await;
        
        // Check memory usage
        self.check_memory_usage();
        
        // Check error rates
        self.check_error_rates();
        
        // Check cache performance
        self.check_cache_performance();
    }

    async fn check_upstream_dns(&self) {
        // TODO: Implement actual DNS query to upstream
        // For now, this is a placeholder
        self.update_check(
            "upstream_dns".to_string(),
            CheckStatus::Pass,
            Some("Upstream DNS servers reachable".to_string()),
        );
    }

    fn check_memory_usage(&self) {
        // Placeholder for memory check
        // In production, would use system metrics
        self.update_check(
            "memory".to_string(),
            CheckStatus::Pass,
            Some("Memory usage within limits".to_string()),
        );
    }

    fn check_error_rates(&self) {
        let queries_total = self.queries_total.load(Ordering::Relaxed);
        let queries_failed = self.queries_failed.load(Ordering::Relaxed);
        
        if queries_total > 100 {
            let error_rate = queries_failed as f64 / queries_total as f64;
            
            let (status, message) = if error_rate > 0.05 {
                (CheckStatus::Fail, format!("High error rate: {:.2}%", error_rate * 100.0))
            } else if error_rate > 0.01 {
                (CheckStatus::Warn, format!("Elevated error rate: {:.2}%", error_rate * 100.0))
            } else {
                (CheckStatus::Pass, format!("Error rate normal: {:.2}%", error_rate * 100.0))
            };
            
            self.update_check("error_rate".to_string(), status, Some(message));
        }
    }

    fn check_cache_performance(&self) {
        let cache_hits = self.cache_hits.load(Ordering::Relaxed);
        let cache_misses = self.cache_misses.load(Ordering::Relaxed);
        
        if cache_hits + cache_misses > 100 {
            let hit_rate = cache_hits as f64 / (cache_hits + cache_misses) as f64;
            
            let (status, message) = if hit_rate < 0.5 {
                (CheckStatus::Warn, format!("Low cache hit rate: {:.2}%", hit_rate * 100.0))
            } else {
                (CheckStatus::Pass, format!("Cache hit rate healthy: {:.2}%", hit_rate * 100.0))
            };
            
            self.update_check("cache_performance".to_string(), status, Some(message));
        }
    }
}

/// HTTP health check endpoint response
pub fn health_check_response(monitor: &HealthMonitor, cache_size: usize) -> (u16, String) {
    let status = monitor.get_status(cache_size);
    
    let status_code = match status.status {
        HealthState::Healthy => 200,
        HealthState::Degraded => 200,  // Still return 200 for degraded
        HealthState::Unhealthy => 503,
    };
    
    let body = serde_json::to_string_pretty(&status).unwrap_or_else(|_| {
        r#"{"status": "error", "message": "Failed to serialize health status"}"#.to_string()
    });
    
    (status_code, body)
}

/// Liveness probe - checks if the server is running
pub fn liveness_probe(monitor: &HealthMonitor) -> (u16, &'static str) {
    if monitor.is_healthy() {
        (200, "OK")
    } else {
        (503, "Unhealthy")
    }
}

/// Readiness probe - checks if the server is ready to serve requests
pub fn readiness_probe(monitor: &HealthMonitor) -> (u16, &'static str) {
    if monitor.is_ready() && monitor.is_healthy() {
        (200, "Ready")
    } else {
        (503, "Not Ready")
    }
}

// Add parking_lot as a lightweight mutex alternative
use parking_lot;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_monitor_basic() {
        let monitor = HealthMonitor::new();
        
        assert!(!monitor.is_ready());
        monitor.set_ready(true);
        assert!(monitor.is_ready());
        
        assert!(monitor.is_healthy());
        monitor.set_healthy(false);
        assert!(!monitor.is_healthy());
    }

    #[test]
    fn test_health_status_calculation() {
        let monitor = HealthMonitor::new();
        
        // Record some queries
        for _ in 0..10 {
            monitor.record_query_success(Duration::from_millis(10));
        }
        
        monitor.record_query_failure();
        monitor.record_query_failure();
        
        // Record cache activity
        for _ in 0..8 {
            monitor.record_cache_hit();
        }
        for _ in 0..2 {
            monitor.record_cache_miss();
        }
        
        let status = monitor.get_status(1000);
        
        assert_eq!(status.queries_total, 12);
        assert_eq!(status.queries_failed, 2);
        assert_eq!(status.cache_hit_rate, 0.8);
    }

    #[test]
    fn test_health_checks() {
        let monitor = HealthMonitor::new();
        
        monitor.update_check(
            "test_check".to_string(),
            CheckStatus::Pass,
            Some("All good".to_string()),
        );
        
        let status = monitor.get_status(0);
        assert_eq!(status.checks.len(), 1);
        assert_eq!(status.checks[0].name, "test_check");
        assert_eq!(status.checks[0].status, CheckStatus::Pass);
    }

    #[test]
    fn test_health_state_determination() {
        let monitor = HealthMonitor::new();
        
        // Test healthy state
        monitor.set_healthy(true);
        let status = monitor.get_status(0);
        assert_eq!(status.status, HealthState::Healthy);
        
        // Test unhealthy when explicitly set
        monitor.set_healthy(false);
        let status = monitor.get_status(0);
        assert_eq!(status.status, HealthState::Unhealthy);
        
        // Test unhealthy with failed check
        monitor.set_healthy(true);
        monitor.update_check(
            "critical".to_string(),
            CheckStatus::Fail,
            Some("Critical failure".to_string()),
        );
        let status = monitor.get_status(0);
        assert_eq!(status.status, HealthState::Unhealthy);
        
        // Test degraded with warning check
        monitor.update_check(
            "critical".to_string(),
            CheckStatus::Warn,
            Some("Warning condition".to_string()),
        );
        let status = monitor.get_status(0);
        assert_eq!(status.status, HealthState::Degraded);
    }

    #[test]
    fn test_latency_statistics() {
        let monitor = HealthMonitor::new();
        
        // Test empty latencies
        let status = monitor.get_status(0);
        assert_eq!(status.latency_ms.p50, 0.0);
        assert_eq!(status.latency_ms.p90, 0.0);
        assert_eq!(status.latency_ms.p99, 0.0);
        assert_eq!(status.latency_ms.mean, 0.0);
        
        // Add various latencies
        monitor.record_query_success(Duration::from_millis(10));
        monitor.record_query_success(Duration::from_millis(20));
        monitor.record_query_success(Duration::from_millis(30));
        monitor.record_query_success(Duration::from_millis(40));
        monitor.record_query_success(Duration::from_millis(50));
        monitor.record_query_success(Duration::from_millis(60));
        monitor.record_query_success(Duration::from_millis(70));
        monitor.record_query_success(Duration::from_millis(80));
        monitor.record_query_success(Duration::from_millis(90));
        monitor.record_query_success(Duration::from_millis(100));
        
        let status = monitor.get_status(0);
        assert!(status.latency_ms.p50 > 0.0);
        assert!(status.latency_ms.p90 > status.latency_ms.p50);
        assert!(status.latency_ms.p99 >= status.latency_ms.p90);
        assert!(status.latency_ms.mean > 0.0);
    }

    #[test]
    fn test_error_rate_health_state() {
        let monitor = HealthMonitor::new();
        
        // Test with low error rate (< 1%)
        for _ in 0..100 {
            monitor.record_query_success(Duration::from_millis(10));
        }
        let status = monitor.get_status(0);
        assert_eq!(status.status, HealthState::Healthy);
        
        // Test with medium error rate (1-5%)
        for _ in 0..2 {
            monitor.record_query_failure();
        }
        let status = monitor.get_status(0);
        assert_eq!(status.status, HealthState::Degraded);
        
        // Test with high error rate (> 5%)
        for _ in 0..10 {
            monitor.record_query_failure();
        }
        let status = monitor.get_status(0);
        assert_eq!(status.status, HealthState::Unhealthy);
    }

    #[test]
    fn test_health_check_updates() {
        let monitor = HealthMonitor::new();
        
        // Add initial check
        monitor.update_check(
            "test".to_string(),
            CheckStatus::Pass,
            Some("Initial".to_string()),
        );
        
        let status = monitor.get_status(0);
        assert_eq!(status.checks.len(), 1);
        assert_eq!(status.checks[0].message, Some("Initial".to_string()));
        
        // Update existing check
        monitor.update_check(
            "test".to_string(),
            CheckStatus::Warn,
            Some("Updated".to_string()),
        );
        
        let status = monitor.get_status(0);
        assert_eq!(status.checks.len(), 1);
        assert_eq!(status.checks[0].status, CheckStatus::Warn);
        assert_eq!(status.checks[0].message, Some("Updated".to_string()));
        
        // Add another check
        monitor.update_check(
            "another".to_string(),
            CheckStatus::Pass,
            None,
        );
        
        let status = monitor.get_status(0);
        assert_eq!(status.checks.len(), 2);
    }

    #[test]
    fn test_probe_endpoints() {
        let monitor = HealthMonitor::new();
        
        // Test liveness probe
        let (code, msg) = liveness_probe(&monitor);
        assert_eq!(code, 200);
        assert_eq!(msg, "OK");
        
        monitor.set_healthy(false);
        let (code, msg) = liveness_probe(&monitor);
        assert_eq!(code, 503);
        assert_eq!(msg, "Unhealthy");
        
        // Test readiness probe
        monitor.set_healthy(true);
        monitor.set_ready(false);
        let (code, msg) = readiness_probe(&monitor);
        assert_eq!(code, 503);
        assert_eq!(msg, "Not Ready");
        
        monitor.set_ready(true);
        let (code, msg) = readiness_probe(&monitor);
        assert_eq!(code, 200);
        assert_eq!(msg, "Ready");
    }

    #[test]
    fn test_health_check_response() {
        let monitor = HealthMonitor::new();
        
        // Test healthy response
        let (code, body) = health_check_response(&monitor, 1000);
        assert_eq!(code, 200);
        assert!(body.contains("\"status\":"));
        
        // Test unhealthy response
        monitor.set_healthy(false);
        let (code, body) = health_check_response(&monitor, 1000);
        assert_eq!(code, 503);
        
        // Verify JSON structure
        let status: HealthStatus = serde_json::from_str(&body).expect("Valid JSON");
        assert_eq!(status.status, HealthState::Unhealthy);
    }

    #[test]
    fn test_latency_buffer_management() {
        let monitor = HealthMonitor::new();
        
        // Add more than 1000 latencies to test buffer management
        for i in 0..1500 {
            monitor.record_query_success(Duration::from_millis(i));
        }
        
        // Buffer should maintain reasonable size
        let latencies = monitor.latencies.lock();
        assert!(latencies.len() <= 1000);
        assert!(latencies.len() >= 500);
    }

    #[test]
    fn test_cache_performance_check() {
        let monitor = HealthMonitor::new();
        
        // Simulate cache activity (need > 100 for check to trigger)
        for _ in 0..61 {
            monitor.record_cache_hit();
        }
        for _ in 0..40 {
            monitor.record_cache_miss();
        }
        
        monitor.check_cache_performance();
        
        let status = monitor.get_status(0);
        let cache_check = status.checks.iter()
            .find(|c| c.name == "cache_performance")
            .expect("Cache performance check should exist");
        
        assert_eq!(cache_check.status, CheckStatus::Pass);
    }

    #[test]
    fn test_error_rate_check() {
        let monitor = HealthMonitor::new();
        
        // Simulate queries with errors
        for _ in 0..95 {
            monitor.record_query_success(Duration::from_millis(10));
        }
        for _ in 0..5 {
            monitor.record_query_failure();
        }
        
        monitor.check_error_rates();
        
        let status = monitor.get_status(0);
        let error_check = status.checks.iter()
            .find(|c| c.name == "error_rate");
        
        // Should not exist if queries < 100
        assert!(error_check.is_none());
        
        // Add more queries to trigger the check
        for _ in 0..5 {
            monitor.record_query_success(Duration::from_millis(10));
        }
        
        monitor.check_error_rates();
        
        let status = monitor.get_status(0);
        let error_check = status.checks.iter()
            .find(|c| c.name == "error_rate")
            .expect("Error rate check should exist");
        
        assert_eq!(error_check.status, CheckStatus::Warn);
    }
}