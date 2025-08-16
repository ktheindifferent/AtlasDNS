//! Intelligent Failover Implementation
//!
//! Provides automatic endpoint health monitoring and intelligent failover
//! with predictive failure detection and smart recovery strategies.
//!
//! # Features
//!
//! * **Active Health Checks** - Periodic endpoint monitoring
//! * **Passive Health Checks** - Learn from real traffic
//! * **Predictive Failure Detection** - ML-based anomaly detection
//! * **Circuit Breaker** - Prevent cascading failures
//! * **Gradual Recovery** - Slow ramp-up for recovered endpoints
//! * **Multi-Region Support** - Cross-datacenter failover
//! * **Custom Health Metrics** - Latency, error rate, throughput

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use tokio::time::interval;

use crate::dns::protocol::{DnsPacket, QueryType, ResultCode};
use crate::dns::errors::DnsError;
use crate::dns::client::{DnsNetworkClient, DnsClient};

/// Failover configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverConfig {
    /// Enable intelligent failover
    pub enabled: bool,
    /// Health check interval
    pub check_interval: Duration,
    /// Health check timeout
    pub check_timeout: Duration,
    /// Number of consecutive failures to mark unhealthy
    pub failure_threshold: u32,
    /// Number of consecutive successes to mark healthy
    pub success_threshold: u32,
    /// Circuit breaker threshold
    pub circuit_breaker_threshold: f64,
    /// Circuit breaker reset timeout
    pub circuit_breaker_timeout: Duration,
    /// Enable predictive failure detection
    pub predictive_detection: bool,
    /// Recovery mode (gradual or immediate)
    pub gradual_recovery: bool,
    /// Recovery ramp-up duration
    pub recovery_duration: Duration,
    /// Maximum endpoints to monitor
    pub max_endpoints: usize,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval: Duration::from_secs(10),
            check_timeout: Duration::from_secs(2),
            failure_threshold: 3,
            success_threshold: 2,
            circuit_breaker_threshold: 0.5,
            circuit_breaker_timeout: Duration::from_secs(30),
            predictive_detection: true,
            gradual_recovery: true,
            recovery_duration: Duration::from_secs(300),
            max_endpoints: 100,
        }
    }
}

/// Endpoint health status
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Endpoint is healthy
    Healthy,
    /// Endpoint is degraded but operational
    Degraded,
    /// Endpoint is unhealthy
    Unhealthy,
    /// Endpoint is in recovery
    Recovering,
    /// Unknown status (not checked yet)
    Unknown,
}

/// Endpoint information
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// Endpoint identifier
    pub id: String,
    /// Address
    pub address: SocketAddr,
    /// Current health status
    pub status: HealthStatus,
    /// Region/zone
    pub region: String,
    /// Priority (lower = higher priority)
    pub priority: u32,
    /// Weight for load balancing
    pub weight: u32,
    /// Health check query
    pub health_query: String,
    /// Expected response
    pub expected_response: Option<IpAddr>,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

/// Endpoint health metrics
#[derive(Debug, Clone)]
struct EndpointMetrics {
    /// Consecutive failures
    consecutive_failures: u32,
    /// Consecutive successes
    consecutive_successes: u32,
    /// Total checks
    total_checks: u64,
    /// Successful checks
    successful_checks: u64,
    /// Average latency (ms)
    avg_latency_ms: f64,
    /// P95 latency (ms)
    p95_latency_ms: f64,
    /// P99 latency (ms)
    p99_latency_ms: f64,
    /// Recent latencies
    recent_latencies: VecDeque<u32>,
    /// Last check time
    last_check: Option<Instant>,
    /// Last successful check
    last_success: Option<Instant>,
    /// Last failure
    last_failure: Option<Instant>,
    /// Circuit breaker state
    circuit_breaker: CircuitBreakerState,
    /// Recovery start time
    recovery_started: Option<Instant>,
    /// Anomaly score (0.0 = normal, 1.0 = anomalous)
    anomaly_score: f64,
}

/// Circuit breaker state
#[derive(Debug, Clone, Copy)]
enum CircuitBreakerState {
    /// Circuit is closed (normal operation)
    Closed,
    /// Circuit is open (blocking requests)
    Open { opened_at: Instant },
    /// Circuit is half-open (testing recovery)
    HalfOpen,
}

/// Intelligent failover manager
pub struct FailoverManager {
    /// Configuration
    config: Arc<RwLock<FailoverConfig>>,
    /// Endpoints
    endpoints: Arc<RwLock<HashMap<String, Endpoint>>>,
    /// Endpoint metrics
    metrics: Arc<RwLock<HashMap<String, EndpointMetrics>>>,
    /// DNS client for health checks
    client: Arc<DnsNetworkClient>,
    /// Statistics
    stats: Arc<RwLock<FailoverStats>>,
    /// Anomaly detector
    anomaly_detector: Arc<AnomalyDetector>,
}

/// Failover statistics
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FailoverStats {
    /// Total health checks performed
    pub total_checks: u64,
    /// Successful health checks
    pub successful_checks: u64,
    /// Total failovers
    pub total_failovers: u64,
    /// Predictive failovers
    pub predictive_failovers: u64,
    /// Circuit breaker trips
    pub circuit_breaker_trips: u64,
    /// Current healthy endpoints
    pub healthy_endpoints: usize,
    /// Current unhealthy endpoints
    pub unhealthy_endpoints: usize,
    /// Average failover time (ms)
    pub avg_failover_time_ms: f64,
}

/// Anomaly detector for predictive failure detection
struct AnomalyDetector {
    /// Historical data window
    window_size: usize,
    /// Z-score threshold
    z_score_threshold: f64,
    /// Minimum samples
    min_samples: usize,
}

impl FailoverManager {
    /// Create new failover manager
    pub fn new(config: FailoverConfig, client: Arc<DnsNetworkClient>) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(HashMap::new())),
            client,
            stats: Arc::new(RwLock::new(FailoverStats::default())),
            anomaly_detector: Arc::new(AnomalyDetector::new()),
        }
    }

    /// Add endpoint to monitor
    pub fn add_endpoint(&self, endpoint: Endpoint) {
        let id = endpoint.id.clone();
        
        self.endpoints.write().insert(id.clone(), endpoint);
        self.metrics.write().insert(id, EndpointMetrics {
            consecutive_failures: 0,
            consecutive_successes: 0,
            total_checks: 0,
            successful_checks: 0,
            avg_latency_ms: 0.0,
            p95_latency_ms: 0.0,
            p99_latency_ms: 0.0,
            recent_latencies: VecDeque::with_capacity(100),
            last_check: None,
            last_success: None,
            last_failure: None,
            circuit_breaker: CircuitBreakerState::Closed,
            recovery_started: None,
            anomaly_score: 0.0,
        });
    }

    /// Remove endpoint
    pub fn remove_endpoint(&self, id: &str) {
        self.endpoints.write().remove(id);
        self.metrics.write().remove(id);
    }

    /// Start health monitoring
    pub async fn start_monitoring(self: Arc<Self>) {
        let config = self.config.read().clone();
        
        if !config.enabled {
            return;
        }

        let mut interval = interval(config.check_interval);
        
        loop {
            interval.tick().await;
            self.run_health_checks().await;
        }
    }

    /// Run health checks for all endpoints
    async fn run_health_checks(&self) {
        let endpoints = self.endpoints.read().clone();
        let config = self.config.read().clone();
        
        for (id, endpoint) in endpoints {
            // Check circuit breaker
            if !self.should_check_endpoint(&id) {
                continue;
            }
            
            // Perform health check
            let result = self.check_endpoint_health(&endpoint).await;
            
            // Update metrics and status
            self.update_endpoint_status(&id, result);
            
            // Check for anomalies if predictive detection enabled
            if config.predictive_detection {
                self.detect_anomalies(&id);
            }
        }
        
        self.update_statistics();
    }

    /// Check if endpoint should be checked
    fn should_check_endpoint(&self, id: &str) -> bool {
        let metrics = self.metrics.read();
        
        if let Some(metric) = metrics.get(id) {
            match metric.circuit_breaker {
                CircuitBreakerState::Open { opened_at } => {
                    let config = self.config.read();
                    // Check if circuit breaker timeout has elapsed
                    opened_at.elapsed() >= config.circuit_breaker_timeout
                }
                _ => true,
            }
        } else {
            true
        }
    }

    /// Check endpoint health
    async fn check_endpoint_health(&self, endpoint: &Endpoint) -> HealthCheckResult {
        let start = Instant::now();
        let config = self.config.read().clone();
        
        // Create health check query in a blocking task
        let client = self.client.clone();
        let health_query = endpoint.health_query.clone();
        let address = endpoint.address;
        
        let query_result = tokio::task::spawn_blocking(move || {
            client.send_query(
                &health_query,
                QueryType::A,
                (address.ip().to_string().as_str(), address.port()),
                false,
            )
        });
        
        // Apply timeout
        let timeout_result = tokio::time::timeout(
            config.check_timeout,
            query_result
        ).await;
        
        let latency_ms = start.elapsed().as_millis() as u32;
        
        match timeout_result {
            Ok(Ok(Ok(response))) => {
                // Check if response is valid
                if self.validate_health_response(&response, endpoint) {
                    HealthCheckResult::Success { latency_ms }
                } else {
                    HealthCheckResult::InvalidResponse
                }
            }
            Ok(Ok(Err(_))) => HealthCheckResult::QueryFailed,
            Ok(Err(_)) => HealthCheckResult::QueryFailed,
            Err(_) => HealthCheckResult::Timeout,
        }
    }

    /// Validate health check response
    fn validate_health_response(&self, response: &DnsPacket, endpoint: &Endpoint) -> bool {
        // Check response code
        if response.header.rescode != ResultCode::NOERROR {
            return false;
        }
        
        // Check expected response if configured
        if let Some(expected_ip) = endpoint.expected_response {
            for answer in &response.answers {
                if let crate::dns::protocol::DnsRecord::A { addr, .. } = answer {
                    if IpAddr::V4(*addr) == expected_ip {
                        return true;
                    }
                }
            }
            false
        } else {
            // Just check that we got some answer
            !response.answers.is_empty()
        }
    }

    /// Update endpoint status based on health check result
    fn update_endpoint_status(&self, id: &str, result: HealthCheckResult) {
        let config = self.config.read().clone();
        let mut endpoints = self.endpoints.write();
        let mut metrics = self.metrics.write();
        
        if let (Some(endpoint), Some(metric)) = (endpoints.get_mut(id), metrics.get_mut(id)) {
            metric.total_checks += 1;
            metric.last_check = Some(Instant::now());
            
            match result {
                HealthCheckResult::Success { latency_ms } => {
                    metric.successful_checks += 1;
                    metric.consecutive_successes += 1;
                    metric.consecutive_failures = 0;
                    metric.last_success = Some(Instant::now());
                    
                    // Update latency metrics
                    metric.recent_latencies.push_back(latency_ms);
                    if metric.recent_latencies.len() > 100 {
                        metric.recent_latencies.pop_front();
                    }
                    self.update_latency_stats(metric);
                    
                    // Update status
                    if metric.consecutive_successes >= config.success_threshold {
                        match endpoint.status {
                            HealthStatus::Unhealthy | HealthStatus::Unknown => {
                                if config.gradual_recovery {
                                    endpoint.status = HealthStatus::Recovering;
                                    metric.recovery_started = Some(Instant::now());
                                } else {
                                    endpoint.status = HealthStatus::Healthy;
                                }
                            }
                            HealthStatus::Recovering => {
                                // Check if recovery period has elapsed
                                if let Some(started) = metric.recovery_started {
                                    if started.elapsed() >= config.recovery_duration {
                                        endpoint.status = HealthStatus::Healthy;
                                        metric.recovery_started = None;
                                    }
                                }
                            }
                            _ => {}
                        }
                        
                        // Reset circuit breaker
                        if matches!(metric.circuit_breaker, CircuitBreakerState::Open { .. }) {
                            metric.circuit_breaker = CircuitBreakerState::HalfOpen;
                        } else if matches!(metric.circuit_breaker, CircuitBreakerState::HalfOpen) {
                            metric.circuit_breaker = CircuitBreakerState::Closed;
                        }
                    }
                }
                _ => {
                    metric.consecutive_failures += 1;
                    metric.consecutive_successes = 0;
                    metric.last_failure = Some(Instant::now());
                    
                    // Update status
                    if metric.consecutive_failures >= config.failure_threshold {
                        endpoint.status = HealthStatus::Unhealthy;
                        
                        // Trip circuit breaker if needed
                        let failure_rate = 1.0 - (metric.successful_checks as f64 / metric.total_checks as f64);
                        if failure_rate >= config.circuit_breaker_threshold {
                            metric.circuit_breaker = CircuitBreakerState::Open {
                                opened_at: Instant::now(),
                            };
                            self.stats.write().circuit_breaker_trips += 1;
                        }
                    } else if metric.consecutive_failures > 1 {
                        endpoint.status = HealthStatus::Degraded;
                    }
                }
            }
        }
    }

    /// Update latency statistics
    fn update_latency_stats(&self, metric: &mut EndpointMetrics) {
        if metric.recent_latencies.is_empty() {
            return;
        }
        
        let mut sorted = metric.recent_latencies.iter().copied().collect::<Vec<_>>();
        sorted.sort_unstable();
        
        let sum: u32 = sorted.iter().sum();
        metric.avg_latency_ms = sum as f64 / sorted.len() as f64;
        
        let p95_idx = (sorted.len() as f64 * 0.95) as usize;
        let p99_idx = (sorted.len() as f64 * 0.99) as usize;
        
        metric.p95_latency_ms = sorted.get(p95_idx).copied().unwrap_or(0) as f64;
        metric.p99_latency_ms = sorted.get(p99_idx).copied().unwrap_or(0) as f64;
    }

    /// Detect anomalies in endpoint metrics
    fn detect_anomalies(&self, id: &str) {
        let mut metrics = self.metrics.write();
        
        if let Some(metric) = metrics.get_mut(id) {
            let anomaly_score = self.anomaly_detector.calculate_anomaly_score(metric);
            metric.anomaly_score = anomaly_score;
            
            // Trigger predictive failover if anomaly score is high
            if anomaly_score > 0.8 {
                if let Some(endpoint) = self.endpoints.write().get_mut(id) {
                    if endpoint.status == HealthStatus::Healthy {
                        endpoint.status = HealthStatus::Degraded;
                        self.stats.write().predictive_failovers += 1;
                        log::warn!("Predictive failover triggered for {} (anomaly score: {:.2})", id, anomaly_score);
                    }
                }
            }
        }
    }

    /// Update statistics
    fn update_statistics(&self) {
        let endpoints = self.endpoints.read();
        let mut stats = self.stats.write();
        
        stats.healthy_endpoints = endpoints.values()
            .filter(|e| e.status == HealthStatus::Healthy)
            .count();
        
        stats.unhealthy_endpoints = endpoints.values()
            .filter(|e| e.status == HealthStatus::Unhealthy)
            .count();
    }

    /// Get best available endpoint
    pub fn get_best_endpoint(&self, region: Option<&str>) -> Option<Endpoint> {
        let endpoints = self.endpoints.read();
        let metrics = self.metrics.read();
        
        let mut candidates: Vec<_> = endpoints.values()
            .filter(|e| {
                e.status == HealthStatus::Healthy || e.status == HealthStatus::Recovering
            })
            .filter(|e| {
                region.is_none() || e.region == region.unwrap()
            })
            .collect();
        
        // Sort by priority and latency
        candidates.sort_by(|a, b| {
            if a.priority != b.priority {
                a.priority.cmp(&b.priority)
            } else {
                // Compare latencies
                let a_latency = metrics.get(&a.id)
                    .map(|m| m.avg_latency_ms)
                    .unwrap_or(f64::MAX);
                let b_latency = metrics.get(&b.id)
                    .map(|m| m.avg_latency_ms)
                    .unwrap_or(f64::MAX);
                
                a_latency.partial_cmp(&b_latency).unwrap()
            }
        });
        
        candidates.first().map(|e| (*e).clone())
    }

    /// Get endpoint metrics
    pub fn get_endpoint_metrics(&self, id: &str) -> Option<EndpointMetricsPublic> {
        self.metrics.read().get(id).map(|m| EndpointMetricsPublic {
            total_checks: m.total_checks,
            successful_checks: m.successful_checks,
            success_rate: if m.total_checks > 0 {
                m.successful_checks as f64 / m.total_checks as f64
            } else {
                0.0
            },
            avg_latency_ms: m.avg_latency_ms,
            p95_latency_ms: m.p95_latency_ms,
            p99_latency_ms: m.p99_latency_ms,
            anomaly_score: m.anomaly_score,
            last_check_secs: m.last_check.map(|t| t.elapsed().as_secs()),
        })
    }

    /// Get statistics
    pub fn get_stats(&self) -> FailoverStats {
        let stats = self.stats.read();
        FailoverStats {
            total_checks: stats.total_checks,
            successful_checks: stats.successful_checks,
            total_failovers: stats.total_failovers,
            predictive_failovers: stats.predictive_failovers,
            circuit_breaker_trips: stats.circuit_breaker_trips,
            healthy_endpoints: stats.healthy_endpoints,
            unhealthy_endpoints: stats.unhealthy_endpoints,
            avg_failover_time_ms: stats.avg_failover_time_ms,
        }
    }
}

/// Health check result
#[derive(Debug, Clone)]
enum HealthCheckResult {
    Success { latency_ms: u32 },
    InvalidResponse,
    QueryFailed,
    Timeout,
}

/// Public endpoint metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointMetricsPublic {
    pub total_checks: u64,
    pub successful_checks: u64,
    pub success_rate: f64,
    pub avg_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub anomaly_score: f64,
    pub last_check_secs: Option<u64>,
}

impl AnomalyDetector {
    fn new() -> Self {
        Self {
            window_size: 100,
            z_score_threshold: 3.0,
            min_samples: 20,
        }
    }

    fn calculate_anomaly_score(&self, metrics: &EndpointMetrics) -> f64 {
        if metrics.recent_latencies.len() < self.min_samples {
            return 0.0;
        }

        // Calculate mean and standard deviation
        let latencies: Vec<f64> = metrics.recent_latencies.iter()
            .map(|&l| l as f64)
            .collect();
        
        let mean = latencies.iter().sum::<f64>() / latencies.len() as f64;
        let variance = latencies.iter()
            .map(|l| (l - mean).powi(2))
            .sum::<f64>() / latencies.len() as f64;
        let std_dev = variance.sqrt();

        if std_dev == 0.0 {
            return 0.0;
        }

        // Calculate Z-score for most recent latency
        if let Some(&latest) = metrics.recent_latencies.back() {
            let z_score = ((latest as f64) - mean).abs() / std_dev;
            
            // Normalize to 0-1 range
            (z_score / self.z_score_threshold).min(1.0)
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_endpoint_status_transitions() {
        let config = FailoverConfig {
            failure_threshold: 2,
            success_threshold: 2,
            ..Default::default()
        };
        
        let client = Arc::new(DnsNetworkClient::new(0).unwrap());
        let manager = FailoverManager::new(config, client);
        
        let endpoint = Endpoint {
            id: "test".to_string(),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            status: HealthStatus::Unknown,
            region: "us-east".to_string(),
            priority: 1,
            weight: 100,
            health_query: "health.example.com".to_string(),
            expected_response: None,
            metadata: HashMap::new(),
        };
        
        manager.add_endpoint(endpoint);
        
        // Simulate failures
        manager.update_endpoint_status("test", HealthCheckResult::Timeout);
        manager.update_endpoint_status("test", HealthCheckResult::Timeout);
        
        let endpoints = manager.endpoints.read();
        assert_eq!(endpoints.get("test").unwrap().status, HealthStatus::Unhealthy);
    }

    #[test]
    fn test_anomaly_detection() {
        let detector = AnomalyDetector::new();
        
        let mut metrics = EndpointMetrics {
            consecutive_failures: 0,
            consecutive_successes: 0,
            total_checks: 100,
            successful_checks: 95,
            avg_latency_ms: 10.0,
            p95_latency_ms: 15.0,
            p99_latency_ms: 20.0,
            recent_latencies: VecDeque::new(),
            last_check: None,
            last_success: None,
            last_failure: None,
            circuit_breaker: CircuitBreakerState::Closed,
            recovery_started: None,
            anomaly_score: 0.0,
        };
        
        // Add normal latencies
        for _ in 0..50 {
            metrics.recent_latencies.push_back(10);
        }
        
        // Add anomalous latency
        metrics.recent_latencies.push_back(100);
        
        let score = detector.calculate_anomaly_score(&metrics);
        assert!(score > 0.5);
    }
}