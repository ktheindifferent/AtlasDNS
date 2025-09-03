//! Health Check Analytics
//!
//! Comprehensive health monitoring with uptime tracking, latency analysis,
//! and failure pattern detection for DNS endpoints.
//!
//! # Features
//!
//! * **Uptime Monitoring** - Track availability percentages
//! * **Latency Analysis** - Response time percentiles and trends
//! * **Failure Pattern Detection** - Identify recurring issues
//! * **Health Scoring** - Composite health metrics
//! * **Trend Analysis** - Historical health patterns
//! * **Predictive Alerting** - Forecast potential failures
//! * **SLA Tracking** - Service level agreement monitoring

use std::sync::Arc;
use std::collections::{HashMap, VecDeque, BTreeMap};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Enable health check analytics
    pub enabled: bool,
    /// Check interval
    pub check_interval: Duration,
    /// Check timeout
    pub check_timeout: Duration,
    /// Failure threshold
    pub failure_threshold: u32,
    /// Success threshold
    pub success_threshold: u32,
    /// History retention (hours)
    pub history_retention_hours: u32,
    /// Enable predictive analytics
    pub predictive_analytics: bool,
    /// SLA targets
    pub sla_targets: SlaTargets,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval: Duration::from_secs(30),
            check_timeout: Duration::from_secs(5),
            failure_threshold: 3,
            success_threshold: 2,
            history_retention_hours: 168, // 7 days
            predictive_analytics: true,
            sla_targets: SlaTargets::default(),
        }
    }
}

/// SLA target configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaTargets {
    /// Uptime percentage target
    pub uptime_target: f64,
    /// Response time target (ms)
    pub response_time_target_ms: f64,
    /// Success rate target
    pub success_rate_target: f64,
    /// Measurement window
    pub measurement_window: Duration,
}

impl Default for SlaTargets {
    fn default() -> Self {
        Self {
            uptime_target: 99.9,
            response_time_target_ms: 100.0,
            success_rate_target: 99.5,
            measurement_window: Duration::from_secs(86400), // 24 hours
        }
    }
}

/// Health check endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckEndpoint {
    /// Endpoint ID
    pub id: String,
    /// Endpoint name
    pub name: String,
    /// Target address
    pub target: SocketAddr,
    /// Check type
    pub check_type: CheckType,
    /// Enabled flag
    pub enabled: bool,
    /// Tags
    pub tags: HashMap<String, String>,
    /// Custom check parameters
    pub parameters: HashMap<String, String>,
}

/// Check type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CheckType {
    Dns,
    Http,
    Https,
    Tcp,
    Udp,
    Icmp,
}

/// Health status
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// Endpoint ID
    pub endpoint_id: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Success flag
    pub success: bool,
    /// Response time
    pub response_time: Duration,
    /// Status code (if applicable)
    pub status_code: Option<u16>,
    /// Error message
    pub error: Option<String>,
    /// Additional metrics
    pub metrics: HashMap<String, f64>,
}

/// Endpoint health state
#[derive(Debug, Clone)]
pub struct EndpointHealth {
    /// Current status
    pub status: HealthStatus,
    /// Last check time
    pub last_check: Instant,
    /// Consecutive failures
    pub consecutive_failures: u32,
    /// Consecutive successes
    pub consecutive_successes: u32,
    /// Health score (0-100)
    pub health_score: f64,
    /// Recent results
    pub recent_results: VecDeque<HealthCheckResult>,
    /// Statistics
    pub stats: HealthStatistics,
}

/// Health statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HealthStatistics {
    /// Total checks
    pub total_checks: u64,
    /// Successful checks
    pub successful_checks: u64,
    /// Failed checks
    pub failed_checks: u64,
    /// Uptime percentage
    pub uptime_percentage: f64,
    /// Average response time
    pub avg_response_time_ms: f64,
    /// Response time percentiles
    pub response_time_percentiles: ResponseTimePercentiles,
    /// Failure patterns
    pub failure_patterns: Vec<FailurePattern>,
}

/// Response time percentiles
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseTimePercentiles {
    pub p50: f64,
    pub p90: f64,
    pub p95: f64,
    pub p99: f64,
    pub p999: f64,
}

/// Failure pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailurePattern {
    /// Pattern type
    pub pattern_type: String,
    /// Occurrence count
    pub occurrences: u32,
    /// Time windows
    pub time_windows: Vec<TimeWindow>,
    /// Correlation score
    pub correlation_score: f64,
}

/// Time window for pattern analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    pub start: u64,
    pub end: u64,
    pub failure_count: u32,
}

/// Trend analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendAnalysis {
    /// Trend direction
    pub direction: TrendDirection,
    /// Trend strength (0-1)
    pub strength: f64,
    /// Predicted value
    pub prediction: f64,
    /// Confidence interval
    pub confidence_interval: (f64, f64),
    /// Anomaly score
    pub anomaly_score: f64,
}

/// Trend direction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrendDirection {
    Improving,
    Stable,
    Degrading,
}

/// SLA compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaComplianceReport {
    /// Reporting period
    pub period: TimeWindow,
    /// Uptime compliance
    pub uptime_compliance: ComplianceStatus,
    /// Response time compliance
    pub response_time_compliance: ComplianceStatus,
    /// Success rate compliance
    pub success_rate_compliance: ComplianceStatus,
    /// Overall compliance
    pub overall_compliance: bool,
    /// Violations
    pub violations: Vec<SlaViolation>,
}

/// Compliance status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStatus {
    pub target: f64,
    pub actual: f64,
    pub compliant: bool,
    pub margin: f64,
}

/// SLA violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaViolation {
    pub timestamp: u64,
    pub violation_type: String,
    pub duration: Duration,
    pub severity: String,
}

/// Health check analytics handler
pub struct HealthCheckAnalyticsHandler {
    /// Configuration
    config: Arc<RwLock<HealthCheckConfig>>,
    /// Endpoints
    endpoints: Arc<RwLock<HashMap<String, HealthCheckEndpoint>>>,
    /// Endpoint health states
    health_states: Arc<RwLock<HashMap<String, EndpointHealth>>>,
    /// Historical data
    history: Arc<RwLock<HashMap<String, Vec<HealthCheckResult>>>>,
    /// Trend analyzer
    trend_analyzer: Arc<TrendAnalyzer>,
    /// Pattern detector
    pattern_detector: Arc<PatternDetector>,
}

/// Trend analyzer
struct TrendAnalyzer {
    /// Moving averages
    moving_averages: RwLock<HashMap<String, MovingAverage>>,
    /// Exponential smoothing
    smoothing_alpha: f64,
}

/// Pattern detector
struct PatternDetector {
    /// Pattern templates
    templates: Vec<PatternTemplate>,
    /// Detection threshold
    threshold: f64,
}

/// Pattern template
#[derive(Debug, Clone)]
struct PatternTemplate {
    name: String,
    signature: Vec<bool>,
    min_occurrences: u32,
}

/// Moving average calculator
#[derive(Debug, Clone)]
struct MovingAverage {
    window_size: usize,
    values: VecDeque<f64>,
    sum: f64,
}

impl MovingAverage {
    fn new(window_size: usize) -> Self {
        Self {
            window_size,
            values: VecDeque::with_capacity(window_size),
            sum: 0.0,
        }
    }

    fn add(&mut self, value: f64) {
        if self.values.len() >= self.window_size {
            if let Some(old) = self.values.pop_front() {
                self.sum -= old;
            }
        }
        self.values.push_back(value);
        self.sum += value;
    }

    fn average(&self) -> f64 {
        if self.values.is_empty() {
            0.0
        } else {
            self.sum / self.values.len() as f64
        }
    }
}

impl HealthCheckAnalyticsHandler {
    /// Create new health check analytics handler
    pub fn new(config: HealthCheckConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            health_states: Arc::new(RwLock::new(HashMap::new())),
            history: Arc::new(RwLock::new(HashMap::new())),
            trend_analyzer: Arc::new(TrendAnalyzer {
                moving_averages: RwLock::new(HashMap::new()),
                smoothing_alpha: 0.3,
            }),
            pattern_detector: Arc::new(PatternDetector {
                templates: Self::create_pattern_templates(),
                threshold: 0.8,
            }),
        }
    }

    /// Add endpoint
    pub fn add_endpoint(&self, endpoint: HealthCheckEndpoint) {
        let id = endpoint.id.clone();
        self.endpoints.write().insert(id.clone(), endpoint);
        
        // Initialize health state
        self.health_states.write().insert(id.clone(), EndpointHealth {
            status: HealthStatus::Unknown,
            last_check: Instant::now(),
            consecutive_failures: 0,
            consecutive_successes: 0,
            health_score: 100.0,
            recent_results: VecDeque::with_capacity(100),
            stats: HealthStatistics::default(),
        });
    }

    /// Remove endpoint
    pub fn remove_endpoint(&self, endpoint_id: &str) {
        self.endpoints.write().remove(endpoint_id);
        self.health_states.write().remove(endpoint_id);
        self.history.write().remove(endpoint_id);
    }

    /// Record health check result
    pub fn record_result(&self, result: HealthCheckResult) {
        let config = self.config.read();
        
        if !config.enabled {
            return;
        }

        // Update health state
        self.update_health_state(&result);
        
        // Store in history
        self.store_history(&result);
        
        // Update statistics
        self.update_statistics(&result);
        
        // Detect patterns
        if config.predictive_analytics {
            self.detect_patterns(&result.endpoint_id);
        }
    }

    /// Update health state
    fn update_health_state(&self, result: &HealthCheckResult) {
        let mut states = self.health_states.write();
        let config = self.config.read();
        
        if let Some(state) = states.get_mut(&result.endpoint_id) {
            state.last_check = Instant::now();
            
            if result.success {
                state.consecutive_failures = 0;
                state.consecutive_successes += 1;
                
                if state.consecutive_successes >= config.success_threshold {
                    state.status = HealthStatus::Healthy;
                }
            } else {
                state.consecutive_successes = 0;
                state.consecutive_failures += 1;
                
                if state.consecutive_failures >= config.failure_threshold {
                    state.status = HealthStatus::Unhealthy;
                } else if state.consecutive_failures > 0 {
                    state.status = HealthStatus::Degraded;
                }
            }
            
            // Update health score
            state.health_score = self.calculate_health_score(state);
            
            // Add to recent results
            state.recent_results.push_back(result.clone());
            if state.recent_results.len() > 100 {
                state.recent_results.pop_front();
            }
        }
    }

    /// Calculate health score
    fn calculate_health_score(&self, state: &EndpointHealth) -> f64 {
        let mut score = 100.0;
        
        // Deduct for failures
        score -= (state.consecutive_failures as f64) * 10.0;
        
        // Consider recent success rate
        let recent_success_rate = state.recent_results.iter()
            .filter(|r| r.success)
            .count() as f64 / state.recent_results.len().max(1) as f64;
        score *= recent_success_rate;
        
        // Consider response time
        let avg_response = state.recent_results.iter()
            .map(|r| r.response_time.as_millis() as f64)
            .sum::<f64>() / state.recent_results.len().max(1) as f64;
        
        if avg_response > 1000.0 {
            score *= 0.9; // Penalty for slow responses
        }
        
        score.max(0.0).min(100.0)
    }

    /// Store in history
    fn store_history(&self, result: &HealthCheckResult) {
        let mut history = self.history.write();
        let config = self.config.read();
        
        let endpoint_history = history.entry(result.endpoint_id.clone())
            .or_insert_with(Vec::new);
        
        endpoint_history.push(result.clone());
        
        // Trim old entries
        let cutoff = Utc::now() - chrono::Duration::hours(config.history_retention_hours as i64);
        endpoint_history.retain(|r| r.timestamp > cutoff);
    }

    /// Update statistics
    fn update_statistics(&self, result: &HealthCheckResult) {
        let mut states = self.health_states.write();
        
        if let Some(state) = states.get_mut(&result.endpoint_id) {
            state.stats.total_checks += 1;
            
            if result.success {
                state.stats.successful_checks += 1;
            } else {
                state.stats.failed_checks += 1;
            }
            
            // Update uptime percentage
            state.stats.uptime_percentage = 
                (state.stats.successful_checks as f64 / state.stats.total_checks as f64) * 100.0;
            
            // Update average response time
            let response_ms = result.response_time.as_millis() as f64;
            state.stats.avg_response_time_ms = 
                ((state.stats.avg_response_time_ms * (state.stats.total_checks - 1) as f64) + response_ms) 
                / state.stats.total_checks as f64;
            
            // Update percentiles
            self.update_percentiles(&mut state.stats, &result.endpoint_id);
        }
    }

    /// Update response time percentiles
    fn update_percentiles(&self, stats: &mut HealthStatistics, endpoint_id: &str) {
        let history = self.history.read();
        
        if let Some(endpoint_history) = history.get(endpoint_id) {
            let mut response_times: Vec<f64> = endpoint_history.iter()
                .map(|r| r.response_time.as_millis() as f64)
                .collect();
            
            response_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
            
            let len = response_times.len();
            if len > 0 {
                stats.response_time_percentiles = ResponseTimePercentiles {
                    p50: response_times[len * 50 / 100],
                    p90: response_times[len * 90 / 100],
                    p95: response_times[len * 95 / 100],
                    p99: response_times[len * 99 / 100],
                    p999: response_times[len.min(len * 999 / 1000)],
                };
            }
        }
    }

    /// Detect failure patterns
    fn detect_patterns(&self, endpoint_id: &str) {
        let history = self.history.read();
        
        if let Some(endpoint_history) = history.get(endpoint_id) {
            let patterns = self.pattern_detector.detect(endpoint_history);
            
            let mut states = self.health_states.write();
            if let Some(state) = states.get_mut(endpoint_id) {
                state.stats.failure_patterns = patterns;
            }
        }
    }

    /// Analyze trends
    pub fn analyze_trends(&self, endpoint_id: &str) -> Option<TrendAnalysis> {
        let history = self.history.read();
        
        history.get(endpoint_id).map(|endpoint_history| {
            self.trend_analyzer.analyze(endpoint_history)
        })
    }

    /// Get SLA compliance report
    pub fn get_sla_compliance(&self, endpoint_id: &str) -> Option<SlaComplianceReport> {
        let states = self.health_states.read();
        let config = self.config.read();
        
        states.get(endpoint_id).map(|state| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            let period = TimeWindow {
                start: now - config.sla_targets.measurement_window.as_secs(),
                end: now,
                failure_count: state.stats.failed_checks as u32,
            };
            
            let uptime_compliance = ComplianceStatus {
                target: config.sla_targets.uptime_target,
                actual: state.stats.uptime_percentage,
                compliant: state.stats.uptime_percentage >= config.sla_targets.uptime_target,
                margin: state.stats.uptime_percentage - config.sla_targets.uptime_target,
            };
            
            let response_time_compliance = ComplianceStatus {
                target: config.sla_targets.response_time_target_ms,
                actual: state.stats.avg_response_time_ms,
                compliant: state.stats.avg_response_time_ms <= config.sla_targets.response_time_target_ms,
                margin: config.sla_targets.response_time_target_ms - state.stats.avg_response_time_ms,
            };
            
            let success_rate = (state.stats.successful_checks as f64 / state.stats.total_checks.max(1) as f64) * 100.0;
            let success_rate_compliance = ComplianceStatus {
                target: config.sla_targets.success_rate_target,
                actual: success_rate,
                compliant: success_rate >= config.sla_targets.success_rate_target,
                margin: success_rate - config.sla_targets.success_rate_target,
            };
            
            SlaComplianceReport {
                period,
                uptime_compliance: uptime_compliance.clone(),
                response_time_compliance: response_time_compliance.clone(),
                success_rate_compliance: success_rate_compliance.clone(),
                overall_compliance: uptime_compliance.compliant && 
                    response_time_compliance.compliant && 
                    success_rate_compliance.compliant,
                violations: Vec::new(), // Would track actual violations
            }
        })
    }

    /// Get endpoint health
    pub fn get_endpoint_health(&self, endpoint_id: &str) -> Option<EndpointHealth> {
        self.health_states.read().get(endpoint_id).cloned()
    }

    /// Get all endpoint health states
    pub fn get_all_health_states(&self) -> HashMap<String, HealthStatus> {
        self.health_states.read()
            .iter()
            .map(|(id, state)| (id.clone(), state.status))
            .collect()
    }

    /// Create pattern templates
    fn create_pattern_templates() -> Vec<PatternTemplate> {
        vec![
            PatternTemplate {
                name: "Periodic Failure".to_string(),
                signature: vec![true, false, false, true, false, false],
                min_occurrences: 3,
            },
            PatternTemplate {
                name: "Cascading Failure".to_string(),
                signature: vec![false, false, false, false, false, true],
                min_occurrences: 2,
            },
            PatternTemplate {
                name: "Flapping".to_string(),
                signature: vec![true, false, true, false, true, false],
                min_occurrences: 2,
            },
        ]
    }
}

impl TrendAnalyzer {
    /// Analyze trends in health data
    fn analyze(&self, history: &[HealthCheckResult]) -> TrendAnalysis {
        let mut ma = self.moving_averages.write();
        let key = "response_time";
        
        let moving_avg = ma.entry(key.to_string())
            .or_insert_with(|| MovingAverage::new(20));
        
        // Calculate trend
        let recent_avg = history.iter()
            .rev()
            .take(10)
            .map(|r| r.response_time.as_millis() as f64)
            .sum::<f64>() / 10.0;
        
        moving_avg.add(recent_avg);
        let long_term_avg = moving_avg.average();
        
        let direction = if recent_avg < long_term_avg * 0.9 {
            TrendDirection::Improving
        } else if recent_avg > long_term_avg * 1.1 {
            TrendDirection::Degrading
        } else {
            TrendDirection::Stable
        };
        
        let strength = ((recent_avg - long_term_avg).abs() / long_term_avg).min(1.0);
        
        TrendAnalysis {
            direction,
            strength,
            prediction: recent_avg + (recent_avg - long_term_avg) * self.smoothing_alpha,
            confidence_interval: (recent_avg * 0.8, recent_avg * 1.2),
            anomaly_score: 0.0, // Would calculate actual anomaly score
        }
    }
}

impl PatternDetector {
    /// Detect patterns in health check results
    fn detect(&self, history: &[HealthCheckResult]) -> Vec<FailurePattern> {
        let mut patterns = Vec::new();
        
        // Convert to success/failure sequence
        let sequence: Vec<bool> = history.iter()
            .map(|r| !r.success)
            .collect();
        
        // Check each template
        for template in &self.templates {
            let occurrences = self.count_pattern_occurrences(&sequence, &template.signature);
            
            if occurrences >= template.min_occurrences {
                patterns.push(FailurePattern {
                    pattern_type: template.name.clone(),
                    occurrences,
                    time_windows: Vec::new(),
                    correlation_score: occurrences as f64 / sequence.len() as f64,
                });
            }
        }
        
        patterns
    }

    /// Count pattern occurrences
    fn count_pattern_occurrences(&self, sequence: &[bool], pattern: &[bool]) -> u32 {
        if sequence.len() < pattern.len() {
            return 0;
        }
        
        let mut count = 0;
        for i in 0..=(sequence.len() - pattern.len()) {
            if sequence[i..i + pattern.len()] == *pattern {
                count += 1;
            }
        }
        
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_score_calculation() {
        let handler = HealthCheckAnalyticsHandler::new(HealthCheckConfig::default());
        
        let endpoint = HealthCheckEndpoint {
            id: "test".to_string(),
            name: "Test Endpoint".to_string(),
            target: "127.0.0.1:53".parse().unwrap(),
            check_type: CheckType::Dns,
            enabled: true,
            tags: HashMap::new(),
            parameters: HashMap::new(),
        };
        
        handler.add_endpoint(endpoint);
        
        // Record successful check
        handler.record_result(HealthCheckResult {
            endpoint_id: "test".to_string(),
            timestamp: chrono::Utc::now(),
            success: true,
            response_time: Duration::from_millis(50),
            status_code: None,
            error: None,
            metrics: HashMap::new(),
        });
        
        let health = handler.get_endpoint_health("test").unwrap();
        assert_eq!(health.status, HealthStatus::Unknown); // Need more checks for status change
        assert!(health.health_score > 0.0);
    }

    #[test]
    fn test_pattern_detection() {
        let detector = PatternDetector {
            templates: vec![
                PatternTemplate {
                    name: "Test Pattern".to_string(),
                    signature: vec![true, false, true],
                    min_occurrences: 1,
                }
            ],
            threshold: 0.5,
        };
        
        let history = vec![
            HealthCheckResult {
                endpoint_id: "test".to_string(),
                timestamp: chrono::Utc::now(),
                success: false,
                response_time: Duration::from_millis(100),
                status_code: None,
                error: None,
                metrics: HashMap::new(),
            },
            HealthCheckResult {
                endpoint_id: "test".to_string(),
                timestamp: chrono::Utc::now(),
                success: true,
                response_time: Duration::from_millis(50),
                status_code: None,
                error: None,
                metrics: HashMap::new(),
            },
            HealthCheckResult {
                endpoint_id: "test".to_string(),
                timestamp: chrono::Utc::now(),
                success: false,
                response_time: Duration::from_millis(100),
                status_code: None,
                error: None,
                metrics: HashMap::new(),
            },
        ];
        
        let patterns = detector.detect(&history);
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].pattern_type, "Test Pattern");
    }
}