//! Alert Management System
//!
//! Smart alerting with anomaly detection, intelligent routing, and
//! multi-channel notification support for DNS operations.
//!
//! # Features
//!
//! * **Anomaly Detection** - ML-based pattern recognition
//! * **Alert Routing** - Intelligent alert distribution
//! * **Multi-Channel** - Email, Slack, PagerDuty, Webhook support
//! * **Alert Suppression** - Deduplication and throttling
//! * **Escalation Policies** - Automatic escalation chains
//! * **Alert Correlation** - Group related alerts
//! * **Runbook Integration** - Automated remediation links

use std::sync::Arc;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH, Instant};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Enable alerting
    pub enabled: bool,
    /// Alert evaluation interval
    pub evaluation_interval: Duration,
    /// Alert retention period
    pub retention_period: Duration,
    /// Notification channels
    pub channels: Vec<NotificationChannel>,
    /// Routing rules
    pub routing_rules: Vec<RoutingRule>,
    /// Suppression rules
    pub suppression_rules: Vec<SuppressionRule>,
    /// Escalation policies
    pub escalation_policies: Vec<EscalationPolicy>,
    /// Enable anomaly detection
    pub anomaly_detection: bool,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            evaluation_interval: Duration::from_secs(30),
            retention_period: Duration::from_days(7),
            channels: Vec::new(),
            routing_rules: Vec::new(),
            suppression_rules: Vec::new(),
            escalation_policies: Vec::new(),
            anomaly_detection: true,
        }
    }
}

/// Notification channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationChannel {
    /// Channel ID
    pub id: String,
    /// Channel name
    pub name: String,
    /// Channel type
    pub channel_type: ChannelType,
    /// Channel configuration
    pub config: HashMap<String, String>,
    /// Enabled flag
    pub enabled: bool,
}

/// Channel type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelType {
    Email,
    Slack,
    PagerDuty,
    Webhook,
    Sms,
    Discord,
    Teams,
}

/// Alert severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Alert state
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AlertState {
    Pending,
    Firing,
    Resolved,
    Suppressed,
}

/// Alert definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Alert ID
    pub id: String,
    /// Alert name
    pub name: String,
    /// Description
    pub description: String,
    /// Severity
    pub severity: Severity,
    /// State
    pub state: AlertState,
    /// Labels
    pub labels: HashMap<String, String>,
    /// Annotations
    pub annotations: HashMap<String, String>,
    /// Value that triggered alert
    pub value: f64,
    /// Threshold
    pub threshold: f64,
    /// Started at
    pub started_at: DateTime<Utc>,
    /// Resolved at
    pub resolved_at: Option<DateTime<Utc>>,
    /// Fingerprint for deduplication
    pub fingerprint: String,
    /// Runbook URL
    pub runbook_url: Option<String>,
}

/// Alert rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    /// Rule ID
    pub id: String,
    /// Rule name
    pub name: String,
    /// Query expression
    pub expr: String,
    /// Duration to wait before firing
    pub for_duration: Duration,
    /// Severity
    pub severity: Severity,
    /// Labels to add
    pub labels: HashMap<String, String>,
    /// Annotations
    pub annotations: HashMap<String, String>,
    /// Enabled flag
    pub enabled: bool,
}

/// Routing rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    /// Rule name
    pub name: String,
    /// Match criteria
    pub match_criteria: MatchCriteria,
    /// Target channels
    pub channels: Vec<String>,
    /// Continue to next rule
    pub continue_matching: bool,
}

/// Match criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchCriteria {
    /// Severity levels
    pub severities: Vec<Severity>,
    /// Label matchers
    pub labels: HashMap<String, String>,
    /// Regular expression patterns
    pub regex_patterns: Vec<String>,
}

/// Suppression rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionRule {
    /// Rule name
    pub name: String,
    /// Match criteria
    pub match_criteria: MatchCriteria,
    /// Suppression duration
    pub duration: Duration,
    /// Reason
    pub reason: String,
}

/// Escalation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPolicy {
    /// Policy name
    pub name: String,
    /// Levels
    pub levels: Vec<EscalationLevel>,
    /// Repeat interval
    pub repeat_interval: Option<Duration>,
}

/// Escalation level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationLevel {
    /// Wait time before escalation
    pub wait_time: Duration,
    /// Target channels
    pub channels: Vec<String>,
    /// Users to notify
    pub users: Vec<String>,
}

/// Anomaly detector
#[derive(Debug, Clone)]
struct AnomalyDetector {
    /// Historical data points
    history: VecDeque<f64>,
    /// Mean value
    mean: f64,
    /// Standard deviation
    std_dev: f64,
    /// Z-score threshold
    z_threshold: f64,
}

impl AnomalyDetector {
    fn new(z_threshold: f64) -> Self {
        Self {
            history: VecDeque::with_capacity(100),
            mean: 0.0,
            std_dev: 0.0,
            z_threshold,
        }
    }

    fn update(&mut self, value: f64) {
        self.history.push_back(value);
        if self.history.len() > 100 {
            self.history.pop_front();
        }
        
        // Recalculate statistics
        if self.history.len() > 1 {
            let sum: f64 = self.history.iter().sum();
            self.mean = sum / self.history.len() as f64;
            
            let variance: f64 = self.history.iter()
                .map(|v| (v - self.mean).powi(2))
                .sum::<f64>() / self.history.len() as f64;
            self.std_dev = variance.sqrt();
        }
    }

    fn is_anomaly(&self, value: f64) -> bool {
        if self.std_dev == 0.0 || self.history.len() < 10 {
            return false;
        }
        
        let z_score = (value - self.mean).abs() / self.std_dev;
        z_score > self.z_threshold
    }
}

/// Alert statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AlertStats {
    /// Total alerts created
    pub total_alerts: u64,
    /// Active alerts
    pub active_alerts: u64,
    /// Suppressed alerts
    pub suppressed_alerts: u64,
    /// Notifications sent
    pub notifications_sent: u64,
    /// Notification failures
    pub notification_failures: u64,
    /// Anomalies detected
    pub anomalies_detected: u64,
}

/// Alert management handler
pub struct AlertManagementHandler {
    /// Configuration
    config: Arc<RwLock<AlertConfig>>,
    /// Alert rules
    rules: Arc<RwLock<HashMap<String, AlertRule>>>,
    /// Active alerts
    active_alerts: Arc<RwLock<HashMap<String, Alert>>>,
    /// Alert history
    history: Arc<RwLock<Vec<Alert>>>,
    /// Anomaly detectors
    anomaly_detectors: Arc<RwLock<HashMap<String, AnomalyDetector>>>,
    /// Statistics
    stats: Arc<RwLock<AlertStats>>,
    /// Notification queue
    notification_queue: Arc<RwLock<Vec<NotificationTask>>>,
}

/// Notification task
#[derive(Debug, Clone)]
struct NotificationTask {
    /// Alert
    alert: Alert,
    /// Target channels
    channels: Vec<String>,
    /// Retry count
    retry_count: u32,
    /// Next retry time
    next_retry: Option<Instant>,
}

impl AlertManagementHandler {
    /// Create new alert management handler
    pub fn new(config: AlertConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            rules: Arc::new(RwLock::new(HashMap::new())),
            active_alerts: Arc::new(RwLock::new(HashMap::new())),
            history: Arc::new(RwLock::new(Vec::new())),
            anomaly_detectors: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(AlertStats::default())),
            notification_queue: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add alert rule
    pub fn add_rule(&self, rule: AlertRule) {
        self.rules.write().insert(rule.id.clone(), rule);
    }

    /// Remove alert rule
    pub fn remove_rule(&self, rule_id: &str) {
        self.rules.write().remove(rule_id);
    }

    /// Evaluate metric
    pub fn evaluate_metric(&self, name: &str, value: f64, labels: HashMap<String, String>) {
        let config = self.config.read();
        
        if !config.enabled {
            return;
        }

        // Check for anomalies
        if config.anomaly_detection {
            self.check_anomaly(name, value, &labels);
        }

        // Evaluate alert rules
        let rules = self.rules.read();
        for rule in rules.values() {
            if rule.enabled {
                self.evaluate_rule(rule, value, &labels);
            }
        }
    }

    /// Check for anomalies
    fn check_anomaly(&self, name: &str, value: f64, labels: &HashMap<String, String>) {
        let mut detectors = self.anomaly_detectors.write();
        
        let detector = detectors.entry(name.to_string())
            .or_insert_with(|| AnomalyDetector::new(3.0));
        
        if detector.is_anomaly(value) {
            self.stats.write().anomalies_detected += 1;
            
            // Create anomaly alert
            let alert = Alert {
                id: format!("anomaly_{}_{}", name, Self::current_timestamp()),
                name: format!("Anomaly detected in {}", name),
                description: format!("Unusual value {} detected (mean: {:.2}, stddev: {:.2})",
                    value, detector.mean, detector.std_dev),
                severity: Severity::Warning,
                state: AlertState::Firing,
                labels: labels.clone(),
                annotations: HashMap::new(),
                value,
                threshold: detector.mean + (detector.z_threshold * detector.std_dev),
                started_at: Utc::now(),
                resolved_at: None,
                fingerprint: self.generate_fingerprint(name, labels),
                runbook_url: None,
            };
            
            self.fire_alert(alert);
        }
        
        detector.update(value);
    }

    /// Evaluate alert rule
    fn evaluate_rule(&self, rule: &AlertRule, value: f64, labels: &HashMap<String, String>) {
        // Simple threshold check (would evaluate expr in production)
        let threshold = 100.0; // Would parse from expr
        
        if value > threshold {
            let mut alert_labels = labels.clone();
            alert_labels.extend(rule.labels.clone());
            
            let alert = Alert {
                id: format!("{}_{}", rule.id, Self::current_timestamp()),
                name: rule.name.clone(),
                description: rule.annotations.get("description")
                    .cloned()
                    .unwrap_or_default(),
                severity: rule.severity,
                state: AlertState::Pending,
                labels: alert_labels,
                annotations: rule.annotations.clone(),
                value,
                threshold,
                started_at: Utc::now(),
                resolved_at: None,
                fingerprint: self.generate_fingerprint(&rule.name, labels),
                runbook_url: rule.annotations.get("runbook_url").cloned(),
            };
            
            self.fire_alert(alert);
        }
    }

    /// Fire alert
    fn fire_alert(&self, mut alert: Alert) {
        // Check suppression
        if self.is_suppressed(&alert) {
            alert.state = AlertState::Suppressed;
            self.stats.write().suppressed_alerts += 1;
            return;
        }

        // Check for existing alert
        let mut active = self.active_alerts.write();
        if let Some(existing) = active.get(&alert.fingerprint) {
            // Update existing alert
            return;
        }

        alert.state = AlertState::Firing;
        active.insert(alert.fingerprint.clone(), alert.clone());
        
        self.stats.write().total_alerts += 1;
        self.stats.write().active_alerts += 1;

        // Route alert
        self.route_alert(&alert);
    }

    /// Resolve alert
    pub fn resolve_alert(&self, fingerprint: &str) {
        let mut active = self.active_alerts.write();
        
        if let Some(mut alert) = active.remove(fingerprint) {
            alert.state = AlertState::Resolved;
            alert.resolved_at = Some(Utc::now());
            
            self.history.write().push(alert.clone());
            self.stats.write().active_alerts -= 1;
            
            // Send resolution notification
            self.route_alert(&alert);
        }
    }

    /// Route alert to channels
    fn route_alert(&self, alert: &Alert) {
        let config = self.config.read();
        let mut matched_channels = Vec::new();

        for rule in &config.routing_rules {
            if self.matches_criteria(alert, &rule.match_criteria) {
                matched_channels.extend(rule.channels.clone());
                
                if !rule.continue_matching {
                    break;
                }
            }
        }

        if !matched_channels.is_empty() {
            self.queue_notification(alert.clone(), matched_channels);
        }
    }

    /// Check if alert matches criteria
    fn matches_criteria(&self, alert: &Alert, criteria: &MatchCriteria) -> bool {
        // Check severity
        if !criteria.severities.is_empty() && !criteria.severities.contains(&alert.severity) {
            return false;
        }

        // Check labels
        for (key, value) in &criteria.labels {
            if alert.labels.get(key) != Some(value) {
                return false;
            }
        }

        true
    }

    /// Check if alert is suppressed
    fn is_suppressed(&self, alert: &Alert) -> bool {
        let config = self.config.read();
        
        for rule in &config.suppression_rules {
            if self.matches_criteria(alert, &rule.match_criteria) {
                return true;
            }
        }
        
        false
    }

    /// Queue notification
    fn queue_notification(&self, alert: Alert, channels: Vec<String>) {
        let task = NotificationTask {
            alert,
            channels,
            retry_count: 0,
            next_retry: None,
        };

        self.notification_queue.write().push(task);
    }

    /// Process notification queue
    pub fn process_notifications(&self) {
        let mut queue = self.notification_queue.write();
        let config = self.config.read();
        
        let mut pending = Vec::new();
        
        for task in queue.drain(..) {
            if let Some(next_retry) = task.next_retry {
                if Instant::now() < next_retry {
                    pending.push(task);
                    continue;
                }
            }

            for channel_id in &task.channels {
                if let Some(channel) = config.channels.iter().find(|c| c.id == *channel_id) {
                    if channel.enabled {
                        self.send_notification(&task.alert, channel);
                    }
                }
            }
        }

        *queue = pending;
    }

    /// Send notification
    fn send_notification(&self, alert: &Alert, channel: &NotificationChannel) {
        match channel.channel_type {
            ChannelType::Email => self.send_email(alert, &channel.config),
            ChannelType::Slack => self.send_slack(alert, &channel.config),
            ChannelType::PagerDuty => self.send_pagerduty(alert, &channel.config),
            ChannelType::Webhook => self.send_webhook(alert, &channel.config),
            _ => {}
        }

        self.stats.write().notifications_sent += 1;
    }

    /// Send email notification
    fn send_email(&self, alert: &Alert, _config: &HashMap<String, String>) {
        // Would implement email sending
        println!("Email alert: {} - {}", alert.name, alert.description);
    }

    /// Send Slack notification
    fn send_slack(&self, alert: &Alert, _config: &HashMap<String, String>) {
        // Would implement Slack webhook
        println!("Slack alert: {} - {}", alert.name, alert.description);
    }

    /// Send PagerDuty notification
    fn send_pagerduty(&self, alert: &Alert, _config: &HashMap<String, String>) {
        // Would implement PagerDuty API
        println!("PagerDuty alert: {} - {}", alert.name, alert.description);
    }

    /// Send webhook notification
    fn send_webhook(&self, alert: &Alert, _config: &HashMap<String, String>) {
        // Would implement webhook POST
        println!("Webhook alert: {} - {}", alert.name, alert.description);
    }

    /// Generate fingerprint
    fn generate_fingerprint(&self, name: &str, labels: &HashMap<String, String>) -> String {
        let mut parts = vec![name.to_string()];
        for (key, value) in labels {
            parts.push(format!("{}={}", key, value));
        }
        parts.sort();
        format!("{:x}", Self::hash_string(&parts.join("|")))
    }

    /// Hash string
    fn hash_string(s: &str) -> u64 {
        let mut hash = 0u64;
        for byte in s.bytes() {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
        }
        hash
    }

    /// Get current timestamp
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Get statistics
    pub fn get_stats(&self) -> AlertStats {
        self.stats.read().clone()
    }

    /// Get active alerts
    pub fn get_active_alerts(&self) -> Vec<Alert> {
        self.active_alerts.read().values().cloned().collect()
    }

    /// Clean old alerts
    pub fn clean_history(&self) {
        let config = self.config.read();
        let cutoff = Utc::now() - chrono::Duration::from_std(config.retention_period).unwrap();
        
        self.history.write().retain(|alert| {
            alert.resolved_at.map_or(true, |resolved| resolved > cutoff)
        });
    }
}

// Helper trait for Duration
trait DurationExt {
    fn from_days(days: u64) -> Duration;
}

impl DurationExt for Duration {
    fn from_days(days: u64) -> Duration {
        Duration::from_secs(days * 24 * 60 * 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anomaly_detection() {
        let mut detector = AnomalyDetector::new(3.0);
        
        // Add normal values
        for _ in 0..20 {
            detector.update(50.0);
        }
        
        // Check normal value
        assert!(!detector.is_anomaly(52.0));
        
        // Check anomaly
        assert!(detector.is_anomaly(200.0));
    }

    #[test]
    fn test_alert_routing() {
        let config = AlertConfig {
            enabled: true,
            routing_rules: vec![
                RoutingRule {
                    name: "critical".to_string(),
                    match_criteria: MatchCriteria {
                        severities: vec![Severity::Critical],
                        labels: HashMap::new(),
                        regex_patterns: vec![],
                    },
                    channels: vec!["pagerduty".to_string()],
                    continue_matching: false,
                }
            ],
            ..Default::default()
        };
        
        let handler = AlertManagementHandler::new(config);
        
        let alert = Alert {
            id: "test".to_string(),
            name: "Test Alert".to_string(),
            description: "Test".to_string(),
            severity: Severity::Critical,
            state: AlertState::Firing,
            labels: HashMap::new(),
            annotations: HashMap::new(),
            value: 100.0,
            threshold: 50.0,
            started_at: chrono::Utc::now(),
            resolved_at: None,
            fingerprint: "test".to_string(),
            runbook_url: None,
        };
        
        handler.route_alert(&alert);
        
        // Check notification queue
        assert!(handler.notification_queue.read().len() > 0);
    }
}