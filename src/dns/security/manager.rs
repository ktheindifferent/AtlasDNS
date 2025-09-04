//! Unified Security Manager for DNS security features

use std::sync::Arc;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use tokio::sync::mpsc;

use crate::dns::protocol::DnsPacket;
use crate::dns::errors::{DnsError, ConfigError};
use super::{
    SecurityCheckResult, SecurityAction, SecurityMetrics, SecurityAlert,
    AlertSeverity, AlertType, ThreatLevel, SecurityComponent,
    DnsFirewall, FirewallConfig,
    EnhancedRateLimiter, RateLimitConfig,
    DDoSProtection, DDoSConfig,
};

/// Unified Security Manager
pub struct SecurityManager {
    config: Arc<RwLock<SecurityConfig>>,
    firewall: Arc<DnsFirewall>,
    rate_limiter: Arc<EnhancedRateLimiter>,
    ddos_protection: Arc<DDoSProtection>,
    metrics: Arc<RwLock<SecurityMetrics>>,
    alerts: Arc<RwLock<Vec<SecurityAlert>>>,
    alert_sender: Option<mpsc::UnboundedSender<SecurityAlert>>,
    event_log: Arc<RwLock<Vec<SecurityEventRecord>>>,
    webhook_config: Arc<RwLock<WebhookConfig>>,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub enabled: bool,
    pub firewall: FirewallConfig,
    pub rate_limiting: RateLimitConfig,
    pub ddos_protection: DDoSConfig,
    pub alert_threshold: AlertSeverity,
    pub log_security_events: bool,
    pub max_event_log_size: usize,
    pub webhook_enabled: bool,
    pub metrics_interval: Duration,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        SecurityConfig {
            enabled: true,
            firewall: FirewallConfig::default(),
            rate_limiting: RateLimitConfig::default(),
            ddos_protection: DDoSConfig::default(),
            alert_threshold: AlertSeverity::Warning,
            log_security_events: true,
            max_event_log_size: 10000,
            webhook_enabled: false,
            metrics_interval: Duration::from_secs(60),
        }
    }
}

/// Security event record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEventRecord {
    pub timestamp: u64, // Unix timestamp
    pub event_type: SecurityEventType,
    pub client_ip: Option<IpAddr>,
    pub domain: Option<String>,
    pub action_taken: SecurityAction,
    pub threat_level: ThreatLevel,
    pub details: serde_json::Value,
}

/// Security event type
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SecurityEventType {
    FirewallBlock,
    RateLimitExceeded,
    DDoSAttackDetected,
    MaliciousPattern,
    SuspiciousActivity,
    SecurityRuleTriggered,
    ConfigurationChange,
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    pub auth_token: Option<String>,
    pub retry_count: u32,
    pub timeout: Duration,
    pub batch_size: usize,
    pub batch_interval: Duration,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        WebhookConfig {
            url: String::new(),
            auth_token: None,
            retry_count: 3,
            timeout: Duration::from_secs(10),
            batch_size: 100,
            batch_interval: Duration::from_secs(30),
        }
    }
}

/// Security statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityStatistics {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub allowed_requests: u64,
    pub firewall_blocks: u64,
    pub rate_limit_blocks: u64,
    pub ddos_blocks: u64,
    pub threat_levels: HashMap<ThreatLevel, u64>,
    pub top_blocked_ips: Vec<(IpAddr, u64)>,
    pub top_blocked_domains: Vec<(String, u64)>,
    pub alerts_generated: u64,
    pub last_reset: u64, // Unix timestamp
}

impl SecurityManager {
    /// Create a new security manager
    pub fn new(config: SecurityConfig) -> Self {
        let firewall = Arc::new(DnsFirewall::new(config.firewall.clone()));
        let rate_limiter = Arc::new(EnhancedRateLimiter::new(config.rate_limiting.clone()));
        let ddos_protection = Arc::new(DDoSProtection::new(config.ddos_protection.clone()));

        let manager = SecurityManager {
            config: Arc::new(RwLock::new(config)),
            firewall,
            rate_limiter,
            ddos_protection,
            metrics: Arc::new(RwLock::new(SecurityMetrics::default())),
            alerts: Arc::new(RwLock::new(Vec::new())),
            alert_sender: None,
            event_log: Arc::new(RwLock::new(Vec::new())),
            webhook_config: Arc::new(RwLock::new(WebhookConfig::default())),
        };

        // Start background tasks that don't require Tokio runtime
        manager.start_metrics_collector();
        
        // Note: Alert processor requires Tokio runtime and will be started automatically
        // when first used if a runtime is available, or can be manually started
        // by calling initialize_background_tasks()
        manager.start_alert_processor();

        manager
    }

    /// Initialize background tasks (must be called after Tokio runtime is started)
    pub fn initialize_background_tasks(&self) {
        self.start_metrics_collector();
        self.start_alert_processor();
    }

    /// Perform comprehensive security check
    pub fn check_request(&self, packet: &DnsPacket, client_ip: IpAddr) -> SecurityCheckResult {
        let config = self.config.read();
        if !config.enabled {
            return SecurityCheckResult {
                allowed: true,
                action: SecurityAction::Allow,
                reason: None,
                threat_level: ThreatLevel::None,
                events: Vec::new(),
            };
        }

        let mut metrics = self.metrics.write();
        metrics.total_queries += 1;

        // Check firewall rules first (fastest)
        let firewall_result = self.firewall.check(packet, client_ip);
        if !firewall_result.allowed {
            metrics.firewall_blocked += 1;
            self.log_security_event(SecurityEventType::FirewallBlock, &firewall_result, packet, client_ip);
            self.generate_alert(AlertType::FirewallBlock, &firewall_result, client_ip);
            return firewall_result;
        }

        // Check rate limiting
        let rate_limit_result = self.rate_limiter.check(packet, client_ip);
        if !rate_limit_result.allowed {
            metrics.rate_limited += 1;
            self.log_security_event(SecurityEventType::RateLimitExceeded, &rate_limit_result, packet, client_ip);
            self.generate_alert(AlertType::RateLimitExceeded, &rate_limit_result, client_ip);
            return rate_limit_result;
        }

        // Check for DDoS attacks
        let ddos_result = self.ddos_protection.check(packet, client_ip);
        if !ddos_result.allowed {
            metrics.ddos_attacks_detected += 1;
            self.log_security_event(SecurityEventType::DDoSAttackDetected, &ddos_result, packet, client_ip);
            self.generate_alert(AlertType::DDoSAttack, &ddos_result, client_ip);
            return ddos_result;
        }

        // Update threat level
        let overall_threat = self.calculate_overall_threat_level(
            &firewall_result,
            &rate_limit_result,
            &ddos_result,
        );
        metrics.threat_level = overall_threat;

        // All checks passed
        SecurityCheckResult {
            allowed: true,
            action: SecurityAction::Allow,
            reason: None,
            threat_level: overall_threat,
            events: Vec::new(),
        }
    }

    /// Add firewall rule
    pub fn add_firewall_rule(&self, rule: super::firewall::FirewallRule) -> Result<(), DnsError> {
        self.firewall.add_rule(rule)?;
        self.log_configuration_change("Added firewall rule");
        Ok(())
    }

    /// Remove firewall rule
    pub fn remove_firewall_rule(&self, rule_id: &str) -> Result<(), DnsError> {
        self.firewall.remove_rule(rule_id)?;
        self.log_configuration_change("Removed firewall rule");
        Ok(())
    }

    /// Load blocklist
    pub fn load_blocklist(&self, source: &str, category: super::firewall::ThreatCategory) -> Result<(), DnsError> {
        self.firewall.load_blocklist(source, category)?;
        self.log_configuration_change("Loaded blocklist");
        Ok(())
    }

    /// Load allowlist
    pub fn load_allowlist(&self, source: &str) -> Result<(), DnsError> {
        self.firewall.load_allowlist(source)?;
        self.log_configuration_change("Loaded allowlist");
        Ok(())
    }

    /// Unblock client
    pub fn unblock_client(&self, client_ip: IpAddr) {
        self.rate_limiter.unblock_client(client_ip);
        self.log_configuration_change(&format!("Unblocked client {}", client_ip));
    }

    /// Get security metrics
    pub fn get_metrics(&self) -> SecurityMetrics {
        self.metrics.read().clone()
    }

    /// Get security statistics
    pub fn get_statistics(&self) -> SecurityStatistics {
        let metrics = self.metrics.read();
        let firewall_metrics = self.firewall.get_metrics();
        let rate_limit_metrics = self.rate_limiter.get_metrics();
        let ddos_metrics = self.ddos_protection.get_metrics();

        SecurityStatistics {
            total_requests: metrics.total_queries,
            blocked_requests: metrics.firewall_blocked + metrics.rate_limited,
            allowed_requests: metrics.total_queries - metrics.firewall_blocked - metrics.rate_limited,
            firewall_blocks: metrics.firewall_blocked,
            rate_limit_blocks: metrics.rate_limited,
            ddos_blocks: ddos_metrics.blocked_queries,
            threat_levels: HashMap::new(),
            top_blocked_ips: Vec::new(),
            top_blocked_domains: Vec::new(),
            alerts_generated: self.alerts.read().len() as u64,
            last_reset: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        }
    }

    /// Get recent alerts
    pub fn get_alerts(&self, limit: usize) -> Vec<SecurityAlert> {
        let alerts = self.alerts.read();
        alerts.iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get security events
    pub fn get_events(&self, limit: usize) -> Vec<SecurityEventRecord> {
        let events = self.event_log.read();
        events.iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Update configuration
    pub fn update_config(&self, config: SecurityConfig) -> Result<(), DnsError> {
        // Update component configurations
        self.firewall.update_config(serde_json::to_value(&config.firewall).map_err(|_| DnsError::InvalidInput)?)?;
        self.rate_limiter.update_config(serde_json::to_value(&config.rate_limiting).map_err(|_| DnsError::InvalidInput)?)?;
        self.ddos_protection.update_config(serde_json::to_value(&config.ddos_protection).map_err(|_| DnsError::InvalidInput)?)?;
        
        *self.config.write() = config;
        self.log_configuration_change("Updated security configuration");
        Ok(())
    }

    /// Configure webhook
    pub fn configure_webhook(&self, webhook_config: WebhookConfig) {
        *self.webhook_config.write() = webhook_config;
        self.log_configuration_change("Updated webhook configuration");
    }

    /// Reset all security components
    pub fn reset_all(&self) {
        self.firewall.reset();
        self.rate_limiter.reset();
        self.ddos_protection.reset();
        *self.metrics.write() = SecurityMetrics::default();
        self.alerts.write().clear();
        self.event_log.write().clear();
        self.log_configuration_change("Reset all security components");
    }

    /// Get rate limiting metrics
    pub fn get_rate_limit_metrics(&self) -> super::rate_limiter::RateLimitMetrics {
        self.rate_limiter.get_metrics()
    }

    /// Get rate limiting configuration
    pub fn get_rate_limit_config(&self) -> RateLimitConfig {
        self.config.read().rate_limiting.clone()
    }

    /// Update rate limiting configuration
    pub fn update_rate_limit_config(&self, config: RateLimitConfig) -> Result<(), DnsError> {
        let config_json = serde_json::to_value(&config).map_err(|_| DnsError::Configuration(ConfigError {
            parameter: "rate_limit_config".to_string(),
            value: "serialized_config".to_string(),
            reason: "Failed to serialize rate limit config".to_string(),
            suggestion: "Check configuration format".to_string(),
        }))?;
        self.rate_limiter.update_config(config_json)?;
        self.config.write().rate_limiting = config;
        self.log_configuration_change("Updated rate limiting configuration");
        Ok(())
    }

    // Internal helper methods

    fn calculate_overall_threat_level(
        &self,
        firewall: &SecurityCheckResult,
        rate_limit: &SecurityCheckResult,
        ddos: &SecurityCheckResult,
    ) -> ThreatLevel {
        firewall.threat_level
            .max(rate_limit.threat_level)
            .max(ddos.threat_level)
    }

    fn log_security_event(
        &self,
        event_type: SecurityEventType,
        result: &SecurityCheckResult,
        packet: &DnsPacket,
        client_ip: IpAddr,
    ) {
        let config = self.config.read();
        if !config.log_security_events {
            return;
        }

        let domain = packet.questions.first().map(|q| q.name.clone());
        
        let event = SecurityEventRecord {
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            event_type,
            client_ip: Some(client_ip),
            domain,
            action_taken: result.action,
            threat_level: result.threat_level,
            details: serde_json::json!({
                "reason": result.reason,
                "events": result.events,
            }),
        };

        let mut event_log = self.event_log.write();
        event_log.push(event);
        
        // Trim log if too large
        if event_log.len() > config.max_event_log_size {
            let drain_count = event_log.len() - config.max_event_log_size;
            event_log.drain(0..drain_count);
        }
    }

    fn generate_alert(
        &self,
        alert_type: AlertType,
        result: &SecurityCheckResult,
        client_ip: IpAddr,
    ) {
        let severity = match result.threat_level {
            ThreatLevel::None => return,
            ThreatLevel::Low => AlertSeverity::Info,
            ThreatLevel::Medium => AlertSeverity::Warning,
            ThreatLevel::High => AlertSeverity::High,
            ThreatLevel::Critical => AlertSeverity::Critical,
        };

        let config = self.config.read();
        if severity < config.alert_threshold {
            return;
        }

        let alert = SecurityAlert {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            severity,
            alert_type,
            message: result.reason.clone().unwrap_or_else(|| format!("{:?}", alert_type)),
            client_ip: Some(client_ip),
            domain: None,
            metadata: serde_json::json!({
                "threat_level": result.threat_level,
                "action": result.action,
            }),
        };

        self.alerts.write().push(alert.clone());
        
        // Send to alert processor if configured
        if let Some(sender) = &self.alert_sender {
            let _ = sender.send(alert);
        }
    }

    fn log_configuration_change(&self, message: &str) {
        let event = SecurityEventRecord {
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            event_type: SecurityEventType::ConfigurationChange,
            client_ip: None,
            domain: None,
            action_taken: SecurityAction::Allow,
            threat_level: ThreatLevel::None,
            details: serde_json::json!({
                "message": message,
            }),
        };

        self.event_log.write().push(event);
    }

    fn start_metrics_collector(&self) {
        let metrics = Arc::clone(&self.metrics);
        let firewall = Arc::clone(&self.firewall);
        let rate_limiter = Arc::clone(&self.rate_limiter);
        let ddos_protection = Arc::clone(&self.ddos_protection);
        let config = Arc::clone(&self.config);

        std::thread::spawn(move || {
            loop {
                std::thread::sleep(config.read().metrics_interval);
                
                // Collect metrics from all components
                let firewall_metrics = firewall.get_metrics();
                let rate_limit_metrics = rate_limiter.get_metrics();
                let ddos_metrics = ddos_protection.get_metrics();
                
                // Update global metrics
                let mut global_metrics = metrics.write();
                global_metrics.active_rules = firewall_metrics.active_rules;
                global_metrics.blocked_ips = rate_limit_metrics.banned_clients;
                global_metrics.throttled_clients = rate_limit_metrics.throttled_clients;
            }
        });
    }

    fn start_alert_processor(&self) {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let webhook_config = Arc::clone(&self.webhook_config);
        
        // Check if we're in a Tokio runtime context
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
            let mut alert_batch = Vec::new();
            let mut last_send = Instant::now();
            
            loop {
                tokio::select! {
                    Some(alert) = rx.recv() => {
                        alert_batch.push(alert);
                        
                        let should_send = {
                            let config = webhook_config.read();
                            if alert_batch.len() >= config.batch_size ||
                               last_send.elapsed() >= config.batch_interval {
                                if config.url.is_empty() {
                                    false
                                } else {
                                    true
                                }
                            } else {
                                false
                            }
                        };
                        
                        if should_send {
                            let config_clone = webhook_config.read().clone();
                            // Send webhook
                            Self::send_webhook(&config_clone, &alert_batch).await;
                            alert_batch.clear();
                            last_send = Instant::now();
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {
                        if !alert_batch.is_empty() {
                            let config_clone = {
                                let config = webhook_config.read();
                                if !config.url.is_empty() {
                                    Some(config.clone())
                                } else {
                                    None
                                }
                            }; // lock definitely dropped here
                            
                            if let Some(config) = config_clone {
                                Self::send_webhook(&config, &alert_batch).await;
                                alert_batch.clear();
                                last_send = Instant::now();
                            }
                        }
                    }
                }
            }
            });
        } else {
            log::debug!("Alert processor not started - no Tokio runtime available");
        }
    }

    async fn send_webhook(config: &WebhookConfig, alerts: &[SecurityAlert]) {
        // Implementation would send alerts to webhook endpoint
        // This is a placeholder for the actual implementation
        let client = reqwest::Client::new();
        let payload = serde_json::json!({
            "alerts": alerts,
            "timestamp": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        });

        for _ in 0..config.retry_count {
            let mut request = client.post(&config.url)
                .json(&payload)
                .timeout(config.timeout);

            if let Some(token) = &config.auth_token {
                request = request.bearer_auth(token);
            }

            match request.send().await {
                Ok(response) if response.status().is_success() => break,
                _ => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        }
    }
}

// Re-export for convenience
pub use super::firewall::FirewallRule;
pub use super::rate_limiter::RateLimitAlgorithm;
pub use super::ddos_protection::AttackType;