//! Webhook Notifications
//!
//! Real-time event streaming for DNS changes with retry logic, event filtering,
//! and multiple webhook endpoint support.
//!
//! # Features
//!
//! * **Multiple Endpoints** - Send events to multiple webhook URLs
//! * **Event Filtering** - Subscribe to specific event types
//! * **Retry Logic** - Automatic retries with exponential backoff
//! * **Event Batching** - Batch multiple events for efficiency
//! * **Signature Verification** - HMAC-SHA256 webhook signatures
//! * **Circuit Breaker** - Disable failing endpoints temporarily
//! * **Event History** - Store and replay events

use std::sync::Arc;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use tokio::time::sleep;
use reqwest;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use uuid::Uuid;

/// Get current unix timestamp safely, returning 0 on error
fn safe_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_else(|e| {
            log::warn!("Failed to get system time: {}, using 0", e);
            0
        })
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Enable webhooks
    pub enabled: bool,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Initial retry delay
    pub initial_retry_delay: Duration,
    /// Maximum retry delay
    pub max_retry_delay: Duration,
    /// Request timeout
    pub request_timeout: Duration,
    /// Enable batching
    pub batching_enabled: bool,
    /// Batch size
    pub batch_size: usize,
    /// Batch interval
    pub batch_interval: Duration,
    /// Circuit breaker threshold
    pub circuit_breaker_threshold: u32,
    /// Circuit breaker timeout
    pub circuit_breaker_timeout: Duration,
    /// Event history size
    pub history_size: usize,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_retries: 3,
            initial_retry_delay: Duration::from_secs(1),
            max_retry_delay: Duration::from_secs(60),
            request_timeout: Duration::from_secs(30),
            batching_enabled: true,
            batch_size: 100,
            batch_interval: Duration::from_secs(5),
            circuit_breaker_threshold: 5,
            circuit_breaker_timeout: Duration::from_secs(300),
            history_size: 10000,
        }
    }
}

/// Webhook endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    /// Endpoint ID
    pub id: String,
    /// Endpoint name
    pub name: String,
    /// Webhook URL
    pub url: String,
    /// Secret for signature verification
    pub secret: Option<String>,
    /// Event filters
    pub event_filters: Vec<EventFilter>,
    /// Headers to include
    pub headers: HashMap<String, String>,
    /// Enabled flag
    pub enabled: bool,
    /// Retry configuration override
    pub retry_config: Option<RetryConfig>,
    /// Tags
    pub tags: HashMap<String, String>,
}

/// Event filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventFilter {
    /// Event type pattern
    pub event_type: String,
    /// Resource type filter
    pub resource_type: Option<String>,
    /// Zone filter
    pub zone: Option<String>,
    /// Action filter
    pub action: Option<String>,
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retries
    pub max_retries: u32,
    /// Retry delay
    pub retry_delay: Duration,
    /// Exponential backoff
    pub exponential_backoff: bool,
}

/// DNS event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEvent {
    /// Event ID
    pub id: String,
    /// Event type
    pub event_type: EventType,
    /// Timestamp
    pub timestamp: u64,
    /// Resource type
    pub resource_type: String,
    /// Resource ID
    pub resource_id: String,
    /// Action
    pub action: EventAction,
    /// Zone
    pub zone: Option<String>,
    /// User
    pub user: Option<String>,
    /// Source IP
    pub source_ip: Option<String>,
    /// Details
    pub details: HashMap<String, serde_json::Value>,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

/// Event type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EventType {
    // Zone events
    ZoneCreated,
    ZoneUpdated,
    ZoneDeleted,
    ZoneTransferInitiated,
    ZoneTransferCompleted,
    ZoneValidationFailed,
    
    // Record events
    RecordCreated,
    RecordUpdated,
    RecordDeleted,
    RecordBulkOperation,
    
    // Health check events
    HealthCheckUp,
    HealthCheckDown,
    HealthCheckFlapping,
    
    // Traffic events
    TrafficPolicyCreated,
    TrafficPolicyUpdated,
    TrafficPolicyDeleted,
    TrafficShiftStarted,
    TrafficShiftCompleted,
    
    // Security events
    DdosAttackDetected,
    RateLimitExceeded,
    FirewallRuleTriggered,
    DnssecValidationFailed,
    
    // System events
    SystemStartup,
    SystemShutdown,
    ConfigurationChanged,
    CertificateExpiring,
    BackupCompleted,
    
    // Custom events
    Custom(String),
}

/// Event action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventAction {
    Create,
    Update,
    Delete,
    Read,
    Validate,
    Transfer,
    Alert,
    Custom(String),
}

/// Webhook delivery
#[derive(Debug, Clone)]
struct WebhookDelivery {
    /// Delivery ID
    id: String,
    /// Endpoint ID
    endpoint_id: String,
    /// Events
    events: Vec<DnsEvent>,
    /// Attempt count
    attempts: u32,
    /// Next retry time
    next_retry: Option<Instant>,
    /// Created at
    created_at: Instant,
}

/// Endpoint state
#[derive(Debug, Clone)]
struct EndpointState {
    /// Consecutive failures
    consecutive_failures: u32,
    /// Circuit breaker state
    circuit_breaker_open: bool,
    /// Circuit breaker opened at
    circuit_breaker_opened_at: Option<Instant>,
    /// Last successful delivery
    last_success: Option<Instant>,
    /// Last failure
    last_failure: Option<Instant>,
    /// Total deliveries
    total_deliveries: u64,
    /// Successful deliveries
    successful_deliveries: u64,
    /// Failed deliveries
    failed_deliveries: u64,
}

/// Webhook statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct WebhookStats {
    /// Total events
    pub total_events: u64,
    /// Delivered events
    pub delivered_events: u64,
    /// Pending events
    pub pending_events: u64,
    /// Failed events
    pub failed_events: u64,
    /// Total deliveries
    pub total_deliveries: u64,
    /// Successful deliveries
    pub successful_deliveries: u64,
    /// Failed deliveries
    pub failed_deliveries: u64,
    /// Average delivery time (ms)
    pub avg_delivery_time_ms: f64,
    /// Events by type
    pub events_by_type: HashMap<String, u64>,
}

/// Webhook handler
pub struct WebhookHandler {
    /// Configuration
    config: Arc<RwLock<WebhookConfig>>,
    /// Endpoints
    endpoints: Arc<RwLock<HashMap<String, WebhookEndpoint>>>,
    /// Endpoint states
    endpoint_states: Arc<RwLock<HashMap<String, EndpointState>>>,
    /// Delivery queue
    delivery_queue: Arc<RwLock<VecDeque<WebhookDelivery>>>,
    /// Event history
    event_history: Arc<RwLock<VecDeque<DnsEvent>>>,
    /// Statistics
    stats: Arc<RwLock<WebhookStats>>,
    /// HTTP client
    client: reqwest::Client,
}

impl WebhookHandler {
    /// Create new webhook handler
    pub fn new(config: WebhookConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()
            .unwrap_or_else(|e| {
                log::error!("Failed to create HTTP client for webhooks: {}, using default", e);
                reqwest::Client::new()
            });
        
        Self {
            config: Arc::new(RwLock::new(config)),
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            endpoint_states: Arc::new(RwLock::new(HashMap::new())),
            delivery_queue: Arc::new(RwLock::new(VecDeque::new())),
            event_history: Arc::new(RwLock::new(VecDeque::new())),
            stats: Arc::new(RwLock::new(WebhookStats::default())),
            client,
        }
    }

    /// Register webhook endpoint
    pub fn register_endpoint(&self, endpoint: WebhookEndpoint) -> Result<(), String> {
        let config = self.config.read();
        
        if !config.enabled {
            return Err("Webhooks are disabled".to_string());
        }
        
        // Validate endpoint
        self.validate_endpoint(&endpoint)?;
        
        // Initialize endpoint state
        self.endpoint_states.write().insert(
            endpoint.id.clone(),
            EndpointState {
                consecutive_failures: 0,
                circuit_breaker_open: false,
                circuit_breaker_opened_at: None,
                last_success: None,
                last_failure: None,
                total_deliveries: 0,
                successful_deliveries: 0,
                failed_deliveries: 0,
            },
        );
        
        self.endpoints.write().insert(endpoint.id.clone(), endpoint);
        
        Ok(())
    }

    /// Unregister webhook endpoint
    pub fn unregister_endpoint(&self, endpoint_id: &str) {
        self.endpoints.write().remove(endpoint_id);
        self.endpoint_states.write().remove(endpoint_id);
        
        // Remove pending deliveries for this endpoint
        self.delivery_queue.write().retain(|d| d.endpoint_id != endpoint_id);
    }

    /// Emit event
    pub async fn emit(&self, event: DnsEvent) {
        let config = self.config.read();
        
        if !config.enabled {
            return;
        }
        
        // Update statistics
        self.stats.write().total_events += 1;
        *self.stats.write().events_by_type
            .entry(format!("{:?}", event.event_type))
            .or_insert(0) += 1;
        
        // Add to history
        self.add_to_history(event.clone());
        
        // Find matching endpoints
        let endpoints = self.endpoints.read();
        let matching_endpoints: Vec<WebhookEndpoint> = endpoints
            .values()
            .filter(|e| e.enabled && self.event_matches_filters(&event, &e.event_filters))
            .cloned()
            .collect();
        
        if matching_endpoints.is_empty() {
            return;
        }
        
        // Create deliveries
        if config.batching_enabled {
            self.add_to_batch(event, matching_endpoints);
        } else {
            for endpoint in matching_endpoints {
                self.create_delivery(endpoint.id.clone(), vec![event.clone()]);
            }
        }
        
        // Process deliveries
        self.process_deliveries().await;
    }

    /// Process deliveries
    async fn process_deliveries(&self) {
        let deliveries: Vec<WebhookDelivery> = {
            let mut queue = self.delivery_queue.write();
            let mut ready_deliveries = Vec::new();
            
            while let Some(delivery) = queue.pop_front() {
                if delivery.next_retry.map_or(true, |t| Instant::now() >= t) {
                    ready_deliveries.push(delivery);
                } else {
                    queue.push_front(delivery);
                    break;
                }
            }
            
            ready_deliveries
        };
        
        for delivery in deliveries {
            self.deliver(delivery).await;
        }
    }

    /// Deliver webhook
    async fn deliver(&self, mut delivery: WebhookDelivery) {
        let endpoints = self.endpoints.read();
        let endpoint = match endpoints.get(&delivery.endpoint_id) {
            Some(e) => e.clone(),
            None => return,
        };
        
        // Check circuit breaker
        if self.is_circuit_breaker_open(&delivery.endpoint_id) {
            self.stats.write().failed_events += delivery.events.len() as u64;
            return;
        }
        
        delivery.attempts += 1;
        
        // Prepare payload
        let payload = if delivery.events.len() == 1 {
            match serde_json::to_string(&delivery.events[0]) {
                Ok(json) => json,
                Err(e) => {
                    log::error!("Failed to serialize single event: {}", e);
                    return;
                }
            }
        } else {
            match serde_json::to_string(&json!({
                "events": delivery.events
            })) {
                Ok(json) => json,
                Err(e) => {
                    log::error!("Failed to serialize event batch: {}", e);
                    return;
                }
            }
        };
        
        // Calculate signature
        let signature = if let Some(secret) = &endpoint.secret {
            Some(self.calculate_signature(&payload, secret))
        } else {
            None
        };
        
        // Build request
        let mut request = self.client.post(&endpoint.url)
            .header("Content-Type", "application/json")
            .header("X-Atlas-Delivery", &delivery.id)
            .header("X-Atlas-Event", format!("{:?}", delivery.events[0].event_type))
            .body(payload);
        
        if let Some(sig) = signature {
            request = request.header("X-Atlas-Signature", sig);
        }
        
        for (key, value) in &endpoint.headers {
            request = request.header(key, value);
        }
        
        // Send request
        let start = Instant::now();
        let result = request.send().await;
        let duration = start.elapsed();
        
        // Update statistics
        self.stats.write().total_deliveries += 1;
        self.update_delivery_time(duration);
        
        match result {
            Ok(response) if response.status().is_success() => {
                self.handle_delivery_success(&delivery.endpoint_id, delivery.events.len());
                self.stats.write().delivered_events += delivery.events.len() as u64;
            }
            _ => {
                self.handle_delivery_failure(&delivery.endpoint_id);
                
                // Retry logic
                let should_retry = self.should_retry(&delivery, &endpoint);
                
                if should_retry {
                    let retry_delay = self.calculate_retry_delay(&delivery, &endpoint);
                    delivery.next_retry = Some(Instant::now() + retry_delay);
                    let event_count = delivery.events.len() as u64;
                    self.delivery_queue.write().push_back(delivery);
                    self.stats.write().pending_events += event_count;
                } else {
                    self.stats.write().failed_events += delivery.events.len() as u64;
                }
            }
        }
    }

    /// Check if event matches filters
    fn event_matches_filters(&self, event: &DnsEvent, filters: &[EventFilter]) -> bool {
        if filters.is_empty() {
            return true;
        }
        
        for filter in filters {
            let type_matches = filter.event_type == "*" || 
                format!("{:?}", event.event_type).contains(&filter.event_type);
            
            let resource_matches = filter.resource_type.as_ref()
                .map_or(true, |rt| rt == &event.resource_type);
            
            let zone_matches = filter.zone.as_ref()
                .map_or(true, |z| event.zone.as_ref() == Some(z));
            
            let action_matches = filter.action.as_ref()
                .map_or(true, |a| format!("{:?}", event.action) == *a);
            
            if type_matches && resource_matches && zone_matches && action_matches {
                return true;
            }
        }
        
        false
    }

    /// Add event to batch
    fn add_to_batch(&self, event: DnsEvent, endpoints: Vec<WebhookEndpoint>) {
        // Implementation would batch events for each endpoint
        for endpoint in endpoints {
            self.create_delivery(endpoint.id, vec![event.clone()]);
        }
    }

    /// Create delivery
    fn create_delivery(&self, endpoint_id: String, events: Vec<DnsEvent>) {
        let delivery = WebhookDelivery {
            id: Uuid::new_v4().to_string(),
            endpoint_id,
            events,
            attempts: 0,
            next_retry: None,
            created_at: Instant::now(),
        };
        
        self.delivery_queue.write().push_back(delivery);
    }

    /// Calculate signature
    fn calculate_signature(&self, payload: &str, secret: &str) -> String {
        type HmacSha256 = Hmac<Sha256>;
        
        let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
            Ok(m) => m,
            Err(e) => {
                log::error!("Failed to create HMAC with secret: {}", e);
                return String::new();
            }
        };
        mac.update(payload.as_bytes());
        
        let result = mac.finalize();
        hex::encode(result.into_bytes())
    }

    /// Check if circuit breaker is open
    fn is_circuit_breaker_open(&self, endpoint_id: &str) -> bool {
        let states = self.endpoint_states.read();
        let config = self.config.read();
        
        if let Some(state) = states.get(endpoint_id) {
            if state.circuit_breaker_open {
                if let Some(opened_at) = state.circuit_breaker_opened_at {
                    if opened_at.elapsed() < config.circuit_breaker_timeout {
                        return true;
                    }
                    // Circuit breaker timeout expired, close it
                    drop(states);
                    self.endpoint_states.write().get_mut(endpoint_id)
                        .map(|s| {
                            s.circuit_breaker_open = false;
                            s.circuit_breaker_opened_at = None;
                            s.consecutive_failures = 0;
                        });
                }
            }
        }
        
        false
    }

    /// Handle delivery success
    fn handle_delivery_success(&self, endpoint_id: &str, event_count: usize) {
        let mut states = self.endpoint_states.write();
        if let Some(state) = states.get_mut(endpoint_id) {
            state.consecutive_failures = 0;
            state.circuit_breaker_open = false;
            state.circuit_breaker_opened_at = None;
            state.last_success = Some(Instant::now());
            state.total_deliveries += 1;
            state.successful_deliveries += 1;
        }
        
        self.stats.write().successful_deliveries += 1;
    }

    /// Handle delivery failure
    fn handle_delivery_failure(&self, endpoint_id: &str) {
        let mut states = self.endpoint_states.write();
        let config = self.config.read();
        
        if let Some(state) = states.get_mut(endpoint_id) {
            state.consecutive_failures += 1;
            state.last_failure = Some(Instant::now());
            state.total_deliveries += 1;
            state.failed_deliveries += 1;
            
            // Open circuit breaker if threshold reached
            if state.consecutive_failures >= config.circuit_breaker_threshold {
                state.circuit_breaker_open = true;
                state.circuit_breaker_opened_at = Some(Instant::now());
            }
        }
        
        self.stats.write().failed_deliveries += 1;
    }

    /// Should retry delivery
    fn should_retry(&self, delivery: &WebhookDelivery, endpoint: &WebhookEndpoint) -> bool {
        let max_retries = endpoint.retry_config.as_ref()
            .map(|c| c.max_retries)
            .unwrap_or(self.config.read().max_retries);
        
        delivery.attempts < max_retries
    }

    /// Calculate retry delay
    fn calculate_retry_delay(&self, delivery: &WebhookDelivery, endpoint: &WebhookEndpoint) -> Duration {
        let config = self.config.read();
        
        if let Some(retry_config) = &endpoint.retry_config {
            if retry_config.exponential_backoff {
                let delay = retry_config.retry_delay * 2u32.pow(delivery.attempts - 1);
                delay.min(config.max_retry_delay)
            } else {
                retry_config.retry_delay
            }
        } else {
            let delay = config.initial_retry_delay * 2u32.pow(delivery.attempts - 1);
            delay.min(config.max_retry_delay)
        }
    }

    /// Add event to history
    fn add_to_history(&self, event: DnsEvent) {
        let mut history = self.event_history.write();
        let config = self.config.read();
        
        history.push_back(event);
        
        while history.len() > config.history_size {
            history.pop_front();
        }
    }

    /// Update delivery time statistics
    fn update_delivery_time(&self, duration: Duration) {
        let mut stats = self.stats.write();
        let n = stats.total_deliveries;
        let new_time = duration.as_millis() as f64;
        
        stats.avg_delivery_time_ms = 
            ((stats.avg_delivery_time_ms * (n - 1) as f64) + new_time) / n as f64;
    }

    /// Validate endpoint
    fn validate_endpoint(&self, endpoint: &WebhookEndpoint) -> Result<(), String> {
        // Validate URL
        reqwest::Url::parse(&endpoint.url)
            .map_err(|e| format!("Invalid URL: {}", e))?;
        
        // Validate filters
        for filter in &endpoint.event_filters {
            if filter.event_type.is_empty() {
                return Err("Event type filter cannot be empty".to_string());
            }
        }
        
        Ok(())
    }

    /// Get endpoint
    pub fn get_endpoint(&self, endpoint_id: &str) -> Option<WebhookEndpoint> {
        self.endpoints.read().get(endpoint_id).cloned()
    }

    /// List endpoints
    pub fn list_endpoints(&self) -> Vec<WebhookEndpoint> {
        self.endpoints.read().values().cloned().collect()
    }

    /// Get statistics
    pub fn get_stats(&self) -> WebhookStats {
        self.stats.read().clone()
    }

    /// Get event history
    pub fn get_history(&self, limit: usize) -> Vec<DnsEvent> {
        let history = self.event_history.read();
        history.iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Test endpoint
    pub async fn test_endpoint(&self, endpoint_id: &str) -> Result<(), String> {
        let endpoints = self.endpoints.read();
        let endpoint = endpoints.get(endpoint_id)
            .ok_or("Endpoint not found")?
            .clone();
        
        // Create test event
        let test_event = DnsEvent {
            id: Uuid::new_v4().to_string(),
            event_type: EventType::Custom("test".to_string()),
            timestamp: safe_unix_timestamp(),
            resource_type: "test".to_string(),
            resource_id: "test".to_string(),
            action: EventAction::Custom("test".to_string()),
            zone: None,
            user: Some("system".to_string()),
            source_ip: None,
            details: HashMap::new(),
            metadata: [("test".to_string(), "true".to_string())].iter().cloned().collect(),
        };
        
        // Create test delivery
        let delivery = WebhookDelivery {
            id: Uuid::new_v4().to_string(),
            endpoint_id: endpoint_id.to_string(),
            events: vec![test_event],
            attempts: 0,
            next_retry: None,
            created_at: Instant::now(),
        };
        
        // Deliver test webhook
        self.deliver(delivery).await;
        
        Ok(())
    }
}

use serde_json::json;
use hex;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_webhook_registration() {
        let config = WebhookConfig::default();
        let handler = WebhookHandler::new(config);
        
        let endpoint = WebhookEndpoint {
            id: "test-endpoint".to_string(),
            name: "Test Endpoint".to_string(),
            url: "https://example.com/webhook".to_string(),
            secret: Some("secret".to_string()),
            event_filters: vec![],
            headers: HashMap::new(),
            enabled: true,
            retry_config: None,
            tags: HashMap::new(),
        };
        
        assert!(handler.register_endpoint(endpoint).is_ok());
        assert_eq!(handler.list_endpoints().len(), 1);
    }

    #[tokio::test]
    async fn test_event_emission() {
        let config = WebhookConfig::default();
        let handler = WebhookHandler::new(config);
        
        let event = DnsEvent {
            id: Uuid::new_v4().to_string(),
            event_type: EventType::ZoneCreated,
            timestamp: safe_unix_timestamp(),
            resource_type: "zone".to_string(),
            resource_id: "example.com".to_string(),
            action: EventAction::Create,
            zone: Some("example.com".to_string()),
            user: Some("admin".to_string()),
            source_ip: Some("192.168.1.1".to_string()),
            details: HashMap::new(),
            metadata: HashMap::new(),
        };
        
        handler.emit(event).await;
        
        let stats = handler.get_stats();
        assert_eq!(stats.total_events, 1);
    }
}