//! Prometheus Metrics Module
//!
//! Provides comprehensive DNS server metrics for monitoring and observability.
//! Exports metrics in Prometheus format for integration with monitoring stacks.
//!
//! # Metrics Categories
//! 
//! * **DNS Query Metrics** - Request counts, types, response codes
//! * **Performance Metrics** - Response times, cache hit rates, throughput
//! * **Security Metrics** - Rate limiting, blocked queries, threat detection
//! * **System Metrics** - Memory usage, connection counts, error rates
//! * **Health Metrics** - Uptime, availability, dependency health

use lazy_static::lazy_static;
use prometheus::{
    GaugeVec, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec,
    register_gauge_vec, register_histogram_vec,
    register_int_counter_vec, register_int_gauge, register_int_gauge_vec,
    Encoder, TextEncoder, Registry,
};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

lazy_static! {
    /// DNS query counters by protocol and query type
    pub static ref DNS_QUERIES_TOTAL: IntCounterVec = register_int_counter_vec!(
        "atlas_dns_queries_total",
        "Total number of DNS queries received",
        &["protocol", "query_type", "zone"]
    ).unwrap();

    /// DNS response counters by response code
    pub static ref DNS_RESPONSES_TOTAL: IntCounterVec = register_int_counter_vec!(
        "atlas_dns_responses_total", 
        "Total number of DNS responses sent",
        &["response_code", "protocol", "query_type"]
    ).unwrap();

    /// DNS query duration histogram
    pub static ref DNS_QUERY_DURATION: HistogramVec = register_histogram_vec!(
        "atlas_dns_query_duration_seconds",
        "DNS query processing duration in seconds",
        &["protocol", "query_type", "cache_hit"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    ).unwrap();

    /// Cache hit/miss counters
    pub static ref DNS_CACHE_OPERATIONS: IntCounterVec = register_int_counter_vec!(
        "atlas_dns_cache_operations_total",
        "DNS cache operations (hit/miss/eviction)",
        &["operation", "record_type"]
    ).unwrap();

    /// Cache size gauge
    pub static ref DNS_CACHE_SIZE: IntGaugeVec = register_int_gauge_vec!(
        "atlas_dns_cache_size",
        "Current number of entries in DNS cache",
        &["cache_type"]
    ).unwrap();

    /// Active connections gauge
    pub static ref ACTIVE_CONNECTIONS: IntGaugeVec = register_int_gauge_vec!(
        "atlas_active_connections",
        "Current number of active connections",
        &["protocol", "connection_type"]
    ).unwrap();

    /// Rate limiting counters
    pub static ref RATE_LIMIT_EVENTS: IntCounterVec = register_int_counter_vec!(
        "atlas_rate_limit_events_total",
        "Rate limiting events",
        &["action", "client_type"]
    ).unwrap();

    /// Security threat counters
    pub static ref SECURITY_EVENTS: IntCounterVec = register_int_counter_vec!(
        "atlas_security_events_total",
        "Security events detected",
        &["event_type", "severity", "action"]
    ).unwrap();

    /// Memory usage gauges
    pub static ref MEMORY_USAGE: GaugeVec = register_gauge_vec!(
        "atlas_memory_usage_bytes",
        "Memory usage by component",
        &["component"]
    ).unwrap();

    /// Zone statistics
    pub static ref ZONE_STATS: IntGaugeVec = register_int_gauge_vec!(
        "atlas_zones",
        "Zone statistics",
        &["metric"]
    ).unwrap();

    /// Upstream DNS server metrics
    pub static ref UPSTREAM_QUERIES: IntCounterVec = register_int_counter_vec!(
        "atlas_upstream_queries_total",
        "Queries sent to upstream DNS servers",
        &["upstream", "status"]
    ).unwrap();

    /// Upstream response times
    pub static ref UPSTREAM_DURATION: HistogramVec = register_histogram_vec!(
        "atlas_upstream_duration_seconds",
        "Upstream DNS query duration",
        &["upstream"],
        vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    ).unwrap();

    /// DNSSEC operations
    pub static ref DNSSEC_OPERATIONS: IntCounterVec = register_int_counter_vec!(
        "atlas_dnssec_operations_total",
        "DNSSEC validation operations",
        &["operation", "result"]
    ).unwrap();

    /// Health check metrics
    pub static ref HEALTH_CHECKS: IntCounterVec = register_int_counter_vec!(
        "atlas_health_checks_total",
        "Health check results",
        &["check_type", "status"]
    ).unwrap();

    /// Server uptime
    pub static ref SERVER_UPTIME: IntGauge = register_int_gauge!(
        "atlas_server_uptime_seconds",
        "Server uptime in seconds"
    ).unwrap();

    /// Configuration reload events
    pub static ref CONFIG_RELOADS: IntCounterVec = register_int_counter_vec!(
        "atlas_config_reloads_total",
        "Configuration reload events",
        &["status"]
    ).unwrap();

    /// Error counters by component
    pub static ref ERRORS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "atlas_errors_total",
        "Total errors by component and type",
        &["component", "error_type"]
    ).unwrap();

    /// Web interface metrics
    pub static ref WEB_REQUESTS: IntCounterVec = register_int_counter_vec!(
        "atlas_web_requests_total",
        "Web interface HTTP requests",
        &["method", "endpoint", "status_code"]
    ).unwrap();

    /// Web request duration
    pub static ref WEB_REQUEST_DURATION: HistogramVec = register_histogram_vec!(
        "atlas_web_request_duration_seconds",
        "Web request processing duration",
        &["method", "endpoint"],
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    ).unwrap();

    /// User sessions
    pub static ref USER_SESSIONS: IntGaugeVec = register_int_gauge_vec!(
        "atlas_user_sessions",
        "Active user sessions",
        &["role"]
    ).unwrap();
    /// Unique clients gauge
    pub static ref UNIQUE_CLIENTS: IntGauge = register_int_gauge!(
        "atlas_unique_clients_total",
        "Total number of unique clients"
    ).unwrap();

    /// Response time percentiles
    pub static ref RESPONSE_TIME_PERCENTILES: GaugeVec = register_gauge_vec!(
        "atlas_response_time_percentiles_ms",
        "Response time percentiles in milliseconds",
        &["percentile"]
    ).unwrap();

    /// Protocol usage counters
    pub static ref PROTOCOL_USAGE: IntCounterVec = register_int_counter_vec!(
        "atlas_protocol_usage_total",
        "Total queries by protocol (DoH, DoT, DoQ, standard)",
        &["protocol_type"]
    ).unwrap();

    /// Cache hit rate gauge
    pub static ref CACHE_HIT_RATE: GaugeVec = register_gauge_vec!(
        "atlas_cache_hit_rate",
        "Cache hit rate percentage",
        &["window"]
    ).unwrap();
    
    /// Web request size in bytes
    pub static ref WEB_REQUEST_SIZE: HistogramVec = register_histogram_vec!(
        "atlas_web_request_size_bytes",
        "Web request size in bytes",
        &["method", "endpoint"],
        vec![100.0, 500.0, 1000.0, 5000.0, 10000.0, 50000.0, 100000.0, 500000.0, 1000000.0]
    ).unwrap();
    
    /// Web response size in bytes
    pub static ref WEB_RESPONSE_SIZE: HistogramVec = register_histogram_vec!(
        "atlas_web_response_size_bytes",
        "Web response size in bytes",
        &["method", "endpoint"],
        vec![100.0, 500.0, 1000.0, 5000.0, 10000.0, 50000.0, 100000.0, 500000.0, 1000000.0]
    ).unwrap();
}

/// Comprehensive metrics summary structure
#[derive(Debug, Clone)]
pub struct MetricsSummary {
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_hit_rate: f64,
    pub unique_clients: usize,
    pub percentiles: HashMap<String, f64>,
    pub query_type_distribution: HashMap<String, (u64, f64)>,
    pub response_code_distribution: HashMap<String, (u64, f64)>,
    pub protocol_distribution: HashMap<String, (u64, f64)>,
    pub api_requests_today: u64,
    pub api_avg_response_time: f64,
    pub web_requests_total: u64,
}

/// Enhanced statistics tracker for real-time metrics
pub struct MetricsTracker {
    /// Track unique clients
    unique_clients: Arc<RwLock<HashSet<String>>>,
    /// Response time samples for percentile calculation
    response_times: Arc<RwLock<Vec<f64>>>,
    /// Cache hit/miss counters for rate calculation
    cache_hits: Arc<RwLock<u64>>,
    cache_misses: Arc<RwLock<u64>>,
    /// Query type distribution
    query_types: Arc<RwLock<HashMap<String, u64>>>,
    /// Response code distribution
    response_codes: Arc<RwLock<HashMap<String, u64>>>,
    /// Protocol usage tracking
    protocol_usage: Arc<RwLock<HashMap<String, u64>>>,
    /// API request tracking with timestamp
    api_requests: Arc<RwLock<Vec<(SystemTime, f64)>>>, // (timestamp, response_time_ms)
    /// Web request counter
    web_requests_total: Arc<RwLock<u64>>,
}

impl MetricsTracker {
    pub fn new() -> Self {
        Self {
            unique_clients: Arc::new(RwLock::new(HashSet::new())),
            response_times: Arc::new(RwLock::new(Vec::new())),
            cache_hits: Arc::new(RwLock::new(0)),
            cache_misses: Arc::new(RwLock::new(0)),
            query_types: Arc::new(RwLock::new(HashMap::new())),
            response_codes: Arc::new(RwLock::new(HashMap::new())),
            protocol_usage: Arc::new(RwLock::new(HashMap::new())),
            api_requests: Arc::new(RwLock::new(Vec::new())),
            web_requests_total: Arc::new(RwLock::new(0)),
        }
    }

    /// Track a unique client
    pub fn track_client(&self, client_ip: String) {
        if let Ok(mut clients) = self.unique_clients.write() {
            clients.insert(client_ip);
            UNIQUE_CLIENTS.set(clients.len() as i64);
        }
    }

    /// Track response time
    pub fn track_response_time(&self, duration_ms: f64) {
        if let Ok(mut times) = self.response_times.write() {
            times.push(duration_ms);
            // Keep only last 10000 samples to prevent unbounded growth
            if times.len() > 10000 {
                times.drain(0..1000);
            }
        }
    }

    /// Track cache hit
    pub fn track_cache_hit(&self, record_type: &str) {
        if let Ok(mut hits) = self.cache_hits.write() {
            *hits += 1;
        }
        DNS_CACHE_OPERATIONS.with_label_values(&["hit", record_type]).inc();
        self.update_cache_hit_rate();
    }

    /// Track cache miss
    pub fn track_cache_miss(&self, record_type: &str) {
        if let Ok(mut misses) = self.cache_misses.write() {
            *misses += 1;
        }
        DNS_CACHE_OPERATIONS.with_label_values(&["miss", record_type]).inc();
        self.update_cache_hit_rate();
    }

    /// Update cache hit rate metric
    fn update_cache_hit_rate(&self) {
        if let (Ok(hits), Ok(misses)) = (self.cache_hits.read(), self.cache_misses.read()) {
            let total = *hits + *misses;
            if total > 0 {
                let hit_rate = (*hits as f64 / total as f64) * 100.0;
                CACHE_HIT_RATE.with_label_values(&["overall"]).set(hit_rate);
            }
        }
    }

    /// Track query type
    pub fn track_query_type(&self, query_type: &str) {
        if let Ok(mut types) = self.query_types.write() {
            *types.entry(query_type.to_string()).or_insert(0) += 1;
        }
    }

    /// Track response code
    pub fn track_response_code(&self, response_code: &str) {
        if let Ok(mut codes) = self.response_codes.write() {
            *codes.entry(response_code.to_string()).or_insert(0) += 1;
        }
    }

    /// Track protocol usage
    pub fn track_protocol(&self, protocol: &str) {
        if let Ok(mut usage) = self.protocol_usage.write() {
            *usage.entry(protocol.to_string()).or_insert(0) += 1;
        }
        PROTOCOL_USAGE.with_label_values(&[protocol]).inc();
    }

    /// Calculate response time percentiles
    pub fn calculate_percentiles(&self) -> HashMap<String, f64> {
        let mut percentiles = HashMap::new();
        
        if let Ok(mut times) = self.response_times.write() {
            if !times.is_empty() {
                times.sort_by(|a, b| a.partial_cmp(b).unwrap());
                
                let p50_idx = (times.len() as f64 * 0.50) as usize;
                let p90_idx = (times.len() as f64 * 0.90) as usize;
                let p95_idx = (times.len() as f64 * 0.95) as usize;
                let p99_idx = (times.len() as f64 * 0.99) as usize;
                
                let p50 = times.get(p50_idx).copied().unwrap_or(0.0);
                let p90 = times.get(p90_idx).copied().unwrap_or(0.0);
                let p95 = times.get(p95_idx).copied().unwrap_or(0.0);
                let p99 = times.get(p99_idx).copied().unwrap_or(0.0);
                
                percentiles.insert("p50".to_string(), p50);
                percentiles.insert("p90".to_string(), p90);
                percentiles.insert("p95".to_string(), p95);
                percentiles.insert("p99".to_string(), p99);
                
                // Update Prometheus metrics
                RESPONSE_TIME_PERCENTILES.with_label_values(&["p50"]).set(p50);
                RESPONSE_TIME_PERCENTILES.with_label_values(&["p90"]).set(p90);
                RESPONSE_TIME_PERCENTILES.with_label_values(&["p95"]).set(p95);
                RESPONSE_TIME_PERCENTILES.with_label_values(&["p99"]).set(p99);
            }
        }
        
        percentiles
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> (u64, u64, f64) {
        let hits = self.cache_hits.read().unwrap_or_else(|e| e.into_inner());
        let misses = self.cache_misses.read().unwrap_or_else(|e| e.into_inner());
        let total = *hits + *misses;
        let hit_rate = if total > 0 {
            (*hits as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        (*hits, *misses, hit_rate)
    }

    /// Get query type distribution
    pub fn get_query_type_distribution(&self) -> HashMap<String, (u64, f64)> {
        if let Ok(types) = self.query_types.read() {
            let total: u64 = types.values().sum();
            types.iter()
                .map(|(k, v)| {
                    let percentage = if total > 0 {
                        (*v as f64 / total as f64) * 100.0
                    } else {
                        0.0
                    };
                    (k.clone(), (*v, percentage))
                })
                .collect()
        } else {
            HashMap::new()
        }
    }

    /// Get response code distribution  
    pub fn get_response_code_distribution(&self) -> HashMap<String, (u64, f64)> {
        if let Ok(codes) = self.response_codes.read() {
            let total: u64 = codes.values().sum();
            codes.iter()
                .map(|(k, v)| {
                    let percentage = if total > 0 {
                        (*v as f64 / total as f64) * 100.0
                    } else {
                        0.0
                    };
                    (k.clone(), (*v, percentage))
                })
                .collect()
        } else {
            HashMap::new()
        }
    }

    /// Get protocol usage distribution
    pub fn get_protocol_distribution(&self) -> HashMap<String, (u64, f64)> {
        if let Ok(usage) = self.protocol_usage.read() {
            let total: u64 = usage.values().sum();
            usage.iter()
                .map(|(k, v)| {
                    let percentage = if total > 0 {
                        (*v as f64 / total as f64) * 100.0
                    } else {
                        0.0
                    };
                    (k.clone(), (*v, percentage))
                })
                .collect()
        } else {
            HashMap::new()
        }
    }

    /// Track an API request
    pub fn track_api_request(&self, response_time_ms: f64) {
        let now = SystemTime::now();
        if let Ok(mut requests) = self.api_requests.write() {
            requests.push((now, response_time_ms));
            
            // Keep only last 1000 requests to prevent memory growth
            let current_len = requests.len();
            if current_len > 1000 {
                requests.drain(0..current_len-1000);
            }
        }
    }

    /// Track a web request
    pub fn track_web_request(&self) {
        if let Ok(mut total) = self.web_requests_total.write() {
            *total += 1;
        }
    }

    /// Get API requests from today
    pub fn get_api_requests_today(&self) -> u64 {
        let now = SystemTime::now();
        let today_start = now
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() / 86400 * 86400; // Start of today in seconds
        let today_start_time = UNIX_EPOCH + Duration::from_secs(today_start);
        
        if let Ok(requests) = self.api_requests.read() {
            requests.iter()
                .filter(|(timestamp, _)| *timestamp >= today_start_time)
                .count() as u64
        } else {
            0
        }
    }

    /// Get average API response time
    pub fn get_api_avg_response_time(&self) -> f64 {
        if let Ok(requests) = self.api_requests.read() {
            if requests.is_empty() {
                return 0.0;
            }
            
            let total_time: f64 = requests.iter().map(|(_, time)| *time).sum();
            total_time / requests.len() as f64
        } else {
            0.0
        }
    }

    /// Get total web requests
    pub fn get_web_requests_total(&self) -> u64 {
        if let Ok(total) = self.web_requests_total.read() {
            *total
        } else {
            0
        }
    }

    /// Get unique client count
    pub fn get_unique_client_count(&self) -> usize {
        self.unique_clients.read()
            .map(|clients| clients.len())
            .unwrap_or(0)
    }
}

/// Metrics collector for Atlas DNS server
pub struct MetricsCollector {
    start_time: Instant,
    registry: Registry,
    tracker: Arc<MetricsTracker>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Self {
        initialize_metrics();
        Self {
            start_time: Instant::now(),
            registry: Registry::new(),
            tracker: Arc::new(MetricsTracker::new()),
        }
    }

    /// Get the metrics tracker
    pub fn tracker(&self) -> Arc<MetricsTracker> {
        self.tracker.clone()
    }

    /// Update server uptime metric
    pub fn update_uptime(&self) {
        let uptime = self.start_time.elapsed().as_secs();
        SERVER_UPTIME.set(uptime as i64);
    }

    /// Record a DNS query
    pub fn record_dns_query(&self, protocol: &str, query_type: &str, zone: &str) {
        DNS_QUERIES_TOTAL
            .with_label_values(&[protocol, query_type, zone])
            .inc();
        
        // Track query type distribution
        self.tracker.track_query_type(query_type);
    }

    /// Record a DNS query with client tracking
    pub fn record_dns_query_with_client(&self, protocol: &str, query_type: &str, zone: &str, client_ip: &str) {
        self.record_dns_query(protocol, query_type, zone);
        self.tracker.track_client(client_ip.to_string());
    }

    /// Record a DNS response
    pub fn record_dns_response(&self, response_code: &str, protocol: &str, query_type: &str) {
        DNS_RESPONSES_TOTAL
            .with_label_values(&[response_code, protocol, query_type])
            .inc();
        
        // Track response code distribution
        self.tracker.track_response_code(response_code);
    }

    /// Record protocol usage (DoH, DoT, DoQ, standard)
    pub fn record_protocol_usage(&self, protocol_type: &str) {
        self.tracker.track_protocol(protocol_type);
    }

    /// Record DNS query duration
    pub fn record_query_duration(&self, duration: Duration, protocol: &str, query_type: &str, cache_hit: bool) {
        let cache_hit_str = if cache_hit { "hit" } else { "miss" };
        let duration_secs = duration.as_secs_f64();
        DNS_QUERY_DURATION
            .with_label_values(&[protocol, query_type, cache_hit_str])
            .observe(duration_secs);
        
        // Track response time in milliseconds for percentile calculation
        self.tracker.track_response_time(duration_secs * 1000.0);
    }

    /// Record cache operation
    pub fn record_cache_operation(&self, operation: &str, record_type: &str) {
        match operation {
            "hit" => self.tracker.track_cache_hit(record_type),
            "miss" => self.tracker.track_cache_miss(record_type),
            _ => {
                DNS_CACHE_OPERATIONS
                    .with_label_values(&[operation, record_type])
                    .inc();
            }
        }
    }

    /// Update cache size
    pub fn update_cache_size(&self, cache_type: &str, size: i64) {
        DNS_CACHE_SIZE
            .with_label_values(&[cache_type])
            .set(size);
    }

    /// Update active connections
    pub fn update_active_connections(&self, protocol: &str, connection_type: &str, count: i64) {
        ACTIVE_CONNECTIONS
            .with_label_values(&[protocol, connection_type])
            .set(count);
    }

    /// Record rate limiting event
    pub fn record_rate_limit(&self, action: &str, client_type: &str) {
        RATE_LIMIT_EVENTS
            .with_label_values(&[action, client_type])
            .inc();
    }

    /// Record security event
    pub fn record_security_event(&self, event_type: &str, severity: &str, action: &str) {
        SECURITY_EVENTS
            .with_label_values(&[event_type, severity, action])
            .inc();
    }

    /// Update memory usage
    pub fn update_memory_usage(&self, component: &str, bytes: f64) {
        MEMORY_USAGE
            .with_label_values(&[component])
            .set(bytes);
    }

    /// Update zone statistics
    pub fn update_zone_stats(&self, metric: &str, value: i64) {
        ZONE_STATS
            .with_label_values(&[metric])
            .set(value);
    }

    /// Record upstream query
    pub fn record_upstream_query(&self, upstream: &str, status: &str) {
        UPSTREAM_QUERIES
            .with_label_values(&[upstream, status])
            .inc();
    }

    /// Record upstream query duration
    pub fn record_upstream_duration(&self, upstream: &str, duration: Duration) {
        UPSTREAM_DURATION
            .with_label_values(&[upstream])
            .observe(duration.as_secs_f64());
    }

    /// Record DNSSEC operation
    pub fn record_dnssec_operation(&self, operation: &str, result: &str) {
        DNSSEC_OPERATIONS
            .with_label_values(&[operation, result])
            .inc();
    }

    /// Record health check
    pub fn record_health_check(&self, check_type: &str, status: &str) {
        HEALTH_CHECKS
            .with_label_values(&[check_type, status])
            .inc();
    }

    /// Record configuration reload
    pub fn record_config_reload(&self, status: &str) {
        CONFIG_RELOADS
            .with_label_values(&[status])
            .inc();
    }

    /// Record error
    pub fn record_error(&self, component: &str, error_type: &str) {
        ERRORS_TOTAL
            .with_label_values(&[component, error_type])
            .inc();
    }

    /// Record web request
    pub fn record_web_request(&self, method: &str, endpoint: &str, status_code: &str) {
        WEB_REQUESTS
            .with_label_values(&[method, endpoint, status_code])
            .inc();
        
        // Track in our internal metrics
        self.tracker.track_web_request();
    }

    /// Record web request duration
    pub fn record_web_duration(&self, method: &str, endpoint: &str, duration: Duration) {
        WEB_REQUEST_DURATION
            .with_label_values(&[method, endpoint])
            .observe(duration.as_secs_f64());
        
        // Track API requests separately
        if endpoint.starts_with("/api") || endpoint.starts_with("/graphql") {
            self.tracker.track_api_request(duration.as_millis() as f64);
        }
    }

    /// Update user sessions
    pub fn update_user_sessions(&self, role: &str, count: i64) {
        USER_SESSIONS
            .with_label_values(&[role])
            .set(count);
    }
    
    /// Record web request size
    pub fn record_web_request_size(&self, method: &str, endpoint: &str, size: u64) {
        WEB_REQUEST_SIZE
            .with_label_values(&[method, endpoint])
            .observe(size as f64);
    }
    
    /// Record web response size
    pub fn record_web_response_size(&self, method: &str, endpoint: &str, size: u64) {
        WEB_RESPONSE_SIZE
            .with_label_values(&[method, endpoint])
            .observe(size as f64);
    }

    /// Record upstream query duration
    pub fn record_upstream_query_duration(&self, duration_ms: f64) {
        UPSTREAM_DURATION
            .with_label_values(&["default"])
            .observe(duration_ms / 1000.0);
    }

    /// Record upstream query success
    pub fn record_upstream_query_success(&self) {
        UPSTREAM_QUERIES
            .with_label_values(&["default", "success"])
            .inc();
    }

    /// Record upstream query failure
    pub fn record_upstream_query_failure(&self) {
        UPSTREAM_QUERIES
            .with_label_values(&["default", "failure"])
            .inc();
    }

    /// Export metrics in Prometheus format
    pub fn export_metrics(&self) -> Result<String, Box<dyn std::error::Error>> {
        self.update_uptime();
        
        // Update percentiles before export
        self.tracker.calculate_percentiles();
        
        let encoder = TextEncoder::new();
        let metric_families = prometheus::gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        
        Ok(String::from_utf8(buffer)?)
    }

    /// Get comprehensive metrics summary
    pub fn get_metrics_summary(&self) -> MetricsSummary {
        let (cache_hits, cache_misses, cache_hit_rate) = self.tracker.get_cache_stats();
        let percentiles = self.tracker.calculate_percentiles();
        let query_types = self.tracker.get_query_type_distribution();
        let response_codes = self.tracker.get_response_code_distribution();
        let protocol_usage = self.tracker.get_protocol_distribution();
        
        MetricsSummary {
            cache_hits,
            cache_misses,
            cache_hit_rate,
            unique_clients: self.tracker.get_unique_client_count(),
            percentiles,
            query_type_distribution: query_types,
            response_code_distribution: response_codes,
            protocol_distribution: protocol_usage,
            api_requests_today: self.tracker.get_api_requests_today(),
            api_avg_response_time: self.tracker.get_api_avg_response_time(),
            web_requests_total: self.tracker.get_web_requests_total(),
        }
    }

    /// Get metrics registry
    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Query timer for measuring DNS query duration
pub struct QueryTimer {
    start: Instant,
    protocol: String,
    query_type: String,
    collector: Option<&'static MetricsCollector>,
}

impl QueryTimer {
    /// Start a new query timer
    pub fn start(protocol: String, query_type: String) -> Self {
        Self {
            start: Instant::now(),
            protocol,
            query_type,
            collector: None,
        }
    }

    /// Finish the timer and record the duration
    pub fn finish(self, cache_hit: bool) {
        let duration = self.start.elapsed();
        
        // Record to global metrics if available
        if let Some(collector) = self.collector {
            collector.record_query_duration(duration, &self.protocol, &self.query_type, cache_hit);
        } else {
            // Fall back to global metrics
            let cache_hit_str = if cache_hit { "hit" } else { "miss" };
            DNS_QUERY_DURATION
                .with_label_values(&[&self.protocol, &self.query_type, cache_hit_str])
                .observe(duration.as_secs_f64());
        }
    }
}

/// Helper macro for timing DNS queries
#[macro_export]
macro_rules! time_dns_query {
    ($protocol:expr, $query_type:expr, $cache_hit:expr, $block:block) => {{
        let timer = $crate::dns::metrics::QueryTimer::start($protocol.to_string(), $query_type.to_string());
        let result = $block;
        timer.finish($cache_hit);
        result
    }};
}

/// Helper macro for recording errors with context
#[macro_export]
macro_rules! record_error {
    ($component:expr, $error_type:expr) => {
        $crate::dns::metrics::ERRORS_TOTAL
            .with_label_values(&[$component, $error_type])
            .inc();
    };
    ($component:expr, $error_type:expr, $error:expr) => {
        $crate::dns::metrics::ERRORS_TOTAL
            .with_label_values(&[$component, $error_type])
            .inc();
        log::error!("Error in {}: {} - {:?}", $component, $error_type, $error);
    };
}

/// Helper function to initialize metrics with default values
pub fn initialize_metrics() {
    // Initialize cache metrics
    DNS_CACHE_SIZE.with_label_values(&["response"]).set(0);
    DNS_CACHE_SIZE.with_label_values(&["negative"]).set(0);
    
    // Initialize connection metrics
    ACTIVE_CONNECTIONS.with_label_values(&["udp", "server"]).set(0);
    ACTIVE_CONNECTIONS.with_label_values(&["tcp", "server"]).set(0);
    ACTIVE_CONNECTIONS.with_label_values(&["tls", "server"]).set(0);
    ACTIVE_CONNECTIONS.with_label_values(&["https", "server"]).set(0);
    
    // Initialize zone metrics
    ZONE_STATS.with_label_values(&["total_zones"]).set(0);
    ZONE_STATS.with_label_values(&["total_records"]).set(0);
    
    // Initialize user session metrics
    USER_SESSIONS.with_label_values(&["admin"]).set(0);
    USER_SESSIONS.with_label_values(&["user"]).set(0);
    USER_SESSIONS.with_label_values(&["readonly"]).set(0);
    
    log::info!("Prometheus metrics initialized");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_metrics_collector_creation() {
        let collector = MetricsCollector::new();
        assert!(collector.start_time.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn test_dns_query_recording() {
        let collector = MetricsCollector::new();
        
        collector.record_dns_query("udp", "A", "example.com");
        collector.record_dns_response("NOERROR", "udp", "A");
        
        // Verify metrics were recorded (values should be > 0)
        let metrics = collector.export_metrics().unwrap();
        assert!(metrics.contains("atlas_dns_queries_total"));
        assert!(metrics.contains("atlas_dns_responses_total"));
    }

    #[test]
    fn test_query_timer() {
        let timer = QueryTimer::start("udp".to_string(), "A".to_string());
        thread::sleep(Duration::from_millis(10));
        timer.finish(false);
        
        // Timer should record duration to metrics
        let metrics = prometheus::gather();
        let duration_metric = metrics.iter()
            .find(|m| m.get_name() == "atlas_dns_query_duration_seconds");
        assert!(duration_metric.is_some());
    }

    #[test]
    fn test_cache_metrics() {
        let collector = MetricsCollector::new();
        
        collector.record_cache_operation("hit", "A");
        collector.record_cache_operation("miss", "AAAA");
        collector.update_cache_size("response", 150);
        
        let metrics = collector.export_metrics().unwrap();
        assert!(metrics.contains("atlas_dns_cache_operations_total"));
        assert!(metrics.contains("atlas_dns_cache_size"));
    }

    #[test]
    fn test_security_metrics() {
        let collector = MetricsCollector::new();
        
        collector.record_security_event("malware_domain", "high", "blocked");
        collector.record_rate_limit("throttled", "external");
        
        let metrics = collector.export_metrics().unwrap();
        assert!(metrics.contains("atlas_security_events_total"));
        assert!(metrics.contains("atlas_rate_limit_events_total"));
    }

    #[test]
    fn test_metrics_export() {
        let collector = MetricsCollector::new();
        
        // Record some test metrics
        collector.record_dns_query("udp", "A", "test.com");
        collector.update_cache_size("response", 100);
        collector.update_active_connections("tcp", "server", 5);
        
        let exported = collector.export_metrics().unwrap();
        
        // Verify Prometheus format
        assert!(exported.contains("# HELP"));
        assert!(exported.contains("# TYPE"));
        assert!(exported.contains("atlas_"));
        
        // Verify specific metrics are present
        assert!(exported.contains("atlas_dns_queries_total"));
        assert!(exported.contains("atlas_dns_cache_size"));
        assert!(exported.contains("atlas_active_connections"));
        assert!(exported.contains("atlas_server_uptime_seconds"));
    }

    #[test]
    fn test_initialize_metrics() {
        initialize_metrics();
        
        // Verify initialization
        let metrics = prometheus::gather();
        assert!(!metrics.is_empty());
        
        // Check that default values are set
        let collector = MetricsCollector::new();
        collector.update_cache_size("response", 0);
        collector.update_zone_stats("total_zones", 0);
        
        let exported = collector.export_metrics().unwrap();
        assert!(exported.contains("atlas_dns_cache_size"));
        assert!(exported.contains("atlas_zones"));
    }

    #[test]
    fn test_metrics_tracker_client_tracking() {
        let tracker = MetricsTracker::new();
        
        // Track unique clients
        tracker.track_client("192.168.1.1".to_string());
        tracker.track_client("192.168.1.2".to_string());
        tracker.track_client("192.168.1.1".to_string()); // Duplicate, should not increase count
        
        assert_eq!(tracker.get_unique_client_count(), 2);
    }

    #[test]
    fn test_metrics_tracker_cache_hit_rate() {
        let tracker = MetricsTracker::new();
        
        // Track cache operations
        tracker.track_cache_hit("A");
        tracker.track_cache_hit("AAAA");
        tracker.track_cache_miss("MX");
        
        let (hits, misses, hit_rate) = tracker.get_cache_stats();
        assert_eq!(hits, 2);
        assert_eq!(misses, 1);
        assert!((hit_rate - 66.66).abs() < 1.0); // ~66.66% hit rate
    }

    #[test]
    fn test_metrics_tracker_response_times() {
        let tracker = MetricsTracker::new();
        
        // Track response times
        tracker.track_response_time(10.0);
        tracker.track_response_time(20.0);
        tracker.track_response_time(30.0);
        tracker.track_response_time(40.0);
        tracker.track_response_time(50.0);
        
        let percentiles = tracker.calculate_percentiles();
        
        // Verify percentiles are calculated
        assert!(percentiles.contains_key("p50"));
        assert!(percentiles.contains_key("p90"));
        assert!(percentiles.contains_key("p95"));
        assert!(percentiles.contains_key("p99"));
        
        // P50 should be around 30.0 (middle value)
        let p50 = percentiles.get("p50").unwrap();
        assert!(*p50 >= 20.0 && *p50 <= 40.0);
    }

    #[test]
    fn test_metrics_tracker_query_type_distribution() {
        let tracker = MetricsTracker::new();
        
        // Track query types
        tracker.track_query_type("A");
        tracker.track_query_type("A");
        tracker.track_query_type("AAAA");
        tracker.track_query_type("MX");
        
        let distribution = tracker.get_query_type_distribution();
        
        let a_stats = distribution.get("A").unwrap();
        assert_eq!(a_stats.0, 2); // 2 A queries
        assert!((a_stats.1 - 50.0).abs() < 1.0); // ~50% of queries
        
        let aaaa_stats = distribution.get("AAAA").unwrap();
        assert_eq!(aaaa_stats.0, 1); // 1 AAAA query
        assert!((aaaa_stats.1 - 25.0).abs() < 1.0); // ~25% of queries
    }

    #[test]
    fn test_metrics_tracker_response_code_distribution() {
        let tracker = MetricsTracker::new();
        
        // Track response codes
        tracker.track_response_code("NOERROR");
        tracker.track_response_code("NOERROR");
        tracker.track_response_code("NOERROR");
        tracker.track_response_code("NXDOMAIN");
        
        let distribution = tracker.get_response_code_distribution();
        
        let noerror_stats = distribution.get("NOERROR").unwrap();
        assert_eq!(noerror_stats.0, 3); // 3 NOERROR responses
        assert!((noerror_stats.1 - 75.0).abs() < 1.0); // ~75% of responses
        
        let nxdomain_stats = distribution.get("NXDOMAIN").unwrap();
        assert_eq!(nxdomain_stats.0, 1); // 1 NXDOMAIN response
        assert!((nxdomain_stats.1 - 25.0).abs() < 1.0); // ~25% of responses
    }

    #[test]
    fn test_metrics_tracker_protocol_distribution() {
        let tracker = MetricsTracker::new();
        
        // Track protocol usage
        tracker.track_protocol("standard");
        tracker.track_protocol("standard");
        tracker.track_protocol("DoH");
        tracker.track_protocol("DoT");
        
        let distribution = tracker.get_protocol_distribution();
        
        let standard_stats = distribution.get("standard").unwrap();
        assert_eq!(standard_stats.0, 2); // 2 standard queries
        assert!((standard_stats.1 - 50.0).abs() < 1.0); // ~50% of queries
        
        let doh_stats = distribution.get("DoH").unwrap();
        assert_eq!(doh_stats.0, 1); // 1 DoH query
        assert!((doh_stats.1 - 25.0).abs() < 1.0); // ~25% of queries
    }

    #[test]
    fn test_metrics_collector_with_client_tracking() {
        let collector = MetricsCollector::new();
        
        // Record queries with client tracking
        collector.record_dns_query_with_client("udp", "A", "example.com", "192.168.1.100");
        collector.record_dns_query_with_client("tcp", "AAAA", "example.com", "192.168.1.101");
        collector.record_dns_query_with_client("udp", "MX", "example.com", "192.168.1.100"); // Same client
        
        let summary = collector.get_metrics_summary();
        assert_eq!(summary.unique_clients, 2); // Only 2 unique clients
    }

    #[test]
    fn test_metrics_collector_protocol_usage() {
        let collector = MetricsCollector::new();
        
        // Record protocol usage
        collector.record_protocol_usage("DoH");
        collector.record_protocol_usage("DoT");
        collector.record_protocol_usage("DoH");
        collector.record_protocol_usage("standard");
        
        let summary = collector.get_metrics_summary();
        let protocol_dist = summary.protocol_distribution;
        
        assert_eq!(protocol_dist.get("DoH").unwrap().0, 2);
        assert_eq!(protocol_dist.get("DoT").unwrap().0, 1);
        assert_eq!(protocol_dist.get("standard").unwrap().0, 1);
    }

    #[test]
    fn test_comprehensive_metrics_summary() {
        let collector = MetricsCollector::new();
        
        // Simulate various DNS operations
        collector.record_dns_query_with_client("udp", "A", "example.com", "192.168.1.1");
        collector.record_dns_response("NOERROR", "udp", "A");
        collector.record_cache_operation("hit", "A");
        collector.record_query_duration(Duration::from_millis(10), "udp", "A", true);
        
        collector.record_dns_query_with_client("tcp", "AAAA", "example.org", "192.168.1.2");
        collector.record_dns_response("NXDOMAIN", "tcp", "AAAA");
        collector.record_cache_operation("miss", "AAAA");
        collector.record_query_duration(Duration::from_millis(50), "tcp", "AAAA", false);
        
        collector.record_protocol_usage("DoH");
        collector.record_protocol_usage("standard");
        
        let summary = collector.get_metrics_summary();
        
        // Verify comprehensive metrics
        assert_eq!(summary.unique_clients, 2);
        assert_eq!(summary.cache_hits, 1);
        assert_eq!(summary.cache_misses, 1);
        assert!((summary.cache_hit_rate - 50.0).abs() < 1.0);
        assert!(!summary.percentiles.is_empty());
        assert!(!summary.query_type_distribution.is_empty());
        assert!(!summary.response_code_distribution.is_empty());
        assert!(!summary.protocol_distribution.is_empty());
    }
}