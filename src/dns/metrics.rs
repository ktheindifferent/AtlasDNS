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
use std::time::{Duration, Instant};

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

/// Metrics collector for Atlas DNS server
pub struct MetricsCollector {
    start_time: Instant,
    registry: Registry,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            registry: Registry::new(),
        }
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
    }

    /// Record a DNS response
    pub fn record_dns_response(&self, response_code: &str, protocol: &str, query_type: &str) {
        DNS_RESPONSES_TOTAL
            .with_label_values(&[response_code, protocol, query_type])
            .inc();
    }

    /// Record DNS query duration
    pub fn record_query_duration(&self, duration: Duration, protocol: &str, query_type: &str, cache_hit: bool) {
        let cache_hit_str = if cache_hit { "hit" } else { "miss" };
        DNS_QUERY_DURATION
            .with_label_values(&[protocol, query_type, cache_hit_str])
            .observe(duration.as_secs_f64());
    }

    /// Record cache operation
    pub fn record_cache_operation(&self, operation: &str, record_type: &str) {
        DNS_CACHE_OPERATIONS
            .with_label_values(&[operation, record_type])
            .inc();
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
    }

    /// Record web request duration
    pub fn record_web_duration(&self, method: &str, endpoint: &str, duration: Duration) {
        WEB_REQUEST_DURATION
            .with_label_values(&[method, endpoint])
            .observe(duration.as_secs_f64());
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
        
        let encoder = TextEncoder::new();
        let metric_families = prometheus::gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        
        Ok(String::from_utf8(buffer)?)
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
}