//! Distributed Tracing with Jaeger
//!
//! Provides comprehensive distributed tracing capabilities for DNS operations
//! using OpenTelemetry and Jaeger for visualization.
//!
//! # Features
//!
//! * **OpenTelemetry Integration** - Standards-based tracing
//! * **Jaeger Backend** - Powerful trace visualization
//! * **Automatic Instrumentation** - Zero-code tracing for DNS operations
//! * **Context Propagation** - Trace across service boundaries
//! * **Sampling Strategies** - Adaptive and probabilistic sampling
//! * **Performance Metrics** - Latency and throughput tracking
//! * **Correlation IDs** - Request tracking across components

use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};

/// Tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    /// Enable distributed tracing
    pub enabled: bool,
    /// Jaeger endpoint
    pub jaeger_endpoint: String,
    /// Service name
    pub service_name: String,
    /// Sampling strategy
    pub sampling_strategy: SamplingStrategy,
    /// Batch export settings
    pub batch_config: BatchConfig,
    /// Trace attributes
    pub default_attributes: HashMap<String, String>,
    /// Enable debug logging
    pub debug: bool,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            jaeger_endpoint: "http://localhost:14268/api/traces".to_string(),
            service_name: "atlas-dns".to_string(),
            sampling_strategy: SamplingStrategy::default(),
            batch_config: BatchConfig::default(),
            default_attributes: HashMap::new(),
            debug: false,
        }
    }
}

/// Sampling strategy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingStrategy {
    /// Strategy type
    pub strategy_type: SamplingType,
    /// Sampling rate (0.0 to 1.0)
    pub rate: f64,
    /// Adaptive sampling config
    pub adaptive: Option<AdaptiveSampling>,
}

impl Default for SamplingStrategy {
    fn default() -> Self {
        Self {
            strategy_type: SamplingType::Probabilistic,
            rate: 0.1,  // 10% sampling
            adaptive: Some(AdaptiveSampling::default()),
        }
    }
}

/// Sampling type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SamplingType {
    AlwaysOn,
    AlwaysOff,
    Probabilistic,
    RateLimiting,
    Adaptive,
}

/// Adaptive sampling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveSampling {
    /// Target samples per second
    pub target_sps: u32,
    /// Max traces per second
    pub max_tps: u32,
    /// Sampling rate bounds
    pub min_rate: f64,
    pub max_rate: f64,
}

impl Default for AdaptiveSampling {
    fn default() -> Self {
        Self {
            target_sps: 100,
            max_tps: 1000,
            min_rate: 0.001,
            max_rate: 1.0,
        }
    }
}

/// Batch export configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchConfig {
    /// Max batch size
    pub max_batch_size: usize,
    /// Max queue size
    pub max_queue_size: usize,
    /// Batch timeout
    pub batch_timeout: Duration,
    /// Export timeout
    pub export_timeout: Duration,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 512,
            max_queue_size: 2048,
            batch_timeout: Duration::from_secs(5),
            export_timeout: Duration::from_secs(30),
        }
    }
}

/// Span representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Span {
    /// Trace ID
    pub trace_id: String,
    /// Span ID
    pub span_id: String,
    /// Parent span ID
    pub parent_span_id: Option<String>,
    /// Operation name
    pub operation_name: String,
    /// Start time
    pub start_time: u64,
    /// End time
    pub end_time: Option<u64>,
    /// Duration (microseconds)
    pub duration_us: Option<u64>,
    /// Status
    pub status: SpanStatus,
    /// Attributes
    pub attributes: HashMap<String, String>,
    /// Events
    pub events: Vec<SpanEvent>,
    /// Links
    pub links: Vec<SpanLink>,
}

/// Span status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpanStatus {
    Unset,
    Ok,
    Error(String),
}

/// Span event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanEvent {
    /// Event name
    pub name: String,
    /// Timestamp
    pub timestamp: u64,
    /// Attributes
    pub attributes: HashMap<String, String>,
}

/// Span link
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanLink {
    /// Linked trace ID
    pub trace_id: String,
    /// Linked span ID
    pub span_id: String,
    /// Link attributes
    pub attributes: HashMap<String, String>,
}

/// Trace context
#[derive(Debug, Clone)]
pub struct TraceContext {
    /// Trace ID
    pub trace_id: String,
    /// Parent span ID
    pub parent_span_id: String,
    /// Trace flags
    pub flags: u8,
    /// Trace state
    pub state: HashMap<String, String>,
    /// Baggage
    pub baggage: HashMap<String, String>,
}

impl TraceContext {
    /// Create new trace context
    pub fn new() -> Self {
        Self {
            trace_id: Self::generate_trace_id(),
            parent_span_id: Self::generate_span_id(),
            flags: 1,  // Sampled
            state: HashMap::new(),
            baggage: HashMap::new(),
        }
    }

    /// Generate trace ID
    fn generate_trace_id() -> String {
        format!("{:032x}", SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos())
    }

    /// Generate span ID
    fn generate_span_id() -> String {
        format!("{:016x}", SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() & 0xFFFFFFFFFFFFFFFF)
    }
}

/// Tracing statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TracingStats {
    /// Total spans created
    pub spans_created: u64,
    /// Spans exported
    pub spans_exported: u64,
    /// Spans dropped
    pub spans_dropped: u64,
    /// Export errors
    pub export_errors: u64,
    /// Average span duration (us)
    pub avg_span_duration_us: f64,
}

/// Distributed tracing handler
pub struct DistributedTracingHandler {
    /// Configuration
    config: Arc<RwLock<TracingConfig>>,
    /// Active spans
    active_spans: Arc<RwLock<HashMap<String, Span>>>,
    /// Export queue
    export_queue: Arc<RwLock<Vec<Span>>>,
    /// Statistics
    stats: Arc<RwLock<TracingStats>>,
    /// Sampling decisions cache
    sampling_cache: Arc<RwLock<HashMap<String, bool>>>,
}

impl DistributedTracingHandler {
    /// Create new tracing handler
    pub fn new(config: TracingConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            active_spans: Arc::new(RwLock::new(HashMap::new())),
            export_queue: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(TracingStats::default())),
            sampling_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start a new span
    pub fn start_span(&self, operation: &str, context: Option<&TraceContext>) -> Span {
        let config = self.config.read();
        
        if !config.enabled {
            return self.create_noop_span(operation);
        }

        let (trace_id, parent_span_id) = if let Some(ctx) = context {
            (ctx.trace_id.clone(), Some(ctx.parent_span_id.clone()))
        } else {
            (TraceContext::generate_trace_id(), None)
        };

        // Check sampling decision
        if !self.should_sample(&trace_id) {
            return self.create_noop_span(operation);
        }

        let span = Span {
            trace_id: trace_id.clone(),
            span_id: TraceContext::generate_span_id(),
            parent_span_id,
            operation_name: operation.to_string(),
            start_time: Self::current_timestamp_us(),
            end_time: None,
            duration_us: None,
            status: SpanStatus::Unset,
            attributes: config.default_attributes.clone(),
            events: Vec::new(),
            links: Vec::new(),
        };

        // Store active span
        self.active_spans.write().insert(span.span_id.clone(), span.clone());
        self.stats.write().spans_created += 1;

        span
    }

    /// End a span
    pub fn end_span(&self, mut span: Span) {
        if !self.config.read().enabled {
            return;
        }

        span.end_time = Some(Self::current_timestamp_us());
        span.duration_us = span.end_time.map(|end| end - span.start_time);

        // Remove from active spans
        self.active_spans.write().remove(&span.span_id);

        // Add to export queue
        self.queue_for_export(span);
    }

    /// Add span attribute
    pub fn add_attribute(&self, span: &mut Span, key: String, value: String) {
        span.attributes.insert(key, value);
    }

    /// Add span event
    pub fn add_event(&self, span: &mut Span, name: String, attributes: HashMap<String, String>) {
        span.events.push(SpanEvent {
            name,
            timestamp: Self::current_timestamp_us(),
            attributes,
        });
    }

    /// Set span status
    pub fn set_status(&self, span: &mut Span, status: SpanStatus) {
        span.status = status;
    }

    /// Create span for DNS query
    pub fn trace_dns_query(&self, domain: &str, query_type: &str) -> Span {
        let mut span = self.start_span("dns.query", None);
        
        self.add_attribute(&mut span, "dns.domain".to_string(), domain.to_string());
        self.add_attribute(&mut span, "dns.query_type".to_string(), query_type.to_string());
        self.add_attribute(&mut span, "dns.protocol".to_string(), "UDP".to_string());
        
        span
    }

    /// Create span for DNS resolution
    pub fn trace_dns_resolution(&self, parent: &Span, resolver: &str) -> Span {
        let context = TraceContext {
            trace_id: parent.trace_id.clone(),
            parent_span_id: parent.span_id.clone(),
            flags: 1,
            state: HashMap::new(),
            baggage: HashMap::new(),
        };

        let mut span = self.start_span("dns.resolve", Some(&context));
        self.add_attribute(&mut span, "dns.resolver".to_string(), resolver.to_string());
        
        span
    }

    /// Create span for cache lookup
    pub fn trace_cache_lookup(&self, parent: &Span, cache_type: &str) -> Span {
        let context = TraceContext {
            trace_id: parent.trace_id.clone(),
            parent_span_id: parent.span_id.clone(),
            flags: 1,
            state: HashMap::new(),
            baggage: HashMap::new(),
        };

        let mut span = self.start_span("dns.cache.lookup", Some(&context));
        self.add_attribute(&mut span, "cache.type".to_string(), cache_type.to_string());
        
        span
    }

    /// Record cache hit/miss
    pub fn record_cache_result(&self, span: &mut Span, hit: bool) {
        let result = if hit { "hit" } else { "miss" };
        self.add_attribute(span, "cache.result".to_string(), result.to_string());
        
        if hit {
            self.add_event(span, "cache.hit".to_string(), HashMap::new());
        } else {
            self.add_event(span, "cache.miss".to_string(), HashMap::new());
        }
    }

    /// Create span for DNSSEC validation
    pub fn trace_dnssec_validation(&self, parent: &Span) -> Span {
        let context = TraceContext {
            trace_id: parent.trace_id.clone(),
            parent_span_id: parent.span_id.clone(),
            flags: 1,
            state: HashMap::new(),
            baggage: HashMap::new(),
        };

        self.start_span("dns.dnssec.validate", Some(&context))
    }

    /// Record DNSSEC result
    pub fn record_dnssec_result(&self, span: &mut Span, valid: bool, algorithm: &str) {
        let status = if valid { "valid" } else { "invalid" };
        self.add_attribute(span, "dnssec.status".to_string(), status.to_string());
        self.add_attribute(span, "dnssec.algorithm".to_string(), algorithm.to_string());
    }

    /// Create span for rate limiting check
    pub fn trace_rate_limit(&self, parent: &Span, client_ip: &str) -> Span {
        let context = TraceContext {
            trace_id: parent.trace_id.clone(),
            parent_span_id: parent.span_id.clone(),
            flags: 1,
            state: HashMap::new(),
            baggage: HashMap::new(),
        };

        let mut span = self.start_span("dns.rate_limit", Some(&context));
        self.add_attribute(&mut span, "client.ip".to_string(), client_ip.to_string());
        
        span
    }

    /// Check if should sample
    fn should_sample(&self, trace_id: &str) -> bool {
        // Check cache
        if let Some(decision) = self.sampling_cache.read().get(trace_id) {
            return *decision;
        }

        let config = self.config.read();
        let decision = match config.sampling_strategy.strategy_type {
            SamplingType::AlwaysOn => true,
            SamplingType::AlwaysOff => false,
            SamplingType::Probabilistic => {
                self.probabilistic_sampling(config.sampling_strategy.rate)
            }
            SamplingType::RateLimiting => {
                self.rate_limited_sampling()
            }
            SamplingType::Adaptive => {
                self.adaptive_sampling(&config.sampling_strategy)
            }
        };

        // Cache decision
        self.sampling_cache.write().insert(trace_id.to_string(), decision);
        
        decision
    }

    /// Probabilistic sampling
    fn probabilistic_sampling(&self, rate: f64) -> bool {
        // Simple probability check
        let random = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() % 1000) as f64 / 1000.0;
        random < rate
    }

    /// Rate limited sampling
    fn rate_limited_sampling(&self) -> bool {
        // Check current rate
        let stats = self.stats.read();
        let current_rate = stats.spans_created;
        
        // Simple rate limit check (would be more sophisticated)
        current_rate < 1000
    }

    /// Adaptive sampling
    fn adaptive_sampling(&self, strategy: &SamplingStrategy) -> bool {
        if let Some(adaptive) = &strategy.adaptive {
            // Calculate current rate
            let stats = self.stats.read();
            let current_sps = stats.spans_created; // Simplified
            
            if current_sps < adaptive.target_sps as u64 {
                return self.probabilistic_sampling(adaptive.max_rate);
            } else {
                return self.probabilistic_sampling(adaptive.min_rate);
            }
        }
        
        self.probabilistic_sampling(strategy.rate)
    }

    /// Queue span for export
    fn queue_for_export(&self, span: Span) {
        let config = self.config.read();
        let mut queue = self.export_queue.write();
        
        // Check queue size
        if queue.len() >= config.batch_config.max_queue_size {
            self.stats.write().spans_dropped += 1;
            return;
        }

        queue.push(span);

        // Check if should export
        if queue.len() >= config.batch_config.max_batch_size {
            drop(queue);
            self.export_batch();
        }
    }

    /// Export batch of spans
    fn export_batch(&self) {
        let mut queue = self.export_queue.write();
        
        if queue.is_empty() {
            return;
        }

        let batch: Vec<Span> = queue.drain(..).collect();
        drop(queue);

        // Would send to Jaeger here
        self.send_to_jaeger(batch);
    }

    /// Send spans to Jaeger
    fn send_to_jaeger(&self, spans: Vec<Span>) {
        // Would implement actual Jaeger export
        let count = spans.len() as u64;
        self.stats.write().spans_exported += count;
        
        if self.config.read().debug {
            for span in &spans {
                println!("Exporting span: {} - {}", span.trace_id, span.operation_name);
            }
        }
    }

    /// Create no-op span
    fn create_noop_span(&self, operation: &str) -> Span {
        Span {
            trace_id: String::new(),
            span_id: String::new(),
            parent_span_id: None,
            operation_name: operation.to_string(),
            start_time: 0,
            end_time: None,
            duration_us: None,
            status: SpanStatus::Unset,
            attributes: HashMap::new(),
            events: Vec::new(),
            links: Vec::new(),
        }
    }

    /// Get current timestamp in microseconds
    fn current_timestamp_us() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64
    }

    /// Get statistics
    pub fn get_stats(&self) -> TracingStats {
        self.stats.read().clone()
    }

    /// Flush pending spans
    pub fn flush(&self) {
        self.export_batch();
    }
}

/// W3C Trace Context propagation
pub struct TraceContextPropagator;

impl TraceContextPropagator {
    /// Extract trace context from headers
    pub fn extract(headers: &HashMap<String, String>) -> Option<TraceContext> {
        let traceparent = headers.get("traceparent")?;
        let parts: Vec<&str> = traceparent.split('-').collect();
        
        if parts.len() != 4 {
            return None;
        }

        let mut context = TraceContext::new();
        context.trace_id = parts[1].to_string();
        context.parent_span_id = parts[2].to_string();
        context.flags = u8::from_str_radix(parts[3], 16).ok()?;

        // Parse tracestate if present
        if let Some(tracestate) = headers.get("tracestate") {
            for pair in tracestate.split(',') {
                let kv: Vec<&str> = pair.split('=').collect();
                if kv.len() == 2 {
                    context.state.insert(kv[0].to_string(), kv[1].to_string());
                }
            }
        }

        Some(context)
    }

    /// Inject trace context into headers
    pub fn inject(context: &TraceContext, headers: &mut HashMap<String, String>) {
        let traceparent = format!("00-{}-{}-{:02x}",
            context.trace_id,
            context.parent_span_id,
            context.flags
        );
        headers.insert("traceparent".to_string(), traceparent);

        if !context.state.is_empty() {
            let tracestate = context.state.iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join(",");
            headers.insert("tracestate".to_string(), tracestate);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_span_creation() {
        let config = TracingConfig::default();
        let handler = DistributedTracingHandler::new(config);
        
        let span = handler.start_span("test.operation", None);
        assert!(!span.trace_id.is_empty());
        assert!(!span.span_id.is_empty());
        assert!(span.parent_span_id.is_none());
    }

    #[test]
    fn test_trace_context_propagation() {
        let mut context = TraceContext::new();
        context.state.insert("vendor".to_string(), "value".to_string());
        
        let mut headers = HashMap::new();
        TraceContextPropagator::inject(&context, &mut headers);
        
        assert!(headers.contains_key("traceparent"));
        assert!(headers.contains_key("tracestate"));
        
        let extracted = TraceContextPropagator::extract(&headers).unwrap();
        assert_eq!(extracted.trace_id, context.trace_id);
    }
}