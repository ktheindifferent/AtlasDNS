//! Extensions for ServerContext to integrate enhanced metrics

use crate::dns::context::ServerContext;
use crate::metrics::{MetricsManager, DnsQueryMetric};
use std::sync::Arc;
use std::time::{SystemTime, Instant};

/// Extension trait for ServerContext to integrate enhanced metrics
pub trait ServerContextExt {
    /// Record a DNS query with enhanced metrics
    async fn record_dns_query_enhanced(
        &self,
        domain: &str,
        query_type: &str,
        client_ip: &str,
        response_code: &str,
        response_time: Instant,
        cache_hit: bool,
        protocol: &str,
        upstream_server: Option<String>,
        dnssec_validated: Option<bool>,
    );
}

impl ServerContextExt for ServerContext {
    async fn record_dns_query_enhanced(
        &self,
        domain: &str,
        query_type: &str,
        client_ip: &str,
        response_code: &str,
        start_time: Instant,
        cache_hit: bool,
        protocol: &str,
        upstream_server: Option<String>,
        dnssec_validated: Option<bool>,
    ) {
        // Record using existing Prometheus metrics
        self.metrics.record_dns_query_with_client(protocol, query_type, domain, client_ip);
        self.metrics.record_dns_response(response_code, protocol, query_type);
        self.metrics.record_query_duration(start_time.elapsed(), protocol, query_type, cache_hit);
        
        // If we have an enhanced metrics manager, use it too
        if let Some(enhanced_metrics) = self.get_enhanced_metrics() {
            let metric = DnsQueryMetric {
                timestamp: SystemTime::now(),
                domain: domain.to_string(),
                query_type: query_type.to_string(),
                client_ip: client_ip.to_string(),
                response_code: response_code.to_string(),
                response_time_ms: start_time.elapsed().as_secs_f64() * 1000.0,
                cache_hit,
                protocol: protocol.to_string(),
                upstream_server,
                dnssec_validated,
            };
            
            enhanced_metrics.collector().record_query(metric).await;
        }
    }
}

/// Helper to get enhanced metrics manager (if available)
impl ServerContext {
    fn get_enhanced_metrics(&self) -> Option<Arc<MetricsManager>> {
        // This would be set during server initialization
        // For now, return None as we're integrating gradually
        None
    }
}