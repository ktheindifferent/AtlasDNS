//! DNS Protocol Implementation
//! 
//! This module provides a complete DNS server implementation with support for:
//! * DNS packet parsing and serialization
//! * Authoritative zone management
//! * Recursive and forwarding resolution
//! * Response caching
//! * Both UDP and TCP transport protocols
//! 
//! # Module Structure
//! 
//! * `protocol` - DNS protocol definitions and packet handling
//! * `server` - UDP and TCP server implementations
//! * `resolve` - Resolution strategies (recursive, forwarding)
//! * `cache` - DNS response caching with TTL support
//! * `authority` - Authoritative zone management
//! * `client` - DNS client for outgoing queries
//! * `context` - Server configuration and shared state
//! * `buffer` - Low-level packet buffer operations

/// Authoritative DNS zone management
pub mod authority;

/// Low-level buffer operations for DNS packet handling
pub mod buffer;

/// DNS response caching with TTL support
pub mod cache;

/// DNS client for making outgoing queries
pub mod client;

/// Server configuration and shared context
pub mod context;

/// DNS protocol definitions and packet structures
pub mod protocol;

/// DNS resolution strategies (recursive, forwarding)
pub mod resolve;

/// UDP and TCP DNS server implementations
pub mod server;

/// RFC 1035 compliant zone file parser
pub mod zone_parser;

/// Internal network utilities
mod netutil;

/// DNS query type definitions
pub mod query_type;

/// DNS security module (firewall, rate limiting, DDoS protection)
pub mod security;

/// DNS result code definitions  
pub mod result_code;

/// DNS record parsing utilities
pub mod record_parsers;

/// Common error handling utilities
pub mod error_utils;

/// Enhanced error types for DNS operations
pub mod errors;

/// Rate limiting for DNS queries
pub mod rate_limit;

/// Retry policy and circuit breaker for DNS queries
pub mod retry_policy;

/// Health check and monitoring
pub mod health;

/// ACME certificate management for SSL/TLS
pub mod acme;

/// Prometheus metrics collection and export
pub mod metrics;

/// Structured JSON logging with correlation IDs
pub mod logging;

/// DNS-over-HTTPS (DoH) implementation - RFC 8484
pub mod doh;

/// DNS-over-TLS (DoT) implementation - RFC 7858
pub mod dot;

/// DNS Firewall for threat protection and content filtering
pub mod firewall;

/// Connection pooling for outbound DNS queries
pub mod connection_pool;

/// Adaptive caching with ML-driven TTL optimization
pub mod adaptive_cache;

/// DNSSEC automation with ECDSA P-256 support
pub mod dnssec;

/// Zero-copy networking for high-performance packet processing
pub mod zerocopy;

/// EDNS0 Extensions - RFC 6891 with client subnet support
pub mod edns0;

/// Query Name Minimization - RFC 7816 for privacy
pub mod qname_minimization;

/// Geographic Load Balancing for global traffic distribution
pub mod geo_loadbalancing;

/// Enhanced DDoS Protection with pattern detection
pub mod ddos_protection;

/// Cache Poisoning Protection with multiple defense layers
pub mod cache_poisoning;

/// Response Policy Zones (RPZ) for threat intelligence
pub mod rpz;

/// Source IP Validation for strict query source verification
pub mod source_validation;

/// Intelligent Failover with health monitoring and predictive detection
pub mod intelligent_failover;

/// Memory Pool Management for pre-allocated buffers
pub mod memory_pool;

/// Performance Optimizer for sub-10ms response times
pub mod performance_optimizer;

/// DNS Analytics for comprehensive query analysis
pub mod analytics;

/// Zone Transfer (AXFR/IXFR) implementation for secondary servers
pub mod zone_transfer;

/// Dynamic DNS Updates (RFC 2136) for programmatic record modification
pub mod dynamic_update;

/// CNAME Flattening for apex domain CNAME support
pub mod cname_flattening;

/// Split-Horizon DNS for different views based on client source
pub mod split_horizon;

/// Grafana Dashboards for comprehensive monitoring and alerting
pub mod grafana_dashboards;

/// Distributed Tracing with Jaeger for request flow visualization
pub mod distributed_tracing;

/// Alert Management with smart alerting and anomaly detection
pub mod alert_management;

/// Health Check Analytics for uptime and failure pattern analysis
pub mod health_check_analytics;

/// Proximity-Based Routing for dynamic closest-server selection
pub mod proximity_routing;

/// Multi-Region Failover for cross-datacenter redundancy
pub mod multi_region_failover;

/// GeoDNS for location-aware DNS responses
pub mod geodns;

/// Traffic Steering for percentage-based traffic distribution
pub mod traffic_steering;

/// Zone Templates for rapid zone deployment from predefined templates
pub mod zone_templates;

/// DNS Views for conditional responses based on client attributes
pub mod dns_views;

/// API Key Management for secure API access control
pub mod api_keys;

#[cfg(test)]
mod cache_test;
