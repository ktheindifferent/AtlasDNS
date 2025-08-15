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

/// Internal network utilities
mod netutil;

/// DNS query type definitions
pub mod query_type;

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

#[cfg(test)]
mod cache_test;
