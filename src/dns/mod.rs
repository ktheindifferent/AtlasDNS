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

#[cfg(test)]
mod cache_test;
