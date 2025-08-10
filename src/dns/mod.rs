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
