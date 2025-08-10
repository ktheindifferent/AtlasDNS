//! Atlas DNS Server
//! 
//! A high-performance, authoritative DNS server implementation in Rust with web management interface.
//! 
//! # Features
//! 
//! * Full DNS protocol support (UDP and TCP)
//! * Recursive and forwarding resolution strategies
//! * Built-in caching with TTL support
//! * Web-based management interface
//! * Zone file management
//! * Support for common DNS record types (A, AAAA, NS, CNAME, MX, TXT, etc.)
//! 
//! # Architecture
//! 
//! The server is divided into two main modules:
//! * `dns` - Core DNS server functionality
//! * `web` - HTTP API and web interface for management

/// DNS server implementation and protocol handling
pub mod dns;

/// Web server and HTTP API for DNS management
pub mod web;
