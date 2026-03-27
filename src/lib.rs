//! Atlas DNS Server
//! 
//! A high-performance, authoritative DNS server implementation in Rust with web management interface.

#![recursion_limit = "512"]
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

/// Kubernetes integration for native K8s resource management
#[cfg(feature = "k8s")]
pub mod k8s;

/// Privilege escalation utilities for binding to privileged ports
pub mod privilege_escalation;

/// Real-time metrics collection and analytics system
pub mod metrics;

/// SQLite-backed persistent storage for zones and user accounts
pub mod storage;

/// Threat intelligence feed manager (public re-export of dns::security::threat_intel)
pub mod threat_intel;

/// Top-level configuration types (re-exports from sub-modules)
pub mod config;

/// DNSSEC full validation chain using `ring` for cryptographic operations
pub mod dnssec;

/// ACME v2 certificate management using instant-acme (DNS-01 challenges, auto-renewal)
pub mod acme;

/// mDNS responder and service browser (RFC 6762) with REST API
pub mod mdns;

/// GeoIP enrichment for DNS query logs using MaxMind databases
pub mod geoip;
