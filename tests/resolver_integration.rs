//! Resolver-level integration test
//!
//! Exercises the DNS resolver logic end-to-end: create a server context with an
//! authoritative zone, insert records, and verify resolution returns the
//! expected answers — all in-process, no network sockets required.

use atlas::dns::cache::SynchronizedCache;
use atlas::dns::context::ServerContext;
use atlas::dns::protocol::{DnsRecord, QueryType, TransientTtl};
use std::net::Ipv4Addr;
use std::sync::Arc;

/// Helper: build a minimal server context for testing.
fn test_context() -> Arc<ServerContext> {
    Arc::new(ServerContext::new().expect("Failed to create ServerContext"))
}

// ---------------------------------------------------------------------------
// Authoritative zone round-trip
// ---------------------------------------------------------------------------

#[test]
fn authoritative_zone_roundtrip() {
    let ctx = test_context();

    let domain = "app.test.local";
    let zone = "test.local";
    let addr = Ipv4Addr::new(10, 0, 0, 42);

    ctx.authority
        .create_zone(zone, &format!("ns1.{}", zone), &format!("admin.{}", zone))
        .expect("create_zone should succeed");

    ctx.authority
        .add_a_record(zone, domain, addr, 300)
        .expect("add_a_record should succeed");

    let result = ctx.authority.query(domain, QueryType::A);
    let packet = result.expect("Authority should return a packet for the domain");

    assert!(
        !packet.answers.is_empty(),
        "Authority should return at least one answer for {domain}"
    );

    match &packet.answers[0] {
        DnsRecord::A {
            domain: d, addr: a, ..
        } => {
            assert_eq!(d, domain);
            assert_eq!(*a, addr);
        }
        other => panic!("Expected A record, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Cache store → lookup cycle
// ---------------------------------------------------------------------------

#[test]
fn cache_store_and_lookup() {
    let cache = SynchronizedCache::new();

    let records = vec![
        DnsRecord::A {
            domain: "cached.example.com".to_string(),
            addr: Ipv4Addr::new(1, 2, 3, 4),
            ttl: TransientTtl(600),
        },
        DnsRecord::A {
            domain: "cached.example.com".to_string(),
            addr: Ipv4Addr::new(1, 2, 3, 5),
            ttl: TransientTtl(600),
        },
    ];

    cache.store(&records).expect("cache store should succeed");

    let packet = cache
        .lookup("cached.example.com", QueryType::A)
        .expect("cache lookup should return a packet");

    assert_eq!(packet.answers.len(), 2, "both A records should be cached");
}

// ---------------------------------------------------------------------------
// Cache miss returns None
// ---------------------------------------------------------------------------

#[test]
fn cache_miss_returns_none() {
    let cache = SynchronizedCache::new();
    assert!(
        cache.lookup("nonexistent.example.com", QueryType::A).is_none(),
        "empty cache should return None"
    );
}

// ---------------------------------------------------------------------------
// Authority handles multiple record types
// ---------------------------------------------------------------------------

#[test]
fn authority_multiple_record_types() {
    let ctx = test_context();
    let zone = "multi.local";

    ctx.authority
        .create_zone(zone, "ns1.multi.local", "admin.multi.local")
        .expect("create_zone should succeed");

    ctx.authority
        .add_a_record(zone, "multi.local", Ipv4Addr::new(10, 0, 0, 1), 300)
        .expect("add_a_record should succeed");

    ctx.authority
        .add_ns_record(zone, "ns1.multi.local")
        .expect("add_ns_record should succeed");

    let a_result = ctx.authority.query("multi.local", QueryType::A);
    let a_packet = a_result.expect("should return A records");
    assert_eq!(a_packet.answers.len(), 1, "should have one A record");

    let ns_result = ctx.authority.query("multi.local", QueryType::Ns);
    let ns_packet = ns_result.expect("should return NS records");
    assert_eq!(ns_packet.answers.len(), 1, "should have one NS record");
}

// ---------------------------------------------------------------------------
// Server context defaults
// ---------------------------------------------------------------------------

#[test]
fn server_context_defaults() {
    let ctx = test_context();
    assert!(ctx.enable_udp, "UDP should be enabled by default");
    assert!(ctx.enable_tcp, "TCP should be enabled by default");
    assert_eq!(ctx.dns_port, 53, "default DNS port should be 53");
}
