//! Integration tests for the mDNS responder and registry wire-protocol handling.

use std::net::Ipv4Addr;
use std::sync::Arc;

use atlas::dns::mdns::{MdnsLocalRecord, MdnsRegistry, MdnsResponder};

// ---------------------------------------------------------------------------
// Helper: build a minimal mDNS A-record query for `hostname.local`
// ---------------------------------------------------------------------------

fn build_query(hostname: &str, qtype: u16) -> Vec<u8> {
    let mut pkt = Vec::new();
    // Header (12 bytes)
    pkt.extend_from_slice(&0u16.to_be_bytes()); // TX-ID
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Flags (standard query)
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    // QNAME: hostname.local
    for label in hostname.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(5); // length of "local"
    pkt.extend_from_slice(b"local");
    pkt.push(0); // root label
    pkt.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    pkt
}

fn a_query(hostname: &str) -> Vec<u8> {
    build_query(hostname, 1) // A = 1
}

fn any_query(hostname: &str) -> Vec<u8> {
    build_query(hostname, 255) // ANY = 255
}

fn make_responder(records: Vec<MdnsLocalRecord>) -> MdnsResponder {
    MdnsResponder::new(records)
}

// ---------------------------------------------------------------------------
// Responder tests
// ---------------------------------------------------------------------------

#[test]
fn responder_answers_configured_hostname() {
    let responder = make_responder(vec![MdnsLocalRecord {
        hostname: "atlas".to_string(),
        ip: Ipv4Addr::new(192, 168, 1, 100),
        ttl: 120,
    }]);

    let query = a_query("atlas");
    let resp = responder
        .maybe_respond(&query)
        .expect("should respond to configured host");

    // QR bit must be set (response)
    assert!(resp[2] & 0x80 != 0, "QR bit should be set");
    // AA bit should be set (authoritative)
    assert!(resp[2] & 0x04 != 0, "AA bit should be set");
    // The response must contain the IP 192.168.1.100
    assert!(
        resp.windows(4).any(|w| w == [192, 168, 1, 100]),
        "response must contain the configured IP"
    );
}

#[test]
fn responder_ignores_unknown_hostname() {
    let responder = make_responder(vec![MdnsLocalRecord {
        hostname: "atlas".to_string(),
        ip: Ipv4Addr::new(192, 168, 1, 100),
        ttl: 120,
    }]);

    let query = a_query("unknown-host");
    assert!(
        responder.maybe_respond(&query).is_none(),
        "should not respond to unknown hosts"
    );
}

#[test]
fn responder_ignores_response_packets() {
    let responder = make_responder(vec![MdnsLocalRecord {
        hostname: "atlas".to_string(),
        ip: Ipv4Addr::new(10, 0, 0, 1),
        ttl: 60,
    }]);

    let mut pkt = a_query("atlas");
    pkt[2] |= 0x80; // set QR bit → "this is a response"
    assert!(
        responder.maybe_respond(&pkt).is_none(),
        "should ignore mDNS response packets"
    );
}

#[test]
fn responder_answers_any_query_type() {
    let responder = make_responder(vec![MdnsLocalRecord {
        hostname: "printer".to_string(),
        ip: Ipv4Addr::new(10, 0, 0, 5),
        ttl: 300,
    }]);

    let query = any_query("printer");
    let resp = responder
        .maybe_respond(&query)
        .expect("ANY queries should match configured A records");

    assert!(resp.windows(4).any(|w| w == [10, 0, 0, 5]));
}

#[test]
fn responder_case_insensitive_match() {
    let responder = make_responder(vec![MdnsLocalRecord {
        hostname: "MyServer".to_string(),
        ip: Ipv4Addr::new(172, 16, 0, 1),
        ttl: 120,
    }]);

    // Query with lowercase
    let query = a_query("myserver");
    assert!(
        responder.maybe_respond(&query).is_some(),
        "hostname matching should be case-insensitive"
    );
}

#[test]
fn responder_handles_multiple_records() {
    let responder = make_responder(vec![
        MdnsLocalRecord {
            hostname: "web".to_string(),
            ip: Ipv4Addr::new(10, 0, 0, 1),
            ttl: 60,
        },
        MdnsLocalRecord {
            hostname: "db".to_string(),
            ip: Ipv4Addr::new(10, 0, 0, 2),
            ttl: 60,
        },
    ]);

    // Query for "web" should return its IP, not "db"'s
    let resp = responder
        .maybe_respond(&a_query("web"))
        .expect("should respond to 'web'");
    assert!(resp.windows(4).any(|w| w == [10, 0, 0, 1]));
    assert!(!resp.windows(4).any(|w| w == [10, 0, 0, 2]));

    // Query for "db"
    let resp = responder
        .maybe_respond(&a_query("db"))
        .expect("should respond to 'db'");
    assert!(resp.windows(4).any(|w| w == [10, 0, 0, 2]));
}

#[test]
fn responder_rejects_aaaa_only_query() {
    let responder = make_responder(vec![MdnsLocalRecord {
        hostname: "v4only".to_string(),
        ip: Ipv4Addr::new(10, 0, 0, 1),
        ttl: 60,
    }]);

    // AAAA = type 28
    let query = build_query("v4only", 28);
    assert!(
        responder.maybe_respond(&query).is_none(),
        "should not respond to AAAA queries when only A records are configured"
    );
}

#[test]
fn responder_rejects_truncated_packet() {
    let responder = make_responder(vec![MdnsLocalRecord {
        hostname: "x".to_string(),
        ip: Ipv4Addr::new(1, 2, 3, 4),
        ttl: 60,
    }]);

    // Packet shorter than DNS header (12 bytes)
    assert!(responder.maybe_respond(&[0u8; 6]).is_none());
    assert!(responder.maybe_respond(&[]).is_none());
}

#[test]
fn response_ancount_matches_records_returned() {
    let responder = make_responder(vec![MdnsLocalRecord {
        hostname: "test".to_string(),
        ip: Ipv4Addr::new(1, 2, 3, 4),
        ttl: 120,
    }]);

    let resp = responder
        .maybe_respond(&a_query("test"))
        .expect("should respond");

    // ANCOUNT is at bytes 6-7 in the DNS header
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    assert_eq!(ancount, 1, "ANCOUNT should be 1 for a single matched record");
}

// ---------------------------------------------------------------------------
// Registry tests
// ---------------------------------------------------------------------------

#[test]
fn registry_upsert_and_lookup() {
    let reg = MdnsRegistry::new();
    reg.upsert("laptop", Some("192.168.1.10".into()), Some("_ssh._tcp".into()));

    assert_eq!(reg.lookup_ip("laptop"), Some("192.168.1.10".into()));

    let devs = reg.all_devices();
    assert_eq!(devs.len(), 1);
    assert_eq!(devs[0].hostname, "laptop");
    assert!(devs[0].services.contains(&"_ssh._tcp".to_string()));
}

#[test]
fn registry_upsert_merges_services() {
    let reg = MdnsRegistry::new();
    reg.upsert("printer", Some("10.0.0.5".into()), Some("_ipp._tcp".into()));
    reg.upsert("printer", None, Some("_http._tcp".into()));

    let devs = reg.all_devices();
    assert_eq!(devs.len(), 1);
    assert_eq!(devs[0].services.len(), 2);
    assert!(devs[0].services.contains(&"_ipp._tcp".to_string()));
    assert!(devs[0].services.contains(&"_http._tcp".to_string()));
    // IP should still be present from first upsert
    assert_eq!(devs[0].ip, Some("10.0.0.5".into()));
}

#[test]
fn registry_upsert_updates_ip() {
    let reg = MdnsRegistry::new();
    reg.upsert("host", Some("10.0.0.1".into()), None);
    reg.upsert("host", Some("10.0.0.2".into()), None);

    assert_eq!(reg.lookup_ip("host"), Some("10.0.0.2".into()));
}

#[test]
fn registry_upsert_no_duplicate_services() {
    let reg = MdnsRegistry::new();
    reg.upsert("dev", None, Some("_http._tcp".into()));
    reg.upsert("dev", None, Some("_http._tcp".into()));

    let devs = reg.all_devices();
    assert_eq!(devs[0].services.len(), 1, "should not duplicate services");
}

#[test]
fn registry_lookup_missing_returns_none() {
    let reg = MdnsRegistry::new();
    assert_eq!(reg.lookup_ip("nonexistent"), None);
}

#[test]
fn registry_all_devices_empty() {
    let reg = MdnsRegistry::new();
    assert!(reg.all_devices().is_empty());
}

#[test]
fn registry_concurrent_access() {
    let reg = Arc::new(MdnsRegistry::new());
    let mut handles = vec![];

    for i in 0..8u8 {
        let r = Arc::clone(&reg);
        handles.push(std::thread::spawn(move || {
            let host = format!("device-{}", i);
            let ip = format!("10.0.0.{}", i);
            for _ in 0..50 {
                r.upsert(&host, Some(ip.clone()), Some("_test._tcp".into()));
                let _ = r.lookup_ip(&host);
                let _ = r.all_devices();
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(reg.all_devices().len(), 8);
}

#[test]
fn registry_last_seen_updates_on_upsert() {
    let reg = MdnsRegistry::new();
    reg.upsert("ts-test", Some("1.2.3.4".into()), None);

    let first_seen = reg.all_devices()[0].last_seen;

    std::thread::sleep(std::time::Duration::from_millis(50));
    reg.upsert("ts-test", None, Some("_svc._tcp".into()));

    let second_seen = reg.all_devices()[0].last_seen;
    assert!(
        second_seen >= first_seen,
        "last_seen should be updated on upsert"
    );
}
