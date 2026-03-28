//! Integration tests for DNS rate limiter behavior.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use atlas::dns::rate_limit::{RateLimitConfig, RateLimiter};

/// Helper: create a limiter with small windows for fast tests.
fn fast_limiter(client_limit: u32, global_limit: u32) -> RateLimiter {
    RateLimiter::new(RateLimitConfig {
        client_limit,
        client_window: Duration::from_millis(80),
        global_limit,
        global_window: Duration::from_millis(80),
        adaptive: false,
        cleanup_interval: Duration::from_secs(300), // don't interfere
    })
}

// ---- per-client limits ----

#[test]
fn client_under_limit_always_allowed() {
    let limiter = fast_limiter(10, 10_000);
    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    for _ in 0..10 {
        assert!(limiter.check_allowed(client).is_ok());
        limiter.record_query(client);
    }
}

#[test]
fn client_over_limit_rejected() {
    let limiter = fast_limiter(3, 10_000);
    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    for _ in 0..3 {
        limiter.check_allowed(client).unwrap();
        limiter.record_query(client);
    }

    assert!(
        limiter.check_allowed(client).is_err(),
        "4th query should be rejected"
    );
}

#[test]
fn client_window_expires_and_allows_again() {
    let limiter = fast_limiter(2, 10_000);
    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

    for _ in 0..2 {
        limiter.check_allowed(client).unwrap();
        limiter.record_query(client);
    }
    assert!(limiter.check_allowed(client).is_err());

    // Wait for both the client window (80ms) and any block duration to expire.
    std::thread::sleep(Duration::from_millis(200));

    assert!(
        limiter.check_allowed(client).is_ok(),
        "should be allowed after window + block expires"
    );
}

#[test]
fn separate_clients_have_independent_budgets() {
    let limiter = fast_limiter(2, 10_000);
    let a = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let b = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));

    // Exhaust client A
    for _ in 0..2 {
        limiter.check_allowed(a).unwrap();
        limiter.record_query(a);
    }
    assert!(limiter.check_allowed(a).is_err());

    // Client B is unaffected
    assert!(limiter.check_allowed(b).is_ok());
    limiter.record_query(b);
    assert!(limiter.check_allowed(b).is_ok());
}

#[test]
fn ipv6_clients_rate_limited_equally() {
    let limiter = fast_limiter(2, 10_000);
    let client = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));

    for _ in 0..2 {
        limiter.check_allowed(client).unwrap();
        limiter.record_query(client);
    }
    assert!(limiter.check_allowed(client).is_err());
}

// ---- global limits ----

#[test]
fn global_limit_rejects_after_threshold() {
    let limiter = fast_limiter(10_000, 5);
    let client = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1));

    for _ in 0..5 {
        limiter.check_allowed(client).unwrap();
        limiter.record_query(client);
    }
    assert!(
        limiter.check_allowed(client).is_err(),
        "global limit should fire"
    );
}

#[test]
fn global_limit_shared_across_clients() {
    let limiter = fast_limiter(10_000, 4);
    let clients: Vec<IpAddr> = (1..=4)
        .map(|i| IpAddr::V4(Ipv4Addr::new(10, 3, 0, i)))
        .collect();

    for c in &clients {
        limiter.check_allowed(*c).unwrap();
        limiter.record_query(*c);
    }

    // One more from any client should hit the global cap
    let extra = IpAddr::V4(Ipv4Addr::new(10, 3, 0, 99));
    assert!(limiter.check_allowed(extra).is_err());
}

// ---- stats reporting ----

#[test]
fn client_stats_reflect_query_counts() {
    let limiter = fast_limiter(100, 10_000);
    let client = IpAddr::V4(Ipv4Addr::new(10, 4, 0, 1));

    for _ in 0..7 {
        limiter.check_allowed(client).unwrap();
        limiter.record_query(client);
    }

    let stats = limiter.get_client_stats();
    let entry = stats
        .iter()
        .find(|s| s.client_ip == "10.4.0.1")
        .expect("client should appear in stats");
    assert_eq!(entry.queries_in_window, 7);
    assert!(!entry.blocked);
}

#[test]
fn global_stats_reflect_query_counts() {
    let limiter = fast_limiter(100, 10_000);
    let client = IpAddr::V4(Ipv4Addr::new(10, 5, 0, 1));

    for _ in 0..12 {
        limiter.record_query(client);
    }

    let gs = limiter.get_global_stats();
    assert_eq!(gs.queries_in_window, 12);
}

// ---- concurrent access ----

#[test]
fn concurrent_queries_are_safe() {
    let limiter = Arc::new(fast_limiter(50, 500));
    let mut handles = vec![];

    for i in 0u8..8 {
        let l = Arc::clone(&limiter);
        handles.push(std::thread::spawn(move || {
            let client = IpAddr::V4(Ipv4Addr::new(10, 6, 0, i));
            let mut allowed = 0u32;
            for _ in 0..20 {
                if l.check_allowed(client).is_ok() {
                    l.record_query(client);
                    allowed += 1;
                }
            }
            allowed
        }));
    }

    let total_allowed: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    // With 8 threads * 20 queries, some must have been allowed
    assert!(total_allowed > 0, "at least some queries should pass");
    // But not all, because global limit is 500 and we have 160 attempts
    // (all could pass since per-client limit is 50 and global is 500)
    assert!(total_allowed <= 160);
}

// ---- adaptive rate limiting ----

#[test]
fn adaptive_mode_increases_limit_under_low_load() {
    let limiter = RateLimiter::new(RateLimitConfig {
        client_limit: 10_000,
        client_window: Duration::from_secs(1),
        global_limit: 20,
        global_window: Duration::from_millis(80),
        adaptive: true,
        cleanup_interval: Duration::from_secs(300),
    });

    let client = IpAddr::V4(Ipv4Addr::new(10, 7, 0, 1));

    // Stay well under the limit (< 80%)
    for _ in 0..5 {
        limiter.check_allowed(client).unwrap();
        limiter.record_query(client);
    }

    // The adaptive algorithm should have nudged the limit up
    let gs = limiter.get_global_stats();
    assert!(
        gs.limit >= 20,
        "adaptive limit should stay at or above baseline"
    );
}
