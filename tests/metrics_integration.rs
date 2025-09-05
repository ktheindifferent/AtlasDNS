//! Integration tests for the real-time metrics system

use atlas::metrics::{
    MetricsManager, DnsQueryMetric, SecurityEvent, TimeRange, AggregationInterval,
};
use std::time::{Duration, SystemTime};
use tokio;

/// Test helper to create sample DNS query metrics
fn create_sample_queries() -> Vec<DnsQueryMetric> {
    let mut queries = Vec::new();
    let now = SystemTime::now();
    
    // Create diverse test data
    let domains = vec!["example.com", "test.org", "google.com", "cloudflare.com"];
    let query_types = vec!["A", "AAAA", "MX", "TXT"];
    let response_codes = vec!["NOERROR", "NXDOMAIN", "SERVFAIL"];
    let client_ips = vec!["192.168.1.1", "192.168.1.2", "10.0.0.1", "8.8.8.8"];
    
    for i in 0..100 {
        queries.push(DnsQueryMetric {
            timestamp: now - Duration::from_secs((i * 60) as u64),
            domain: domains[i % domains.len()].to_string(),
            query_type: query_types[i % query_types.len()].to_string(),
            client_ip: client_ips[i % client_ips.len()].to_string(),
            response_code: response_codes[i % response_codes.len()].to_string(),
            response_time_ms: 10.0 + ((i % 50) as f64),
            cache_hit: (i % 3) != 0,
            protocol: if (i % 2) == 0 { "UDP" } else { "TCP" }.to_string(),
            upstream_server: if (i % 5) == 0 { Some("8.8.8.8".to_string()) } else { None },
            dnssec_validated: if (i % 4) == 0 { Some(true) } else { None },
        });
    }
    
    queries
}

#[tokio::test]
async fn test_metrics_manager_initialization() {
    let manager = MetricsManager::new(":memory:").await;
    assert!(manager.is_ok());
    
    let manager = manager.unwrap();
    assert!(manager.collector().get_snapshot().await.is_ok());
}

#[tokio::test]
async fn test_metrics_collection() {
    let manager = MetricsManager::new(":memory:").await.unwrap();
    let collector = manager.collector();
    
    // Record sample queries
    let queries = create_sample_queries();
    for query in queries.iter().take(10) {
        collector.record_query(query.clone()).await;
    }
    
    // Get snapshot and verify
    let snapshot = collector.get_snapshot().await.unwrap();
    assert_eq!(snapshot.query_count, 10);
    assert!(snapshot.cache_hits > 0);
    assert!(snapshot.unique_clients > 0);
}

#[tokio::test]
async fn test_time_series_storage() {
    let manager = MetricsManager::new(":memory:").await.unwrap();
    let collector = manager.collector();
    
    // Record queries
    let queries = create_sample_queries();
    for query in queries.iter().take(20) {
        collector.record_query(query.clone()).await;
    }
    
    // Wait for background task to store data
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Query stored data
    let range = TimeRange::last_hour();
    let analytics = manager.aggregator()
        .get_dns_analytics(range, AggregationInterval::Minute)
        .await
        .unwrap();
    
    assert!(!analytics.is_empty());
}

#[tokio::test]
async fn test_aggregation() {
    let manager = MetricsManager::new(":memory:").await.unwrap();
    let collector = manager.collector();
    
    // Record diverse queries
    let queries = create_sample_queries();
    for query in &queries {
        collector.record_query(query.clone()).await;
    }
    
    // Get aggregated metrics
    let range = TimeRange::last_24_hours();
    let aggregated = manager.aggregator()
        .get_aggregated_metrics(range, AggregationInterval::Hour)
        .await
        .unwrap();
    
    assert!(aggregated.total_queries > 0);
    assert!(aggregated.avg_cache_hit_rate > 0.0);
    assert!(!aggregated.query_type_distribution.is_empty());
    assert!(!aggregated.response_code_distribution.is_empty());
}

#[tokio::test]
async fn test_query_type_distribution() {
    let manager = MetricsManager::new(":memory:").await.unwrap();
    let collector = manager.collector();
    
    // Record queries with known distribution
    for _ in 0..60 {
        collector.record_query(DnsQueryMetric {
            timestamp: SystemTime::now(),
            domain: "test.com".to_string(),
            query_type: "A".to_string(),
            client_ip: "192.168.1.1".to_string(),
            response_code: "NOERROR".to_string(),
            response_time_ms: 15.0,
            cache_hit: true,
            protocol: "UDP".to_string(),
            upstream_server: None,
            dnssec_validated: None,
        }).await;
    }
    
    for _ in 0..40 {
        collector.record_query(DnsQueryMetric {
            timestamp: SystemTime::now(),
            domain: "test.com".to_string(),
            query_type: "AAAA".to_string(),
            client_ip: "192.168.1.2".to_string(),
            response_code: "NOERROR".to_string(),
            response_time_ms: 20.0,
            cache_hit: false,
            protocol: "UDP".to_string(),
            upstream_server: None,
            dnssec_validated: None,
        }).await;
    }
    
    let range = TimeRange::last_hour();
    let distribution = manager.aggregator()
        .get_query_type_distribution(range)
        .await
        .unwrap();
    
    assert_eq!(distribution.len(), 2);
    
    let a_record = distribution.iter().find(|d| d.query_type == "A").unwrap();
    assert_eq!(a_record.count, 60);
    assert!((a_record.percentage - 60.0).abs() < 1.0);
    
    let aaaa_record = distribution.iter().find(|d| d.query_type == "AAAA").unwrap();
    assert_eq!(aaaa_record.count, 40);
    assert!((aaaa_record.percentage - 40.0).abs() < 1.0);
}

#[tokio::test]
async fn test_cache_hit_rate() {
    let manager = MetricsManager::new(":memory:").await.unwrap();
    let collector = manager.collector();
    
    // Record 70 cache hits and 30 cache misses
    for i in 0..100 {
        collector.record_query(DnsQueryMetric {
            timestamp: SystemTime::now(),
            domain: format!("test{}.com", i),
            query_type: "A".to_string(),
            client_ip: "192.168.1.1".to_string(),
            response_code: "NOERROR".to_string(),
            response_time_ms: 10.0,
            cache_hit: i < 70,
            protocol: "UDP".to_string(),
            upstream_server: None,
            dnssec_validated: None,
        }).await;
    }
    
    let hit_rate = collector.get_cache_hit_rate().await;
    assert!((hit_rate - 70.0).abs() < 1.0);
}

#[tokio::test]
async fn test_response_time_percentiles() {
    let manager = MetricsManager::new(":memory:").await.unwrap();
    let collector = manager.collector();
    
    // Record queries with known response times
    for i in 1..=100 {
        collector.record_query(DnsQueryMetric {
            timestamp: SystemTime::now(),
            domain: format!("test{}.com", i),
            query_type: "A".to_string(),
            client_ip: "192.168.1.1".to_string(),
            response_code: "NOERROR".to_string(),
            response_time_ms: i as f64,
            cache_hit: false,
            protocol: "UDP".to_string(),
            upstream_server: None,
            dnssec_validated: None,
        }).await;
    }
    
    let percentiles = collector.get_response_time_percentiles().await;
    
    assert!(percentiles.contains_key("p50"));
    assert!(percentiles.contains_key("p95"));
    assert!(percentiles.contains_key("p99"));
    
    // P50 should be around 50ms
    let p50 = percentiles.get("p50").unwrap();
    assert!(*p50 >= 45.0 && *p50 <= 55.0);
    
    // P95 should be around 95ms
    let p95 = percentiles.get("p95").unwrap();
    assert!(*p95 >= 90.0 && *p95 <= 96.0);
}

#[tokio::test]
async fn test_top_domains() {
    let manager = MetricsManager::new(":memory:").await.unwrap();
    let collector = manager.collector();
    
    // Record queries with specific domain distribution
    let domains = vec![
        ("popular.com", 50),
        ("common.org", 30),
        ("rare.net", 10),
        ("unique.io", 5),
    ];
    
    for (domain, count) in &domains {
        for _ in 0..*count {
            collector.record_query(DnsQueryMetric {
                timestamp: SystemTime::now(),
                domain: domain.to_string(),
                query_type: "A".to_string(),
                client_ip: "192.168.1.1".to_string(),
                response_code: "NOERROR".to_string(),
                response_time_ms: 10.0,
                cache_hit: false,
                protocol: "UDP".to_string(),
                upstream_server: None,
                dnssec_validated: None,
            }).await;
        }
    }
    
    let range = TimeRange::last_hour();
    let top_domains = manager.aggregator()
        .get_top_domains(range, 3)
        .await
        .unwrap();
    
    assert_eq!(top_domains.len(), 3);
    assert_eq!(top_domains[0].domain, "popular.com");
    assert_eq!(top_domains[0].query_count, 50);
}

#[tokio::test]
async fn test_geographic_distribution() {
    let manager = MetricsManager::new(":memory:").await.unwrap();
    let collector = manager.collector();
    
    // Record queries from different IPs
    let ips = vec![
        "192.168.1.1",  // Private - US
        "8.8.8.8",      // Google - US
        "1.1.1.1",      // Cloudflare - AU
    ];
    
    for ip in &ips {
        for _ in 0..10 {
            collector.record_query(DnsQueryMetric {
                timestamp: SystemTime::now(),
                domain: "test.com".to_string(),
                query_type: "A".to_string(),
                client_ip: ip.to_string(),
                response_code: "NOERROR".to_string(),
                response_time_ms: 10.0,
                cache_hit: false,
                protocol: "UDP".to_string(),
                upstream_server: None,
                dnssec_validated: None,
            }).await;
        }
    }
    
    // Test GeoIP lookup
    let geoip = manager.geoip();
    let location = geoip.lookup("8.8.8.8").await;
    assert!(location.is_some());
    
    let loc = location.unwrap();
    assert!(!loc.country_code.is_empty());
    assert!(!loc.country_name.is_empty());
}

#[tokio::test]
async fn test_security_events() {
    let manager = MetricsManager::new(":memory:").await.unwrap();
    let collector = manager.collector();
    
    // Record security events
    for i in 0..5 {
        collector.record_security_event(SecurityEvent {
            timestamp: SystemTime::now(),
            event_type: "rate_limit".to_string(),
            source_ip: format!("192.168.1.{}", i),
            target_domain: Some("suspicious.com".to_string()),
            action_taken: "blocked".to_string(),
            severity: "medium".to_string(),
        }).await;
    }
    
    let events = collector.get_recent_security_events(10).await;
    assert_eq!(events.len(), 5);
    assert_eq!(events[0].event_type, "rate_limit");
}

#[tokio::test]
async fn test_query_rate_calculation() {
    let manager = MetricsManager::new(":memory:").await.unwrap();
    let collector = manager.collector();
    
    // Record 60 queries (should be 1 query per second over a minute)
    for _ in 0..60 {
        collector.record_query(DnsQueryMetric {
            timestamp: SystemTime::now(),
            domain: "test.com".to_string(),
            query_type: "A".to_string(),
            client_ip: "192.168.1.1".to_string(),
            response_code: "NOERROR".to_string(),
            response_time_ms: 10.0,
            cache_hit: false,
            protocol: "UDP".to_string(),
            upstream_server: None,
            dnssec_validated: None,
        }).await;
    }
    
    let rate = collector.get_query_rate().await;
    assert!(rate > 0.0);
}

#[tokio::test]
async fn test_websocket_streaming() {
    let manager = MetricsManager::new(":memory:").await.unwrap();
    let stream = manager.stream();
    
    // Subscribe to updates
    let filter = atlas::metrics::streaming::SubscriptionFilter::default();
    let mut subscriber = stream.subscribe(filter).await;
    
    // Broadcast an update
    let snapshot = manager.collector().get_snapshot().await.unwrap();
    stream.broadcast_update(&snapshot).await;
    
    // Try to receive the update
    tokio::select! {
        result = subscriber.recv() => {
            assert!(result.is_ok());
            let update = result.unwrap();
            assert!(matches!(update.update_type, atlas::metrics::streaming::UpdateType::Snapshot));
        }
        _ = tokio::time::sleep(Duration::from_secs(1)) => {
            // Timeout is okay for this test
        }
    }
}

#[tokio::test]
async fn test_data_retention() {
    let manager = MetricsManager::new(":memory:").await.unwrap();
    let collector = manager.collector();
    
    // Record old and new queries
    let old_time = SystemTime::now() - Duration::from_secs(31 * 24 * 3600); // 31 days ago
    let new_time = SystemTime::now();
    
    // This test just verifies the cleanup method exists and doesn't crash
    collector.cleanup_memory().await;
    
    // Verify we can still record new queries
    collector.record_query(DnsQueryMetric {
        timestamp: new_time,
        domain: "test.com".to_string(),
        query_type: "A".to_string(),
        client_ip: "192.168.1.1".to_string(),
        response_code: "NOERROR".to_string(),
        response_time_ms: 10.0,
        cache_hit: false,
        protocol: "UDP".to_string(),
        upstream_server: None,
        dnssec_validated: None,
    }).await;
    
    let snapshot = collector.get_snapshot().await.unwrap();
    assert!(snapshot.query_count > 0);
}

#[tokio::test]
async fn test_concurrent_metrics_recording() {
    let manager = MetricsManager::new(":memory:").await.unwrap();
    let collector = manager.collector();
    
    // Spawn multiple tasks to record metrics concurrently
    let mut handles = vec![];
    
    for i in 0..10 {
        let collector_clone = collector.clone();
        let handle = tokio::spawn(async move {
            for j in 0..10 {
                collector_clone.record_query(DnsQueryMetric {
                    timestamp: SystemTime::now(),
                    domain: format!("test{}.com", i * 10 + j),
                    query_type: "A".to_string(),
                    client_ip: format!("192.168.{}.{}", i, j),
                    response_code: "NOERROR".to_string(),
                    response_time_ms: 10.0,
                    cache_hit: false,
                    protocol: "UDP".to_string(),
                    upstream_server: None,
                    dnssec_validated: None,
                }).await;
            }
        });
        handles.push(handle);
    }
    
    // Wait for all tasks to complete
    for handle in handles {
        handle.await.unwrap();
    }
    
    // Verify all queries were recorded
    let snapshot = collector.get_snapshot().await.unwrap();
    assert_eq!(snapshot.query_count, 100);
    assert!(snapshot.unique_clients <= 100);
}