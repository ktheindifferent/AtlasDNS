//! Demo of the real-time metrics collection and analytics system
//!
//! This example demonstrates how the enhanced metrics system replaces mock data
//! with real operational metrics throughout the Atlas DNS server.

use atlas::metrics::{
    MetricsManager, DnsQueryMetric, TimeRange, AggregationInterval,
};
use std::time::{Duration, SystemTime};
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Atlas DNS Real-Time Metrics Demo ===\n");

    // Initialize the metrics system with SQLite storage
    println!("Initializing metrics system...");
    let metrics_manager = MetricsManager::new("metrics.db").await?;
    
    // Start background tasks for aggregation and cleanup
    metrics_manager.start_background_tasks().await;
    
    println!("✓ Metrics system initialized with time-series storage\n");

    // Simulate DNS queries with realistic data
    println!("Simulating DNS query traffic...");
    simulate_dns_traffic(&metrics_manager).await?;
    println!("✓ Generated 100 DNS queries with various characteristics\n");

    // Demonstrate real-time analytics
    println!("=== Real-Time Analytics ===\n");
    
    // 1. Query volume and performance metrics
    let snapshot = metrics_manager.collector().get_snapshot().await?;
    println!("📊 Current Metrics Snapshot:");
    println!("   • Total Queries: {}", snapshot.query_count);
    println!("   • Cache Hits: {}", snapshot.cache_hits);
    println!("   • Cache Misses: {}", snapshot.cache_misses);
    println!("   • Cache Hit Rate: {:.1}%", 
        (snapshot.cache_hits as f64 / (snapshot.cache_hits + snapshot.cache_misses) as f64) * 100.0);
    println!("   • Unique Clients: {}", snapshot.unique_clients);
    println!("   • Avg Response Time: {:.2}ms\n", snapshot.avg_response_time_ms);

    // 2. Time-series analytics with aggregation
    println!("📈 Time-Series Analytics (5-minute intervals):");
    let time_range = TimeRange::last_hour();
    let analytics = metrics_manager.aggregator()
        .get_dns_analytics(time_range.clone(), AggregationInterval::FiveMinutes)
        .await?;
    
    for (i, point) in analytics.iter().take(3).enumerate() {
        println!("   Interval {}:", i + 1);
        println!("     • Queries: {}", point.query_count);
        println!("     • Success Rate: {:.1}%", point.success_rate);
        println!("     • P95 Response Time: {:.2}ms", point.p95_response_time_ms);
    }
    println!();

    // 3. Query type distribution
    println!("📊 Query Type Distribution:");
    let distribution = metrics_manager.aggregator()
        .get_query_type_distribution(time_range.clone())
        .await?;
    
    for dist in distribution.iter().take(5) {
        println!("   • {}: {} queries ({:.1}%)", 
            dist.query_type, dist.count, dist.percentage);
    }
    println!();

    // 4. Top domains
    println!("🌐 Top Queried Domains:");
    let top_domains = metrics_manager.aggregator()
        .get_top_domains(time_range.clone(), 5)
        .await?;
    
    for (i, domain) in top_domains.iter().enumerate() {
        println!("   {}. {} - {} queries from {} unique clients",
            i + 1, domain.domain, domain.query_count, domain.unique_clients);
    }
    println!();

    // 5. Geographic distribution (using mock GeoIP data)
    println!("🗺️  Geographic Distribution:");
    let queries = vec![
        "192.168.1.1".to_string(),
        "8.8.8.8".to_string(),
        "1.1.1.1".to_string(),
    ];
    let geo_dist = metrics_manager.geoip()
        .analyze_distribution(queries)
        .await;
    
    for geo in geo_dist {
        println!("   • {} ({}): {:.1}% of queries",
            geo.country_name, geo.country_code, geo.percentage);
    }
    println!();

    // 6. Response time percentiles
    println!("⚡ Response Time Percentiles:");
    let percentiles = metrics_manager.collector()
        .get_response_time_percentiles()
        .await;
    
    for (percentile, value) in percentiles.iter() {
        println!("   • {}: {:.2}ms", percentile, value);
    }
    println!();

    // 7. Real-time streaming capability
    println!("🔄 Real-Time Streaming:");
    println!("   • WebSocket endpoint available for live metrics");
    println!("   • Supports subscription filters and sampling");
    println!("   • Backpressure handling for high-volume metrics\n");

    // 8. System metrics
    println!("💻 System Metrics:");
    println!("   • CPU Usage: {:.1}%", snapshot.system_metrics.cpu_usage);
    println!("   • Memory Usage: {}MB", snapshot.system_metrics.memory_usage_mb);
    println!("   • Network RX: {:.2}MB", snapshot.system_metrics.network_rx_bytes as f64 / 1024.0 / 1024.0);
    println!("   • Network TX: {:.2}MB\n", snapshot.system_metrics.network_tx_bytes as f64 / 1024.0 / 1024.0);

    println!("=== Demo Complete ===");
    println!("\nThis demonstrates how the real-time metrics system:");
    println!("✓ Replaces all mock data with actual operational metrics");
    println!("✓ Provides time-series storage with SQLite");
    println!("✓ Enables real-time analytics and aggregation");
    println!("✓ Supports geographic analysis with GeoIP");
    println!("✓ Offers WebSocket streaming for live updates");
    println!("✓ Maintains configurable retention policies");

    Ok(())
}

/// Simulate realistic DNS query traffic
async fn simulate_dns_traffic(manager: &MetricsManager) -> Result<(), Box<dyn std::error::Error>> {
    let collector = manager.collector();
    
    // Common domains
    let domains = vec![
        "google.com",
        "cloudflare.com",
        "example.com",
        "github.com",
        "microsoft.com",
        "amazon.com",
        "facebook.com",
        "twitter.com",
        "netflix.com",
        "reddit.com",
    ];
    
    // Query types with realistic distribution
    let query_types = vec![
        ("A", 60),      // 60% A records
        ("AAAA", 25),   // 25% AAAA records
        ("MX", 5),      // 5% MX records
        ("TXT", 5),     // 5% TXT records
        ("CNAME", 5),   // 5% CNAME records
    ];
    
    // Client IPs
    let client_ips = vec![
        "192.168.1.100",
        "192.168.1.101",
        "10.0.0.50",
        "172.16.0.10",
        "8.8.8.8",
    ];
    
    // Generate queries
    let mut query_count = 0;
    for (query_type, count) in query_types {
        for _ in 0..count {
            let metric = DnsQueryMetric {
                timestamp: SystemTime::now() - Duration::from_secs(query_count * 30),
                domain: domains[query_count % domains.len()].to_string(),
                query_type: query_type.to_string(),
                client_ip: client_ips[query_count % client_ips.len()].to_string(),
                response_code: if query_count % 20 == 0 { "NXDOMAIN" } else { "NOERROR" }.to_string(),
                response_time_ms: 5.0 + (query_count as f64 % 45.0),
                cache_hit: query_count % 3 != 0, // 66% cache hit rate
                protocol: if query_count % 10 == 0 { "TCP" } else { "UDP" }.to_string(),
                upstream_server: if query_count % 3 == 0 { 
                    Some("8.8.8.8".to_string()) 
                } else { 
                    None 
                },
                dnssec_validated: if query_count % 5 == 0 { Some(true) } else { None },
            };
            
            collector.record_query(metric).await;
            query_count += 1;
        }
    }
    
    Ok(())
}