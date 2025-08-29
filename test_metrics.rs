// Simple test to verify metrics collection works
use atlas::dns::metrics::{MetricsCollector, MetricsTracker};
use std::time::Duration;

fn main() {
    println!("Testing Atlas DNS Metrics Collection...\n");
    
    // Create a new metrics collector
    let collector = MetricsCollector::new();
    
    // Simulate DNS operations
    println!("Simulating DNS queries...");
    
    // Record various query types with client tracking
    collector.record_dns_query_with_client("udp", "A", "example.com", "192.168.1.100");
    collector.record_dns_query_with_client("tcp", "AAAA", "example.org", "192.168.1.101");
    collector.record_dns_query_with_client("udp", "MX", "mail.example.com", "192.168.1.100");
    collector.record_dns_query_with_client("udp", "TXT", "example.net", "192.168.1.102");
    collector.record_dns_query_with_client("tcp", "CNAME", "www.example.com", "192.168.1.103");
    
    // Record responses
    collector.record_dns_response("NOERROR", "udp", "A");
    collector.record_dns_response("NOERROR", "tcp", "AAAA");
    collector.record_dns_response("NXDOMAIN", "udp", "MX");
    collector.record_dns_response("NOERROR", "udp", "TXT");
    collector.record_dns_response("SERVFAIL", "tcp", "CNAME");
    
    // Record cache operations
    collector.record_cache_operation("hit", "A");
    collector.record_cache_operation("hit", "AAAA");
    collector.record_cache_operation("miss", "MX");
    collector.record_cache_operation("hit", "TXT");
    collector.record_cache_operation("miss", "CNAME");
    
    // Record query durations
    collector.record_query_duration(Duration::from_millis(5), "udp", "A", true);
    collector.record_query_duration(Duration::from_millis(10), "tcp", "AAAA", true);
    collector.record_query_duration(Duration::from_millis(50), "udp", "MX", false);
    collector.record_query_duration(Duration::from_millis(8), "udp", "TXT", true);
    collector.record_query_duration(Duration::from_millis(100), "tcp", "CNAME", false);
    
    // Record protocol usage
    collector.record_protocol_usage("standard");
    collector.record_protocol_usage("standard");
    collector.record_protocol_usage("DoH");
    collector.record_protocol_usage("DoT");
    collector.record_protocol_usage("standard");
    
    // Get comprehensive metrics summary
    println!("\n=== Metrics Summary ===");
    let summary = collector.get_metrics_summary();
    
    println!("Unique Clients: {}", summary.unique_clients);
    println!("Cache Hits: {}", summary.cache_hits);
    println!("Cache Misses: {}", summary.cache_misses);
    println!("Cache Hit Rate: {:.2}%", summary.cache_hit_rate);
    
    println!("\n=== Response Time Percentiles (ms) ===");
    for (percentile, value) in &summary.percentiles {
        println!("{}: {:.2}ms", percentile, value);
    }
    
    println!("\n=== Query Type Distribution ===");
    for (query_type, (count, percentage)) in &summary.query_type_distribution {
        println!("{}: {} queries ({:.1}%)", query_type, count, percentage);
    }
    
    println!("\n=== Response Code Distribution ===");
    for (code, (count, percentage)) in &summary.response_code_distribution {
        println!("{}: {} responses ({:.1}%)", code, count, percentage);
    }
    
    println!("\n=== Protocol Distribution ===");
    for (protocol, (count, percentage)) in &summary.protocol_distribution {
        println!("{}: {} queries ({:.1}%)", protocol, count, percentage);
    }
    
    // Export Prometheus metrics
    println!("\n=== Prometheus Metrics (sample) ===");
    if let Ok(metrics) = collector.export_metrics() {
        // Show first few lines of Prometheus output
        for line in metrics.lines().take(20) {
            println!("{}", line);
        }
        println!("... (truncated)");
    }
    
    println!("\n✅ Metrics collection test completed successfully!");
}