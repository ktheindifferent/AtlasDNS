use serde_derive::{Deserialize, Serialize};
use serde_json::json;

use crate::dns::context::ServerContext;
use crate::web::{Result, WebError};

#[derive(Serialize, Deserialize)]
pub struct ZoneSummary {
    domain: String,
    record_count: usize,
    last_modified: String,
}

pub fn index(context: &ServerContext) -> Result<serde_json::Value> {
    // Get zone statistics
    let zones = context.authority.read().map_err(|_| WebError::LockError)?;
    let total_zones = zones.zones().len();
    
    // Calculate total records across all zones
    let mut total_records = 0;
    let mut zone_summaries = Vec::new();
    
    for zone in zones.zones().iter().take(5) { // Show only first 5 zones in recent list
        let record_count = zone.records.len();
        total_records += record_count;
        
        zone_summaries.push(json!({
            "domain": zone.domain,
            "record_count": record_count,
            "last_modified": "Recently", // You could track actual modification time
        }));
    }
    
    // Get cache statistics
    let cache_list = context.cache.list().unwrap_or_else(|_| Vec::new());
    let cache_entries = cache_list.len();
    let cache_hit_rate = 75; // Placeholder - you could implement actual cache hit tracking
    
    // Get query statistics
    let client_sent_queries = context.client.get_sent_count();
    let client_failed_queries = context.client.get_failed_count();
    let server_tcp_queries = context.statistics.get_tcp_query_count();
    let server_udp_queries = context.statistics.get_udp_query_count();
    
    // Calculate memory usage (approximate)
    let memory_usage = 45; // Placeholder - you could implement actual memory tracking
    
    // Build response
    Ok(json!({
        "ok": true,
        
        // Stats for cards
        "total_zones": total_zones,
        "total_records": total_records,
        "cache_entries": cache_entries,
        "active_users": 1, // Placeholder - implement user tracking
        "active_zones": total_zones, // All zones are active for now
        "last_update": "Just now",
        
        // Zone list for table
        "zones": zone_summaries,
        
        // System status
        "cache_hit_rate": cache_hit_rate,
        "memory_usage": memory_usage,
        "uptime": "Running", // You could track actual uptime
        "version": env!("CARGO_PKG_VERSION"),
        "server_name": "Atlas DNS",
        
        // Query statistics
        "client_sent_queries": client_sent_queries,
        "client_failed_queries": client_failed_queries,
        "server_tcp_queries": server_tcp_queries,
        "server_udp_queries": server_udp_queries,
        
        // Recent activity (placeholder)
        "activities": []
    }))
}
