use serde_derive::{Deserialize, Serialize};
use serde_json::json;
use std::sync::{Arc, Mutex, OnceLock};

use crate::dns::context::ServerContext;
use crate::web::{Result, WebError};
use crate::web::system_info::{SystemInfoCollector, format};
use crate::web::activity::ActivityLogger;
use crate::web::users::UserManager;

// Global system info collector - initialized once and reused
static SYSTEM_COLLECTOR: OnceLock<Arc<Mutex<SystemInfoCollector>>> = OnceLock::new();

fn get_system_collector() -> &'static Arc<Mutex<SystemInfoCollector>> {
    SYSTEM_COLLECTOR.get_or_init(|| {
        Arc::new(Mutex::new(SystemInfoCollector::new()))
    })
}

#[derive(Serialize, Deserialize)]
pub struct ZoneSummary {
    domain: String,
    record_count: usize,
    last_modified: String,
}

pub fn index(context: &ServerContext, user_manager: &UserManager, activity_logger: &ActivityLogger) -> Result<serde_json::Value> {
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
    
    // Get real cache hit rate from cache stats
    let cache_stats = context.cache.get_stats().unwrap_or({
        crate::dns::cache::CacheStats {
            total_entries: cache_entries,
            hit_rate: 0.0,
            total_hits: 0,
            total_misses: 0,
            memory_usage_bytes: 0,
        }
    });
    let cache_hit_rate = cache_stats.hit_rate.round() as u32;
    
    // Get query statistics
    let client_sent_queries = context.client.get_sent_count();
    let client_failed_queries = context.client.get_failed_count();
    let server_tcp_queries = context.statistics.get_tcp_query_count();
    let server_udp_queries = context.statistics.get_udp_query_count();
    let total_queries = client_sent_queries + server_tcp_queries + server_udp_queries;

    // Compute top 10 queried domains and blocked count from in-memory log
    let recent_all = context.query_log_storage.get_recent(1000);
    let blocked_count = recent_all.iter()
        .filter(|e| e.response_code == "NXDOMAIN" || e.response_code == "REFUSED")
        .count();
    let mut domain_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for entry in &recent_all {
        *domain_counts.entry(entry.domain.clone()).or_insert(0) += 1;
    }
    let mut top_domains_vec: Vec<(String, usize)> = domain_counts.into_iter().collect();
    top_domains_vec.sort_by(|a, b| b.1.cmp(&a.1));
    let top_domains: Vec<serde_json::Value> = top_domains_vec.iter().take(10).map(|(domain, count)| {
        json!({ "domain": domain, "count": count })
    }).collect();

    // Recent query log (last 50)
    let recent_queries: Vec<serde_json::Value> = context.query_log_storage.get_recent(50).iter().map(|e| {
        json!({
            "timestamp": e.timestamp.format("%H:%M:%S").to_string(),
            "client_ip": e.client_ip.as_deref().unwrap_or("unknown"),
            "domain": e.domain,
            "query_type": e.query_type,
            "response": e.response_code,
            "latency_ms": e.latency_ms.unwrap_or(0),
            "cache_hit": e.cache_hit,
        })
    }).collect();
    
    // Get real system information
    let system_collector = get_system_collector();
    let sys_info = if let Ok(mut collector) = system_collector.lock() {
        collector.get_system_info()
    } else {
        // Fallback if we can't get the lock
        return build_fallback_response(context, user_manager, activity_logger, total_zones, total_records, zone_summaries, cache_entries, cache_hit_rate, 
                                      client_sent_queries, client_failed_queries, server_tcp_queries, server_udp_queries);
    };
    
    // Build response with real system data
    Ok(json!({
        "ok": true,
        
        // DNS Stats for cards
        "total_zones": total_zones,
        "total_records": total_records,
        "cache_entries": cache_entries,
        "active_users": user_manager.get_active_user_count(),
        "active_sessions": user_manager.get_active_session_count(),
        "total_users": user_manager.get_total_user_count(),
        "active_zones": total_zones,
        "last_update": "Just now",
        
        // Zone list for table
        "zones": zone_summaries,
        
        // Real System Status
        "cache_hit_rate": cache_hit_rate,
        "memory_usage": sys_info.memory.usage_percent.round() as u32,
        "memory_total": format::format_bytes(sys_info.memory.total_bytes),
        "memory_used": format::format_bytes(sys_info.memory.used_bytes),
        "memory_available": format::format_bytes(sys_info.memory.available_bytes),
        
        // CPU Information
        "cpu_usage": sys_info.cpu.usage_percent.round() as u32,
        "cpu_cores": sys_info.cpu.cores_logical,
        "cpu_brand": sys_info.cpu.brand,
        "cpu_frequency": sys_info.cpu.frequency_mhz,
        
        // Disk Information
        "disk_usage": sys_info.disk.usage_percent.round() as u32,
        "disk_total": format::format_bytes(sys_info.disk.total_space_bytes),
        "disk_used": format::format_bytes(sys_info.disk.used_space_bytes),
        "disk_available": format::format_bytes(sys_info.disk.available_space_bytes),
        "disk_details": sys_info.disk.disks.iter().take(3).map(|disk| json!({
            "name": disk.name,
            "mount_point": disk.mount_point,
            "file_system": disk.file_system,
            "usage_percent": disk.usage_percent.round() as u32,
            "total_space": format::format_bytes(disk.total_space_bytes),
            "available_space": format::format_bytes(disk.available_space_bytes)
        })).collect::<Vec<_>>(),
        
        // Temperature Information
        "cpu_temperature": sys_info.thermal.cpu_temperature_celsius,
        "thermal_state": format!("{:?}", sys_info.thermal.thermal_state),
        "thermal_components": sys_info.thermal.components.iter().take(5).map(|component| {
            let (temp_str, color_class) = format::format_temperature(component.temperature_celsius);
            json!({
                "label": component.label,
                "temperature": temp_str,
                "temperature_raw": component.temperature_celsius,
                "color_class": color_class
            })
        }).collect::<Vec<_>>(),
        
        // System Details
        "uptime": format::format_duration(sys_info.system.uptime_seconds),
        "uptime_seconds": sys_info.system.uptime_seconds,
        "hostname": sys_info.system.hostname,
        "os_name": sys_info.system.os_name,
        "os_version": sys_info.system.os_version,
        "architecture": sys_info.system.architecture,
        "version": env!("CARGO_PKG_VERSION"),
        "server_name": "Atlas DNS",
        "dot_enabled": context.dot_enabled,
        "doh_enabled": context.doh_server_enabled,

        // Process Information
        "total_processes": sys_info.processes.total_processes,
        "running_processes": sys_info.processes.running_processes,
        "atlas_process": sys_info.processes.atlas_process.as_ref().map(|proc| json!({
            "pid": proc.pid,
            "cpu_usage": proc.cpu_usage_percent.round() as u32,
            "memory_usage": format::format_bytes(proc.memory_bytes),
            "memory_percent": proc.memory_percent,
            "runtime": format::format_duration(proc.runtime_seconds)
        })),
        
        // Network Information (summary)
        "network_bytes_received": format::format_bytes(sys_info.network.total_bytes_received),
        "network_bytes_transmitted": format::format_bytes(sys_info.network.total_bytes_transmitted),
        "network_interfaces": sys_info.network.interfaces.len(),
        
        // Load Average (Unix systems)
        "load_average": json!({
            "one_minute": sys_info.system.load_average.one_minute,
            "five_minutes": sys_info.system.load_average.five_minutes,
            "fifteen_minutes": sys_info.system.load_average.fifteen_minutes
        }),
        
        // DNS Query statistics
        "client_sent_queries": client_sent_queries,
        "client_failed_queries": client_failed_queries,
        "server_tcp_queries": server_tcp_queries,
        "server_udp_queries": server_udp_queries,
        "total_queries": total_queries,
        "blocked_count": blocked_count,
        "top_domains": top_domains,
        "recent_queries": recent_queries,
        
        // Recent activity from activity logger
        "activities": activity_logger.get_recent(10).iter().map(|entry| json!({
            "timestamp": entry.time_ago(),
            "user": entry.user.clone(),
            "action": entry.action.clone(),
            "resource": entry.resource.clone(),
            "success": entry.success,
            "details": entry.details.clone(),
        })).collect::<Vec<_>>()
    }))
}

// Fallback function if system info collection fails
fn build_fallback_response(
    _context: &ServerContext,
    user_manager: &UserManager,
    activity_logger: &ActivityLogger,
    total_zones: usize,
    total_records: usize,
    zone_summaries: Vec<serde_json::Value>,
    cache_entries: usize,
    cache_hit_rate: u32,
    client_sent_queries: usize,
    client_failed_queries: usize,
    server_tcp_queries: usize,
    server_udp_queries: usize,
) -> Result<serde_json::Value> {
    Ok(json!({
        "ok": true,
        "total_zones": total_zones,
        "total_records": total_records,
        "cache_entries": cache_entries,
        "active_users": user_manager.get_active_user_count(),
        "active_sessions": user_manager.get_active_session_count(),
        "total_users": user_manager.get_total_user_count(),
        "active_zones": total_zones,
        "last_update": "Just now",
        "zones": zone_summaries,
        "cache_hit_rate": cache_hit_rate,
        "memory_usage": 0,
        "uptime": "Unknown",
        "version": env!("CARGO_PKG_VERSION"),
        "server_name": "Atlas DNS",
        "client_sent_queries": client_sent_queries,
        "client_failed_queries": client_failed_queries,
        "server_tcp_queries": server_tcp_queries,
        "server_udp_queries": server_udp_queries,
        "total_queries": client_sent_queries + server_tcp_queries + server_udp_queries,
        "blocked_count": 0,
        "top_domains": serde_json::Value::Array(vec![]),
        "recent_queries": serde_json::Value::Array(vec![]),
        "activities": activity_logger.get_recent(10).into_iter().map(|entry| json!({
            "timestamp": entry.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
            "action": entry.action,
            "resource": entry.resource,
            "success": entry.success,
            "details": entry.details,
        })).collect::<Vec<_>>(),
        "system_error": "Unable to collect system information"
    }))
}
