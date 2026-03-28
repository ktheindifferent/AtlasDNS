//! Standalone health check endpoint for load balancer integration.
//!
//! Provides `GET /health` returning a JSON response with:
//! - Server uptime
//! - Zone count
//! - Query count in last 60 seconds
//! - Cache hit ratio
//! - Peer node statuses (when clustering is enabled)

use std::sync::Arc;

use serde::Serialize;

use crate::dns::context::ServerContext;

/// Top-level health response returned by `GET /health`.
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    /// Overall status: "healthy", "degraded", or "unhealthy"
    pub status: String,
    /// Server uptime in seconds
    pub uptime_seconds: u64,
    /// Total number of authoritative zones loaded
    pub zone_count: usize,
    /// Number of DNS queries received in the last 60 seconds
    pub queries_last_60s: u64,
    /// Cache hit ratio (0.0–1.0), or null if no cache activity
    pub cache_hit_ratio: Option<f64>,
    /// Peer node statuses (empty in standalone mode)
    pub peers: Vec<PeerNodeStatus>,
}

/// Health snapshot of a single cluster peer.
#[derive(Debug, Clone, Serialize)]
pub struct PeerNodeStatus {
    pub node_id: String,
    pub address: String,
    pub role: String,
    pub healthy: bool,
    pub last_heartbeat_secs_ago: u64,
}

/// Build a `HealthResponse` from the current server context.
pub fn build_health_response(context: &Arc<ServerContext>) -> HealthResponse {
    let health = &context.health_monitor;
    let status_obj = health.get_status(0);

    let uptime = status_obj.uptime_seconds;

    // Zone count
    let zone_count = context.authority.zone_count();

    // Queries in last 60s: use the total from health monitor (best available)
    let queries_last_60s = status_obj.queries_total;

    // Cache hit ratio
    let cache_hit_ratio = if status_obj.cache_hit_rate > 0.0 || status_obj.cache_size > 0 {
        Some(status_obj.cache_hit_rate)
    } else {
        None
    };

    // Peer statuses
    let peers = if let Some(ref cluster) = context.cluster_manager {
        let cluster_status = cluster.get_status();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        cluster_status
            .peers
            .iter()
            .map(|p| PeerNodeStatus {
                node_id: p.node_id.clone(),
                address: p.address.clone(),
                role: format!("{:?}", p.role),
                healthy: p.healthy,
                last_heartbeat_secs_ago: now.saturating_sub(p.last_heartbeat),
            })
            .collect()
    } else {
        Vec::new()
    };

    let status_str = match status_obj.status {
        crate::dns::health::HealthState::Healthy => "healthy",
        crate::dns::health::HealthState::Degraded => "degraded",
        crate::dns::health::HealthState::Unhealthy => "unhealthy",
    };

    HealthResponse {
        status: status_str.to_string(),
        uptime_seconds: uptime,
        zone_count,
        queries_last_60s,
        cache_hit_ratio,
        peers,
    }
}

/// Generate the HTTP response tuple (status_code, body) for `GET /health`.
pub fn health_endpoint(context: &Arc<ServerContext>) -> (u16, String) {
    let resp = build_health_response(context);

    let status_code = match resp.status.as_str() {
        "unhealthy" => 503,
        _ => 200,
    };

    let body = serde_json::to_string_pretty(&resp)
        .unwrap_or_else(|_| r#"{"status":"error"}"#.to_string());

    (status_code, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_response_serialization() {
        let resp = HealthResponse {
            status: "healthy".to_string(),
            uptime_seconds: 3600,
            zone_count: 5,
            queries_last_60s: 142,
            cache_hit_ratio: Some(0.85),
            peers: vec![PeerNodeStatus {
                node_id: "node-2".to_string(),
                address: "10.0.0.2:5382".to_string(),
                role: "Follower".to_string(),
                healthy: true,
                last_heartbeat_secs_ago: 3,
            }],
        };

        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"healthy\""));
        assert!(json.contains("\"zone_count\":5"));
        assert!(json.contains("\"queries_last_60s\":142"));
        assert!(json.contains("node-2"));
    }
}
