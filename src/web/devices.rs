//! `GET /api/devices` and `GET /api/mdns/devices` — returns the mDNS device registry as JSON.

use std::sync::Arc;

use crate::dns::context::ServerContext;

/// Return all mDNS-discovered devices as a JSON array.
pub fn get_devices(context: &Arc<ServerContext>) -> serde_json::Value {
    match &context.mdns_registry {
        Some(registry) => {
            let devices = registry.all_devices();
            serde_json::json!({
                "count": devices.len(),
                "devices": devices,
            })
        }
        None => serde_json::json!({
            "count": 0,
            "devices": [],
            "error": "mDNS registry not available",
        }),
    }
}

/// Lookup a single device by hostname.
pub fn get_device_by_hostname(context: &Arc<ServerContext>, hostname: &str) -> serde_json::Value {
    match &context.mdns_registry {
        Some(registry) => {
            let devices = registry.all_devices();
            match devices.iter().find(|d| d.hostname.eq_ignore_ascii_case(hostname)) {
                Some(device) => serde_json::to_value(device).unwrap_or(serde_json::json!(null)),
                None => serde_json::json!({"error": "device not found"}),
            }
        }
        None => serde_json::json!({"error": "mDNS registry not available"}),
    }
}
