//! `GET /api/devices` — returns the mDNS device registry as JSON.

use std::sync::Arc;

use crate::dns::context::ServerContext;

/// Return all mDNS-discovered devices as a JSON array.
pub fn get_devices(context: &Arc<ServerContext>) -> serde_json::Value {
    match &context.mdns_registry {
        Some(registry) => {
            let devices = registry.all_devices();
            serde_json::to_value(&devices).unwrap_or(serde_json::json!([]))
        }
        None => serde_json::json!([]),
    }
}
