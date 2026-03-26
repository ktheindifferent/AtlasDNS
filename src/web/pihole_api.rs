//! Pi-hole v3/v4/v5 Compatible API
//!
//! Exposes Pi-hole API endpoints at `/admin/api.php` so that existing
//! Pi-hole dashboards (Pi-hole Admin, Gravity Sync, mobile apps, Grafana
//! panels, etc.) can connect to AtlasDNS as if it were a Pi-hole instance.
//!
//! ## Supported query parameters
//!
//! | Parameter                          | Description                              |
//! |------------------------------------|------------------------------------------|
//! | `?summary`                         | Formatted summary statistics             |
//! | `?summaryRaw`                      | Raw numeric summary statistics           |
//! | `?type`                            | Query-type breakdown                     |
//! | `?recentBlocked`                   | Most recently blocked domain             |
//! | `?topItems[=N]`                    | Top queried and top blocked domains      |
//! | `?getQuerySources[=N]`             | Top client IPs by query count            |
//! | `?getQueryLog` / `?getAllQueries`  | Recent query log                         |
//! | `?enable`                          | Enable blocking (no-op, returns status)  |
//! | `?disable`                         | Disable blocking (no-op, returns status) |
//! | `?status`                          | Current blocking status                  |
//! | `?version`                         | API version information                  |
//! | `?list=black&add=<domain>`         | Add domain to blocklist                  |
//! | `?list=black&sub=<domain>`         | Remove domain from blocklist             |

use std::sync::Arc;
use serde_json::{json, Value};
use tiny_http::{Request, Response, StatusCode};

use crate::dns::context::ServerContext;
use crate::web::{WebError, handle_json_response};

/// Handler for the Pi-hole v3/v4/v5 compatible API surface.
pub struct PiholeApiHandler {
    context: Arc<ServerContext>,
}

impl PiholeApiHandler {
    pub fn new(context: Arc<ServerContext>) -> Self {
        Self { context }
    }

    /// Dispatch a request to `/admin/api.php?<action>`.
    pub fn handle(
        &self,
        request: &Request,
    ) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        let url = request.url();
        let query = url.find('?').map(|i| &url[i + 1..]).unwrap_or("");

        let params: std::collections::HashMap<&str, &str> = query
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|kv| {
                let mut it = kv.splitn(2, '=');
                let k = it.next().unwrap_or("");
                let v = it.next().unwrap_or("");
                (k, v)
            })
            .collect();

        // Blocklist management: ?list=black&add=<domain> / ?list=black&sub=<domain>
        if params.get("list").map(|v| *v == "black" || *v == "blacklist").unwrap_or(false) {
            if let Some(&domain) = params.get("add") {
                return self.blocklist_add(domain);
            }
            if let Some(&domain) = params.get("sub") {
                return self.blocklist_remove(domain);
            }
        }

        if params.contains_key("summary") || params.contains_key("summaryRaw") {
            return self.summary();
        }
        if params.contains_key("type") {
            return self.query_type_breakdown();
        }
        if params.contains_key("recentBlocked") {
            return self.recent_blocked();
        }
        if params.contains_key("topItems") {
            let count: usize = params.get("topItems")
                .and_then(|v| v.parse().ok())
                .unwrap_or(10);
            return self.top_items(count);
        }
        if params.contains_key("getQuerySources") {
            let count: usize = params.get("getQuerySources")
                .and_then(|v| v.parse().ok())
                .unwrap_or(10);
            return self.query_sources(count);
        }
        if params.contains_key("getQueryLog") || params.contains_key("getAllQueries") {
            return self.query_log();
        }
        if params.contains_key("enable") {
            return self.set_blocking(true);
        }
        if params.contains_key("disable") {
            return self.set_blocking(false);
        }
        if params.contains_key("status") {
            return self.status();
        }
        if params.contains_key("version") {
            return self.version();
        }

        handle_json_response(&json!({}), StatusCode(200))
    }

    // -------------------------------------------------------------------------
    // Endpoint implementations
    // -------------------------------------------------------------------------

    fn summary(&self) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        let tcp = self.context.statistics.get_tcp_query_count();
        let udp = self.context.statistics.get_udp_query_count();
        let total_queries = (tcp + udp) as u64;

        let (blocked, blocklist_size) = self.blocked_and_list_size();

        let ads_pct = if total_queries > 0 {
            (blocked as f64 / total_queries as f64) * 100.0
        } else {
            0.0
        };

        let cache_entries = self.context.cache.list().map(|v| v.len()).unwrap_or(0);

        let body = json!({
            "domains_being_blocked": blocklist_size,
            "dns_queries_today":     total_queries,
            "ads_blocked_today":     blocked,
            "ads_percentage_today":  ads_pct,
            "unique_domains":        cache_entries,
            "queries_forwarded":     udp,
            "queries_cached":        cache_entries,
            "clients_ever_seen":     self.unique_clients(),
            "unique_clients":        self.unique_clients(),
            "dns_queries_all_types": total_queries,
            "reply_NODATA":          0,
            "reply_NXDOMAIN":        0,
            "reply_CNAME":           0,
            "reply_IP":              total_queries.saturating_sub(blocked),
            "privacy_level":         0,
            "status":                "enabled",
            "gravity_last_updated": {
                "absolute": 0,
                "relative": { "days": 0, "hours": 0, "minutes": 0 }
            }
        });
        handle_json_response(&body, StatusCode(200))
    }

    fn query_type_breakdown(&self) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        let mut type_counts: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();

        if let Some(ref tracker) = self.context.device_tracker {
            for entry in tracker.get_log(10_000, None) {
                let qt = entry.query_type.to_uppercase();
                let label = match qt.as_str() {
                    "A"     => "A (IPv4)".to_string(),
                    "AAAA"  => "AAAA (IPv6)".to_string(),
                    "MX"    => "MX".to_string(),
                    "PTR"   => "PTR".to_string(),
                    "SRV"   => "SRV".to_string(),
                    "SOA"   => "SOA".to_string(),
                    "CNAME" => "CNAME".to_string(),
                    "TXT"   => "TXT".to_string(),
                    "NS"    => "NS".to_string(),
                    "ANY"   => "ANY".to_string(),
                    other   => other.to_string(),
                };
                *type_counts.entry(label).or_insert(0) += 1;
            }
        }

        // Convert to percentages (Pi-hole v4 format)
        let total: u64 = type_counts.values().sum();
        let querytypes: serde_json::Map<String, Value> = type_counts
            .into_iter()
            .map(|(k, v)| {
                let pct = if total > 0 { (v as f64 / total as f64) * 100.0 } else { 0.0 };
                (k, json!(pct))
            })
            .collect();

        handle_json_response(&json!({ "querytypes": querytypes }), StatusCode(200))
    }

    fn recent_blocked(&self) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        let domain = if let Some(ref tracker) = self.context.device_tracker {
            tracker
                .get_log(1000, None)
                .into_iter()
                .find(|e| e.blocked)
                .map(|e| e.domain)
                .unwrap_or_default()
        } else {
            String::new()
        };

        // Pi-hole returns plain text for this endpoint
        let response = Response::from_string(domain)
            .with_status_code(StatusCode(200))
            .with_header(
                tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/plain"[..])
                    .expect("static header"),
            );
        Ok(response)
    }

    fn top_items(&self, count: usize) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        let (top_queries, top_ads) = if let Some(ref tracker) = self.context.device_tracker {
            let log = tracker.get_log(10_000, None);
            let mut domain_counts: std::collections::HashMap<String, u64> =
                std::collections::HashMap::new();
            let mut blocked_counts: std::collections::HashMap<String, u64> =
                std::collections::HashMap::new();
            for entry in &log {
                *domain_counts.entry(entry.domain.clone()).or_insert(0) += 1;
                if entry.blocked {
                    *blocked_counts.entry(entry.domain.clone()).or_insert(0) += 1;
                }
            }
            let mut top: Vec<(String, u64)> = domain_counts.into_iter().collect();
            top.sort_by(|a, b| b.1.cmp(&a.1));
            top.truncate(count);

            let mut blocked: Vec<(String, u64)> = blocked_counts.into_iter().collect();
            blocked.sort_by(|a, b| b.1.cmp(&a.1));
            blocked.truncate(count);

            (top, blocked)
        } else {
            (vec![], vec![])
        };

        let top_queries_map: serde_json::Map<String, Value> = top_queries
            .into_iter()
            .map(|(d, n)| (d, json!(n)))
            .collect();
        let top_ads_map: serde_json::Map<String, Value> = top_ads
            .into_iter()
            .map(|(d, n)| (d, json!(n)))
            .collect();

        handle_json_response(
            &json!({ "top_queries": top_queries_map, "top_ads": top_ads_map }),
            StatusCode(200),
        )
    }

    fn query_sources(&self, count: usize) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        let top_sources: serde_json::Map<String, Value> =
            if let Some(ref tracker) = self.context.device_tracker {
                let mut clients = tracker.get_clients();
                clients.sort_by(|a, b| b.query_count.cmp(&a.query_count));
                clients.truncate(count);
                clients
                    .into_iter()
                    .map(|c| {
                        // Pi-hole uses "ip|hostname" as key; we don't do reverse DNS, so just IP
                        let key = format!("{}|", c.client_ip);
                        (key, json!(c.query_count))
                    })
                    .collect()
            } else {
                serde_json::Map::new()
            };

        handle_json_response(&json!({ "top_sources": top_sources }), StatusCode(200))
    }

    fn query_log(&self) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        let entries: Vec<Value> = if let Some(ref qlog) = self.context.query_log {
            qlog.get_log(100, None, None)
                .into_iter()
                .map(|e| json!({
                    "timestamp": e.timestamp,
                    "type":      e.query_type,
                    "domain":    e.domain,
                    "client":    e.client_ip,
                    "status":    if e.blocked { "blocked" } else { "ok" },
                    "dnssec":    e.dnssec_status.unwrap_or_default()
                }))
                .collect()
        } else {
            vec![]
        };

        handle_json_response(&json!({ "data": entries }), StatusCode(200))
    }

    fn blocklist_add(&self, domain: &str) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        let domain = domain.trim().to_lowercase();
        if domain.is_empty() {
            return handle_json_response(
                &json!({ "success": false, "message": "domain is required" }),
                StatusCode(400),
            );
        }
        self.context
            .security_manager
            .add_domains_to_blocklist(
                &[domain.clone()],
                crate::dns::security::firewall::ThreatCategory::Custom,
            )
            .map_err(|e| WebError::InternalError(e.to_string()))?;
        log::info!("Pi-hole API: added '{}' to blocklist", domain);
        handle_json_response(
            &json!({ "success": true, "message": format!("Added {} to blacklist", domain) }),
            StatusCode(200),
        )
    }

    fn blocklist_remove(&self, domain: &str) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        let domain = domain.trim().to_lowercase();
        if domain.is_empty() {
            return handle_json_response(
                &json!({ "success": false, "message": "domain is required" }),
                StatusCode(400),
            );
        }
        self.context
            .security_manager
            .remove_from_blocklist(&[domain.clone()])
            .map_err(|e| WebError::InternalError(e.to_string()))?;
        log::info!("Pi-hole API: removed '{}' from blocklist", domain);
        handle_json_response(
            &json!({ "success": true, "message": format!("Removed {} from blacklist", domain) }),
            StatusCode(200),
        )
    }

    fn set_blocking(&self, enable: bool) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        log::info!(
            "Pi-hole API: blocking {} requested",
            if enable { "enable" } else { "disable" }
        );
        let status = if enable { "enabled" } else { "disabled" };
        handle_json_response(&json!({ "status": status }), StatusCode(200))
    }

    fn status(&self) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        handle_json_response(&json!({ "status": "enabled" }), StatusCode(200))
    }

    fn version(&self) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        handle_json_response(
            &json!({ "version": 5, "FTL": "AtlasDNS", "branch": "master" }),
            StatusCode(200),
        )
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// Returns `(blocked_today, domains_in_blocklist)`.
    fn blocked_and_list_size(&self) -> (u64, u64) {
        let fw_metrics = self.context.security_manager.get_metrics();
        let blocked = fw_metrics.firewall_blocked;
        let blocklist_size = self.context.security_manager.get_blocklist_count();
        (blocked, blocklist_size)
    }

    fn unique_clients(&self) -> usize {
        self.context
            .device_tracker
            .as_ref()
            .map(|t| t.get_clients().len())
            .unwrap_or(0)
    }
}
