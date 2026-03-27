//! REST API handlers for threat intelligence feeds and domain reputation.
//!
//! # Endpoints
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | GET    | `/api/v2/threat-intel/stats`         | Overall stats + per-feed info |
//! | GET    | `/api/v2/threat-intel/feeds`         | List all configured feeds |
//! | POST   | `/api/v2/threat-intel/feeds/:id/refresh` | Force-refresh a specific feed |
//! | POST   | `/api/v2/threat-intel/refresh`       | Refresh all feeds |
//! | GET    | `/api/v2/threat-intel/hits`          | Recent threat-intel hits |
//! | GET    | `/api/v2/threat-intel/reputation/:domain` | Query domain reputation |

use std::sync::Arc;
use serde_json::json;
use tiny_http::{Request, Response, StatusCode};

use crate::dns::context::ServerContext;
use crate::web::{WebError, handle_json_response};

pub struct ThreatIntelApiHandler {
    context: Arc<ServerContext>,
}

impl ThreatIntelApiHandler {
    pub fn new(context: Arc<ServerContext>) -> Self {
        Self { context }
    }

    // -----------------------------------------------------------------------
    // GET /api/v2/threat-intel/stats
    // -----------------------------------------------------------------------

    pub fn get_stats(&self) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        let mgr = self.require_manager()?;
        let stats = mgr.get_stats();
        handle_json_response(&json!({ "success": true, "data": stats }), StatusCode(200))
    }

    // -----------------------------------------------------------------------
    // GET /api/v2/threat-intel/feeds
    // -----------------------------------------------------------------------

    pub fn list_feeds(&self) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        let mgr = self.require_manager()?;
        let feeds = mgr.list_feeds();
        handle_json_response(&json!({ "success": true, "data": feeds }), StatusCode(200))
    }

    // -----------------------------------------------------------------------
    // POST /api/v2/threat-intel/feeds/:id/refresh
    // -----------------------------------------------------------------------

    pub fn refresh_feed(
        &self,
        feed_id: &str,
        request: &mut Request,
    ) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        let _ = request; // not needed – kept for uniform handler signature
        let mgr = self.require_manager()?;
        let feed_id = feed_id.to_string();
        let feed_id_display = feed_id.clone();

        // Run the async refresh in a blocking context via a dedicated runtime
        let result = std::thread::spawn(move || -> Result<usize, String> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("Runtime error: {}", e))?;
            rt.block_on(mgr.refresh_feed(&feed_id))
        })
        .join()
        .map_err(|_| "Refresh thread panicked".to_string());

        match result {
            Ok(Ok(count)) => handle_json_response(
                &json!({ "success": true, "data": { "feed_id": feed_id_display, "domains_loaded": count } }),
                StatusCode(200),
            ),
            Ok(Err(e)) | Err(e) => handle_json_response(
                &json!({ "success": false, "error": e }),
                StatusCode(500),
            ),
        }
    }

    // -----------------------------------------------------------------------
    // POST /api/v2/threat-intel/refresh
    // -----------------------------------------------------------------------

    pub fn refresh_all(
        &self,
        request: &mut Request,
    ) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        let _ = request;
        let mgr = self.require_manager()?;

        let results: std::collections::HashMap<String, Result<usize, String>> =
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("runtime");
                rt.block_on(mgr.refresh_all())
            })
            .join()
            .map_err(|_| WebError::InternalError("Refresh thread panicked".to_string()))?;

        let summary: Vec<serde_json::Value> = results
            .into_iter()
            .map(|(id, res)| match res {
                Ok(n) => json!({ "feed_id": id, "success": true, "domains_loaded": n }),
                Err(e) => json!({ "feed_id": id, "success": false, "error": e }),
            })
            .collect();

        handle_json_response(
            &json!({ "success": true, "data": summary }),
            StatusCode(200),
        )
    }

    // -----------------------------------------------------------------------
    // GET /api/v2/threat-intel/hits?limit=50
    // -----------------------------------------------------------------------

    pub fn get_hits(
        &self,
        request: &Request,
    ) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        let limit = parse_query_param(request.url(), "limit")
            .unwrap_or(50)
            .min(1000);

        let mgr = self.require_manager()?;
        let hits = mgr.get_recent_hits(limit);
        handle_json_response(
            &json!({ "success": true, "data": hits, "count": hits.len() }),
            StatusCode(200),
        )
    }

    // -----------------------------------------------------------------------
    // GET /api/v2/threat-intel/reputation/:domain
    // -----------------------------------------------------------------------

    pub fn get_reputation(
        &self,
        domain: &str,
    ) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        if domain.is_empty() {
            return handle_json_response(
                &json!({ "success": false, "error": "domain parameter is required" }),
                StatusCode(400),
            );
        }

        let mgr = self.require_manager()?;
        let rep = mgr.query_reputation(domain);
        handle_json_response(&json!({ "success": true, "data": rep }), StatusCode(200))
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn require_manager(
        &self,
    ) -> Result<Arc<crate::dns::security::ThreatIntelManager>, WebError> {
        self.context
            .threat_intel
            .clone()
            .ok_or_else(|| WebError::InternalError("ThreatIntelManager not configured".into()))
    }
}

/// Parse a numeric query-string parameter from a URL like `/path?key=value`.
fn parse_query_param(url: &str, key: &str) -> Option<usize> {
    let query = url.split_once('?')?.1;
    for part in query.split('&') {
        let mut kv = part.splitn(2, '=');
        if kv.next()? == key {
            return kv.next()?.parse().ok();
        }
    }
    None
}
