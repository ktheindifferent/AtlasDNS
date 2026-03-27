//! REST API handlers for blocklist management (`/api/v2/blocklists`).

use std::sync::Arc;
use serde::Deserialize;
use serde_json::json;
use tiny_http::{Request, Response, StatusCode};

use crate::dns::blocklist_updater::{BlocklistBundle, BlocklistEntry, BlocklistPreset};
use crate::dns::context::ServerContext;
use crate::dns::security::firewall::ThreatCategory;
use crate::web::{WebError, handle_json_response};

// ---------------------------------------------------------------------------
// Request/response shapes
// ---------------------------------------------------------------------------

/// Request body for POST /api/v2/blocklists
#[derive(Debug, Deserialize)]
pub struct AddBlocklistRequest {
    /// Download URL (required unless `preset` is set).
    pub url: Option<String>,
    /// Well-known preset name (optional; overrides `url` and `category` defaults).
    pub preset: Option<String>,
    /// Threat category label (optional; defaults to `Adware`).
    pub category: Option<String>,
    /// Hours between automatic refreshes (optional; default 24).
    pub update_interval_hours: Option<u64>,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Stateless handler – all state lives in `ServerContext.blocklist_updater`.
pub struct BlocklistApiHandler {
    context: Arc<ServerContext>,
}

impl BlocklistApiHandler {
    pub fn new(context: Arc<ServerContext>) -> Self {
        Self { context }
    }

    // -----------------------------------------------------------------------
    // GET /api/v2/blocklists
    // -----------------------------------------------------------------------

    pub fn list_blocklists(&self) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        let entries = self.updater_entries();
        let response = json!({ "success": true, "data": entries });
        handle_json_response(&response, StatusCode(200))
    }

    // -----------------------------------------------------------------------
    // POST /api/v2/blocklists
    // -----------------------------------------------------------------------

    pub fn add_blocklist(
        &self,
        request: &mut Request,
    ) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        let body = parse_json_body::<AddBlocklistRequest>(request)?;

        let updater = self.require_updater()?;

        let id = if let Some(preset_name) = &body.preset {
            // Add by preset
            let preset = parse_preset(preset_name)?;
            updater.add_preset(preset)
        } else {
            // Add custom URL
            let url = body
                .url
                .ok_or_else(|| WebError::InvalidInput("'url' or 'preset' is required".into()))?;
            let category = body
                .category
                .as_deref()
                .map(parse_category)
                .unwrap_or(Ok(ThreatCategory::Adware))?;
            let interval = body.update_interval_hours.unwrap_or(24);
            updater.add_entry(url, category, interval, None)
        };

        let response = json!({ "success": true, "data": { "id": id } });
        handle_json_response(&response, StatusCode(201))
    }

    // -----------------------------------------------------------------------
    // DELETE /api/v2/blocklists/:id
    // -----------------------------------------------------------------------

    pub fn remove_blocklist(
        &self,
        id: &str,
    ) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        let updater = self.require_updater()?;
        updater.remove_entry(id);
        let response = json!({ "success": true });
        handle_json_response(&response, StatusCode(200))
    }

    // -----------------------------------------------------------------------
    // POST /api/v2/blocklists/:id/refresh
    // -----------------------------------------------------------------------

    pub fn refresh_blocklist(
        &self,
        id: &str,
    ) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        let updater = self.require_updater()?;
        match updater.refresh_entry(id) {
            Ok(count) => {
                let response = json!({
                    "success": true,
                    "data": { "id": id, "domains_loaded": count }
                });
                handle_json_response(&response, StatusCode(200))
            }
            Err(e) => {
                let response = json!({ "success": false, "error": e });
                handle_json_response(&response, StatusCode(400))
            }
        }
    }

    // -----------------------------------------------------------------------
    // POST /api/v2/blocklists/bundle
    // -----------------------------------------------------------------------

    /// Apply a preset bundle, adding all its constituent blocklists at once.
    ///
    /// Request body: `{"bundle": "home_basic" | "home_plus" | "strict"}`
    pub fn apply_bundle(
        &self,
        request: &mut Request,
    ) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        #[derive(serde::Deserialize)]
        struct BundleRequest {
            bundle: String,
        }

        let body = parse_json_body::<BundleRequest>(request)?;
        let bundle = parse_bundle(&body.bundle)?;
        let updater = self.require_updater()?;
        let ids = updater.apply_bundle(bundle);

        let response = json!({
            "success": true,
            "data": {
                "bundle": body.bundle,
                "description": bundle.description(),
                "ids": ids,
                "count": ids.len(),
            }
        });
        handle_json_response(&response, StatusCode(201))
    }

    // -----------------------------------------------------------------------
    // GET /api/v2/blocklists/bundles  (list available bundles)
    // -----------------------------------------------------------------------

    pub fn list_bundles(&self) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        let bundles: Vec<_> = BlocklistBundle::all()
            .into_iter()
            .map(|b| {
                json!({
                    "name": format!("{:?}", b),
                    "description": b.description(),
                    "presets": b.presets().iter().map(|p| format!("{:?}", p)).collect::<Vec<_>>(),
                })
            })
            .collect();
        let response = json!({ "success": true, "data": bundles });
        handle_json_response(&response, StatusCode(200))
    }

    // -----------------------------------------------------------------------
    // GET /api/v2/blocklists/presets
    // -----------------------------------------------------------------------

    pub fn list_presets(&self) -> Result<Response<std::io::Cursor<Vec<u8>>>, WebError> {
        let presets: Vec<_> = BlocklistPreset::all()
            .into_iter()
            .map(|p| {
                json!({
                    "name": format!("{:?}", p),
                    "url": p.url(),
                    "description": p.description(),
                    "category": format!("{:?}", p.category()),
                })
            })
            .collect();
        let response = json!({ "success": true, "data": presets });
        handle_json_response(&response, StatusCode(200))
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn require_updater(
        &self,
    ) -> Result<Arc<crate::dns::blocklist_updater::BlocklistUpdater>, WebError> {
        self.context
            .blocklist_updater
            .clone()
            .ok_or_else(|| WebError::InternalError("BlocklistUpdater not configured".into()))
    }

    fn updater_entries(&self) -> Vec<BlocklistEntry> {
        self.context
            .blocklist_updater
            .as_ref()
            .map(|u| u.list_entries())
            .unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn parse_bundle(name: &str) -> Result<BlocklistBundle, WebError> {
    match name.to_ascii_lowercase().as_str() {
        "home_basic" | "homebasic" | "home-basic" | "basic" => Ok(BlocklistBundle::HomeBasic),
        "home_plus" | "homeplus" | "home-plus" | "plus" => Ok(BlocklistBundle::HomePlus),
        "strict" => Ok(BlocklistBundle::Strict),
        other => Err(WebError::InvalidInput(format!(
            "Unknown bundle '{}'. Valid bundles: home_basic, home_plus, strict",
            other
        ))),
    }
}

fn parse_preset(name: &str) -> Result<BlocklistPreset, WebError> {
    match name.to_ascii_lowercase().as_str() {
        "hagezi" => Ok(BlocklistPreset::Hagezi),
        "hagezilight" | "hagezi_light" | "hagezi-light" => Ok(BlocklistPreset::HageziLight),
        "oisdfull" | "oisd_full" | "oisd-full" => Ok(BlocklistPreset::OISDFull),
        "oisdbasic" | "oisd_basic" | "oisd-basic" => Ok(BlocklistPreset::OISDBasic),
        "stevenblack" | "steven_black" | "steven-black" => Ok(BlocklistPreset::StevenBlack),
        "stevenblackextended" | "steven_black_extended" | "steven-black-extended" => {
            Ok(BlocklistPreset::StevenBlackExtended)
        }
        "urlhausabuse" | "urlhaus_abuse" | "urlhaus-abuse" | "urlhaus" => {
            Ok(BlocklistPreset::URLhausAbuse)
        }
        other => Err(WebError::InvalidInput(format!("Unknown preset: '{}'", other))),
    }
}

fn parse_category(s: &str) -> Result<ThreatCategory, WebError> {
    match s.to_ascii_lowercase().as_str() {
        "malware" => Ok(ThreatCategory::Malware),
        "phishing" => Ok(ThreatCategory::Phishing),
        "botnet" => Ok(ThreatCategory::Botnet),
        "cryptomining" | "crypto_mining" => Ok(ThreatCategory::CryptoMining),
        "ransomware" => Ok(ThreatCategory::Ransomware),
        "spyware" => Ok(ThreatCategory::Spyware),
        "adware" => Ok(ThreatCategory::Adware),
        "tracking" => Ok(ThreatCategory::Tracking),
        "adult" => Ok(ThreatCategory::Adult),
        "gambling" => Ok(ThreatCategory::Gambling),
        "violence" => Ok(ThreatCategory::Violence),
        "custom" => Ok(ThreatCategory::Custom),
        other => Err(WebError::InvalidInput(format!("Unknown category: '{}'", other))),
    }
}

fn parse_json_body<T: serde::de::DeserializeOwned>(
    request: &mut Request,
) -> Result<T, WebError> {
    let mut body = String::new();
    request
        .as_reader()
        .read_to_string(&mut body)
        .map_err(|_| WebError::InvalidInput("Failed to read request body".into()))?;
    serde_json::from_str(&body)
        .map_err(|e| WebError::InvalidInput(format!("Invalid JSON: {}", e)))
}
