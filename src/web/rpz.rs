//! RPZ (Response Policy Zone) admin API endpoints.
//!
//! Provides runtime management of the RPZ DNS firewall engine:
//! - List / add / remove RPZ zones
//! - Add / remove individual rules within a zone
//! - View statistics
//! - Load zones from files or AXFR
//! - Enable / disable zones and the engine globally

use std::net::IpAddr;
use std::sync::Arc;

use serde_derive::Deserialize;
use serde_json::json;
use tiny_http::{Request, ResponseBox};

use crate::dns::context::ServerContext;
use crate::dns::rpz::{
    RpzAction, RpzRule, RpzTriggerType, RpzZone, RpzZoneSource, ThreatCategory,
};
use crate::web::{handle_json_response, Result, WebError};

// ─── Request / response types ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AddZoneRequest {
    pub name: String,
    pub priority: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool { true }

#[derive(Debug, Deserialize)]
pub struct AddRuleRequest {
    pub trigger_value: String,
    #[serde(default = "default_qname")]
    pub trigger_type: String,
    #[serde(default = "default_nxdomain")]
    pub action: String,
    pub redirect_to: Option<String>,
    pub category: Option<String>,
    pub description: Option<String>,
}

fn default_qname() -> String { "QNAME".into() }
fn default_nxdomain() -> String { "NXDOMAIN".into() }

#[derive(Debug, Deserialize)]
pub struct RemoveRuleRequest {
    pub trigger_value: String,
    #[serde(default = "default_qname")]
    pub trigger_type: String,
}

#[derive(Debug, Deserialize)]
pub struct LoadFileRequest {
    pub name: String,
    pub priority: u32,
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct LoadAxfrRequest {
    pub name: String,
    pub priority: u32,
    pub server: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub zone_name: String,
}

fn default_port() -> u16 { 53 }

#[derive(Debug, Deserialize)]
pub struct SetEnabledRequest {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct WhitelistRequest {
    pub domain: String,
}

// ─── Parsing helpers ─────────────────────────────────────────────────────────

fn parse_trigger_type(s: &str) -> Result<RpzTriggerType> {
    match s.to_uppercase().as_str() {
        "QNAME" | "Q" => Ok(RpzTriggerType::QName),
        "CLIENT-IP" | "CLIENT_IP" | "CLIENTIP" | "IP" => Ok(RpzTriggerType::ClientIp),
        "NSDNAME" | "NS" => Ok(RpzTriggerType::NsDName),
        _ => Err(WebError::InvalidInput(format!("Unknown trigger type: {}", s))),
    }
}

fn parse_action(s: &str) -> Result<RpzAction> {
    match s.to_uppercase().as_str() {
        "NXDOMAIN" | "NX" => Ok(RpzAction::NxDomain),
        "NODATA" | "ND" => Ok(RpzAction::NoData),
        "DROP" => Ok(RpzAction::Drop),
        "REDIRECT" | "REDIR" => Ok(RpzAction::Redirect),
        "PASSTHRU" | "PASS" | "ALLOW" => Ok(RpzAction::Passthru),
        "TCP-ONLY" | "TCP_ONLY" | "TCPONLY" | "TCP" => Ok(RpzAction::TcpOnly),
        _ => Err(WebError::InvalidInput(format!("Unknown action: {}", s))),
    }
}

fn parse_category(s: &str) -> ThreatCategory {
    match s.to_lowercase().as_str() {
        "malware" => ThreatCategory::Malware,
        "phishing" => ThreatCategory::Phishing,
        "botnet" => ThreatCategory::Botnet,
        "advertising" | "ads" => ThreatCategory::Advertising,
        "tracking" => ThreatCategory::Tracking,
        "adult" => ThreatCategory::Adult,
        "gambling" => ThreatCategory::Gambling,
        _ => ThreatCategory::Custom(0),
    }
}

fn read_json_body<T: serde::de::DeserializeOwned>(request: &mut Request) -> Result<T> {
    let mut body = String::new();
    request.as_reader().read_to_string(&mut body)
        .map_err(WebError::Io)?;
    serde_json::from_str(&body).map_err(|e| WebError::InvalidInput(e.to_string()))
}

// ─── Handler implementations ─────────────────────────────────────────────────

/// GET /api/rpz/zones — list all RPZ zones
pub fn list_zones(context: &Arc<ServerContext>) -> Result<ResponseBox> {
    let zones = context.rpz_engine.list_zones();
    let data = json!({
        "enabled": context.rpz_engine.is_enabled(),
        "zones": zones,
    });
    Ok(handle_json_response(&data, tiny_http::StatusCode(200))?.boxed())
}

/// POST /api/rpz/zones — add a new inline RPZ zone
pub fn add_zone(context: &Arc<ServerContext>, request: &mut Request) -> Result<ResponseBox> {
    let req: AddZoneRequest = read_json_body(request)?;
    let mut zone = RpzZone::new(req.name.clone(), req.priority, RpzZoneSource::Inline);
    zone.enabled = req.enabled;
    context.rpz_engine.add_zone(zone);
    log::info!("RPZ API: added zone '{}' priority={}", req.name, req.priority);
    let data = json!({"status": "ok", "zone": req.name});
    Ok(handle_json_response(&data, tiny_http::StatusCode(201))?.boxed())
}

/// DELETE /api/rpz/zones/{name} — remove an RPZ zone
pub fn remove_zone(context: &Arc<ServerContext>, zone_name: &str) -> Result<ResponseBox> {
    if context.rpz_engine.remove_zone(zone_name) {
        log::info!("RPZ API: removed zone '{}'", zone_name);
        let data = json!({"status": "ok"});
        Ok(handle_json_response(&data, tiny_http::StatusCode(200))?.boxed())
    } else {
        let data = json!({"error": "Zone not found"});
        Ok(handle_json_response(&data, tiny_http::StatusCode(404))?.boxed())
    }
}

/// POST /api/rpz/zones/{name}/enable — enable/disable a zone
pub fn set_zone_enabled(
    context: &Arc<ServerContext>, zone_name: &str, request: &mut Request,
) -> Result<ResponseBox> {
    let req: SetEnabledRequest = read_json_body(request)?;
    if context.rpz_engine.set_zone_enabled(zone_name, req.enabled) {
        let data = json!({"status": "ok", "zone": zone_name, "enabled": req.enabled});
        Ok(handle_json_response(&data, tiny_http::StatusCode(200))?.boxed())
    } else {
        let data = json!({"error": "Zone not found"});
        Ok(handle_json_response(&data, tiny_http::StatusCode(404))?.boxed())
    }
}

/// POST /api/rpz/zones/{name}/rules — add a rule to a zone
pub fn add_rule(
    context: &Arc<ServerContext>, zone_name: &str, request: &mut Request,
) -> Result<ResponseBox> {
    let req: AddRuleRequest = read_json_body(request)?;
    let trigger_type = parse_trigger_type(&req.trigger_type)?;
    let action = parse_action(&req.action)?;
    let category = req.category.as_deref().map(parse_category)
        .unwrap_or(ThreatCategory::Custom(0));
    let redirect_to = match &req.redirect_to {
        Some(ip_str) => Some(ip_str.parse::<IpAddr>()
            .map_err(|e| WebError::InvalidInput(format!("Invalid redirect IP: {}", e)))?),
        None => None,
    };

    if action == RpzAction::Redirect && redirect_to.is_none() {
        return Err(WebError::InvalidInput("Redirect action requires redirect_to IP".into()));
    }

    let rule = RpzRule {
        trigger_value: req.trigger_value.clone(),
        trigger_type,
        action,
        redirect_to,
        category,
        description: req.description,
        local_data: None,
    };

    if context.rpz_engine.add_rule_to_zone(zone_name, rule) {
        log::info!("RPZ API: added rule {}:{} -> {} to zone '{}'",
            req.trigger_type, req.trigger_value, req.action, zone_name);
        let data = json!({"status": "ok"});
        Ok(handle_json_response(&data, tiny_http::StatusCode(201))?.boxed())
    } else {
        let data = json!({"error": "Zone not found"});
        Ok(handle_json_response(&data, tiny_http::StatusCode(404))?.boxed())
    }
}

/// DELETE /api/rpz/zones/{name}/rules — remove a rule from a zone
pub fn remove_rule(
    context: &Arc<ServerContext>, zone_name: &str, request: &mut Request,
) -> Result<ResponseBox> {
    let req: RemoveRuleRequest = read_json_body(request)?;
    let trigger_type = parse_trigger_type(&req.trigger_type)?;

    if context.rpz_engine.remove_rule_from_zone(zone_name, &req.trigger_value, trigger_type) {
        log::info!("RPZ API: removed rule {}:{} from zone '{}'",
            req.trigger_type, req.trigger_value, zone_name);
        let data = json!({"status": "ok"});
        Ok(handle_json_response(&data, tiny_http::StatusCode(200))?.boxed())
    } else {
        let data = json!({"error": "Rule or zone not found"});
        Ok(handle_json_response(&data, tiny_http::StatusCode(404))?.boxed())
    }
}

/// GET /api/rpz/stats — get RPZ statistics
pub fn get_stats(context: &Arc<ServerContext>) -> Result<ResponseBox> {
    let stats = context.rpz_engine.get_stats();
    Ok(handle_json_response(&stats, tiny_http::StatusCode(200))?.boxed())
}

/// POST /api/rpz/stats/reset — reset statistics
pub fn reset_stats(context: &Arc<ServerContext>) -> Result<ResponseBox> {
    context.rpz_engine.reset_stats();
    let data = json!({"status": "ok"});
    Ok(handle_json_response(&data, tiny_http::StatusCode(200))?.boxed())
}

/// POST /api/rpz/enable — enable/disable the engine globally
pub fn set_engine_enabled(
    context: &Arc<ServerContext>, request: &mut Request,
) -> Result<ResponseBox> {
    let req: SetEnabledRequest = read_json_body(request)?;
    context.rpz_engine.set_enabled(req.enabled);
    log::info!("RPZ API: engine enabled={}", req.enabled);
    let data = json!({"status": "ok", "enabled": req.enabled});
    Ok(handle_json_response(&data, tiny_http::StatusCode(200))?.boxed())
}

/// POST /api/rpz/load/file — load a zone from a local file
pub fn load_from_file(
    context: &Arc<ServerContext>, request: &mut Request,
) -> Result<ResponseBox> {
    let req: LoadFileRequest = read_json_body(request)?;
    match context.rpz_engine.load_zone_from_file(&req.name, req.priority, &req.path) {
        Ok(count) => {
            let data = json!({"status": "ok", "zone": req.name, "rules_loaded": count});
            Ok(handle_json_response(&data, tiny_http::StatusCode(200))?.boxed())
        }
        Err(e) => {
            let data = json!({"error": e});
            Ok(handle_json_response(&data, tiny_http::StatusCode(400))?.boxed())
        }
    }
}

/// POST /api/rpz/load/axfr — load a zone from remote AXFR
pub fn load_from_axfr(
    context: &Arc<ServerContext>, request: &mut Request,
) -> Result<ResponseBox> {
    let req: LoadAxfrRequest = read_json_body(request)?;
    match context.rpz_engine.load_zone_from_axfr(
        &req.name, req.priority, &req.server, req.port, &req.zone_name,
    ) {
        Ok(count) => {
            let data = json!({"status": "ok", "zone": req.name, "rules_loaded": count});
            Ok(handle_json_response(&data, tiny_http::StatusCode(200))?.boxed())
        }
        Err(e) => {
            let data = json!({"error": e});
            Ok(handle_json_response(&data, tiny_http::StatusCode(400))?.boxed())
        }
    }
}

/// GET /api/rpz/whitelist — list whitelisted domains
pub fn get_whitelist(context: &Arc<ServerContext>) -> Result<ResponseBox> {
    let domains = context.rpz_engine.get_whitelist();
    let data = json!({"whitelist": domains});
    Ok(handle_json_response(&data, tiny_http::StatusCode(200))?.boxed())
}

/// POST /api/rpz/whitelist — add a domain to the whitelist
pub fn add_to_whitelist(
    context: &Arc<ServerContext>, request: &mut Request,
) -> Result<ResponseBox> {
    let req: WhitelistRequest = read_json_body(request)?;
    context.rpz_engine.add_whitelist(&req.domain);
    let data = json!({"status": "ok", "domain": req.domain});
    Ok(handle_json_response(&data, tiny_http::StatusCode(201))?.boxed())
}

/// DELETE /api/rpz/whitelist/{domain} — remove a domain from the whitelist
pub fn remove_from_whitelist(
    context: &Arc<ServerContext>, domain: &str,
) -> Result<ResponseBox> {
    if context.rpz_engine.remove_whitelist(domain) {
        let data = json!({"status": "ok"});
        Ok(handle_json_response(&data, tiny_http::StatusCode(200))?.boxed())
    } else {
        let data = json!({"error": "Domain not in whitelist"});
        Ok(handle_json_response(&data, tiny_http::StatusCode(404))?.boxed())
    }
}
