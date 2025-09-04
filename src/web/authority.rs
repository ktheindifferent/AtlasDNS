use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde_derive::{Deserialize, Serialize};
use serde_json::json;

use crate::dns::authority::Zone;
use crate::dns::context::ServerContext;
use crate::dns::protocol::{DnsRecord, TransientTtl};

use crate::web::cache::CacheRecordEntry;
use crate::web::util::FormDataDecodable;
use crate::web::{Result, WebError};
use crate::web::validation::{
    validate_dns_name, validate_record_type, validate_ipv4_address, 
    validate_ipv6_address, validate_ttl, validate_cname_target, sanitize_log
};

#[derive(Debug, Serialize, Deserialize)]
pub struct ZoneCreateRequest {
    pub domain: String,
    pub m_name: String,
    pub r_name: String,
    pub serial: Option<u32>,
    pub refresh: Option<u32>,
    pub retry: Option<u32>,
    pub expire: Option<u32>,
    pub minimum: Option<u32>,
}

impl FormDataDecodable<ZoneCreateRequest> for ZoneCreateRequest {
    fn from_formdata(fields: Vec<(String, String)>) -> Result<ZoneCreateRequest> {
        let mut d: HashMap<_, _> = fields.into_iter().collect();

        let domain = d
            .remove("domain").ok_or(WebError::MissingField("domain"))?;
        let m_name = d
            .remove("m_name").ok_or(WebError::MissingField("m_name"))?;
        let r_name = d
            .remove("r_name").ok_or(WebError::MissingField("r_name"))?;

        Ok(ZoneCreateRequest {
            domain,
            m_name,
            r_name,
            serial: d.get("serial").and_then(|x| x.parse::<u32>().ok()),
            refresh: d.get("refresh").and_then(|x| x.parse::<u32>().ok()),
            retry: d.get("retry").and_then(|x| x.parse::<u32>().ok()),
            expire: d.get("expire").and_then(|x| x.parse::<u32>().ok()),
            minimum: d.get("minimum").and_then(|x| x.parse::<u32>().ok()),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecordRequest {
    pub recordtype: String,
    pub domain: String,
    pub ttl: u32,
    pub host: Option<String>,
}

impl FormDataDecodable<RecordRequest> for RecordRequest {
    fn from_formdata(fields: Vec<(String, String)>) -> Result<RecordRequest> {
        let mut d: HashMap<_, _> = fields.into_iter().collect();

        let recordtype = d
            .remove("recordtype").ok_or(WebError::MissingField("recordtype"))?;
        let domain = d
            .remove("domain").ok_or(WebError::MissingField("domain"))?;

        let ttl = d
            .get("ttl")
            .and_then(|x| x.parse::<u32>().ok()).ok_or(WebError::MissingField("ttl"))?;

        Ok(RecordRequest {
            recordtype,
            domain,
            ttl,
            host: d.remove("host"),
        })
    }
}

impl RecordRequest {
    fn into_resourcerecord(self) -> Result<DnsRecord> {
        log::info!("{:?}", sanitize_log(&format!("{:?}", self)));
        
        // Validate domain name
        let domain = validate_dns_name(&self.domain)
            .map_err(|e| WebError::InvalidInput(e.to_string()))?;
        
        // Validate TTL
        let ttl = validate_ttl(self.ttl)
            .map_err(|e| WebError::InvalidInput(e.to_string()))?;
        
        // Validate and create record based on type
        let record_type = validate_record_type(&self.recordtype)
            .map_err(|e| WebError::InvalidInput(e.to_string()))?;
        
        match record_type.as_str() {
            "A" => {
                let host = self.host.ok_or_else(|| 
                    WebError::InvalidInput("A record requires host IP address".to_string()))?;
                let addr = validate_ipv4_address(&host)
                    .map_err(|e| WebError::InvalidInput(e.to_string()))?;

                Ok(DnsRecord::A {
                    domain,
                    addr,
                    ttl: TransientTtl(ttl),
                })
            }
            "AAAA" => {
                let host = self.host.ok_or_else(|| 
                    WebError::InvalidInput("AAAA record requires host IPv6 address".to_string()))?;
                let addr = validate_ipv6_address(&host)
                    .map_err(|e| WebError::InvalidInput(e.to_string()))?;

                Ok(DnsRecord::Aaaa {
                    domain,
                    addr,
                    ttl: TransientTtl(ttl),
                })
            }
            "CNAME" => {
                let host = self.host.ok_or_else(|| 
                    WebError::InvalidInput("CNAME record requires target hostname".to_string()))?;
                let validated_host = validate_cname_target(&host)
                    .map_err(|e| WebError::InvalidInput(e.to_string()))?;

                Ok(DnsRecord::Cname {
                    domain,
                    host: validated_host,
                    ttl: TransientTtl(ttl),
                })
            }
            _ => Err(WebError::InvalidInput(format!("Unsupported record type: {}", record_type)))
        }
    }
}

pub fn zone_list(context: &ServerContext) -> Result<serde_json::Value> {
    let zones = context.authority.read().map_err(|_| WebError::LockError)?;

    let mut zones_json = Vec::new();
    for zone in &zones.zones() {
        zones_json.push(json!({
            "domain": zone.domain,
            "m_name": zone.m_name,
            "r_name": zone.r_name,
            "serial": zone.serial,
            "refresh": zone.refresh,
            "retry": zone.retry,
            "expire": zone.expire,
            "minimum": zone.minimum,
        }));
    }

    let zone_count = zones_json.len();
    Ok(json!({
        "ok": true,
        "zones": zones_json,
        "zone_count": zone_count,
    }))
}

pub fn zone_create(context: &ServerContext, request: ZoneCreateRequest) -> Result<Zone> {
    // Validate domain names
    let domain = validate_dns_name(&request.domain)
        .map_err(|e| WebError::InvalidInput(e.to_string()))?;
    let m_name = validate_dns_name(&request.m_name)
        .map_err(|e| WebError::InvalidInput(e.to_string()))?;
    let r_name = validate_dns_name(&request.r_name)
        .map_err(|e| WebError::InvalidInput(e.to_string()))?;
    
    // Validate TTL values
    let refresh = request.refresh.unwrap_or(3600);
    let retry = request.retry.unwrap_or(3600);
    let expire = request.expire.unwrap_or(3600);
    let minimum = request.minimum.unwrap_or(3600);
    
    validate_ttl(refresh).map_err(|e| WebError::InvalidInput(e.to_string()))?;
    validate_ttl(retry).map_err(|e| WebError::InvalidInput(e.to_string()))?;
    validate_ttl(expire).map_err(|e| WebError::InvalidInput(e.to_string()))?;
    validate_ttl(minimum).map_err(|e| WebError::InvalidInput(e.to_string()))?;

    let mut zones = context.authority.write().map_err(|_| WebError::LockError)?;

    let mut zone = Zone::new(domain.clone(), m_name, r_name);
    zone.serial = 0;
    zone.refresh = refresh;
    zone.retry = retry;
    zone.expire = expire;
    zone.minimum = minimum;
    zones.add_zone(zone.clone());

    zones.save(&context.zones_dir)?;
    
    log::info!("Zone created: {}", sanitize_log(&domain));

    Ok(zone)
}

pub fn zone_view(context: &ServerContext, zone: &str) -> Result<serde_json::Value> {
    let zones = context.authority.read().map_err(|_| WebError::LockError)?;

    let zone = zones.get_zone(zone).ok_or(WebError::ZoneNotFound)?;

    let mut records = Vec::new();
    for (id, rr) in zone.records.iter().enumerate() {
        records.push(CacheRecordEntry {
            id: id as u32,
            record: rr.clone(),
        });
    }

    Ok(json!({
        "ok": true,
        "zone": zone.domain,
        "records": records,
    }))
}

pub fn record_create(context: &ServerContext, zone: &str, request: RecordRequest) -> Result<()> {
    // Validate zone name
    let zone_name = validate_dns_name(zone)
        .map_err(|e| WebError::InvalidInput(e.to_string()))?;
    
    // Convert and validate the record request
    let rr = request.into_resourcerecord()?;

    let mut zones = context.authority.write().map_err(|_| WebError::LockError)?;
    let zone = zones
        .get_zone_mut(&zone_name).ok_or(WebError::ZoneNotFound)?;
    zone.add_record(&rr);

    zones.save(&context.zones_dir)?;
    
    log::info!("Record created in zone {}: {:?}", sanitize_log(&zone_name), rr);

    Ok(())
}

pub fn record_delete(context: &ServerContext, zone: &str, request: RecordRequest) -> Result<()> {
    // Validate zone name
    let zone_name = validate_dns_name(zone)
        .map_err(|e| WebError::InvalidInput(e.to_string()))?;
    
    // Convert and validate the record request
    let rr = request.into_resourcerecord()?;

    let mut zones = context.authority.write().map_err(|_| WebError::LockError)?;
    let zone = zones
        .get_zone_mut(&zone_name).ok_or(WebError::ZoneNotFound)?;
    zone.delete_record(&rr);

    zones.save(&context.zones_dir)?;
    
    log::info!("Record deleted from zone {}: {:?}", sanitize_log(&zone_name), rr);

    Ok(())
}

