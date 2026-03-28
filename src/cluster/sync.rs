//! gRPC-based zone synchronization between cluster nodes.
//!
//! The primary node broadcasts zone updates to replicas via the `ZoneSync`
//! service.  Replicas apply the update to their local authority store and
//! acknowledge with a success/failure status.
//!
//! # Wire format
//!
//! We define the protobuf messages inline using `prost` derive macros instead
//! of a `.proto` file to keep the build simple (no `tonic-build` step).

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

use prost::Message;
use serde::{Serialize, Deserialize};
use tonic::Status;

use crate::dns::authority::Authority;
use crate::dns::protocol::DnsRecord;

// ─────────────────────────── Protobuf messages ────────────────────────────

/// A single DNS resource record in the sync payload.
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct SyncRecord {
    /// JSON-serialized `DnsRecord`
    #[prost(string, tag = "1")]
    pub record_json: String,
}

/// Full zone snapshot sent from primary to replica.
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct SyncZoneRequest {
    /// Zone domain name (e.g. "example.com")
    #[prost(string, tag = "1")]
    pub domain: String,

    /// SOA primary nameserver
    #[prost(string, tag = "2")]
    pub m_name: String,

    /// SOA responsible person
    #[prost(string, tag = "3")]
    pub r_name: String,

    /// SOA serial
    #[prost(uint32, tag = "4")]
    pub serial: u32,

    /// SOA refresh
    #[prost(uint32, tag = "5")]
    pub refresh: u32,

    /// SOA retry
    #[prost(uint32, tag = "6")]
    pub retry: u32,

    /// SOA expire
    #[prost(uint32, tag = "7")]
    pub expire: u32,

    /// SOA minimum TTL
    #[prost(uint32, tag = "8")]
    pub minimum: u32,

    /// All resource records for this zone
    #[prost(message, repeated, tag = "9")]
    pub records: Vec<SyncRecord>,

    /// Node ID of the sending primary
    #[prost(string, tag = "10")]
    pub from_node_id: String,
}

/// Response from replica after applying a zone sync.
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct SyncZoneResponse {
    /// Whether the zone was applied successfully
    #[prost(bool, tag = "1")]
    pub success: bool,

    /// Human-readable message (error details on failure)
    #[prost(string, tag = "2")]
    pub message: String,

    /// Replica's node ID
    #[prost(string, tag = "3")]
    pub node_id: String,

    /// Number of records applied
    #[prost(uint32, tag = "4")]
    pub records_applied: u32,
}

// ─────────────────────────── Service implementation ───────────────────────

/// Server-side handler for the ZoneSync gRPC service (runs on replicas).
///
/// Receives zone snapshots from the primary and applies them to the local
/// authority store.
pub struct ZoneSyncHandler {
    authority: Arc<Authority>,
    node_id: String,
}

impl ZoneSyncHandler {
    pub fn new(authority: Arc<Authority>, node_id: String) -> Self {
        Self { authority, node_id }
    }

    /// Process a SyncZone request: deserialize records, build a Zone, and
    /// upsert it into the authority store.
    pub fn handle_sync_zone(
        &self,
        req: SyncZoneRequest,
    ) -> Result<SyncZoneResponse, Status> {
        log::info!(
            "[zone_sync] received zone '{}' (serial {}) from node '{}'",
            req.domain, req.serial, req.from_node_id
        );

        // Deserialize records from JSON
        let mut records = BTreeSet::new();
        for sync_rec in &req.records {
            match serde_json::from_str::<DnsRecord>(&sync_rec.record_json) {
                Ok(rec) => {
                    records.insert(rec);
                }
                Err(e) => {
                    log::warn!(
                        "[zone_sync] skipping malformed record in zone '{}': {}",
                        req.domain, e
                    );
                }
            }
        }

        let record_count = records.len() as u32;

        // Build the zone
        let zone = crate::dns::authority::Zone {
            domain: req.domain.clone(),
            m_name: req.m_name,
            r_name: req.r_name,
            serial: req.serial,
            refresh: req.refresh,
            retry: req.retry,
            expire: req.expire,
            minimum: req.minimum,
            records,
            dnssec_enabled: false,
            signed_zone: None,
        };

        // Apply to authority via upsert
        match self.authority.upsert_zone(zone) {
            Ok(()) => {
                log::info!(
                    "[zone_sync] applied zone '{}' with {} records",
                    req.domain, record_count
                );
                Ok(SyncZoneResponse {
                    success: true,
                    message: format!("Zone '{}' applied successfully", req.domain),
                    node_id: self.node_id.clone(),
                    records_applied: record_count,
                })
            }
            Err(e) => {
                log::error!("[zone_sync] failed to apply zone '{}': {}", req.domain, e);
                Ok(SyncZoneResponse {
                    success: false,
                    message: format!("Failed to apply zone: {}", e),
                    node_id: self.node_id.clone(),
                    records_applied: 0,
                })
            }
        }
    }
}

// ─────────────────────────── gRPC server ──────────────────────────────────

/// Start the ZoneSync gRPC server on the given address.
///
/// Uses a raw TCP listener with tonic, handling the `SyncZone` RPC manually.
/// Spawn with `tokio::spawn`.
pub async fn start_zone_sync_server(
    addr: SocketAddr,
    authority: Arc<Authority>,
    node_id: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::net::TcpListener;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let handler = Arc::new(ZoneSyncHandler::new(authority, node_id));
    let listener = TcpListener::bind(addr).await?;
    log::info!("[zone_sync] gRPC server listening on {}", addr);

    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                log::warn!("[zone_sync] accept error: {}", e);
                continue;
            }
        };

        let handler = handler.clone();
        tokio::spawn(async move {
            log::debug!("[zone_sync] connection from {}", peer);

            // Read all data from the stream (simplified: read up to 16MB)
            let mut buf = Vec::new();
            let mut tmp = vec![0u8; 65536];
            loop {
                match stream.read(&mut tmp).await {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.len() > 16 * 1024 * 1024 {
                            log::warn!("[zone_sync] payload too large from {}", peer);
                            return;
                        }
                        // If we have enough data for a complete message, process it
                        if n < tmp.len() {
                            break;
                        }
                    }
                    Err(e) => {
                        log::warn!("[zone_sync] read error from {}: {}", peer, e);
                        return;
                    }
                }
            }

            // Try to decode as a SyncZoneRequest (skip any HTTP/2 framing — we
            // use a simplified binary protocol for the TCP transport).
            // Format: 4-byte big-endian length + protobuf payload
            if buf.len() < 4 {
                log::warn!("[zone_sync] short message from {}", peer);
                return;
            }

            let msg_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            if buf.len() < 4 + msg_len {
                log::warn!("[zone_sync] incomplete message from {}", peer);
                return;
            }

            let msg_bytes = &buf[4..4 + msg_len];
            let req = match SyncZoneRequest::decode(msg_bytes) {
                Ok(r) => r,
                Err(e) => {
                    log::warn!("[zone_sync] decode error from {}: {}", peer, e);
                    return;
                }
            };

            let resp = match handler.handle_sync_zone(req) {
                Ok(r) => r,
                Err(e) => {
                    log::error!("[zone_sync] handler error: {}", e);
                    SyncZoneResponse {
                        success: false,
                        message: e.to_string(),
                        node_id: String::new(),
                        records_applied: 0,
                    }
                }
            };

            // Encode and send response: 4-byte length + protobuf
            let mut resp_buf = Vec::new();
            if resp.encode(&mut resp_buf).is_ok() {
                let len_bytes = (resp_buf.len() as u32).to_be_bytes();
                let _ = stream.write_all(&len_bytes).await;
                let _ = stream.write_all(&resp_buf).await;
                let _ = stream.flush().await;
            }
        });
    }
}

// ─────────────────────────── Client helper ─────────────────────────────────

/// Send a zone sync request to a replica node over TCP.
///
/// Wire format: 4-byte big-endian length prefix + protobuf payload.
pub async fn send_zone_sync(
    replica_addr: &str,
    zone: &crate::dns::authority::Zone,
    from_node_id: &str,
) -> Result<SyncZoneResponse, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::net::TcpStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let records: Vec<SyncRecord> = zone
        .records
        .iter()
        .filter_map(|rec| {
            serde_json::to_string(rec).ok().map(|json| SyncRecord {
                record_json: json,
            })
        })
        .collect();

    let request = SyncZoneRequest {
        domain: zone.domain.clone(),
        m_name: zone.m_name.clone(),
        r_name: zone.r_name.clone(),
        serial: zone.serial,
        refresh: zone.refresh,
        retry: zone.retry,
        expire: zone.expire,
        minimum: zone.minimum,
        records,
        from_node_id: from_node_id.to_string(),
    };

    let mut buf = Vec::new();
    request.encode(&mut buf)?;

    // Connect to replica
    let mut stream = TcpStream::connect(replica_addr).await?;

    // Send: 4-byte length + payload
    let len_bytes = (buf.len() as u32).to_be_bytes();
    stream.write_all(&len_bytes).await?;
    stream.write_all(&buf).await?;
    stream.flush().await?;

    // Read response: 4-byte length + payload
    let mut resp_len_buf = [0u8; 4];
    stream.read_exact(&mut resp_len_buf).await?;
    let resp_len = u32::from_be_bytes(resp_len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await?;

    let response = SyncZoneResponse::decode(&resp_buf[..])?;
    Ok(response)
}

/// Broadcast a zone update to all replica nodes.
///
/// Returns a list of `(replica_addr, result)` pairs.
pub async fn broadcast_zone_sync(
    replica_addrs: &[String],
    zone: &crate::dns::authority::Zone,
    from_node_id: &str,
) -> Vec<(String, Result<SyncZoneResponse, String>)> {
    let mut results = Vec::with_capacity(replica_addrs.len());

    for addr in replica_addrs {
        let result = send_zone_sync(addr, zone, from_node_id).await;
        match result {
            Ok(resp) => {
                log::info!(
                    "[zone_sync] sync to {}: success={}, records={}",
                    addr, resp.success, resp.records_applied
                );
                results.push((addr.clone(), Ok(resp)));
            }
            Err(e) => {
                log::error!("[zone_sync] sync to {} failed: {}", addr, e);
                results.push((addr.clone(), Err(e.to_string())));
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_zone_request_roundtrip() {
        let req = SyncZoneRequest {
            domain: "example.com".to_string(),
            m_name: "ns1.example.com".to_string(),
            r_name: "admin.example.com".to_string(),
            serial: 2026032701,
            refresh: 3600,
            retry: 900,
            expire: 604800,
            minimum: 86400,
            records: vec![SyncRecord {
                record_json: r#"{"A":{"domain":"www.example.com","addr":"93.184.216.34","ttl":3600}}"#.to_string(),
            }],
            from_node_id: "node-1".to_string(),
        };

        let mut buf = Vec::new();
        req.encode(&mut buf).unwrap();

        let decoded = SyncZoneRequest::decode(&buf[..]).unwrap();
        assert_eq!(decoded.domain, "example.com");
        assert_eq!(decoded.serial, 2026032701);
        assert_eq!(decoded.records.len(), 1);
        assert_eq!(decoded.from_node_id, "node-1");
    }

    #[test]
    fn test_sync_zone_response_roundtrip() {
        let resp = SyncZoneResponse {
            success: true,
            message: "OK".to_string(),
            node_id: "replica-1".to_string(),
            records_applied: 42,
        };

        let mut buf = Vec::new();
        resp.encode(&mut buf).unwrap();

        let decoded = SyncZoneResponse::decode(&buf[..]).unwrap();
        assert!(decoded.success);
        assert_eq!(decoded.records_applied, 42);
    }
}
