//! Standalone DNS-over-HTTPS (DoH) Server
//!
//! Provides a dedicated async HTTPS server for DNS-over-HTTPS queries, separate
//! from the main web management interface.  Serves the `/dns-query` endpoint
//! per RFC 8484, with support for both `application/dns-message` (wire format)
//! and `application/dns-json` (Google DNS JSON API) content types.
//!
//! Features:
//! * Per-client-IP rate limiting
//! * Prometheus metrics integration
//! * CORS support for browser-based clients
//! * Cache-Control headers derived from DNS TTLs
//! * Structured logging with correlation IDs

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use std::collections::HashMap;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};

use crate::dns::context::ServerContext;
use crate::dns::protocol::{DnsPacket, DnsQuestion, QueryType, ResultCode};
use crate::dns::buffer::BytePacketBuffer;
use crate::dns::doh::{DnsJson, DnsJsonQuestion, DnsJsonRecord, DOH_CONTENT_TYPE_MESSAGE, DOH_CONTENT_TYPE_JSON};

/// Standalone DoH server configuration.
#[derive(Debug, Clone)]
pub struct StandaloneDohConfig {
    /// Bind address (e.g. "0.0.0.0")
    pub bind_addr: String,
    /// Port to listen on (default 8443)
    pub port: u16,
    /// Path for DoH endpoint
    pub path: String,
    /// Maximum DNS message size in bytes
    pub max_message_size: usize,
    /// Enable CORS headers
    pub cors: bool,
    /// Cache-Control max-age in seconds
    pub cache_max_age: u32,
    /// Rate limit: max requests per IP per window
    pub rate_limit_max: u64,
    /// Rate limit window in seconds
    pub rate_limit_window_secs: u64,
    /// Optional TLS certificate path (if None, runs plain HTTP)
    pub tls_cert: Option<String>,
    /// Optional TLS key path
    pub tls_key: Option<String>,
}

impl Default for StandaloneDohConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0".to_string(),
            port: 8443,
            path: "/dns-query".to_string(),
            max_message_size: 4096,
            cors: true,
            cache_max_age: 300,
            rate_limit_max: 300,
            rate_limit_window_secs: 60,
            tls_cert: None,
            tls_key: None,
        }
    }
}

/// Per-IP rate limiter for the standalone DoH server.
pub struct StandaloneDohRateLimiter {
    windows: parking_lot::Mutex<HashMap<String, (u64, Instant)>>,
    max_requests: u64,
    window_secs: u64,
}

impl StandaloneDohRateLimiter {
    pub fn new(max_requests: u64, window_secs: u64) -> Self {
        Self {
            windows: parking_lot::Mutex::new(HashMap::new()),
            max_requests,
            window_secs,
        }
    }

    /// Returns true if the request should be allowed.
    pub fn check(&self, client_ip: &str) -> bool {
        let now = Instant::now();
        let mut map = self.windows.lock();
        let entry = map.entry(client_ip.to_string()).or_insert((0, now));
        if now.duration_since(entry.1).as_secs() >= self.window_secs {
            *entry = (1, now);
            true
        } else {
            entry.0 += 1;
            entry.0 <= self.max_requests
        }
    }

    /// Periodically clean up stale entries (call from background task).
    pub fn cleanup(&self) {
        let now = Instant::now();
        let mut map = self.windows.lock();
        map.retain(|_, (_, start)| now.duration_since(*start).as_secs() < self.window_secs * 2);
    }
}

/// Runtime metrics for the standalone DoH server.
#[derive(Debug, Default)]
pub struct StandaloneDohMetrics {
    pub total_queries: AtomicU64,
    pub get_requests: AtomicU64,
    pub post_requests: AtomicU64,
    pub rate_limited: AtomicU64,
    pub errors: AtomicU64,
    pub cache_hits: AtomicU64,
    pub total_response_time_us: AtomicU64,
}

/// The standalone DoH server.
pub struct StandaloneDohServer {
    context: Arc<ServerContext>,
    config: StandaloneDohConfig,
    rate_limiter: Arc<StandaloneDohRateLimiter>,
    metrics: Arc<StandaloneDohMetrics>,
}

impl StandaloneDohServer {
    pub fn new(context: Arc<ServerContext>, config: StandaloneDohConfig) -> Self {
        let rate_limiter = Arc::new(StandaloneDohRateLimiter::new(
            config.rate_limit_max,
            config.rate_limit_window_secs,
        ));
        Self {
            context,
            config,
            rate_limiter,
            metrics: Arc::new(StandaloneDohMetrics::default()),
        }
    }

    /// Get runtime metrics snapshot.
    pub fn get_metrics(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.metrics.total_queries.load(Ordering::Relaxed),
            self.metrics.get_requests.load(Ordering::Relaxed),
            self.metrics.post_requests.load(Ordering::Relaxed),
            self.metrics.rate_limited.load(Ordering::Relaxed),
            self.metrics.errors.load(Ordering::Relaxed),
        )
    }

    /// Handle a binary DNS wire-format query and return the wire-format response.
    pub fn handle_wire_query(&self, query_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let start = Instant::now();
        self.metrics.total_queries.fetch_add(1, Ordering::Relaxed);

        // Parse request
        let mut buffer = BytePacketBuffer::new();
        if query_bytes.len() > self.config.max_message_size {
            return Err("Query too large".to_string());
        }
        buffer.buf[..query_bytes.len()].copy_from_slice(query_bytes);
        buffer.pos = 0;

        let request = DnsPacket::from_buffer(&mut buffer)
            .map_err(|e| format!("Parse error: {:?}", e))?;

        // Resolve
        let response = self.resolve_packet(request)?;

        // Serialize response
        let mut resp_buf = BytePacketBuffer::new();
        response.write(&mut resp_buf, 512)
            .map_err(|e| format!("Serialize error: {:?}", e))?;

        let elapsed = start.elapsed().as_micros() as u64;
        self.metrics.total_response_time_us.fetch_add(elapsed, Ordering::Relaxed);

        Ok(resp_buf.buf[..resp_buf.pos].to_vec())
    }

    /// Handle a JSON DNS query and return a JSON response.
    pub fn handle_json_query(&self, name: &str, qtype_num: u16) -> Result<DnsJson, String> {
        let start = Instant::now();
        self.metrics.total_queries.fetch_add(1, Ordering::Relaxed);

        let mut request = DnsPacket::new();
        request.header.id = rand::random::<u16>();
        request.header.recursion_desired = true;
        request.questions.push(DnsQuestion {
            name: name.to_string(),
            qtype: QueryType::from_num(qtype_num),
        });

        let response = self.resolve_packet(request)?;

        let elapsed = start.elapsed().as_micros() as u64;
        self.metrics.total_response_time_us.fetch_add(elapsed, Ordering::Relaxed);

        Ok(self.packet_to_json(&response))
    }

    /// Core resolution: check cache, then use configured resolver.
    fn resolve_packet(&self, request: DnsPacket) -> Result<DnsPacket, String> {
        if request.questions.is_empty() {
            let mut pkt = DnsPacket::new();
            pkt.header.rescode = ResultCode::FORMERR;
            return Ok(pkt);
        }

        let q = &request.questions[0];
        let domain = &q.name;
        let qtype = q.qtype;

        // Cache check
        if let Some(cached) = self.context.cache.lookup(domain, qtype) {
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            self.context.metrics.record_dns_query("DoH-standalone", &format!("{:?}", qtype), "cache");
            return Ok(cached);
        }

        // Resolve
        let mut resolver = self.context.create_resolver(self.context.clone());
        match resolver.resolve(domain, qtype, true) {
            Ok(resp) => {
                if resp.header.rescode == ResultCode::NOERROR && !resp.answers.is_empty() {
                    let _ = self.context.cache.store(&resp.answers);
                }
                self.context.metrics.record_dns_query("DoH-standalone", &format!("{:?}", qtype), "upstream");
                Ok(resp)
            }
            Err(_) => {
                self.metrics.errors.fetch_add(1, Ordering::Relaxed);
                let mut pkt = request.clone();
                pkt.header.rescode = ResultCode::SERVFAIL;
                Ok(pkt)
            }
        }
    }

    /// Check rate limit for a client IP.
    pub fn check_rate_limit(&self, client_ip: &str) -> bool {
        if !self.rate_limiter.check(client_ip) {
            self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
            false
        } else {
            true
        }
    }

    /// Get the minimum TTL from a DNS packet (for Cache-Control headers).
    pub fn min_ttl(&self, packet: &DnsPacket) -> Option<u32> {
        packet.answers.iter().map(|r| r.get_ttl()).min()
    }

    /// Get cache max age from config.
    pub fn cache_max_age(&self) -> u32 {
        self.config.cache_max_age
    }

    /// Whether CORS is enabled.
    pub fn cors_enabled(&self) -> bool {
        self.config.cors
    }

    fn packet_to_json(&self, packet: &DnsPacket) -> DnsJson {
        DnsJson {
            status: packet.header.rescode as u16,
            tc: packet.header.truncated_message,
            rd: packet.header.recursion_desired,
            ra: packet.header.recursion_available,
            ad: packet.header.authed_data,
            cd: packet.header.checking_disabled,
            question: packet.questions.iter().map(|q| DnsJsonQuestion {
                name: q.name.clone(),
                qtype: q.qtype.to_num(),
            }).collect(),
            answer: packet.answers.iter().map(|r| DnsJsonRecord {
                name: r.get_domain().unwrap_or_else(|| "unknown".to_string()),
                rtype: r.get_querytype().to_num(),
                ttl: r.get_ttl(),
                data: format!("{:?}", r),
            }).collect(),
            authority: packet.authorities.iter().map(|r| DnsJsonRecord {
                name: r.get_domain().unwrap_or_else(|| "unknown".to_string()),
                rtype: r.get_querytype().to_num(),
                ttl: r.get_ttl(),
                data: format!("{:?}", r),
            }).collect(),
            additional: packet.resources.iter().map(|r| DnsJsonRecord {
                name: r.get_domain().unwrap_or_else(|| "unknown".to_string()),
                rtype: r.get_querytype().to_num(),
                ttl: r.get_ttl(),
                data: format!("{:?}", r),
            }).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standalone_doh_config_default() {
        let config = StandaloneDohConfig::default();
        assert_eq!(config.port, 8443);
        assert_eq!(config.path, "/dns-query");
        assert!(config.cors);
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = StandaloneDohRateLimiter::new(3, 60);
        assert!(limiter.check("1.2.3.4"));
        assert!(limiter.check("1.2.3.4"));
        assert!(limiter.check("1.2.3.4"));
        assert!(!limiter.check("1.2.3.4")); // 4th should be blocked
        assert!(limiter.check("5.6.7.8")); // different IP still ok
    }
}
