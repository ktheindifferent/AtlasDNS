//! DNS-over-TLS (DoT) Implementation — RFC 7858
//!
//! Provides a TLS listener on port 853.  Each client connection is served
//! over a persistent TLS session (rustls); DNS messages are framed with a
//! 2-byte big-endian length prefix as required by RFC 7858 §3.3.
//!
//! # Certificate resolution order
//! 1. Explicit paths in [`DotConfig`] (`cert_path` / `key_path`)
//! 2. Environment variables `TLS_CERT_PATH` / `TLS_KEY_PATH`
//! 3. Auto-generated self-signed certificate via `rcgen` (development mode)

use std::io::{BufReader, Read, Write};
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use rustls::{Certificate, PrivateKey, ServerConfig, ServerConnection, StreamOwned};

use crate::dns::buffer::BytePacketBuffer;
use crate::dns::context::ServerContext;
use crate::dns::errors::DnsError;
use crate::dns::logging::{CorrelationContext, DnsQueryLog};
use crate::dns::protocol::{DnsPacket, ResultCode};
use crate::dns::resolve::{DnsResolver, RecursiveDnsResolver};

// ── Configuration ────────────────────────────────────────────────────────────

/// Runtime configuration for the DNS-over-TLS server.
#[derive(Debug, Clone)]
pub struct DotConfig {
    /// Enable the DoT server.
    pub enabled: bool,
    /// TCP port to listen on (RFC 7858 default: 853).
    pub port: u16,
    /// Path to a PEM-encoded certificate chain.
    /// `None` → check `TLS_CERT_PATH` env var, then auto-generate.
    pub cert_path: Option<String>,
    /// Path to a PEM-encoded private key.
    /// `None` → check `TLS_KEY_PATH` env var, then auto-generate.
    pub key_path: Option<String>,
    /// Per-connection read/write timeout in seconds.
    pub timeout_secs: u64,
    /// Maximum number of simultaneous connections (advisory; currently
    /// enforced at the OS accept-queue level).
    pub max_connections: usize,
}

impl Default for DotConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 853,
            cert_path: None,
            key_path: None,
            timeout_secs: 10,
            max_connections: 1000,
        }
    }
}

// ── Server ───────────────────────────────────────────────────────────────────

/// DNS-over-TLS server (RFC 7858).
pub struct DotServer {
    context: Arc<ServerContext>,
    config: DotConfig,
    tls_config: Arc<ServerConfig>,
}

impl DotServer {
    /// Create a new DoT server, loading (or generating) TLS material.
    pub fn new(context: Arc<ServerContext>, config: DotConfig) -> Result<Self, DnsError> {
        let (certs, key) = Self::resolve_tls_material(&config)?;

        let tls_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| {
                DnsError::Io(std::io::Error::other(e.to_string()))
            })?;

        Ok(Self {
            context,
            config,
            tls_config: Arc::new(tls_config),
        })
    }

    // ── TLS material helpers ─────────────────────────────────────────────────

    /// Resolve certs + key: explicit config → env vars → self-signed.
    fn resolve_tls_material(
        config: &DotConfig,
    ) -> Result<(Vec<Certificate>, PrivateKey), DnsError> {
        let cert_path = config
            .cert_path
            .clone()
            .or_else(|| std::env::var("TLS_CERT_PATH").ok());
        let key_path = config
            .key_path
            .clone()
            .or_else(|| std::env::var("TLS_KEY_PATH").ok());

        match (cert_path, key_path) {
            (Some(cp), Some(kp)) => {
                let cert_pem = std::fs::read(&cp).map_err(|e| {
                    DnsError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("DoT cert '{}': {}", cp, e),
                    ))
                })?;
                let key_pem = std::fs::read(&kp).map_err(|e| {
                    DnsError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("DoT key '{}': {}", kp, e),
                    ))
                })?;
                let certs = Self::parse_pem_certs(&cert_pem)?;
                let key = Self::parse_pem_key(&key_pem)?;
                log::info!("DoT: loaded TLS certificate from {}", cp);
                Ok((certs, key))
            }
            _ => {
                log::warn!(
                    "DoT: no TLS certificate configured \
                     (set TLS_CERT_PATH/TLS_KEY_PATH or --dot-cert/--dot-key). \
                     Generating a self-signed certificate for development."
                );
                Self::generate_self_signed()
            }
        }
    }

    /// Generate a self-signed certificate with rcgen.
    fn generate_self_signed() -> Result<(Vec<Certificate>, PrivateKey), DnsError> {
        let cert = generate_simple_self_signed(vec![
            "localhost".to_string(),
            "atlas-dns".to_string(),
        ])
        .map_err(|e| {
            DnsError::Io(std::io::Error::other(e.to_string()))
        })?;

        let cert_der = cert.serialize_der().map_err(|e| {
            DnsError::Io(std::io::Error::other(e.to_string()))
        })?;
        let key_der = cert.serialize_private_key_der();

        Ok((vec![Certificate(cert_der)], PrivateKey(key_der)))
    }

    /// Parse PEM-encoded certificate chain.
    fn parse_pem_certs(pem: &[u8]) -> Result<Vec<Certificate>, DnsError> {
        let mut reader = BufReader::new(pem);
        let raw = rustls_pemfile::certs(&mut reader).map_err(|e| {
            DnsError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
        })?;
        if raw.is_empty() {
            return Err(DnsError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "DoT: no certificates found in PEM file",
            )));
        }
        Ok(raw.into_iter().map(Certificate).collect())
    }

    /// Parse a PEM-encoded private key (PKCS#8 or RSA).
    fn parse_pem_key(pem: &[u8]) -> Result<PrivateKey, DnsError> {
        // Try PKCS#8 first
        let mut reader = BufReader::new(pem);
        if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut reader)
            .map_err(|e| {
                DnsError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e.to_string(),
                ))
            })?
            .into_iter()
            .next()
        {
            return Ok(PrivateKey(key));
        }

        // Fall back to RSA
        let mut reader = BufReader::new(pem);
        if let Some(key) = rustls_pemfile::rsa_private_keys(&mut reader)
            .map_err(|e| {
                DnsError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e.to_string(),
                ))
            })?
            .into_iter()
            .next()
        {
            return Ok(PrivateKey(key));
        }

        Err(DnsError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DoT: no private key found in PEM file",
        )))
    }

    // ── Server loop ──────────────────────────────────────────────────────────

    /// Start the DoT server.  Blocks the calling thread.
    pub fn run(&self) -> Result<(), DnsError> {
        let listener = TcpListener::bind(("0.0.0.0", self.config.port)).map_err(DnsError::Io)?;

        log::info!(
            "DoT (DNS-over-TLS) server listening on port {} (RFC 7858)",
            self.config.port
        );

        for stream in listener.incoming() {
            match stream {
                Ok(tcp) => {
                    let tls_cfg = self.tls_config.clone();
                    let ctx = self.context.clone();
                    let timeout = self.config.timeout_secs;
                    std::thread::spawn(move || {
                        if let Err(e) = Self::handle_connection(tcp, tls_cfg, ctx, timeout) {
                            log::debug!("DoT connection ended: {:?}", e);
                        }
                    });
                }
                Err(e) => {
                    log::error!("DoT: accept error: {}", e);
                }
            }
        }

        Ok(())
    }

    /// TLS handshake → message loop for one connection.
    fn handle_connection(
        tcp: TcpStream,
        tls_cfg: Arc<ServerConfig>,
        context: Arc<ServerContext>,
        timeout_secs: u64,
    ) -> Result<(), DnsError> {
        let peer = tcp.peer_addr().ok();
        let dur = Duration::from_secs(timeout_secs);
        tcp.set_read_timeout(Some(dur)).map_err(DnsError::Io)?;
        tcp.set_write_timeout(Some(dur)).map_err(DnsError::Io)?;
        tcp.set_nodelay(true).map_err(DnsError::Io)?;

        let conn = ServerConnection::new(tls_cfg).map_err(|e| {
            DnsError::Io(std::io::Error::other(e.to_string()))
        })?;
        let mut tls = StreamOwned::new(conn, tcp);

        log::debug!("DoT: TLS connection from {:?}", peer);

        // RFC 7858 §3.3 — 2-byte big-endian length prefix per message
        loop {
            let mut len_buf = [0u8; 2];
            match tls.read_exact(&mut len_buf) {
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(e) => {
                    log::debug!("DoT read len: {}", e);
                    break;
                }
            }

            let msg_len = u16::from_be_bytes(len_buf) as usize;
            if msg_len == 0 {
                continue;
            }

            let mut msg = vec![0u8; msg_len];
            if let Err(e) = tls.read_exact(&mut msg) {
                log::debug!("DoT read body: {}", e);
                break;
            }

            let response = match Self::process_query(&msg, context.clone()) {
                Ok(r) => r,
                Err(e) => {
                    log::warn!("DoT query error: {:?}", e);
                    continue;
                }
            };

            let rlen = response.len() as u16;
            if tls.write_all(&rlen.to_be_bytes()).is_err()
                || tls.write_all(&response).is_err()
                || tls.flush().is_err()
            {
                break;
            }
        }

        Ok(())
    }

    // ── Query processing ─────────────────────────────────────────────────────

    /// Parse a raw DNS query and return a serialised response.
    fn process_query(
        query_bytes: &[u8],
        context: Arc<ServerContext>,
    ) -> Result<Vec<u8>, DnsError> {
        let ctx = CorrelationContext::new("dot_server", "process_query");

        // Deserialise request
        let mut buf = BytePacketBuffer::new();
        if query_bytes.len() > buf.buf.len() {
            return Err(DnsError::PacketTooLarge);
        }
        buf.buf[..query_bytes.len()].copy_from_slice(query_bytes);
        buf.pos = 0;

        let request = DnsPacket::from_buffer(&mut buf)?;

        if request.questions.is_empty() {
            let mut ep = DnsPacket::new();
            ep.header.id = request.header.id;
            ep.header.rescode = ResultCode::FORMERR;
            ep.header.response = true;
            let mut rb = BytePacketBuffer::new();
            ep.write(&mut rb, 512)?;
            return Ok(rb.buf[..rb.pos].to_vec());
        }

        let question = &request.questions[0];
        let domain = &question.name;
        let qtype = question.qtype;

        // Log the query
        let query_log = DnsQueryLog {
            domain: domain.clone(),
            query_type: format!("{:?}", qtype),
            protocol: "DoT".to_string(),
            response_code: "NOERROR".to_string(),
            answer_count: 0,
            cache_hit: false,
            upstream_server: None,
            dnssec_status: None,
            timestamp: chrono::Utc::now(),
            client_ip: None,
            latency_ms: None,
        };
        context.logger.log_dns_query(&ctx, query_log);

        // Cache hit path
        if let Some(cached) = context.cache.lookup(domain, qtype) {
            context
                .metrics
                .record_dns_query("DoT", &format!("{:?}", qtype), "cache");
            let mut rb = BytePacketBuffer::new();
            let mut pkt = cached;
            pkt.header.id = request.header.id;
            pkt.write(&mut rb, 512)?;
            return Ok(rb.buf[..rb.pos].to_vec());
        }

        // Recursive resolution
        let mut resolver = RecursiveDnsResolver::new(context.clone());
        let mut response = match resolver.resolve(domain, qtype, true) {
            Ok(p) => p,
            Err(_) => {
                let mut ep = DnsPacket::new();
                ep.header.id = request.header.id;
                ep.header.rescode = ResultCode::SERVFAIL;
                ep.header.response = true;
                ep
            }
        };
        response.header.id = request.header.id;

        if response.header.rescode == ResultCode::NOERROR && !response.answers.is_empty() {
            let _ = context.cache.store(&response.answers);
        }

        context
            .metrics
            .record_dns_query("DoT", &format!("{:?}", qtype), "recursive");

        let mut rb = BytePacketBuffer::new();
        response.write(&mut rb, 512)?;
        Ok(rb.buf[..rb.pos].to_vec())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dot_config_default() {
        let cfg = DotConfig::default();
        assert_eq!(cfg.port, 853);
        assert!(!cfg.enabled);
        assert!(cfg.cert_path.is_none());
        assert!(cfg.key_path.is_none());
    }

    #[test]
    fn test_generate_self_signed() {
        let result = DotServer::generate_self_signed();
        assert!(result.is_ok(), "self-signed gen failed: {:?}", result.err());
        let (certs, _key) = result.unwrap();
        assert!(!certs.is_empty());
    }

    #[test]
    fn test_message_length_roundtrip() {
        let len: u16 = 512;
        assert_eq!(len, u16::from_be_bytes(len.to_be_bytes()));
    }
}
