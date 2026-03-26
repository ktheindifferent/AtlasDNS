//! Standalone Prometheus metrics HTTP server
//!
//! Runs a minimal HTTP/1.1 server on a dedicated port (default 9153 — the
//! standard port used by DNS exporters such as coredns and bind_exporter).
//!
//! The single endpoint `GET /metrics` returns all registered Prometheus metrics
//! in the standard text/plain exposition format (version 0.0.4).  No
//! authentication is required so that Prometheus scrapers work without extra
//! configuration.
//!
//! # Usage
//!
//! ```ignore
//! let server = PrometheusServer::new(context.clone());
//! std::thread::spawn(move || server.run());
//! ```

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use crate::dns::context::ServerContext;

/// Lightweight HTTP server that serves Prometheus metrics on a dedicated port.
pub struct PrometheusServer {
    port: u16,
    context: Arc<ServerContext>,
}

impl PrometheusServer {
    /// Create a new `PrometheusServer` bound to `context.metrics_port`.
    pub fn new(context: Arc<ServerContext>) -> Self {
        Self {
            port: context.metrics_port,
            context,
        }
    }

    /// Block and serve metrics requests indefinitely.
    ///
    /// Each accepted TCP connection is handled synchronously (one at a time) —
    /// metrics scrapes are infrequent (typically every 15–60 s) so this is
    /// more than fast enough.
    pub fn run(&self) {
        let addr = format!("0.0.0.0:{}", self.port);
        let listener = match TcpListener::bind(&addr) {
            Ok(l) => {
                log::info!("Prometheus metrics server listening on {}", addr);
                l
            }
            Err(e) => {
                log::error!("Failed to bind Prometheus metrics server on {}: {}", addr, e);
                return;
            }
        };

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    // Read the HTTP request (we only need the request line, but we
                    // must drain at least part of the socket so the client doesn't
                    // get a connection-reset).
                    let mut buf = [0u8; 2048];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let request = std::str::from_utf8(&buf[..n]).unwrap_or("");

                    // Only respond to GET /metrics; return 404 for everything else.
                    let (status, body, content_type) =
                        if request.starts_with("GET /metrics") || request.starts_with("GET / ") {
                            let body = self
                                .context
                                .metrics
                                .export_metrics()
                                .unwrap_or_else(|e| {
                                    log::warn!("Failed to export Prometheus metrics: {}", e);
                                    String::new()
                                });
                            ("200 OK", body, "text/plain; version=0.0.4; charset=utf-8")
                        } else if request.starts_with("GET /health") {
                            ("200 OK", "ok\n".to_string(), "text/plain")
                        } else {
                            (
                                "404 Not Found",
                                "404 Not Found\n".to_string(),
                                "text/plain",
                            )
                        };

                    let response = format!(
                        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status,
                        content_type,
                        body.len(),
                        body,
                    );

                    if let Err(e) = stream.write_all(response.as_bytes()) {
                        log::debug!("Failed to write metrics response: {}", e);
                    }
                }
                Err(e) => {
                    log::debug!("Metrics server accept error: {}", e);
                }
            }
        }
    }
}
