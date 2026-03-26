//! Captive-portal HTTP server for blocked-domain redirection.
//!
//! When the DNS firewall redirects a blocked domain to the captive-portal IP,
//! any HTTP request that arrives on the portal port is answered with a
//! configurable "this site is blocked" page (or an HTTP redirect).
//!
//! # Integration
//!
//! 1. Set [`CaptivePortalConfig::portal_ip`] to an IP the DNS server will
//!    return for blocked A queries (sinkhole address).
//! 2. Call [`CaptivePortal::start`] during server startup; it spawns a
//!    background thread.
//! 3. Point RPZ / firewall sinkhole actions at `portal_ip`.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the captive portal HTTP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptivePortalConfig {
    /// Whether the portal is active.
    pub enabled: bool,
    /// TCP port the portal HTTP server listens on (default: 8082).
    pub listen_port: u16,
    /// IPv4 address that the DNS server returns for blocked domains (sinkhole IP).
    pub portal_ip: Ipv4Addr,
    /// HTML to serve when no redirect URL is configured.
    /// The placeholder `{domain}` is replaced with the `Host:` header value.
    pub page_html: String,
    /// If set, the portal sends a 302 redirect to this URL instead of serving HTML.
    pub redirect_url: Option<String>,
}

impl Default for CaptivePortalConfig {
    fn default() -> Self {
        CaptivePortalConfig {
            enabled: false,
            listen_port: 8082,
            portal_ip: Ipv4Addr::new(127, 0, 0, 2),
            page_html: DEFAULT_PAGE.to_string(),
            redirect_url: None,
        }
    }
}

const DEFAULT_PAGE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Site Blocked – AtlasDNS</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: #f0f2f5; display: flex; align-items: center;
           justify-content: center; min-height: 100vh; margin: 0; }
    .card { background: #fff; border-radius: 12px; padding: 48px 40px;
            box-shadow: 0 4px 24px rgba(0,0,0,.10); max-width: 480px;
            text-align: center; }
    .icon { font-size: 64px; margin-bottom: 16px; }
    h1 { color: #e74c3c; margin: 0 0 12px; font-size: 1.8rem; }
    p  { color: #555; line-height: 1.6; }
    code { background: #f5f5f5; padding: 2px 6px; border-radius: 4px;
           font-size: .95em; }
    .footer { margin-top: 32px; font-size: .8rem; color: #aaa; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">&#128683;</div>
    <h1>Site Blocked</h1>
    <p>Access to <code>{domain}</code> has been blocked by
       <strong>AtlasDNS</strong> content filtering.</p>
    <p>If you believe this is a mistake, please contact your
       network administrator.</p>
    <div class="footer">Powered by AtlasDNS</div>
  </div>
</body>
</html>"#;

// ---------------------------------------------------------------------------
// CaptivePortal
// ---------------------------------------------------------------------------

/// Lightweight captive-portal HTTP server for blocked-domain responses.
pub struct CaptivePortal {
    config: Arc<RwLock<CaptivePortalConfig>>,
}

impl CaptivePortal {
    /// Create a new captive portal with the given configuration.
    pub fn new(config: CaptivePortalConfig) -> Self {
        CaptivePortal {
            config: Arc::new(RwLock::new(config)),
        }
    }

    /// Return the sinkhole/portal IPv4 address that the DNS server should
    /// return for blocked A queries.
    pub fn portal_ip(&self) -> Ipv4Addr {
        self.config.read().portal_ip
    }

    /// Whether the portal server is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.read().enabled
    }

    /// Start the background HTTP server thread.
    ///
    /// If the portal is disabled this is a no-op.  Returns an error if the
    /// TCP socket cannot be bound.
    pub fn start(&self) -> std::io::Result<()> {
        let cfg = self.config.read().clone();
        if !cfg.enabled {
            return Ok(());
        }

        // Load custom page from config/portal.html if it exists
        let html = if std::path::Path::new("config/portal.html").exists() {
            std::fs::read_to_string("config/portal.html").unwrap_or(cfg.page_html.clone())
        } else {
            cfg.page_html.clone()
        };

        let addr = format!("0.0.0.0:{}", cfg.listen_port);
        let listener = TcpListener::bind(&addr)?;
        log::info!("Captive portal HTTP server listening on {}", addr);

        thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(s) => {
                        let html_clone = html.clone();
                        let redirect = cfg.redirect_url.clone();
                        thread::spawn(move || {
                            if let Err(e) = handle_request(s, &html_clone, redirect.as_deref()) {
                                log::trace!("Captive portal connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => log::warn!("Captive portal accept error: {}", e),
                }
            }
        });

        Ok(())
    }

    /// Update the page HTML at runtime.
    pub fn set_page_html(&self, html: String) {
        self.config.write().page_html = html;
    }

    /// Update the redirect URL at runtime (`None` to serve HTML instead).
    pub fn set_redirect_url(&self, url: Option<String>) {
        self.config.write().redirect_url = url;
    }

    /// Return a clone of the current configuration.
    pub fn get_config(&self) -> CaptivePortalConfig {
        self.config.read().clone()
    }
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

fn handle_request(
    mut stream: TcpStream,
    html: &str,
    redirect: Option<&str>,
) -> std::io::Result<()> {
    // Read request (we only need the Host header)
    let mut buf = [0u8; 4096];
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let _ = stream.read(&mut buf);

    let raw = std::str::from_utf8(&buf).unwrap_or("");
    let host = raw
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("host:"))
        .and_then(|l| l.splitn(2, ':').nth(1))
        .map(|h| h.trim())
        .unwrap_or("blocked-site");

    let response = if let Some(url) = redirect {
        format!(
            "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            url
        )
    } else {
        let page = html.replace("{domain}", host);
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            page.len(),
            page
        )
    };

    stream.write_all(response.as_bytes())
}
