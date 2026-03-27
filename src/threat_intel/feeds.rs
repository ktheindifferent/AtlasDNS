//! Threat intelligence feed fetching and parsing.
//!
//! Supports:
//! - **abuse.ch URLhaus**: Plain-text domain list from `urlhaus.abuse.ch/downloads/text_online/`
//! - **Spamhaus DNSBL**: DNS-based blocklist lookup against `zen.spamhaus.org`
//! - **Spamhaus DROP/EDROP**: CIDR block lists for known-bad IP ranges
//! - **Feodo Tracker**: Botnet C2 IP list from abuse.ch (JSON format)
//! - **Aggregate fetcher**: Fetch all feeds with RPZ auto-population support

use std::collections::HashSet;
use std::net::{Ipv4Addr, IpAddr};
use std::time::Duration;

/// Fetch the URLhaus online-hosts plain-text feed.
///
/// The feed contains one domain/URL per line; lines starting with `#` are
/// comments.  We extract the hostname from each URL entry and return a
/// de-duplicated set of domains.
pub async fn fetch_urlhaus_domains() -> Result<HashSet<String>, String> {
    let url = "https://urlhaus.abuse.ch/downloads/text_online/";
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent("AtlasDNS/1.0 (threat-intel)")
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("URLhaus fetch failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("URLhaus returned HTTP {}", resp.status()));
    }

    let text = resp
        .text()
        .await
        .map_err(|e| format!("URLhaus body read error: {e}"))?;

    Ok(parse_urlhaus_text(&text))
}

/// Parse URLhaus plain-text feed body into a set of domains.
///
/// Each non-comment line is a full URL (e.g. `http://evil.com/malware.exe`).
/// We extract just the hostname portion and lowercase it.
pub fn parse_urlhaus_text(text: &str) -> HashSet<String> {
    let mut domains = HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Lines are full URLs — extract the hostname
        let host = extract_host_from_url(line);
        if !host.is_empty() && host.contains('.') && !is_ip_address(host) {
            domains.insert(host.to_lowercase());
        }
    }
    domains
}

/// Extract the hostname from a URL string (without pulling in the `url` crate).
fn extract_host_from_url(raw: &str) -> &str {
    let stripped = raw
        .strip_prefix("https://")
        .or_else(|| raw.strip_prefix("http://"))
        .unwrap_or(raw);

    // Take everything up to the first `/` or `:`
    let host = stripped.split('/').next().unwrap_or("");
    host.split(':').next().unwrap_or("")
}

/// Quick check whether a string looks like an IPv4 address.
fn is_ip_address(s: &str) -> bool {
    s.parse::<Ipv4Addr>().is_ok()
}

// ---------------------------------------------------------------------------
// Spamhaus DNSBL lookup
// ---------------------------------------------------------------------------

/// Check whether an IPv4 address is listed in the Spamhaus ZEN DNSBL.
///
/// The lookup follows the standard DNSBL convention: reverse the IP octets and
/// query `d.c.b.a.zen.spamhaus.org` for an A record.  A successful response
/// (any `127.0.0.x` address) means the IP is listed.
///
/// Returns `true` if the IP is listed, `false` otherwise (including on lookup
/// failure / timeout).
pub async fn check_spamhaus_dnsbl(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    let query = format!(
        "{}.{}.{}.{}.zen.spamhaus.org",
        octets[3], octets[2], octets[1], octets[0]
    );

    // Use a simple DNS UDP lookup to avoid pulling in a full resolver dep.
    // We build a minimal query and parse the response.
    match tokio::net::lookup_host(format!("{query}:0")).await {
        Ok(mut addrs) => {
            // Any 127.x.x.x answer means "listed"
            addrs.any(|addr| match addr.ip() {
                IpAddr::V4(v4) => v4.octets()[0] == 127,
                _ => false,
            })
        }
        Err(_) => false, // NXDOMAIN or timeout → not listed
    }
}

/// Return Spamhaus ZEN result codes for an IPv4 address.
///
/// The return codes (127.0.0.x) indicate which specific Spamhaus list
/// matched.  Returns an empty vec if the IP is not listed.
pub async fn spamhaus_dnsbl_codes(ip: Ipv4Addr) -> Vec<Ipv4Addr> {
    let octets = ip.octets();
    let query = format!(
        "{}.{}.{}.{}.zen.spamhaus.org",
        octets[3], octets[2], octets[1], octets[0]
    );

    match tokio::net::lookup_host(format!("{query}:0")).await {
        Ok(addrs) => addrs
            .filter_map(|addr| match addr.ip() {
                IpAddr::V4(v4) if v4.octets()[0] == 127 => Some(v4),
                _ => None,
            })
            .collect(),
        Err(_) => vec![],
    }
}

// ---------------------------------------------------------------------------
// Spamhaus DROP / EDROP (IP block lists)
// ---------------------------------------------------------------------------

/// Fetch and parse the Spamhaus DROP list (Don't Route Or Peer).
///
/// The DROP list contains CIDR blocks allocated to spammers or cyber-crime
/// operations.  Format: `CIDR ; SBLxxxxxx` (one entry per line, comments
/// start with `;`).
pub async fn fetch_spamhaus_drop() -> Result<Vec<String>, String> {
    fetch_and_parse_cidr_list(
        "https://www.spamhaus.org/drop/drop.txt",
        "Spamhaus DROP",
    ).await
}

/// Fetch and parse the Spamhaus EDROP list (Extended DROP).
pub async fn fetch_spamhaus_edrop() -> Result<Vec<String>, String> {
    fetch_and_parse_cidr_list(
        "https://www.spamhaus.org/drop/edrop.txt",
        "Spamhaus EDROP",
    ).await
}

/// Shared helper that fetches a Spamhaus-style CIDR text list.
async fn fetch_and_parse_cidr_list(url: &str, label: &str) -> Result<Vec<String>, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent("AtlasDNS/1.0 (threat-intel)")
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("{label} fetch failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("{label} returned HTTP {}", resp.status()));
    }

    let text = resp
        .text()
        .await
        .map_err(|e| format!("{label} body read error: {e}"))?;

    Ok(parse_spamhaus_drop_text(&text))
}

/// Parse Spamhaus DROP/EDROP text format into a list of CIDR strings.
///
/// Format: `network/prefix ; SBLref`
/// Lines starting with `;` are comments.
pub fn parse_spamhaus_drop_text(text: &str) -> Vec<String> {
    let mut cidrs = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        // Take everything before the first `;` or whitespace as the CIDR
        let cidr = line.split(';').next().unwrap_or("").trim();
        if cidr.contains('/') {
            cidrs.push(cidr.to_string());
        }
    }
    cidrs
}

// ---------------------------------------------------------------------------
// Feodo Tracker (abuse.ch) — JSON feed
// ---------------------------------------------------------------------------

/// Fetch and parse the Feodo Tracker botnet C2 IP list (JSON format).
///
/// Returns a set of IP addresses associated with active botnet command &
/// control servers.
pub async fn fetch_feodo_tracker_ips() -> Result<HashSet<String>, String> {
    let url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json";
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent("AtlasDNS/1.0 (threat-intel)")
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Feodo Tracker fetch failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("Feodo Tracker returned HTTP {}", resp.status()));
    }

    let text = resp
        .text()
        .await
        .map_err(|e| format!("Feodo Tracker body read error: {e}"))?;

    Ok(parse_feodo_tracker_json(&text))
}

/// Parse Feodo Tracker JSON into a set of IP strings.
///
/// The JSON is an array of objects, each with at least an `"ip_address"` field.
/// We also accept `"dst_ip"` as a fallback key.
pub fn parse_feodo_tracker_json(text: &str) -> HashSet<String> {
    let mut ips = HashSet::new();

    // Parse as JSON array
    if let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(text) {
        for entry in &entries {
            if let Some(ip) = entry.get("ip_address").and_then(|v| v.as_str()) {
                let ip = ip.trim();
                if !ip.is_empty() {
                    ips.insert(ip.to_string());
                }
            } else if let Some(ip) = entry.get("dst_ip").and_then(|v| v.as_str()) {
                let ip = ip.trim();
                if !ip.is_empty() {
                    ips.insert(ip.to_string());
                }
            }
        }
    } else {
        // Fallback: try line-by-line (plain text IP list)
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('{') || line.starts_with('[') {
                continue;
            }
            if line.parse::<Ipv4Addr>().is_ok() || line.parse::<std::net::Ipv6Addr>().is_ok() {
                ips.insert(line.to_string());
            }
        }
    }

    ips
}

// ---------------------------------------------------------------------------
// Aggregate feed fetcher with RPZ auto-population
// ---------------------------------------------------------------------------

/// Fetch all configured threat intelligence feeds and return domains and IPs
/// suitable for populating RPZ zones.
///
/// Returns `(domains, ip_cidrs, botnet_ips)` where:
/// - `domains` — malware-distributing domains from URLhaus
/// - `ip_cidrs` — CIDR blocks from Spamhaus DROP+EDROP
/// - `botnet_ips` — individual C2 IPs from Feodo Tracker
pub async fn fetch_all_feeds() -> ThreatFeedResults {
    let mut results = ThreatFeedResults::default();

    // URLhaus domains
    match fetch_urlhaus_domains().await {
        Ok(domains) => {
            log::info!("[THREAT-INTEL] URLhaus: {} domains fetched", domains.len());
            results.urlhaus_domains = domains;
        }
        Err(e) => {
            log::warn!("[THREAT-INTEL] URLhaus fetch failed: {}", e);
            results.errors.push(format!("URLhaus: {e}"));
        }
    }

    // Spamhaus DROP
    match fetch_spamhaus_drop().await {
        Ok(cidrs) => {
            log::info!("[THREAT-INTEL] Spamhaus DROP: {} CIDRs fetched", cidrs.len());
            results.spamhaus_drop_cidrs = cidrs;
        }
        Err(e) => {
            log::warn!("[THREAT-INTEL] Spamhaus DROP fetch failed: {}", e);
            results.errors.push(format!("Spamhaus DROP: {e}"));
        }
    }

    // Spamhaus EDROP
    match fetch_spamhaus_edrop().await {
        Ok(cidrs) => {
            log::info!("[THREAT-INTEL] Spamhaus EDROP: {} CIDRs fetched", cidrs.len());
            results.spamhaus_edrop_cidrs = cidrs;
        }
        Err(e) => {
            log::warn!("[THREAT-INTEL] Spamhaus EDROP fetch failed: {}", e);
            results.errors.push(format!("Spamhaus EDROP: {e}"));
        }
    }

    // Feodo Tracker
    match fetch_feodo_tracker_ips().await {
        Ok(ips) => {
            log::info!("[THREAT-INTEL] Feodo Tracker: {} IPs fetched", ips.len());
            results.feodo_ips = ips;
        }
        Err(e) => {
            log::warn!("[THREAT-INTEL] Feodo Tracker fetch failed: {}", e);
            results.errors.push(format!("Feodo Tracker: {e}"));
        }
    }

    results
}

/// Results from fetching all threat intelligence feeds.
#[derive(Debug, Default)]
pub struct ThreatFeedResults {
    pub urlhaus_domains: HashSet<String>,
    pub spamhaus_drop_cidrs: Vec<String>,
    pub spamhaus_edrop_cidrs: Vec<String>,
    pub feodo_ips: HashSet<String>,
    pub errors: Vec<String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_urlhaus_plain_text() {
        let text = r#"
# URLhaus online URLs (plain text)
# Last updated: 2024-01-01
#
http://evil.example.com/malware.exe
https://bad.example.org/payload
http://192.168.1.1/bad
# A comment line
http://another-bad.example.net:8080/path
"#;
        let domains = parse_urlhaus_text(text);
        assert!(domains.contains("evil.example.com"));
        assert!(domains.contains("bad.example.org"));
        assert!(domains.contains("another-bad.example.net"));
        // IP addresses should be excluded
        assert!(!domains.contains("192.168.1.1"));
        assert_eq!(domains.len(), 3);
    }

    #[test]
    fn extract_host_handles_edge_cases() {
        assert_eq!(extract_host_from_url("http://example.com/path"), "example.com");
        assert_eq!(extract_host_from_url("https://example.com:8080/p"), "example.com");
        assert_eq!(extract_host_from_url("example.com/stuff"), "example.com");
        assert_eq!(extract_host_from_url(""), "");
    }

    #[test]
    fn ip_detection() {
        assert!(is_ip_address("1.2.3.4"));
        assert!(is_ip_address("192.168.0.1"));
        assert!(!is_ip_address("example.com"));
        assert!(!is_ip_address("not-an-ip"));
    }

    #[test]
    fn parse_spamhaus_drop_format() {
        let text = r#"
; Spamhaus DROP List
; Last-Modified: Mon, 01 Jan 2024 00:00:00 GMT
;
1.10.16.0/20 ; SBL256263
5.34.242.0/23 ; SBL459530
27.126.160.0/20 ; SBL360890
"#;
        let cidrs = parse_spamhaus_drop_text(text);
        assert_eq!(cidrs.len(), 3);
        assert!(cidrs.contains(&"1.10.16.0/20".to_string()));
        assert!(cidrs.contains(&"5.34.242.0/23".to_string()));
        assert!(cidrs.contains(&"27.126.160.0/20".to_string()));
    }

    #[test]
    fn parse_feodo_json() {
        let json = r#"[
            {"ip_address": "1.2.3.4", "port": 443, "status": "online"},
            {"ip_address": "5.6.7.8", "port": 8080, "status": "online"},
            {"ip_address": "  9.10.11.12  ", "port": 443, "status": "offline"}
        ]"#;
        let ips = parse_feodo_tracker_json(json);
        assert_eq!(ips.len(), 3);
        assert!(ips.contains("1.2.3.4"));
        assert!(ips.contains("5.6.7.8"));
        assert!(ips.contains("9.10.11.12"));
    }

    #[test]
    fn parse_feodo_fallback_plaintext() {
        let text = "# Feodo IPs\n1.2.3.4\n5.6.7.8\n";
        let ips = parse_feodo_tracker_json(text);
        assert_eq!(ips.len(), 2);
        assert!(ips.contains("1.2.3.4"));
    }
}
