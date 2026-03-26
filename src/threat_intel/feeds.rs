//! Threat intelligence feed fetching and parsing.
//!
//! Supports:
//! - **abuse.ch URLhaus**: Plain-text domain list from `urlhaus.abuse.ch/downloads/text_online/`
//! - **Spamhaus DNSBL**: DNS-based blocklist lookup against `zen.spamhaus.org`

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
}
