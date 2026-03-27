//! AtlasDNS Health-Check CLI
//!
//! Connects to a running AtlasDNS instance, queries a test domain,
//! verifies the response, checks the metrics/health endpoint, and
//! exits 0 (pass) or 1 (fail).
//!
//! Usage:
//!   atlasdns-check [OPTIONS]
//!
//! Options:
//!   --dns-host <IP>      DNS server address   (default: 127.0.0.1)
//!   --dns-port <PORT>    DNS server port       (default: 53)
//!   --web-host <URL>     Web API base URL      (default: http://127.0.0.1:5380)
//!   --domain <DOMAIN>    Domain to query        (default: health.check.local)
//!   --query-type <TYPE>  Query type             (default: A)
//!   --timeout <MS>       Timeout in ms          (default: 5000)

use std::net::UdpSocket;
use std::process;
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let dns_host = get_arg(&args, "--dns-host").unwrap_or_else(|| "127.0.0.1".to_string());
    let dns_port: u16 = get_arg(&args, "--dns-port")
        .and_then(|s| s.parse().ok())
        .unwrap_or(53);
    let web_host = get_arg(&args, "--web-host")
        .unwrap_or_else(|| "http://127.0.0.1:5380".to_string());
    let domain = get_arg(&args, "--domain").unwrap_or_else(|| "health.check.local".to_string());
    let timeout_ms: u64 = get_arg(&args, "--timeout")
        .and_then(|s| s.parse().ok())
        .unwrap_or(5000);

    let timeout = Duration::from_millis(timeout_ms);
    let mut passed = 0u32;
    let mut failed = 0u32;

    // ── Check 1: DNS query ──────────────────────────────────────────
    eprint!("[1/3] DNS query to {}:{} for {} ... ", dns_host, dns_port, domain);
    match dns_query(&dns_host, dns_port, &domain, timeout) {
        Ok(latency) => {
            eprintln!("OK ({:.1}ms)", latency.as_secs_f64() * 1000.0);
            passed += 1;
        }
        Err(e) => {
            eprintln!("FAIL: {}", e);
            failed += 1;
        }
    }

    // ── Check 2: Web API health / dashboard ─────────────────────────
    eprint!("[2/3] Web API at {} ... ", web_host);
    match web_health_check(&web_host, timeout) {
        Ok(status) => {
            eprintln!("OK (HTTP {})", status);
            passed += 1;
        }
        Err(e) => {
            eprintln!("FAIL: {}", e);
            failed += 1;
        }
    }

    // ── Check 3: Metrics endpoint ───────────────────────────────────
    let metrics_url = format!("{}/api/v2/metrics", web_host);
    eprint!("[3/3] Metrics endpoint at {} ... ", metrics_url);
    match metrics_check(&metrics_url, timeout) {
        Ok(()) => {
            eprintln!("OK");
            passed += 1;
        }
        Err(e) => {
            eprintln!("FAIL: {}", e);
            failed += 1;
        }
    }

    // ── Summary ─────────────────────────────────────────────────────
    eprintln!();
    eprintln!("Results: {} passed, {} failed", passed, failed);

    if failed > 0 {
        process::exit(1);
    }
}

/// Build a minimal DNS query packet for an A record and send it over UDP.
/// Returns the round-trip latency on success.
fn dns_query(host: &str, port: u16, domain: &str, timeout: Duration) -> Result<Duration, String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind: {}", e))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("set_read_timeout: {}", e))?;

    let packet = build_dns_query(domain);
    let addr = format!("{}:{}", host, port);

    let start = Instant::now();
    socket
        .send_to(&packet, &addr)
        .map_err(|e| format!("send: {}", e))?;

    let mut buf = [0u8; 512];
    let (len, _) = socket
        .recv_from(&mut buf)
        .map_err(|e| format!("recv: {}", e))?;
    let latency = start.elapsed();

    if len < 12 {
        return Err("response too short".into());
    }

    // Check QR bit (response) and RCODE
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qr = (flags >> 15) & 1;
    let rcode = flags & 0x0F;

    if qr != 1 {
        return Err("not a response".into());
    }

    // RCODE 0 (NOERROR) or 3 (NXDOMAIN) are both acceptable for a health check
    if rcode != 0 && rcode != 3 {
        return Err(format!("unexpected RCODE: {}", rcode));
    }

    Ok(latency)
}

/// Build a minimal DNS A-record query packet.
fn build_dns_query(domain: &str) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);

    // Header: ID=0xABCD, flags=0x0100 (RD=1), QDCOUNT=1
    pkt.extend_from_slice(&[0xAB, 0xCD]); // ID
    pkt.extend_from_slice(&[0x01, 0x00]); // Flags: standard query, RD
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    // Question: encode domain name
    for label in domain.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // root label

    pkt.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
    pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

    pkt
}

/// Check the web API returns a 200 on the root or /api/health endpoint.
fn web_health_check(base_url: &str, timeout: Duration) -> Result<u16, String> {
    let url = format!("{}/api/health", base_url);
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| format!("client build: {}", e))?;

    let resp = client.get(&url).send();
    match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            if status >= 200 && status < 400 {
                Ok(status)
            } else {
                Err(format!("HTTP {}", status))
            }
        }
        Err(e) => {
            // Fall back to root URL
            let resp2 = client
                .get(base_url)
                .send()
                .map_err(|_| format!("health endpoint unreachable: {}", e))?;
            let status = resp2.status().as_u16();
            if status >= 200 && status < 400 {
                Ok(status)
            } else {
                Err(format!("HTTP {}", status))
            }
        }
    }
}

/// Check the metrics endpoint returns valid data.
fn metrics_check(url: &str, timeout: Duration) -> Result<(), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| format!("client build: {}", e))?;

    let resp = client.get(url).send().map_err(|e| format!("{}", e))?;

    let status = resp.status().as_u16();
    if status < 200 || status >= 400 {
        return Err(format!("HTTP {}", status));
    }

    let body = resp.text().map_err(|e| format!("read body: {}", e))?;
    if body.is_empty() {
        return Err("empty response".into());
    }

    // Verify it's valid JSON or Prometheus text format
    if body.starts_with('{') {
        serde_json::from_str::<serde_json::Value>(&body)
            .map_err(|e| format!("invalid JSON: {}", e))?;
    }

    Ok(())
}

/// Simple argument parser: returns the value after `--flag`.
fn get_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}
