//! Standalone threat intelligence feed updater for AtlasDNS.
//!
//! Designed to run hourly via cron. Fetches threat feeds (abuse.ch, Spamhaus,
//! OpenPhish, Phishing Army), updates the local threat DB, and triggers a
//! cache flush via the HTTP API.
//!
//! Usage:
//!     atlasdns-feeder [--api-url http://localhost:8080] [--api-key KEY]
//!
//! Cron example (every hour):
//!     0 * * * * /usr/local/bin/atlasdns-feeder --api-url http://localhost:8080

use std::collections::HashMap;
use std::process;
use std::time::Instant;

use clap::Parser;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

/// AtlasDNS threat intelligence feed updater.
#[derive(Parser)]
#[command(name = "atlasdns-feeder", about = "Fetch threat feeds and update AtlasDNS")]
struct Args {
    /// AtlasDNS HTTP API base URL
    #[arg(long, default_value = "http://localhost:8080", env = "ATLAS_API_URL")]
    api_url: String,

    /// API key for authentication (optional if API is unauthenticated)
    #[arg(long, env = "ATLAS_API_KEY")]
    api_key: Option<String>,

    /// Flush the DNS cache after updating feeds
    #[arg(long, default_value_t = true)]
    flush_cache: bool,

    /// Timeout per feed fetch in seconds
    #[arg(long, default_value_t = 60)]
    timeout: u64,

    /// Dry run: fetch feeds but don't push to AtlasDNS
    #[arg(long)]
    dry_run: bool,
}

/// Feed definition: id, name, URL, and expected format.
struct FeedSource {
    id: &'static str,
    name: &'static str,
    url: &'static str,
    _category: &'static str,
}

const FEEDS: &[FeedSource] = &[
    FeedSource {
        id: "urlhaus",
        name: "abuse.ch URLhaus",
        url: "https://urlhaus.abuse.ch/downloads/hostfile/",
        _category: "malware_c2",
    },
    FeedSource {
        id: "threatfox",
        name: "abuse.ch ThreatFox IOC",
        url: "https://threatfox.abuse.ch/downloads/hostfile/",
        _category: "malware_c2",
    },
    FeedSource {
        id: "spamhaus_drop",
        name: "Spamhaus DROP",
        url: "https://www.spamhaus.org/drop/drop.txt",
        _category: "botnet",
    },
    FeedSource {
        id: "spamhaus_edrop",
        name: "Spamhaus EDROP",
        url: "https://www.spamhaus.org/drop/edrop.txt",
        _category: "botnet",
    },
    FeedSource {
        id: "openphish",
        name: "OpenPhish",
        url: "https://openphish.com/feed.txt",
        _category: "phishing",
    },
    FeedSource {
        id: "phishing_army",
        name: "Phishing Army",
        url: "https://phishing.army/download/phishing_army_blocklist.txt",
        _category: "phishing",
    },
];

#[derive(Serialize)]
struct RefreshRequest {
    feed_ids: Vec<String>,
}

#[derive(Deserialize)]
struct RefreshResponse {
    #[serde(default)]
    results: HashMap<String, FeedResult>,
}

#[derive(Deserialize)]
struct FeedResult {
    #[serde(default)]
    domains_loaded: usize,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct FlushResponse {
    #[serde(default)]
    flushed: usize,
}

fn main() {
    // Initialize logging to syslog/stderr
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .env()
        .init()
        .expect("Failed to initialize logger");

    let args = Args::parse();
    let start = Instant::now();

    log::info!("atlasdns-feeder starting (api={})", args.api_url);

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(args.timeout))
        .user_agent("atlasdns-feeder/1.0")
        .build()
        .unwrap_or_else(|e| {
            log::error!("Failed to create HTTP client: {}", e);
            process::exit(1);
        });

    // Step 1: Trigger feed refresh via AtlasDNS API
    let mut total_domains = 0usize;
    let mut errors = 0usize;

    if args.dry_run {
        log::info!("[DRY RUN] Would refresh {} feeds via API", FEEDS.len());
        for feed in FEEDS {
            log::info!("  - {} ({}): {}", feed.id, feed.name, feed.url);
        }
    } else {
        let refresh_url = format!("{}/api/threat-intel/refresh", args.api_url);
        let feed_ids: Vec<String> = FEEDS.iter().map(|f| f.id.to_string()).collect();

        let mut req = client.post(&refresh_url)
            .json(&RefreshRequest { feed_ids });

        if let Some(ref key) = args.api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }

        match req.send() {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<RefreshResponse>() {
                    Ok(data) => {
                        for (feed_id, result) in &data.results {
                            if let Some(ref err) = result.error {
                                log::warn!("Feed {} failed: {}", feed_id, err);
                                errors += 1;
                            } else {
                                log::info!("Feed {} loaded {} domains", feed_id, result.domains_loaded);
                                total_domains += result.domains_loaded;
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("Failed to parse refresh response: {}", e);
                        // Non-fatal: refresh may have succeeded server-side
                    }
                }
            }
            Ok(resp) => {
                log::error!("Feed refresh request failed: HTTP {}", resp.status());
                errors += 1;
            }
            Err(e) => {
                log::error!("Feed refresh request failed: {}", e);
                errors += 1;
            }
        }
    }

    // Step 2: Flush DNS cache
    if args.flush_cache && !args.dry_run {
        let flush_url = format!("{}/api/cache/flush", args.api_url);
        let mut req = client.post(&flush_url);
        if let Some(ref key) = args.api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }

        match req.send() {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<FlushResponse>() {
                    Ok(data) => log::info!("Cache flushed: {} entries removed", data.flushed),
                    Err(_) => log::info!("Cache flush completed"),
                }
            }
            Ok(resp) => log::warn!("Cache flush returned HTTP {}", resp.status()),
            Err(e) => log::warn!("Cache flush failed: {}", e),
        }
    }

    let elapsed = start.elapsed();
    log::info!(
        "atlasdns-feeder finished in {:.1}s: {} domains loaded, {} errors",
        elapsed.as_secs_f64(),
        total_domains,
        errors,
    );

    if errors > 0 {
        process::exit(1);
    }
}
