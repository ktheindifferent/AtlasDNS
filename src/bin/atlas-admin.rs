//! Atlas DNS Admin CLI
//!
//! Lightweight admin interface for day-to-day AtlasDNS operations.
//! Connects to the server via its REST API (default: http://localhost:5380).
//!
//! # Usage
//!
//! ```text
//! atlas-admin status
//! atlas-admin blocklist add <url>
//! atlas-admin blocklist list
//! atlas-admin blocklist update
//! atlas-admin query-log [--limit N] [--client IP]
//! atlas-admin client <ip> allow
//! atlas-admin client <ip> block
//! ```

use clap::{Parser, Subcommand};
use colored::*;
use comfy_table::{Table, presets::UTF8_FULL};
use reqwest::blocking::Client;
use serde_json::Value;
use std::time::Duration;

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

/// Atlas DNS admin tool — connects to the server REST API.
#[derive(Parser)]
#[command(name = "atlas-admin")]
#[command(about = "AtlasDNS administration CLI", long_about = None)]
#[command(version)]
struct Cli {
    /// AtlasDNS base URL
    #[arg(short = 'H', long, env = "ATLAS_HOST", default_value = "http://localhost:5380")]
    host: String,

    /// API key (passed as X-Api-Key header)
    #[arg(short = 'k', long, env = "ATLAS_API_KEY")]
    api_key: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show server stats (queries/s, block rate, uptime)
    Status,

    /// Manage blocklists
    Blocklist {
        #[command(subcommand)]
        action: BlocklistCommands,
    },

    /// Tail the query log (most-recent entries first)
    QueryLog {
        /// Maximum number of entries to show
        #[arg(short, long, default_value = "50")]
        limit: usize,

        /// Filter by client IP
        #[arg(short, long)]
        client: Option<String>,

        /// Show only blocked queries
        #[arg(short, long)]
        blocked: bool,
    },

    /// Manage per-client policy
    Client {
        /// Client IP address
        ip: String,

        #[command(subcommand)]
        action: ClientAction,
    },
}

#[derive(Subcommand)]
enum BlocklistCommands {
    /// Add a blocklist by URL
    Add {
        /// URL of the blocklist (plain-text, one domain per line)
        url: String,
        /// Human-readable name
        #[arg(short, long, default_value = "")]
        name: String,
    },
    /// List active blocklists with domain counts
    List,
    /// Force-refresh all blocklists from their sources
    Update,
}

#[derive(Subcommand)]
enum ClientAction {
    /// Allow all queries from this client (bypass_all = true)
    Allow,
    /// Block all queries from this client (bypass_all = false)
    Block,
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

fn make_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("Failed to build HTTP client")
}

fn add_auth(
    req: reqwest::blocking::RequestBuilder,
    api_key: &Option<String>,
) -> reqwest::blocking::RequestBuilder {
    if let Some(key) = api_key {
        req.header("X-Api-Key", key)
    } else {
        req
    }
}

fn get_json(client: &Client, url: &str, api_key: &Option<String>) -> Result<Value, String> {
    let resp = add_auth(client.get(url), api_key)
        .send()
        .map_err(|e| format!("Request failed: {e}"))?;
    let status = resp.status();
    let body: Value = resp.json().map_err(|e| format!("Bad JSON: {e}"))?;
    if !status.is_success() {
        return Err(format!(
            "HTTP {}: {}",
            status,
            body["error"].as_str().unwrap_or("unknown error")
        ));
    }
    Ok(body)
}

fn post_json(
    client: &Client,
    url: &str,
    api_key: &Option<String>,
    body: &Value,
) -> Result<Value, String> {
    let resp = add_auth(client.post(url), api_key)
        .json(body)
        .send()
        .map_err(|e| format!("Request failed: {e}"))?;
    let status = resp.status();
    let resp_body: Value = resp.json().map_err(|e| format!("Bad JSON: {e}"))?;
    if !status.is_success() {
        return Err(format!(
            "HTTP {}: {}",
            status,
            resp_body["error"].as_str().unwrap_or("unknown error")
        ));
    }
    Ok(resp_body)
}

fn put_json(
    client: &Client,
    url: &str,
    api_key: &Option<String>,
    body: &Value,
) -> Result<Value, String> {
    let resp = add_auth(client.put(url), api_key)
        .json(body)
        .send()
        .map_err(|e| format!("Request failed: {e}"))?;
    let status = resp.status();
    let resp_body: Value = resp.json().map_err(|e| format!("Bad JSON: {e}"))?;
    if !status.is_success() {
        return Err(format!(
            "HTTP {}: {}",
            status,
            resp_body["error"].as_str().unwrap_or("unknown error")
        ));
    }
    Ok(resp_body)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_status(host: &str, api_key: &Option<String>) {
    let client = make_client();
    let url = format!("{host}/api/v2/stats/summary");

    match get_json(&client, &url, api_key) {
        Ok(body) => {
            let data = &body["data"];
            println!("{}", "AtlasDNS Server Status".bold().green());
            println!("{}", "─".repeat(40));

            let fields = [
                ("Uptime",          data["uptime_secs"].as_u64().map(format_uptime).unwrap_or_default()),
                ("Total queries",   data["total_queries"].as_u64().unwrap_or(0).to_string()),
                ("Blocked queries", data["blocked_queries"].as_u64().unwrap_or(0).to_string()),
                ("Block rate",      format!("{:.1}%",
                    data["block_rate_percent"].as_f64().unwrap_or(0.0))),
                ("Queries/s",       format!("{:.1}",
                    data["queries_per_second"].as_f64().unwrap_or(0.0))),
                ("Cache hits",      data["cache_hits"].as_u64().unwrap_or(0).to_string()),
                ("Cache misses",    data["cache_misses"].as_u64().unwrap_or(0).to_string()),
                ("Active clients",  data["active_clients"].as_u64().unwrap_or(0).to_string()),
            ];

            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["Metric", "Value"]);
            for (k, v) in &fields {
                table.add_row(vec![k.to_string(), v.clone()]);
            }
            println!("{table}");
        }
        Err(e) => eprintln!("{} {}", "Error:".red().bold(), e),
    }
}

fn format_uptime(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if d > 0 { format!("{d}d {h}h {m}m {s}s") }
    else if h > 0 { format!("{h}h {m}m {s}s") }
    else { format!("{m}m {s}s") }
}

fn cmd_blocklist_list(host: &str, api_key: &Option<String>) {
    let client = make_client();
    let url = format!("{host}/api/v2/blocklists");

    match get_json(&client, &url, api_key) {
        Ok(body) => {
            let lists = body["data"].as_array().cloned().unwrap_or_default();
            if lists.is_empty() {
                println!("{}", "No blocklists configured.".yellow());
                return;
            }
            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["ID", "Name", "URL", "Domains", "Last Updated"]);
            for entry in &lists {
                table.add_row(vec![
                    entry["id"].as_str().unwrap_or("-").to_string(),
                    entry["name"].as_str().unwrap_or("-").to_string(),
                    entry["url"].as_str().unwrap_or("-").to_string(),
                    entry["domain_count"].as_u64().unwrap_or(0).to_string(),
                    entry["last_updated"].as_str().unwrap_or("never").to_string(),
                ]);
            }
            println!("{table}");
            println!("Total: {} blocklist(s)", lists.len());
        }
        Err(e) => eprintln!("{} {}", "Error:".red().bold(), e),
    }
}

fn cmd_blocklist_add(host: &str, api_key: &Option<String>, url_arg: &str, name: &str) {
    let client = make_client();
    let api_url = format!("{host}/api/v2/blocklists");
    let name = if name.is_empty() { url_arg } else { name };
    let payload = serde_json::json!({ "url": url_arg, "name": name });

    match post_json(&client, &api_url, api_key, &payload) {
        Ok(body) => {
            let id = body["data"]["id"].as_str().unwrap_or("?");
            println!("{} Blocklist added (id: {})", "✓".green().bold(), id);
        }
        Err(e) => eprintln!("{} {}", "Error:".red().bold(), e),
    }
}

fn cmd_blocklist_update(host: &str, api_key: &Option<String>) {
    let client = make_client();

    // Fetch list of blocklists, then refresh each one.
    let list_url = format!("{host}/api/v2/blocklists");
    let lists = match get_json(&client, &list_url, api_key) {
        Ok(body) => body["data"].as_array().cloned().unwrap_or_default(),
        Err(e) => { eprintln!("{} {}", "Error:".red().bold(), e); return; }
    };

    if lists.is_empty() {
        println!("{}", "No blocklists to update.".yellow());
        return;
    }

    let mut ok = 0usize;
    let mut fail = 0usize;

    for entry in &lists {
        if let Some(id) = entry["id"].as_str() {
            let refresh_url = format!("{host}/api/v2/blocklists/{id}/refresh");
            match post_json(&client, &refresh_url, api_key, &serde_json::json!({})) {
                Ok(_) => {
                    println!("  {} Refreshed {}", "✓".green(), entry["name"].as_str().unwrap_or(id));
                    ok += 1;
                }
                Err(e) => {
                    println!("  {} Failed {}: {e}", "✗".red(), entry["name"].as_str().unwrap_or(id));
                    fail += 1;
                }
            }
        }
    }

    println!("\nDone: {} updated, {} failed", ok, fail);
}

fn cmd_query_log(
    host: &str,
    api_key: &Option<String>,
    limit: usize,
    client_filter: &Option<String>,
    blocked_only: bool,
) {
    let client = make_client();
    let mut url = format!("{host}/api/v2/query-log?limit={limit}");
    if let Some(ip) = client_filter {
        url.push_str(&format!("&client={ip}"));
    }
    if blocked_only {
        url.push_str("&blocked=true");
    }

    match get_json(&client, &url, api_key) {
        Ok(body) => {
            let entries = body["data"].as_array().cloned().unwrap_or_default();
            if entries.is_empty() {
                println!("{}", "No log entries found.".yellow());
                return;
            }
            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["Time", "Client", "Domain", "Type", "Blocked", "DNSSEC", "ms"]);
            for e in &entries {
                let ts = e["timestamp"].as_i64().unwrap_or(0);
                let time = chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
                    .map(|t| t.format("%H:%M:%S").to_string())
                    .unwrap_or_else(|| ts.to_string());
                let blocked = e["blocked"].as_bool().unwrap_or(false);
                let blocked_str = if blocked { "yes".red().to_string() } else { "no".green().to_string() };
                let dnssec = e["dnssec_status"].as_str().unwrap_or("-").to_string();
                table.add_row(vec![
                    time,
                    e["client_ip"].as_str().unwrap_or("-").to_string(),
                    e["domain"].as_str().unwrap_or("-").to_string(),
                    e["query_type"].as_str().unwrap_or("-").to_string(),
                    blocked_str,
                    dnssec,
                    e["response_ms"].as_i64().unwrap_or(0).to_string(),
                ]);
            }
            println!("{table}");
            println!("Showing {} of {} entries", entries.len(), body["meta"]["count"].as_u64().unwrap_or(0));
        }
        Err(e) => eprintln!("{} {}", "Error:".red().bold(), e),
    }
}

fn cmd_client_policy(host: &str, api_key: &Option<String>, ip: &str, allow: bool) {
    let client = make_client();
    let url = format!("{host}/api/v2/clients/{ip}/policy");
    let payload = serde_json::json!({ "bypass_all": allow });

    match put_json(&client, &url, api_key, &payload) {
        Ok(_) => {
            let action = if allow { "allowed (bypass_all = true)" } else { "blocked (bypass_all = false)" };
            println!("{} Client {} {}", "✓".green().bold(), ip, action);
        }
        Err(e) => eprintln!("{} {}", "Error:".red().bold(), e),
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Status => {
            cmd_status(&cli.host, &cli.api_key);
        }

        Commands::Blocklist { action } => match action {
            BlocklistCommands::List => {
                cmd_blocklist_list(&cli.host, &cli.api_key);
            }
            BlocklistCommands::Add { url, name } => {
                cmd_blocklist_add(&cli.host, &cli.api_key, url, name);
            }
            BlocklistCommands::Update => {
                cmd_blocklist_update(&cli.host, &cli.api_key);
            }
        },

        Commands::QueryLog { limit, client, blocked } => {
            cmd_query_log(&cli.host, &cli.api_key, *limit, client, *blocked);
        }

        Commands::Client { ip, action } => {
            let allow = matches!(action, ClientAction::Allow);
            cmd_client_policy(&cli.host, &cli.api_key, ip, allow);
        }
    }
}
