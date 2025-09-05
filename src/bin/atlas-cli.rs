//! Atlas DNS CLI Tool
//!
//! Complete command-line management interface for Atlas DNS with auto-completion,
//! interactive mode, and comprehensive DNS operations support.

use clap::{Parser, Subcommand, Args, ValueEnum};
use colored::*;
use comfy_table::Table;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest;
use serde_json::{json, Value};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;
use tokio;

/// Atlas DNS CLI - Manage your DNS infrastructure from the command line
#[derive(Parser)]
#[command(name = "atlas")]
#[command(author = "Atlas DNS Team")]
#[command(version = "1.0.0")]
#[command(about = "Atlas DNS Command Line Interface", long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Atlas DNS server endpoint
    #[arg(short = 'H', long, env = "ATLAS_HOST", default_value = "http://localhost:5380")]
    host: String,

    /// API key for authentication
    #[arg(short = 'k', long, env = "ATLAS_API_KEY")]
    api_key: Option<String>,

    /// Output format
    #[arg(short = 'o', long, value_enum, default_value = "table")]
    output: OutputFormat,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// No color output
    #[arg(long)]
    no_color: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(ValueEnum, Clone)]
enum OutputFormat {
    Table,
    Json,
    Yaml,
    Csv,
    Plain,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage DNS zones
    Zone {
        #[command(subcommand)]
        action: ZoneCommands,
    },
    
    /// Manage DNS records
    Record {
        #[command(subcommand)]
        action: RecordCommands,
    },
    
    /// Query DNS records
    Query(QueryArgs),
    
    /// Manage health checks
    Health {
        #[command(subcommand)]
        action: HealthCommands,
    },
    
    /// Manage traffic policies
    Traffic {
        #[command(subcommand)]
        action: TrafficCommands,
    },
    
    /// View system status
    Status,
    
    /// View statistics
    Stats(StatsArgs),
    
    /// Manage configuration
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },
    
    /// Import/Export operations
    Transfer {
        #[command(subcommand)]
        action: TransferCommands,
    },
    
    /// Interactive shell
    Shell,
    
    /// Generate shell completions
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Subcommand)]
enum ZoneCommands {
    /// List all zones
    List {
        /// Filter by name pattern
        #[arg(short, long)]
        filter: Option<String>,
        
        /// Show only enabled zones
        #[arg(long)]
        enabled_only: bool,
    },
    
    /// Get zone details
    Get {
        /// Zone name
        zone: String,
        
        /// Include all records
        #[arg(long)]
        with_records: bool,
    },
    
    /// Create a new zone
    Create {
        /// Zone name
        zone: String,
        
        /// Zone type
        #[arg(short = 't', long, default_value = "primary")]
        zone_type: String,
        
        /// Name servers (comma-separated)
        #[arg(short = 'n', long)]
        nameservers: Option<String>,
        
        /// Enable DNSSEC
        #[arg(long)]
        dnssec: bool,
        
        /// Zone template to use
        #[arg(long)]
        template: Option<String>,
    },
    
    /// Update zone
    Update {
        /// Zone name
        zone: String,
        
        /// Enable/disable zone
        #[arg(long)]
        enabled: Option<bool>,
        
        /// Update TTL
        #[arg(long)]
        ttl: Option<u32>,
    },
    
    /// Delete zone
    Delete {
        /// Zone name
        zone: String,
        
        /// Force deletion without confirmation
        #[arg(short, long)]
        force: bool,
    },
    
    /// Validate zone
    Validate {
        /// Zone name
        zone: String,
    },
    
    /// Clone zone
    Clone {
        /// Source zone
        source: String,
        
        /// Target zone
        target: String,
        
        /// Include records
        #[arg(long, default_value = "true")]
        with_records: bool,
    },
}

#[derive(Subcommand)]
enum RecordCommands {
    /// List records in a zone
    List {
        /// Zone name
        zone: String,
        
        /// Filter by record type
        #[arg(short = 't', long)]
        record_type: Option<String>,
        
        /// Filter by name pattern
        #[arg(short = 'n', long)]
        name: Option<String>,
    },
    
    /// Get record details
    Get {
        /// Zone name
        zone: String,
        
        /// Record name
        name: String,
        
        /// Record type
        #[arg(short = 't', long)]
        record_type: String,
    },
    
    /// Create a new record
    Create {
        /// Zone name
        zone: String,
        
        /// Record name
        name: String,
        
        /// Record type
        #[arg(short = 't', long)]
        record_type: String,
        
        /// Record value
        value: String,
        
        /// TTL
        #[arg(long, default_value = "3600")]
        ttl: u32,
        
        /// Priority (for MX records)
        #[arg(short = 'p', long)]
        priority: Option<u16>,
    },
    
    /// Update record
    Update {
        /// Zone name
        zone: String,
        
        /// Record name
        name: String,
        
        /// Record type
        #[arg(short = 't', long)]
        record_type: String,
        
        /// New value
        #[arg(long)]
        value: Option<String>,
        
        /// New TTL
        #[arg(long)]
        ttl: Option<u32>,
    },
    
    /// Delete record
    Delete {
        /// Zone name
        zone: String,
        
        /// Record name
        name: String,
        
        /// Record type
        #[arg(short = 't', long)]
        record_type: String,
        
        /// Force deletion
        #[arg(short, long)]
        force: bool,
    },
    
    /// Bulk operations
    Bulk {
        /// Operation file (JSON/CSV)
        file: PathBuf,
        
        /// Dry run
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Args)]
struct QueryArgs {
    /// Domain name to query
    domain: String,
    
    /// Query type
    #[arg(short = 't', long, default_value = "A")]
    query_type: String,
    
    /// Use specific nameserver
    #[arg(short = 's', long)]
    server: Option<String>,
    
    /// Enable DNSSEC validation
    #[arg(long)]
    dnssec: bool,
    
    /// Show trace
    #[arg(long)]
    trace: bool,
}

#[derive(Subcommand)]
enum HealthCommands {
    /// List health checks
    List {
        /// Filter by status
        #[arg(short, long)]
        status: Option<String>,
    },
    
    /// Get health check details
    Get {
        /// Health check ID
        id: String,
    },
    
    /// Create health check
    Create {
        /// Name
        name: String,
        
        /// Target
        target: String,
        
        /// Check type
        #[arg(short = 't', long, default_value = "http")]
        check_type: String,
        
        /// Interval (seconds)
        #[arg(short = 'i', long, default_value = "30")]
        interval: u32,
    },
    
    /// Delete health check
    Delete {
        /// Health check ID
        id: String,
    },
    
    /// Test health check
    Test {
        /// Health check ID
        id: String,
    },
}

#[derive(Subcommand)]
enum TrafficCommands {
    /// List traffic policies
    List,
    
    /// Get traffic policy
    Get {
        /// Policy ID
        id: String,
    },
    
    /// Create traffic policy
    Create {
        /// Policy name
        name: String,
        
        /// Policy type
        #[arg(short = 't', long)]
        policy_type: String,
        
        /// Configuration file
        #[arg(short = 'f', long)]
        config_file: Option<PathBuf>,
    },
    
    /// Update traffic policy
    Update {
        /// Policy ID
        id: String,
        
        /// New configuration file
        #[arg(short = 'f', long)]
        config_file: PathBuf,
    },
    
    /// Delete traffic policy
    Delete {
        /// Policy ID
        id: String,
    },
    
    /// Simulate traffic policy
    Simulate {
        /// Policy ID
        id: String,
        
        /// Number of requests
        #[arg(short = 'n', long, default_value = "100")]
        requests: u32,
    },
}

#[derive(Args)]
struct StatsArgs {
    /// Time range (1h, 24h, 7d, 30d)
    #[arg(short = 'r', long, default_value = "24h")]
    range: String,
    
    /// Group by (zone, type, response_code)
    #[arg(short = 'g', long)]
    group_by: Option<String>,
    
    /// Show top N
    #[arg(short = 'n', long, default_value = "10")]
    top: usize,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Get configuration
    Get {
        /// Configuration key
        key: Option<String>,
    },
    
    /// Set configuration
    Set {
        /// Configuration key
        key: String,
        
        /// Configuration value
        value: String,
    },
    
    /// Reload configuration
    Reload,
    
    /// Validate configuration
    Validate {
        /// Configuration file
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum TransferCommands {
    /// Import zones/records
    Import {
        /// Import file
        file: PathBuf,
        
        /// Format (bind, json, csv)
        #[arg(short = 'f', long)]
        format: Option<String>,
        
        /// Dry run
        #[arg(long)]
        dry_run: bool,
    },
    
    /// Export zones/records
    Export {
        /// Output file
        file: PathBuf,
        
        /// Format (bind, json, csv)
        #[arg(short = 'f', long)]
        format: Option<String>,
        
        /// Zone to export (all if not specified)
        #[arg(short = 'z', long)]
        zone: Option<String>,
    },
    
    /// Sync with external provider
    Sync {
        /// Provider (route53, cloudflare, google)
        provider: String,
        
        /// Direction (push, pull, both)
        #[arg(short = 'd', long, default_value = "both")]
        direction: String,
        
        /// Dry run
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(ValueEnum, Clone, Debug)]
enum Shell {
    Bash,
    Zsh,
    Fish,
    PowerShell,
    Elvish,
}

/// API client for Atlas DNS
struct AtlasClient {
    base_url: String,
    api_key: Option<String>,
    client: reqwest::Client,
}

impl AtlasClient {
    fn new(base_url: String, api_key: Option<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        
        Self {
            base_url,
            api_key,
            client,
        }
    }

    async fn get(&self, path: &str) -> Result<Value, Box<dyn std::error::Error>> {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self.client.get(&url);
        
        if let Some(api_key) = &self.api_key {
            request = request.header("X-API-Key", api_key);
        }
        
        let response = request.send().await?;
        let json = response.json().await?;
        Ok(json)
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value, Box<dyn std::error::Error>> {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self.client.post(&url).json(&body);
        
        if let Some(api_key) = &self.api_key {
            request = request.header("X-API-Key", api_key);
        }
        
        let response = request.send().await?;
        let json = response.json().await?;
        Ok(json)
    }

    async fn put(&self, path: &str, body: Value) -> Result<Value, Box<dyn std::error::Error>> {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self.client.put(&url).json(&body);
        
        if let Some(api_key) = &self.api_key {
            request = request.header("X-API-Key", api_key);
        }
        
        let response = request.send().await?;
        let json = response.json().await?;
        Ok(json)
    }

    async fn delete(&self, path: &str) -> Result<Value, Box<dyn std::error::Error>> {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self.client.delete(&url);
        
        if let Some(api_key) = &self.api_key {
            request = request.header("X-API-Key", api_key);
        }
        
        let response = request.send().await?;
        if response.status().is_success() {
            Ok(json!({"success": true}))
        } else {
            Ok(json!({"success": false, "error": response.text().await?}))
        }
    }
}

/// Output formatter
struct OutputFormatter {
    format: OutputFormat,
    no_color: bool,
}

impl OutputFormatter {
    fn new(format: OutputFormat, no_color: bool) -> Self {
        if no_color {
            colored::control::set_override(false);
        }
        Self { format, no_color }
    }

    fn print(&self, data: &Value) {
        match self.format {
            OutputFormat::Json => {
                println!("{}", serde_json::to_string_pretty(data).unwrap());
            }
            OutputFormat::Yaml => {
                println!("{}", serde_yaml::to_string(data).unwrap());
            }
            OutputFormat::Table => {
                self.print_table(data);
            }
            OutputFormat::Csv => {
                self.print_csv(data);
            }
            OutputFormat::Plain => {
                self.print_plain(data);
            }
        }
    }

    fn print_table(&self, data: &Value) {
        let mut table = Table::new();
        
        if let Some(array) = data.as_array() {
            if !array.is_empty() {
                // Get headers from first object
                if let Some(first) = array[0].as_object() {
                    let headers: Vec<String> = first.keys().cloned().collect();
                    table.set_header(&headers);
                    
                    // Add rows
                    for item in array {
                        if let Some(obj) = item.as_object() {
                            let row: Vec<String> = headers.iter()
                                .map(|h| obj.get(h)
                                    .map(|v| self.value_to_string(v))
                                    .unwrap_or_default())
                                .collect();
                            table.add_row(row);
                        }
                    }
                }
            }
        } else if let Some(obj) = data.as_object() {
            table.set_header(vec!["Key", "Value"]);
            for (key, value) in obj {
                table.add_row(vec![key.clone(), self.value_to_string(value)]);
            }
        }
        
        println!("{}", table);
    }

    fn print_csv(&self, data: &Value) {
        if let Some(array) = data.as_array() {
            if !array.is_empty() {
                if let Some(first) = array[0].as_object() {
                    // Print headers
                    let headers: Vec<String> = first.keys().cloned().collect();
                    println!("{}", headers.join(","));
                    
                    // Print rows
                    for item in array {
                        if let Some(obj) = item.as_object() {
                            let row: Vec<String> = headers.iter()
                                .map(|h| obj.get(h)
                                    .map(|v| self.value_to_string(v))
                                    .unwrap_or_default())
                                .collect();
                            println!("{}", row.join(","));
                        }
                    }
                }
            }
        }
    }

    fn print_plain(&self, data: &Value) {
        println!("{}", self.value_to_string(data));
    }

    fn value_to_string(&self, value: &Value) -> String {
        match value {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Null => "null".to_string(),
            _ => value.to_string(),
        }
    }

    fn print_success(&self, message: &str) {
        println!("{} {}", "✓".green().bold(), message);
    }

    fn print_error(&self, message: &str) {
        eprintln!("{} {}", "✗".red().bold(), message);
    }

    fn print_warning(&self, message: &str) {
        println!("{} {}", "⚠".yellow().bold(), message);
    }

    fn print_info(&self, message: &str) {
        println!("{} {}", "ℹ".blue().bold(), message);
    }
}

/// Progress indicator
fn show_progress(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(Duration::from_millis(100));
    pb
}

/// Confirmation prompt
fn confirm(message: &str) -> bool {
    print!("{} {} [y/N]: ", "?".yellow().bold(), message);
    io::stdout().flush().unwrap();
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    let client = AtlasClient::new(cli.host.clone(), cli.api_key.clone());
    let formatter = OutputFormatter::new(cli.output.clone(), cli.no_color);
    
    match cli.command {
        Commands::Zone { action } => handle_zone_commands(action, &client, &formatter).await?,
        Commands::Record { action } => handle_record_commands(action, &client, &formatter).await?,
        Commands::Query(args) => handle_query(args, &client, &formatter).await?,
        Commands::Health { action } => handle_health_commands(action, &client, &formatter).await?,
        Commands::Traffic { action } => handle_traffic_commands(action, &client, &formatter).await?,
        Commands::Status => handle_status(&client, &formatter).await?,
        Commands::Stats(args) => handle_stats(args, &client, &formatter).await?,
        Commands::Config { action } => handle_config_commands(action, &client, &formatter).await?,
        Commands::Transfer { action } => handle_transfer_commands(action, &client, &formatter).await?,
        Commands::Shell => handle_interactive_shell(&client, &formatter).await?,
        Commands::Completions { shell } => generate_completions(shell),
    }
    
    Ok(())
}

async fn handle_zone_commands(
    action: ZoneCommands,
    client: &AtlasClient,
    formatter: &OutputFormatter,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        ZoneCommands::List { filter, enabled_only } => {
            let pb = show_progress("Fetching zones...");
            let mut path = "/api/v2/zones".to_string();
            if let Some(f) = filter {
                path.push_str(&format!("?filter={}", f));
            }
            let zones = client.get(&path).await?;
            pb.finish_and_clear();
            formatter.print(&zones);
        }
        ZoneCommands::Get { zone, with_records } => {
            let pb = show_progress(&format!("Fetching zone {}...", zone));
            let path = format!("/api/v2/zones/{}", zone);
            let zone_data = client.get(&path).await?;
            pb.finish_and_clear();
            formatter.print(&zone_data);
        }
        ZoneCommands::Create { zone, zone_type, nameservers, dnssec, template } => {
            let pb = show_progress(&format!("Creating zone {}...", zone));
            let body = json!({
                "name": zone,
                "type": zone_type,
                "nameservers": nameservers,
                "dnssec": dnssec,
                "template": template
            });
            let result = client.post("/api/v2/zones", body).await?;
            pb.finish_and_clear();
            formatter.print_success(&format!("Zone {} created successfully", zone));
            formatter.print(&result);
        }
        ZoneCommands::Update { zone, enabled, ttl } => {
            let pb = show_progress(&format!("Updating zone {}...", zone));
            let mut body = json!({});
            if let Some(e) = enabled {
                body["enabled"] = json!(e);
            }
            if let Some(t) = ttl {
                body["ttl"] = json!(t);
            }
            let path = format!("/api/v2/zones/{}", zone);
            let result = client.put(&path, body).await?;
            pb.finish_and_clear();
            formatter.print_success(&format!("Zone {} updated successfully", zone));
            formatter.print(&result);
        }
        ZoneCommands::Delete { zone, force } => {
            if !force && !confirm(&format!("Delete zone {}?", zone)) {
                formatter.print_warning("Deletion cancelled");
                return Ok(());
            }
            let pb = show_progress(&format!("Deleting zone {}...", zone));
            let path = format!("/api/v2/zones/{}", zone);
            client.delete(&path).await?;
            pb.finish_and_clear();
            formatter.print_success(&format!("Zone {} deleted successfully", zone));
        }
        ZoneCommands::Validate { zone } => {
            let pb = show_progress(&format!("Validating zone {}...", zone));
            let path = format!("/api/v2/zones/{}/validate", zone);
            let result = client.get(&path).await?;
            pb.finish_and_clear();
            formatter.print(&result);
        }
        ZoneCommands::Clone { source, target, with_records } => {
            let pb = show_progress(&format!("Cloning zone {} to {}...", source, target));
            let body = json!({
                "source": source,
                "target": target,
                "with_records": with_records
            });
            let result = client.post("/api/v2/zones/clone", body).await?;
            pb.finish_and_clear();
            formatter.print_success(&format!("Zone cloned successfully"));
            formatter.print(&result);
        }
    }
    Ok(())
}

async fn handle_record_commands(
    action: RecordCommands,
    client: &AtlasClient,
    formatter: &OutputFormatter,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        RecordCommands::List { zone, record_type, name } => {
            let pb = show_progress(&format!("Fetching records for zone {}...", zone));
            let mut path = format!("/api/v2/zones/{}/records", zone);
            let mut params = vec![];
            if let Some(t) = record_type {
                params.push(format!("type={}", t));
            }
            if let Some(n) = name {
                params.push(format!("name={}", n));
            }
            if !params.is_empty() {
                path.push_str(&format!("?{}", params.join("&")));
            }
            let records = client.get(&path).await?;
            pb.finish_and_clear();
            formatter.print(&records);
        }
        RecordCommands::Get { zone, name, record_type } => {
            let pb = show_progress(&format!("Fetching record {}...", name));
            let path = format!("/api/v2/zones/{}/records/{}/{}", zone, name, record_type);
            let record = client.get(&path).await?;
            pb.finish_and_clear();
            formatter.print(&record);
        }
        RecordCommands::Create { zone, name, record_type, value, ttl, priority } => {
            let pb = show_progress(&format!("Creating record {}...", name));
            let mut body = json!({
                "name": name,
                "type": record_type,
                "value": value,
                "ttl": ttl
            });
            if let Some(p) = priority {
                body["priority"] = json!(p);
            }
            let path = format!("/api/v2/zones/{}/records", zone);
            let result = client.post(&path, body).await?;
            pb.finish_and_clear();
            formatter.print_success(&format!("Record created successfully"));
            formatter.print(&result);
        }
        RecordCommands::Update { zone, name, record_type, value, ttl } => {
            let pb = show_progress(&format!("Updating record {}...", name));
            let mut body = json!({});
            if let Some(v) = value {
                body["value"] = json!(v);
            }
            if let Some(t) = ttl {
                body["ttl"] = json!(t);
            }
            let path = format!("/api/v2/zones/{}/records/{}/{}", zone, name, record_type);
            let result = client.put(&path, body).await?;
            pb.finish_and_clear();
            formatter.print_success(&format!("Record updated successfully"));
            formatter.print(&result);
        }
        RecordCommands::Delete { zone, name, record_type, force } => {
            if !force && !confirm(&format!("Delete record {} {} in zone {}?", name, record_type, zone)) {
                formatter.print_warning("Deletion cancelled");
                return Ok(());
            }
            let pb = show_progress(&format!("Deleting record {}...", name));
            let path = format!("/api/v2/zones/{}/records/{}/{}", zone, name, record_type);
            client.delete(&path).await?;
            pb.finish_and_clear();
            formatter.print_success(&format!("Record deleted successfully"));
        }
        RecordCommands::Bulk { file, dry_run } => {
            let pb = show_progress("Processing bulk operations...");
            let content = fs::read_to_string(file)?;
            let body = json!({
                "operations": serde_json::from_str::<Value>(&content)?,
                "dry_run": dry_run
            });
            let result = client.post("/api/v2/bulk", body).await?;
            pb.finish_and_clear();
            formatter.print(&result);
        }
    }
    Ok(())
}

async fn handle_query(
    args: QueryArgs,
    client: &AtlasClient,
    formatter: &OutputFormatter,
) -> Result<(), Box<dyn std::error::Error>> {
    let pb = show_progress(&format!("Querying {} {}...", args.domain, args.query_type));
    let body = json!({
        "domain": args.domain,
        "type": args.query_type,
        "server": args.server,
        "dnssec": args.dnssec,
        "trace": args.trace
    });
    let result = client.post("/api/v2/query", body).await?;
    pb.finish_and_clear();
    formatter.print(&result);
    Ok(())
}

async fn handle_health_commands(
    action: HealthCommands,
    client: &AtlasClient,
    formatter: &OutputFormatter,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        HealthCommands::List { status } => {
            let pb = show_progress("Fetching health checks...");
            let mut path = "/api/v2/health-checks".to_string();
            if let Some(s) = status {
                path.push_str(&format!("?status={}", s));
            }
            let checks = client.get(&path).await?;
            pb.finish_and_clear();
            formatter.print(&checks);
        }
        HealthCommands::Get { id } => {
            let pb = show_progress(&format!("Fetching health check {}...", id));
            let path = format!("/api/v2/health-checks/{}", id);
            let check = client.get(&path).await?;
            pb.finish_and_clear();
            formatter.print(&check);
        }
        HealthCommands::Create { name, target, check_type, interval } => {
            let pb = show_progress("Creating health check...");
            let body = json!({
                "name": name,
                "target": target,
                "type": check_type,
                "interval": interval
            });
            let result = client.post("/api/v2/health-checks", body).await?;
            pb.finish_and_clear();
            formatter.print_success("Health check created successfully");
            formatter.print(&result);
        }
        HealthCommands::Delete { id } => {
            let pb = show_progress(&format!("Deleting health check {}...", id));
            let path = format!("/api/v2/health-checks/{}", id);
            client.delete(&path).await?;
            pb.finish_and_clear();
            formatter.print_success("Health check deleted successfully");
        }
        HealthCommands::Test { id } => {
            let pb = show_progress(&format!("Testing health check {}...", id));
            let path = format!("/api/v2/health-checks/{}/test", id);
            let result = client.post(&path, json!({})).await?;
            pb.finish_and_clear();
            formatter.print(&result);
        }
    }
    Ok(())
}

async fn handle_traffic_commands(
    action: TrafficCommands,
    client: &AtlasClient,
    formatter: &OutputFormatter,
) -> Result<(), Box<dyn std::error::Error>> {
    // Implementation for traffic commands
    formatter.print_info("Traffic commands implementation");
    Ok(())
}

async fn handle_status(
    client: &AtlasClient,
    formatter: &OutputFormatter,
) -> Result<(), Box<dyn std::error::Error>> {
    let pb = show_progress("Fetching system status...");
    let status = client.get("/api/v2/status").await?;
    pb.finish_and_clear();
    formatter.print(&status);
    Ok(())
}

async fn handle_stats(
    args: StatsArgs,
    client: &AtlasClient,
    formatter: &OutputFormatter,
) -> Result<(), Box<dyn std::error::Error>> {
    let pb = show_progress("Fetching statistics...");
    let mut path = format!("/api/v2/stats?range={}&top={}", args.range, args.top);
    if let Some(g) = args.group_by {
        path.push_str(&format!("&group_by={}", g));
    }
    let stats = client.get(&path).await?;
    pb.finish_and_clear();
    formatter.print(&stats);
    Ok(())
}

async fn handle_config_commands(
    action: ConfigCommands,
    client: &AtlasClient,
    formatter: &OutputFormatter,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        ConfigCommands::Get { key } => {
            let pb = show_progress("Fetching configuration...");
            let path = if let Some(k) = key {
                format!("/api/v2/config/{}", k)
            } else {
                "/api/v2/config".to_string()
            };
            let config = client.get(&path).await?;
            pb.finish_and_clear();
            formatter.print(&config);
        }
        ConfigCommands::Set { key, value } => {
            let pb = show_progress(&format!("Setting {} = {}...", key, value));
            let body = json!({ key: value });
            let result = client.put("/api/v2/config", body).await?;
            pb.finish_and_clear();
            formatter.print_success("Configuration updated successfully");
            formatter.print(&result);
        }
        ConfigCommands::Reload => {
            let pb = show_progress("Reloading configuration...");
            client.post("/api/v2/config/reload", json!({})).await?;
            pb.finish_and_clear();
            formatter.print_success("Configuration reloaded successfully");
        }
        ConfigCommands::Validate { file } => {
            let pb = show_progress("Validating configuration...");
            let content = fs::read_to_string(file)?;
            let body = json!({ "config": content });
            let result = client.post("/api/v2/config/validate", body).await?;
            pb.finish_and_clear();
            formatter.print(&result);
        }
    }
    Ok(())
}

async fn handle_transfer_commands(
    action: TransferCommands,
    client: &AtlasClient,
    formatter: &OutputFormatter,
) -> Result<(), Box<dyn std::error::Error>> {
    // Implementation for transfer commands
    formatter.print_info("Transfer commands implementation");
    Ok(())
}

async fn handle_interactive_shell(
    client: &AtlasClient,
    formatter: &OutputFormatter,
) -> Result<(), Box<dyn std::error::Error>> {
    formatter.print_info("Entering interactive shell. Type 'help' for commands, 'exit' to quit.");
    
    loop {
        print!("atlas> ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        let input = input.trim();
        if input == "exit" || input == "quit" {
            break;
        }
        
        if input == "help" {
            println!("Available commands:");
            println!("  zone list        - List all zones");
            println!("  record list <zone> - List records in zone");
            println!("  status           - Show system status");
            println!("  help             - Show this help");
            println!("  exit             - Exit shell");
            continue;
        }
        
        // Parse and execute command
        // This would need more sophisticated parsing in production
        formatter.print_info(&format!("Command: {}", input));
    }
    
    formatter.print_info("Goodbye!");
    Ok(())
}

fn generate_completions(shell: Shell) {
    // This would generate shell completions for the specified shell
    println!("Generating completions for {:?}", shell);
    println!("Add the following to your shell configuration:");
    match shell {
        Shell::Bash => {
            println!("source <(atlas completions bash)");
        }
        Shell::Zsh => {
            println!("source <(atlas completions zsh)");
        }
        Shell::Fish => {
            println!("atlas completions fish | source");
        }
        _ => {
            println!("Completions for {:?} coming soon", shell);
        }
    }
}