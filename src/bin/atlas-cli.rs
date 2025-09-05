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
    #[command(subcommand)]
    command: StatsCommands,
}

#[derive(Subcommand)]
enum StatsCommands {
    /// Show general system statistics
    System {
        /// Time range (1h, 24h, 7d, 30d)
        #[arg(short = 'r', long, default_value = "24h")]
        range: String,
    },
    
    /// Show query statistics
    Queries {
        /// Time range (1h, 24h, 7d, 30d)
        #[arg(short = 'r', long, default_value = "24h")]
        range: String,
        
        /// Group by (zone, type, response_code)
        #[arg(short = 'g', long)]
        group_by: Option<String>,
        
        /// Show top N entries
        #[arg(short = 'n', long, default_value = "10")]
        top: usize,
    },
    
    /// Show zone-specific statistics
    Zones {
        /// Specific zone name (optional)
        #[arg(short = 'z', long)]
        zone: Option<String>,
        
        /// Time range (1h, 24h, 7d, 30d)
        #[arg(short = 'r', long, default_value = "24h")]
        range: String,
    },
    
    /// Show cache statistics
    Cache {
        /// Show detailed cache information
        #[arg(short = 'd', long)]
        detailed: bool,
    },
    
    /// Show upstream server statistics
    Upstream {
        /// Time range (1h, 24h, 7d, 30d)
        #[arg(short = 'r', long, default_value = "24h")]
        range: String,
        
        /// Include health check data
        #[arg(short = 'h', long)]
        health: bool,
    },
    
    /// Show performance metrics
    Performance {
        /// Time range (1h, 24h, 7d, 30d)
        #[arg(short = 'r', long, default_value = "24h")]
        range: String,
        
        /// Include latency percentiles
        #[arg(short = 'p', long)]
        percentiles: bool,
    },
    
    /// Export statistics to file
    Export {
        /// Output file path
        #[arg(short = 'o', long)]
        output: String,
        
        /// Export format (json, csv)
        #[arg(short = 'f', long, default_value = "json")]
        format: String,
        
        /// Time range (1h, 24h, 7d, 30d)
        #[arg(short = 'r', long, default_value = "24h")]
        range: String,
    },
    
    /// Reset statistics counters
    Reset {
        /// Confirmation flag
        #[arg(long)]
        confirm: bool,
    },
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
        Commands::Stats(args) => handle_stats_commands(args.command, &client, &formatter).await?,
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
        ZoneCommands::List { filter, enabled_only: _ } => {
            let pb = show_progress("Fetching zones...");
            let mut path = "/api/v2/zones".to_string();
            if let Some(f) = filter {
                path.push_str(&format!("?filter={}", f));
            }
            let zones = client.get(&path).await?;
            pb.finish_and_clear();
            formatter.print(&zones);
        }
        ZoneCommands::Get { zone, with_records: _ } => {
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
    match action {
        TrafficCommands::List => {
            let pb = show_progress("Fetching traffic policies...");
            let policies = client.get("/api/v2/traffic/policies").await?;
            pb.finish_and_clear();
            
            if let Some(policies_array) = policies.as_array() {
                if policies_array.is_empty() {
                    formatter.print_info("No traffic policies found");
                } else {
                    let mut table = Table::new();
                    table.set_header(vec!["ID", "Name", "Type", "Priority", "Status", "Targets"]);
                    
                    for policy in policies_array {
                        let id = policy["id"].as_str().unwrap_or("N/A");
                        let name = policy["name"].as_str().unwrap_or("N/A");
                        let policy_type = policy["type"].as_str().unwrap_or("N/A");
                        let priority = policy["priority"].as_u64().unwrap_or(0);
                        let status = policy["status"].as_str().unwrap_or("unknown");
                        let targets = policy["targets"].as_array()
                            .map(|arr| arr.len().to_string())
                            .unwrap_or_else(|| "0".to_string());
                        
                        table.add_row(vec![id, name, policy_type, &priority.to_string(), status, &targets]);
                    }
                    
                    println!("{}", table);
                }
            } else {
                formatter.print_error("Invalid response format from server");
            }
        },
        TrafficCommands::Get { id } => {
            let pb = show_progress(&format!("Fetching traffic policy {}...", id));
            let path = format!("/api/v2/traffic/policies/{}", id);
            let policy = client.get(&path).await?;
            pb.finish_and_clear();
            formatter.print(&policy);
        },
        TrafficCommands::Create { name, policy_type, config_file } => {
            let pb = show_progress(&format!("Creating traffic policy '{}'...", name));
            
            let mut body = json!({
                "name": name,
                "type": policy_type
            });
            
            // If config file is provided, merge its contents
            if let Some(config_path) = config_file {
                let config_content = fs::read_to_string(config_path)?;
                let config: Value = serde_json::from_str(&config_content)?;
                if let Some(obj) = body.as_object_mut() {
                    if let Some(config_obj) = config.as_object() {
                        for (key, value) in config_obj {
                            obj.insert(key.clone(), value.clone());
                        }
                    }
                }
            }
            
            let result = client.post("/api/v2/traffic/policies", body).await?;
            pb.finish_and_clear();
            formatter.print_success("Traffic policy created successfully");
            formatter.print(&result);
        },
        TrafficCommands::Update { id, config_file } => {
            let pb = show_progress(&format!("Updating traffic policy {}...", id));
            
            let config_content = fs::read_to_string(config_file)?;
            let body: Value = serde_json::from_str(&config_content)?;
            
            let path = format!("/api/v2/traffic/policies/{}", id);
            let result = client.put(&path, body).await?;
            pb.finish_and_clear();
            formatter.print_success(&format!("Traffic policy {} updated successfully", id));
            formatter.print(&result);
        },
        TrafficCommands::Delete { id } => {
            let pb = show_progress(&format!("Deleting traffic policy {}...", id));
            let path = format!("/api/v2/traffic/policies/{}", id);
            let result = client.delete(&path).await?;
            pb.finish_and_clear();
            formatter.print_success(&format!("Traffic policy {} deleted successfully", id));
        },
        TrafficCommands::Simulate { id, requests } => {
            let pb = show_progress(&format!("Simulating traffic policy {} ({} requests)...", id, requests));
            let path = format!("/api/v2/traffic/policies/{}/simulate", id);
            let body = json!({ "requests": requests });
            let result = client.post(&path, body).await?;
            pb.finish_and_clear();
            formatter.print_success(&format!("Simulation completed for policy {}", id));
            
            if let Some(result_obj) = result.as_object() {
                let mut table = Table::new();
                table.set_header(vec!["Metric", "Value"]);
                
                if let Some(total) = result_obj.get("total_requests") {
                    table.add_row(vec!["Total Requests".to_string(), total.to_string()]);
                }
                if let Some(success) = result_obj.get("successful_requests") {
                    table.add_row(vec!["Successful".to_string(), success.to_string()]);
                }
                if let Some(failed) = result_obj.get("failed_requests") {
                    table.add_row(vec!["Failed".to_string(), failed.to_string()]);
                }
                if let Some(avg_latency) = result_obj.get("avg_latency_ms") {
                    table.add_row(vec!["Avg Latency".to_string(), format!("{:.2}ms", avg_latency.as_f64().unwrap_or(0.0))]);
                }
                
                println!("{}", table);
            }
        },
    }
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

async fn handle_stats_commands(
    command: StatsCommands,
    client: &AtlasClient,
    formatter: &OutputFormatter,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        StatsCommands::System { range } => {
            let pb = show_progress("Fetching system statistics...");
            let system_stats = client.get(&format!("/api/v2/stats/system?range={}", range)).await?;
            pb.finish_and_clear();
            
            // Parse and format system statistics
            if let Some(stats) = system_stats.as_object() {
                let mut table = Table::new();
                table.set_header(vec!["Metric", "Value", "Change"]);
                
                // Add system metrics
                if let Some(uptime) = stats.get("uptime") {
                    table.add_row(vec!["Uptime".to_string(), format_duration(uptime), "-".to_string()]);
                }
                if let Some(queries) = stats.get("total_queries") {
                    let change = stats.get("query_change").map(|v| format!("{:+.1}%", v.as_f64().unwrap_or(0.0))).unwrap_or("-".to_string());
                    table.add_row(vec!["Total Queries".to_string(), queries.to_string(), change]);
                }
                if let Some(cache_hits) = stats.get("cache_hit_rate") {
                    table.add_row(vec!["Cache Hit Rate".to_string(), format!("{:.1}%", cache_hits.as_f64().unwrap_or(0.0) * 100.0), "-".to_string()]);
                }
                if let Some(memory) = stats.get("memory_usage") {
                    table.add_row(vec!["Memory Usage".to_string(), format_bytes(memory.as_u64().unwrap_or(0)), "-".to_string()]);
                }
                
                formatter.print_info(&format!("System Statistics ({})", range));
                println!("{}", table);
            } else {
                formatter.print(&system_stats);
            }
        },
        
        StatsCommands::Queries { range, group_by, top } => {
            let pb = show_progress("Fetching query statistics...");
            let mut path = format!("/api/v2/stats/queries?range={}&top={}", range, top);
            if let Some(ref g) = group_by {
                path.push_str(&format!("&group_by={}", g));
            }
            let query_stats = client.get(&path).await?;
            pb.finish_and_clear();
            
            if let Some(data) = query_stats.as_object() {
                let mut table = Table::new();
                
                if let Some(group) = &group_by {
                    match group.as_str() {
                        "zone" => {
                            table.set_header(vec!["Zone", "Queries", "Percentage"]);
                            if let Some(zones) = data.get("zones").and_then(|z| z.as_array()) {
                                for zone in zones.iter().take(top) {
                                    if let Some(z) = zone.as_object() {
                                        let name = z.get("name").and_then(|n| n.as_str()).unwrap_or("Unknown");
                                        let count = z.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
                                        let pct = z.get("percentage").and_then(|p| p.as_f64()).unwrap_or(0.0);
                                        table.add_row(vec![name.to_string(), count.to_string(), format!("{:.1}%", pct)]);
                                    }
                                }
                            }
                        },
                        "type" => {
                            table.set_header(vec!["Query Type", "Count", "Percentage"]);
                            if let Some(types) = data.get("types").and_then(|t| t.as_array()) {
                                for qtype in types.iter().take(top) {
                                    if let Some(t) = qtype.as_object() {
                                        let name = t.get("type").and_then(|n| n.as_str()).unwrap_or("Unknown");
                                        let count = t.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
                                        let pct = t.get("percentage").and_then(|p| p.as_f64()).unwrap_or(0.0);
                                        table.add_row(vec![name.to_string(), count.to_string(), format!("{:.1}%", pct)]);
                                    }
                                }
                            }
                        },
                        "response_code" => {
                            table.set_header(vec!["Response Code", "Count", "Percentage"]);
                            if let Some(codes) = data.get("response_codes").and_then(|c| c.as_array()) {
                                for code in codes.iter().take(top) {
                                    if let Some(c) = code.as_object() {
                                        let code_val = c.get("code").and_then(|n| n.as_u64()).unwrap_or(0);
                                        let count = c.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
                                        let pct = c.get("percentage").and_then(|p| p.as_f64()).unwrap_or(0.0);
                                        let code_name = match code_val {
                                            0 => "NOERROR",
                                            2 => "SERVFAIL",
                                            3 => "NXDOMAIN",
                                            5 => "REFUSED",
                                            _ => "OTHER",
                                        };
                                        table.add_row(vec![format!("{} ({})", code_name, code_val), count.to_string(), format!("{:.1}%", pct)]);
                                    }
                                }
                            }
                        },
                        _ => {
                            formatter.print_error(&format!("Unknown grouping: {}", group));
                            return Ok(());
                        }
                    }
                } else {
                    // Show general query statistics
                    table.set_header(vec!["Metric", "Value"]);
                    if let Some(total) = data.get("total_queries") {
                        table.add_row(vec!["Total Queries".to_string(), total.to_string()]);
                    }
                    if let Some(avg) = data.get("avg_per_second") {
                        table.add_row(vec!["Avg Queries/sec".to_string(), format!("{:.2}", avg.as_f64().unwrap_or(0.0))]);
                    }
                    if let Some(peak) = data.get("peak_qps") {
                        table.add_row(vec!["Peak QPS".to_string(), peak.to_string()]);
                    }
                }
                
                formatter.print_info(&format!("Query Statistics ({}) - Top {}", range, top));
                if let Some(ref gb) = group_by {
                    formatter.print_info(&format!("Grouped by: {}", gb));
                }
                println!("{}", table);
            } else {
                formatter.print(&query_stats);
            }
        },
        
        StatsCommands::Zones { zone, range } => {
            let pb = show_progress("Fetching zone statistics...");
            let path = if let Some(z) = zone {
                format!("/api/v2/stats/zones/{}?range={}", z, range)
            } else {
                format!("/api/v2/stats/zones?range={}", range)
            };
            let zone_stats = client.get(&path).await?;
            pb.finish_and_clear();
            
            if let Some(data) = zone_stats.as_object() {
                let mut table = Table::new();
                table.set_header(vec!["Zone", "Queries", "Records", "Hit Rate", "Avg Latency"]);
                
                if let Some(zones) = data.get("zones").and_then(|z| z.as_array()) {
                    for zone_data in zones {
                        if let Some(z) = zone_data.as_object() {
                            let name = z.get("name").and_then(|n| n.as_str()).unwrap_or("Unknown");
                            let queries = z.get("query_count").and_then(|c| c.as_u64()).unwrap_or(0);
                            let records = z.get("record_count").and_then(|c| c.as_u64()).unwrap_or(0);
                            let hit_rate = z.get("cache_hit_rate").and_then(|h| h.as_f64()).unwrap_or(0.0);
                            let latency = z.get("avg_latency_ms").and_then(|l| l.as_f64()).unwrap_or(0.0);
                            
                            table.add_row(vec![
                                name.to_string(),
                                queries.to_string(),
                                records.to_string(),
                                format!("{:.1}%", hit_rate * 100.0),
                                format!("{:.2}ms", latency)
                            ]);
                        }
                    }
                }
                
                formatter.print_info(&format!("Zone Statistics ({})", range));
                println!("{}", table);
            } else {
                formatter.print(&zone_stats);
            }
        },
        
        StatsCommands::Cache { detailed } => {
            let pb = show_progress("Fetching cache statistics...");
            let path = if detailed {
                "/api/v2/stats/cache?detailed=true"
            } else {
                "/api/v2/stats/cache"
            };
            let cache_stats = client.get(path).await?;
            pb.finish_and_clear();
            
            if let Some(data) = cache_stats.as_object() {
                let mut table = Table::new();
                table.set_header(vec!["Metric", "Value"]);
                
                if let Some(size) = data.get("cache_size") {
                    table.add_row(vec!["Cache Entries".to_string(), size.to_string()]);
                }
                if let Some(hit_rate) = data.get("hit_rate") {
                    table.add_row(vec!["Hit Rate".to_string(), format!("{:.1}%", hit_rate.as_f64().unwrap_or(0.0) * 100.0)]);
                }
                if let Some(memory) = data.get("memory_usage") {
                    table.add_row(vec!["Memory Usage".to_string(), format_bytes(memory.as_u64().unwrap_or(0))]);
                }
                if let Some(expired) = data.get("expired_entries") {
                    table.add_row(vec!["Expired Entries".to_string(), expired.to_string()]);
                }
                
                if detailed {
                    if let Some(types) = data.get("entry_types").and_then(|t| t.as_object()) {
                        for (record_type, count) in types {
                            table.add_row(vec![format!("{} Records", record_type.to_uppercase()), count.to_string()]);
                        }
                    }
                }
                
                formatter.print_info("Cache Statistics");
                println!("{}", table);
            } else {
                formatter.print(&cache_stats);
            }
        },
        
        StatsCommands::Upstream { range, health } => {
            let pb = show_progress("Fetching upstream server statistics...");
            let mut path = format!("/api/v2/stats/upstream?range={}", range);
            if health {
                path.push_str("&include_health=true");
            }
            let upstream_stats = client.get(&path).await?;
            pb.finish_and_clear();
            
            if let Some(data) = upstream_stats.as_object() {
                let mut table = Table::new();
                if health {
                    table.set_header(vec!["Server", "Status", "Queries", "Avg Latency", "Success Rate", "Last Check"]);
                } else {
                    table.set_header(vec!["Server", "Queries", "Avg Latency", "Success Rate"]);
                }
                
                if let Some(servers) = data.get("servers").and_then(|s| s.as_array()) {
                    for server in servers {
                        if let Some(s) = server.as_object() {
                            let address = s.get("address").and_then(|a| a.as_str()).unwrap_or("Unknown");
                            let queries = s.get("query_count").and_then(|q| q.as_u64()).unwrap_or(0);
                            let latency = s.get("avg_latency_ms").and_then(|l| l.as_f64()).unwrap_or(0.0);
                            let success_rate = s.get("success_rate").and_then(|r| r.as_f64()).unwrap_or(0.0);
                            
                            if health {
                                let status = s.get("status").and_then(|st| st.as_str()).unwrap_or("Unknown");
                                let last_check = s.get("last_health_check").and_then(|lc| lc.as_str()).unwrap_or("Never");
                                let status_colored = match status {
                                    "healthy" => format!("\x1b[32m{}\x1b[0m", status),
                                    "unhealthy" => format!("\x1b[31m{}\x1b[0m", status),
                                    _ => status.to_string(),
                                };
                                
                                table.add_row(vec![
                                    address.to_string(),
                                    status_colored,
                                    queries.to_string(),
                                    format!("{:.2}ms", latency),
                                    format!("{:.1}%", success_rate * 100.0),
                                    last_check.to_string()
                                ]);
                            } else {
                                table.add_row(vec![
                                    address.to_string(),
                                    queries.to_string(),
                                    format!("{:.2}ms", latency),
                                    format!("{:.1}%", success_rate * 100.0)
                                ]);
                            }
                        }
                    }
                }
                
                formatter.print_info(&format!("Upstream Server Statistics ({})", range));
                println!("{}", table);
            } else {
                formatter.print(&upstream_stats);
            }
        },
        
        StatsCommands::Performance { range, percentiles } => {
            let pb = show_progress("Fetching performance statistics...");
            let mut path = format!("/api/v2/stats/performance?range={}", range);
            if percentiles {
                path.push_str("&include_percentiles=true");
            }
            let perf_stats = client.get(&path).await?;
            pb.finish_and_clear();
            
            if let Some(data) = perf_stats.as_object() {
                let mut table = Table::new();
                table.set_header(vec!["Metric", "Value"]);
                
                if let Some(avg_latency) = data.get("avg_query_latency_ms") {
                    table.add_row(vec!["Avg Query Latency".to_string(), format!("{:.2}ms", avg_latency.as_f64().unwrap_or(0.0))]);
                }
                if let Some(qps) = data.get("queries_per_second") {
                    table.add_row(vec!["Queries/sec".to_string(), format!("{:.2}", qps.as_f64().unwrap_or(0.0))]);
                }
                if let Some(cpu) = data.get("cpu_usage_percent") {
                    table.add_row(vec!["CPU Usage".to_string(), format!("{:.1}%", cpu.as_f64().unwrap_or(0.0))]);
                }
                if let Some(memory) = data.get("memory_usage_mb") {
                    table.add_row(vec!["Memory Usage".to_string(), format!("{:.1}MB", memory.as_f64().unwrap_or(0.0))]);
                }
                
                if percentiles {
                    if let Some(p50) = data.get("latency_p50_ms") {
                        table.add_row(vec!["Latency P50".to_string(), format!("{:.2}ms", p50.as_f64().unwrap_or(0.0))]);
                    }
                    if let Some(p95) = data.get("latency_p95_ms") {
                        table.add_row(vec!["Latency P95".to_string(), format!("{:.2}ms", p95.as_f64().unwrap_or(0.0))]);
                    }
                    if let Some(p99) = data.get("latency_p99_ms") {
                        table.add_row(vec!["Latency P99".to_string(), format!("{:.2}ms", p99.as_f64().unwrap_or(0.0))]);
                    }
                }
                
                formatter.print_info(&format!("Performance Statistics ({})", range));
                println!("{}", table);
            } else {
                formatter.print(&perf_stats);
            }
        },
        
        StatsCommands::Export { output, format, range } => {
            let pb = show_progress(&format!("Exporting statistics to {}...", output));
            let stats_data = client.get(&format!("/api/v2/stats/export?range={}&format={}", range, format)).await?;
            
            match format.as_str() {
                "json" => {
                    fs::write(&output, serde_json::to_string_pretty(&stats_data)?)?;
                },
                "csv" => {
                    // Convert JSON to CSV format
                    let csv_data = json_to_csv(&stats_data)?;
                    fs::write(&output, csv_data)?;
                },
                _ => {
                    pb.finish_and_clear();
                    formatter.print_error(&format!("Unsupported format: {}. Use 'json' or 'csv'", format));
                    return Ok(());
                }
            }
            
            pb.finish_and_clear();
            formatter.print_success(&format!("Statistics exported to {} in {} format", output, format));
        },
        
        StatsCommands::Reset { confirm } => {
            if !confirm {
                formatter.print_error("Use --confirm flag to reset statistics counters");
                return Ok(());
            }
            
            let pb = show_progress("Resetting statistics counters...");
            client.post("/api/v2/stats/reset", json!({})).await?;
            pb.finish_and_clear();
            formatter.print_success("Statistics counters have been reset");
        },
    }
    
    Ok(())
}

// Helper function to format duration in seconds to human readable format
fn format_duration(value: &serde_json::Value) -> String {
    if let Some(seconds) = value.as_u64() {
        let days = seconds / 86400;
        let hours = (seconds % 86400) / 3600;
        let minutes = (seconds % 3600) / 60;
        
        if days > 0 {
            format!("{}d {}h {}m", days, hours, minutes)
        } else if hours > 0 {
            format!("{}h {}m", hours, minutes)
        } else {
            format!("{}m", minutes)
        }
    } else {
        value.to_string()
    }
}

// Helper function to format bytes in human readable format
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    
    format!("{:.1}{}", size, UNITS[unit_index])
}

// Helper function to convert JSON to CSV format
fn json_to_csv(data: &serde_json::Value) -> Result<String, Box<dyn std::error::Error>> {
    let mut csv_output = String::new();
    
    if let Some(obj) = data.as_object() {
        // Add headers
        let headers: Vec<String> = obj.keys().cloned().collect();
        csv_output.push_str(&headers.join(","));
        csv_output.push('\n');
        
        // Add values
        let values: Vec<String> = obj.values()
            .map(|v| match v {
                serde_json::Value::String(s) => format!("\"{}\"", s),
                _ => v.to_string(),
            })
            .collect();
        csv_output.push_str(&values.join(","));
        csv_output.push('\n');
    }
    
    Ok(csv_output)
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
    match action {
        TransferCommands::Import { file, format, dry_run } => {
            let pb = show_progress(&format!("Importing from {}...", file.display()));
            
            // Read the import file
            let content = fs::read_to_string(&file)?;
            let format_str = format.unwrap_or_else(|| {
                file.extension()
                    .and_then(|ext| ext.to_str())
                    .map(|s| s.to_string())
                    .unwrap_or("bind".to_string())
            });
            
            let body = json!({
                "content": content,
                "format": format_str,
                "dry_run": dry_run
            });
            
            let result = client.post("/api/v2/transfers/import", body).await?;
            pb.finish_and_clear();
            
            if dry_run {
                formatter.print_info("Dry run completed - no changes were made");
            } else {
                formatter.print_success("Import completed successfully");
            }
            
            if let Some(result_obj) = result.as_object() {
                let mut table = Table::new();
                table.set_header(vec!["Metric", "Count"]);
                
                if let Some(zones) = result_obj.get("zones_imported") {
                    table.add_row(vec!["Zones Imported".to_string(), zones.to_string()]);
                }
                if let Some(records) = result_obj.get("records_imported") {
                    table.add_row(vec!["Records Imported".to_string(), records.to_string()]);
                }
                if let Some(errors) = result_obj.get("errors") {
                    table.add_row(vec!["Errors".to_string(), errors.to_string()]);
                }
                if let Some(warnings) = result_obj.get("warnings") {
                    table.add_row(vec!["Warnings".to_string(), warnings.to_string()]);
                }
                
                println!("{}", table);
            }
        },
        
        TransferCommands::Export { file, format, zone } => {
            let pb = show_progress(&format!("Exporting to {}...", file.display()));
            
            let format_str = format.unwrap_or_else(|| {
                file.extension()
                    .and_then(|ext| ext.to_str())
                    .map(|s| s.to_string())
                    .unwrap_or("bind".to_string())
            });
            
            let mut path = format!("/api/v2/transfers/export?format={}", format_str);
            if let Some(z) = zone {
                path.push_str(&format!("&zone={}", z));
            }
            
            let export_data = client.get(&path).await?;
            
            // Write the exported data to file
            if let Some(content) = export_data.get("content").and_then(|c| c.as_str()) {
                fs::write(&file, content)?;
                pb.finish_and_clear();
                formatter.print_success(&format!("Export completed: {} ({} format)", file.display(), format_str));
                
                if let Some(stats) = export_data.as_object() {
                    let mut table = Table::new();
                    table.set_header(vec!["Metric", "Count"]);
                    
                    if let Some(zones) = stats.get("zones_exported") {
                        table.add_row(vec!["Zones Exported".to_string(), zones.to_string()]);
                    }
                    if let Some(records) = stats.get("records_exported") {
                        table.add_row(vec!["Records Exported".to_string(), records.to_string()]);
                    }
                    
                    println!("{}", table);
                }
            } else {
                pb.finish_and_clear();
                formatter.print_error("No content received from server");
            }
        },
        
        TransferCommands::Sync { provider, direction, dry_run } => {
            let pb = show_progress(&format!("Syncing with {} ({} direction)...", provider, direction));
            
            let mut body = json!({
                "provider": provider,
                "direction": direction
            });
            
            body["dry_run"] = Value::Bool(dry_run);
            
            let result = client.post("/api/v2/transfers/sync", body).await?;
            pb.finish_and_clear();
            
            formatter.print_success(&format!("Sync completed with {} ({})", provider, direction));
            
            if let Some(result_obj) = result.as_object() {
                let mut table = Table::new();
                table.set_header(vec!["Metric", "Count"]);
                
                if let Some(pushed) = result_obj.get("records_pushed") {
                    table.add_row(vec!["Records Pushed".to_string(), pushed.to_string()]);
                }
                if let Some(pulled) = result_obj.get("records_pulled") {
                    table.add_row(vec!["Records Pulled".to_string(), pulled.to_string()]);
                }
                if let Some(conflicts) = result_obj.get("conflicts") {
                    table.add_row(vec!["Conflicts".to_string(), conflicts.to_string()]);
                }
                if let Some(errors) = result_obj.get("errors") {
                    table.add_row(vec!["Errors".to_string(), errors.to_string()]);
                }
                
                println!("{}", table);
                
                // Show conflicts if any
                if let Some(conflict_list) = result_obj.get("conflict_details").and_then(|c| c.as_array()) {
                    if !conflict_list.is_empty() {
                        formatter.print_info("\nConflicts detected:");
                        let mut conflict_table = Table::new();
                        conflict_table.set_header(vec!["Zone", "Record", "Local Value", "Remote Value", "Resolution"]);
                        
                        for conflict in conflict_list {
                            if let Some(c) = conflict.as_object() {
                                let zone = c.get("zone").and_then(|z| z.as_str()).unwrap_or("N/A");
                                let record = c.get("record").and_then(|r| r.as_str()).unwrap_or("N/A");
                                let local = c.get("local_value").and_then(|l| l.as_str()).unwrap_or("N/A");
                                let remote = c.get("remote_value").and_then(|r| r.as_str()).unwrap_or("N/A");
                                let resolution = c.get("resolution").and_then(|r| r.as_str()).unwrap_or("Manual");
                                
                                conflict_table.add_row(vec![
                                    zone.to_string(),
                                    record.to_string(),
                                    local.to_string(),
                                    remote.to_string(),
                                    resolution.to_string()
                                ]);
                            }
                        }
                        println!("{}", conflict_table);
                    }
                }
            }
        },
    }
    
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