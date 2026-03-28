//! AtlasDNS backup/restore CLI
//!
//! Provides AXFR-style zone export/import:
//!
//! ```text
//! atlasdns-backup zones export <zone> <output.zone>
//! atlasdns-backup zones import <zone> <input.zone>
//! ```

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::process;

use clap::{Parser, Subcommand};

use atlas::dns::authority::Authority;
use atlas::dns::protocol::DnsRecord;
use atlas::dns::zone_parser::ZoneParser;

#[derive(Parser)]
#[command(name = "atlasdns-backup", about = "AtlasDNS zone backup and restore")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Zone backup and restore operations
    Zones {
        #[command(subcommand)]
        action: ZoneAction,
    },
}

#[derive(Subcommand)]
enum ZoneAction {
    /// Export a zone to BIND zone file format (AXFR-style)
    Export {
        /// Zone name (e.g. "example.com")
        zone: String,
        /// Output file path (e.g. "example.com.zone")
        output: String,
        /// Zones directory (default: /opt/atlas/zones)
        #[arg(long, default_value = "/opt/atlas/zones")]
        zones_dir: String,
    },
    /// Import a zone from a BIND zone file
    Import {
        /// Zone name (e.g. "example.com")
        zone: String,
        /// Input file path (e.g. "example.com.zone")
        input: String,
        /// Zones directory (default: /opt/atlas/zones)
        #[arg(long, default_value = "/opt/atlas/zones")]
        zones_dir: String,
    },
}

fn main() {
    simple_logger::init_with_level(log::Level::Info).ok();

    let cli = Cli::parse();

    match cli.command {
        Commands::Zones { action } => match action {
            ZoneAction::Export { zone, output, zones_dir } => {
                if let Err(e) = export_zone(&zone, &output, &zones_dir) {
                    eprintln!("Error exporting zone '{}': {}", zone, e);
                    process::exit(1);
                }
            }
            ZoneAction::Import { zone, input, zones_dir } => {
                if let Err(e) = import_zone(&zone, &input, &zones_dir) {
                    eprintln!("Error importing zone '{}': {}", zone, e);
                    process::exit(1);
                }
            }
        },
    }
}

/// Export a zone to BIND zone file format.
fn export_zone(zone_name: &str, output_path: &str, zones_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    let authority = Authority::new();

    // Load zones from disk
    if let Err(e) = authority.load(zones_dir) {
        return Err(format!("Failed to load zones from '{}': {}", zones_dir, e).into());
    }

    let zone = authority.get_zone_clone(zone_name)
        .map_err(|e| format!("Zone '{}' not found: {}", zone_name, e))?;

    let file = File::create(output_path)?;
    let mut writer = BufWriter::new(file);

    // Write zone file header
    writeln!(writer, "; Zone file for {}", zone.domain)?;
    writeln!(writer, "; Exported by atlasdns-backup")?;
    writeln!(writer, "; Serial: {}", zone.serial)?;
    writeln!(writer, "")?;
    writeln!(writer, "$ORIGIN {}.", zone.domain)?;
    writeln!(writer, "$TTL 3600")?;
    writeln!(writer, "")?;

    // Write SOA record
    writeln!(
        writer,
        "@\tIN\tSOA\t{}. {}. {} {} {} {} {}",
        zone.m_name, zone.r_name, zone.serial,
        zone.refresh, zone.retry, zone.expire, zone.minimum
    )?;
    writeln!(writer, "")?;

    // Write all records
    for record in &zone.records {
        if let Some(line) = format_record_bind(&record, &zone.domain) {
            writeln!(writer, "{}", line)?;
        }
    }

    writer.flush()?;

    println!(
        "Exported zone '{}' ({} records) to '{}'",
        zone_name,
        zone.records.len(),
        output_path
    );

    Ok(())
}

/// Import a zone from a BIND zone file.
fn import_zone(zone_name: &str, input_path: &str, zones_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(input_path);
    if !path.exists() {
        return Err(format!("Input file '{}' not found", input_path).into());
    }

    // Parse the zone file (validates syntax)
    let mut parser = ZoneParser::new(zone_name);
    let zone = parser.parse_file(path)
        .map_err(|e| format!("Zone file syntax error: {}", e))?;

    println!(
        "Validated zone '{}': {} records, serial {}",
        zone.domain, zone.records.len(), zone.serial
    );

    // Load existing authority and upsert the zone
    let authority = Authority::new();
    let _ = authority.load(zones_dir); // OK if dir is empty

    authority.upsert_zone(zone)
        .map_err(|e| format!("Failed to store zone: {}", e))?;

    // Save back to disk
    if let Err(e) = authority.save(zones_dir) {
        return Err(format!("Failed to save zones to '{}': {}", zones_dir, e).into());
    }

    println!("Imported zone '{}' to '{}'", zone_name, zones_dir);

    Ok(())
}

/// Format a DnsRecord as a BIND zone file line.
fn format_record_bind(record: &DnsRecord, origin: &str) -> Option<String> {
    match record {
        DnsRecord::A { domain, addr, ttl } => {
            let name = relative_name(domain, origin);
            Some(format!("{}\t{}\tIN\tA\t{}", name, ttl.0, addr))
        }
        DnsRecord::Aaaa { domain, addr, ttl } => {
            let name = relative_name(domain, origin);
            Some(format!("{}\t{}\tIN\tAAAA\t{}", name, ttl.0, addr))
        }
        DnsRecord::Ns { domain, host, ttl } => {
            let name = relative_name(domain, origin);
            Some(format!("{}\t{}\tIN\tNS\t{}.", name, ttl.0, host))
        }
        DnsRecord::Cname { domain, host, ttl } => {
            let name = relative_name(domain, origin);
            Some(format!("{}\t{}\tIN\tCNAME\t{}.", name, ttl.0, host))
        }
        DnsRecord::Mx { domain, priority, host, ttl } => {
            let name = relative_name(domain, origin);
            Some(format!("{}\t{}\tIN\tMX\t{} {}.", name, ttl.0, priority, host))
        }
        DnsRecord::Txt { domain, data, ttl } => {
            let name = relative_name(domain, origin);
            Some(format!("{}\t{}\tIN\tTXT\t\"{}\"", name, ttl.0, data))
        }
        DnsRecord::Srv { domain, priority, weight, port, host, ttl } => {
            let name = relative_name(domain, origin);
            Some(format!(
                "{}\t{}\tIN\tSRV\t{} {} {} {}.",
                name, ttl.0, priority, weight, port, host
            ))
        }
        DnsRecord::Soa { .. } => {
            // SOA is written in the header
            None
        }
        _ => {
            // Skip unsupported record types in export
            None
        }
    }
}

/// Convert an absolute domain name to a name relative to the zone origin.
fn relative_name(domain: &str, origin: &str) -> String {
    if domain == origin {
        "@".to_string()
    } else if let Some(prefix) = domain.strip_suffix(&format!(".{}", origin)) {
        prefix.to_string()
    } else {
        domain.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_relative_name() {
        assert_eq!(relative_name("example.com", "example.com"), "@");
        assert_eq!(relative_name("www.example.com", "example.com"), "www");
        assert_eq!(relative_name("sub.www.example.com", "example.com"), "sub.www");
        assert_eq!(relative_name("other.org", "example.com"), "other.org");
    }

    #[test]
    fn test_format_record_bind() {
        let record = DnsRecord::A {
            domain: "www.example.com".to_string(),
            addr: Ipv4Addr::new(93, 184, 216, 34),
            ttl: TransientTtl(3600),
        };
        let line = format_record_bind(&record, "example.com").unwrap();
        assert!(line.contains("www"));
        assert!(line.contains("93.184.216.34"));
        assert!(line.contains("IN\tA"));
    }
}
