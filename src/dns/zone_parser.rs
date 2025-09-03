//! RFC 1035 compliant zone file parser
//! 
//! This module implements a complete zone file parser that supports:
//! - Standard BIND zone file format
//! - All common DNS record types
//! - Zone file directives ($ORIGIN, $TTL, $INCLUDE)
//! - Comments and multi-line records
//! - Relative and absolute domain names
//! - @ symbol for zone apex

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::dns::protocol::{DnsRecord, TransientTtl};
use super::authority::Zone;

/// Parser errors with line number information
#[derive(Debug)]
pub enum ParseError {
    InvalidSyntax { line: usize, message: String },
    InvalidRecordType { line: usize, record_type: String },
    InvalidIpAddress { line: usize, addr: String },
    InvalidDomainName { line: usize, domain: String },
    InvalidTtl { line: usize, ttl: String },
    MissingField { line: usize, field: String },
    CircularInclude { line: usize, file: String },
    IoError { line: usize, error: std::io::Error },
    DuplicateRecord { line: usize, record: String },
    MissingSoa { zone: String },
    InvalidSoaSerial { line: usize, serial: String },
    MissingGlueRecord { line: usize, ns: String },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::InvalidSyntax { line, message } => 
                write!(f, "Line {}: Invalid syntax: {}", line, message),
            ParseError::InvalidRecordType { line, record_type } => 
                write!(f, "Line {}: Unknown record type: {}", line, record_type),
            ParseError::InvalidIpAddress { line, addr } => 
                write!(f, "Line {}: Invalid IP address: {}", line, addr),
            ParseError::InvalidDomainName { line, domain } => 
                write!(f, "Line {}: Invalid domain name: {}", line, domain),
            ParseError::InvalidTtl { line, ttl } => 
                write!(f, "Line {}: Invalid TTL value: {}", line, ttl),
            ParseError::MissingField { line, field } => 
                write!(f, "Line {}: Missing required field: {}", line, field),
            ParseError::CircularInclude { line, file } => 
                write!(f, "Line {}: Circular include detected: {}", line, file),
            ParseError::IoError { line, error } => 
                write!(f, "Line {}: IO error: {}", line, error),
            ParseError::DuplicateRecord { line, record } => 
                write!(f, "Line {}: Duplicate record: {}", line, record),
            ParseError::MissingSoa { zone } => 
                write!(f, "Missing SOA record for zone: {}", zone),
            ParseError::InvalidSoaSerial { line, serial } => 
                write!(f, "Line {}: Invalid SOA serial: {}", line, serial),
            ParseError::MissingGlueRecord { line, ns } => 
                write!(f, "Line {}: Missing glue record for NS: {}", line, ns),
        }
    }
}

impl std::error::Error for ParseError {}

type Result<T> = std::result::Result<T, ParseError>;

/// Zone file parser state
pub struct ZoneParser {
    origin: String,
    default_ttl: u32,
    current_ttl: Option<u32>,
    include_stack: Vec<PathBuf>,
    line_number: usize,
    last_domain: Option<String>,
}

impl ZoneParser {
    /// Create a new zone parser for the given zone
    pub fn new(zone_name: &str) -> Self {
        let origin = if zone_name.ends_with('.') {
            zone_name.to_string()
        } else {
            format!("{}.", zone_name)
        };

        ZoneParser {
            origin,
            default_ttl: 3600, // Default 1 hour
            current_ttl: None,
            include_stack: Vec::new(),
            line_number: 0,
            last_domain: None,
        }
    }

    /// Parse a zone file from a string
    pub fn parse_string(&mut self, content: &str) -> Result<Zone> {
        let lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        self.parse_lines(&lines)
    }

    /// Parse a zone file from a file path
    pub fn parse_file(&mut self, path: &Path) -> Result<Zone> {
        if self.include_stack.contains(&path.to_path_buf()) {
            return Err(ParseError::CircularInclude {
                line: self.line_number,
                file: path.display().to_string(),
            });
        }

        self.include_stack.push(path.to_path_buf());
        
        let file = File::open(path).map_err(|e| ParseError::IoError {
            line: self.line_number,
            error: e,
        })?;

        // For now, only support uncompressed files
        // TODO: Add gzip support with flate2 crate
        let reader = BufReader::new(file);
        let lines = reader.lines().collect::<std::io::Result<Vec<_>>>()
            .map_err(|e| ParseError::IoError {
                line: self.line_number,
                error: e,
            })?;

        let result = self.parse_lines(&lines);
        self.include_stack.pop();
        result
    }

    /// Parse zone file lines
    fn parse_lines(&mut self, lines: &[String]) -> Result<Zone> {
        let mut zone = Zone::new(
            self.origin.trim_end_matches('.').to_string(),
            format!("ns1.{}", self.origin),
            format!("admin.{}", self.origin),
        );

        let mut in_multiline = false;
        let mut multiline_buffer = String::new();
        let mut multiline_start = 0;

        for (idx, line) in lines.iter().enumerate() {
            self.line_number = idx + 1;

            // Handle multi-line records (parentheses)
            if in_multiline {
                multiline_buffer.push(' ');
                multiline_buffer.push_str(line.trim());
                if line.contains(')') {
                    in_multiline = false;
                    self.line_number = multiline_start;
                    self.parse_line(&mut zone, &multiline_buffer)?;
                    multiline_buffer.clear();
                }
                continue;
            }

            if line.contains('(') && !line.contains(')') {
                in_multiline = true;
                multiline_start = self.line_number;
                multiline_buffer = line.to_string();
                continue;
            }

            self.parse_line(&mut zone, line)?;
        }

        if in_multiline {
            return Err(ParseError::InvalidSyntax {
                line: multiline_start,
                message: "Unclosed parentheses in multi-line record".to_string(),
            });
        }

        // Validate zone has SOA record
        let has_soa = zone.records.iter().any(|r| matches!(r, DnsRecord::Soa { .. }));
        if !has_soa && !zone.records.is_empty() {
            // Auto-generate SOA if missing
            zone.records.insert(DnsRecord::Soa {
                domain: self.origin.trim_end_matches('.').to_string(),
                m_name: zone.m_name.clone(),
                r_name: zone.r_name.clone(),
                serial: zone.serial,
                refresh: zone.refresh,
                retry: zone.retry,
                expire: zone.expire,
                minimum: zone.minimum,
                ttl: TransientTtl(self.default_ttl),
            });
        }

        Ok(zone)
    }

    /// Parse a single line
    fn parse_line(&mut self, zone: &mut Zone, line: &str) -> Result<()> {
        // Remove comments
        let line = if let Some(pos) = line.find(';') {
            &line[..pos]
        } else {
            line
        };

        let line = line.trim();
        if line.is_empty() {
            return Ok(());
        }

        // Handle directives
        if line.starts_with('$') {
            return self.parse_directive(zone, line);
        }

        // Parse record
        self.parse_record(zone, line)
    }

    /// Parse zone file directives
    fn parse_directive(&mut self, zone: &mut Zone, line: &str) -> Result<()> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(());
        }

        match parts[0].to_uppercase().as_str() {
            "$ORIGIN" => {
                if parts.len() < 2 {
                    return Err(ParseError::MissingField {
                        line: self.line_number,
                        field: "origin domain".to_string(),
                    });
                }
                self.origin = self.normalize_domain(parts[1]);
            }
            "$TTL" => {
                if parts.len() < 2 {
                    return Err(ParseError::MissingField {
                        line: self.line_number,
                        field: "TTL value".to_string(),
                    });
                }
                self.default_ttl = self.parse_ttl(parts[1])?;
                self.current_ttl = Some(self.default_ttl);
            }
            "$INCLUDE" => {
                if parts.len() < 2 {
                    return Err(ParseError::MissingField {
                        line: self.line_number,
                        field: "include file".to_string(),
                    });
                }
                let path = Path::new(parts[1]);
                let included_zone = self.parse_file(path)?;
                // Merge records from included file
                for record in included_zone.records {
                    zone.records.insert(record);
                }
            }
            _ => {
                return Err(ParseError::InvalidSyntax {
                    line: self.line_number,
                    message: format!("Unknown directive: {}", parts[0]),
                });
            }
        }

        Ok(())
    }

    /// Parse a DNS record
    fn parse_record(&mut self, zone: &mut Zone, line: &str) -> Result<()> {
        let mut parts: Vec<String> = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;

        // Handle quoted strings properly
        for ch in line.chars() {
            if ch == '"' {
                in_quotes = !in_quotes;
                current.push(ch);
            } else if ch.is_whitespace() && !in_quotes {
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
            } else {
                current.push(ch);
            }
        }
        if !current.is_empty() {
            parts.push(current);
        }

        if parts.is_empty() {
            return Ok(());
        }

        let mut idx = 0;
        let mut domain = None;
        let mut ttl = None;
        let mut class = None;

        // Parse domain (optional, uses last domain if blank)
        if !parts[idx].chars().next().map_or(false, |c| c.is_ascii_digit()) 
            && !parts[idx].eq_ignore_ascii_case("IN") 
            && !is_record_type(&parts[idx]) {
            domain = Some(self.normalize_domain(&parts[idx]));
            self.last_domain = domain.clone();
            idx += 1;
        } else if parts[idx].is_empty() || parts[idx].chars().all(|c| c.is_whitespace()) {
            domain = self.last_domain.clone();
        }

        // Parse TTL (optional)
        if idx < parts.len() && parts[idx].chars().next().map_or(false, |c| c.is_ascii_digit()) {
            ttl = Some(self.parse_ttl(&parts[idx])?);
            idx += 1;
        }

        // Parse class (optional, defaults to IN)
        if idx < parts.len() && parts[idx].eq_ignore_ascii_case("IN") {
            class = Some("IN");
            idx += 1;
        }

        // Parse TTL again if it comes after class
        if idx < parts.len() && ttl.is_none() && parts[idx].chars().next().map_or(false, |c| c.is_ascii_digit()) {
            ttl = Some(self.parse_ttl(&parts[idx])?);
            idx += 1;
        }

        // Parse record type
        if idx >= parts.len() {
            return Err(ParseError::MissingField {
                line: self.line_number,
                field: "record type".to_string(),
            });
        }

        let record_type = parts[idx].to_uppercase();
        idx += 1;

        // Use domain from last record if not specified
        let domain = domain.or_else(|| self.last_domain.clone()).ok_or_else(|| {
            ParseError::MissingField {
                line: self.line_number,
                field: "domain name".to_string(),
            }
        })?;

        // Use default TTL if not specified
        let ttl = ttl.unwrap_or(self.current_ttl.unwrap_or(self.default_ttl));

        // Parse record data based on type
        let record = match record_type.as_str() {
            "A" => self.parse_a_record(domain, ttl, &parts[idx..])?,
            "AAAA" => self.parse_aaaa_record(domain, ttl, &parts[idx..])?,
            "CNAME" => self.parse_cname_record(domain, ttl, &parts[idx..])?,
            "MX" => self.parse_mx_record(domain, ttl, &parts[idx..])?,
            "NS" => self.parse_ns_record(domain, ttl, &parts[idx..])?,
            "TXT" => self.parse_txt_record(domain, ttl, &parts[idx..])?,
            "SOA" => self.parse_soa_record(zone, domain, ttl, &parts[idx..])?,
            "PTR" => self.parse_ptr_record(domain, ttl, &parts[idx..])?,
            "SRV" => self.parse_srv_record(domain, ttl, &parts[idx..])?,
            "CAA" => self.parse_caa_record(domain, ttl, &parts[idx..])?,
            _ => {
                return Err(ParseError::InvalidRecordType {
                    line: self.line_number,
                    record_type,
                });
            }
        };

        if let Some(record) = record {
            // Check for duplicates
            if zone.records.contains(&record) {
                return Err(ParseError::DuplicateRecord {
                    line: self.line_number,
                    record: format!("{:?}", record),
                });
            }
            zone.records.insert(record);
        }

        Ok(())
    }

    /// Parse A record
    fn parse_a_record(&self, domain: String, ttl: u32, parts: &[String]) -> Result<Option<DnsRecord>> {
        if parts.is_empty() {
            return Err(ParseError::MissingField {
                line: self.line_number,
                field: "IPv4 address".to_string(),
            });
        }

        let addr = Ipv4Addr::from_str(&parts[0]).map_err(|_| ParseError::InvalidIpAddress {
            line: self.line_number,
            addr: parts[0].clone(),
        })?;

        Ok(Some(DnsRecord::A {
            domain,
            addr,
            ttl: TransientTtl(ttl),
        }))
    }

    /// Parse AAAA record
    fn parse_aaaa_record(&self, domain: String, ttl: u32, parts: &[String]) -> Result<Option<DnsRecord>> {
        if parts.is_empty() {
            return Err(ParseError::MissingField {
                line: self.line_number,
                field: "IPv6 address".to_string(),
            });
        }

        let addr = Ipv6Addr::from_str(&parts[0]).map_err(|_| ParseError::InvalidIpAddress {
            line: self.line_number,
            addr: parts[0].clone(),
        })?;

        Ok(Some(DnsRecord::Aaaa {
            domain,
            addr,
            ttl: TransientTtl(ttl),
        }))
    }

    /// Parse CNAME record
    fn parse_cname_record(&self, domain: String, ttl: u32, parts: &[String]) -> Result<Option<DnsRecord>> {
        if parts.is_empty() {
            return Err(ParseError::MissingField {
                line: self.line_number,
                field: "canonical name".to_string(),
            });
        }

        let host = self.normalize_domain(&parts[0]);

        Ok(Some(DnsRecord::Cname {
            domain,
            host,
            ttl: TransientTtl(ttl),
        }))
    }

    /// Parse MX record
    fn parse_mx_record(&self, domain: String, ttl: u32, parts: &[String]) -> Result<Option<DnsRecord>> {
        if parts.len() < 2 {
            return Err(ParseError::MissingField {
                line: self.line_number,
                field: "MX priority or host".to_string(),
            });
        }

        let priority = parts[0].parse::<u16>().map_err(|_| ParseError::InvalidSyntax {
            line: self.line_number,
            message: format!("Invalid MX priority: {}", parts[0]),
        })?;

        let host = self.normalize_domain(&parts[1]);

        Ok(Some(DnsRecord::Mx {
            domain,
            priority,
            host,
            ttl: TransientTtl(ttl),
        }))
    }

    /// Parse NS record
    fn parse_ns_record(&self, domain: String, ttl: u32, parts: &[String]) -> Result<Option<DnsRecord>> {
        if parts.is_empty() {
            return Err(ParseError::MissingField {
                line: self.line_number,
                field: "nameserver".to_string(),
            });
        }

        let host = self.normalize_domain(&parts[0]);

        Ok(Some(DnsRecord::Ns {
            domain,
            host,
            ttl: TransientTtl(ttl),
        }))
    }

    /// Parse TXT record
    fn parse_txt_record(&self, domain: String, ttl: u32, parts: &[String]) -> Result<Option<DnsRecord>> {
        if parts.is_empty() {
            return Err(ParseError::MissingField {
                line: self.line_number,
                field: "text data".to_string(),
            });
        }

        // Concatenate all parts and handle quoted strings
        let mut data = String::new();
        for part in parts {
            if !data.is_empty() {
                data.push(' ');
            }
            // Remove quotes if present
            if part.starts_with('"') && part.ends_with('"') {
                data.push_str(&part[1..part.len()-1]);
            } else {
                data.push_str(part);
            }
        }

        Ok(Some(DnsRecord::Txt {
            domain,
            data,
            ttl: TransientTtl(ttl),
        }))
    }

    /// Parse SOA record
    fn parse_soa_record(&self, zone: &mut Zone, domain: String, ttl: u32, parts: &[String]) -> Result<Option<DnsRecord>> {
        if parts.len() < 7 {
            return Err(ParseError::MissingField {
                line: self.line_number,
                field: "SOA fields".to_string(),
            });
        }

        let m_name = self.normalize_domain(&parts[0]);
        let r_name = self.normalize_domain(&parts[1]);
        
        let serial = parts[2].parse::<u32>().map_err(|_| ParseError::InvalidSoaSerial {
            line: self.line_number,
            serial: parts[2].clone(),
        })?;

        let refresh = self.parse_ttl(&parts[3])?;
        let retry = self.parse_ttl(&parts[4])?;
        let expire = self.parse_ttl(&parts[5])?;
        let minimum = self.parse_ttl(&parts[6])?;

        // Update zone metadata
        zone.m_name = m_name.clone();
        zone.r_name = r_name.clone();
        zone.serial = serial;
        zone.refresh = refresh;
        zone.retry = retry;
        zone.expire = expire;
        zone.minimum = minimum;

        Ok(Some(DnsRecord::Soa {
            domain,
            m_name,
            r_name,
            serial,
            refresh,
            retry,
            expire,
            minimum,
            ttl: TransientTtl(ttl),
        }))
    }

    /// Parse PTR record
    fn parse_ptr_record(&self, domain: String, ttl: u32, parts: &[String]) -> Result<Option<DnsRecord>> {
        if parts.is_empty() {
            return Err(ParseError::MissingField {
                line: self.line_number,
                field: "PTR target".to_string(),
            });
        }

        // PTR records are just CNAMEs in our implementation
        let host = self.normalize_domain(&parts[0]);

        Ok(Some(DnsRecord::Cname {
            domain,
            host,
            ttl: TransientTtl(ttl),
        }))
    }

    /// Parse SRV record
    fn parse_srv_record(&self, domain: String, ttl: u32, parts: &[String]) -> Result<Option<DnsRecord>> {
        if parts.len() < 4 {
            return Err(ParseError::MissingField {
                line: self.line_number,
                field: "SRV fields".to_string(),
            });
        }

        let priority = parts[0].parse::<u16>().map_err(|_| ParseError::InvalidSyntax {
            line: self.line_number,
            message: format!("Invalid SRV priority: {}", parts[0]),
        })?;

        let weight = parts[1].parse::<u16>().map_err(|_| ParseError::InvalidSyntax {
            line: self.line_number,
            message: format!("Invalid SRV weight: {}", parts[1]),
        })?;

        let port = parts[2].parse::<u16>().map_err(|_| ParseError::InvalidSyntax {
            line: self.line_number,
            message: format!("Invalid SRV port: {}", parts[2]),
        })?;

        let host = self.normalize_domain(&parts[3]);

        Ok(Some(DnsRecord::Srv {
            domain,
            priority,
            weight,
            port,
            host,
            ttl: TransientTtl(ttl),
        }))
    }

    /// Parse CAA record (stored as TXT in our implementation)
    fn parse_caa_record(&self, domain: String, ttl: u32, parts: &[String]) -> Result<Option<DnsRecord>> {
        if parts.len() < 3 {
            return Err(ParseError::MissingField {
                line: self.line_number,
                field: "CAA fields".to_string(),
            });
        }

        // CAA format: flags tag value
        let data = format!("{} {} {}", parts[0], parts[1], parts[2]);

        Ok(Some(DnsRecord::Txt {
            domain,
            data,
            ttl: TransientTtl(ttl),
        }))
    }

    /// Parse TTL value (supports time units)
    pub fn parse_ttl(&self, ttl_str: &str) -> Result<u32> {
        let ttl_str = ttl_str.to_uppercase();
        
        // Handle time units (1h, 30m, 1d, etc.)
        if let Some(last_char) = ttl_str.chars().last() {
            if last_char.is_alphabetic() {
                let number_part = &ttl_str[..ttl_str.len()-1];
                let value = number_part.parse::<u32>().map_err(|_| ParseError::InvalidTtl {
                    line: self.line_number,
                    ttl: ttl_str.clone(),
                })?;

                return match last_char {
                    'S' => Ok(value),           // seconds
                    'M' => Ok(value * 60),      // minutes
                    'H' => Ok(value * 3600),    // hours
                    'D' => Ok(value * 86400),   // days
                    'W' => Ok(value * 604800),  // weeks
                    _ => Err(ParseError::InvalidTtl {
                        line: self.line_number,
                        ttl: ttl_str.clone(),
                    }),
                };
            }
        }

        // Plain number (seconds)
        ttl_str.parse::<u32>().map_err(|_| ParseError::InvalidTtl {
            line: self.line_number,
            ttl: ttl_str.to_string(),
        })
    }

    /// Normalize domain name (handle @, relative names, etc.)
    fn normalize_domain(&self, domain: &str) -> String {
        let domain = domain.trim();

        // Handle @ for zone apex
        if domain == "@" {
            return self.origin.trim_end_matches('.').to_string();
        }

        // Handle relative names
        if !domain.ends_with('.') {
            if domain.is_empty() {
                self.origin.trim_end_matches('.').to_string()
            } else {
                format!("{}.{}", domain, self.origin.trim_end_matches('.'))
            }
        } else {
            domain.trim_end_matches('.').to_string()
        }
    }
}

/// Check if a string is a known record type
fn is_record_type(s: &str) -> bool {
    matches!(s.to_uppercase().as_str(),
        "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT" | "SOA" | "PTR" | "SRV" | "CAA"
    )
}

/// Validate zone for common issues
pub fn validate_zone(zone: &Zone) -> Vec<String> {
    let mut warnings = Vec::new();

    // Check for SOA record
    let has_soa = zone.records.iter().any(|r| matches!(r, DnsRecord::Soa { .. }));
    if !has_soa {
        warnings.push("Zone missing SOA record".to_string());
    }

    // Check for NS records
    let ns_records: Vec<_> = zone.records.iter()
        .filter_map(|r| match r {
            DnsRecord::Ns { host, .. } => Some(host.clone()),
            _ => None,
        })
        .collect();

    if ns_records.is_empty() {
        warnings.push("Zone has no NS records".to_string());
    }

    // Check for glue records
    for ns in &ns_records {
        if ns.ends_with(&zone.domain) {
            let has_glue = zone.records.iter().any(|r| match r {
                DnsRecord::A { domain, .. } | DnsRecord::Aaaa { domain, .. } => {
                    domain == ns
                }
                _ => false,
            });

            if !has_glue {
                warnings.push(format!("Missing glue record for NS: {}", ns));
            }
        }
    }

    warnings
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_zone() {
        let zone_content = r#"
$ORIGIN example.com.
$TTL 3600

@   IN  SOA ns1.example.com. admin.example.com. (
            2024010101 ; serial
            3600       ; refresh
            1800       ; retry
            604800     ; expire
            86400 )    ; minimum

    IN  NS  ns1.example.com.
    IN  NS  ns2.example.com.
    IN  MX  10 mail.example.com.

www IN  A   192.0.2.1
    IN  AAAA 2001:db8::1
ftp IN  CNAME www
"#;

        let mut parser = ZoneParser::new("example.com");
        let zone = parser.parse_string(zone_content).expect("Failed to parse zone");

        assert_eq!(zone.domain, "example.com");
        assert_eq!(zone.serial, 2024010101);
        assert!(zone.records.len() > 0);

        // Check for specific records
        let has_www_a = zone.records.iter().any(|r| matches!(r, 
            DnsRecord::A { domain, .. } if domain == "www.example.com"
        ));
        assert!(has_www_a);
    }

    #[test]
    fn test_parse_ttl_units() {
        let mut parser = ZoneParser::new("test.com");
        
        assert_eq!(parser.parse_ttl("300").unwrap(), 300);
        assert_eq!(parser.parse_ttl("5m").unwrap(), 300);
        assert_eq!(parser.parse_ttl("1h").unwrap(), 3600);
        assert_eq!(parser.parse_ttl("1d").unwrap(), 86400);
        assert_eq!(parser.parse_ttl("1w").unwrap(), 604800);
    }

    #[test]
    fn test_wildcard_support() {
        let zone_content = r#"
$ORIGIN example.com.
*.subdomain IN A 192.0.2.100
"#;

        let mut parser = ZoneParser::new("example.com");
        let zone = parser.parse_string(zone_content).expect("Failed to parse zone");

        let has_wildcard = zone.records.iter().any(|r| matches!(r,
            DnsRecord::A { domain, .. } if domain == "*.subdomain.example.com"
        ));
        assert!(has_wildcard);
    }

    #[test]
    fn test_txt_record_quotes() {
        let zone_content = r#"
$ORIGIN example.com.
@   IN  TXT "v=spf1 include:_spf.example.com ~all"
"#;

        let mut parser = ZoneParser::new("example.com");
        let zone = parser.parse_string(zone_content).expect("Failed to parse zone");

        let txt_record = zone.records.iter().find_map(|r| match r {
            DnsRecord::Txt { data, .. } => Some(data.clone()),
            _ => None,
        });

        assert_eq!(txt_record.unwrap(), "v=spf1 include:_spf.example.com ~all");
    }
}