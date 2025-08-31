//! Example of importing zone files using the RFC-compliant parser
//!
//! Run with: cargo run --example zone_import

use dns_server::dns::zone_parser::{ZoneParser, validate_zone};
use dns_server::dns::authority::Authority;
use std::sync::Arc;

fn main() {
    println!("Zone File Import Example");
    println!("========================\n");

    // Example zone file content
    let zone_content = r#"
; Example DNS Zone File
$ORIGIN example.com.
$TTL 3600  ; Default TTL of 1 hour

; SOA Record - Start of Authority
@   IN  SOA ns1.example.com. admin.example.com. (
            2024010101 ; serial
            3600       ; refresh (1 hour)
            1800       ; retry (30 minutes)
            604800     ; expire (1 week)
            86400 )    ; minimum (1 day)

; Name Servers
        IN  NS  ns1.example.com.
        IN  NS  ns2.example.com.

; Mail Servers  
        IN  MX  10 mail.example.com.
        IN  MX  20 mail2.example.com.

; A Records
@       IN  A   192.0.2.1           ; Zone apex
www     IN  A   192.0.2.2           ; Web server
mail    IN  A   192.0.2.3           ; Mail server
ns1     IN  A   192.0.2.10          ; Name server 1 (glue)
ns2     IN  A   192.0.2.11          ; Name server 2 (glue)

; AAAA Records (IPv6)
@       IN  AAAA    2001:db8::1
www     IN  AAAA    2001:db8::2

; CNAME Records
blog    IN  CNAME   www.example.com.
shop    IN  CNAME   www.example.com.

; TXT Records
@       IN  TXT     "v=spf1 include:_spf.example.com ~all"
_dmarc  IN  TXT     "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"

; SRV Records
_http._tcp  IN  SRV 10 60 80 www.example.com.

; Wildcard Record
*.dev   IN  A   192.0.2.100         ; Catch-all for dev subdomains
"#;

    // Method 1: Direct parsing
    println!("Method 1: Direct Zone Parsing");
    println!("------------------------------");
    
    let mut parser = ZoneParser::new("example.com");
    match parser.parse_string(zone_content) {
        Ok(zone) => {
            println!("✓ Successfully parsed zone: {}", zone.domain);
            println!("  Serial: {}", zone.serial);
            println!("  Records: {}", zone.records.len());
            
            // Validate the zone
            let warnings = validate_zone(&zone);
            if warnings.is_empty() {
                println!("  Validation: ✓ No issues found");
            } else {
                println!("  Validation warnings:");
                for warning in warnings {
                    println!("    ⚠ {}", warning);
                }
            }
        }
        Err(e) => {
            eprintln!("✗ Failed to parse zone: {}", e);
        }
    }

    println!();

    // Method 2: Using Authority's import_zone
    println!("Method 2: Import via Authority");
    println!("-------------------------------");
    
    let authority = Arc::new(Authority::new());
    
    match authority.import_zone("example.com", zone_content) {
        Ok(_) => {
            println!("✓ Successfully imported zone into authority");
            
            // Query the imported zone
            match authority.query_zone("example.com", "www.example.com") {
                Ok(records) => {
                    println!("  Query for www.example.com returned {} records:", records.len());
                    for record in records {
                        println!("    - {:?}", record);
                    }
                }
                Err(e) => {
                    eprintln!("  Failed to query zone: {:?}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("✗ Failed to import zone: {}", e);
        }
    }

    println!();

    // Demonstrate TTL parsing
    println!("TTL Format Examples");
    println!("-------------------");
    
    let ttl_examples = vec![
        ("300", "5 minutes"),
        ("1h", "1 hour"),
        ("1d", "1 day"),
        ("1w", "1 week"),
    ];
    
    let parser = ZoneParser::new("test.com");
    for (ttl_str, description) in ttl_examples {
        match parser.parse_ttl(ttl_str) {
            Ok(seconds) => {
                println!("  {} = {} seconds ({})", ttl_str, seconds, description);
            }
            Err(e) => {
                eprintln!("  Failed to parse '{}': {}", ttl_str, e);
            }
        }
    }

    println!();

    // Demonstrate error handling
    println!("Error Handling Examples");
    println!("-----------------------");
    
    let invalid_zones = vec![
        ("Invalid IP", "www IN A 999.999.999.999"),
        ("Missing field", "www IN A"),
        ("Unknown type", "www IN UNKNOWN 192.0.2.1"),
    ];
    
    for (description, content) in invalid_zones {
        let mut parser = ZoneParser::new("test.com");
        match parser.parse_string(content) {
            Ok(_) => println!("  {}: Unexpectedly succeeded", description),
            Err(e) => println!("  {}: ✓ {}", description, e),
        }
    }

    println!("\n✓ Zone import example completed successfully!");
}