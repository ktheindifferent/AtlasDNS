# RFC-Compliant Zone File Parser

## Overview

The zone file parser provides complete RFC 1035 compliant parsing of DNS zone files, supporting standard BIND format with all common record types and directives.

## Features

### ✅ Supported Record Types
- **A** - IPv4 addresses
- **AAAA** - IPv6 addresses  
- **CNAME** - Canonical names
- **MX** - Mail exchange
- **NS** - Name servers
- **TXT** - Text records
- **SOA** - Start of Authority
- **PTR** - Pointer records
- **SRV** - Service records
- **CAA** - Certificate Authority Authorization

### ✅ Zone File Directives
- **$ORIGIN** - Set the zone origin
- **$TTL** - Set default TTL
- **$INCLUDE** - Include external zone files

### ✅ Advanced Features
- **Relative and absolute domain names**
- **@ symbol for zone apex**
- **Wildcard records (*)**
- **Multi-line records with parentheses**
- **Comments (;)**
- **Quoted strings in TXT records**
- **TTL units (s, m, h, d, w)**
- **Escape sequences in domain names**

### ✅ Error Handling
- **Line number reporting**
- **Detailed error messages**
- **Validation of record formats**
- **Duplicate record detection**
- **Circular include detection**
- **Missing glue record warnings**

## Usage

### Basic Import

```rust
use dns_server::dns::zone_parser::ZoneParser;
use dns_server::dns::authority::Authority;

// Parse zone file string
let mut parser = ZoneParser::new("example.com");
let zone = parser.parse_string(zone_content)?;

// Or import directly into Authority
let authority = Authority::new();
authority.import_zone("example.com", zone_content)?;
```

### Parse from File

```rust
use std::path::Path;

let mut parser = ZoneParser::new("example.com");
let zone = parser.parse_file(Path::new("zones/example.com.zone"))?;
```

### Zone Validation

```rust
use dns_server::dns::zone_parser::validate_zone;

let warnings = validate_zone(&zone);
for warning in warnings {
    println!("Warning: {}", warning);
}
```

## Zone File Format

### Basic Structure

```zone
; Comments start with semicolon
$ORIGIN example.com.    ; Set zone origin
$TTL 3600              ; Default TTL (1 hour)

; SOA Record (required)
@   IN  SOA ns1.example.com. admin.example.com. (
            2024010101  ; serial
            3600        ; refresh
            1800        ; retry
            604800      ; expire
            86400 )     ; minimum

; NS Records
    IN  NS  ns1.example.com.
    IN  NS  ns2.example.com.

; A Records
www IN  A   192.0.2.1
```

### TTL Formats

```zone
; Seconds (default)
www  300   IN  A  192.0.2.1

; With units
short  30s  IN  A  10.0.0.1   ; 30 seconds
quick  5m   IN  A  10.0.0.2   ; 5 minutes
normal 1h   IN  A  10.0.0.3   ; 1 hour
long   1d   IN  A  10.0.0.4   ; 1 day
week   1w   IN  A  10.0.0.5   ; 1 week
```

### Special Syntax

```zone
; Zone apex using @
@       IN  A   192.0.2.1
@       IN  MX  10 mail

; Relative vs absolute names
relative    IN  A  10.0.0.1      ; Becomes relative.example.com
absolute.   IN  A  10.0.0.2      ; Stays as absolute

; Wildcards
*           IN  A  10.0.0.100    ; Matches *.example.com
*.sub       IN  A  10.0.0.101    ; Matches *.sub.example.com

; Multi-line records
long    IN  TXT ( "This is a very long TXT record"
                  " that spans multiple lines"
                  " using parentheses" )
```

### Including Files

```zone
$INCLUDE zones/common-records.zone
$INCLUDE zones/mail-servers.zone
```

## Error Messages

The parser provides detailed error messages with line numbers:

```
Line 5: Invalid IP address: 999.999.999.999
Line 10: Unknown record type: INVALID
Line 15: Missing required field: IPv4 address
Line 20: Duplicate record: A www.example.com 192.0.2.1
Line 25: Circular include detected: zones/include.zone
```

## Performance Considerations

- **Streaming**: Large files are processed line-by-line
- **Memory efficient**: Records stored in BTreeSet
- **Parallel parsing**: Multiple $INCLUDE files can be processed concurrently
- **Validation**: Optional post-parse validation

## Compatibility

The parser is compatible with:
- BIND zone files
- RFC 1035 standard format
- Common DNS server implementations
- Zone transfer (AXFR) output

## Testing

Comprehensive test coverage includes:
- Standard zone files
- Complex multi-record zones
- Edge cases and error conditions
- Real-world production zone files
- Fuzz testing with malformed input

## Example Zone Files

Example zone files are provided in `tests/zone_files/`:
- `example.com.zone` - Standard zone with all record types
- `complex.zone` - Advanced features and edge cases
- `minimal.zone` - Minimum viable zone
- `include_main.zone` - Demonstrates $INCLUDE directive

## Running Examples

```bash
# Run the zone import example
cargo run --example zone_import

# Run parser tests
cargo test zone_parser

# Parse a zone file
cargo run --bin parse_zone -- zones/example.com.zone
```