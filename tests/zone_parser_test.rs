use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use dns_server::dns::zone_parser::{ZoneParser, ParseError, validate_zone};
use dns_server::dns::protocol::{DnsRecord, TransientTtl};
use dns_server::dns::authority::Zone;

#[test]
fn test_parse_example_zone() {
    let content = fs::read_to_string("tests/zone_files/example.com.zone")
        .expect("Failed to read example.com.zone");
    
    let mut parser = ZoneParser::new("example.com");
    let zone = parser.parse_string(&content).expect("Failed to parse zone");
    
    // Verify zone metadata
    assert_eq!(zone.domain, "example.com");
    assert_eq!(zone.serial, 2024010101);
    assert_eq!(zone.refresh, 3600);
    assert_eq!(zone.retry, 1800);
    assert_eq!(zone.expire, 604800);
    assert_eq!(zone.minimum, 86400);
    
    // Check for SOA record
    let soa_count = zone.records.iter()
        .filter(|r| matches!(r, DnsRecord::Soa { .. }))
        .count();
    assert_eq!(soa_count, 1);
    
    // Check for A records
    let a_records: Vec<_> = zone.records.iter()
        .filter_map(|r| match r {
            DnsRecord::A { domain, addr, .. } => Some((domain.clone(), *addr)),
            _ => None
        })
        .collect();
    
    assert!(a_records.iter().any(|(d, _)| d == "www.example.com"));
    assert!(a_records.iter().any(|(d, _)| d == "mail.example.com"));
    assert!(a_records.iter().any(|(d, _)| d == "ns1.example.com"));
    
    // Check for AAAA records
    let aaaa_count = zone.records.iter()
        .filter(|r| matches!(r, DnsRecord::Aaaa { .. }))
        .count();
    assert!(aaaa_count > 0);
    
    // Check for MX records
    let mx_records: Vec<_> = zone.records.iter()
        .filter_map(|r| match r {
            DnsRecord::Mx { priority, host, .. } => Some((*priority, host.clone())),
            _ => None
        })
        .collect();
    
    assert_eq!(mx_records.len(), 2);
    assert!(mx_records.iter().any(|(p, h)| *p == 10 && h == "mail.example.com"));
    
    // Check for CNAME records
    let cname_count = zone.records.iter()
        .filter(|r| matches!(r, DnsRecord::Cname { .. }))
        .count();
    assert!(cname_count > 0);
    
    // Check for TXT records
    let txt_records: Vec<_> = zone.records.iter()
        .filter_map(|r| match r {
            DnsRecord::Txt { domain, data, .. } => Some((domain.clone(), data.clone())),
            _ => None
        })
        .collect();
    
    assert!(txt_records.iter().any(|(_, data)| data.contains("v=spf1")));
    
    // Check for wildcard record
    let wildcard_a = zone.records.iter().any(|r| matches!(r,
        DnsRecord::A { domain, .. } if domain == "*.dev.example.com"
    ));
    assert!(wildcard_a);
}

#[test]
fn test_parse_complex_zone() {
    let content = fs::read_to_string("tests/zone_files/complex.zone")
        .expect("Failed to read complex.zone");
    
    let mut parser = ZoneParser::new("complex.test");
    let zone = parser.parse_string(&content).expect("Failed to parse zone");
    
    // Test TTL parsing with units
    let short_record = zone.records.iter().find(|r| matches!(r,
        DnsRecord::A { domain, .. } if domain == "short.complex.test"
    ));
    assert!(short_record.is_some());
    
    // Test @ symbol resolution
    let apex_record = zone.records.iter().find(|r| matches!(r,
        DnsRecord::A { domain, addr, .. } 
            if domain == "complex.test" && addr == &Ipv4Addr::new(192, 168, 1, 1)
    ));
    assert!(apex_record.is_some());
    
    // Test multi-line TXT record
    let long_txt = zone.records.iter().find_map(|r| match r {
        DnsRecord::Txt { domain, data, .. } if domain == "long.complex.test" => Some(data.clone()),
        _ => None
    });
    assert!(long_txt.is_some());
    let txt_content = long_txt.unwrap();
    assert!(txt_content.contains("very long TXT record"));
    assert!(txt_content.contains("multiple lines"));
    
    // Test wildcards
    let wildcard_count = zone.records.iter()
        .filter(|r| match r {
            DnsRecord::A { domain, .. } => domain.starts_with("*"),
            _ => false
        })
        .count();
    assert!(wildcard_count >= 2);
    
    // Test SRV record
    let srv_record = zone.records.iter().any(|r| matches!(r,
        DnsRecord::Srv { domain, port, .. } 
            if domain == "_ldap._tcp.complex.test" && *port == 389
    ));
    assert!(srv_record);
}

#[test]
fn test_parse_minimal_zone() {
    let content = fs::read_to_string("tests/zone_files/minimal.zone")
        .expect("Failed to read minimal.zone");
    
    let mut parser = ZoneParser::new("minimal.test");
    let zone = parser.parse_string(&content).expect("Failed to parse zone");
    
    // Should have at least SOA, NS, and A records
    assert!(zone.records.len() >= 3);
    
    // Verify SOA exists
    let has_soa = zone.records.iter().any(|r| matches!(r, DnsRecord::Soa { .. }));
    assert!(has_soa);
    
    // Verify NS exists
    let has_ns = zone.records.iter().any(|r| matches!(r, DnsRecord::Ns { .. }));
    assert!(has_ns);
}

#[test]
fn test_ttl_parsing() {
    let mut parser = ZoneParser::new("test.com");
    
    // Test various TTL formats
    assert_eq!(parser.parse_ttl("60").unwrap(), 60);
    assert_eq!(parser.parse_ttl("300").unwrap(), 300);
    assert_eq!(parser.parse_ttl("3600").unwrap(), 3600);
    
    // Test with units
    assert_eq!(parser.parse_ttl("30s").unwrap(), 30);
    assert_eq!(parser.parse_ttl("5m").unwrap(), 300);
    assert_eq!(parser.parse_ttl("2h").unwrap(), 7200);
    assert_eq!(parser.parse_ttl("1d").unwrap(), 86400);
    assert_eq!(parser.parse_ttl("1w").unwrap(), 604800);
    
    // Test case insensitivity
    assert_eq!(parser.parse_ttl("1H").unwrap(), 3600);
    assert_eq!(parser.parse_ttl("2D").unwrap(), 172800);
}

#[test]
fn test_domain_normalization() {
    let content = r#"
$ORIGIN test.com.
@       IN  A   10.0.0.1
www     IN  A   10.0.0.2
ftp.    IN  A   10.0.0.3
mail.test.com.  IN  A   10.0.0.4
"#;
    
    let mut parser = ZoneParser::new("test.com");
    let zone = parser.parse_string(content).expect("Failed to parse zone");
    
    // Check @ is resolved to zone apex
    let apex = zone.records.iter().any(|r| matches!(r,
        DnsRecord::A { domain, .. } if domain == "test.com"
    ));
    assert!(apex);
    
    // Check relative name is expanded
    let www = zone.records.iter().any(|r| matches!(r,
        DnsRecord::A { domain, .. } if domain == "www.test.com"
    ));
    assert!(www);
    
    // Check absolute names are preserved
    let mail = zone.records.iter().any(|r| matches!(r,
        DnsRecord::A { domain, .. } if domain == "mail.test.com"
    ));
    assert!(mail);
}

#[test]
fn test_wildcard_records() {
    let content = r#"
$ORIGIN wildcard.test.
*.sub       IN  A   10.0.0.1
*.*.deep    IN  A   10.0.0.2
*           IN  MX  10 mail.wildcard.test.
"#;
    
    let mut parser = ZoneParser::new("wildcard.test");
    let zone = parser.parse_string(content).expect("Failed to parse zone");
    
    // Check single-level wildcard
    let sub_wildcard = zone.records.iter().any(|r| matches!(r,
        DnsRecord::A { domain, .. } if domain == "*.sub.wildcard.test"
    ));
    assert!(sub_wildcard);
    
    // Check wildcard MX
    let wildcard_mx = zone.records.iter().any(|r| matches!(r,
        DnsRecord::Mx { domain, .. } if domain == "*.wildcard.test"
    ));
    assert!(wildcard_mx);
}

#[test]
fn test_quoted_txt_records() {
    let content = r#"
$ORIGIN txt.test.
@   IN  TXT "simple text"
@   IN  TXT "text with spaces and special chars: @#$%"
@   IN  TXT "multi" "part" "record"
"#;
    
    let mut parser = ZoneParser::new("txt.test");
    let zone = parser.parse_string(content).expect("Failed to parse zone");
    
    let txt_records: Vec<_> = zone.records.iter()
        .filter_map(|r| match r {
            DnsRecord::Txt { data, .. } => Some(data.clone()),
            _ => None
        })
        .collect();
    
    assert_eq!(txt_records.len(), 3);
    assert!(txt_records.iter().any(|d| d == "simple text"));
    assert!(txt_records.iter().any(|d| d.contains("special chars")));
    assert!(txt_records.iter().any(|d| d == "multi part record"));
}

#[test]
fn test_srv_records() {
    let content = r#"
$ORIGIN srv.test.
_http._tcp  IN  SRV 10 60 80 www.srv.test.
_ldap._tcp  IN  SRV 0 0 389 ldap.srv.test.
"#;
    
    let mut parser = ZoneParser::new("srv.test");
    let zone = parser.parse_string(content).expect("Failed to parse zone");
    
    let srv_records: Vec<_> = zone.records.iter()
        .filter_map(|r| match r {
            DnsRecord::Srv { domain, priority, weight, port, host, .. } => {
                Some((domain.clone(), *priority, *weight, *port, host.clone()))
            },
            _ => None
        })
        .collect();
    
    assert_eq!(srv_records.len(), 2);
    
    let http_srv = srv_records.iter()
        .find(|(d, _, _, _, _)| d == "_http._tcp.srv.test");
    assert!(http_srv.is_some());
    let (_, priority, weight, port, _) = http_srv.unwrap();
    assert_eq!(*priority, 10);
    assert_eq!(*weight, 60);
    assert_eq!(*port, 80);
}

#[test]
fn test_zone_validation() {
    // Zone without SOA
    let mut zone = Zone::new("test.com".to_string(), "ns1.test.com".to_string(), "admin.test.com".to_string());
    zone.add_record(&DnsRecord::A {
        domain: "www.test.com".to_string(),
        addr: Ipv4Addr::new(10, 0, 0, 1),
        ttl: TransientTtl(3600),
    });
    
    let warnings = validate_zone(&zone);
    assert!(warnings.iter().any(|w| w.contains("SOA")));
    
    // Zone without NS records
    zone.add_record(&DnsRecord::Soa {
        domain: "test.com".to_string(),
        m_name: "ns1.test.com".to_string(),
        r_name: "admin.test.com".to_string(),
        serial: 1,
        refresh: 3600,
        retry: 1800,
        expire: 604800,
        minimum: 86400,
        ttl: TransientTtl(3600),
    });
    
    let warnings = validate_zone(&zone);
    assert!(warnings.iter().any(|w| w.contains("NS")));
    
    // Zone with NS but missing glue
    zone.add_record(&DnsRecord::Ns {
        domain: "test.com".to_string(),
        host: "ns1.test.com".to_string(),
        ttl: TransientTtl(3600),
    });
    
    let warnings = validate_zone(&zone);
    assert!(warnings.iter().any(|w| w.contains("glue")));
    
    // Add glue record
    zone.add_record(&DnsRecord::A {
        domain: "ns1.test.com".to_string(),
        addr: Ipv4Addr::new(10, 0, 0, 2),
        ttl: TransientTtl(3600),
    });
    
    let warnings = validate_zone(&zone);
    assert!(warnings.is_empty());
}

#[test]
fn test_error_handling() {
    let mut parser = ZoneParser::new("error.test");
    
    // Invalid IP address
    let content = "www IN A 999.999.999.999";
    let result = parser.parse_string(content);
    assert!(matches!(result, Err(ParseError::InvalidIpAddress { .. })));
    
    // Missing field
    let content = "www IN A";
    let result = parser.parse_string(content);
    assert!(matches!(result, Err(ParseError::MissingField { .. })));
    
    // Invalid TTL
    let content = "www invalid IN A 10.0.0.1";
    let result = parser.parse_string(content);
    assert!(matches!(result, Err(ParseError::InvalidRecordType { .. }) | Err(ParseError::InvalidSyntax { .. })));
    
    // Unclosed parentheses
    let content = r#"
@   IN  SOA ns1 admin (
    1 3600 1800
"#;
    let result = parser.parse_string(content);
    assert!(matches!(result, Err(ParseError::InvalidSyntax { .. })));
}

#[test]
fn test_multiline_soa() {
    let content = r#"
$ORIGIN multiline.test.
@   IN  SOA ns1.multiline.test. admin.multiline.test. (
            2024010101  ; serial
            3600        ; refresh
            1800        ; retry
            604800      ; expire
            86400       ; minimum
            )
"#;
    
    let mut parser = ZoneParser::new("multiline.test");
    let zone = parser.parse_string(content).expect("Failed to parse zone");
    
    assert_eq!(zone.serial, 2024010101);
    assert_eq!(zone.refresh, 3600);
    assert_eq!(zone.retry, 1800);
    assert_eq!(zone.expire, 604800);
    assert_eq!(zone.minimum, 86400);
}

#[test]
fn test_caa_records() {
    let content = r#"
$ORIGIN caa.test.
@   IN  CAA 0 issue "letsencrypt.org"
@   IN  CAA 0 issuewild "letsencrypt.org"
@   IN  CAA 128 iodef "mailto:security@caa.test"
"#;
    
    let mut parser = ZoneParser::new("caa.test");
    let zone = parser.parse_string(content).expect("Failed to parse zone");
    
    // CAA records are stored as TXT in our implementation
    let caa_records: Vec<_> = zone.records.iter()
        .filter_map(|r| match r {
            DnsRecord::Txt { data, .. } if data.contains("issue") || data.contains("iodef") => Some(data.clone()),
            _ => None
        })
        .collect();
    
    assert_eq!(caa_records.len(), 3);
    assert!(caa_records.iter().any(|d| d.contains("letsencrypt.org")));
    assert!(caa_records.iter().any(|d| d.contains("iodef")));
}

#[test]
fn test_duplicate_detection() {
    let content = r#"
$ORIGIN dup.test.
www IN A 10.0.0.1
www IN A 10.0.0.1
"#;
    
    let mut parser = ZoneParser::new("dup.test");
    let result = parser.parse_string(content);
    
    assert!(matches!(result, Err(ParseError::DuplicateRecord { .. })));
}