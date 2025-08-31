#[cfg(test)]
mod tests {
    use super::super::zone_parser::{ZoneParser, validate_zone};
    use super::super::protocol::{DnsRecord, TransientTtl};
    use super::super::authority::Zone;
    use std::net::Ipv4Addr;

    #[test]
    fn test_basic_zone_parsing() {
        let zone_content = r#"
$ORIGIN example.com.
$TTL 3600

@   IN  SOA ns1.example.com. admin.example.com. (
            2024010101
            3600
            1800
            604800
            86400 )

    IN  NS  ns1.example.com.
    IN  NS  ns2.example.com.

www IN  A   192.0.2.1
"#;

        let mut parser = ZoneParser::new("example.com");
        let zone = parser.parse_string(zone_content).expect("Failed to parse zone");

        assert_eq!(zone.domain, "example.com");
        assert_eq!(zone.serial, 2024010101);

        // Check for A record
        let has_www = zone.records.iter().any(|r| matches!(r,
            DnsRecord::A { domain, .. } if domain == "www.example.com"
        ));
        assert!(has_www);
    }

    #[test]
    fn test_ttl_parsing() {
        let parser = ZoneParser::new("test.com");
        
        assert_eq!(parser.parse_ttl("300").unwrap(), 300);
        assert_eq!(parser.parse_ttl("5m").unwrap(), 300);
        assert_eq!(parser.parse_ttl("1h").unwrap(), 3600);
        assert_eq!(parser.parse_ttl("1d").unwrap(), 86400);
    }

    #[test]
    fn test_wildcard_and_apex() {
        let zone_content = r#"
$ORIGIN test.com.
@       IN  A   10.0.0.1
*.sub   IN  A   10.0.0.2
"#;

        let mut parser = ZoneParser::new("test.com");
        let zone = parser.parse_string(zone_content).expect("Failed to parse zone");

        // Check apex record
        let has_apex = zone.records.iter().any(|r| matches!(r,
            DnsRecord::A { domain, .. } if domain == "test.com"
        ));
        assert!(has_apex);

        // Check wildcard
        let has_wildcard = zone.records.iter().any(|r| matches!(r,
            DnsRecord::A { domain, .. } if domain == "*.sub.test.com"
        ));
        assert!(has_wildcard);
    }

    #[test]
    fn test_zone_validation() {
        let mut zone = Zone::new(
            "test.com".to_string(),
            "ns1.test.com".to_string(),
            "admin.test.com".to_string()
        );
        
        // Empty zone should have warnings
        let warnings = validate_zone(&zone);
        assert!(!warnings.is_empty());
        
        // Add SOA
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
        
        // Add NS
        zone.add_record(&DnsRecord::Ns {
            domain: "test.com".to_string(),
            host: "ns1.external.com".to_string(),
            ttl: TransientTtl(3600),
        });
        
        let warnings = validate_zone(&zone);
        // Should have no warnings with external NS
        assert!(warnings.is_empty());
    }
}