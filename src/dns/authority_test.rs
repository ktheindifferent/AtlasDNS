#[cfg(test)]
mod tests {
    use super::super::authority::{Authority, Zone};
    use super::super::protocol::{DnsRecord, QueryType, TransientTtl, ResultCode};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::collections::BTreeSet;

    fn create_test_authority() -> Authority {
        let authority = Authority::new();
        
        // Create a test zone
        let mut zone = Zone::new(
            "example.com".to_string(),
            "ns1.example.com".to_string(),
            "admin.example.com".to_string(),
        );
        zone.serial = 2024010101;
        zone.refresh = 3600;
        zone.retry = 600;
        zone.expire = 86400;
        zone.minimum = 3600;
        
        // Add various records for testing
        let mut records = BTreeSet::new();
        
        // Root domain record (@)
        records.insert(DnsRecord::A {
            domain: "@".to_string(),
            addr: Ipv4Addr::new(192, 168, 1, 1),
            ttl: TransientTtl(3600),
        });
        
        // Specific subdomain records
        records.insert(DnsRecord::A {
            domain: "www.example.com".to_string(),
            addr: Ipv4Addr::new(192, 168, 1, 10),
            ttl: TransientTtl(3600),
        });
        
        records.insert(DnsRecord::A {
            domain: "mail.example.com".to_string(),
            addr: Ipv4Addr::new(192, 168, 1, 20),
            ttl: TransientTtl(3600),
        });
        
        // Wildcard records
        records.insert(DnsRecord::A {
            domain: "*.example.com".to_string(),
            addr: Ipv4Addr::new(192, 168, 1, 100),
            ttl: TransientTtl(3600),
        });
        
        records.insert(DnsRecord::A {
            domain: "*.dev.example.com".to_string(),
            addr: Ipv4Addr::new(192, 168, 1, 200),
            ttl: TransientTtl(3600),
        });
        
        // Additional record types for wildcards
        records.insert(DnsRecord::Aaaa {
            domain: "*.example.com".to_string(),
            addr: "2001:db8::100".parse().unwrap(),
            ttl: TransientTtl(3600),
        });
        
        records.insert(DnsRecord::Txt {
            domain: "*.example.com".to_string(),
            data: "Wildcard TXT record".to_string(),
            ttl: TransientTtl(3600),
        });
        
        records.insert(DnsRecord::Mx {
            domain: "@".to_string(),
            priority: 10,
            host: "mail.example.com".to_string(),
            ttl: TransientTtl(3600),
        });
        
        records.insert(DnsRecord::Cname {
            domain: "alias.example.com".to_string(),
            host: "www.example.com".to_string(),
            ttl: TransientTtl(3600),
        });
        
        zone.records = records;
        
        // Add the zone to authority
        let mut zones = authority.zones.write().unwrap();
        zones.add_zone(zone);
        drop(zones);
        
        authority
    }

    #[test]
    fn test_root_record_resolution() {
        let authority = create_test_authority();
        
        // Query for the root domain
        let result = authority.query("example.com", QueryType::A);
        assert!(result.is_some());
        
        let packet = result.unwrap();
        assert_eq!(packet.header.rescode, ResultCode::NOERROR);
        assert_eq!(packet.answers.len(), 1);
        
        if let DnsRecord::A { domain, addr, .. } = &packet.answers[0] {
            assert_eq!(domain, "example.com");
            assert_eq!(addr, &Ipv4Addr::new(192, 168, 1, 1));
        } else {
            panic!("Expected A record");
        }
    }

    #[test]
    fn test_root_mx_record() {
        let authority = create_test_authority();
        
        // Query for MX record at root
        let result = authority.query("example.com", QueryType::Mx);
        assert!(result.is_some());
        
        let packet = result.unwrap();
        assert_eq!(packet.header.rescode, ResultCode::NOERROR);
        assert_eq!(packet.answers.len(), 1);
        
        if let DnsRecord::Mx { domain, priority, host, .. } = &packet.answers[0] {
            assert_eq!(domain, "example.com");
            assert_eq!(*priority, 10);
            assert_eq!(host, "mail.example.com");
        } else {
            panic!("Expected MX record");
        }
    }

    #[test]
    fn test_exact_match_precedence() {
        let authority = create_test_authority();
        
        // Query for www.example.com should return exact match, not wildcard
        let result = authority.query("www.example.com", QueryType::A);
        assert!(result.is_some());
        
        let packet = result.unwrap();
        assert_eq!(packet.header.rescode, ResultCode::NOERROR);
        assert_eq!(packet.answers.len(), 1);
        
        if let DnsRecord::A { domain, addr, .. } = &packet.answers[0] {
            assert_eq!(domain, "www.example.com");
            assert_eq!(addr, &Ipv4Addr::new(192, 168, 1, 10)); // Exact match IP, not wildcard IP
        } else {
            panic!("Expected A record");
        }
    }

    #[test]
    fn test_wildcard_single_level() {
        let authority = create_test_authority();
        
        // Query for a non-existent subdomain should match wildcard
        let result = authority.query("test.example.com", QueryType::A);
        assert!(result.is_some());
        
        let packet = result.unwrap();
        assert_eq!(packet.header.rescode, ResultCode::NOERROR);
        assert_eq!(packet.answers.len(), 1);
        
        if let DnsRecord::A { domain, addr, .. } = &packet.answers[0] {
            assert_eq!(domain, "test.example.com"); // Domain should match query
            assert_eq!(addr, &Ipv4Addr::new(192, 168, 1, 100)); // Wildcard IP
        } else {
            panic!("Expected A record");
        }
    }

    #[test]
    fn test_wildcard_multiple_types() {
        let authority = create_test_authority();
        
        // Query for AAAA record with wildcard
        let result = authority.query("random.example.com", QueryType::Aaaa);
        assert!(result.is_some());
        
        let packet = result.unwrap();
        assert_eq!(packet.header.rescode, ResultCode::NOERROR);
        assert_eq!(packet.answers.len(), 1);
        
        if let DnsRecord::Aaaa { domain, addr, .. } = &packet.answers[0] {
            assert_eq!(domain, "random.example.com");
            assert_eq!(addr, &"2001:db8::100".parse::<Ipv6Addr>().unwrap());
        } else {
            panic!("Expected AAAA record");
        }
        
        // Query for TXT record with wildcard
        let result = authority.query("another.example.com", QueryType::Txt);
        assert!(result.is_some());
        
        let packet = result.unwrap();
        assert_eq!(packet.header.rescode, ResultCode::NOERROR);
        assert_eq!(packet.answers.len(), 1);
        
        if let DnsRecord::Txt { domain, data, .. } = &packet.answers[0] {
            assert_eq!(domain, "another.example.com");
            assert_eq!(data, "Wildcard TXT record");
        } else {
            panic!("Expected TXT record");
        }
    }

    #[test]
    fn test_wildcard_subdomain() {
        let authority = create_test_authority();
        
        // Query for subdomain under dev should match *.dev.example.com
        let result = authority.query("app1.dev.example.com", QueryType::A);
        assert!(result.is_some());
        
        let packet = result.unwrap();
        assert_eq!(packet.header.rescode, ResultCode::NOERROR);
        assert_eq!(packet.answers.len(), 1);
        
        if let DnsRecord::A { domain, addr, .. } = &packet.answers[0] {
            assert_eq!(domain, "app1.dev.example.com");
            assert_eq!(addr, &Ipv4Addr::new(192, 168, 1, 200)); // *.dev.example.com IP
        } else {
            panic!("Expected A record");
        }
    }

    #[test]
    fn test_no_match_deep_subdomain() {
        let authority = create_test_authority();
        
        // Query for deep subdomain that doesn't match any wildcard
        let result = authority.query("deep.sub.example.com", QueryType::A);
        assert!(result.is_some());
        
        let packet = result.unwrap();
        // Should return NXDOMAIN as *.example.com doesn't match multiple levels
        assert_eq!(packet.header.rescode, ResultCode::NXDOMAIN);
        assert_eq!(packet.answers.len(), 0);
        assert_eq!(packet.authorities.len(), 1); // Should have SOA record
    }

    #[test]
    fn test_cname_exact_match() {
        let authority = create_test_authority();
        
        // Query for CNAME record
        let result = authority.query("alias.example.com", QueryType::Cname);
        assert!(result.is_some());
        
        let packet = result.unwrap();
        assert_eq!(packet.header.rescode, ResultCode::NOERROR);
        assert_eq!(packet.answers.len(), 1);
        
        if let DnsRecord::Cname { domain, host, .. } = &packet.answers[0] {
            assert_eq!(domain, "alias.example.com");
            assert_eq!(host, "www.example.com");
        } else {
            panic!("Expected CNAME record");
        }
    }

    #[test]
    fn test_cname_with_a_query() {
        let authority = create_test_authority();
        
        // Query for A record on CNAME should return CNAME
        let result = authority.query("alias.example.com", QueryType::A);
        assert!(result.is_some());
        
        let packet = result.unwrap();
        assert_eq!(packet.header.rescode, ResultCode::NOERROR);
        assert_eq!(packet.answers.len(), 1);
        
        if let DnsRecord::Cname { domain, host, .. } = &packet.answers[0] {
            assert_eq!(domain, "alias.example.com");
            assert_eq!(host, "www.example.com");
        } else {
            panic!("Expected CNAME record");
        }
    }

    #[test]
    fn test_nxdomain_response() {
        let authority = create_test_authority();
        
        // Query for non-existent record type
        let result = authority.query("www.example.com", QueryType::Mx);
        assert!(result.is_some());
        
        let packet = result.unwrap();
        assert_eq!(packet.header.rescode, ResultCode::NXDOMAIN);
        assert_eq!(packet.answers.len(), 0);
        assert_eq!(packet.authorities.len(), 1);
        
        // Check SOA record in authority section
        if let DnsRecord::Soa { domain, .. } = &packet.authorities[0] {
            assert_eq!(domain, "example.com");
        } else {
            panic!("Expected SOA record in authority section");
        }
    }

    #[test]
    fn test_wildcard_does_not_match_itself() {
        let authority = create_test_authority();
        
        // Querying for the wildcard domain itself should not match
        let result = authority.query("*.example.com", QueryType::A);
        assert!(result.is_some());
        
        let packet = result.unwrap();
        assert_eq!(packet.header.rescode, ResultCode::NXDOMAIN);
        assert_eq!(packet.answers.len(), 0);
    }

    #[test]
    fn test_zone_apex_with_at_notation() {
        let authority = Authority::new();
        
        // Create a zone with @ notation in domain
        let mut zone = Zone::new(
            "test.org".to_string(),
            "ns1.test.org".to_string(),
            "admin.test.org".to_string(),
        );
        
        let mut records = BTreeSet::new();
        
        // Add record with @.test.org notation
        records.insert(DnsRecord::A {
            domain: "@.test.org".to_string(),
            addr: Ipv4Addr::new(10, 0, 0, 1),
            ttl: TransientTtl(3600),
        });
        
        zone.records = records;
        
        let mut zones = authority.zones.write().unwrap();
        zones.add_zone(zone);
        drop(zones);
        
        // Query for zone apex should match
        let result = authority.query("test.org", QueryType::A);
        assert!(result.is_some());
        
        let packet = result.unwrap();
        assert_eq!(packet.header.rescode, ResultCode::NOERROR);
        assert_eq!(packet.answers.len(), 1);
        
        if let DnsRecord::A { domain, addr, .. } = &packet.answers[0] {
            assert_eq!(domain, "test.org");
            assert_eq!(addr, &Ipv4Addr::new(10, 0, 0, 1));
        } else {
            panic!("Expected A record");
        }
    }

    #[test]
    fn test_multiple_wildcards_specificity() {
        let authority = Authority::new();
        
        let mut zone = Zone::new(
            "multi.com".to_string(),
            "ns1.multi.com".to_string(),
            "admin.multi.com".to_string(),
        );
        
        let mut records = BTreeSet::new();
        
        // Add multiple wildcard levels
        records.insert(DnsRecord::A {
            domain: "*.multi.com".to_string(),
            addr: Ipv4Addr::new(1, 1, 1, 1),
            ttl: TransientTtl(3600),
        });
        
        records.insert(DnsRecord::A {
            domain: "*.api.multi.com".to_string(),
            addr: Ipv4Addr::new(2, 2, 2, 2),
            ttl: TransientTtl(3600),
        });
        
        records.insert(DnsRecord::A {
            domain: "v1.api.multi.com".to_string(),
            addr: Ipv4Addr::new(3, 3, 3, 3),
            ttl: TransientTtl(3600),
        });
        
        zone.records = records;
        
        let mut zones = authority.zones.write().unwrap();
        zones.add_zone(zone);
        drop(zones);
        
        // Test exact match takes precedence
        let result = authority.query("v1.api.multi.com", QueryType::A);
        assert!(result.is_some());
        let packet = result.unwrap();
        if let DnsRecord::A { addr, .. } = &packet.answers[0] {
            assert_eq!(addr, &Ipv4Addr::new(3, 3, 3, 3));
        }
        
        // Test more specific wildcard matches
        let result = authority.query("v2.api.multi.com", QueryType::A);
        assert!(result.is_some());
        let packet = result.unwrap();
        if let DnsRecord::A { addr, .. } = &packet.answers[0] {
            assert_eq!(addr, &Ipv4Addr::new(2, 2, 2, 2));
        }
        
        // Test general wildcard matches
        let result = authority.query("www.multi.com", QueryType::A);
        assert!(result.is_some());
        let packet = result.unwrap();
        if let DnsRecord::A { addr, .. } = &packet.answers[0] {
            assert_eq!(addr, &Ipv4Addr::new(1, 1, 1, 1));
        }
    }
}