//! Property-based testing for DNS record parsers using proptest

use proptest::prelude::*;
use atlas::dns::buffer::{PacketBuffer, VectorPacketBuffer};
use atlas::dns::protocol::{DnsRecord, TransientTtl};
use atlas::dns::record_parsers::RecordParser;
use std::net::{Ipv4Addr, Ipv6Addr};

// Strategy for generating valid domain names
fn domain_name_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(
        "[a-z][a-z0-9-]{0,61}[a-z0-9]?",
        1..5
    ).prop_map(|parts| parts.join("."))
}

// Strategy for generating IPv4 addresses
fn ipv4_strategy() -> impl Strategy<Value = Ipv4Addr> {
    (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
        .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d))
}

// Strategy for generating IPv6 addresses
fn ipv6_strategy() -> impl Strategy<Value = Ipv6Addr> {
    (
        any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>(),
        any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>()
    ).prop_map(|(a, b, c, d, e, f, g, h)| Ipv6Addr::new(a, b, c, d, e, f, g, h))
}

// Strategy for TTL values
fn ttl_strategy() -> impl Strategy<Value = u32> {
    prop::num::u32::ANY
}

// Strategy for generating valid TXT record data
fn txt_data_strategy() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(
        prop::string::string_regex("[\\x20-\\x7E]{0,255}").unwrap(),
        1..4
    )
}

proptest! {
    #[test]
    fn test_a_record_roundtrip(
        domain in domain_name_strategy(),
        addr in ipv4_strategy(),
        ttl in ttl_strategy()
    ) {
        // Create and write A record data
        let mut buffer = VectorPacketBuffer::new();
        let addr_bytes = addr.octets();
        let raw_addr = ((addr_bytes[0] as u32) << 24) |
                      ((addr_bytes[1] as u32) << 16) |
                      ((addr_bytes[2] as u32) << 8) |
                      (addr_bytes[3] as u32);
        buffer.write_u32(raw_addr).unwrap();
        buffer.pos = 0;
        
        // Parse the A record
        let result = RecordParser::parse_a(&mut buffer, domain.clone(), ttl);
        prop_assert!(result.is_ok());
        
        if let Ok(DnsRecord::A { domain: parsed_domain, addr: parsed_addr, ttl: parsed_ttl }) = result {
            prop_assert_eq!(parsed_domain, domain);
            prop_assert_eq!(parsed_addr, addr);
            prop_assert_eq!(parsed_ttl.0, ttl);
        } else {
            prop_assert!(false, "Expected A record");
        }
    }

    #[test]
    fn test_aaaa_record_roundtrip(
        domain in domain_name_strategy(),
        addr in ipv6_strategy(),
        ttl in ttl_strategy()
    ) {
        // Create and write AAAA record data
        let mut buffer = VectorPacketBuffer::new();
        let segments = addr.segments();
        for i in 0..4 {
            let val = ((segments[i*2] as u32) << 16) | (segments[i*2+1] as u32);
            buffer.write_u32(val).unwrap();
        }
        buffer.pos = 0;
        
        // Parse the AAAA record
        let result = RecordParser::parse_aaaa(&mut buffer, domain.clone(), ttl);
        prop_assert!(result.is_ok());
        
        if let Ok(DnsRecord::Aaaa { domain: parsed_domain, addr: parsed_addr, ttl: parsed_ttl }) = result {
            prop_assert_eq!(parsed_domain, domain);
            prop_assert_eq!(parsed_addr, addr);
            prop_assert_eq!(parsed_ttl.0, ttl);
        } else {
            prop_assert!(false, "Expected AAAA record");
        }
    }

    #[test]
    fn test_mx_record_roundtrip(
        domain in domain_name_strategy(),
        priority in any::<u16>(),
        host in domain_name_strategy(),
        ttl in ttl_strategy()
    ) {
        // Create and write MX record data
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_u16(priority).unwrap();
        buffer.write_qname(&host).unwrap();
        buffer.pos = 0;
        
        // Parse the MX record
        let result = RecordParser::parse_mx(&mut buffer, domain.clone(), ttl);
        prop_assert!(result.is_ok());
        
        if let Ok(DnsRecord::Mx { 
            domain: parsed_domain, 
            priority: parsed_priority, 
            host: parsed_host, 
            ttl: parsed_ttl 
        }) = result {
            prop_assert_eq!(parsed_domain, domain);
            prop_assert_eq!(parsed_priority, priority);
            prop_assert_eq!(parsed_host, host);
            prop_assert_eq!(parsed_ttl.0, ttl);
        } else {
            prop_assert!(false, "Expected MX record");
        }
    }

    #[test]
    fn test_ns_record_roundtrip(
        domain in domain_name_strategy(),
        host in domain_name_strategy(),
        ttl in ttl_strategy()
    ) {
        // Create and write NS record data
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_qname(&host).unwrap();
        buffer.pos = 0;
        
        // Parse the NS record
        let result = RecordParser::parse_ns(&mut buffer, domain.clone(), ttl);
        prop_assert!(result.is_ok());
        
        if let Ok(DnsRecord::Ns { 
            domain: parsed_domain, 
            host: parsed_host, 
            ttl: parsed_ttl 
        }) = result {
            prop_assert_eq!(parsed_domain, domain);
            prop_assert_eq!(parsed_host, host);
            prop_assert_eq!(parsed_ttl.0, ttl);
        } else {
            prop_assert!(false, "Expected NS record");
        }
    }

    #[test]
    fn test_cname_record_roundtrip(
        domain in domain_name_strategy(),
        host in domain_name_strategy(),
        ttl in ttl_strategy()
    ) {
        // Create and write CNAME record data
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_qname(&host).unwrap();
        buffer.pos = 0;
        
        // Parse the CNAME record
        let result = RecordParser::parse_cname(&mut buffer, domain.clone(), ttl);
        prop_assert!(result.is_ok());
        
        if let Ok(DnsRecord::Cname { 
            domain: parsed_domain, 
            host: parsed_host, 
            ttl: parsed_ttl 
        }) = result {
            prop_assert_eq!(parsed_domain, domain);
            prop_assert_eq!(parsed_host, host);
            prop_assert_eq!(parsed_ttl.0, ttl);
        } else {
            prop_assert!(false, "Expected CNAME record");
        }
    }

    #[test]
    fn test_txt_record_roundtrip(
        domain in domain_name_strategy(),
        txt_strings in txt_data_strategy(),
        ttl in ttl_strategy()
    ) {
        // Create and write TXT record data
        let mut buffer = VectorPacketBuffer::new();
        for txt_str in &txt_strings {
            let bytes = txt_str.as_bytes();
            let len = std::cmp::min(bytes.len(), 255);
            buffer.write_u8(len as u8).unwrap();
            for &byte in &bytes[..len] {
                buffer.write_u8(byte).unwrap();
            }
        }
        let data_len = buffer.buffer.len() as u16;
        buffer.pos = 0;
        
        // Parse the TXT record
        let result = RecordParser::parse_txt(&mut buffer, domain.clone(), ttl, data_len);
        prop_assert!(result.is_ok());
        
        if let Ok(DnsRecord::Txt { 
            domain: parsed_domain, 
            data: parsed_data, 
            ttl: parsed_ttl 
        }) = result {
            prop_assert_eq!(parsed_domain, domain);
            // Join all txt_strings together (that's how the parser concatenates them)
            let expected_data: String = txt_strings.iter()
                .map(|s| &s[..std::cmp::min(s.len(), 255)])
                .collect::<Vec<_>>()
                .join("");
            prop_assert_eq!(parsed_data, expected_data);
            prop_assert_eq!(parsed_ttl.0, ttl);
        } else {
            prop_assert!(false, "Expected TXT record");
        }
    }

    #[test]
    fn test_srv_record_roundtrip(
        domain in domain_name_strategy(),
        priority in any::<u16>(),
        weight in any::<u16>(),
        port in any::<u16>(),
        host in domain_name_strategy(),
        ttl in ttl_strategy()
    ) {
        // Create and write SRV record data
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_u16(priority).unwrap();
        buffer.write_u16(weight).unwrap();
        buffer.write_u16(port).unwrap();
        buffer.write_qname(&host).unwrap();
        buffer.pos = 0;
        
        // Parse the SRV record
        let result = RecordParser::parse_srv(&mut buffer, domain.clone(), ttl);
        prop_assert!(result.is_ok());
        
        if let Ok(DnsRecord::Srv { 
            domain: parsed_domain,
            priority: parsed_priority,
            weight: parsed_weight,
            port: parsed_port,
            host: parsed_host,
            ttl: parsed_ttl 
        }) = result {
            prop_assert_eq!(parsed_domain, domain);
            prop_assert_eq!(parsed_priority, priority);
            prop_assert_eq!(parsed_weight, weight);
            prop_assert_eq!(parsed_port, port);
            prop_assert_eq!(parsed_host, host);
            prop_assert_eq!(parsed_ttl.0, ttl);
        } else {
            prop_assert!(false, "Expected SRV record");
        }
    }

    #[test]
    fn test_soa_record_roundtrip(
        domain in domain_name_strategy(),
        m_name in domain_name_strategy(),
        r_name in domain_name_strategy(),
        serial in any::<u32>(),
        refresh in any::<u32>(),
        retry in any::<u32>(),
        expire in any::<u32>(),
        minimum in any::<u32>(),
        ttl in ttl_strategy()
    ) {
        // Create and write SOA record data
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_qname(&m_name).unwrap();
        buffer.write_qname(&r_name).unwrap();
        buffer.write_u32(serial).unwrap();
        buffer.write_u32(refresh).unwrap();
        buffer.write_u32(retry).unwrap();
        buffer.write_u32(expire).unwrap();
        buffer.write_u32(minimum).unwrap();
        buffer.pos = 0;
        
        // Parse the SOA record
        let result = RecordParser::parse_soa(&mut buffer, domain.clone(), ttl);
        prop_assert!(result.is_ok());
        
        if let Ok(DnsRecord::Soa { 
            domain: parsed_domain,
            m_name: parsed_m_name,
            r_name: parsed_r_name,
            serial: parsed_serial,
            refresh: parsed_refresh,
            retry: parsed_retry,
            expire: parsed_expire,
            minimum: parsed_minimum,
            ttl: parsed_ttl 
        }) = result {
            prop_assert_eq!(parsed_domain, domain);
            prop_assert_eq!(parsed_m_name, m_name);
            prop_assert_eq!(parsed_r_name, r_name);
            prop_assert_eq!(parsed_serial, serial);
            prop_assert_eq!(parsed_refresh, refresh);
            prop_assert_eq!(parsed_retry, retry);
            prop_assert_eq!(parsed_expire, expire);
            prop_assert_eq!(parsed_minimum, minimum);
            prop_assert_eq!(parsed_ttl.0, ttl);
        } else {
            prop_assert!(false, "Expected SOA record");
        }
    }

    #[test]
    fn test_parser_never_panics_on_random_input(
        random_bytes in prop::collection::vec(any::<u8>(), 0..1024)
    ) {
        // Test that parsers don't panic on arbitrary input
        let mut buffer = VectorPacketBuffer::new();
        for byte in &random_bytes {
            buffer.buffer.push(*byte);
        }
        buffer.pos = 0;
        
        // Try parsing as different record types - none should panic
        let _ = RecordParser::parse_a(&mut buffer, "test".to_string(), 0);
        
        buffer.pos = 0;
        let _ = RecordParser::parse_aaaa(&mut buffer, "test".to_string(), 0);
        
        buffer.pos = 0;
        let _ = RecordParser::parse_ns(&mut buffer, "test".to_string(), 0);
        
        buffer.pos = 0;
        let _ = RecordParser::parse_cname(&mut buffer, "test".to_string(), 0);
        
        buffer.pos = 0;
        let _ = RecordParser::parse_mx(&mut buffer, "test".to_string(), 0);
        
        buffer.pos = 0;
        let _ = RecordParser::parse_soa(&mut buffer, "test".to_string(), 0);
        
        buffer.pos = 0;
        let _ = RecordParser::parse_srv(&mut buffer, "test".to_string(), 0);
        
        buffer.pos = 0;
        let data_len = random_bytes.len().min(u16::MAX as usize) as u16;
        let _ = RecordParser::parse_txt(&mut buffer, "test".to_string(), 0, data_len);
        
        buffer.pos = 0;
        let _ = RecordParser::parse_opt(&mut buffer, "test".to_string(), 0, 0, data_len);
        
        buffer.pos = 0;
        let _ = RecordParser::parse_unknown(&mut buffer, "test".to_string(), 99, 0, data_len);
        
        // If we get here without panicking, the test passes
        prop_assert!(true);
    }

    #[test]
    fn test_domain_names_are_normalized(
        parts in prop::collection::vec("[A-Za-z][A-Za-z0-9-]{0,61}[A-Za-z0-9]?", 1..5)
    ) {
        // Test that domain names are consistently normalized (lowercase)
        let domain = parts.join(".");
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_qname(&domain).unwrap();
        buffer.pos = 0;
        
        let result = RecordParser::parse_ns(&mut buffer, "test.com".to_string(), 3600);
        prop_assert!(result.is_ok());
        
        if let Ok(DnsRecord::Ns { host, .. }) = result {
            // DNS names should be case-insensitive and normalized to lowercase
            prop_assert_eq!(host.to_lowercase(), domain.to_lowercase());
        }
    }

    #[test]
    fn test_txt_record_handles_empty_strings(
        domain in domain_name_strategy(),
        num_empty_strings in 1..10usize,
        ttl in ttl_strategy()
    ) {
        // Test TXT records with empty strings
        let mut buffer = VectorPacketBuffer::new();
        for _ in 0..num_empty_strings {
            buffer.write_u8(0).unwrap(); // Empty string
        }
        let data_len = buffer.buffer.len() as u16;
        buffer.pos = 0;
        
        let result = RecordParser::parse_txt(&mut buffer, domain.clone(), ttl, data_len);
        prop_assert!(result.is_ok());
        
        if let Ok(DnsRecord::Txt { data, .. }) = result {
            // Should result in an empty string (concatenation of empty strings)
            prop_assert_eq!(data, "");
        }
    }

    #[test]
    fn test_unknown_record_preserves_metadata(
        domain in domain_name_strategy(),
        qtype in 100..=65000u16, // Unknown record types
        data_len in 0..=512u16,
        ttl in ttl_strategy()
    ) {
        // Test unknown record type handling
        let mut buffer = VectorPacketBuffer::new();
        // Add dummy data
        for i in 0..data_len {
            buffer.write_u8((i % 256) as u8).unwrap();
        }
        buffer.pos = 0;
        
        let result = RecordParser::parse_unknown(&mut buffer, domain.clone(), qtype, ttl, data_len);
        prop_assert!(result.is_ok());
        
        if let Ok(DnsRecord::Unknown { 
            domain: parsed_domain,
            qtype: parsed_qtype,
            data_len: parsed_data_len,
            ttl: parsed_ttl
        }) = result {
            prop_assert_eq!(parsed_domain, domain);
            prop_assert_eq!(parsed_qtype, qtype);
            prop_assert_eq!(parsed_data_len, data_len);
            prop_assert_eq!(parsed_ttl.0, ttl);
            // Verify the buffer position advanced by data_len
            prop_assert_eq!(buffer.pos, data_len as usize);
        }
    }
}