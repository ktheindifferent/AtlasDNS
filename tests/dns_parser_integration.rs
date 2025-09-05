//! Integration tests for DNS record parsers with real DNS packet data

use atlas::dns::buffer::{BytePacketBuffer, PacketBuffer};
use atlas::dns::protocol::{DnsPacket, DnsRecord};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Helper to create a DNS packet from raw bytes
fn parse_dns_packet(data: &[u8]) -> Result<DnsPacket, Box<dyn std::error::Error>> {
    let mut buffer = BytePacketBuffer::new();
    for (i, &byte) in data.iter().enumerate() {
        if i < 512 {
            buffer.buf[i] = byte;
        }
    }
    buffer.pos = 0;
    
    DnsPacket::from_buffer(&mut buffer).map_err(|e| e.into())
}

#[test]
fn test_real_a_record_response() {
    // Real DNS response for google.com A record query
    // This is a captured packet from a real DNS query
    let packet_data = vec![
        // DNS Header
        0x12, 0x34, // Transaction ID
        0x81, 0x80, // Flags: Response, Recursion Desired, Recursion Available
        0x00, 0x01, // Questions: 1
        0x00, 0x01, // Answer RRs: 1
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        
        // Question Section
        0x06, b'g', b'o', b'o', b'g', b'l', b'e', // google
        0x03, b'c', b'o', b'm', // com
        0x00,       // Root label
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
        
        // Answer Section
        0xC0, 0x0C, // Name: pointer to offset 12 (google.com)
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x01, 0x2C, // TTL: 300 seconds
        0x00, 0x04, // Data length: 4
        0x8E, 0xFA, 0xBD, 0x0E, // IP: 142.250.189.14
    ];
    
    let packet = parse_dns_packet(&packet_data).expect("Failed to parse packet");
    assert_eq!(packet.answers.len(), 1);
    
    if let DnsRecord::A { domain, addr, ttl } = &packet.answers[0] {
        assert_eq!(domain, "google.com");
        assert_eq!(*addr, Ipv4Addr::new(142, 250, 189, 14));
        assert_eq!(ttl.0, 300);
    } else {
        panic!("Expected A record in answer");
    }
}

#[test]
fn test_real_aaaa_record_response() {
    // Real DNS response for IPv6 query
    let packet_data = vec![
        // DNS Header
        0x45, 0x67, // Transaction ID
        0x81, 0x80, // Flags
        0x00, 0x01, // Questions: 1
        0x00, 0x01, // Answer RRs: 1
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        
        // Question Section
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        0x00, 0x1C, // Type: AAAA
        0x00, 0x01, // Class: IN
        
        // Answer Section
        0xC0, 0x0C, // Name: pointer
        0x00, 0x1C, // Type: AAAA
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x0E, 0x10, // TTL: 3600
        0x00, 0x10, // Data length: 16
        // IPv6 address: 2606:2800:220:1:248:1893:25c8:1946
        0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01,
        0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46,
    ];
    
    let packet = parse_dns_packet(&packet_data).expect("Failed to parse packet");
    assert_eq!(packet.answers.len(), 1);
    
    if let DnsRecord::Aaaa { domain, addr, ttl } = &packet.answers[0] {
        assert_eq!(domain, "example.com");
        assert_eq!(*addr, Ipv6Addr::new(0x2606, 0x2800, 0x0220, 0x0001, 0x0248, 0x1893, 0x25c8, 0x1946));
        assert_eq!(ttl.0, 3600);
    } else {
        panic!("Expected AAAA record in answer");
    }
}

#[test]
fn test_multiple_records_in_response() {
    // Test packet with multiple answer records
    let packet_data = vec![
        // DNS Header
        0xAB, 0xCD, // Transaction ID
        0x81, 0x80, // Flags
        0x00, 0x01, // Questions: 1
        0x00, 0x02, // Answer RRs: 2
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        
        // Question Section
        0x03, b'w', b'w', b'w',
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
        
        // Answer 1: CNAME
        0xC0, 0x0C, // Name: pointer to www.example.com
        0x00, 0x05, // Type: CNAME
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x01, 0x2C, // TTL: 300
        0x00, 0x0D, // Data length
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        
        // Answer 2: A record
        0xC0, 0x2B, // Name: pointer to example.com
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x01, 0x2C, // TTL: 300
        0x00, 0x04, // Data length
        0x5D, 0xB8, 0xD8, 0x22, // IP: 93.184.216.34
    ];
    
    let packet = parse_dns_packet(&packet_data).expect("Failed to parse packet");
    assert_eq!(packet.answers.len(), 2);
    
    // Check CNAME record
    if let DnsRecord::Cname { domain, host, .. } = &packet.answers[0] {
        assert_eq!(domain, "www.example.com");
        assert_eq!(host, "example.com");
    } else {
        panic!("Expected CNAME record as first answer");
    }
    
    // Check A record
    if let DnsRecord::A { domain, addr, .. } = &packet.answers[1] {
        assert_eq!(domain, "example.com");
        assert_eq!(*addr, Ipv4Addr::new(93, 184, 216, 34));
    } else {
        panic!("Expected A record as second answer");
    }
}

#[test]
fn test_mx_record_response() {
    // Test MX record response
    let packet_data = vec![
        // DNS Header
        0x11, 0x22, // Transaction ID
        0x81, 0x80, // Flags
        0x00, 0x01, // Questions: 1
        0x00, 0x02, // Answer RRs: 2
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        
        // Question Section
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        0x00, 0x0F, // Type: MX
        0x00, 0x01, // Class: IN
        
        // Answer 1: MX with priority 10
        0xC0, 0x0C, // Name: pointer
        0x00, 0x0F, // Type: MX
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x0E, 0x10, // TTL: 3600
        0x00, 0x11, // Data length
        0x00, 0x0A, // Priority: 10
        0x04, b'm', b'a', b'i', b'l',
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        
        // Answer 2: MX with priority 20
        0xC0, 0x0C, // Name: pointer
        0x00, 0x0F, // Type: MX
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x0E, 0x10, // TTL: 3600
        0x00, 0x13, // Data length
        0x00, 0x14, // Priority: 20
        0x06, b'b', b'a', b'c', b'k', b'u', b'p',
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
    ];
    
    let packet = parse_dns_packet(&packet_data).expect("Failed to parse packet");
    assert_eq!(packet.answers.len(), 2);
    
    // Check first MX record
    if let DnsRecord::Mx { priority, host, .. } = &packet.answers[0] {
        assert_eq!(*priority, 10);
        assert_eq!(host, "mail.example.com");
    } else {
        panic!("Expected MX record as first answer");
    }
    
    // Check second MX record
    if let DnsRecord::Mx { priority, host, .. } = &packet.answers[1] {
        assert_eq!(*priority, 20);
        assert_eq!(host, "backup.example.com");
    } else {
        panic!("Expected MX record as second answer");
    }
}

#[test]
fn test_txt_record_response() {
    // Test TXT record response
    let packet_data = vec![
        // DNS Header
        0x33, 0x44, // Transaction ID
        0x81, 0x80, // Flags
        0x00, 0x01, // Questions: 1
        0x00, 0x01, // Answer RRs: 1
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        
        // Question Section
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        0x00, 0x10, // Type: TXT
        0x00, 0x01, // Class: IN
        
        // Answer: TXT record
        0xC0, 0x0C, // Name: pointer
        0x00, 0x10, // Type: TXT
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x01, 0x2C, // TTL: 300
        0x00, 0x25, // Data length: 37
        0x24, // String length: 36
        b'v', b'=', b's', b'p', b'f', b'1', b' ',
        b'i', b'n', b'c', b'l', b'u', b'd', b'e', b':', b'_',
        b's', b'p', b'f', b'.', b'g', b'o', b'o', b'g', b'l', b'e', b'.', b'c', b'o', b'm',
        b' ', b'~', b'a', b'l', b'l',
    ];
    
    let packet = parse_dns_packet(&packet_data).expect("Failed to parse packet");
    assert_eq!(packet.answers.len(), 1);
    
    if let DnsRecord::Txt { domain, data, .. } = &packet.answers[0] {
        assert_eq!(domain, "example.com");
        assert_eq!(data, "v=spf1 include:_spf.google.com ~all");
    } else {
        panic!("Expected TXT record in answer");
    }
}

#[test]
fn test_soa_record_response() {
    // Test SOA record response
    let packet_data = vec![
        // DNS Header
        0x55, 0x66, // Transaction ID
        0x81, 0x80, // Flags
        0x00, 0x01, // Questions: 1
        0x00, 0x01, // Answer RRs: 1
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        
        // Question Section
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        0x00, 0x06, // Type: SOA
        0x00, 0x01, // Class: IN
        
        // Answer: SOA record
        0xC0, 0x0C, // Name: pointer
        0x00, 0x06, // Type: SOA
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x15, 0x18, // TTL: 5400
        0x00, 0x26, // Data length
        // MNAME: ns1.example.com
        0x03, b'n', b's', b'1',
        0xC0, 0x0C, // pointer to example.com
        // RNAME: admin.example.com
        0x05, b'a', b'd', b'm', b'i', b'n',
        0xC0, 0x0C, // pointer to example.com
        0x78, 0x49, 0x52, 0x25, // Serial: 2018063525
        0x00, 0x00, 0x1C, 0x20, // Refresh: 7200
        0x00, 0x00, 0x0E, 0x10, // Retry: 3600
        0x00, 0x12, 0x75, 0x00, // Expire: 1209600
        0x00, 0x00, 0x00, 0x78, // Minimum: 120
    ];
    
    let packet = parse_dns_packet(&packet_data).expect("Failed to parse packet");
    assert_eq!(packet.answers.len(), 1);
    
    if let DnsRecord::Soa { domain, m_name, r_name, serial, refresh, retry, expire, minimum, .. } = &packet.answers[0] {
        assert_eq!(domain, "example.com");
        assert_eq!(m_name, "ns1.example.com");
        assert_eq!(r_name, "admin.example.com");
        assert_eq!(*serial, 2018063525);
        assert_eq!(*refresh, 7200);
        assert_eq!(*retry, 3600);
        assert_eq!(*expire, 1209600);
        assert_eq!(*minimum, 120);
    } else {
        panic!("Expected SOA record in answer");
    }
}

#[test]
fn test_ns_record_response() {
    // Test NS record response
    let packet_data = vec![
        // DNS Header
        0x77, 0x88, // Transaction ID
        0x81, 0x80, // Flags
        0x00, 0x01, // Questions: 1
        0x00, 0x02, // Answer RRs: 2
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        
        // Question Section
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        0x00, 0x02, // Type: NS
        0x00, 0x01, // Class: IN
        
        // Answer 1: NS record
        0xC0, 0x0C, // Name: pointer
        0x00, 0x02, // Type: NS
        0x00, 0x01, // Class: IN
        0x00, 0x01, 0x51, 0x80, // TTL: 86400
        0x00, 0x06, // Data length
        0x03, b'n', b's', b'1',
        0xC0, 0x0C, // pointer to example.com
        
        // Answer 2: NS record
        0xC0, 0x0C, // Name: pointer
        0x00, 0x02, // Type: NS
        0x00, 0x01, // Class: IN
        0x00, 0x01, 0x51, 0x80, // TTL: 86400
        0x00, 0x06, // Data length
        0x03, b'n', b's', b'2',
        0xC0, 0x0C, // pointer to example.com
    ];
    
    let packet = parse_dns_packet(&packet_data).expect("Failed to parse packet");
    assert_eq!(packet.answers.len(), 2);
    
    // Check first NS record
    if let DnsRecord::Ns { host, .. } = &packet.answers[0] {
        assert_eq!(host, "ns1.example.com");
    } else {
        panic!("Expected NS record as first answer");
    }
    
    // Check second NS record
    if let DnsRecord::Ns { host, .. } = &packet.answers[1] {
        assert_eq!(host, "ns2.example.com");
    } else {
        panic!("Expected NS record as second answer");
    }
}

#[test]
fn test_srv_record_response() {
    // Test SRV record response
    let packet_data = vec![
        // DNS Header
        0x99, 0xAA, // Transaction ID
        0x81, 0x80, // Flags
        0x00, 0x01, // Questions: 1
        0x00, 0x01, // Answer RRs: 1
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        
        // Question Section: _sip._tcp.example.com
        0x04, b'_', b's', b'i', b'p',
        0x04, b'_', b't', b'c', b'p',
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        0x00, 0x21, // Type: SRV
        0x00, 0x01, // Class: IN
        
        // Answer: SRV record
        0xC0, 0x0C, // Name: pointer
        0x00, 0x21, // Type: SRV
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x0E, 0x10, // TTL: 3600
        0x00, 0x14, // Data length: 20
        0x00, 0x0A, // Priority: 10
        0x00, 0x3C, // Weight: 60
        0x13, 0xC4, // Port: 5060
        0x03, b's', b'i', b'p',
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
    ];
    
    let packet = parse_dns_packet(&packet_data).expect("Failed to parse packet");
    assert_eq!(packet.answers.len(), 1);
    
    if let DnsRecord::Srv { domain, priority, weight, port, host, .. } = &packet.answers[0] {
        assert_eq!(domain, "_sip._tcp.example.com");
        assert_eq!(*priority, 10);
        assert_eq!(*weight, 60);
        assert_eq!(*port, 5060);
        assert_eq!(host, "sip.example.com");
    } else {
        panic!("Expected SRV record in answer");
    }
}

#[test]
fn test_edns0_opt_record() {
    // Test packet with EDNS0 OPT record in additional section
    let packet_data = vec![
        // DNS Header
        0xBB, 0xCC, // Transaction ID
        0x81, 0x80, // Flags
        0x00, 0x01, // Questions: 1
        0x00, 0x01, // Answer RRs: 1
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x01, // Additional RRs: 1
        
        // Question Section
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
        
        // Answer: A record
        0xC0, 0x0C, // Name: pointer
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x01, 0x2C, // TTL: 300
        0x00, 0x04, // Data length
        0x5D, 0xB8, 0xD8, 0x22, // IP: 93.184.216.34
        
        // Additional: OPT record
        0x00,       // Name: root domain
        0x00, 0x29, // Type: OPT
        0x10, 0x00, // Class: 4096 (UDP payload size)
        0x00, 0x00, 0x00, 0x00, // TTL: Extended RCODE and flags
        0x00, 0x00, // Data length: 0
    ];
    
    let packet = parse_dns_packet(&packet_data).expect("Failed to parse packet");
    assert_eq!(packet.answers.len(), 1);
    assert_eq!(packet.resources.len(), 1);
    
    // Check OPT record
    if let DnsRecord::Opt { packet_len, flags, .. } = &packet.resources[0] {
        assert_eq!(*packet_len, 4096);
        assert_eq!(*flags, 0);
    } else {
        panic!("Expected OPT record in additional section");
    }
}

#[test]
fn test_compressed_names_multiple_pointers() {
    // Test complex compression with multiple pointers
    let packet_data = vec![
        // DNS Header
        0xDD, 0xEE, // Transaction ID
        0x81, 0x80, // Flags
        0x00, 0x01, // Questions: 1
        0x00, 0x03, // Answer RRs: 3
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        
        // Question: mail.example.com
        0x04, b'm', b'a', b'i', b'l',
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
        
        // Answer 1: mail.example.com A record
        0xC0, 0x0C, // Name: pointer to mail.example.com
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x01, 0x2C, // TTL: 300
        0x00, 0x04, // Data length
        0xC0, 0xA8, 0x00, 0x01, // IP: 192.168.0.1
        
        // Answer 2: example.com A record
        0xC0, 0x11, // Name: pointer to example.com
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x01, 0x2C, // TTL: 300
        0x00, 0x04, // Data length
        0xC0, 0xA8, 0x00, 0x02, // IP: 192.168.0.2
        
        // Answer 3: www.example.com CNAME to example.com
        0x03, b'w', b'w', b'w',
        0xC0, 0x11, // pointer to example.com
        0x00, 0x05, // Type: CNAME
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x01, 0x2C, // TTL: 300
        0x00, 0x02, // Data length
        0xC0, 0x11, // CNAME target: pointer to example.com
    ];
    
    let packet = parse_dns_packet(&packet_data).expect("Failed to parse packet");
    assert_eq!(packet.answers.len(), 3);
    
    // Verify all three records parsed correctly with compression
    if let DnsRecord::A { domain, addr, .. } = &packet.answers[0] {
        assert_eq!(domain, "mail.example.com");
        assert_eq!(*addr, Ipv4Addr::new(192, 168, 0, 1));
    }
    
    if let DnsRecord::A { domain, addr, .. } = &packet.answers[1] {
        assert_eq!(domain, "example.com");
        assert_eq!(*addr, Ipv4Addr::new(192, 168, 0, 2));
    }
    
    if let DnsRecord::Cname { domain, host, .. } = &packet.answers[2] {
        assert_eq!(domain, "www.example.com");
        assert_eq!(host, "example.com");
    }
}

#[test]
fn test_malformed_packet_handling() {
    // Test that malformed packets don't cause panics
    
    // Truncated packet
    let truncated = vec![0x12, 0x34, 0x81, 0x80];
    let result = parse_dns_packet(&truncated);
    assert!(result.is_err());
    
    // Packet with invalid compression pointer
    let invalid_pointer = vec![
        0x12, 0x34, 0x81, 0x80,
        0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        // Question with invalid compression
        0xC0, 0xFF, // Invalid pointer offset
        0x00, 0x01, 0x00, 0x01,
    ];
    let result = parse_dns_packet(&invalid_pointer);
    assert!(result.is_err());
}

#[test]
fn test_maximum_packet_size() {
    // Test handling of maximum size DNS packet (512 bytes for standard UDP)
    let mut packet_data = vec![
        // DNS Header
        0xFF, 0xFF, // Transaction ID
        0x81, 0x80, // Flags
        0x00, 0x01, // Questions: 1
        0x00, 0x01, // Answer RRs: 1
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        
        // Question
        0x04, b't', b'e', b's', b't',
        0x00,
        0x00, 0x10, // Type: TXT
        0x00, 0x01, // Class: IN
        
        // Answer: TXT record with maximum data
        0xC0, 0x0C, // Name: pointer
        0x00, 0x10, // Type: TXT
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x01, 0x2C, // TTL: 300
        0x01, 0xE5, // Data length: 485 bytes (to reach 512 total)
    ];
    
    // Add TXT data strings to fill the packet
    let remaining = 512 - packet_data.len();
    let mut txt_data = Vec::new();
    let mut bytes_left = remaining;
    
    while bytes_left > 0 {
        let chunk_size = std::cmp::min(255, bytes_left - 1); // -1 for length byte
        txt_data.push(chunk_size as u8);
        for _ in 0..chunk_size {
            txt_data.push(b'X');
        }
        bytes_left -= chunk_size + 1;
    }
    
    packet_data.extend(txt_data);
    
    // Should parse without error
    let result = parse_dns_packet(&packet_data);
    assert!(result.is_ok());
    
    let packet = result.unwrap();
    assert_eq!(packet.answers.len(), 1);
    
    if let DnsRecord::Txt { data, .. } = &packet.answers[0] {
        assert!(!data.is_empty());
    }
}