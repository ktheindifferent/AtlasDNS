//! DNS Record parsing implementations

use std::net::{Ipv4Addr, Ipv6Addr};
use crate::dns::buffer::PacketBuffer;
use crate::dns::protocol::{DnsRecord, TransientTtl, ProtocolError};

type Result<T> = std::result::Result<T, ProtocolError>;

/// Parser functions for each DNS record type
pub struct RecordParser;

impl RecordParser {
    /// Parse an A record (IPv4 address)
    pub fn parse_a<T: PacketBuffer>(
        buffer: &mut T,
        domain: String,
        ttl: u32,
    ) -> Result<DnsRecord> {
        let raw_addr = buffer.read_u32()?;
        let addr = Ipv4Addr::new(
            ((raw_addr >> 24) & 0xFF) as u8,
            ((raw_addr >> 16) & 0xFF) as u8,
            ((raw_addr >> 8) & 0xFF) as u8,
            (raw_addr & 0xFF) as u8,
        );

        Ok(DnsRecord::A {
            domain,
            addr,
            ttl: TransientTtl(ttl),
        })
    }

    /// Parse an AAAA record (IPv6 address)
    pub fn parse_aaaa<T: PacketBuffer>(
        buffer: &mut T,
        domain: String,
        ttl: u32,
    ) -> Result<DnsRecord> {
        let raw_addr1 = buffer.read_u32()?;
        let raw_addr2 = buffer.read_u32()?;
        let raw_addr3 = buffer.read_u32()?;
        let raw_addr4 = buffer.read_u32()?;
        
        let addr = Ipv6Addr::new(
            ((raw_addr1 >> 16) & 0xFFFF) as u16,
            (raw_addr1 & 0xFFFF) as u16,
            ((raw_addr2 >> 16) & 0xFFFF) as u16,
            (raw_addr2 & 0xFFFF) as u16,
            ((raw_addr3 >> 16) & 0xFFFF) as u16,
            (raw_addr3 & 0xFFFF) as u16,
            ((raw_addr4 >> 16) & 0xFFFF) as u16,
            (raw_addr4 & 0xFFFF) as u16,
        );

        Ok(DnsRecord::Aaaa {
            domain,
            addr,
            ttl: TransientTtl(ttl),
        })
    }

    /// Parse an NS record (Name Server)
    pub fn parse_ns<T: PacketBuffer>(
        buffer: &mut T,
        domain: String,
        ttl: u32,
    ) -> Result<DnsRecord> {
        let mut host = String::new();
        buffer.read_qname(&mut host)?;

        Ok(DnsRecord::Ns {
            domain,
            host,
            ttl: TransientTtl(ttl),
        })
    }

    /// Parse a CNAME record (Canonical Name)
    pub fn parse_cname<T: PacketBuffer>(
        buffer: &mut T,
        domain: String,
        ttl: u32,
    ) -> Result<DnsRecord> {
        let mut host = String::new();
        buffer.read_qname(&mut host)?;

        Ok(DnsRecord::Cname {
            domain,
            host,
            ttl: TransientTtl(ttl),
        })
    }

    /// Parse an SOA record (Start of Authority)
    pub fn parse_soa<T: PacketBuffer>(
        buffer: &mut T,
        domain: String,
        ttl: u32,
    ) -> Result<DnsRecord> {
        let mut m_name = String::new();
        buffer.read_qname(&mut m_name)?;

        let mut r_name = String::new();
        buffer.read_qname(&mut r_name)?;

        let serial = buffer.read_u32()?;
        let refresh = buffer.read_u32()?;
        let retry = buffer.read_u32()?;
        let expire = buffer.read_u32()?;
        let minimum = buffer.read_u32()?;

        Ok(DnsRecord::Soa {
            domain,
            m_name,
            r_name,
            serial,
            refresh,
            retry,
            expire,
            minimum,
            ttl: TransientTtl(ttl),
        })
    }

    /// Parse an MX record (Mail Exchange)
    pub fn parse_mx<T: PacketBuffer>(
        buffer: &mut T,
        domain: String,
        ttl: u32,
    ) -> Result<DnsRecord> {
        let priority = buffer.read_u16()?;
        let mut host = String::new();
        buffer.read_qname(&mut host)?;

        Ok(DnsRecord::Mx {
            domain,
            priority,
            host,
            ttl: TransientTtl(ttl),
        })
    }

    /// Parse a TXT record (Text)
    pub fn parse_txt<T: PacketBuffer>(
        buffer: &mut T,
        domain: String,
        ttl: u32,
        data_len: u16,
    ) -> Result<DnsRecord> {
        let mut data = String::new();
        
        let cur_pos = buffer.pos();
        let target_pos = cur_pos + data_len as usize;
        
        while buffer.pos() < target_pos {
            let len = buffer.read()? as usize;
            let pos = buffer.pos();
            let str_buffer = buffer.get_range(pos, len)?;
            data.push_str(&String::from_utf8_lossy(str_buffer));
            buffer.step(len)?;
        }

        Ok(DnsRecord::Txt {
            domain,
            data,
            ttl: TransientTtl(ttl),
        })
    }

    /// Parse an SRV record (Service)
    pub fn parse_srv<T: PacketBuffer>(
        buffer: &mut T,
        domain: String,
        ttl: u32,
    ) -> Result<DnsRecord> {
        let priority = buffer.read_u16()?;
        let weight = buffer.read_u16()?;
        let port = buffer.read_u16()?;
        
        let mut host = String::new();
        buffer.read_qname(&mut host)?;

        Ok(DnsRecord::Srv {
            domain,
            priority,
            weight,
            port,
            host,
            ttl: TransientTtl(ttl),
        })
    }

    /// Parse an OPT record (EDNS0)
    pub fn parse_opt<T: PacketBuffer>(
        buffer: &mut T,
        _domain: String,
        class: u16,
        ttl: u32,
        data_len: u16,
    ) -> Result<DnsRecord> {
        let mut data = String::new();
        
        for _ in 0..data_len {
            data.push_str(&format!("{:02X} ", buffer.read()?));
        }

        Ok(DnsRecord::Opt {
            packet_len: class,
            flags: ttl,
            data,
        })
    }

    /// Parse an Unknown record type
    pub fn parse_unknown<T: PacketBuffer>(
        buffer: &mut T,
        domain: String,
        qtype_num: u16,
        ttl: u32,
        data_len: u16,
    ) -> Result<DnsRecord> {
        buffer.step(data_len as usize)?;

        Ok(DnsRecord::Unknown {
            domain,
            qtype: qtype_num,
            data_len,
            ttl: TransientTtl(ttl),
        })
    }
}

// Tests for record parsers
#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::buffer::{BytePacketBuffer, VectorPacketBuffer};
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Helper function to create a buffer with test data
    fn create_buffer_with_data(data: &[u8]) -> BytePacketBuffer {
        let mut buffer = BytePacketBuffer::new();
        for (i, &byte) in data.iter().enumerate() {
            buffer.buf[i] = byte;
        }
        buffer.pos = 0;
        buffer
    }

    // Helper function to create a vector buffer with test data
    fn create_vector_buffer_with_data(data: &[u8]) -> VectorPacketBuffer {
        let mut buffer = VectorPacketBuffer::new();
        for &byte in data {
            buffer.buffer.push(byte);
        }
        buffer.pos = 0;
        buffer
    }

    #[test]
    fn test_parse_a_record() {
        // Test data for A record: 192.168.1.1
        let data = [0xC0, 0xA8, 0x01, 0x01];
        let mut buffer = create_buffer_with_data(&data);
        
        let result = RecordParser::parse_a(&mut buffer, "example.com".to_string(), 3600);
        assert!(result.is_ok());
        
        if let Ok(DnsRecord::A { domain, addr, ttl }) = result {
            assert_eq!(domain, "example.com");
            assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 1));
            assert_eq!(ttl.0, 3600);
        } else {
            panic!("Expected A record but got: {:?}", result);
        }
    }

    #[test]
    fn test_parse_a_record_edge_cases() {
        // Test minimum IPv4: 0.0.0.0
        let data = [0x00, 0x00, 0x00, 0x00];
        let mut buffer = create_buffer_with_data(&data);
        let result = RecordParser::parse_a(&mut buffer, "min.test".to_string(), 0);
        assert!(result.is_ok());
        if let Ok(DnsRecord::A { addr, .. }) = result {
            assert_eq!(addr, Ipv4Addr::new(0, 0, 0, 0));
        }

        // Test maximum IPv4: 255.255.255.255
        let data = [0xFF, 0xFF, 0xFF, 0xFF];
        let mut buffer = create_buffer_with_data(&data);
        let result = RecordParser::parse_a(&mut buffer, "max.test".to_string(), u32::MAX);
        assert!(result.is_ok());
        if let Ok(DnsRecord::A { addr, ttl, .. }) = result {
            assert_eq!(addr, Ipv4Addr::new(255, 255, 255, 255));
            assert_eq!(ttl.0, u32::MAX);
        }
    }

    #[test]
    fn test_parse_aaaa_record() {
        // Test data for AAAA record: 2001:db8::1
        let data = [
            0x20, 0x01, 0x0d, 0xb8,  // 2001:0db8
            0x00, 0x00, 0x00, 0x00,  // 0000:0000
            0x00, 0x00, 0x00, 0x00,  // 0000:0000
            0x00, 0x00, 0x00, 0x01,  // 0000:0001
        ];
        let mut buffer = create_buffer_with_data(&data);
        
        let result = RecordParser::parse_aaaa(&mut buffer, "ipv6.example.com".to_string(), 7200);
        assert!(result.is_ok());
        
        if let Ok(DnsRecord::Aaaa { domain, addr, ttl }) = result {
            assert_eq!(domain, "ipv6.example.com");
            assert_eq!(addr, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
            assert_eq!(ttl.0, 7200);
        } else {
            panic!("Expected AAAA record but got: {:?}", result);
        }
    }

    #[test]
    fn test_parse_aaaa_record_edge_cases() {
        // Test all zeros IPv6
        let data = [0; 16];
        let mut buffer = create_buffer_with_data(&data);
        let result = RecordParser::parse_aaaa(&mut buffer, "zero.ipv6".to_string(), 300);
        assert!(result.is_ok());
        if let Ok(DnsRecord::Aaaa { addr, .. }) = result {
            assert_eq!(addr, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        }

        // Test all ones IPv6
        let data = [0xFF; 16];
        let mut buffer = create_buffer_with_data(&data);
        let result = RecordParser::parse_aaaa(&mut buffer, "max.ipv6".to_string(), 86400);
        assert!(result.is_ok());
        if let Ok(DnsRecord::Aaaa { addr, .. }) = result {
            assert_eq!(addr, Ipv6Addr::new(0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF));
        }
    }

    #[test]
    fn test_parse_ns_record() {
        // Create NS record data: ns1.example.com
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_qname(&"ns1.example.com".to_string()).unwrap();
        buffer.pos = 0;
        
        let result = RecordParser::parse_ns(&mut buffer, "example.com".to_string(), 86400);
        assert!(result.is_ok());
        
        if let Ok(DnsRecord::Ns { domain, host, ttl }) = result {
            assert_eq!(domain, "example.com");
            assert_eq!(host, "ns1.example.com");
            assert_eq!(ttl.0, 86400);
        } else {
            panic!("Expected NS record but got: {:?}", result);
        }
    }

    #[test]
    fn test_parse_cname_record() {
        // Create CNAME record data: www.example.com -> example.com
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_qname(&"example.com".to_string()).unwrap();
        buffer.pos = 0;
        
        let result = RecordParser::parse_cname(&mut buffer, "www.example.com".to_string(), 3600);
        assert!(result.is_ok());
        
        if let Ok(DnsRecord::Cname { domain, host, ttl }) = result {
            assert_eq!(domain, "www.example.com");
            assert_eq!(host, "example.com");
            assert_eq!(ttl.0, 3600);
        } else {
            panic!("Expected CNAME record but got: {:?}", result);
        }
    }

    #[test]
    fn test_parse_mx_record() {
        // Create MX record data: priority 10, mail.example.com
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_u16(10).unwrap(); // priority
        buffer.write_qname(&"mail.example.com".to_string()).unwrap();
        buffer.pos = 0;
        
        let result = RecordParser::parse_mx(&mut buffer, "example.com".to_string(), 3600);
        assert!(result.is_ok());
        
        if let Ok(DnsRecord::Mx { domain, priority, host, ttl }) = result {
            assert_eq!(domain, "example.com");
            assert_eq!(priority, 10);
            assert_eq!(host, "mail.example.com");
            assert_eq!(ttl.0, 3600);
        } else {
            panic!("Expected MX record but got: {:?}", result);
        }
    }

    #[test]
    fn test_parse_mx_record_edge_cases() {
        // Test minimum priority
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_u16(0).unwrap();
        buffer.write_qname(&"highest.priority.com".to_string()).unwrap();
        buffer.pos = 0;
        
        let result = RecordParser::parse_mx(&mut buffer, "test.com".to_string(), 3600);
        assert!(result.is_ok());
        if let Ok(DnsRecord::Mx { priority, .. }) = result {
            assert_eq!(priority, 0);
        }

        // Test maximum priority
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_u16(65535).unwrap();
        buffer.write_qname(&"lowest.priority.com".to_string()).unwrap();
        buffer.pos = 0;
        
        let result = RecordParser::parse_mx(&mut buffer, "test.com".to_string(), 3600);
        assert!(result.is_ok());
        if let Ok(DnsRecord::Mx { priority, .. }) = result {
            assert_eq!(priority, 65535);
        }
    }

    #[test]
    fn test_parse_soa_record() {
        // Create SOA record data
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_qname(&"ns1.example.com".to_string()).unwrap(); // mname
        buffer.write_qname(&"admin.example.com".to_string()).unwrap(); // rname
        buffer.write_u32(2021010101).unwrap(); // serial
        buffer.write_u32(7200).unwrap(); // refresh
        buffer.write_u32(3600).unwrap(); // retry
        buffer.write_u32(1209600).unwrap(); // expire
        buffer.write_u32(86400).unwrap(); // minimum
        buffer.pos = 0;
        
        let result = RecordParser::parse_soa(&mut buffer, "example.com".to_string(), 86400);
        assert!(result.is_ok());
        
        if let Ok(DnsRecord::Soa { domain, m_name, r_name, serial, refresh, retry, expire, minimum, ttl }) = result {
            assert_eq!(domain, "example.com");
            assert_eq!(m_name, "ns1.example.com");
            assert_eq!(r_name, "admin.example.com");
            assert_eq!(serial, 2021010101);
            assert_eq!(refresh, 7200);
            assert_eq!(retry, 3600);
            assert_eq!(expire, 1209600);
            assert_eq!(minimum, 86400);
            assert_eq!(ttl.0, 86400);
        } else {
            panic!("Expected SOA record but got: {:?}", result);
        }
    }

    #[test]
    fn test_parse_soa_record_edge_cases() {
        // Test with maximum values
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_qname(&"a".to_string()).unwrap();
        buffer.write_qname(&"b".to_string()).unwrap();
        buffer.write_u32(u32::MAX).unwrap();
        buffer.write_u32(u32::MAX).unwrap();
        buffer.write_u32(u32::MAX).unwrap();
        buffer.write_u32(u32::MAX).unwrap();
        buffer.write_u32(u32::MAX).unwrap();
        buffer.pos = 0;
        
        let result = RecordParser::parse_soa(&mut buffer, "test".to_string(), u32::MAX);
        assert!(result.is_ok());
        if let Ok(DnsRecord::Soa { serial, refresh, retry, expire, minimum, ttl, .. }) = result {
            assert_eq!(serial, u32::MAX);
            assert_eq!(refresh, u32::MAX);
            assert_eq!(retry, u32::MAX);
            assert_eq!(expire, u32::MAX);
            assert_eq!(minimum, u32::MAX);
            assert_eq!(ttl.0, u32::MAX);
        }
    }

    #[test]
    fn test_parse_txt_record() {
        // Create TXT record data
        let mut buffer = VectorPacketBuffer::new();
        let txt_data = "v=spf1 include:_spf.google.com ~all";
        buffer.write_u8(txt_data.len() as u8).unwrap();
        for byte in txt_data.bytes() {
            buffer.write_u8(byte).unwrap();
        }
        let data_len = buffer.buffer.len() as u16;
        buffer.pos = 0;
        
        let result = RecordParser::parse_txt(&mut buffer, "example.com".to_string(), 300, data_len);
        assert!(result.is_ok());
        
        if let Ok(DnsRecord::Txt { domain, data, ttl }) = result {
            assert_eq!(domain, "example.com");
            assert_eq!(data, txt_data);
            assert_eq!(ttl.0, 300);
        } else {
            panic!("Expected TXT record but got: {:?}", result);
        }
    }

    #[test]
    fn test_parse_txt_record_multiple_strings() {
        // TXT records can contain multiple strings
        let mut buffer = VectorPacketBuffer::new();
        let txt1 = "first part";
        let txt2 = "second part";
        buffer.write_u8(txt1.len() as u8).unwrap();
        for byte in txt1.bytes() {
            buffer.write_u8(byte).unwrap();
        }
        buffer.write_u8(txt2.len() as u8).unwrap();
        for byte in txt2.bytes() {
            buffer.write_u8(byte).unwrap();
        }
        let data_len = buffer.buffer.len() as u16;
        buffer.pos = 0;
        
        let result = RecordParser::parse_txt(&mut buffer, "multi.txt".to_string(), 300, data_len);
        assert!(result.is_ok());
        
        if let Ok(DnsRecord::Txt { data, .. }) = result {
            assert_eq!(data, "first partsecond part");
        }
    }

    #[test]
    fn test_parse_txt_record_empty() {
        // Test empty TXT record
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_u8(0).unwrap(); // Empty string
        let data_len = 1;
        buffer.pos = 0;
        
        let result = RecordParser::parse_txt(&mut buffer, "empty.txt".to_string(), 300, data_len);
        assert!(result.is_ok());
        
        if let Ok(DnsRecord::Txt { data, .. }) = result {
            assert_eq!(data, "");
        }
    }

    #[test]
    fn test_parse_txt_record_max_length() {
        // Test maximum length TXT string (255 bytes per string)
        let mut buffer = VectorPacketBuffer::new();
        let long_string = "a".repeat(255);
        buffer.write_u8(255).unwrap();
        for byte in long_string.bytes() {
            buffer.write_u8(byte).unwrap();
        }
        let data_len = 256;
        buffer.pos = 0;
        
        let result = RecordParser::parse_txt(&mut buffer, "long.txt".to_string(), 300, data_len);
        assert!(result.is_ok());
        
        if let Ok(DnsRecord::Txt { data, .. }) = result {
            assert_eq!(data.len(), 255);
            assert!(data.chars().all(|c| c == 'a'));
        }
    }

    #[test]
    fn test_parse_srv_record() {
        // Create SRV record data
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_u16(10).unwrap(); // priority
        buffer.write_u16(60).unwrap(); // weight
        buffer.write_u16(5060).unwrap(); // port
        buffer.write_qname(&"sip.example.com".to_string()).unwrap();
        buffer.pos = 0;
        
        let result = RecordParser::parse_srv(&mut buffer, "_sip._tcp.example.com".to_string(), 86400);
        assert!(result.is_ok());
        
        if let Ok(DnsRecord::Srv { domain, priority, weight, port, host, ttl }) = result {
            assert_eq!(domain, "_sip._tcp.example.com");
            assert_eq!(priority, 10);
            assert_eq!(weight, 60);
            assert_eq!(port, 5060);
            assert_eq!(host, "sip.example.com");
            assert_eq!(ttl.0, 86400);
        } else {
            panic!("Expected SRV record but got: {:?}", result);
        }
    }

    #[test]
    fn test_parse_srv_record_edge_cases() {
        // Test with all zero values
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_u16(0).unwrap();
        buffer.write_u16(0).unwrap();
        buffer.write_u16(0).unwrap();
        buffer.write_qname(&"target.example.com".to_string()).unwrap();
        buffer.pos = 0;
        
        let result = RecordParser::parse_srv(&mut buffer, "service".to_string(), 300);
        assert!(result.is_ok());
        if let Ok(DnsRecord::Srv { priority, weight, port, .. }) = result {
            assert_eq!(priority, 0);
            assert_eq!(weight, 0);
            assert_eq!(port, 0);
        }

        // Test with maximum values
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_u16(u16::MAX).unwrap();
        buffer.write_u16(u16::MAX).unwrap();
        buffer.write_u16(u16::MAX).unwrap();
        buffer.write_qname(&"max.example.com".to_string()).unwrap();
        buffer.pos = 0;
        
        let result = RecordParser::parse_srv(&mut buffer, "service".to_string(), 300);
        assert!(result.is_ok());
        if let Ok(DnsRecord::Srv { priority, weight, port, .. }) = result {
            assert_eq!(priority, u16::MAX);
            assert_eq!(weight, u16::MAX);
            assert_eq!(port, u16::MAX);
        }
    }

    #[test]
    fn test_parse_opt_record() {
        // Create OPT record data
        let mut buffer = VectorPacketBuffer::new();
        let test_data = [0x00, 0x0A, 0x00, 0x08, 0xFF, 0xFF, 0xFF, 0xFF];
        for &byte in &test_data {
            buffer.write_u8(byte).unwrap();
        }
        buffer.pos = 0;
        
        let class = 4096; // UDP payload size
        let ttl = 0x00810000; // Extended RCODE and flags
        let data_len = test_data.len() as u16;
        
        let result = RecordParser::parse_opt(&mut buffer, "".to_string(), class, ttl, data_len);
        assert!(result.is_ok());
        
        if let Ok(DnsRecord::Opt { packet_len, flags, data }) = result {
            assert_eq!(packet_len, 4096);
            assert_eq!(flags, 0x00810000);
            assert!(!data.is_empty());
        } else {
            panic!("Expected OPT record but got: {:?}", result);
        }
    }

    #[test]
    fn test_parse_unknown_record() {
        // Create unknown record data
        let mut buffer = VectorPacketBuffer::new();
        for i in 0..10 {
            buffer.write_u8(i).unwrap();
        }
        buffer.pos = 0;
        
        let result = RecordParser::parse_unknown(&mut buffer, "unknown.example.com".to_string(), 99, 3600, 10);
        assert!(result.is_ok());
        
        if let Ok(DnsRecord::Unknown { domain, qtype, data_len, ttl }) = result {
            assert_eq!(domain, "unknown.example.com");
            assert_eq!(qtype, 99);
            assert_eq!(data_len, 10);
            assert_eq!(ttl.0, 3600);
            assert_eq!(buffer.pos, 10); // Should have stepped over the data
        } else {
            panic!("Expected Unknown record but got: {:?}", result);
        }
    }

    #[test]
    fn test_buffer_overflow_protection() {
        // Test that parsers handle buffer overflow gracefully
        let mut buffer = BytePacketBuffer::new();
        buffer.pos = 510; // Near the end of the buffer
        
        // Try to read a 32-bit value when only 2 bytes remain
        let result = RecordParser::parse_a(&mut buffer, "overflow.test".to_string(), 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_domain_name_compression() {
        // Test parsing with compressed domain names
        let mut buffer = VectorPacketBuffer::new();
        
        // Write a domain name that will be referenced
        buffer.write_qname(&"example.com".to_string()).unwrap();
        let reference_pos = 0;
        
        // Write NS record with compression pointer
        buffer.write_u8(0xC0).unwrap(); // Compression flag
        buffer.write_u8(reference_pos).unwrap(); // Offset
        
        buffer.pos = buffer.buffer.len() - 2; // Position before the compression pointer
        
        let result = RecordParser::parse_ns(&mut buffer, "test.com".to_string(), 3600);
        assert!(result.is_ok());
        
        if let Ok(DnsRecord::Ns { host, .. }) = result {
            assert_eq!(host, "example.com");
        }
    }

    #[test]
    fn test_special_characters_in_txt() {
        // Test TXT record with special characters
        let mut buffer = VectorPacketBuffer::new();
        let special_txt = "Special chars: \t\n\r\"'\\";
        buffer.write_u8(special_txt.len() as u8).unwrap();
        for byte in special_txt.bytes() {
            buffer.write_u8(byte).unwrap();
        }
        let data_len = buffer.buffer.len() as u16;
        buffer.pos = 0;
        
        let result = RecordParser::parse_txt(&mut buffer, "special.txt".to_string(), 300, data_len);
        assert!(result.is_ok());
        
        if let Ok(DnsRecord::Txt { data, .. }) = result {
            assert_eq!(data, special_txt);
        }
    }

    #[test]
    fn test_utf8_in_txt_record() {
        // Test TXT record with UTF-8 characters
        let mut buffer = VectorPacketBuffer::new();
        let utf8_txt = "Hello 世界 🌍";
        let bytes = utf8_txt.as_bytes();
        buffer.write_u8(bytes.len() as u8).unwrap();
        for &byte in bytes {
            buffer.write_u8(byte).unwrap();
        }
        let data_len = buffer.buffer.len() as u16;
        buffer.pos = 0;
        
        let result = RecordParser::parse_txt(&mut buffer, "utf8.txt".to_string(), 300, data_len);
        assert!(result.is_ok());
        
        if let Ok(DnsRecord::Txt { data, .. }) = result {
            assert_eq!(data, utf8_txt);
        }
    }

    #[test]
    fn test_parse_with_vector_buffer() {
        // Test that parsers work with different buffer implementations
        let mut buffer = create_vector_buffer_with_data(&[192, 168, 1, 1]);
        
        let result = RecordParser::parse_a(&mut buffer, "test.com".to_string(), 3600);
        assert!(result.is_ok());
        
        if let Ok(DnsRecord::A { addr, .. }) = result {
            assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 1));
        }
    }
}