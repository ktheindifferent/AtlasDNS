#!/usr/bin/env rust-script
//! A standalone test script to verify DNS parser tests work
//! Run with: rustc test_dns_parsers.rs && ./test_dns_parsers

// This is a simplified version for verification
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq)]
struct TestBuffer {
    data: Vec<u8>,
    pos: usize,
}

impl TestBuffer {
    fn new(data: &[u8]) -> Self {
        TestBuffer {
            data: data.to_vec(),
            pos: 0,
        }
    }
    
    fn read_u32(&mut self) -> u32 {
        let result = ((self.data[self.pos] as u32) << 24) |
                    ((self.data[self.pos + 1] as u32) << 16) |
                    ((self.data[self.pos + 2] as u32) << 8) |
                    (self.data[self.pos + 3] as u32);
        self.pos += 4;
        result
    }
}

fn parse_a_record(buffer: &mut TestBuffer) -> Ipv4Addr {
    let raw_addr = buffer.read_u32();
    Ipv4Addr::new(
        ((raw_addr >> 24) & 0xFF) as u8,
        ((raw_addr >> 16) & 0xFF) as u8,
        ((raw_addr >> 8) & 0xFF) as u8,
        (raw_addr & 0xFF) as u8,
    )
}

fn main() {
    println!("Testing DNS Record Parsers...\n");
    
    // Test A record parsing
    println!("Test 1: Parse A record (192.168.1.1)");
    let mut buffer = TestBuffer::new(&[0xC0, 0xA8, 0x01, 0x01]);
    let addr = parse_a_record(&mut buffer);
    assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 1));
    println!("✓ Passed: A record parsed correctly as {}", addr);
    
    // Test edge case: 0.0.0.0
    println!("\nTest 2: Parse A record (0.0.0.0)");
    let mut buffer = TestBuffer::new(&[0x00, 0x00, 0x00, 0x00]);
    let addr = parse_a_record(&mut buffer);
    assert_eq!(addr, Ipv4Addr::new(0, 0, 0, 0));
    println!("✓ Passed: Minimum IPv4 parsed correctly as {}", addr);
    
    // Test edge case: 255.255.255.255
    println!("\nTest 3: Parse A record (255.255.255.255)");
    let mut buffer = TestBuffer::new(&[0xFF, 0xFF, 0xFF, 0xFF]);
    let addr = parse_a_record(&mut buffer);
    assert_eq!(addr, Ipv4Addr::new(255, 255, 255, 255));
    println!("✓ Passed: Maximum IPv4 parsed correctly as {}", addr);
    
    // Test Google DNS
    println!("\nTest 4: Parse A record (8.8.8.8)");
    let mut buffer = TestBuffer::new(&[0x08, 0x08, 0x08, 0x08]);
    let addr = parse_a_record(&mut buffer);
    assert_eq!(addr, Ipv4Addr::new(8, 8, 8, 8));
    println!("✓ Passed: Google DNS parsed correctly as {}", addr);
    
    println!("\n✅ All tests passed successfully!");
    println!("\nSummary:");
    println!("- DNS A record parsing logic is correct");
    println!("- Edge cases (min/max values) handled properly");
    println!("- Buffer reading implementation works as expected");
}