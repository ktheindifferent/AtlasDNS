//! Performance benchmarks for DNS record parsers

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use atlas::dns::buffer::{BytePacketBuffer, PacketBuffer, VectorPacketBuffer};
use atlas::dns::protocol::{DnsRecord, TransientTtl};
use atlas::dns::record_parsers::RecordParser;
use std::net::{Ipv4Addr, Ipv6Addr};

fn create_a_record_buffer() -> BytePacketBuffer {
    let mut buffer = BytePacketBuffer::new();
    // Write IPv4 address 192.168.1.1
    buffer.buf[0] = 0xC0;
    buffer.buf[1] = 0xA8;
    buffer.buf[2] = 0x01;
    buffer.buf[3] = 0x01;
    buffer.pos = 0;
    buffer
}

fn create_aaaa_record_buffer() -> BytePacketBuffer {
    let mut buffer = BytePacketBuffer::new();
    // Write IPv6 address 2001:db8::1
    let data = [
        0x20, 0x01, 0x0d, 0xb8,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
    ];
    for (i, &byte) in data.iter().enumerate() {
        buffer.buf[i] = byte;
    }
    buffer.pos = 0;
    buffer
}

fn create_txt_record_buffer(size: usize) -> VectorPacketBuffer {
    let mut buffer = VectorPacketBuffer::new();
    let mut remaining = size;
    
    while remaining > 0 {
        let chunk_size = std::cmp::min(255, remaining);
        buffer.write_u8(chunk_size as u8).unwrap();
        for _ in 0..chunk_size {
            buffer.write_u8(b'X').unwrap();
        }
        remaining -= chunk_size;
    }
    
    buffer.pos = 0;
    buffer
}

fn create_soa_record_buffer() -> VectorPacketBuffer {
    let mut buffer = VectorPacketBuffer::new();
    buffer.write_qname(&"ns1.example.com".to_string()).unwrap();
    buffer.write_qname(&"admin.example.com".to_string()).unwrap();
    buffer.write_u32(2021010101).unwrap();
    buffer.write_u32(7200).unwrap();
    buffer.write_u32(3600).unwrap();
    buffer.write_u32(1209600).unwrap();
    buffer.write_u32(86400).unwrap();
    buffer.pos = 0;
    buffer
}

fn create_domain_name_buffer(domain: &str) -> VectorPacketBuffer {
    let mut buffer = VectorPacketBuffer::new();
    buffer.write_qname(&domain.to_string()).unwrap();
    buffer.pos = 0;
    buffer
}

fn benchmark_a_record_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("A Record Parsing");
    
    group.bench_function("parse_a_record", |b| {
        b.iter(|| {
            let mut buffer = create_a_record_buffer();
            let result = RecordParser::parse_a(
                &mut buffer,
                black_box("example.com".to_string()),
                black_box(3600)
            );
            black_box(result)
        });
    });
    
    group.finish();
}

fn benchmark_aaaa_record_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("AAAA Record Parsing");
    
    group.bench_function("parse_aaaa_record", |b| {
        b.iter(|| {
            let mut buffer = create_aaaa_record_buffer();
            let result = RecordParser::parse_aaaa(
                &mut buffer,
                black_box("ipv6.example.com".to_string()),
                black_box(3600)
            );
            black_box(result)
        });
    });
    
    group.finish();
}

fn benchmark_txt_record_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("TXT Record Parsing");
    group.throughput(Throughput::Elements(1));
    
    for size in [10, 100, 255, 500].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            |b, &size| {
                b.iter(|| {
                    let mut buffer = create_txt_record_buffer(size);
                    let result = RecordParser::parse_txt(
                        &mut buffer,
                        black_box("txt.example.com".to_string()),
                        black_box(300),
                        black_box(buffer.buffer.len() as u16)
                    );
                    black_box(result)
                });
            }
        );
    }
    
    group.finish();
}

fn benchmark_soa_record_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("SOA Record Parsing");
    
    group.bench_function("parse_soa_record", |b| {
        b.iter(|| {
            let mut buffer = create_soa_record_buffer();
            let result = RecordParser::parse_soa(
                &mut buffer,
                black_box("example.com".to_string()),
                black_box(86400)
            );
            black_box(result)
        });
    });
    
    group.finish();
}

fn benchmark_domain_name_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("Domain Name Parsing");
    
    let test_domains = vec![
        "a.com",
        "www.example.com",
        "deeply.nested.subdomain.example.com",
        "very.deeply.nested.subdomain.with.many.labels.example.com",
    ];
    
    for domain in test_domains {
        group.bench_with_input(
            BenchmarkId::from_parameter(domain),
            &domain,
            |b, &domain| {
                b.iter(|| {
                    let mut buffer = create_domain_name_buffer(domain);
                    let result = RecordParser::parse_ns(
                        &mut buffer,
                        black_box("test.com".to_string()),
                        black_box(3600)
                    );
                    black_box(result)
                });
            }
        );
    }
    
    group.finish();
}

fn benchmark_mx_record_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("MX Record Parsing");
    
    group.bench_function("parse_mx_record", |b| {
        b.iter(|| {
            let mut buffer = VectorPacketBuffer::new();
            buffer.write_u16(10).unwrap();
            buffer.write_qname(&"mail.example.com".to_string()).unwrap();
            buffer.pos = 0;
            
            let result = RecordParser::parse_mx(
                &mut buffer,
                black_box("example.com".to_string()),
                black_box(3600)
            );
            black_box(result)
        });
    });
    
    group.finish();
}

fn benchmark_srv_record_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("SRV Record Parsing");
    
    group.bench_function("parse_srv_record", |b| {
        b.iter(|| {
            let mut buffer = VectorPacketBuffer::new();
            buffer.write_u16(10).unwrap();
            buffer.write_u16(60).unwrap();
            buffer.write_u16(5060).unwrap();
            buffer.write_qname(&"sip.example.com".to_string()).unwrap();
            buffer.pos = 0;
            
            let result = RecordParser::parse_srv(
                &mut buffer,
                black_box("_sip._tcp.example.com".to_string()),
                black_box(86400)
            );
            black_box(result)
        });
    });
    
    group.finish();
}

fn benchmark_cname_record_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("CNAME Record Parsing");
    
    group.bench_function("parse_cname_record", |b| {
        b.iter(|| {
            let mut buffer = VectorPacketBuffer::new();
            buffer.write_qname(&"example.com".to_string()).unwrap();
            buffer.pos = 0;
            
            let result = RecordParser::parse_cname(
                &mut buffer,
                black_box("www.example.com".to_string()),
                black_box(3600)
            );
            black_box(result)
        });
    });
    
    group.finish();
}

fn benchmark_opt_record_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("OPT Record Parsing");
    
    group.bench_function("parse_opt_record", |b| {
        b.iter(|| {
            let mut buffer = VectorPacketBuffer::new();
            for i in 0..8 {
                buffer.write_u8(i).unwrap();
            }
            buffer.pos = 0;
            
            let result = RecordParser::parse_opt(
                &mut buffer,
                black_box("".to_string()),
                black_box(4096),
                black_box(0x00810000),
                black_box(8)
            );
            black_box(result)
        });
    });
    
    group.finish();
}

fn benchmark_unknown_record_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("Unknown Record Parsing");
    group.throughput(Throughput::Bytes(100));
    
    group.bench_function("parse_unknown_record", |b| {
        b.iter(|| {
            let mut buffer = VectorPacketBuffer::new();
            for i in 0..100 {
                buffer.write_u8((i % 256) as u8).unwrap();
            }
            buffer.pos = 0;
            
            let result = RecordParser::parse_unknown(
                &mut buffer,
                black_box("unknown.example.com".to_string()),
                black_box(99),
                black_box(3600),
                black_box(100)
            );
            black_box(result)
        });
    });
    
    group.finish();
}

fn benchmark_buffer_implementations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Buffer Implementation Comparison");
    
    // Compare BytePacketBuffer vs VectorPacketBuffer for A record parsing
    group.bench_function("BytePacketBuffer_A_record", |b| {
        b.iter(|| {
            let mut buffer = create_a_record_buffer();
            let result = RecordParser::parse_a(
                &mut buffer,
                black_box("example.com".to_string()),
                black_box(3600)
            );
            black_box(result)
        });
    });
    
    group.bench_function("VectorPacketBuffer_A_record", |b| {
        b.iter(|| {
            let mut buffer = VectorPacketBuffer::new();
            buffer.write_u32(0xC0A80101).unwrap();
            buffer.pos = 0;
            let result = RecordParser::parse_a(
                &mut buffer,
                black_box("example.com".to_string()),
                black_box(3600)
            );
            black_box(result)
        });
    });
    
    group.finish();
}

fn benchmark_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("Memory Usage");
    
    // Benchmark memory allocation patterns for different record types
    group.bench_function("allocate_a_record", |b| {
        b.iter(|| {
            let record = DnsRecord::A {
                domain: black_box("example.com".to_string()),
                addr: black_box(Ipv4Addr::new(192, 168, 1, 1)),
                ttl: black_box(TransientTtl(3600)),
            };
            black_box(record)
        });
    });
    
    group.bench_function("allocate_txt_record", |b| {
        b.iter(|| {
            let record = DnsRecord::Txt {
                domain: black_box("example.com".to_string()),
                data: black_box("x".repeat(255)),
                ttl: black_box(TransientTtl(300)),
            };
            black_box(record)
        });
    });
    
    group.bench_function("allocate_soa_record", |b| {
        b.iter(|| {
            let record = DnsRecord::Soa {
                domain: black_box("example.com".to_string()),
                m_name: black_box("ns1.example.com".to_string()),
                r_name: black_box("admin.example.com".to_string()),
                serial: black_box(2021010101),
                refresh: black_box(7200),
                retry: black_box(3600),
                expire: black_box(1209600),
                minimum: black_box(86400),
                ttl: black_box(TransientTtl(86400)),
            };
            black_box(record)
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_a_record_parsing,
    benchmark_aaaa_record_parsing,
    benchmark_txt_record_parsing,
    benchmark_soa_record_parsing,
    benchmark_domain_name_parsing,
    benchmark_mx_record_parsing,
    benchmark_srv_record_parsing,
    benchmark_cname_record_parsing,
    benchmark_opt_record_parsing,
    benchmark_unknown_record_parsing,
    benchmark_buffer_implementations,
    benchmark_memory_usage
);
criterion_main!(benches);