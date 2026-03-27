//! DNS Benchmark Tool
//!
//! Fires a configurable number of DNS queries against a target server
//! and reports latency percentiles (p50/p95/p99), min, max, avg.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use crate::dns::buffer::{BytePacketBuffer, PacketBuffer, VectorPacketBuffer};
use crate::dns::protocol::{DnsPacket, DnsQuestion, QueryType};

/// Benchmark configuration.
pub struct BenchConfig {
    pub server: String,
    pub port: u16,
    pub domain: String,
    pub query_type: QueryType,
    pub count: u32,
    pub timeout_ms: u64,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            server: "127.0.0.1".to_string(),
            port: 53,
            domain: "google.com".to_string(),
            query_type: QueryType::A,
            count: 1000,
            timeout_ms: 2000,
        }
    }
}

/// Benchmark result for a single query.
struct QueryResult {
    latency_us: u64,
    success: bool,
}

/// Aggregated benchmark results.
pub struct BenchResults {
    pub total: u32,
    pub success: u32,
    pub failed: u32,
    pub latencies_us: Vec<u64>,
    pub elapsed: Duration,
}

impl BenchResults {
    pub fn p50(&self) -> u64 { percentile(&self.latencies_us, 50) }
    pub fn p95(&self) -> u64 { percentile(&self.latencies_us, 95) }
    pub fn p99(&self) -> u64 { percentile(&self.latencies_us, 99) }
    pub fn min(&self) -> u64 { self.latencies_us.first().copied().unwrap_or(0) }
    pub fn max(&self) -> u64 { self.latencies_us.last().copied().unwrap_or(0) }
    pub fn avg(&self) -> u64 {
        if self.latencies_us.is_empty() { 0 }
        else { self.latencies_us.iter().sum::<u64>() / self.latencies_us.len() as u64 }
    }
    pub fn qps(&self) -> f64 {
        if self.elapsed.as_secs_f64() == 0.0 { 0.0 }
        else { self.total as f64 / self.elapsed.as_secs_f64() }
    }

    /// Print a human-readable report to stdout.
    pub fn print_report(&self) {
        println!("\n=== Atlas DNS Benchmark Results ===");
        println!("Queries:   {} total, {} success, {} failed", self.total, self.success, self.failed);
        println!("Duration:  {:.2}s ({:.0} qps)", self.elapsed.as_secs_f64(), self.qps());
        println!();
        if self.latencies_us.is_empty() {
            println!("No successful queries to report latency.");
            return;
        }
        println!("Latency (microseconds):");
        println!("  Min:  {:>8} us  ({:.2} ms)", self.min(), self.min() as f64 / 1000.0);
        println!("  Avg:  {:>8} us  ({:.2} ms)", self.avg(), self.avg() as f64 / 1000.0);
        println!("  p50:  {:>8} us  ({:.2} ms)", self.p50(), self.p50() as f64 / 1000.0);
        println!("  p95:  {:>8} us  ({:.2} ms)", self.p95(), self.p95() as f64 / 1000.0);
        println!("  p99:  {:>8} us  ({:.2} ms)", self.p99(), self.p99() as f64 / 1000.0);
        println!("  Max:  {:>8} us  ({:.2} ms)", self.max(), self.max() as f64 / 1000.0);
        println!();

        // ASCII histogram
        let bucket_edges: &[(u64, &str)] = &[
            (100, "<0.1ms"),
            (500, "0.1-0.5ms"),
            (1_000, "0.5-1ms"),
            (5_000, "1-5ms"),
            (10_000, "5-10ms"),
            (50_000, "10-50ms"),
            (100_000, "50-100ms"),
            (500_000, "100-500ms"),
            (u64::MAX, ">500ms"),
        ];

        let mut counts = vec![0u64; bucket_edges.len()];
        for &val in &self.latencies_us {
            for (i, &(edge, _)) in bucket_edges.iter().enumerate() {
                if val <= edge {
                    counts[i] += 1;
                    break;
                }
            }
        }

        let max_count = *counts.iter().max().unwrap_or(&1);
        let bar_width = 40;

        println!("Latency Distribution:");
        for (i, &(_, label)) in bucket_edges.iter().enumerate() {
            let count = counts[i];
            let bar_len = if max_count > 0 { (count as usize * bar_width) / max_count as usize } else { 0 };
            let bar: String = "\u{2588}".repeat(bar_len);
            println!("  {:>10} | {:<width$} {}", label, bar, count, width = bar_width);
        }
        println!("===================================\n");
    }
}

/// Run the benchmark.
pub fn run_bench(config: &BenchConfig) -> BenchResults {
    println!("Atlas DNS Benchmark");
    println!("Target:  {}:{}", config.server, config.port);
    println!("Domain:  {} ({:?})", config.domain, config.query_type);
    println!("Count:   {}", config.count);
    println!("Timeout: {}ms", config.timeout_ms);
    println!("Running...");

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to bind UDP socket: {}", e);
            return BenchResults {
                total: config.count,
                success: 0,
                failed: config.count,
                latencies_us: Vec::new(),
                elapsed: Duration::ZERO,
            };
        }
    };
    let _ = socket.set_read_timeout(Some(Duration::from_millis(config.timeout_ms)));

    let target = format!("{}:{}", config.server, config.port);
    let mut results: Vec<QueryResult> = Vec::with_capacity(config.count as usize);

    let bench_start = Instant::now();

    for i in 0..config.count {
        let result = send_single_query(&socket, &target, &config.domain, config.query_type, i as u16);
        results.push(result);
    }

    let elapsed = bench_start.elapsed();

    let mut latencies: Vec<u64> = results.iter()
        .filter(|r| r.success)
        .map(|r| r.latency_us)
        .collect();
    latencies.sort_unstable();

    let success = results.iter().filter(|r| r.success).count() as u32;
    let failed = config.count - success;

    BenchResults {
        total: config.count,
        success,
        failed,
        latencies_us: latencies,
        elapsed,
    }
}

fn send_single_query(
    socket: &UdpSocket,
    target: &str,
    domain: &str,
    qtype: QueryType,
    id: u16,
) -> QueryResult {
    // Build query packet
    let mut packet = DnsPacket::new();
    packet.header.id = id.wrapping_add(1);
    packet.header.questions = 1;
    packet.header.recursion_desired = true;

    packet.questions.push(DnsQuestion::new(domain.to_string(), qtype));

    let mut req_buffer = VectorPacketBuffer::new();
    if packet.write(&mut req_buffer, 512).is_err() {
        return QueryResult { latency_us: 0, success: false };
    }
    let len = req_buffer.pos();
    let data = match req_buffer.get_range(0, len) {
        Ok(d) => d.to_vec(),
        Err(_) => return QueryResult { latency_us: 0, success: false },
    };

    let start = Instant::now();

    if socket.send_to(&data, target).is_err() {
        return QueryResult { latency_us: 0, success: false };
    }

    let mut recv_buf = [0u8; 512];
    match socket.recv_from(&mut recv_buf) {
        Ok((size, _)) => {
            let latency_us = start.elapsed().as_micros() as u64;
            // Quick sanity check: parse the response
            let mut buffer = BytePacketBuffer::new();
            buffer.buf[..size].copy_from_slice(&recv_buf[..size]);
            match DnsPacket::from_buffer(&mut buffer) {
                Ok(_) => QueryResult { latency_us, success: true },
                Err(_) => QueryResult { latency_us, success: false },
            }
        }
        Err(_) => QueryResult { latency_us: 0, success: false },
    }
}

fn percentile(sorted: &[u64], p: usize) -> u64 {
    if sorted.is_empty() { return 0; }
    let idx = (sorted.len() * p / 100).min(sorted.len() - 1);
    sorted[idx]
}
