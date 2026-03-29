#![allow(dead_code)]
//! DNS-based Load Balancing with Health Checking
//!
//! Provides load balancing across backend IP pools for DNS domains, with
//! configurable rotation strategies and periodic health checks.
//!
//! # Features
//!
//! * **Pool Management** - Define pools of backend IPs per domain
//! * **Multiple Strategies** - Round-robin, weighted, least-connections, random
//! * **Health Checking** - TCP connect or ICMP ping checks per backend
//! * **Auto-Recovery** - Unhealthy backends removed; restored on recovery
//! * **TOML Config** - Load pool definitions from `~/.atlasdns/lb.toml`
//! * **Metrics** - Per-backend request counts, health status, latency

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Serialize, Deserialize};

use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, TransientTtl, ResultCode};

// ---------------------------------------------------------------------------
// Configuration types (map to TOML)
// ---------------------------------------------------------------------------

/// Load balancing strategy for a pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum LbStrategy {
    #[default]
    RoundRobin,
    Weighted,
    LeastConnections,
    Random,
}

impl std::fmt::Display for LbStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LbStrategy::RoundRobin => write!(f, "round-robin"),
            LbStrategy::Weighted => write!(f, "weighted"),
            LbStrategy::LeastConnections => write!(f, "least-connections"),
            LbStrategy::Random => write!(f, "random"),
        }
    }
}

/// Health-check specification, e.g. `"tcp:80"` or `"icmp"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum HealthCheckKind {
    /// TCP connect to the given port
    Tcp(u16),
    /// ICMP ping (best-effort; falls back to TCP:80 if raw sockets unavailable)
    Icmp,
    /// No health checking
    #[default]
    None,
}

impl HealthCheckKind {
    /// Parse from a config string like `"tcp:80"` or `"icmp"`.
    pub fn parse(s: &str) -> Self {
        let s = s.trim().to_lowercase();
        if s == "icmp" || s == "ping" {
            return HealthCheckKind::Icmp;
        }
        if let Some(port_str) = s.strip_prefix("tcp:") {
            if let Ok(port) = port_str.trim().parse::<u16>() {
                return HealthCheckKind::Tcp(port);
            }
        }
        if s == "none" || s.is_empty() {
            return HealthCheckKind::None;
        }
        // Default: try parsing as a bare port number
        if let Ok(port) = s.parse::<u16>() {
            return HealthCheckKind::Tcp(port);
        }
        HealthCheckKind::None
    }
}

/// TOML-level pool definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    /// Domain name this pool serves (e.g. `"web.example.com"`)
    pub name: String,
    /// Backend IP addresses
    pub backends: Vec<String>,
    /// Load balancing strategy
    #[serde(default)]
    pub strategy: LbStrategy,
    /// Health check spec string (e.g. `"tcp:80"`, `"icmp"`, `"none"`)
    #[serde(default)]
    pub health_check: Option<String>,
    /// Per-backend weights (only used with `weighted` strategy)
    #[serde(default)]
    pub weights: Option<Vec<u32>>,
    /// Health check interval in seconds (default 30)
    #[serde(default = "default_check_interval")]
    pub check_interval_secs: u64,
    /// TTL for synthesised DNS answers (default 30)
    #[serde(default = "default_ttl")]
    pub ttl: u32,
}

fn default_check_interval() -> u64 { 30 }
fn default_ttl() -> u32 { 30 }

/// Top-level TOML config file structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LbConfig {
    #[serde(default)]
    pub pool: Vec<PoolConfig>,
}

// ---------------------------------------------------------------------------
// Runtime state
// ---------------------------------------------------------------------------

/// Health status of a single backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum BackendHealth {
    Healthy,
    Unhealthy,
    Unknown,
}

impl std::fmt::Display for BackendHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendHealth::Healthy => write!(f, "healthy"),
            BackendHealth::Unhealthy => write!(f, "unhealthy"),
            BackendHealth::Unknown => write!(f, "unknown"),
        }
    }
}

/// Runtime state for a single backend IP.
pub struct Backend {
    pub addr: IpAddr,
    pub weight: u32,
    pub healthy: AtomicBool,
    pub request_count: AtomicU64,
    pub active_connections: AtomicU64,
    pub last_check: RwLock<Option<Instant>>,
    pub last_latency_ms: RwLock<Option<u64>>,
}

impl Backend {
    fn new(addr: IpAddr, weight: u32) -> Self {
        Backend {
            addr,
            weight,
            healthy: AtomicBool::new(true), // assume healthy until proven otherwise
            request_count: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            last_check: RwLock::new(None),
            last_latency_ms: RwLock::new(None),
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    pub fn health_status(&self) -> BackendHealth {
        if self.last_check.read().is_none() {
            BackendHealth::Unknown
        } else if self.is_healthy() {
            BackendHealth::Healthy
        } else {
            BackendHealth::Unhealthy
        }
    }
}

/// Serialisable snapshot of a backend for API responses.
#[derive(Debug, Serialize)]
pub struct BackendSnapshot {
    pub address: String,
    pub health: String,
    pub weight: u32,
    pub request_count: u64,
    pub active_connections: u64,
    pub last_latency_ms: Option<u64>,
}

/// A runtime load-balanced pool.
pub struct LbPool {
    pub domain: String,
    pub strategy: LbStrategy,
    pub health_check: HealthCheckKind,
    pub backends: Vec<Arc<Backend>>,
    pub check_interval: Duration,
    pub ttl: u32,
    /// Round-robin counter
    rr_counter: AtomicU64,
}

/// Serialisable snapshot of a pool for API responses.
#[derive(Debug, Serialize)]
pub struct PoolSnapshot {
    pub domain: String,
    pub strategy: String,
    pub health_check: String,
    pub ttl: u32,
    pub check_interval_secs: u64,
    pub total_requests: u64,
    pub healthy_backends: usize,
    pub total_backends: usize,
    pub backends: Vec<BackendSnapshot>,
}

impl LbPool {
    /// Build a pool from a TOML config entry.
    pub fn from_config(cfg: &PoolConfig) -> Self {
        let health_check = cfg.health_check.as_deref()
            .map(HealthCheckKind::parse)
            .unwrap_or(HealthCheckKind::None);

        let backends: Vec<Arc<Backend>> = cfg.backends.iter().enumerate().map(|(i, addr_str)| {
            let addr: IpAddr = addr_str.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            let weight = cfg.weights.as_ref()
                .and_then(|w| w.get(i).copied())
                .unwrap_or(1);
            Arc::new(Backend::new(addr, weight))
        }).collect();

        LbPool {
            domain: cfg.name.clone(),
            strategy: cfg.strategy.clone(),
            health_check,
            backends,
            check_interval: Duration::from_secs(cfg.check_interval_secs),
            ttl: cfg.ttl,
            rr_counter: AtomicU64::new(0),
        }
    }

    /// Select the next healthy backend according to the pool strategy.
    pub fn select_backend(&self) -> Option<Arc<Backend>> {
        let healthy: Vec<&Arc<Backend>> = self.backends.iter()
            .filter(|b| b.is_healthy())
            .collect();

        if healthy.is_empty() {
            return None;
        }

        let selected = match self.strategy {
            LbStrategy::RoundRobin => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
                healthy[idx % healthy.len()].clone()
            }
            LbStrategy::Weighted => {
                let total_weight: u32 = healthy.iter().map(|b| b.weight).sum();
                if total_weight == 0 {
                    return healthy.first().map(|b| (*b).clone());
                }
                let mut rng_val = (self.rr_counter.fetch_add(1, Ordering::Relaxed) * 2654435761) % total_weight as u64;
                let mut pick = healthy[0];
                for b in &healthy {
                    if rng_val < b.weight as u64 {
                        pick = b;
                        break;
                    }
                    rng_val -= b.weight as u64;
                }
                pick.clone()
            }
            LbStrategy::LeastConnections => {
                healthy.iter()
                    .min_by_key(|b| b.active_connections.load(Ordering::Relaxed))
                    .map(|b| (*b).clone())
                    .unwrap()
            }
            LbStrategy::Random => {
                // Use a mix of counter + time for cheap pseudo-randomness
                let seed = self.rr_counter.fetch_add(1, Ordering::Relaxed)
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let idx = (seed >> 33) as usize % healthy.len();
                healthy[idx].clone()
            }
        };

        selected.request_count.fetch_add(1, Ordering::Relaxed);
        Some(selected)
    }

    /// Select multiple backends (for multi-answer responses).
    pub fn select_all_healthy(&self) -> Vec<Arc<Backend>> {
        self.backends.iter()
            .filter(|b| b.is_healthy())
            .cloned()
            .collect()
    }

    /// Build a DNS A/AAAA response packet for this pool.
    pub fn resolve(&self, qname: &str, qtype: QueryType) -> Option<DnsPacket> {
        if qtype != QueryType::A && qtype != QueryType::Aaaa {
            return None;
        }

        let backend = self.select_backend()?;

        let mut packet = DnsPacket::new();
        packet.header.rescode = ResultCode::NOERROR;
        packet.header.authoritative_answer = true;

        match (qtype, backend.addr) {
            (QueryType::A, IpAddr::V4(ipv4)) => {
                packet.answers.push(DnsRecord::A {
                    domain: qname.to_string(),
                    addr: ipv4,
                    ttl: TransientTtl(self.ttl),
                });
            }
            (QueryType::Aaaa, IpAddr::V6(ipv6)) => {
                packet.answers.push(DnsRecord::Aaaa {
                    domain: qname.to_string(),
                    addr: ipv6,
                    ttl: TransientTtl(self.ttl),
                });
            }
            // Query type doesn't match backend address family — try finding another
            _ => {
                for b in self.select_all_healthy() {
                    match (qtype, b.addr) {
                        (QueryType::A, IpAddr::V4(ipv4)) => {
                            packet.answers.push(DnsRecord::A {
                                domain: qname.to_string(),
                                addr: ipv4,
                                ttl: TransientTtl(self.ttl),
                            });
                            b.request_count.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        (QueryType::Aaaa, IpAddr::V6(ipv6)) => {
                            packet.answers.push(DnsRecord::Aaaa {
                                domain: qname.to_string(),
                                addr: ipv6,
                                ttl: TransientTtl(self.ttl),
                            });
                            b.request_count.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        _ => continue,
                    }
                }
                if packet.answers.is_empty() {
                    return None;
                }
            }
        }

        Some(packet)
    }

    /// Run health checks on all backends in this pool.
    pub fn run_health_checks(&self) {
        for backend in &self.backends {
            let now = Instant::now();

            // Skip if checked recently
            if let Some(last) = *backend.last_check.read() {
                if now.duration_since(last) < self.check_interval {
                    continue;
                }
            }

            let (healthy, latency_ms) = match &self.health_check {
                HealthCheckKind::Tcp(port) => check_tcp(backend.addr, *port),
                HealthCheckKind::Icmp => check_icmp_or_fallback(backend.addr),
                HealthCheckKind::None => {
                    // No health check configured — always healthy
                    (true, None)
                }
            };

            let was_healthy = backend.healthy.swap(healthy, Ordering::Relaxed);
            *backend.last_check.write() = Some(Instant::now());
            *backend.last_latency_ms.write() = latency_ms;

            if was_healthy && !healthy {
                log::warn!(
                    "[LB] Backend {} in pool marked UNHEALTHY",
                    backend.addr
                );
            } else if !was_healthy && healthy {
                log::info!(
                    "[LB] Backend {} in pool recovered (HEALTHY)",
                    backend.addr
                );
            }
        }
    }

    /// Create a snapshot for API/dashboard consumption.
    pub fn snapshot(&self) -> PoolSnapshot {
        let backends: Vec<BackendSnapshot> = self.backends.iter().map(|b| {
            BackendSnapshot {
                address: b.addr.to_string(),
                health: b.health_status().to_string(),
                weight: b.weight,
                request_count: b.request_count.load(Ordering::Relaxed),
                active_connections: b.active_connections.load(Ordering::Relaxed),
                last_latency_ms: *b.last_latency_ms.read(),
            }
        }).collect();

        let healthy_count = self.backends.iter().filter(|b| b.is_healthy()).count();
        let total_requests: u64 = self.backends.iter()
            .map(|b| b.request_count.load(Ordering::Relaxed))
            .sum();

        let hc_str = match &self.health_check {
            HealthCheckKind::Tcp(port) => format!("tcp:{}", port),
            HealthCheckKind::Icmp => "icmp".to_string(),
            HealthCheckKind::None => "none".to_string(),
        };

        PoolSnapshot {
            domain: self.domain.clone(),
            strategy: self.strategy.to_string(),
            health_check: hc_str,
            ttl: self.ttl,
            check_interval_secs: self.check_interval.as_secs(),
            total_requests,
            healthy_backends: healthy_count,
            total_backends: self.backends.len(),
            backends,
        }
    }
}

// ---------------------------------------------------------------------------
// Health check implementations
// ---------------------------------------------------------------------------

fn check_tcp(addr: IpAddr, port: u16) -> (bool, Option<u64>) {
    let start = Instant::now();
    let sock_addr = std::net::SocketAddr::new(addr, port);
    match TcpStream::connect_timeout(&sock_addr, Duration::from_secs(5)) {
        Ok(_stream) => {
            let ms = start.elapsed().as_millis() as u64;
            (true, Some(ms))
        }
        Err(_) => {
            let ms = start.elapsed().as_millis() as u64;
            (false, Some(ms))
        }
    }
}

fn check_icmp_or_fallback(addr: IpAddr) -> (bool, Option<u64>) {
    // ICMP requires raw sockets (root). Fall back to TCP:80.
    check_tcp(addr, 80)
}

// ---------------------------------------------------------------------------
// LoadBalancerManager — the top-level coordinator
// ---------------------------------------------------------------------------

/// Central manager holding all LB pools, providing lookup and health-check
/// orchestration.
pub struct LoadBalancerManager {
    pools: RwLock<HashMap<String, Arc<LbPool>>>,
}

impl LoadBalancerManager {
    pub fn new() -> Self {
        LoadBalancerManager {
            pools: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for LoadBalancerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadBalancerManager {
    /// Load pools from a parsed TOML config.
    pub fn load_config(&self, config: &LbConfig) {
        let mut pools = self.pools.write();
        for cfg in &config.pool {
            let domain = cfg.name.to_lowercase();
            let pool = Arc::new(LbPool::from_config(cfg));
            log::info!(
                "[LB] Loaded pool '{}': {} backends, strategy={}, health_check={:?}",
                domain,
                pool.backends.len(),
                pool.strategy,
                cfg.health_check,
            );
            pools.insert(domain, pool);
        }
    }

    /// Load from the default config file `~/.atlasdns/lb.toml`.
    pub fn load_default_config(&self) {
        let path = dirs_path();
        if let Ok(content) = std::fs::read_to_string(&path) {
            match toml::from_str::<LbConfig>(&content) {
                Ok(config) => {
                    log::info!("[LB] Loaded {} pool(s) from {}", config.pool.len(), path);
                    self.load_config(&config);
                }
                Err(e) => {
                    log::warn!("[LB] Failed to parse {}: {}", path, e);
                }
            }
        } else {
            log::debug!("[LB] No config file at {}", path);
        }
    }

    /// Try to resolve a query against LB pools. Returns `Some(packet)` if the
    /// queried domain matches a pool.
    pub fn resolve(&self, qname: &str, qtype: QueryType) -> Option<DnsPacket> {
        let pools = self.pools.read();
        let key = qname.to_lowercase().trim_end_matches('.').to_string();
        if let Some(pool) = pools.get(&key) {
            return pool.resolve(qname, qtype);
        }
        None
    }

    /// Add a pool at runtime.
    pub fn add_pool(&self, config: &PoolConfig) {
        let domain = config.name.to_lowercase();
        let pool = Arc::new(LbPool::from_config(config));
        self.pools.write().insert(domain, pool);
    }

    /// Remove a pool by domain name.
    pub fn remove_pool(&self, domain: &str) -> bool {
        self.pools.write().remove(&domain.to_lowercase()).is_some()
    }

    /// Run health checks on all pools.
    pub fn run_all_health_checks(&self) {
        let pools = self.pools.read();
        for pool in pools.values() {
            pool.run_health_checks();
        }
    }

    /// Get snapshot of all pools for API/dashboard.
    pub fn get_all_snapshots(&self) -> Vec<PoolSnapshot> {
        let pools = self.pools.read();
        pools.values().map(|p| p.snapshot()).collect()
    }

    /// Get snapshot of a single pool.
    pub fn get_pool_snapshot(&self, domain: &str) -> Option<PoolSnapshot> {
        let pools = self.pools.read();
        pools.get(&domain.to_lowercase()).map(|p| p.snapshot())
    }

    /// Number of configured pools.
    pub fn pool_count(&self) -> usize {
        self.pools.read().len()
    }

    /// Start a background thread that runs health checks periodically.
    pub fn start_health_check_loop(self: &Arc<Self>) {
        let manager = Arc::clone(self);
        std::thread::Builder::new()
            .name("lb-health-checker".into())
            .spawn(move || {
                log::info!("[LB] Health check background thread started");
                loop {
                    manager.run_all_health_checks();
                    std::thread::sleep(Duration::from_secs(10));
                }
            })
            .expect("Failed to spawn LB health check thread");
    }
}

/// Return the default config file path: `~/.atlasdns/lb.toml`
fn dirs_path() -> String {
    if let Some(home) = std::env::var_os("HOME") {
        format!("{}/.atlasdns/lb.toml", home.to_string_lossy())
    } else {
        "/etc/atlasdns/lb.toml".to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> LbConfig {
        LbConfig {
            pool: vec![
                PoolConfig {
                    name: "web.example.com".to_string(),
                    backends: vec![
                        "192.168.1.10".to_string(),
                        "192.168.1.11".to_string(),
                        "192.168.1.12".to_string(),
                    ],
                    strategy: LbStrategy::RoundRobin,
                    health_check: Some("tcp:80".to_string()),
                    weights: None,
                    check_interval_secs: 30,
                    ttl: 30,
                },
                PoolConfig {
                    name: "api.example.com".to_string(),
                    backends: vec![
                        "10.0.0.1".to_string(),
                        "10.0.0.2".to_string(),
                    ],
                    strategy: LbStrategy::Weighted,
                    health_check: Some("tcp:443".to_string()),
                    weights: Some(vec![3, 1]),
                    check_interval_secs: 15,
                    ttl: 10,
                },
            ],
        }
    }

    #[test]
    fn test_pool_round_robin() {
        let cfg = &sample_config().pool[0];
        let pool = LbPool::from_config(cfg);

        // All backends start healthy
        let b1 = pool.select_backend().unwrap();
        let b2 = pool.select_backend().unwrap();
        let _b3 = pool.select_backend().unwrap();
        let b4 = pool.select_backend().unwrap();

        // Round-robin should cycle through backends
        assert_eq!(b1.addr, b4.addr); // wraps around
        assert_ne!(b1.addr, b2.addr);
    }

    #[test]
    fn test_unhealthy_backend_skipped() {
        let cfg = &sample_config().pool[0];
        let pool = LbPool::from_config(cfg);

        // Mark first backend unhealthy
        pool.backends[0].healthy.store(false, Ordering::Relaxed);

        for _ in 0..10 {
            let b = pool.select_backend().unwrap();
            assert_ne!(b.addr, pool.backends[0].addr);
        }
    }

    #[test]
    fn test_all_unhealthy_returns_none() {
        let cfg = &sample_config().pool[0];
        let pool = LbPool::from_config(cfg);

        for b in &pool.backends {
            b.healthy.store(false, Ordering::Relaxed);
        }

        assert!(pool.select_backend().is_none());
    }

    #[test]
    fn test_resolve_a_record() {
        let cfg = &sample_config().pool[0];
        let pool = LbPool::from_config(cfg);

        let packet = pool.resolve("web.example.com", QueryType::A).unwrap();
        assert_eq!(packet.header.rescode, ResultCode::NOERROR);
        assert!(!packet.answers.is_empty());
    }

    #[test]
    fn test_manager_lookup() {
        let mgr = LoadBalancerManager::new();
        mgr.load_config(&sample_config());

        assert_eq!(mgr.pool_count(), 2);

        let pkt = mgr.resolve("web.example.com", QueryType::A);
        assert!(pkt.is_some());

        let pkt = mgr.resolve("unknown.example.com", QueryType::A);
        assert!(pkt.is_none());
    }

    #[test]
    fn test_health_check_kind_parsing() {
        assert!(matches!(HealthCheckKind::parse("tcp:80"), HealthCheckKind::Tcp(80)));
        assert!(matches!(HealthCheckKind::parse("tcp:443"), HealthCheckKind::Tcp(443)));
        assert!(matches!(HealthCheckKind::parse("icmp"), HealthCheckKind::Icmp));
        assert!(matches!(HealthCheckKind::parse("ping"), HealthCheckKind::Icmp));
        assert!(matches!(HealthCheckKind::parse("none"), HealthCheckKind::None));
        assert!(matches!(HealthCheckKind::parse(""), HealthCheckKind::None));
    }

    #[test]
    fn test_toml_deserialization() {
        let toml_str = r#"
[[pool]]
name = "web.example.com"
backends = ["192.168.1.10", "192.168.1.11"]
strategy = "round-robin"
health_check = "tcp:80"

[[pool]]
name = "api.example.com"
backends = ["10.0.0.1", "10.0.0.2"]
strategy = "weighted"
health_check = "tcp:443"
weights = [3, 1]
check_interval_secs = 15
ttl = 10
"#;
        let config: LbConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.pool.len(), 2);
        assert_eq!(config.pool[0].name, "web.example.com");
        assert_eq!(config.pool[0].strategy, LbStrategy::RoundRobin);
        assert_eq!(config.pool[1].weights, Some(vec![3, 1]));
    }

    #[test]
    fn test_pool_snapshot() {
        let mgr = LoadBalancerManager::new();
        mgr.load_config(&sample_config());

        let snapshots = mgr.get_all_snapshots();
        assert_eq!(snapshots.len(), 2);

        let web_snap = snapshots.iter().find(|s| s.domain == "web.example.com").unwrap();
        assert_eq!(web_snap.total_backends, 3);
        assert_eq!(web_snap.healthy_backends, 3);
        assert_eq!(web_snap.strategy, "round-robin");
    }

    #[test]
    fn test_least_connections_strategy() {
        let cfg = PoolConfig {
            name: "lc.example.com".to_string(),
            backends: vec!["1.1.1.1".to_string(), "2.2.2.2".to_string()],
            strategy: LbStrategy::LeastConnections,
            health_check: None,
            weights: None,
            check_interval_secs: 30,
            ttl: 30,
        };
        let pool = LbPool::from_config(&cfg);

        // Give first backend some connections
        pool.backends[0].active_connections.store(10, Ordering::Relaxed);
        pool.backends[1].active_connections.store(2, Ordering::Relaxed);

        let b = pool.select_backend().unwrap();
        assert_eq!(b.addr, "2.2.2.2".parse::<IpAddr>().unwrap());
    }
}
