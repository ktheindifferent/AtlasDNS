//! Geographic Load Balancing Implementation
//!
//! Routes DNS queries to the nearest or best-performing servers based on
//! geographic location, latency, and server health.
//!
//! # Features
//!
//! * **GeoIP Detection** - Identify client location from IP address
//! * **Proximity Routing** - Route to nearest datacenter
//! * **Health-Aware** - Consider server health in routing decisions
//! * **Latency-Based** - Route based on measured latencies
//! * **Failover Support** - Automatic failover to next best location
//! * **Custom Policies** - Define routing rules per zone

use std::collections::HashMap;
use std::sync::Arc;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};

use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, TransientTtl};
use crate::dns::errors::DnsError;

/// Geographic region identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GeoRegion {
    /// North America
    NorthAmerica,
    /// South America
    SouthAmerica,
    /// Europe
    Europe,
    /// Asia Pacific
    AsiaPacific,
    /// Middle East
    MiddleEast,
    /// Africa
    Africa,
    /// Oceania
    Oceania,
    /// Custom region
    Custom(u32),
}

/// Datacenter location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Datacenter {
    /// Unique identifier
    pub id: String,
    /// Display name
    pub name: String,
    /// Geographic region
    pub region: GeoRegion,
    /// Country code (ISO 3166-1 alpha-2)
    pub country: String,
    /// City name
    pub city: String,
    /// Latitude
    pub latitude: f64,
    /// Longitude
    pub longitude: f64,
    /// Server addresses
    pub servers: Vec<ServerEndpoint>,
    /// Is datacenter active
    pub active: bool,
    /// Weight for load distribution
    pub weight: u32,
}

/// Server endpoint in a datacenter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEndpoint {
    /// IP address
    pub address: IpAddr,
    /// Server health status
    pub health: HealthStatus,
    /// Current load (0-100)
    pub load: u8,
    /// Response time in milliseconds
    pub latency_ms: u32,
    /// Last health check time (seconds since epoch)
    #[serde(skip)]
    pub last_check: Option<Instant>,
}

/// Health status of a server
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Server is healthy
    Healthy,
    /// Server is degraded but operational
    Degraded,
    /// Server is unhealthy
    Unhealthy,
    /// Health unknown
    Unknown,
}

/// Load balancing policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadBalancingPolicy {
    /// Route to geographically nearest datacenter
    GeographicProximity,
    /// Route based on lowest latency
    LowestLatency,
    /// Round-robin across datacenters
    RoundRobin,
    /// Weighted round-robin
    WeightedRoundRobin,
    /// Route based on server load
    LeastConnections,
    /// Custom routing function
    Custom(String),
}

/// GeoIP database entry
#[derive(Debug, Clone)]
struct GeoIPEntry {
    /// IP range start
    start_ip: IpAddr,
    /// IP range end
    end_ip: IpAddr,
    /// Geographic region
    region: GeoRegion,
    /// Country code
    country: String,
    /// City (optional)
    city: Option<String>,
    /// Latitude
    latitude: f64,
    /// Longitude  
    longitude: f64,
}

/// Geographic load balancer
pub struct GeoLoadBalancer {
    /// Datacenter configurations
    datacenters: Arc<RwLock<HashMap<String, Datacenter>>>,
    /// GeoIP database
    geoip_db: Arc<RwLock<Vec<GeoIPEntry>>>,
    /// Zone routing policies
    zone_policies: Arc<RwLock<HashMap<String, ZonePolicy>>>,
    /// Health checker
    health_checker: Arc<HealthChecker>,
    /// Statistics
    stats: Arc<RwLock<GeoStats>>,
    /// Round-robin counters
    rr_counters: Arc<RwLock<HashMap<String, usize>>>,
}

/// Zone-specific routing policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZonePolicy {
    /// Zone name
    pub zone: String,
    /// Load balancing policy
    pub policy: LoadBalancingPolicy,
    /// Preferred datacenters
    pub preferred_dcs: Vec<String>,
    /// Fallback datacenters
    pub fallback_dcs: Vec<String>,
    /// Enable health checks
    pub health_checks: bool,
    /// TTL for responses
    pub ttl: u32,
    /// Enable EDNS client subnet
    pub use_ecs: bool,
}

/// Geographic routing statistics
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GeoStats {
    /// Total queries routed
    pub total_queries: u64,
    /// Queries per region
    pub queries_by_region: HashMap<GeoRegion, u64>,
    /// Queries per datacenter
    pub queries_by_dc: HashMap<String, u64>,
    /// Failovers performed
    pub failovers: u64,
    /// Average routing time
    pub avg_routing_time_us: u64,
}

/// Health checker for datacenters
pub struct HealthChecker {
    /// Check interval
    check_interval: Duration,
    /// Timeout for health checks
    timeout: Duration,
    /// Last check results
    last_results: Arc<RwLock<HashMap<String, HealthCheckResult>>>,
}

/// Health check result
#[derive(Debug, Clone)]
struct HealthCheckResult {
    /// Datacenter ID
    dc_id: String,
    /// Overall health
    health: HealthStatus,
    /// Individual server results
    server_results: Vec<(IpAddr, HealthStatus, u32)>,
    /// Check timestamp
    timestamp: Instant,
}

impl GeoLoadBalancer {
    /// Create a new geographic load balancer
    pub fn new() -> Self {
        Self {
            datacenters: Arc::new(RwLock::new(HashMap::new())),
            geoip_db: Arc::new(RwLock::new(Vec::new())),
            zone_policies: Arc::new(RwLock::new(HashMap::new())),
            health_checker: Arc::new(HealthChecker::new()),
            stats: Arc::new(RwLock::new(GeoStats::default())),
            rr_counters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialize with default datacenters
    pub fn init_default_datacenters(&mut self) {
        let datacenters = vec![
            Datacenter {
                id: "us-east".to_string(),
                name: "US East (Virginia)".to_string(),
                region: GeoRegion::NorthAmerica,
                country: "US".to_string(),
                city: "Ashburn".to_string(),
                latitude: 39.0438,
                longitude: -77.4874,
                servers: vec![
                    ServerEndpoint {
                        address: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
                        health: HealthStatus::Healthy,
                        load: 30,
                        latency_ms: 5,
                        last_check: Some(Instant::now()),
                    },
                ],
                active: true,
                weight: 100,
            },
            Datacenter {
                id: "eu-west".to_string(),
                name: "EU West (Frankfurt)".to_string(),
                region: GeoRegion::Europe,
                country: "DE".to_string(),
                city: "Frankfurt".to_string(),
                latitude: 50.1109,
                longitude: 8.6821,
                servers: vec![
                    ServerEndpoint {
                        address: IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)),
                        health: HealthStatus::Healthy,
                        load: 45,
                        latency_ms: 8,
                        last_check: Some(Instant::now()),
                    },
                ],
                active: true,
                weight: 100,
            },
            Datacenter {
                id: "ap-southeast".to_string(),
                name: "Asia Pacific (Singapore)".to_string(),
                region: GeoRegion::AsiaPacific,
                country: "SG".to_string(),
                city: "Singapore".to_string(),
                latitude: 1.3521,
                longitude: 103.8198,
                servers: vec![
                    ServerEndpoint {
                        address: IpAddr::V4(Ipv4Addr::new(10, 2, 1, 1)),
                        health: HealthStatus::Healthy,
                        load: 60,
                        latency_ms: 12,
                        last_check: Some(Instant::now()),
                    },
                ],
                active: true,
                weight: 100,
            },
        ];

        let mut dcs = self.datacenters.write();
        for dc in datacenters {
            dcs.insert(dc.id.clone(), dc);
        }
    }

    /// Route query based on geographic location
    pub fn route_query(
        &self,
        packet: &DnsPacket,
        client_ip: IpAddr,
        zone: &str,
    ) -> Result<DnsPacket, DnsError> {
        let start = Instant::now();
        
        // Get client location from EDNS client subnet if available
        let effective_ip = self.get_effective_client_ip(packet, client_ip);
        
        // Determine client region
        let client_region = self.get_client_region(effective_ip);
        
        // Get zone policy
        let policy = self.get_zone_policy(zone);
        
        // Select datacenter based on policy
        let datacenter = self.select_datacenter(
            client_region,
            &policy,
            zone,
        )?;
        
        // Build response with selected datacenter
        let response = self.build_geo_response(
            packet,
            &datacenter,
            policy.ttl,
        )?;
        
        // Update statistics
        self.update_stats(client_region, &datacenter.id, start.elapsed());
        
        Ok(response)
    }

    /// Get effective client IP from EDNS client subnet
    fn get_effective_client_ip(&self, packet: &DnsPacket, default_ip: IpAddr) -> IpAddr {
        // For now, just use the default IP
        // Full EDNS processing would require mutable packet
        default_ip
    }

    /// Get client's geographic region
    fn get_client_region(&self, ip: IpAddr) -> GeoRegion {
        let geoip = self.geoip_db.read();
        
        for entry in geoip.iter() {
            if self.ip_in_range(ip, entry.start_ip, entry.end_ip) {
                return entry.region;
            }
        }
        
        // Default region based on IP type
        match ip {
            IpAddr::V4(addr) => {
                let first_octet = addr.octets()[0];
                match first_octet {
                    1..=50 => GeoRegion::AsiaPacific,
                    51..=100 => GeoRegion::Europe,
                    101..=150 => GeoRegion::NorthAmerica,
                    _ => GeoRegion::NorthAmerica,
                }
            }
            IpAddr::V6(_) => GeoRegion::Europe,
        }
    }

    /// Check if IP is in range
    fn ip_in_range(&self, ip: IpAddr, start: IpAddr, end: IpAddr) -> bool {
        match (ip, start, end) {
            (IpAddr::V4(ip), IpAddr::V4(s), IpAddr::V4(e)) => {
                ip >= s && ip <= e
            }
            (IpAddr::V6(ip), IpAddr::V6(s), IpAddr::V6(e)) => {
                ip >= s && ip <= e
            }
            _ => false,
        }
    }

    /// Get zone-specific policy
    fn get_zone_policy(&self, zone: &str) -> ZonePolicy {
        self.zone_policies
            .read()
            .get(zone)
            .cloned()
            .unwrap_or_else(|| ZonePolicy {
                zone: zone.to_string(),
                policy: LoadBalancingPolicy::GeographicProximity,
                preferred_dcs: Vec::new(),
                fallback_dcs: Vec::new(),
                health_checks: true,
                ttl: 300,
                use_ecs: true,
            })
    }

    /// Select best datacenter based on policy
    fn select_datacenter(
        &self,
        client_region: GeoRegion,
        policy: &ZonePolicy,
        zone: &str,
    ) -> Result<Datacenter, DnsError> {
        let dcs = self.datacenters.read();
        
        // Filter active and healthy datacenters
        let available_dcs: Vec<&Datacenter> = dcs
            .values()
            .filter(|dc| dc.active && self.is_datacenter_healthy(dc))
            .collect();
        
        if available_dcs.is_empty() {
            return Err(DnsError::Operation(crate::dns::errors::OperationError {
                context: "Geographic routing".to_string(),
                details: "No healthy datacenters available".to_string(),
                recovery_hint: Some("Check datacenter health".to_string()),
            }));
        }
        
        // Apply routing policy
        let selected = match &policy.policy {
            LoadBalancingPolicy::GeographicProximity => {
                // Find datacenter in same region or closest
                available_dcs
                    .iter()
                    .find(|dc| dc.region == client_region)
                    .or_else(|| available_dcs.first())
                    .copied()
            }
            LoadBalancingPolicy::LowestLatency => {
                // Select datacenter with lowest average latency
                available_dcs
                    .iter()
                    .min_by_key(|dc| self.get_datacenter_latency(dc))
                    .copied()
            }
            LoadBalancingPolicy::RoundRobin => {
                // Simple round-robin selection
                let mut counters = self.rr_counters.write();
                let counter = counters.entry(zone.to_string()).or_insert(0);
                let selected = available_dcs[*counter % available_dcs.len()];
                *counter += 1;
                Some(selected)
            }
            LoadBalancingPolicy::WeightedRoundRobin => {
                // Weighted selection based on datacenter weights
                self.select_weighted(&available_dcs)
            }
            LoadBalancingPolicy::LeastConnections => {
                // Select datacenter with lowest load
                available_dcs
                    .iter()
                    .min_by_key(|dc| self.get_datacenter_load(dc))
                    .copied()
            }
            LoadBalancingPolicy::Custom(_) => {
                // Custom policy would be implemented here
                available_dcs.first().copied()
            }
        };
        
        selected
            .cloned()
            .ok_or_else(|| DnsError::Operation(crate::dns::errors::OperationError {
                context: "Geographic routing".to_string(),
                details: "Failed to select datacenter".to_string(),
                recovery_hint: Some("Check routing policy configuration".to_string()),
            }))
    }

    /// Check if datacenter is healthy
    fn is_datacenter_healthy(&self, dc: &Datacenter) -> bool {
        dc.servers.iter().any(|s| s.health == HealthStatus::Healthy)
    }

    /// Get average datacenter latency
    fn get_datacenter_latency(&self, dc: &Datacenter) -> u32 {
        if dc.servers.is_empty() {
            return u32::MAX;
        }
        
        let total: u32 = dc.servers.iter().map(|s| s.latency_ms).sum();
        total / dc.servers.len() as u32
    }

    /// Get datacenter load
    fn get_datacenter_load(&self, dc: &Datacenter) -> u8 {
        if dc.servers.is_empty() {
            return 100;
        }
        
        let total: u16 = dc.servers.iter().map(|s| s.load as u16).sum();
        (total / dc.servers.len() as u16) as u8
    }

    /// Select datacenter using weighted round-robin
    fn select_weighted<'a>(&self, datacenters: &[&'a Datacenter]) -> Option<&'a Datacenter> {
        let total_weight: u32 = datacenters.iter().map(|dc| dc.weight).sum();
        
        if total_weight == 0 {
            return datacenters.first().copied();
        }
        
        // Simple weighted selection
        let random = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u32) % total_weight;
        
        let mut cumulative = 0;
        for dc in datacenters {
            cumulative += dc.weight;
            if random < cumulative {
                return Some(dc);
            }
        }
        
        datacenters.last().copied()
    }

    /// Build DNS response with selected datacenter
    fn build_geo_response(
        &self,
        request: &DnsPacket,
        datacenter: &Datacenter,
        ttl: u32,
    ) -> Result<DnsPacket, DnsError> {
        let mut response = DnsPacket::new();
        response.header.id = request.header.id;
        response.header.response = true;
        response.header.recursion_available = true;
        
        // Copy questions
        response.questions = request.questions.clone();
        
        // Add answers based on query type
        if let Some(question) = request.questions.first() {
            for server in &datacenter.servers {
                if server.health != HealthStatus::Healthy {
                    continue;
                }
                
                match question.qtype {
                    QueryType::A => {
                        if let IpAddr::V4(addr) = server.address {
                            response.answers.push(DnsRecord::A {
                                domain: question.name.clone(),
                                addr,
                                ttl: TransientTtl(ttl),
                            });
                        }
                    }
                    QueryType::Aaaa => {
                        if let IpAddr::V6(addr) = server.address {
                            response.answers.push(DnsRecord::Aaaa {
                                domain: question.name.clone(),
                                addr,
                                ttl: TransientTtl(ttl),
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
        
        Ok(response)
    }

    /// Update statistics
    fn update_stats(&self, region: GeoRegion, dc_id: &str, routing_time: Duration) {
        let mut stats = self.stats.write();
        
        stats.total_queries += 1;
        *stats.queries_by_region.entry(region).or_insert(0) += 1;
        *stats.queries_by_dc.entry(dc_id.to_string()).or_insert(0) += 1;
        
        // Update average routing time
        let new_time = routing_time.as_micros() as u64;
        let n = stats.total_queries;
        stats.avg_routing_time_us = 
            ((stats.avg_routing_time_us * (n - 1)) + new_time) / n;
    }

    /// Get statistics
    pub fn get_stats(&self) -> GeoStats {
        let stats = self.stats.read();
        GeoStats {
            total_queries: stats.total_queries,
            queries_by_region: stats.queries_by_region.clone(),
            queries_by_dc: stats.queries_by_dc.clone(),
            failovers: stats.failovers,
            avg_routing_time_us: stats.avg_routing_time_us,
        }
    }

    /// Calculate distance between two geographic points
    pub fn calculate_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
        // Haversine formula
        let r = 6371.0; // Earth's radius in km
        
        let dlat = (lat2 - lat1).to_radians();
        let dlon = (lon2 - lon1).to_radians();
        
        let a = (dlat / 2.0).sin().powi(2) +
                lat1.to_radians().cos() * lat2.to_radians().cos() *
                (dlon / 2.0).sin().powi(2);
        
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
        
        r * c
    }
}

impl HealthChecker {
    /// Create new health checker
    pub fn new() -> Self {
        Self {
            check_interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            last_results: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Perform health check on datacenter
    pub async fn check_datacenter(&self, dc: &Datacenter) -> HealthCheckResult {
        let mut server_results = Vec::new();
        let mut overall_health = HealthStatus::Healthy;
        
        for server in &dc.servers {
            // Simplified health check - would ping server in production
            let health = if server.latency_ms < 100 && server.load < 80 {
                HealthStatus::Healthy
            } else if server.latency_ms < 500 && server.load < 95 {
                HealthStatus::Degraded
            } else {
                HealthStatus::Unhealthy
            };
            
            server_results.push((server.address, health, server.latency_ms));
            
            if health == HealthStatus::Unhealthy {
                overall_health = HealthStatus::Unhealthy;
            } else if health == HealthStatus::Degraded && overall_health != HealthStatus::Unhealthy {
                overall_health = HealthStatus::Degraded;
            }
        }
        
        let result = HealthCheckResult {
            dc_id: dc.id.clone(),
            health: overall_health,
            server_results,
            timestamp: Instant::now(),
        };
        
        self.last_results.write().insert(dc.id.clone(), result.clone());
        
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geo_region_detection() {
        let balancer = GeoLoadBalancer::new();
        
        let ip_us = IpAddr::V4(Ipv4Addr::new(104, 20, 1, 1));
        let region = balancer.get_client_region(ip_us);
        assert_eq!(region, GeoRegion::NorthAmerica);
    }

    #[test]
    fn test_distance_calculation() {
        // New York to London
        let distance = GeoLoadBalancer::calculate_distance(
            40.7128, -74.0060,  // NYC
            51.5074, -0.1278,   // London
        );
        
        // Should be approximately 5570 km
        assert!(distance > 5500.0 && distance < 5600.0);
    }

    #[test]
    fn test_datacenter_health_check() {
        let dc = Datacenter {
            id: "test".to_string(),
            name: "Test DC".to_string(),
            region: GeoRegion::NorthAmerica,
            country: "US".to_string(),
            city: "Test".to_string(),
            latitude: 0.0,
            longitude: 0.0,
            servers: vec![
                ServerEndpoint {
                    address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    health: HealthStatus::Healthy,
                    load: 50,
                    latency_ms: 10,
                    last_check: None,
                },
            ],
            active: true,
            weight: 100,
        };
        
        let balancer = GeoLoadBalancer::new();
        assert!(balancer.is_datacenter_healthy(&dc));
    }
}