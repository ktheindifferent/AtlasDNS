//! Proximity-Based Routing
//!
//! Dynamic closest-server selection based on network latency, geographic
//! distance, and real-time performance metrics.
//!
//! # Features
//!
//! * **Latency-Based Routing** - Route to lowest latency endpoint
//! * **Geographic Proximity** - Consider physical distance
//! * **Network Topology Aware** - AS path and hop count consideration
//! * **Dynamic Probing** - Continuous latency measurement
//! * **Weighted Selection** - Multi-factor routing decisions
//! * **Failover Support** - Automatic rerouting on failures
//! * **Client Subnet Awareness** - EDNS Client Subnet support

use std::sync::Arc;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};

/// Proximity routing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProximityRoutingConfig {
    /// Enable proximity routing
    pub enabled: bool,
    /// Routing algorithm
    pub algorithm: RoutingAlgorithm,
    /// Probe interval
    pub probe_interval: Duration,
    /// Probe timeout
    pub probe_timeout: Duration,
    /// Weight factors
    pub weight_factors: WeightFactors,
    /// Enable client subnet
    pub client_subnet_enabled: bool,
    /// Maximum endpoints to return
    pub max_endpoints: usize,
    /// Cache proximity data
    pub cache_proximity: bool,
    /// Cache TTL
    pub cache_ttl: Duration,
}

impl Default for ProximityRoutingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            algorithm: RoutingAlgorithm::WeightedProximity,
            probe_interval: Duration::from_secs(60),
            probe_timeout: Duration::from_secs(5),
            weight_factors: WeightFactors::default(),
            client_subnet_enabled: true,
            max_endpoints: 3,
            cache_proximity: true,
            cache_ttl: Duration::from_secs(300),
        }
    }
}

/// Routing algorithm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoutingAlgorithm {
    /// Lowest latency wins
    LowestLatency,
    /// Shortest geographic distance
    GeographicNearest,
    /// Weighted combination of factors
    WeightedProximity,
    /// Network topology based
    TopologyAware,
    /// Custom algorithm
    Custom(String),
}

/// Weight factors for routing decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightFactors {
    /// Latency weight (0-1)
    pub latency: f64,
    /// Geographic distance weight (0-1)
    pub geographic: f64,
    /// Network hops weight (0-1)
    pub network_hops: f64,
    /// Load weight (0-1)
    pub load: f64,
    /// Health score weight (0-1)
    pub health: f64,
}

impl Default for WeightFactors {
    fn default() -> Self {
        Self {
            latency: 0.4,
            geographic: 0.2,
            network_hops: 0.2,
            load: 0.1,
            health: 0.1,
        }
    }
}

/// Proximity endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProximityEndpoint {
    /// Endpoint ID
    pub id: String,
    /// Endpoint address
    pub address: SocketAddr,
    /// Geographic location
    pub location: GeographicLocation,
    /// Network information
    pub network_info: NetworkInfo,
    /// Current load (0-1)
    pub load: f64,
    /// Health score (0-100)
    pub health_score: f64,
    /// Enabled flag
    pub enabled: bool,
    /// Tags
    pub tags: HashMap<String, String>,
}

/// Geographic location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeographicLocation {
    /// Latitude
    pub latitude: f64,
    /// Longitude
    pub longitude: f64,
    /// Country code
    pub country: String,
    /// City
    pub city: String,
    /// Region/State
    pub region: String,
    /// Continent
    pub continent: String,
}

/// Network information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// AS number
    pub asn: u32,
    /// AS name
    pub as_name: String,
    /// Network prefix
    pub prefix: String,
    /// Peering points
    pub peering_points: Vec<String>,
}

/// Client information
#[derive(Debug, Clone)]
pub struct ClientInfo {
    /// Client IP
    pub ip: IpAddr,
    /// Client subnet (EDNS)
    pub subnet: Option<ClientSubnet>,
    /// Estimated location
    pub location: Option<GeographicLocation>,
    /// Network info
    pub network_info: Option<NetworkInfo>,
}

/// EDNS Client Subnet
#[derive(Debug, Clone)]
pub struct ClientSubnet {
    /// Address family
    pub family: u16,
    /// Source prefix length
    pub source_prefix_len: u8,
    /// Scope prefix length
    pub scope_prefix_len: u8,
    /// Address
    pub address: IpAddr,
}

/// Proximity measurement
#[derive(Debug, Clone)]
pub struct ProximityMeasurement {
    /// Endpoint ID
    pub endpoint_id: String,
    /// Latency
    pub latency: Duration,
    /// Geographic distance (km)
    pub distance_km: f64,
    /// Network hops
    pub network_hops: u32,
    /// AS path length
    pub as_path_length: u32,
    /// Measurement time
    pub measured_at: Instant,
    /// Proximity score (0-100, higher is better)
    pub proximity_score: f64,
}

/// Routing decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingDecision {
    /// Selected endpoints (ordered by preference)
    pub endpoints: Vec<SelectedEndpoint>,
    /// Decision reasoning
    pub reasoning: String,
    /// Decision timestamp
    pub timestamp: u64,
    /// Cache key
    pub cache_key: String,
}

/// Selected endpoint with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedEndpoint {
    /// Endpoint ID
    pub id: String,
    /// Endpoint address
    pub address: SocketAddr,
    /// Proximity score
    pub score: f64,
    /// Latency
    pub latency_ms: f64,
    /// Distance
    pub distance_km: f64,
}

/// Proximity cache entry
#[derive(Debug, Clone)]
struct ProximityCacheEntry {
    /// Measurements
    measurements: Vec<ProximityMeasurement>,
    /// Cached at
    cached_at: Instant,
    /// Decision
    decision: Option<RoutingDecision>,
}

/// Proximity routing statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProximityRoutingStats {
    /// Total routing decisions
    pub total_decisions: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// Average decision time (ms)
    pub avg_decision_time_ms: f64,
    /// Routing by algorithm
    pub routing_by_algorithm: HashMap<String, u64>,
}

/// Proximity routing handler
pub struct ProximityRoutingHandler {
    /// Configuration
    config: Arc<RwLock<ProximityRoutingConfig>>,
    /// Endpoints
    endpoints: Arc<RwLock<HashMap<String, ProximityEndpoint>>>,
    /// Proximity cache
    proximity_cache: Arc<RwLock<HashMap<String, ProximityCacheEntry>>>,
    /// Latency probes
    latency_probes: Arc<RwLock<HashMap<String, LatencyProbe>>>,
    /// Statistics
    stats: Arc<RwLock<ProximityRoutingStats>>,
}

/// Latency probe
#[derive(Debug, Clone)]
struct LatencyProbe {
    /// Endpoint ID
    endpoint_id: String,
    /// Recent measurements
    measurements: Vec<Duration>,
    /// Moving average
    moving_avg: f64,
    /// Last probe
    last_probe: Instant,
}

impl ProximityRoutingHandler {
    /// Create new proximity routing handler
    pub fn new(config: ProximityRoutingConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            proximity_cache: Arc::new(RwLock::new(HashMap::new())),
            latency_probes: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ProximityRoutingStats::default())),
        }
    }

    /// Add endpoint
    pub fn add_endpoint(&self, endpoint: ProximityEndpoint) {
        let id = endpoint.id.clone();
        self.endpoints.write().insert(id.clone(), endpoint);
        
        // Initialize latency probe
        self.latency_probes.write().insert(id.clone(), LatencyProbe {
            endpoint_id: id,
            measurements: Vec::new(),
            moving_avg: 0.0,
            last_probe: Instant::now(),
        });
    }

    /// Remove endpoint
    pub fn remove_endpoint(&self, endpoint_id: &str) {
        self.endpoints.write().remove(endpoint_id);
        self.latency_probes.write().remove(endpoint_id);
        self.proximity_cache.write().clear(); // Clear cache
    }

    /// Route query to closest endpoint
    pub fn route_query(&self, client_info: &ClientInfo, domain: &str) -> RoutingDecision {
        let config = self.config.read();
        let start = Instant::now();
        
        if !config.enabled {
            return self.default_routing();
        }

        self.stats.write().total_decisions += 1;

        // Check cache
        let cache_key = self.generate_cache_key(client_info, domain);
        if config.cache_proximity {
            if let Some(cached) = self.get_cached_decision(&cache_key) {
                self.stats.write().cache_hits += 1;
                return cached;
            }
        }
        
        self.stats.write().cache_misses += 1;

        // Measure proximity to all endpoints
        let measurements = self.measure_proximity(client_info);
        
        // Apply routing algorithm
        let decision = match config.algorithm {
            RoutingAlgorithm::LowestLatency => {
                self.route_by_latency(measurements.clone())
            }
            RoutingAlgorithm::GeographicNearest => {
                self.route_by_geography(measurements.clone())
            }
            RoutingAlgorithm::WeightedProximity => {
                self.route_by_weighted_proximity(measurements.clone(), &config.weight_factors)
            }
            RoutingAlgorithm::TopologyAware => {
                self.route_by_topology(measurements.clone())
            }
            RoutingAlgorithm::Custom(ref name) => {
                self.route_custom(measurements.clone(), name)
            }
        };

        // Cache decision
        if config.cache_proximity {
            self.cache_decision(&cache_key, &decision, measurements);
        }

        // Update statistics
        let duration = start.elapsed();
        self.update_stats(duration, &config.algorithm);

        decision
    }

    /// Measure proximity to all endpoints
    fn measure_proximity(&self, client_info: &ClientInfo) -> Vec<ProximityMeasurement> {
        let endpoints = self.endpoints.read();
        let mut measurements = Vec::new();

        for endpoint in endpoints.values() {
            if !endpoint.enabled {
                continue;
            }

            let measurement = self.measure_endpoint_proximity(client_info, endpoint);
            measurements.push(measurement);
        }

        // Sort by proximity score (higher is better)
        measurements.sort_by(|a, b| b.proximity_score.partial_cmp(&a.proximity_score).unwrap());
        
        measurements
    }

    /// Measure proximity to single endpoint
    fn measure_endpoint_proximity(
        &self,
        client_info: &ClientInfo,
        endpoint: &ProximityEndpoint,
    ) -> ProximityMeasurement {
        // Get latency from probes
        let latency = self.get_endpoint_latency(&endpoint.id)
            .unwrap_or(Duration::from_millis(100));

        // Calculate geographic distance
        let distance_km = if let Some(client_loc) = &client_info.location {
            self.calculate_distance(client_loc, &endpoint.location)
        } else {
            1000.0 // Default distance
        };

        // Calculate network hops
        let (network_hops, as_path_length) = self.calculate_network_distance(
            client_info.network_info.as_ref(),
            &endpoint.network_info,
        );

        // Calculate proximity score
        let proximity_score = self.calculate_proximity_score(
            latency,
            distance_km,
            network_hops,
            endpoint.load,
            endpoint.health_score,
        );

        ProximityMeasurement {
            endpoint_id: endpoint.id.clone(),
            latency,
            distance_km,
            network_hops,
            as_path_length,
            measured_at: Instant::now(),
            proximity_score,
        }
    }

    /// Calculate proximity score
    fn calculate_proximity_score(
        &self,
        latency: Duration,
        distance_km: f64,
        network_hops: u32,
        load: f64,
        health_score: f64,
    ) -> f64 {
        let config = self.config.read();
        let weights = &config.weight_factors;

        let mut score = 100.0;

        // Latency factor (lower is better)
        let latency_ms = latency.as_millis() as f64;
        let latency_score = (100.0 - latency_ms.min(100.0)) * weights.latency;
        score *= latency_score / 100.0;

        // Geographic factor (closer is better)
        let geo_score = (100.0 - (distance_km / 100.0).min(100.0)) * weights.geographic;
        score *= geo_score / 100.0;

        // Network hops factor (fewer is better)
        let hops_score = (100.0 - (network_hops as f64 * 10.0).min(100.0)) * weights.network_hops;
        score *= hops_score / 100.0;

        // Load factor (lower is better)
        let load_score = (100.0 - (load * 100.0)) * weights.load;
        score *= load_score / 100.0;

        // Health factor (higher is better)
        let health_weight_score = health_score * weights.health;
        score *= health_weight_score / 100.0;

        score.max(0.0).min(100.0)
    }

    /// Route by lowest latency
    fn route_by_latency(&self, mut measurements: Vec<ProximityMeasurement>) -> RoutingDecision {
        measurements.sort_by_key(|m| m.latency);
        self.create_decision(measurements, "Lowest latency routing")
    }

    /// Route by geographic proximity
    fn route_by_geography(&self, mut measurements: Vec<ProximityMeasurement>) -> RoutingDecision {
        measurements.sort_by(|a, b| a.distance_km.partial_cmp(&b.distance_km).unwrap());
        self.create_decision(measurements, "Geographic proximity routing")
    }

    /// Route by weighted proximity
    fn route_by_weighted_proximity(
        &self,
        measurements: Vec<ProximityMeasurement>,
        _weights: &WeightFactors,
    ) -> RoutingDecision {
        // Already sorted by proximity score
        self.create_decision(measurements, "Weighted proximity routing")
    }

    /// Route by network topology
    fn route_by_topology(&self, mut measurements: Vec<ProximityMeasurement>) -> RoutingDecision {
        measurements.sort_by_key(|m| m.as_path_length);
        self.create_decision(measurements, "Topology-aware routing")
    }

    /// Custom routing algorithm
    fn route_custom(&self, measurements: Vec<ProximityMeasurement>, name: &str) -> RoutingDecision {
        // Would implement custom algorithm
        self.create_decision(measurements, &format!("Custom routing: {}", name))
    }

    /// Create routing decision
    fn create_decision(
        &self,
        measurements: Vec<ProximityMeasurement>,
        reasoning: &str,
    ) -> RoutingDecision {
        let config = self.config.read();
        let endpoints = self.endpoints.read();
        
        let selected: Vec<SelectedEndpoint> = measurements
            .iter()
            .take(config.max_endpoints)
            .filter_map(|m| {
                endpoints.get(&m.endpoint_id).map(|e| SelectedEndpoint {
                    id: e.id.clone(),
                    address: e.address,
                    score: m.proximity_score,
                    latency_ms: m.latency.as_millis() as f64,
                    distance_km: m.distance_km,
                })
            })
            .collect();

        RoutingDecision {
            endpoints: selected,
            reasoning: reasoning.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            cache_key: String::new(),
        }
    }

    /// Default routing (all endpoints)
    fn default_routing(&self) -> RoutingDecision {
        let endpoints = self.endpoints.read();
        
        let selected: Vec<SelectedEndpoint> = endpoints
            .values()
            .filter(|e| e.enabled)
            .map(|e| SelectedEndpoint {
                id: e.id.clone(),
                address: e.address,
                score: 50.0,
                latency_ms: 0.0,
                distance_km: 0.0,
            })
            .collect();

        RoutingDecision {
            endpoints: selected,
            reasoning: "Default routing (proximity disabled)".to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            cache_key: String::new(),
        }
    }

    /// Get endpoint latency
    fn get_endpoint_latency(&self, endpoint_id: &str) -> Option<Duration> {
        self.latency_probes.read()
            .get(endpoint_id)
            .map(|probe| Duration::from_millis(probe.moving_avg as u64))
    }

    /// Calculate geographic distance (Haversine formula)
    fn calculate_distance(&self, loc1: &GeographicLocation, loc2: &GeographicLocation) -> f64 {
        const EARTH_RADIUS_KM: f64 = 6371.0;
        
        let lat1 = loc1.latitude.to_radians();
        let lat2 = loc2.latitude.to_radians();
        let dlat = (loc2.latitude - loc1.latitude).to_radians();
        let dlon = (loc2.longitude - loc1.longitude).to_radians();
        
        let a = (dlat / 2.0).sin().powi(2) +
            lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
        
        EARTH_RADIUS_KM * c
    }

    /// Calculate network distance
    fn calculate_network_distance(
        &self,
        client_net: Option<&NetworkInfo>,
        endpoint_net: &NetworkInfo,
    ) -> (u32, u32) {
        if let Some(client) = client_net {
            if client.asn == endpoint_net.asn {
                return (1, 0); // Same AS
            }
            
            // Simplified AS path calculation
            let as_path_length = 3; // Would calculate actual AS path
            let network_hops = 5; // Would trace actual hops
            
            (network_hops, as_path_length)
        } else {
            (10, 5) // Default values
        }
    }

    /// Generate cache key
    fn generate_cache_key(&self, client_info: &ClientInfo, domain: &str) -> String {
        let subnet = if let Some(subnet) = &client_info.subnet {
            format!("{}/{}", subnet.address, subnet.source_prefix_len)
        } else {
            client_info.ip.to_string()
        };
        
        format!("{}:{}", subnet, domain)
    }

    /// Get cached decision
    fn get_cached_decision(&self, cache_key: &str) -> Option<RoutingDecision> {
        let cache = self.proximity_cache.read();
        let config = self.config.read();
        
        cache.get(cache_key).and_then(|entry| {
            if entry.cached_at.elapsed() < config.cache_ttl {
                entry.decision.clone()
            } else {
                None
            }
        })
    }

    /// Cache decision
    fn cache_decision(
        &self,
        cache_key: &str,
        decision: &RoutingDecision,
        measurements: Vec<ProximityMeasurement>,
    ) {
        let entry = ProximityCacheEntry {
            measurements,
            cached_at: Instant::now(),
            decision: Some(decision.clone()),
        };
        
        self.proximity_cache.write().insert(cache_key.to_string(), entry);
    }

    /// Update latency probe
    pub fn update_latency(&self, endpoint_id: &str, latency: Duration) {
        let mut probes = self.latency_probes.write();
        
        if let Some(probe) = probes.get_mut(endpoint_id) {
            probe.measurements.push(latency);
            if probe.measurements.len() > 10 {
                probe.measurements.remove(0);
            }
            
            // Calculate moving average
            let sum: Duration = probe.measurements.iter().sum();
            probe.moving_avg = sum.as_millis() as f64 / probe.measurements.len() as f64;
            probe.last_probe = Instant::now();
        }
    }

    /// Update statistics
    fn update_stats(&self, decision_time: Duration, algorithm: &RoutingAlgorithm) {
        let mut stats = self.stats.write();
        
        // Update average decision time
        let n = stats.total_decisions;
        let new_time = decision_time.as_millis() as f64;
        stats.avg_decision_time_ms = 
            ((stats.avg_decision_time_ms * (n - 1) as f64) + new_time) / n as f64;
        
        // Update algorithm usage
        let algo_name = format!("{:?}", algorithm);
        *stats.routing_by_algorithm.entry(algo_name).or_insert(0) += 1;
    }

    /// Get statistics
    pub fn get_stats(&self) -> ProximityRoutingStats {
        self.stats.read().clone()
    }

    /// Clear proximity cache
    pub fn clear_cache(&self) {
        self.proximity_cache.write().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distance_calculation() {
        let handler = ProximityRoutingHandler::new(ProximityRoutingConfig::default());
        
        let loc1 = GeographicLocation {
            latitude: 37.7749,  // San Francisco
            longitude: -122.4194,
            country: "US".to_string(),
            city: "San Francisco".to_string(),
            region: "CA".to_string(),
            continent: "NA".to_string(),
        };
        
        let loc2 = GeographicLocation {
            latitude: 40.7128,  // New York
            longitude: -74.0060,
            country: "US".to_string(),
            city: "New York".to_string(),
            region: "NY".to_string(),
            continent: "NA".to_string(),
        };
        
        let distance = handler.calculate_distance(&loc1, &loc2);
        assert!(distance > 4000.0 && distance < 4200.0); // ~4130 km
    }

    #[test]
    fn test_proximity_scoring() {
        let handler = ProximityRoutingHandler::new(ProximityRoutingConfig::default());
        
        let score = handler.calculate_proximity_score(
            Duration::from_millis(10),
            100.0,
            3,
            0.2,
            90.0,
        );
        
        assert!(score > 0.0 && score <= 100.0);
    }
}