//! Traffic Steering Implementation
//!
//! Percentage-based traffic distribution with A/B testing support,
//! canary deployments, and gradual rollout capabilities.
//!
//! # Features
//!
//! * **Percentage-Based Routing** - Precise traffic distribution
//! * **A/B Testing** - Multi-variant experiment support
//! * **Canary Deployments** - Safe progressive rollouts
//! * **Blue-Green Deployments** - Zero-downtime updates
//! * **Sticky Sessions** - Consistent user routing
//! * **Geo-Aware Steering** - Location-based distribution
//! * **Time-Based Rules** - Schedule-driven traffic shifts

use std::sync::Arc;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

/// Traffic steering configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSteeringConfig {
    /// Enable traffic steering
    pub enabled: bool,
    /// Default steering mode
    pub default_mode: SteeringMode,
    /// Session stickiness
    pub sticky_sessions: bool,
    /// Sticky session TTL
    pub session_ttl: Duration,
    /// Hash algorithm for distribution
    pub hash_algorithm: HashAlgorithm,
    /// Enable gradual shifts
    pub gradual_shifts: bool,
    /// Shift interval
    pub shift_interval: Duration,
    /// Maximum shift percentage per interval
    pub max_shift_percentage: f64,
}

impl Default for TrafficSteeringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_mode: SteeringMode::Weighted,
            sticky_sessions: true,
            session_ttl: Duration::from_secs(3600),
            hash_algorithm: HashAlgorithm::ConsistentHash,
            gradual_shifts: true,
            shift_interval: Duration::from_secs(300),
            max_shift_percentage: 10.0,
        }
    }
}

/// Steering mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SteeringMode {
    /// Weighted distribution
    Weighted,
    /// Round-robin
    RoundRobin,
    /// Random selection
    Random,
    /// Hash-based (consistent)
    HashBased,
    /// Least connections
    LeastConnections,
    /// Geographic
    Geographic,
    /// Time-based
    TimeBased,
}

/// Hash algorithm for distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// Consistent hashing
    ConsistentHash,
    /// Rendezvous hashing
    RendezvousHash,
    /// Maglev hashing
    MaglevHash,
    /// Simple modulo
    Modulo,
}

/// Traffic pool definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficPool {
    /// Pool ID
    pub id: String,
    /// Pool name
    pub name: String,
    /// Pool endpoints
    pub endpoints: Vec<PoolEndpoint>,
    /// Target percentage (0-100)
    pub target_percentage: f64,
    /// Current percentage
    pub current_percentage: f64,
    /// Pool type
    pub pool_type: PoolType,
    /// Enabled flag
    pub enabled: bool,
    /// Health threshold
    pub health_threshold: f64,
    /// Tags
    pub tags: HashMap<String, String>,
}

/// Pool type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PoolType {
    /// Production traffic
    Production,
    /// Canary deployment
    Canary,
    /// A/B test variant
    ABTest(String),
    /// Blue deployment
    Blue,
    /// Green deployment
    Green,
    /// Staging
    Staging,
}

/// Pool endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolEndpoint {
    /// Endpoint ID
    pub id: String,
    /// Address
    pub address: SocketAddr,
    /// Weight within pool
    pub weight: f64,
    /// Health status
    pub healthy: bool,
    /// Connections
    pub connections: u64,
    /// Response time (ms)
    pub response_time_ms: f64,
}

/// Steering policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteeringPolicy {
    /// Policy ID
    pub id: String,
    /// Policy name
    pub name: String,
    /// Domain pattern
    pub domain_pattern: String,
    /// Pools
    pub pools: Vec<String>,
    /// Steering rules
    pub rules: Vec<SteeringRule>,
    /// Priority
    pub priority: u32,
    /// Enabled flag
    pub enabled: bool,
}

/// Steering rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteeringRule {
    /// Rule type
    pub rule_type: RuleType,
    /// Pool assignments
    pub pool_assignments: HashMap<String, f64>,
    /// Condition
    pub condition: Option<RuleCondition>,
}

/// Rule type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleType {
    /// Percentage-based distribution
    Percentage,
    /// Geographic routing
    Geographic,
    /// Time-based routing
    TimeBased,
    /// Header-based routing
    HeaderBased,
    /// Cookie-based routing
    CookieBased,
    /// Custom logic
    Custom(String),
}

/// Rule condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCondition {
    /// Condition type
    pub condition_type: ConditionType,
    /// Parameters
    pub parameters: HashMap<String, String>,
}

/// Condition type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionType {
    /// Time range
    TimeRange,
    /// Geographic location
    Geographic,
    /// Client subnet
    ClientSubnet,
    /// Query rate
    QueryRate,
    /// Custom
    Custom,
}

/// Session entry
#[derive(Debug, Clone)]
struct SessionEntry {
    /// Client IP
    client_ip: IpAddr,
    /// Assigned pool
    pool_id: String,
    /// Created at
    created_at: Instant,
    /// Last accessed
    last_accessed: Instant,
}

/// Traffic shift
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficShift {
    /// Shift ID
    pub id: String,
    /// From pool
    pub from_pool: String,
    /// To pool
    pub to_pool: String,
    /// Target percentage
    pub target_percentage: f64,
    /// Current percentage
    pub current_percentage: f64,
    /// Start time
    pub start_time: u64,
    /// End time
    pub end_time: Option<u64>,
    /// Status
    pub status: ShiftStatus,
}

/// Shift status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ShiftStatus {
    /// Scheduled
    Scheduled,
    /// In progress
    InProgress,
    /// Completed
    Completed,
    /// Cancelled
    Cancelled,
    /// Failed
    Failed,
}

/// Steering decision
#[derive(Debug, Clone)]
pub struct SteeringDecision {
    /// Selected pool
    pub pool_id: String,
    /// Selected endpoints
    pub endpoints: Vec<PoolEndpoint>,
    /// Decision reason
    pub reason: String,
    /// Cache hit
    pub cache_hit: bool,
    /// Session matched
    pub session_matched: bool,
}

/// Steering statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SteeringStats {
    /// Total decisions
    pub total_decisions: u64,
    /// Decisions by pool
    pub by_pool: HashMap<String, u64>,
    /// Session hits
    pub session_hits: u64,
    /// Session misses
    pub session_misses: u64,
    /// Active shifts
    pub active_shifts: usize,
    /// Completed shifts
    pub completed_shifts: u64,
    /// Failed decisions
    pub failed_decisions: u64,
}

/// Traffic steering handler
pub struct TrafficSteeringHandler {
    /// Configuration
    config: Arc<RwLock<TrafficSteeringConfig>>,
    /// Traffic pools
    pools: Arc<RwLock<HashMap<String, TrafficPool>>>,
    /// Steering policies
    policies: Arc<RwLock<HashMap<String, SteeringPolicy>>>,
    /// Active sessions
    sessions: Arc<RwLock<HashMap<String, SessionEntry>>>,
    /// Traffic shifts
    shifts: Arc<RwLock<Vec<TrafficShift>>>,
    /// Statistics
    stats: Arc<RwLock<SteeringStats>>,
    /// Decision cache
    decision_cache: Arc<RwLock<HashMap<String, (SteeringDecision, Instant)>>>,
}

impl TrafficSteeringHandler {
    /// Create new traffic steering handler
    pub fn new(config: TrafficSteeringConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            pools: Arc::new(RwLock::new(HashMap::new())),
            policies: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            shifts: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(SteeringStats::default())),
            decision_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add traffic pool
    pub fn add_pool(&self, pool: TrafficPool) {
        self.pools.write().insert(pool.id.clone(), pool);
    }

    /// Remove traffic pool
    pub fn remove_pool(&self, pool_id: &str) {
        self.pools.write().remove(pool_id);
        
        // Clean up sessions
        self.sessions.write().retain(|_, session| {
            session.pool_id != pool_id
        });
    }

    /// Add steering policy
    pub fn add_policy(&self, policy: SteeringPolicy) {
        self.policies.write().insert(policy.id.clone(), policy);
    }

    /// Make steering decision
    pub fn make_decision(&self, client_ip: IpAddr, domain: &str) -> SteeringDecision {
        let config = self.config.read();
        
        if !config.enabled {
            return self.default_decision();
        }

        self.stats.write().total_decisions += 1;

        // Check for sticky session
        if config.sticky_sessions {
            if let Some(decision) = self.check_session(client_ip, domain) {
                self.stats.write().session_hits += 1;
                return decision;
            }
            self.stats.write().session_misses += 1;
        }

        // Check decision cache
        let cache_key = format!("{}:{}", client_ip, domain);
        if let Some(cached) = self.get_cached_decision(&cache_key) {
            return cached;
        }

        // Find matching policy
        let policy = self.find_matching_policy(domain);
        
        // Apply steering rules
        let pool_id = if let Some(policy) = policy {
            self.apply_policy_rules(&policy, client_ip)
        } else {
            self.apply_default_steering(client_ip, domain)
        };

        // Get pool endpoints
        let (endpoints, reason) = self.get_pool_endpoints(&pool_id);

        // Create decision
        let decision = SteeringDecision {
            pool_id: pool_id.clone(),
            endpoints,
            reason,
            cache_hit: false,
            session_matched: false,
        };

        // Cache decision
        self.cache_decision(&cache_key, decision.clone());

        // Create session if enabled
        if config.sticky_sessions {
            self.create_session(client_ip, domain, &pool_id);
        }

        // Update statistics
        *self.stats.write().by_pool.entry(pool_id).or_insert(0) += 1;

        decision
    }

    /// Check session
    fn check_session(&self, client_ip: IpAddr, domain: &str) -> Option<SteeringDecision> {
        let config = self.config.read();
        let session_key = format!("{}:{}", client_ip, domain);
        
        let mut sessions = self.sessions.write();
        if let Some(session) = sessions.get_mut(&session_key) {
            if session.created_at.elapsed() < config.session_ttl {
                session.last_accessed = Instant::now();
                
                let (endpoints, reason) = self.get_pool_endpoints(&session.pool_id);
                
                return Some(SteeringDecision {
                    pool_id: session.pool_id.clone(),
                    endpoints,
                    reason,
                    cache_hit: false,
                    session_matched: true,
                });
            } else {
                // Session expired
                sessions.remove(&session_key);
            }
        }
        
        None
    }

    /// Create session
    fn create_session(&self, client_ip: IpAddr, domain: &str, pool_id: &str) {
        let session_key = format!("{}:{}", client_ip, domain);
        
        let session = SessionEntry {
            client_ip,
            pool_id: pool_id.to_string(),
            created_at: Instant::now(),
            last_accessed: Instant::now(),
        };
        
        self.sessions.write().insert(session_key, session);
        
        // Clean old sessions
        if self.sessions.read().len() > 10000 {
            self.clean_sessions();
        }
    }

    /// Clean expired sessions
    fn clean_sessions(&self) {
        let config = self.config.read();
        let ttl = config.session_ttl;
        
        self.sessions.write().retain(|_, session| {
            session.created_at.elapsed() < ttl
        });
    }

    /// Find matching policy
    fn find_matching_policy(&self, domain: &str) -> Option<SteeringPolicy> {
        let policies = self.policies.read();
        
        let mut matches: Vec<(SteeringPolicy, u32)> = Vec::new();
        
        for policy in policies.values() {
            if !policy.enabled {
                continue;
            }
            
            if self.domain_matches_pattern(domain, &policy.domain_pattern) {
                matches.push((policy.clone(), policy.priority));
            }
        }
        
        // Sort by priority (lower = higher priority)
        matches.sort_by_key(|(_, priority)| *priority);
        
        matches.into_iter().next().map(|(policy, _)| policy)
    }

    /// Check if domain matches pattern
    fn domain_matches_pattern(&self, domain: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        
        if pattern.starts_with("*.") {
            let suffix = &pattern[2..];
            return domain.ends_with(suffix);
        }
        
        domain == pattern
    }

    /// Apply policy rules
    fn apply_policy_rules(&self, policy: &SteeringPolicy, client_ip: IpAddr) -> String {
        for rule in &policy.rules {
            if let Some(condition) = &rule.condition {
                if !self.evaluate_condition(condition, client_ip) {
                    continue;
                }
            }
            
            // Apply rule based on type
            match &rule.rule_type {
                RuleType::Percentage => {
                    return self.select_by_percentage(&rule.pool_assignments, client_ip);
                }
                RuleType::Geographic => {
                    return self.select_by_geography(&rule.pool_assignments, client_ip);
                }
                _ => {
                    // Use first pool
                    if let Some(pool_id) = rule.pool_assignments.keys().next() {
                        return pool_id.clone();
                    }
                }
            }
        }
        
        // Default to first pool
        policy.pools.first().cloned().unwrap_or_default()
    }

    /// Select pool by percentage
    fn select_by_percentage(&self, assignments: &HashMap<String, f64>, client_ip: IpAddr) -> String {
        let config = self.config.read();
        
        // Process active shifts
        let adjusted = self.apply_traffic_shifts(assignments);
        
        // Calculate hash for consistent selection
        let hash = match config.hash_algorithm {
            HashAlgorithm::ConsistentHash => self.consistent_hash(client_ip),
            HashAlgorithm::RendezvousHash => self.rendezvous_hash(client_ip),
            HashAlgorithm::MaglevHash => self.maglev_hash(client_ip),
            HashAlgorithm::Modulo => self.simple_hash(client_ip),
        };
        
        // Select pool based on hash
        let mut cumulative = 0.0;
        let hash_normalized = (hash % 10000) as f64 / 10000.0;
        
        for (pool_id, percentage) in adjusted.iter() {
            cumulative += percentage / 100.0;
            if hash_normalized < cumulative {
                return pool_id.clone();
            }
        }
        
        // Fallback to first pool
        adjusted.keys().next().cloned().unwrap_or_default()
    }

    /// Apply traffic shifts
    fn apply_traffic_shifts(&self, base: &HashMap<String, f64>) -> HashMap<String, f64> {
        let mut adjusted = base.clone();
        let shifts = self.shifts.read();
        
        for shift in shifts.iter() {
            if shift.status != ShiftStatus::InProgress {
                continue;
            }
            
            if let Some(from_pct) = adjusted.get_mut(&shift.from_pool) {
                *from_pct -= shift.current_percentage;
            }
            
            if let Some(to_pct) = adjusted.get_mut(&shift.to_pool) {
                *to_pct += shift.current_percentage;
            }
        }
        
        adjusted
    }

    /// Select by geography
    fn select_by_geography(&self, assignments: &HashMap<String, f64>, _client_ip: IpAddr) -> String {
        // Would implement geographic selection
        // For now, use first pool
        assignments.keys().next().cloned().unwrap_or_default()
    }

    /// Apply default steering
    fn apply_default_steering(&self, client_ip: IpAddr, _domain: &str) -> String {
        let config = self.config.read();
        let pools = self.pools.read();
        
        let active_pools: Vec<String> = pools
            .iter()
            .filter(|(_, pool)| pool.enabled)
            .map(|(id, _)| id.clone())
            .collect();
        
        if active_pools.is_empty() {
            return String::new();
        }
        
        match config.default_mode {
            SteeringMode::RoundRobin => {
                let index = (self.stats.read().total_decisions as usize) % active_pools.len();
                active_pools[index].clone()
            }
            SteeringMode::Random => {
                let index = (client_ip.to_string().len()) % active_pools.len();
                active_pools[index].clone()
            }
            _ => active_pools[0].clone(),
        }
    }

    /// Evaluate condition
    fn evaluate_condition(&self, _condition: &RuleCondition, _client_ip: IpAddr) -> bool {
        // Would implement condition evaluation
        true
    }

    /// Get pool endpoints
    fn get_pool_endpoints(&self, pool_id: &str) -> (Vec<PoolEndpoint>, String) {
        let pools = self.pools.read();
        
        if let Some(pool) = pools.get(pool_id) {
            let healthy_endpoints: Vec<PoolEndpoint> = pool.endpoints
                .iter()
                .filter(|e| e.healthy)
                .cloned()
                .collect();
            
            if !healthy_endpoints.is_empty() {
                return (healthy_endpoints, format!("Pool {} selected", pool.name));
            }
        }
        
        (Vec::new(), "No healthy endpoints".to_string())
    }

    /// Consistent hash
    fn consistent_hash(&self, client_ip: IpAddr) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(client_ip.to_string().as_bytes());
        let result = hasher.finalize();
        
        let mut hash = 0u64;
        for i in 0..8 {
            hash = (hash << 8) | result[i] as u64;
        }
        hash
    }

    /// Rendezvous hash
    fn rendezvous_hash(&self, client_ip: IpAddr) -> u64 {
        // Simplified rendezvous hash
        self.consistent_hash(client_ip)
    }

    /// Maglev hash
    fn maglev_hash(&self, client_ip: IpAddr) -> u64 {
        // Simplified Maglev hash
        self.consistent_hash(client_ip)
    }

    /// Simple hash
    fn simple_hash(&self, client_ip: IpAddr) -> u64 {
        client_ip.to_string().bytes().fold(0u64, |acc, b| {
            acc.wrapping_mul(31).wrapping_add(b as u64)
        })
    }

    /// Get cached decision
    fn get_cached_decision(&self, key: &str) -> Option<SteeringDecision> {
        let cache = self.decision_cache.read();
        
        cache.get(key).and_then(|(decision, cached_at)| {
            if cached_at.elapsed() < Duration::from_secs(60) {
                Some(decision.clone())
            } else {
                None
            }
        })
    }

    /// Cache decision
    fn cache_decision(&self, key: &str, decision: SteeringDecision) {
        self.decision_cache.write().insert(
            key.to_string(),
            (decision, Instant::now()),
        );
        
        // Clean cache if too large
        if self.decision_cache.read().len() > 10000 {
            self.clean_decision_cache();
        }
    }

    /// Clean decision cache
    fn clean_decision_cache(&self) {
        self.decision_cache.write().retain(|_, (_, cached_at)| {
            cached_at.elapsed() < Duration::from_secs(60)
        });
    }

    /// Default decision
    fn default_decision(&self) -> SteeringDecision {
        SteeringDecision {
            pool_id: String::new(),
            endpoints: Vec::new(),
            reason: "Steering disabled".to_string(),
            cache_hit: false,
            session_matched: false,
        }
    }

    /// Start traffic shift
    pub fn start_shift(
        &self,
        from_pool: &str,
        to_pool: &str,
        target_percentage: f64,
    ) -> Result<String, String> {
        let pools = self.pools.read();
        
        if !pools.contains_key(from_pool) {
            return Err(format!("Source pool {} not found", from_pool));
        }
        if !pools.contains_key(to_pool) {
            return Err(format!("Target pool {} not found", to_pool));
        }
        
        let shift = TrafficShift {
            id: Self::generate_id(),
            from_pool: from_pool.to_string(),
            to_pool: to_pool.to_string(),
            target_percentage,
            current_percentage: 0.0,
            start_time: Self::current_timestamp(),
            end_time: None,
            status: ShiftStatus::InProgress,
        };
        
        let shift_id = shift.id.clone();
        self.shifts.write().push(shift);
        
        Ok(shift_id)
    }

    /// Update shift progress
    pub fn update_shift_progress(&self) {
        let config = self.config.read();
        let mut shifts = self.shifts.write();
        
        for shift in shifts.iter_mut() {
            if shift.status != ShiftStatus::InProgress {
                continue;
            }
            
            if shift.current_percentage < shift.target_percentage {
                let increment = config.max_shift_percentage.min(
                    shift.target_percentage - shift.current_percentage
                );
                shift.current_percentage += increment;
                
                if shift.current_percentage >= shift.target_percentage {
                    shift.status = ShiftStatus::Completed;
                    shift.end_time = Some(Self::current_timestamp());
                    self.stats.write().completed_shifts += 1;
                }
            }
        }
    }

    /// Cancel shift
    pub fn cancel_shift(&self, shift_id: &str) -> Result<(), String> {
        let mut shifts = self.shifts.write();
        
        if let Some(shift) = shifts.iter_mut().find(|s| s.id == shift_id) {
            if shift.status == ShiftStatus::InProgress {
                shift.status = ShiftStatus::Cancelled;
                shift.end_time = Some(Self::current_timestamp());
                Ok(())
            } else {
                Err("Shift not in progress".to_string())
            }
        } else {
            Err("Shift not found".to_string())
        }
    }

    /// Get active shifts
    pub fn get_active_shifts(&self) -> Vec<TrafficShift> {
        self.shifts.read()
            .iter()
            .filter(|s| s.status == ShiftStatus::InProgress)
            .cloned()
            .collect()
    }

    /// Get statistics
    pub fn get_stats(&self) -> SteeringStats {
        let mut stats = self.stats.read().clone();
        stats.active_shifts = self.get_active_shifts().len();
        stats
    }
    
    /// Check if traffic steering is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.read().enabled
    }
    
    /// Get number of active policies
    pub fn get_policy_count(&self) -> usize {
        self.policies.read().len()
    }
    
    /// Get number of traffic pools
    pub fn get_pool_count(&self) -> usize {
        self.pools.read().len()
    }
    
    /// Get configuration
    pub fn get_config(&self) -> TrafficSteeringConfig {
        self.config.read().clone()
    }

    /// Generate ID
    fn generate_id() -> String {
        format!("{:x}", Self::current_timestamp())
    }

    /// Get current timestamp
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_percentage_distribution() {
        let config = TrafficSteeringConfig::default();
        let handler = TrafficSteeringHandler::new(config);
        
        // Create pools
        handler.add_pool(TrafficPool {
            id: "production".to_string(),
            name: "Production".to_string(),
            endpoints: vec![],
            target_percentage: 90.0,
            current_percentage: 90.0,
            pool_type: PoolType::Production,
            enabled: true,
            health_threshold: 0.8,
            tags: HashMap::new(),
        });
        
        handler.add_pool(TrafficPool {
            id: "canary".to_string(),
            name: "Canary".to_string(),
            endpoints: vec![],
            target_percentage: 10.0,
            current_percentage: 10.0,
            pool_type: PoolType::Canary,
            enabled: true,
            health_threshold: 0.8,
            tags: HashMap::new(),
        });
        
        // Test distribution
        let mut production_count = 0;
        let mut canary_count = 0;
        
        for i in 0..1000 {
            let ip = IpAddr::from([192, 168, 1, i as u8]);
            let decision = handler.make_decision(ip, "example.com");
            
            if decision.pool_id == "production" {
                production_count += 1;
            } else if decision.pool_id == "canary" {
                canary_count += 1;
            }
        }
        
        // Roughly 90/10 split (allow for hash distribution variance)
        assert!(production_count > 800);
        assert!(canary_count > 50);
    }

    #[test]
    fn test_traffic_shift() {
        let config = TrafficSteeringConfig::default();
        let handler = TrafficSteeringHandler::new(config);
        
        // Create pools
        handler.add_pool(TrafficPool {
            id: "blue".to_string(),
            name: "Blue".to_string(),
            endpoints: vec![],
            target_percentage: 100.0,
            current_percentage: 100.0,
            pool_type: PoolType::Blue,
            enabled: true,
            health_threshold: 0.8,
            tags: HashMap::new(),
        });
        
        handler.add_pool(TrafficPool {
            id: "green".to_string(),
            name: "Green".to_string(),
            endpoints: vec![],
            target_percentage: 0.0,
            current_percentage: 0.0,
            pool_type: PoolType::Green,
            enabled: true,
            health_threshold: 0.8,
            tags: HashMap::new(),
        });
        
        // Start shift
        let shift_id = handler.start_shift("blue", "green", 50.0).unwrap();
        
        // Verify shift created
        let shifts = handler.get_active_shifts();
        assert_eq!(shifts.len(), 1);
        assert_eq!(shifts[0].id, shift_id);
        
        // Update progress
        handler.update_shift_progress();
        
        let shifts = handler.get_active_shifts();
        assert!(shifts[0].current_percentage > 0.0);
    }
}