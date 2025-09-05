//! Advanced DDoS Protection with intelligent attack detection

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use sha2::Digest;

use crate::dns::protocol::{DnsPacket, QueryType};
use crate::dns::errors::DnsError;
use super::{SecurityCheckResult, SecurityAction, SecurityEvent, SecurityComponent};

/// DDoS Protection system
pub struct DDoSProtection {
    config: Arc<RwLock<DDoSConfig>>,
    attack_detector: Arc<RwLock<AttackDetector>>,
    pattern_analyzer: Arc<RwLock<PatternAnalyzer>>,
    dns_cookie_validator: Arc<RwLock<DnsCookieValidator>>,
    connection_limiter: Arc<RwLock<ConnectionLimiter>>,
    entropy_detector: Arc<RwLock<EntropyDetector>>,
    mitigation_engine: Arc<RwLock<MitigationEngine>>,
    metrics: Arc<RwLock<DDoSMetrics>>,
}

/// DDoS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DDoSConfig {
    pub enabled: bool,
    pub detection_threshold: u32,
    pub mitigation_mode: MitigationMode,
    pub enable_dns_cookies: bool,
    pub enable_entropy_detection: bool,
    pub enable_pattern_analysis: bool,
    pub max_connections_per_ip: u32,
    pub amplification_threshold: f64,
    pub random_subdomain_threshold: f64,
    pub auto_mitigation: bool,
    pub mitigation_duration: Duration,
    pub whitelist: Vec<IpAddr>,
}

impl Default for DDoSConfig {
    fn default() -> Self {
        DDoSConfig {
            enabled: true,
            detection_threshold: 1000,
            mitigation_mode: MitigationMode::Automatic,
            enable_dns_cookies: true,
            enable_entropy_detection: true,
            enable_pattern_analysis: true,
            max_connections_per_ip: 100,
            amplification_threshold: 10.0,
            random_subdomain_threshold: 0.8,
            auto_mitigation: true,
            mitigation_duration: Duration::from_secs(300),
            whitelist: Vec::new(),
        }
    }
}

/// Mitigation mode
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum MitigationMode {
    Automatic,
    Manual,
    Learning,
    Aggressive,
}

/// Threat level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub enum ThreatLevel {
    #[default]
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// Attack type
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AttackType {
    VolumetricFlood,
    AmplificationAttack,
    RandomSubdomainAttack,
    NxDomainFlood,
    QueryFlood,
    SlowDrip,
    CachePoisoning,
    TunnelAttempt,
    PatternAnomaly,
}

/// Attack detector
struct AttackDetector {
    current_attacks: HashMap<AttackType, AttackInfo>,
    detection_window: Duration,
    query_rates: VecDeque<(Instant, u32)>,
    anomaly_scores: HashMap<IpAddr, f64>,
}

/// Attack information
#[derive(Debug, Clone)]
struct AttackInfo {
    attack_type: AttackType,
    started_at: Instant,
    severity: ThreatLevel,
    source_ips: HashSet<IpAddr>,
    target_domains: HashSet<String>,
    query_count: u64,
    mitigated: bool,
}

/// Pattern analyzer
struct PatternAnalyzer {
    query_patterns: HashMap<String, QueryPattern>,
    suspicious_patterns: Vec<SuspiciousPattern>,
    baseline_profiles: HashMap<IpAddr, BaselineProfile>,
}

/// Query pattern
#[derive(Debug, Clone)]
struct QueryPattern {
    pattern: String,
    count: u64,
    first_seen: Instant,
    last_seen: Instant,
    sources: HashSet<IpAddr>,
}

/// Suspicious pattern
#[derive(Debug, Clone)]
struct SuspiciousPattern {
    pattern_type: PatternType,
    regex: Option<regex::Regex>,
    threshold: f64,
    severity: ThreatLevel,
}

/// Pattern type
#[derive(Debug, Clone, Copy, PartialEq)]
enum PatternType {
    RandomSubdomain,
    DgaDetection,
    TunnelDetection,
    AmplificationPattern,
    CachePoison,
}

/// Baseline profile for normal behavior
#[derive(Debug, Clone)]
struct BaselineProfile {
    client_ip: IpAddr,
    avg_qps: f64,
    common_query_types: HashMap<QueryType, u32>,
    common_domains: HashSet<String>,
    last_updated: Instant,
}

/// DNS Cookie validator (RFC 7873)
struct DnsCookieValidator {
    server_secret: Vec<u8>,
    client_cookies: HashMap<IpAddr, ClientCookie>,
    cookie_lifetime: Duration,
}

/// Client cookie information
#[derive(Debug, Clone)]
struct ClientCookie {
    cookie: Vec<u8>,
    validated: bool,
    created_at: Instant,
    challenge_count: u32,
}

/// Connection limiter
struct ConnectionLimiter {
    connections: HashMap<IpAddr, ConnectionInfo>,
    max_connections: u32,
    rate_per_second: u32,
}

/// Connection information
#[derive(Debug, Clone)]
struct ConnectionInfo {
    active_connections: u32,
    connection_rate: VecDeque<Instant>,
    first_seen: Instant,
    last_seen: Instant,
    total_queries: u64,
}

/// Entropy detector for random subdomain attacks
struct EntropyDetector {
    entropy_threshold: f64,
    window_size: usize,
    domain_entropy: HashMap<String, EntropyInfo>,
}

/// Entropy information
#[derive(Debug, Clone)]
struct EntropyInfo {
    domain: String,
    entropy_scores: VecDeque<f64>,
    avg_entropy: f64,
    is_suspicious: bool,
}

/// Mitigation engine
struct MitigationEngine {
    active_mitigations: HashMap<IpAddr, MitigationAction>,
    mitigation_rules: Vec<MitigationRule>,
    effectiveness_tracker: HashMap<MitigationAction, EffectivenessMetrics>,
}

/// Mitigation action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
enum MitigationAction {
    BlockIp,
    RateLimit,
    RequireCookie,
    TarpitConnection,
    Redirect,
    Challenge,
}

/// Mitigation rule
#[derive(Debug, Clone)]
struct MitigationRule {
    condition: MitigationCondition,
    action: MitigationAction,
    priority: u32,
    expires_at: Option<Instant>,
}

/// Mitigation condition
#[derive(Debug, Clone)]
enum MitigationCondition {
    ThreatLevel(ThreatLevel),
    AttackType(AttackType),
    QueryRate(u32),
    EntropyScore(f64),
    ConnectionCount(u32),
}

/// Effectiveness metrics
#[derive(Debug, Clone, Default)]
struct EffectivenessMetrics {
    applied_count: u64,
    success_count: u64,
    failure_count: u64,
    effectiveness_rate: f64,
}

/// DDoS metrics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DDoSMetrics {
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub attacks_detected: u64,
    pub attacks_mitigated: u64,
    pub current_threat_level: ThreatLevel,
    pub active_attacks: usize,
    pub blocked_ips: usize,
    pub challenged_clients: usize,
    pub cookie_validations: u64,
    pub entropy_detections: u64,
}

impl DDoSProtection {
    /// Create new DDoS protection system
    pub fn new(config: DDoSConfig) -> Self {
        let server_secret = Self::generate_server_secret();
        
        DDoSProtection {
            config: Arc::new(RwLock::new(config)),
            attack_detector: Arc::new(RwLock::new(AttackDetector {
                current_attacks: HashMap::new(),
                detection_window: Duration::from_secs(60),
                query_rates: VecDeque::new(),
                anomaly_scores: HashMap::new(),
            })),
            pattern_analyzer: Arc::new(RwLock::new(PatternAnalyzer {
                query_patterns: HashMap::new(),
                suspicious_patterns: Self::initialize_suspicious_patterns(),
                baseline_profiles: HashMap::new(),
            })),
            dns_cookie_validator: Arc::new(RwLock::new(DnsCookieValidator {
                server_secret,
                client_cookies: HashMap::new(),
                cookie_lifetime: Duration::from_secs(3600),
            })),
            connection_limiter: Arc::new(RwLock::new(ConnectionLimiter {
                connections: HashMap::new(),
                max_connections: 100,
                rate_per_second: 10,
            })),
            entropy_detector: Arc::new(RwLock::new(EntropyDetector {
                entropy_threshold: 3.5,
                window_size: 100,
                domain_entropy: HashMap::new(),
            })),
            mitigation_engine: Arc::new(RwLock::new(MitigationEngine {
                active_mitigations: HashMap::new(),
                mitigation_rules: Self::initialize_mitigation_rules(),
                effectiveness_tracker: HashMap::new(),
            })),
            metrics: Arc::new(RwLock::new(DDoSMetrics::default())),
        }
    }

    /// Check for DDoS attacks
    pub fn check_attack(&self, packet: &DnsPacket, client_ip: IpAddr) -> SecurityCheckResult {
        let config = self.config.read();
        if !config.enabled {
            return SecurityCheckResult {
                allowed: true,
                action: SecurityAction::Allow,
                reason: None,
                threat_level: ThreatLevel::None,
                events: Vec::new(),
            };
        }

        // Check whitelist
        if config.whitelist.contains(&client_ip) {
            return SecurityCheckResult {
                allowed: true,
                action: SecurityAction::Allow,
                reason: None,
                threat_level: ThreatLevel::None,
                events: Vec::new(),
            };
        }

        let mut metrics = self.metrics.write();
        metrics.total_queries += 1;

        let mut events = Vec::new();
        let mut threat_level = ThreatLevel::None;

        // Check connection limits
        if let Some(action) = self.check_connection_limits(client_ip) {
            events.push(SecurityEvent::ConnectionLimitExceeded {
                client_ip,
                connections: self.get_connection_count(client_ip),
            });
            threat_level = ThreatLevel::Medium;
        }

        // Check for amplification attacks
        if config.enable_pattern_analysis {
            if let Some(amplification_factor) = self.detect_amplification(packet) {
                if amplification_factor > config.amplification_threshold {
                    events.push(SecurityEvent::AmplificationAttackDetected {
                        client_ip,
                        amplification_factor,
                    });
                    threat_level = threat_level.max(ThreatLevel::High);
                }
            }
        }

        // Check for random subdomain attacks
        if config.enable_entropy_detection {
            if let Some(domain) = self.get_query_domain(packet) {
                let entropy = self.calculate_entropy(&domain);
                if entropy > config.random_subdomain_threshold {
                    events.push(SecurityEvent::RandomSubdomainAttack {
                        domain: domain.clone(),
                        entropy,
                    });
                    threat_level = threat_level.max(ThreatLevel::High);
                    metrics.entropy_detections += 1;
                }
            }
        }

        // Check DNS cookies if required
        // Skip cookie validation for internal/private networks
        if config.enable_dns_cookies && !self.is_internal_network(client_ip) {
            if !self.validate_dns_cookie(packet, client_ip) {
                metrics.cookie_validations += 1;
                return SecurityCheckResult {
                    allowed: false,
                    action: SecurityAction::Challenge,
                    reason: Some("DNS cookie validation required".to_string()),
                    threat_level: ThreatLevel::Low,
                    events: vec![SecurityEvent::DnsCookieRequired { client_ip }],
                };
            }
        }

        // Analyze patterns
        if config.enable_pattern_analysis {
            if let Some((pattern_type, severity)) = self.analyze_patterns(packet, client_ip) {
                events.push(SecurityEvent::SuspiciousPatternDetected {
                    pattern_type: format!("{:?}", pattern_type),
                    client_ip,
                });
                threat_level = threat_level.max(severity);
            }
        }

        // Detect ongoing attacks
        let attack_info = self.detect_attack_type(packet, client_ip);
        if let Some(attack) = attack_info {
            events.push(SecurityEvent::AttackDetected {
                attack_type: attack.attack_type,
                severity: attack.severity,
            });
            threat_level = threat_level.max(attack.severity);
            metrics.attacks_detected += 1;

            // Apply mitigation if configured
            if config.auto_mitigation {
                let mitigation = self.select_mitigation(&attack);
                self.apply_mitigation(client_ip, mitigation);
                metrics.attacks_mitigated += 1;
                
                return SecurityCheckResult {
                    allowed: false,
                    action: self.convert_mitigation_action(mitigation),
                    reason: Some(format!("DDoS attack detected: {:?}", attack.attack_type)),
                    threat_level,
                    events,
                };
            }
        }

        // Update metrics
        metrics.current_threat_level = threat_level;
        metrics.active_attacks = self.get_active_attack_count();

        if threat_level >= ThreatLevel::Medium {
            metrics.blocked_queries += 1;
            SecurityCheckResult {
                allowed: false,
                action: SecurityAction::BlockRefused,
                reason: Some("Potential DDoS attack detected".to_string()),
                threat_level,
                events,
            }
        } else {
            SecurityCheckResult {
                allowed: true,
                action: SecurityAction::Allow,
                reason: None,
                threat_level,
                events,
            }
        }
    }

    /// Initialize suspicious patterns
    fn initialize_suspicious_patterns() -> Vec<SuspiciousPattern> {
        vec![
            SuspiciousPattern {
                pattern_type: PatternType::RandomSubdomain,
                regex: None,
                threshold: 0.8,
                severity: ThreatLevel::High,
            },
            SuspiciousPattern {
                pattern_type: PatternType::DgaDetection,
                regex: Some(regex::Regex::new(r"^[a-z0-9]{16,}\.").unwrap()),
                threshold: 0.7,
                severity: ThreatLevel::High,
            },
            SuspiciousPattern {
                pattern_type: PatternType::TunnelDetection,
                regex: Some(regex::Regex::new(r"^[a-f0-9]{32,}\.").unwrap()),
                threshold: 0.6,
                severity: ThreatLevel::Medium,
            },
        ]
    }

    /// Initialize mitigation rules
    fn initialize_mitigation_rules() -> Vec<MitigationRule> {
        vec![
            MitigationRule {
                condition: MitigationCondition::ThreatLevel(ThreatLevel::Critical),
                action: MitigationAction::BlockIp,
                priority: 1,
                expires_at: None,
            },
            MitigationRule {
                condition: MitigationCondition::ThreatLevel(ThreatLevel::High),
                action: MitigationAction::RequireCookie,
                priority: 2,
                expires_at: None,
            },
            MitigationRule {
                condition: MitigationCondition::QueryRate(1000),
                action: MitigationAction::RateLimit,
                priority: 3,
                expires_at: None,
            },
        ]
    }

    /// Generate server secret for DNS cookies
    fn generate_server_secret() -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..32).map(|_| rng.gen()).collect()
    }

    /// Check connection limits
    fn check_connection_limits(&self, client_ip: IpAddr) -> Option<MitigationAction> {
        let mut limiter = self.connection_limiter.write();
        let config = self.config.read();
        
        let info = limiter.connections.entry(client_ip).or_insert_with(|| {
            ConnectionInfo {
                active_connections: 0,
                connection_rate: VecDeque::new(),
                first_seen: Instant::now(),
                last_seen: Instant::now(),
                total_queries: 0,
            }
        });
        
        info.active_connections += 1;
        info.total_queries += 1;
        info.last_seen = Instant::now();
        
        if info.active_connections > config.max_connections_per_ip {
            Some(MitigationAction::RateLimit)
        } else {
            None
        }
    }

    /// Detect amplification attacks
    fn detect_amplification(&self, packet: &DnsPacket) -> Option<f64> {
        // Check for query types commonly used in amplification attacks
        if let Some(question) = packet.questions.first() {
            match question.qtype {
                QueryType::Txt | QueryType::Unknown(255) => { // 255 is ANY
                    // Calculate potential response size vs query size
                    let query_size = 50; // Approximate
                    let potential_response_size = 500; // Approximate
                    Some(potential_response_size as f64 / query_size as f64)
                }
                _ => None,
            }
        } else {
            None
        }
    }

    /// Calculate entropy of a domain name
    fn calculate_entropy(&self, domain: &str) -> f64 {
        let mut char_counts = HashMap::new();
        let total_chars = domain.len() as f64;
        
        for c in domain.chars() {
            *char_counts.entry(c).or_insert(0) += 1;
        }
        
        let mut entropy = 0.0;
        for count in char_counts.values() {
            let probability = *count as f64 / total_chars;
            if probability > 0.0 {
                entropy -= probability * probability.log2();
            }
        }
        
        entropy
    }

    /// Check if IP address is from an internal/private network
    fn is_internal_network(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                // RFC 1918 private networks
                let octets = ipv4.octets();
                // 10.0.0.0/8
                octets[0] == 10 ||
                // 172.16.0.0/12
                (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
                // 192.168.0.0/16
                (octets[0] == 192 && octets[1] == 168) ||
                // 127.0.0.0/8 (loopback)
                octets[0] == 127
            }
            IpAddr::V6(ipv6) => {
                // IPv6 private addresses
                ipv6.is_loopback() || 
                ipv6.segments()[0] == 0xfc00 || // fc00::/7 unique local
                ipv6.segments()[0] == 0xfe80    // fe80::/10 link local
            }
        }
    }

    /// Validate DNS cookie
    fn validate_dns_cookie(&self, packet: &DnsPacket, client_ip: IpAddr) -> bool {
        // Simplified DNS cookie validation
        // In production, this would parse EDNS options and validate cookies
        let validator = self.dns_cookie_validator.read();
        
        if let Some(cookie_info) = validator.client_cookies.get(&client_ip) {
            cookie_info.validated
        } else {
            false
        }
    }

    /// Analyze patterns
    fn analyze_patterns(&self, packet: &DnsPacket, client_ip: IpAddr) -> Option<(PatternType, ThreatLevel)> {
        let analyzer = self.pattern_analyzer.read();
        
        if let Some(domain) = self.get_query_domain(packet) {
            for pattern in &analyzer.suspicious_patterns {
                if let Some(regex) = &pattern.regex {
                    if regex.is_match(&domain) {
                        return Some((pattern.pattern_type, pattern.severity));
                    }
                }
            }
        }
        
        None
    }

    /// Detect attack type
    fn detect_attack_type(&self, packet: &DnsPacket, client_ip: IpAddr) -> Option<AttackInfo> {
        let mut detector = self.attack_detector.write();
        
        // Update query rates
        let now = Instant::now();
        detector.query_rates.push_back((now, 1));
        
        // Clean old entries
        let cutoff = now - detector.detection_window;
        while let Some(&(time, _)) = detector.query_rates.front() {
            if time < cutoff {
                detector.query_rates.pop_front();
            } else {
                break;
            }
        }
        
        // Calculate current QPS
        let current_qps = detector.query_rates.len() as u32;
        let config = self.config.read();
        
        if current_qps > config.detection_threshold {
            Some(AttackInfo {
                attack_type: AttackType::QueryFlood,
                started_at: now,
                severity: ThreatLevel::High,
                source_ips: HashSet::from([client_ip]),
                target_domains: HashSet::new(),
                query_count: current_qps as u64,
                mitigated: false,
            })
        } else {
            None
        }
    }

    /// Select mitigation action
    fn select_mitigation(&self, attack: &AttackInfo) -> MitigationAction {
        let engine = self.mitigation_engine.read();
        
        for rule in &engine.mitigation_rules {
            match &rule.condition {
                MitigationCondition::ThreatLevel(level) if attack.severity >= *level => {
                    return rule.action;
                }
                MitigationCondition::AttackType(attack_type) if attack.attack_type == *attack_type => {
                    return rule.action;
                }
                _ => continue,
            }
        }
        
        MitigationAction::RateLimit
    }

    /// Apply mitigation
    fn apply_mitigation(&self, client_ip: IpAddr, action: MitigationAction) {
        let mut engine = self.mitigation_engine.write();
        engine.active_mitigations.insert(client_ip, action);
        
        let metrics = engine.effectiveness_tracker.entry(action).or_default();
        metrics.applied_count += 1;
    }

    /// Convert mitigation action to security action
    fn convert_mitigation_action(&self, action: MitigationAction) -> SecurityAction {
        match action {
            MitigationAction::BlockIp => SecurityAction::BlockRefused,
            MitigationAction::RateLimit => SecurityAction::RateLimit,
            MitigationAction::RequireCookie => SecurityAction::Challenge,
            MitigationAction::TarpitConnection => SecurityAction::BlockServfail,
            MitigationAction::Redirect => SecurityAction::Sinkhole(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            MitigationAction::Challenge => SecurityAction::Challenge,
        }
    }

    /// Get connection count for an IP
    fn get_connection_count(&self, client_ip: IpAddr) -> u32 {
        let limiter = self.connection_limiter.read();
        limiter.connections.get(&client_ip)
            .map(|info| info.active_connections)
            .unwrap_or(0)
    }

    /// Get active attack count
    fn get_active_attack_count(&self) -> usize {
        let detector = self.attack_detector.read();
        detector.current_attacks.len()
    }

    /// Get query domain from packet
    fn get_query_domain(&self, packet: &DnsPacket) -> Option<String> {
        packet.questions.first().map(|q| q.name.clone())
    }

    /// Get DDoS metrics
    pub fn get_metrics(&self) -> DDoSMetrics {
        self.metrics.read().clone()
    }
}

impl SecurityComponent for DDoSProtection {
    fn check(&self, packet: &DnsPacket, client_ip: IpAddr) -> SecurityCheckResult {
        self.check_attack(packet, client_ip)
    }

    fn metrics(&self) -> serde_json::Value {
        serde_json::to_value(self.get_metrics()).unwrap_or(serde_json::Value::Null)
    }

    fn reset(&self) {
        *self.metrics.write() = DDoSMetrics::default();
        self.attack_detector.write().current_attacks.clear();
        self.mitigation_engine.write().active_mitigations.clear();
    }

    fn config(&self) -> serde_json::Value {
        serde_json::to_value(&*self.config.read()).unwrap_or(serde_json::Value::Null)
    }

    fn update_config(&self, config: serde_json::Value) -> Result<(), DnsError> {
        let new_config: DDoSConfig = serde_json::from_value(config)
            .map_err(|_| DnsError::InvalidInput)?;
        *self.config.write() = new_config;
        Ok(())
    }
}

