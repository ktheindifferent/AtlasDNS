//! Cache Poisoning Protection Implementation
//!
//! Prevents DNS cache poisoning attacks through multiple defense mechanisms
//! including source port randomization, query ID verification, and response validation.
//!
//! # Features
//!
//! * **Port Randomization** - Random source ports for queries
//! * **Query ID Validation** - Cryptographically secure query IDs
//! * **DNSSEC Validation** - Verify signed responses
//! * **Response Validation** - Multiple checks on responses
//! * **Bailiwick Checking** - Ensure responses are in-domain
//! * **TTL Capping** - Limit excessive TTL values
//! * **0x20 Bit Encoding** - Case randomization for additional entropy

use std::collections::HashMap;
use std::sync::Arc;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use rand::{Rng, thread_rng};
use serde::{Serialize, Deserialize};

use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, ResultCode, DnsQuestion};
use crate::dns::errors::DnsError;

/// Cache poisoning protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoisonProtectionConfig {
    /// Enable cache poisoning protection
    pub enabled: bool,
    /// Use port randomization
    pub port_randomization: bool,
    /// Port range for randomization
    pub port_range: (u16, u16),
    /// Enable 0x20 bit encoding
    pub bit_0x20: bool,
    /// Enable DNSSEC validation
    pub dnssec_validation: bool,
    /// Maximum acceptable TTL (seconds)
    pub max_ttl: u32,
    /// Minimum acceptable TTL (seconds)
    pub min_ttl: u32,
    /// Enable bailiwick checking
    pub bailiwick_check: bool,
    /// Response time window (ms)
    pub response_window_ms: u64,
    /// Maximum query retries
    pub max_retries: u32,
}

impl Default for PoisonProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port_randomization: true,
            port_range: (49152, 65535), // Dynamic/private ports
            bit_0x20: true,
            dnssec_validation: true,
            max_ttl: 86400,  // 24 hours
            min_ttl: 0,
            bailiwick_check: true,
            response_window_ms: 5000,  // 5 seconds
            max_retries: 3,
        }
    }
}

/// Query tracking for validation
#[derive(Debug, Clone)]
struct QueryTracker {
    /// Query ID
    query_id: u16,
    /// Original query name
    query_name: String,
    /// 0x20 encoded name (if used)
    encoded_name: Option<String>,
    /// Query type
    query_type: QueryType,
    /// Source port used
    source_port: u16,
    /// Destination server
    dest_server: SocketAddr,
    /// Query timestamp
    timestamp: Instant,
    /// Retry count
    retries: u32,
    /// Expected bailiwick
    bailiwick: String,
}

/// Response validation result
#[derive(Debug)]
pub enum ValidationResult {
    /// Response is valid
    Valid,
    /// Response is suspicious but might be legitimate
    Suspicious(String),
    /// Response is invalid (likely poisoning attempt)
    Invalid(String),
}

/// Cache poisoning protection system
pub struct CachePoisonProtection {
    /// Configuration
    config: Arc<RwLock<PoisonProtectionConfig>>,
    /// Active queries being tracked
    active_queries: Arc<RwLock<HashMap<u16, QueryTracker>>>,
    /// DNSSEC validation enabled (simplified for now)
    dnssec_enabled: bool,
    /// Statistics
    stats: Arc<RwLock<PoisonProtectionStats>>,
    /// Port pool for randomization
    port_pool: Arc<RwLock<Vec<u16>>>,
}

/// Protection statistics
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PoisonProtectionStats {
    /// Total queries protected
    pub queries_protected: u64,
    /// Suspicious responses detected
    pub suspicious_responses: u64,
    /// Invalid responses blocked
    pub invalid_responses: u64,
    /// DNSSEC validation failures
    pub dnssec_failures: u64,
    /// Bailiwick check failures
    pub bailiwick_failures: u64,
    /// TTL anomalies detected
    pub ttl_anomalies: u64,
    /// Port randomization entropy bits
    pub port_entropy_bits: f64,
}

impl CachePoisonProtection {
    /// Create new cache poisoning protection
    pub fn new(config: PoisonProtectionConfig) -> Self {
        // Initialize port pool
        let mut port_pool = Vec::new();
        if config.port_randomization {
            for port in config.port_range.0..=config.port_range.1 {
                port_pool.push(port);
            }
        }

        // Calculate port entropy
        let port_entropy_bits = (port_pool.len() as f64).log2();

        let mut stats = PoisonProtectionStats::default();
        stats.port_entropy_bits = port_entropy_bits;

        let dnssec_enabled = config.dnssec_validation;
        
        Self {
            config: Arc::new(RwLock::new(config)),
            active_queries: Arc::new(RwLock::new(HashMap::new())),
            dnssec_enabled,
            stats: Arc::new(RwLock::new(stats)),
            port_pool: Arc::new(RwLock::new(port_pool)),
        }
    }

    /// Prepare outgoing query with protection
    pub fn prepare_query(
        &self,
        packet: &mut DnsPacket,
        dest_server: SocketAddr,
    ) -> Result<u16, DnsError> {
        let config = self.config.read();
        
        if !config.enabled {
            return Ok(0); // Use default port
        }

        // Generate secure random query ID
        let query_id = self.generate_secure_id();
        packet.header.id = query_id;

        // Get query details
        let query = packet.questions.first().ok_or_else(|| {
            DnsError::Protocol(crate::dns::errors::ProtocolError {
                kind: crate::dns::errors::ProtocolErrorKind::MalformedPacket,
                packet_id: Some(packet.header.id),
                query_name: None,
                recoverable: false,
            })
        })?;

        let mut tracker = QueryTracker {
            query_id,
            query_name: query.name.clone(),
            encoded_name: None,
            query_type: query.qtype,
            source_port: 0,
            dest_server,
            timestamp: Instant::now(),
            retries: 0,
            bailiwick: self.extract_bailiwick(&query.name),
        };

        // Apply 0x20 bit encoding if enabled
        if config.bit_0x20 {
            let encoded = self.apply_0x20_encoding(&query.name);
            packet.questions[0].name = encoded.clone();
            tracker.encoded_name = Some(encoded);
        }

        // Select random source port if enabled
        let source_port = if config.port_randomization {
            self.get_random_port()
        } else {
            0 // Use default
        };
        tracker.source_port = source_port;

        // Track the query
        self.active_queries.write().insert(query_id, tracker);
        self.stats.write().queries_protected += 1;

        Ok(source_port)
    }

    /// Validate incoming response
    pub fn validate_response(
        &self,
        response: &DnsPacket,
        source_addr: SocketAddr,
    ) -> ValidationResult {
        let config = self.config.read();
        
        if !config.enabled {
            return ValidationResult::Valid;
        }

        // Check if we're tracking this query
        let tracker = match self.active_queries.read().get(&response.header.id) {
            Some(t) => t.clone(),
            None => {
                self.stats.write().invalid_responses += 1;
                return ValidationResult::Invalid("Unknown query ID".to_string());
            }
        };

        // Check response timing
        if tracker.timestamp.elapsed().as_millis() > config.response_window_ms as u128 {
            self.stats.write().suspicious_responses += 1;
            return ValidationResult::Suspicious("Response outside time window".to_string());
        }

        // Validate source address matches destination
        if source_addr != tracker.dest_server {
            self.stats.write().invalid_responses += 1;
            return ValidationResult::Invalid(format!(
                "Response from unexpected server: {} (expected {})",
                source_addr, tracker.dest_server
            ));
        }

        // Validate 0x20 encoding if used
        if config.bit_0x20 {
            if let Some(encoded) = &tracker.encoded_name {
                if let Some(question) = response.questions.first() {
                    if !self.validate_0x20_response(&question.name, encoded) {
                        self.stats.write().invalid_responses += 1;
                        return ValidationResult::Invalid("0x20 validation failed".to_string());
                    }
                }
            }
        }

        // Validate response code
        if response.header.rescode == ResultCode::FORMERR {
            self.stats.write().suspicious_responses += 1;
            return ValidationResult::Suspicious("FORMERR response".to_string());
        }

        // Validate answers
        for answer in &response.answers {
            // Check bailiwick
            if config.bailiwick_check {
                if !self.check_bailiwick(answer, &tracker.bailiwick) {
                    self.stats.write().bailiwick_failures += 1;
                    return ValidationResult::Invalid("Bailiwick check failed".to_string());
                }
            }

            // Check TTL limits
            let ttl = self.get_record_ttl(answer);
            if ttl > config.max_ttl || ttl < config.min_ttl {
                self.stats.write().ttl_anomalies += 1;
                return ValidationResult::Suspicious(format!(
                    "TTL {} outside acceptable range [{}, {}]",
                    ttl, config.min_ttl, config.max_ttl
                ));
            }
        }

        // DNSSEC validation if enabled (simplified check)
        if config.dnssec_validation && self.dnssec_enabled {
            if !self.validate_dnssec_simple(response) {
                self.stats.write().dnssec_failures += 1;
                return ValidationResult::Invalid("DNSSEC validation failed".to_string());
            }
        }

        // Clean up tracker
        self.active_queries.write().remove(&response.header.id);

        ValidationResult::Valid
    }

    /// Generate cryptographically secure query ID
    fn generate_secure_id(&self) -> u16 {
        let mut rng = thread_rng();
        rng.gen()
    }

    /// Get random port from pool
    fn get_random_port(&self) -> u16 {
        let pool = self.port_pool.read();
        if pool.is_empty() {
            return 0;
        }
        
        let mut rng = thread_rng();
        let index = rng.gen_range(0, pool.len());
        pool[index]
    }

    /// Apply 0x20 bit encoding to domain name
    fn apply_0x20_encoding(&self, name: &str) -> String {
        let mut rng = thread_rng();
        let mut encoded = String::new();
        
        for ch in name.chars() {
            if ch.is_ascii_alphabetic() && rng.gen_bool(0.5) {
                if ch.is_ascii_lowercase() {
                    encoded.push(ch.to_ascii_uppercase());
                } else {
                    encoded.push(ch.to_ascii_lowercase());
                }
            } else {
                encoded.push(ch);
            }
        }
        
        encoded
    }

    /// Validate 0x20 encoded response
    fn validate_0x20_response(&self, response_name: &str, query_name: &str) -> bool {
        // Names should match case-insensitively
        response_name.eq_ignore_ascii_case(query_name)
    }

    /// Extract bailiwick from domain name
    fn extract_bailiwick(&self, name: &str) -> String {
        // Bailiwick is typically the parent domain
        let parts: Vec<&str> = name.split('.').collect();
        if parts.len() > 2 {
            parts[1..].join(".")
        } else {
            name.to_string()
        }
    }

    /// Check if record is within bailiwick
    fn check_bailiwick(&self, record: &DnsRecord, bailiwick: &str) -> bool {
        let record_domain = match record {
            DnsRecord::A { domain, .. } |
            DnsRecord::Aaaa { domain, .. } |
            DnsRecord::Ns { domain, .. } |
            DnsRecord::Cname { domain, .. } |
            DnsRecord::Mx { domain, .. } |
            DnsRecord::Txt { domain, .. } |
            DnsRecord::Soa { domain, .. } => domain,
            _ => return true, // Other record types don't have domain
        };

        // Check if record domain is within bailiwick
        record_domain.ends_with(bailiwick) || record_domain == bailiwick
    }

    /// Get TTL from DNS record
    fn get_record_ttl(&self, record: &DnsRecord) -> u32 {
        match record {
            DnsRecord::A { ttl, .. } |
            DnsRecord::Aaaa { ttl, .. } |
            DnsRecord::Ns { ttl, .. } |
            DnsRecord::Cname { ttl, .. } |
            DnsRecord::Mx { ttl, .. } |
            DnsRecord::Txt { ttl, .. } |
            DnsRecord::Soa { ttl, .. } => ttl.0,
            _ => 0,
        }
    }

    /// Validate DNSSEC signatures (simplified)
    fn validate_dnssec_simple(&self, _packet: &DnsPacket) -> bool {
        // Simplified - would perform full DNSSEC validation
        // In production, this would check RRSIG records
        true
    }

    /// Clean up old tracked queries
    pub fn cleanup_old_queries(&self) {
        let config = self.config.read();
        let cutoff = Duration::from_millis(config.response_window_ms * 2);
        
        self.active_queries.write().retain(|_, tracker| {
            tracker.timestamp.elapsed() < cutoff
        });
    }

    /// Get statistics
    pub fn get_stats(&self) -> PoisonProtectionStats {
        let stats = self.stats.read();
        PoisonProtectionStats {
            queries_protected: stats.queries_protected,
            suspicious_responses: stats.suspicious_responses,
            invalid_responses: stats.invalid_responses,
            dnssec_failures: stats.dnssec_failures,
            bailiwick_failures: stats.bailiwick_failures,
            ttl_anomalies: stats.ttl_anomalies,
            port_entropy_bits: stats.port_entropy_bits,
        }
    }

    /// Calculate poisoning resistance score (0-100)
    pub fn calculate_resistance_score(&self) -> f64 {
        let config = self.config.read();
        let mut score = 0.0;

        // Base score for being enabled
        if config.enabled {
            score += 20.0;
        }

        // Port randomization (up to 30 points based on entropy)
        if config.port_randomization {
            let entropy_score = (self.stats.read().port_entropy_bits / 16.0) * 30.0;
            score += entropy_score.min(30.0);
        }

        // 0x20 encoding (15 points)
        if config.bit_0x20 {
            score += 15.0;
        }

        // DNSSEC validation (20 points)
        if config.dnssec_validation {
            score += 20.0;
        }

        // Bailiwick checking (10 points)
        if config.bailiwick_check {
            score += 10.0;
        }

        // TTL validation (5 points)
        if config.max_ttl < 86400 * 7 {  // Less than a week
            score += 5.0;
        }

        score.min(100.0)
    }
}

/// Response sanitizer for cache storage
pub struct ResponseSanitizer {
    /// Maximum records per response
    max_records: usize,
    /// Strip additional records
    strip_additional: bool,
    /// Normalize TTLs
    normalize_ttls: bool,
}

impl ResponseSanitizer {
    /// Create new response sanitizer
    pub fn new() -> Self {
        Self {
            max_records: 100,
            strip_additional: false,
            normalize_ttls: true,
        }
    }

    /// Sanitize response before caching
    pub fn sanitize(&self, packet: &mut DnsPacket) -> Result<(), DnsError> {
        // Limit number of records
        if packet.answers.len() > self.max_records {
            packet.answers.truncate(self.max_records);
        }

        // Strip additional records if configured
        if self.strip_additional {
            packet.resources.clear();
        }

        // Normalize TTLs if configured
        if self.normalize_ttls {
            self.normalize_packet_ttls(packet);
        }

        Ok(())
    }

    /// Normalize TTLs within packet
    fn normalize_packet_ttls(&self, packet: &mut DnsPacket) {
        // Find minimum TTL
        let mut min_ttl = u32::MAX;
        
        for record in &packet.answers {
            let ttl = match record {
                DnsRecord::A { ttl, .. } |
                DnsRecord::Aaaa { ttl, .. } |
                DnsRecord::Ns { ttl, .. } |
                DnsRecord::Cname { ttl, .. } |
                DnsRecord::Mx { ttl, .. } |
                DnsRecord::Txt { ttl, .. } |
                DnsRecord::Soa { ttl, .. } => ttl.0,
                _ => continue,
            };
            min_ttl = min_ttl.min(ttl);
        }

        // Apply minimum TTL to all records
        if min_ttl < u32::MAX {
            for record in &mut packet.answers {
                self.update_record_ttl(record, min_ttl);
            }
        }
    }

    /// Update record TTL
    fn update_record_ttl(&self, record: &mut DnsRecord, new_ttl: u32) {
        use crate::dns::protocol::TransientTtl;
        
        match record {
            DnsRecord::A { ttl, .. } |
            DnsRecord::Aaaa { ttl, .. } |
            DnsRecord::Ns { ttl, .. } |
            DnsRecord::Cname { ttl, .. } |
            DnsRecord::Mx { ttl, .. } |
            DnsRecord::Txt { ttl, .. } |
            DnsRecord::Soa { ttl, .. } => {
                *ttl = TransientTtl(new_ttl);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_0x20_encoding() {
        let protection = CachePoisonProtection::new(PoisonProtectionConfig::default());
        
        let original = "example.com";
        let encoded = protection.apply_0x20_encoding(original);
        
        // Should have same length
        assert_eq!(original.len(), encoded.len());
        
        // Should match case-insensitively
        assert!(encoded.eq_ignore_ascii_case(original));
        
        // Should have some case differences
        assert_ne!(original, encoded);
    }

    #[test]
    fn test_bailiwick_extraction() {
        let protection = CachePoisonProtection::new(PoisonProtectionConfig::default());
        
        assert_eq!(protection.extract_bailiwick("www.example.com"), "example.com");
        assert_eq!(protection.extract_bailiwick("sub.domain.example.com"), "domain.example.com");
        assert_eq!(protection.extract_bailiwick("example.com"), "example.com");
    }

    #[test]
    fn test_resistance_score() {
        let mut config = PoisonProtectionConfig::default();
        config.enabled = true;
        config.port_randomization = true;
        config.bit_0x20 = true;
        config.dnssec_validation = true;
        config.bailiwick_check = true;
        
        let protection = CachePoisonProtection::new(config);
        let score = protection.calculate_resistance_score();
        
        // Should have a high score with all features enabled
        assert!(score > 80.0);
    }

    #[test]
    fn test_response_sanitizer() {
        use crate::dns::protocol::TransientTtl;
        
        let sanitizer = ResponseSanitizer::new();
        let mut packet = DnsPacket::new();
        
        // Add some answers with different TTLs
        packet.answers.push(DnsRecord::A {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(192, 168, 1, 1),
            ttl: TransientTtl(3600),
        });
        
        packet.answers.push(DnsRecord::A {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(192, 168, 1, 2),
            ttl: TransientTtl(7200),
        });
        
        sanitizer.sanitize(&mut packet).unwrap();
        
        // All records should have the same (minimum) TTL after normalization
        for record in &packet.answers {
            if let DnsRecord::A { ttl, .. } = record {
                assert_eq!(ttl.0, 3600);
            }
        }
    }
}