//! Query Name Minimization Implementation - RFC 7816
//!
//! Enhances privacy by minimizing the amount of query name information 
//! sent to authoritative name servers that don't need it.
//!
//! # Features
//!
//! * **Incremental Resolution** - Query one label at a time
//! * **NS Caching** - Reuse known nameserver information
//! * **Privacy Protection** - Minimize information leakage
//! * **Fallback Support** - Handle non-supporting servers
//! * **Performance Optimization** - Smart caching strategies

use std::collections::HashMap;
use std::sync::Arc;
use std::net::IpAddr;
use parking_lot::RwLock;

use crate::dns::protocol::{DnsPacket, QueryType, ResultCode, DnsRecord};
use crate::dns::client::DnsClient;
use crate::dns::context::ServerContext;
use crate::dns::errors::DnsError;

/// Query minimization configuration
#[derive(Debug, Clone)]
pub struct QnameMinConfig {
    /// Enable query name minimization
    pub enabled: bool,
    /// Maximum iterations for minimization
    pub max_iterations: usize,
    /// Use aggressive minimization (always start from root)
    pub aggressive: bool,
    /// Cache NS records for optimization
    pub cache_ns: bool,
    /// Fallback to full query on errors
    pub fallback_enabled: bool,
    /// Maximum label depth to minimize
    pub max_minimization_depth: usize,
}

impl Default for QnameMinConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_iterations: 10,
            aggressive: false,
            cache_ns: true,
            fallback_enabled: true,
            max_minimization_depth: 7,
        }
    }
}

/// Query minimization state
#[derive(Debug, Clone)]
struct MinimizationState {
    /// Original query name
    original_qname: String,
    /// Current minimized query
    current_qname: String,
    /// Labels in the original query
    labels: Vec<String>,
    /// Current label index
    label_index: usize,
    /// Known nameservers
    known_ns: HashMap<String, Vec<IpAddr>>,
    /// Iteration count
    iterations: usize,
}

impl MinimizationState {
    /// Create new minimization state
    fn new(qname: &str) -> Self {
        let labels: Vec<String> = qname
            .split('.')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        
        Self {
            original_qname: qname.to_string(),
            current_qname: String::new(),
            labels,
            label_index: 0,
            known_ns: HashMap::new(),
            iterations: 0,
        }
    }

    /// Get next minimized query name
    fn next_qname(&mut self) -> Option<String> {
        if self.label_index >= self.labels.len() {
            return None;
        }
        
        // Build query name from current position to end
        let qname = self.labels[self.label_index..].join(".");
        self.current_qname = qname.clone();
        self.label_index += 1;
        self.iterations += 1;
        
        Some(qname)
    }

    /// Check if minimization is complete
    fn is_complete(&self) -> bool {
        self.current_qname == self.original_qname || 
        self.label_index >= self.labels.len()
    }

    /// Get the zone cut for current query
    fn get_zone_cut(&self) -> String {
        if self.label_index > 0 {
            self.labels[self.label_index - 1..].join(".")
        } else {
            String::new()
        }
    }
}

/// Query name minimization resolver
pub struct QnameMinimizer {
    /// Configuration
    config: QnameMinConfig,
    /// NS cache for optimization
    ns_cache: Arc<RwLock<HashMap<String, NSCacheEntry>>>,
    /// Statistics
    stats: Arc<RwLock<MinimizationStats>>,
}

/// NS cache entry
#[derive(Debug, Clone)]
struct NSCacheEntry {
    /// Nameserver addresses
    servers: Vec<IpAddr>,
    /// Zone name
    zone: String,
    /// TTL
    ttl: u32,
    /// Cache time
    cached_at: std::time::Instant,
}

/// Minimization statistics
#[derive(Debug, Default)]
pub struct MinimizationStats {
    /// Total queries minimized
    pub queries_minimized: u64,
    /// Queries with fallback
    pub fallback_used: u64,
    /// Average iterations
    pub avg_iterations: f64,
    /// Cache hits
    pub cache_hits: u64,
    /// Privacy improvement score (0-100)
    pub privacy_score: f64,
}

impl QnameMinimizer {
    /// Create new query minimizer
    pub fn new(config: QnameMinConfig) -> Self {
        Self {
            config,
            ns_cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(MinimizationStats::default())),
        }
    }

    /// Resolve query with name minimization
    pub fn resolve_minimized(
        &self,
        qname: &str,
        qtype: QueryType,
        context: &Arc<ServerContext>,
    ) -> Result<DnsPacket, DnsError> {
        if !self.config.enabled {
            // Minimization disabled, use normal resolution
            return self.resolve_full(qname, qtype, context);
        }

        // Don't minimize for certain query types
        if !self.should_minimize(qtype) {
            return self.resolve_full(qname, qtype, context);
        }

        let mut state = MinimizationState::new(qname);
        
        // Check if we have cached NS for this domain
        if self.config.cache_ns {
            if let Some(ns) = self.find_closest_ns(qname) {
                state.known_ns.insert(ns.zone.clone(), ns.servers.clone());
                // Skip to the appropriate label
                state.label_index = self.calculate_skip_labels(qname, &ns.zone);
            }
        }

        // Perform minimized resolution
        match self.resolve_incremental(&mut state, qtype, context) {
            Ok(packet) => {
                self.update_stats(&state, true);
                Ok(packet)
            }
            Err(e) if self.config.fallback_enabled => {
                log::debug!("Query minimization failed, falling back to full query: {:?}", e);
                self.stats.write().fallback_used += 1;
                self.resolve_full(qname, qtype, context)
            }
            Err(e) => {
                self.update_stats(&state, false);
                Err(e)
            }
        }
    }

    /// Perform incremental minimized resolution
    fn resolve_incremental(
        &self,
        state: &mut MinimizationState,
        qtype: QueryType,
        context: &Arc<ServerContext>,
    ) -> Result<DnsPacket, DnsError> {
        while state.iterations < self.config.max_iterations {
            // Get next minimized query
            let qname = match state.next_qname() {
                Some(q) => q,
                None => break,
            };

            // Determine query type for this iteration
            let iteration_qtype = if state.is_complete() {
                qtype  // Use actual query type for final query
            } else {
                QueryType::Ns  // Use NS query for intermediate steps
            };

            log::debug!("Minimized query: {} ({:?})", qname, iteration_qtype);

            // Find nameserver for this query
            let (ns_host, ns_port) = self.find_nameserver_for_zone(&state.get_zone_cut(), context)?;
            let ns_addr = (ns_host.as_str(), ns_port);

            // Send query
            let response = context.client.send_query(
                &qname,
                iteration_qtype,
                ns_addr,
                false,
            ).map_err(|e| DnsError::Operation(crate::dns::errors::OperationError {
                context: "Query minimization".to_string(),
                details: format!("Failed to send query: {:?}", e),
                recovery_hint: Some("Check network connectivity".to_string()),
            }))?;

            // Process response
            match response.header.rescode {
                ResultCode::NOERROR => {
                    // Cache NS records if present
                    if self.config.cache_ns {
                        self.cache_ns_records(&qname, &response);
                    }

                    // If this was the final query, return the response
                    if state.is_complete() {
                        return Ok(response);
                    }

                    // Check if we got a referral or answer
                    if !response.answers.is_empty() {
                        // Got an answer for intermediate query
                        if iteration_qtype == QueryType::Ns {
                            // Extract NS information
                            for record in &response.answers {
                                if let DnsRecord::Ns { host, .. } = record {
                                    // Store NS information
                                    if let Some(addr) = self.resolve_ns_address(host, context) {
                                        state.known_ns.entry(qname.clone())
                                            .or_insert_with(Vec::new)
                                            .push(addr);
                                    }
                                }
                            }
                        }
                    }
                }
                ResultCode::NXDOMAIN => {
                    // Domain doesn't exist at this level
                    if state.is_complete() {
                        return Ok(response);
                    }
                    // Continue with next label
                }
                ResultCode::REFUSED | ResultCode::SERVFAIL => {
                    // Server doesn't support minimization or has issues
                    if self.config.fallback_enabled {
                        log::debug!("Server returned {:?}, falling back", response.header.rescode);
                        return self.resolve_full(&state.original_qname, qtype, context);
                    }
                    return Err(DnsError::Protocol(crate::dns::errors::ProtocolError {
                        kind: crate::dns::errors::ProtocolErrorKind::ResponseMismatch,
                        packet_id: Some(response.header.id),
                        query_name: Some(qname),
                        recoverable: true,
                    }));
                }
                _ => {
                    // Other error, continue or fail
                    if state.is_complete() {
                        return Ok(response);
                    }
                }
            }
        }

        // Max iterations reached
        if self.config.fallback_enabled {
            self.resolve_full(&state.original_qname, qtype, context)
        } else {
            Err(DnsError::Operation(crate::dns::errors::OperationError {
                context: "Query minimization".to_string(),
                details: "Maximum iterations reached".to_string(),
                recovery_hint: Some("Enable fallback or increase max_iterations".to_string()),
            }))
        }
    }

    /// Resolve full query without minimization
    fn resolve_full(
        &self,
        qname: &str,
        qtype: QueryType,
        context: &Arc<ServerContext>,
    ) -> Result<DnsPacket, DnsError> {
        // Use standard resolution
        let (ns_host, ns_port) = self.find_nameserver_for_zone(".", context)?;
        let ns_addr = (ns_host.as_str(), ns_port);
        context.client.send_query(qname, qtype, ns_addr, true)
            .map_err(|e| DnsError::Operation(crate::dns::errors::OperationError {
                context: "Query resolution".to_string(),
                details: format!("Failed to resolve query: {:?}", e),
                recovery_hint: Some("Check DNS configuration".to_string()),
            }))
    }

    /// Check if query type should be minimized
    fn should_minimize(&self, qtype: QueryType) -> bool {
        match qtype {
            // Don't minimize these types
            QueryType::Ns | 
            QueryType::Soa | 
            QueryType::Opt => false,
            // Minimize all others
            _ => true,
        }
    }

    /// Find closest cached NS for domain
    fn find_closest_ns(&self, qname: &str) -> Option<NSCacheEntry> {
        let cache = self.ns_cache.read();
        let labels: Vec<&str> = qname.split('.').collect();
        
        // Check from most specific to least specific
        for i in 0..labels.len() {
            let zone = labels[i..].join(".");
            if let Some(entry) = cache.get(&zone) {
                // Check if entry is still valid
                if entry.cached_at.elapsed().as_secs() < entry.ttl as u64 {
                    return Some(entry.clone());
                }
            }
        }
        
        None
    }

    /// Calculate how many labels to skip based on known NS
    fn calculate_skip_labels(&self, qname: &str, ns_zone: &str) -> usize {
        let qname_labels: Vec<&str> = qname.split('.').collect();
        let ns_labels: Vec<&str> = ns_zone.split('.').collect();
        
        if qname_labels.len() >= ns_labels.len() {
            qname_labels.len() - ns_labels.len()
        } else {
            0
        }
    }

    /// Find nameserver for zone
    fn find_nameserver_for_zone(
        &self,
        zone: &str,
        context: &Arc<ServerContext>,
    ) -> Result<(String, u16), DnsError> {
        // Check cache first
        if let Some(ns) = self.ns_cache.read().get(zone) {
            if !ns.servers.is_empty() {
                return Ok((ns.servers[0].to_string(), 53));
            }
        }

        // Use configured upstream or root servers
        if let crate::dns::context::ResolveStrategy::Forward { ref host, port } = context.resolve_strategy {
            Ok((host.clone(), port))
        } else {
            // Use root server
            Ok(("198.41.0.4".to_string(), 53))  // a.root-servers.net
        }
    }

    /// Resolve NS hostname to IP address
    fn resolve_ns_address(&self, host: &str, context: &Arc<ServerContext>) -> Option<IpAddr> {
        // Try cache first
        if let Some(packet) = context.cache.lookup(host, QueryType::A) {
            for record in &packet.answers {
                if let DnsRecord::A { addr, .. } = record {
                    return Some(IpAddr::V4(*addr));
                }
            }
        }

        // Would need to resolve the NS address
        // For now, return None to continue
        None
    }

    /// Cache NS records from response
    fn cache_ns_records(&self, zone: &str, packet: &DnsPacket) {
        let mut servers = Vec::new();
        let mut ttl = 3600u32;

        // Extract NS records
        for record in &packet.authorities {
            if let DnsRecord::Ns { ttl: ns_ttl, .. } = record {
                ttl = ttl.min(ns_ttl.0);
            }
        }

        // Extract glue records (A/AAAA in additional section)
        for record in &packet.resources {
            match record {
                DnsRecord::A { addr, .. } => {
                    servers.push(IpAddr::V4(*addr));
                }
                DnsRecord::Aaaa { addr, .. } => {
                    servers.push(IpAddr::V6(*addr));
                }
                _ => {}
            }
        }

        if !servers.is_empty() {
            let entry = NSCacheEntry {
                servers,
                zone: zone.to_string(),
                ttl,
                cached_at: std::time::Instant::now(),
            };

            self.ns_cache.write().insert(zone.to_string(), entry);
            self.stats.write().cache_hits += 1;
        }
    }

    /// Update statistics
    fn update_stats(&self, state: &MinimizationState, success: bool) {
        let mut stats = self.stats.write();
        
        if success {
            stats.queries_minimized += 1;
            
            // Update average iterations
            let n = stats.queries_minimized as f64;
            stats.avg_iterations = 
                (stats.avg_iterations * (n - 1.0) + state.iterations as f64) / n;
            
            // Calculate privacy score (0-100)
            // Score based on how much of the query was hidden
            let total_labels = state.labels.len();
            let hidden_labels = total_labels.saturating_sub(state.iterations);
            stats.privacy_score = if total_labels > 0 {
                (hidden_labels as f64 / total_labels as f64) * 100.0
            } else {
                0.0
            };
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> MinimizationStats {
        let stats = self.stats.read();
        MinimizationStats {
            queries_minimized: stats.queries_minimized,
            fallback_used: stats.fallback_used,
            avg_iterations: stats.avg_iterations,
            cache_hits: stats.cache_hits,
            privacy_score: stats.privacy_score,
        }
    }
}

/// Extension trait for DnsPacket to support minimization
pub trait QnameMinimizationExt {
    /// Check if packet is a referral
    fn is_referral(&self) -> bool;
    
    /// Extract zone cut from packet
    fn get_zone_cut(&self) -> Option<String>;
}

impl QnameMinimizationExt for DnsPacket {
    fn is_referral(&self) -> bool {
        // Referral has NS records in authority but no answers
        self.answers.is_empty() && 
        self.authorities.iter().any(|r| matches!(r, DnsRecord::Ns { .. }))
    }

    fn get_zone_cut(&self) -> Option<String> {
        // Find the zone from NS records
        for record in &self.authorities {
            if let DnsRecord::Ns { domain, .. } = record {
                return Some(domain.clone());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimization_state() {
        let mut state = MinimizationState::new("www.example.com");
        
        assert_eq!(state.labels.len(), 3);
        assert_eq!(state.next_qname(), Some("www.example.com".to_string()));
        assert_eq!(state.next_qname(), Some("example.com".to_string()));
        assert_eq!(state.next_qname(), Some("com".to_string()));
        assert_eq!(state.next_qname(), None);
    }

    #[test]
    fn test_should_minimize() {
        let config = QnameMinConfig::default();
        let minimizer = QnameMinimizer::new(config);
        
        assert!(minimizer.should_minimize(QueryType::A));
        assert!(minimizer.should_minimize(QueryType::Aaaa));
        assert!(!minimizer.should_minimize(QueryType::Ns));
        assert!(!minimizer.should_minimize(QueryType::Soa));
    }

    #[test]
    fn test_privacy_score_calculation() {
        let config = QnameMinConfig::default();
        let minimizer = QnameMinimizer::new(config);
        
        let mut state = MinimizationState::new("www.example.com");
        state.iterations = 2;  // Only revealed 2 labels instead of 3
        
        minimizer.update_stats(&state, true);
        let stats = minimizer.get_stats();
        
        assert!(stats.privacy_score > 0.0);
    }
}