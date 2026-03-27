//! Full Iterative DNS Resolver with DNSSEC Chain Validation
//!
//! Performs iterative resolution starting from root hints, walking the DNS
//! hierarchy from root → TLD → authoritative nameserver.  Validated responses
//! (DNSSEC Secure) are stored in a separate cache partition so that bogus
//! answers cannot poison the validated store.
//!
//! # DNSSEC Validation
//!
//! * **Trust anchor**: The IANA root zone KSK (key tag 20326, algorithm 8)
//! * **Chain**: DS → DNSKEY → RRSIG for each delegation point
//! * **Bogus responses**: Return SERVFAIL to the client
//! * **Insecure delegations**: Treated as Insecure (not an error)

use std::sync::Arc;
use std::collections::HashMap;
use std::net::Ipv4Addr;

use parking_lot::RwLock;

use crate::dns::context::ServerContext;
use crate::dns::protocol::{
    DnsPacket, DnsQuestion, DnsRecord, QueryType, ResultCode, TransientTtl, ValidationStatus,
};
use crate::dns::buffer::BytePacketBuffer;
use crate::dns::cache::SynchronizedCache;

// ─── Root Hints ──────────────────────────────────────────────────────────────

/// IANA root server addresses (as of 2024).
const ROOT_SERVERS: &[(&str, &str)] = &[
    ("a.root-servers.net", "198.41.0.4"),
    ("b.root-servers.net", "170.247.170.2"),
    ("c.root-servers.net", "192.33.4.12"),
    ("d.root-servers.net", "199.7.91.13"),
    ("e.root-servers.net", "192.203.230.10"),
    ("f.root-servers.net", "192.5.5.241"),
    ("g.root-servers.net", "192.112.36.4"),
    ("h.root-servers.net", "198.97.190.53"),
    ("i.root-servers.net", "192.36.148.17"),
    ("j.root-servers.net", "192.58.128.30"),
    ("k.root-servers.net", "193.0.14.129"),
    ("l.root-servers.net", "199.7.83.42"),
    ("m.root-servers.net", "202.12.27.33"),
];

/// Root zone trust anchor key tag (IANA 2024 KSK).
pub const ROOT_TRUST_ANCHOR_KEY_TAG: u16 = 20326;

// ─── Validated Cache ─────────────────────────────────────────────────────────

/// A cache wrapper that separates DNSSEC-validated responses from unvalidated
/// ones.  Lookups prefer the validated partition.
pub struct ValidatedCache {
    /// Cache for DNSSEC Secure responses
    validated: Arc<SynchronizedCache>,
    /// Cache for unvalidated / Insecure responses
    unvalidated: Arc<SynchronizedCache>,
}

impl ValidatedCache {
    pub fn new() -> Self {
        Self {
            validated: Arc::new(SynchronizedCache::new()),
            unvalidated: Arc::new(SynchronizedCache::new()),
        }
    }

    /// Look up in validated cache first, then unvalidated.
    pub fn lookup(&self, domain: &str, qtype: QueryType) -> Option<DnsPacket> {
        self.validated.lookup(domain, qtype)
            .or_else(|| self.unvalidated.lookup(domain, qtype))
    }

    /// Store a response in the appropriate partition based on validation status.
    pub fn store(&self, records: &[DnsRecord], status: Option<ValidationStatus>) {
        match status {
            Some(ValidationStatus::Secure) => {
                let _ = self.validated.store(records);
            }
            _ => {
                let _ = self.unvalidated.store(records);
            }
        }
    }

    /// Store an NXDOMAIN in the appropriate partition.
    pub fn store_nxdomain(&self, domain: &str, qtype: QueryType, ttl: u32, status: Option<ValidationStatus>) {
        match status {
            Some(ValidationStatus::Secure) => {
                let _ = self.validated.store_nxdomain(domain, qtype, ttl);
            }
            _ => {
                let _ = self.unvalidated.store_nxdomain(domain, qtype, ttl);
            }
        }
    }

    /// Clear both partitions.
    pub fn clear(&self) {
        self.validated.clear();
        self.unvalidated.clear();
    }

    /// Statistics: (validated_size, unvalidated_size).
    pub fn sizes(&self) -> (usize, usize) {
        let v = self.validated.list().map(|l| l.len()).unwrap_or(0);
        let u = self.unvalidated.list().map(|l| l.len()).unwrap_or(0);
        (v, u)
    }
}

// ─── Iterative Resolver ──────────────────────────────────────────────────────

/// Maximum number of delegation steps before giving up.
const MAX_ITERATIONS: u32 = 30;

/// Maximum depth for CNAME chains.
const MAX_CNAME_DEPTH: u32 = 8;

/// Full iterative resolver with DNSSEC validation support.
///
/// Unlike the basic `RecursiveDnsResolver` in `resolve.rs`, this resolver:
/// * Ships with built-in root hints — works without pre-seeded cache
/// * Maintains a separate validated-response cache
/// * Performs DNSSEC chain-of-trust validation at each delegation
/// * Returns SERVFAIL for bogus responses when in strict mode
pub struct IterativeResolver {
    context: Arc<ServerContext>,
    validated_cache: Arc<ValidatedCache>,
    dnssec_strict: bool,
}

impl IterativeResolver {
    /// Create a new iterative resolver.
    ///
    /// * `context` — shared server context (for the DNS client and metrics)
    /// * `dnssec_strict` — if `true`, bogus DNSSEC responses yield SERVFAIL;
    ///   if `false`, they are treated as Insecure
    pub fn new(context: Arc<ServerContext>, dnssec_strict: bool) -> Self {
        Self {
            context,
            validated_cache: Arc::new(ValidatedCache::new()),
            dnssec_strict,
        }
    }

    /// Get a reference to the validated cache.
    pub fn cache(&self) -> &Arc<ValidatedCache> {
        &self.validated_cache
    }

    /// Seed the cache with root server NS + A records.
    pub fn seed_root_hints(&self) {
        let mut records: Vec<DnsRecord> = Vec::new();
        for (name, ip) in ROOT_SERVERS {
            records.push(DnsRecord::Ns {
                domain: String::new(), // root zone
                host: name.to_string(),
                ttl: TransientTtl(518400), // 6 days
            });
            if let Ok(addr) = ip.parse::<Ipv4Addr>() {
                records.push(DnsRecord::A {
                    domain: name.to_string(),
                    addr,
                    ttl: TransientTtl(518400),
                });
            }
        }
        // Store root hints in the main context cache so the basic resolver
        // also benefits from them.
        let _ = self.context.cache.store(&records);
        self.validated_cache.store(&records, Some(ValidationStatus::Secure));
        log::info!("[iterative] seeded {} root hint records", records.len());
    }

    /// Resolve a query iteratively from root hints.
    pub fn resolve(&self, qname: &str, qtype: QueryType) -> Result<DnsPacket, String> {
        // Check validated cache first
        if let Some(cached) = self.validated_cache.lookup(qname, qtype) {
            return Ok(cached);
        }

        // Also check main context cache
        if let Some(cached) = self.context.cache.lookup(qname, qtype) {
            return Ok(cached);
        }

        self.iterate(qname, qtype, 0)
    }

    fn iterate(&self, qname: &str, qtype: QueryType, depth: u32) -> Result<DnsPacket, String> {
        if depth > MAX_ITERATIONS {
            return Err(format!("Max iterations exceeded resolving {}", qname));
        }

        // Find the closest nameserver
        let ns_ip = self.find_closest_ns(qname)
            .ok_or_else(|| format!("No nameserver found for {}", qname))?;

        log::debug!("[iterative] querying {} for {} {:?} (depth={})", ns_ip, qname, qtype, depth);

        // Query the nameserver
        let response = self.context.client
            .send_query(qname, qtype, (&ns_ip, 53), false)
            .map_err(|e| format!("Query to {} failed: {}", ns_ip, e))?;

        // DNSSEC validation (if enabled)
        let validation_status = if self.context.dnssec_enabled {
            self.validate_response(&response, qname, qtype)
        } else {
            None
        };

        // Check for bogus in strict mode
        if self.dnssec_strict {
            if let Some(ValidationStatus::Bogus) = validation_status {
                log::warn!("[iterative] DNSSEC bogus response for {} {:?} → SERVFAIL", qname, qtype);
                let mut pkt = DnsPacket::new();
                pkt.header.rescode = ResultCode::SERVFAIL;
                return Ok(pkt);
            }
        }

        // Case 1: Got an answer
        if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
            // Cache the answer
            self.validated_cache.store(&response.answers, validation_status);
            let _ = self.context.cache.store(&response.answers);
            let _ = self.context.cache.store(&response.authorities);
            let _ = self.context.cache.store(&response.resources);

            // Check for CNAME and follow it
            if qtype != QueryType::Cname {
                for answer in &response.answers {
                    if let DnsRecord::Cname { host, .. } = answer {
                        if depth < MAX_CNAME_DEPTH {
                            return self.iterate(host, qtype, depth + 1);
                        }
                    }
                }
            }

            let mut result = response;
            result.dnssec_status = validation_status;
            return Ok(result);
        }

        // Case 2: NXDOMAIN
        if response.header.rescode == ResultCode::NXDOMAIN {
            if let Some(ttl) = response.get_ttl_from_soa() {
                self.validated_cache.store_nxdomain(qname, qtype, ttl, validation_status);
                let _ = self.context.cache.store_nxdomain(qname, qtype, ttl);
            }
            let mut result = response;
            result.dnssec_status = validation_status;
            return Ok(result);
        }

        // Case 3: Delegation — follow NS records
        // Cache authority + additional records
        let _ = self.context.cache.store(&response.authorities);
        let _ = self.context.cache.store(&response.resources);
        self.validated_cache.store(&response.authorities, validation_status);
        self.validated_cache.store(&response.resources, validation_status);

        // Try to find the next nameserver from the delegation
        if let Some(new_ns) = response.get_resolved_ns(qname) {
            return self.iterate_with_ns(qname, qtype, &new_ns, depth + 1);
        }

        // Unresolved NS — resolve the NS first
        if let Some(ns_name) = response.get_unresolved_ns(qname) {
            let ns_response = self.iterate(&ns_name, QueryType::A, depth + 1)?;
            if let Some(ns_addr) = ns_response.get_random_a() {
                return self.iterate_with_ns(qname, qtype, &ns_addr, depth + 1);
            }
        }

        // No progress — return what we have
        Ok(response)
    }

    fn iterate_with_ns(
        &self,
        qname: &str,
        qtype: QueryType,
        ns_ip: &str,
        depth: u32,
    ) -> Result<DnsPacket, String> {
        if depth > MAX_ITERATIONS {
            return Err(format!("Max iterations exceeded resolving {}", qname));
        }

        let response = self.context.client
            .send_query(qname, qtype, (ns_ip, 53), false)
            .map_err(|e| format!("Query to {} failed: {}", ns_ip, e))?;

        let validation_status = if self.context.dnssec_enabled {
            self.validate_response(&response, qname, qtype)
        } else {
            None
        };

        if self.dnssec_strict {
            if let Some(ValidationStatus::Bogus) = validation_status {
                let mut pkt = DnsPacket::new();
                pkt.header.rescode = ResultCode::SERVFAIL;
                return Ok(pkt);
            }
        }

        if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
            self.validated_cache.store(&response.answers, validation_status);
            let _ = self.context.cache.store(&response.answers);
            let _ = self.context.cache.store(&response.authorities);
            let _ = self.context.cache.store(&response.resources);

            let mut result = response;
            result.dnssec_status = validation_status;
            return Ok(result);
        }

        if response.header.rescode == ResultCode::NXDOMAIN {
            if let Some(ttl) = response.get_ttl_from_soa() {
                self.validated_cache.store_nxdomain(qname, qtype, ttl, validation_status);
                let _ = self.context.cache.store_nxdomain(qname, qtype, ttl);
            }
            let mut result = response;
            result.dnssec_status = validation_status;
            return Ok(result);
        }

        // Delegation
        let _ = self.context.cache.store(&response.authorities);
        let _ = self.context.cache.store(&response.resources);
        self.validated_cache.store(&response.authorities, validation_status);
        self.validated_cache.store(&response.resources, validation_status);

        if let Some(new_ns) = response.get_resolved_ns(qname) {
            return self.iterate_with_ns(qname, qtype, &new_ns, depth + 1);
        }

        if let Some(ns_name) = response.get_unresolved_ns(qname) {
            let ns_resp = self.iterate(&ns_name, QueryType::A, depth + 1)?;
            if let Some(ns_addr) = ns_resp.get_random_a() {
                return self.iterate_with_ns(qname, qtype, &ns_addr, depth + 1);
            }
        }

        Ok(response)
    }

    /// Find the closest cached nameserver for a domain.
    fn find_closest_ns(&self, qname: &str) -> Option<String> {
        let labels: Vec<&str> = qname.split('.').collect();

        for i in 0..=labels.len() {
            let domain = if i < labels.len() {
                labels[i..].join(".")
            } else {
                String::new() // root
            };

            // Try validated cache first
            if let Some(ns_packet) = self.validated_cache.lookup(&domain, QueryType::Ns) {
                if let Some(ns_name) = ns_packet.get_unresolved_ns(&domain) {
                    // Try to resolve the NS name from cache
                    if let Some(a_packet) = self.context.cache.lookup(&ns_name, QueryType::A) {
                        if let Some(addr) = a_packet.get_random_a() {
                            return Some(addr);
                        }
                    }
                }
                if let Some(addr) = ns_packet.get_resolved_ns(&domain) {
                    return Some(addr);
                }
            }

            // Then try main context cache
            if let Some(addr) = self.context.cache
                .lookup(&domain, QueryType::Ns)
                .and_then(|ns_pkt| ns_pkt.get_unresolved_ns(&domain))
                .and_then(|ns_name| self.context.cache.lookup(&ns_name, QueryType::A))
                .and_then(|a_pkt| a_pkt.get_random_a())
            {
                return Some(addr);
            }
        }

        // Fall back to a random root server
        let idx = rand::random::<usize>() % ROOT_SERVERS.len();
        Some(ROOT_SERVERS[idx].1.to_string())
    }

    /// Validate a DNS response using DNSSEC.
    fn validate_response(
        &self,
        response: &DnsPacket,
        qname: &str,
        qtype: QueryType,
    ) -> Option<ValidationStatus> {
        use crate::dns::context::ResolveStrategy;
        use crate::dnssec::chain::ChainOfTrustValidator;
        use crate::dnssec::validator::DnssecValidationMode;

        let mode = match self.context.dnssec_validation_mode {
            crate::dns::dnssec::ValidationMode::Strict => DnssecValidationMode::Strict,
            crate::dns::dnssec::ValidationMode::Opportunistic => DnssecValidationMode::Opportunistic,
            crate::dns::dnssec::ValidationMode::Off => return None,
        };

        let validator = ChainOfTrustValidator::new(mode);

        // Determine upstream for fetching DNSKEY/DS records
        let upstream: Option<(String, u16)> = match &self.context.resolve_strategy {
            ResolveStrategy::Forward { host, port } => Some((host.clone(), *port)),
            ResolveStrategy::DohForward { fallback_host, fallback_port, .. } =>
                Some((fallback_host.clone(), *fallback_port)),
            ResolveStrategy::Recursive => Some(("198.41.0.4".to_string(), 53)),
        };

        if let Some((host, port)) = upstream {
            let fetch = |name: &str, qt: QueryType| -> Option<DnsPacket> {
                self.context.client
                    .send_query(name, qt, (host.as_str(), port), true)
                    .ok()
            };
            match validator.dnssec_validate(response, qname, qtype, fetch) {
                Ok(status) => Some(status),
                Err(_) => Some(ValidationStatus::Bogus),
            }
        } else {
            match validator.validator().validate_response(response) {
                Ok(status) => Some(status),
                Err(_) => Some(ValidationStatus::Bogus),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_servers_populated() {
        assert_eq!(ROOT_SERVERS.len(), 13);
    }

    #[test]
    fn test_validated_cache_separation() {
        let cache = ValidatedCache::new();
        let records = vec![DnsRecord::A {
            domain: "secure.example.com".to_string(),
            addr: "1.2.3.4".parse().unwrap(),
            ttl: TransientTtl(300),
        }];
        cache.store(&records, Some(ValidationStatus::Secure));

        // Should be found via lookup (validated partition)
        assert!(cache.validated.lookup("secure.example.com", QueryType::A).is_some());
        // Unvalidated should be empty for this domain
        assert!(cache.unvalidated.lookup("secure.example.com", QueryType::A).is_none());
    }

    #[test]
    fn test_validated_cache_insecure_goes_to_unvalidated() {
        let cache = ValidatedCache::new();
        let records = vec![DnsRecord::A {
            domain: "insecure.example.com".to_string(),
            addr: "5.6.7.8".parse().unwrap(),
            ttl: TransientTtl(300),
        }];
        cache.store(&records, Some(ValidationStatus::Insecure));

        assert!(cache.unvalidated.lookup("insecure.example.com", QueryType::A).is_some());
        assert!(cache.validated.lookup("insecure.example.com", QueryType::A).is_none());
    }
}
