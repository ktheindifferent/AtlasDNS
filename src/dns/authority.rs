//! Contains the data store for local zones
//! 
//! ## Wildcard DNS Record Support
//! 
//! The Authority supports wildcard DNS records using the `*` character:
//! - `*.example.com` - Matches any single-level subdomain (e.g., `foo.example.com`, `bar.example.com`)
//! - `*.sub.example.com` - Matches any subdomain under `sub.example.com`
//! - Wildcards only match one level of subdomain (not multiple levels)
//! - Exact matches always take precedence over wildcard matches
//! 
//! ## Root/Apex Record Support
//! 
//! The Authority supports the `@` symbol to reference the zone apex (root domain):
//! - `@` - Refers to the zone root (e.g., `example.com` for the `example.com` zone)
//! - `@.example.com` - Alternative notation for the zone apex
//! - Useful for setting records directly on the domain itself (A, MX, TXT records)
//! 
//! ## Query Resolution Precedence
//! 
//! When resolving DNS queries, the following precedence is used:
//! 1. Exact domain match (highest priority)
//! 2. Wildcard match (if no exact match found)
//! 3. NXDOMAIN response (if no matches found)
//! 
//! ## Examples
//! 
//! ```ignore
//! // Create zone with wildcard and root records
//! let mut zone = Zone::new("example.com", "ns1.example.com", "admin.example.com");
//! 
//! // Root domain A record
//! zone.add_record(&DnsRecord::A {
//!     domain: "@".to_string(),
//!     addr: "192.168.1.1".parse().unwrap(),
//!     ttl: TransientTtl(3600),
//! });
//! 
//! // Wildcard A record for all subdomains
//! zone.add_record(&DnsRecord::A {
//!     domain: "*.example.com".to_string(),
//!     addr: "192.168.1.100".parse().unwrap(),
//!     ttl: TransientTtl(3600),
//! });
//! 
//! // Specific subdomain (overrides wildcard)
//! zone.add_record(&DnsRecord::A {
//!     domain: "www.example.com".to_string(),
//!     addr: "192.168.1.10".parse().unwrap(),
//!     ttl: TransientTtl(3600),
//! });
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, LockResult, RwLock, RwLockReadGuard, RwLockWriteGuard};


use crate::dns::buffer::{PacketBuffer, StreamPacketBuffer, VectorPacketBuffer};
use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, ResultCode, TransientTtl};
use crate::dns::dnssec::{DnssecSigner, DnssecValidationStatus, SigningConfig, SignedZone, ValidationMode};
use crate::storage::PersistentStorage;

/// Errors that can be returned by [`Authority`] and [`Zones`] operations.
#[derive(Debug)]
pub enum AuthorityError {
    Buffer(crate::dns::buffer::BufferError),
    Protocol(crate::dns::protocol::ProtocolError),
    Io(std::io::Error),
    PoisonedLock,
    NoSuchZone(String),
    ZoneExists(String),
    NoSuchRecord,
}

impl std::fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorityError::Buffer(e) => write!(f, "Buffer error: {:?}", e),
            AuthorityError::Protocol(e) => write!(f, "Protocol error: {:?}", e),
            AuthorityError::Io(e) => write!(f, "IO error: {}", e),
            AuthorityError::PoisonedLock => write!(f, "Lock was poisoned"),
            AuthorityError::NoSuchZone(zone) => write!(f, "Zone not found: {}", zone),
            AuthorityError::ZoneExists(zone) => write!(f, "Zone already exists: {}", zone),
            AuthorityError::NoSuchRecord => write!(f, "Record not found"),
        }
    }
}

impl std::error::Error for AuthorityError {}

impl From<std::io::Error> for AuthorityError {
    fn from(err: std::io::Error) -> Self {
        AuthorityError::Io(err)
    }
}

impl From<crate::dns::buffer::BufferError> for AuthorityError {
    fn from(err: crate::dns::buffer::BufferError) -> Self {
        AuthorityError::Buffer(err)
    }
}

impl From<crate::dns::protocol::ProtocolError> for AuthorityError {
    fn from(err: crate::dns::protocol::ProtocolError) -> Self {
        AuthorityError::Protocol(err)
    }
}

type Result<T> = std::result::Result<T, AuthorityError>;

/// A DNS zone containing SOA metadata and a set of resource records.
///
/// Records are stored in a `BTreeSet` for deterministic ordering and
/// automatic deduplication.
#[derive(Clone, Debug, Default)]
pub struct Zone {
    /// The authoritative domain name for this zone (e.g. `"example.com"`).
    pub domain: String,
    /// Primary nameserver hostname (SOA MNAME field).
    pub m_name: String,
    /// Responsible-person mailbox in DNS notation (SOA RNAME field).
    pub r_name: String,
    /// Zone serial number; incremented on every zone change.
    pub serial: u32,
    /// SOA REFRESH — how often secondaries should check for updates (seconds).
    pub refresh: u32,
    /// SOA RETRY — how long secondaries wait before retrying after a failed refresh.
    pub retry: u32,
    /// SOA EXPIRE — how long secondaries may serve the zone without a successful refresh.
    pub expire: u32,
    /// SOA MINIMUM — default negative-caching TTL.
    pub minimum: u32,
    /// All resource records belonging to this zone.
    pub records: BTreeSet<DnsRecord>,
    /// Whether DNSSEC signing is active for this zone.
    pub dnssec_enabled: bool,
    /// DNSSEC signing state (keys, RRSIG records, DS records).
    pub signed_zone: Option<SignedZone>,
}

impl Zone {
    /// Create a new, empty zone with the given SOA primary fields.
    pub fn new(domain: String, m_name: String, r_name: String) -> Zone {
        Zone {
            domain,
            m_name,
            r_name,
            serial: 0,
            refresh: 0,
            retry: 0,
            expire: 0,
            minimum: 0,
            records: BTreeSet::new(),
            dnssec_enabled: false,
            signed_zone: None,
        }
    }

    /// Insert a record into the zone. Returns `true` if the record was new.
    pub fn add_record(&mut self, rec: &DnsRecord) -> bool {
        self.records.insert(rec.clone())
    }

    /// Remove a record from the zone. Returns `true` if the record existed.
    pub fn delete_record(&mut self, rec: &DnsRecord) -> bool {
        self.records.remove(rec)
    }
}

/// In-memory collection of [`Zone`] objects, keyed by domain name.
#[derive(Default)]
pub struct Zones {
    zones: BTreeMap<String, Zone>,
}

impl<'a> Zones {
    /// Create an empty `Zones` collection.
    pub fn new() -> Zones {
        Zones {
            zones: BTreeMap::new(),
        }
    }

    /// Load all zone files from the given directory into memory.
    ///
    /// Each file is expected to be in the binary format written by [`save`].
    /// Files that cannot be opened or parsed are skipped with a warning.
    pub fn load(&mut self, zones_dir: &str) -> Result<()> {
        let zones_dir = Path::new(zones_dir).read_dir()?;

        for wrapped_filename in zones_dir {
            let filename = match wrapped_filename {
                Ok(x) => x,
                Err(_) => continue,
            };

            let mut zone_file = match File::open(filename.path()) {
                Ok(x) => x,
                Err(_) => continue,
            };

            let mut buffer = StreamPacketBuffer::new(&mut zone_file);

            let mut zone = Zone::new(String::new(), String::new(), String::new());
            buffer.read_qname(&mut zone.domain)?;
            buffer.read_qname(&mut zone.m_name)?;
            buffer.read_qname(&mut zone.r_name)?;
            zone.serial = buffer.read_u32()?;
            zone.refresh = buffer.read_u32()?;
            zone.retry = buffer.read_u32()?;
            zone.expire = buffer.read_u32()?;
            zone.minimum = buffer.read_u32()?;

            let record_count = buffer.read_u32()?;

            for _ in 0..record_count {
                let rr = DnsRecord::read(&mut buffer)?;
                zone.add_record(&rr);
            }

            println!("Loaded zone {} with {} records", zone.domain, record_count);

            self.zones.insert(zone.domain.clone(), zone);
        }

        Ok(())
    }

    /// Persist all zones to binary files in `zones_dir`, one file per zone.
    pub fn save(&mut self, zones_dir: &str) -> Result<()> {
        let zones_dir = Path::new(zones_dir);
        for zone in self.zones.values() {
            let filename = zones_dir.join(Path::new(&zone.domain));
            let mut zone_file = match File::create(&filename) {
                Ok(x) => x,
                Err(_) => {
                    println!("Failed to save file {:?}", filename);
                    continue;
                }
            };

            let mut buffer = VectorPacketBuffer::new();
            let _ = buffer.write_qname(&zone.domain);
            let _ = buffer.write_qname(&zone.m_name);
            let _ = buffer.write_qname(&zone.r_name);
            let _ = buffer.write_u32(zone.serial);
            let _ = buffer.write_u32(zone.refresh);
            let _ = buffer.write_u32(zone.retry);
            let _ = buffer.write_u32(zone.expire);
            let _ = buffer.write_u32(zone.minimum);
            let _ = buffer.write_u32(zone.records.len() as u32);

            for rec in &zone.records {
                let _ = rec.write(&mut buffer);
            }

            let _ = zone_file.write(&buffer.buffer[0..buffer.pos]);
        }

        Ok(())
    }

    /// Return a list of all zones in the collection.
    pub fn zones(&self) -> Vec<&Zone> {
        self.zones.values().collect()
    }

    /// Insert or replace a zone.
    pub fn add_zone(&mut self, zone: Zone) {
        self.zones.insert(zone.domain.clone(), zone);
    }

    /// Get an immutable reference to the zone for `domain`, if it exists.
    pub fn get_zone(&'a self, domain: &str) -> Option<&'a Zone> {
        self.zones.get(domain)
    }

    /// Get a mutable reference to the zone for `domain`, if it exists.
    pub fn get_zone_mut(&'a mut self, domain: &str) -> Option<&'a mut Zone> {
        self.zones.get_mut(domain)
    }
}

/// Thread-safe authoritative DNS data store, holding a set of [`Zone`]s and
/// an optional persistent storage backend.
#[derive(Default)]
pub struct Authority {
    zones: RwLock<Zones>,
    dnssec_signer: RwLock<DnssecSigner>,
    /// Optional persistent storage backend. When present, zone mutations are
    /// written through to the database immediately.
    storage: Option<Arc<PersistentStorage>>,
}

impl Authority {
    /// Create an in-memory-only `Authority`.
    pub fn new() -> Authority {
        let signing_config = SigningConfig::default();
        Authority {
            zones: RwLock::new(Zones::new()),
            dnssec_signer: RwLock::new(DnssecSigner::new(signing_config)),
            storage: None,
        }
    }

    /// Create an `Authority` backed by persistent storage.
    ///
    /// Zones stored in the database are loaded immediately on construction.
    /// If the database is empty the file-based `zones_dir` is used as a
    /// fallback (existing behaviour).
    pub fn with_storage(storage: Arc<PersistentStorage>) -> Authority {
        let signing_config = SigningConfig::default();
        let auth = Authority {
            zones: RwLock::new(Zones::new()),
            dnssec_signer: RwLock::new(DnssecSigner::new(signing_config)),
            storage: Some(storage.clone()),
        };

        match storage.load_all_zones() {
            Ok(zones) if !zones.is_empty() => {
                if let Ok(mut z) = auth.zones.write() {
                    for zone in zones {
                        log::info!("Loaded persisted zone: {}", zone.domain);
                        z.zones.insert(zone.domain.clone(), zone);
                    }
                }
            }
            Ok(_) => {
                log::info!("No zones found in storage; will fall back to zone files");
            }
            Err(e) => {
                log::error!("Failed to load zones from storage: {}", e);
            }
        }

        auth
    }

    /// If a storage backend is configured, persist the named zone.
    fn persist_zone(&self, zone_name: &str) {
        let storage = match &self.storage {
            Some(s) => s.clone(),
            None => return,
        };
        if let Ok(zones) = self.zones.read() {
            if let Some(zone) = zones.zones.get(zone_name) {
                if let Err(e) = storage.save_zone(zone) {
                    log::error!("Failed to persist zone {}: {}", zone_name, e);
                }
            }
        }
    }

    /// If a storage backend is configured, delete the named zone from storage.
    fn remove_persisted_zone(&self, zone_name: &str) {
        if let Some(storage) = &self.storage {
            if let Err(e) = storage.delete_zone(zone_name) {
                log::error!("Failed to delete zone {} from storage: {}", zone_name, e);
            }
        }
    }

    /// Load zone files from `zones_dir` into memory, replacing any existing in-memory data.
    pub fn load(&self, zones_dir: &str) -> Result<()> {
        let mut zones = self
            .zones
            .write()
            .map_err(|_| AuthorityError::PoisonedLock)?;
        zones.load(zones_dir)?;

        Ok(())
    }

    /// Look up `qname`/`qtype` across all zones and return a response packet,
    /// or `None` if no zone is authoritative for the name.
    pub fn query(&self, qname: &str, qtype: QueryType) -> Option<DnsPacket> {
        let zones = self.zones.read().ok()?;

        let mut best_match = None;
        for zone in zones.zones() {
            if !qname.ends_with(&zone.domain) {
                continue;
            }

            if let Some((len, _)) = best_match {
                if len < zone.domain.len() {
                    best_match = Some((zone.domain.len(), zone));
                }
            } else {
                best_match = Some((zone.domain.len(), zone));
            }
        }

        let zone = match best_match {
            Some((_, zone)) => zone,
            None => return None,
        };

        log::info!("zone: {:?}", zone);

        let mut packet = DnsPacket::new();
        packet.header.authoritative_answer = true;

        // Collect exact matches and wildcard matches separately
        let mut exact_matches = Vec::new();
        let mut wildcard_matches = Vec::new();

        for rec in &zone.records {
            let domain = match rec.get_domain() {
                Some(x) => x,
                None => continue,
            };

            log::info!("qname: {:?}", qname);
            log::info!("domain: {:?}", domain);

            // Handle @ symbol (zone apex)
            let normalized_domain = if domain == "@" || domain == format!("@.{}", zone.domain) {
                zone.domain.clone()
            } else {
                domain.clone()
            };

            // Check for exact match
            if &normalized_domain == qname {
                let rtype = rec.get_querytype();
                log::info!("qtype: {:?}", qtype);
                log::info!("rtype: {:?}", rtype);
                
                if qtype == rtype || (qtype == QueryType::A && rtype == QueryType::Cname) {
                    exact_matches.push(rec.clone());
                }
            } 
            // Check for wildcard match
            else if normalized_domain.starts_with("*.") {
                // Extract the wildcard suffix (everything after "*.")
                let wildcard_suffix = &normalized_domain[2..];
                
                // Check if the query name matches the wildcard pattern
                if qname.ends_with(wildcard_suffix) {
                    // Ensure it's not an exact match with the wildcard domain itself
                    if qname != &normalized_domain {
                        // Verify there's at least one label before the wildcard suffix
                        let prefix_len = qname.len() - wildcard_suffix.len();
                        if prefix_len > 0 && qname.chars().nth(prefix_len - 1) == Some('.') {
                            let rtype = rec.get_querytype();
                            
                            if qtype == rtype || (qtype == QueryType::A && rtype == QueryType::Cname) {
                                // Clone the record and update the domain to match the query
                                let mut matched_rec = rec.clone();
                                // Update the domain field in the cloned record
                                match &mut matched_rec {
                                    DnsRecord::A { ref mut domain, .. } |
                                    DnsRecord::Aaaa { ref mut domain, .. } |
                                    DnsRecord::Ns { ref mut domain, .. } |
                                    DnsRecord::Cname { ref mut domain, .. } |
                                    DnsRecord::Srv { ref mut domain, .. } |
                                    DnsRecord::Mx { ref mut domain, .. } |
                                    DnsRecord::Txt { ref mut domain, .. } |
                                    DnsRecord::Soa { ref mut domain, .. } |
                                    DnsRecord::Unknown { ref mut domain, .. } |
                                    DnsRecord::Ds { ref mut domain, .. } |
                                    DnsRecord::Rrsig { ref mut domain, .. } |
                                    DnsRecord::Nsec { ref mut domain, .. } |
                                    DnsRecord::Dnskey { ref mut domain, .. } |
                                    DnsRecord::Nsec3 { ref mut domain, .. } |
                                    DnsRecord::Nsec3param { ref mut domain, .. } => {
                                        *domain = qname.to_string();
                                    }
                                    DnsRecord::Opt { .. } => {
                                        // OPT records don't have a domain field
                                    }
                                }
                                wildcard_matches.push(matched_rec);
                            }
                        }
                    }
                }
            }
        }

        // Prioritize exact matches over wildcard matches
        if !exact_matches.is_empty() {
            packet.answers = exact_matches;
        } else if !wildcard_matches.is_empty() {
            packet.answers = wildcard_matches;
        }

        if packet.answers.is_empty() {
            packet.header.rescode = ResultCode::NXDOMAIN;

            packet.authorities.push(DnsRecord::Soa {
                domain: zone.domain.clone(),
                m_name: zone.m_name.clone(),
                r_name: zone.r_name.clone(),
                serial: zone.serial,
                refresh: zone.refresh,
                retry: zone.retry,
                expire: zone.expire,
                minimum: zone.minimum,
                ttl: TransientTtl(zone.minimum),
            });
        }

        Some(packet)
    }

    /// Acquire a shared read lock on the underlying [`Zones`] collection.
    pub fn read(&self) -> LockResult<RwLockReadGuard<'_, Zones>> {
        self.zones.read()
    }

    /// Acquire an exclusive write lock on the underlying [`Zones`] collection.
    pub fn write(&self) -> LockResult<RwLockWriteGuard<'_, Zones>> {
        self.zones.write()
    }
    
    /// Insert or replace a record in `zone_name`, creating the zone if it does not exist.
    /// All existing records sharing the same domain label are removed before inserting.
    pub fn upsert(&self, zone_name: &str, record: DnsRecord) -> Result<()> {
        let mut zones = self
            .zones
            .write()
            .map_err(|_| AuthorityError::PoisonedLock)?;
        
        // Find or create zone
        let zone = zones.zones.entry(zone_name.to_string())
            .or_insert_with(|| Zone {
                domain: zone_name.to_string(),
                m_name: format!("ns1.{}", zone_name),
                r_name: format!("admin.{}", zone_name),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 86400,
                minimum: 3600,
                records: BTreeSet::new(),
                dnssec_enabled: false,
                signed_zone: None,
            });
        
        // Remove existing records with same domain
        if let Some(domain) = record.get_domain() {
            zone.records.retain(|r| r.get_domain() != Some(domain.clone()));
        }
        
        // Add new record
        zone.records.insert(record);
        drop(zones);

        // Persist the updated zone
        self.persist_zone(zone_name);

        Ok(())
    }

    /// Remove all records in `zone_name` whose domain label equals `domain`.
    pub fn delete_records(&self, zone_name: &str, domain: &str) -> Result<()> {
        let mut zones = self
            .zones
            .write()
            .map_err(|_| AuthorityError::PoisonedLock)?;

        if let Some(zone) = zones.zones.get_mut(zone_name) {
            zone.records.retain(|r| r.get_domain() != Some(domain.to_string()));
        }
        drop(zones);

        self.persist_zone(zone_name);

        Ok(())
    }

    /// Return all resource records for `zone_name`, or `None` if the zone does not exist.
    pub fn get_zone_records(&self, zone_name: &str) -> Option<Vec<DnsRecord>> {
        let zones = self.zones.read().ok()?;
        zones.zones.get(zone_name).map(|zone| {
            zone.records.iter().cloned().collect()
        })
    }

    /// List all zone names
    pub fn list_zones(&self) -> Result<Vec<String>> {
        let zones = self.zones.read().map_err(|_| AuthorityError::PoisonedLock)?;
        Ok(zones.zones.keys().cloned().collect())
    }

    /// Check if a zone exists
    pub fn zone_exists(&self, zone_name: &str) -> bool {
        match self.zones.read() {
            Ok(zones) => zones.zones.contains_key(zone_name),
            Err(_) => false, // If lock is poisoned, assume zone doesn't exist
        }
    }

    /// Create a new zone
    pub fn create_zone(&self, zone_name: &str, m_name: &str, r_name: &str) -> Result<()> {
        let mut zones = self.zones.write().map_err(|_| AuthorityError::PoisonedLock)?;
        if zones.zones.contains_key(zone_name) {
            return Err(AuthorityError::ZoneExists(zone_name.to_string()));
        }
        let zone = Zone::new(zone_name.to_string(), m_name.to_string(), r_name.to_string());
        zones.zones.insert(zone_name.to_string(), zone);
        drop(zones);

        self.persist_zone(zone_name);
        Ok(())
    }

    /// Delete a zone
    pub fn delete_zone(&self, zone_name: &str) -> Result<()> {
        let mut zones = self.zones.write().map_err(|_| AuthorityError::PoisonedLock)?;
        if zones.zones.remove(zone_name).is_none() {
            return Err(AuthorityError::NoSuchZone(zone_name.to_string()));
        }
        drop(zones);

        self.remove_persisted_zone(zone_name);
        Ok(())
    }

    /// Add SOA record to a zone
    pub fn add_soa_record(&self, zone_name: &str, m_name: &str, r_name: &str, serial: u32, refresh: u32, retry: u32, expire: u32, minimum: u32) -> Result<()> {
        let mut zones = self.zones.write().map_err(|_| AuthorityError::PoisonedLock)?;
        let zone = zones.zones.get_mut(zone_name)
            .ok_or_else(|| AuthorityError::NoSuchZone(zone_name.to_string()))?;
        
        let soa_record = DnsRecord::Soa {
            domain: zone_name.to_string(),
            ttl: TransientTtl(3600),
            m_name: m_name.to_string(),
            r_name: r_name.to_string(),
            serial,
            refresh,
            retry,
            expire,
            minimum,
        };
        
        zone.add_record(&soa_record);
        Ok(())
    }

    /// Update SOA record
    pub fn update_soa_record(&self, zone_name: &str, serial: u32) -> Result<()> {
        let mut zones = self.zones.write().map_err(|_| AuthorityError::PoisonedLock)?;
        let zone = zones.zones.get_mut(zone_name)
            .ok_or_else(|| AuthorityError::NoSuchZone(zone_name.to_string()))?;
        
        // Find and update SOA record
        let records = zone.records.clone();
        for record in &records {
            if let DnsRecord::Soa { domain, ttl, m_name, r_name, serial: _, refresh, retry, expire, minimum } = record {
                // Remove old SOA record
                zone.records.remove(record);
                // Add updated SOA record
                let updated_soa = DnsRecord::Soa {
                    domain: domain.clone(),
                    ttl: *ttl,
                    m_name: m_name.clone(),
                    r_name: r_name.clone(),
                    serial,
                    refresh: *refresh,
                    retry: *retry,
                    expire: *expire,
                    minimum: *minimum,
                };
                zone.records.insert(updated_soa);
                return Ok(());
            }
        }
        
        Err(AuthorityError::NoSuchRecord)
    }

    /// Add NS record to a zone
    pub fn add_ns_record(&self, zone_name: &str, ns_host: &str) -> Result<()> {
        let mut zones = self.zones.write().map_err(|_| AuthorityError::PoisonedLock)?;
        let zone = zones.zones.get_mut(zone_name)
            .ok_or_else(|| AuthorityError::NoSuchZone(zone_name.to_string()))?;
        
        let ns_record = DnsRecord::Ns {
            domain: zone_name.to_string(),
            ttl: TransientTtl(3600),
            host: ns_host.to_string(),
        };
        
        zone.add_record(&ns_record);
        Ok(())
    }

    /// Add A record to a zone
    pub fn add_a_record(&self, zone_name: &str, domain: &str, addr: std::net::Ipv4Addr, ttl: u32) -> Result<()> {
        let mut zones = self.zones.write().map_err(|_| AuthorityError::PoisonedLock)?;
        let zone = zones.zones.get_mut(zone_name)
            .ok_or_else(|| AuthorityError::NoSuchZone(zone_name.to_string()))?;
        
        let a_record = DnsRecord::A {
            domain: domain.to_string(),
            ttl: TransientTtl(ttl),
            addr,
        };
        
        zone.add_record(&a_record);
        Ok(())
    }

    /// Add AAAA record to a zone
    pub fn add_aaaa_record(&self, zone_name: &str, domain: &str, addr: std::net::Ipv6Addr, ttl: u32) -> Result<()> {
        let mut zones = self.zones.write().map_err(|_| AuthorityError::PoisonedLock)?;
        let zone = zones.zones.get_mut(zone_name)
            .ok_or_else(|| AuthorityError::NoSuchZone(zone_name.to_string()))?;
        
        let aaaa_record = DnsRecord::Aaaa {
            domain: domain.to_string(),
            ttl: TransientTtl(ttl),
            addr,
        };
        
        zone.add_record(&aaaa_record);
        Ok(())
    }

    /// Add CNAME record to a zone
    pub fn add_cname_record(&self, zone_name: &str, domain: &str, host: &str, ttl: u32) -> Result<()> {
        let mut zones = self.zones.write().map_err(|_| AuthorityError::PoisonedLock)?;
        let zone = zones.zones.get_mut(zone_name)
            .ok_or_else(|| AuthorityError::NoSuchZone(zone_name.to_string()))?;
        
        let cname_record = DnsRecord::Cname {
            domain: domain.to_string(),
            ttl: TransientTtl(ttl),
            host: host.to_string(),
        };
        
        zone.add_record(&cname_record);
        Ok(())
    }

    /// Add MX record to a zone
    pub fn add_mx_record(&self, zone_name: &str, domain: &str, priority: u16, host: &str, ttl: u32) -> Result<()> {
        let mut zones = self.zones.write().map_err(|_| AuthorityError::PoisonedLock)?;
        let zone = zones.zones.get_mut(zone_name)
            .ok_or_else(|| AuthorityError::NoSuchZone(zone_name.to_string()))?;
        
        let mx_record = DnsRecord::Mx {
            domain: domain.to_string(),
            ttl: TransientTtl(ttl),
            priority,
            host: host.to_string(),
        };
        
        zone.add_record(&mx_record);
        Ok(())
    }

    /// Add TXT record to a zone
    pub fn add_txt_record(&self, zone_name: &str, domain: &str, data: &str, ttl: u32) -> Result<()> {
        let mut zones = self.zones.write().map_err(|_| AuthorityError::PoisonedLock)?;
        let zone = zones.zones.get_mut(zone_name)
            .ok_or_else(|| AuthorityError::NoSuchZone(zone_name.to_string()))?;
        
        let txt_record = DnsRecord::Txt {
            domain: domain.to_string(),
            ttl: TransientTtl(ttl),
            data: data.to_string(),
        };
        
        zone.add_record(&txt_record);
        Ok(())
    }

    /// Export zone to string
    pub fn export_zone(&self, zone_name: &str) -> Result<String> {
        let zones = self.zones.read().map_err(|_| AuthorityError::PoisonedLock)?;
        let zone = zones.zones.get(zone_name)
            .ok_or_else(|| AuthorityError::NoSuchZone(zone_name.to_string()))?;
        
        // Create a simple zone file format
        let mut output = String::new();
        output.push_str(&format!("; Zone: {}\n", zone_name));
        
        for record in &zone.records {
            output.push_str(&format!("{:?}\n", record));
        }
        
        Ok(output)
    }

    /// Import zone from string using RFC-compliant zone file parser
    pub fn import_zone(&self, zone_name: &str, data: &str) -> Result<()> {
        // Parse the zone file
        let mut parser = crate::dns::zone_parser::ZoneParser::new(zone_name);
        let parsed_zone = parser.parse_string(data).map_err(|e| {
            AuthorityError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Zone parse error: {}", e)
            ))
        })?;

        // Validate the parsed zone
        let warnings = crate::dns::zone_parser::validate_zone(&parsed_zone);
        for warning in &warnings {
            eprintln!("Zone validation warning: {}", warning);
        }

        // Add the parsed zone to authority
        let mut zones = self.zones.write().map_err(|_| AuthorityError::PoisonedLock)?;
        
        if zones.zones.contains_key(zone_name) {
            return Err(AuthorityError::ZoneExists(zone_name.to_string()));
        }

        zones.zones.insert(zone_name.to_string(), parsed_zone);
        Ok(())
    }

    /// Enable DNSSEC for a zone
    pub fn enable_dnssec(&self, zone_name: &str) -> Result<()> {
        let mut signer = self.dnssec_signer.write().map_err(|_| AuthorityError::PoisonedLock)?;
        
        // Get zone records
        let _records = self.get_zone_records(zone_name)
            .ok_or_else(|| AuthorityError::NoSuchZone(zone_name.to_string()))?;
        
        // Sign the zone
        let signed_zone = signer.enable_zone(zone_name, self)
            .map_err(|e| AuthorityError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
        
        // Store signed zone data
        let mut zones = self.zones.write().map_err(|_| AuthorityError::PoisonedLock)?;
        if let Some(zone) = zones.zones.get_mut(zone_name) {
            // Collect DNSKEY and RRSIG records first
            let mut dnskey_records = Vec::new();
            let mut rrsig_records = Vec::new();
            
            // Add DNSKEY records to the zone
            for dnskey in &signed_zone.dnskeys {
                let dnskey_record = DnsRecord::Dnskey {
                    domain: zone_name.to_string(),
                    flags: dnskey.flags,
                    protocol: dnskey.protocol,
                    algorithm: dnskey.algorithm as u8,
                    public_key: dnskey.public_key.clone(),
                    ttl: TransientTtl(3600),
                };
                dnskey_records.push(dnskey_record);
            }
            
            // Add RRSIG records
            for rrsig in &signed_zone.rrsigs {
                let rrsig_record = DnsRecord::Rrsig {
                    domain: zone_name.to_string(),
                    type_covered: rrsig.type_covered.to_num(),
                    algorithm: rrsig.algorithm as u8,
                    labels: rrsig.labels,
                    original_ttl: rrsig.original_ttl,
                    expiration: rrsig.expiration,
                    inception: rrsig.inception,
                    key_tag: rrsig.key_tag,
                    signer_name: rrsig.signer_name.clone(),
                    signature: rrsig.signature.clone(),
                    ttl: TransientTtl(3600),
                };
                rrsig_records.push(rrsig_record);
            }
            
            // Now update the zone
            zone.dnssec_enabled = true;
            zone.signed_zone = Some(signed_zone);
            
            // Add the collected records
            for record in dnskey_records {
                zone.add_record(&record);
            }
            for record in rrsig_records {
                zone.add_record(&record);
            }
        }
        
        Ok(())
    }

    /// Disable DNSSEC for a zone
    pub fn disable_dnssec(&self, zone_name: &str) -> Result<()> {
        let mut zones = self.zones.write().map_err(|_| AuthorityError::PoisonedLock)?;
        let zone = zones.zones.get_mut(zone_name)
            .ok_or_else(|| AuthorityError::NoSuchZone(zone_name.to_string()))?;
        
        zone.dnssec_enabled = false;
        zone.signed_zone = None;
        
        // Remove DNSSEC records
        zone.records.retain(|r| {
            !matches!(r, 
                DnsRecord::Dnskey { .. } | 
                DnsRecord::Rrsig { .. } | 
                DnsRecord::Nsec { .. } | 
                DnsRecord::Nsec3 { .. } |
                DnsRecord::Ds { .. }
            )
        });
        
        Ok(())
    }

    /// Get DNSSEC status for a zone
    pub fn get_dnssec_status(&self, zone_name: &str) -> Option<bool> {
        let zones = self.zones.read().ok()?;
        zones.zones.get(zone_name).map(|z| z.dnssec_enabled)
    }

    /// Get DS records for a zone (for parent zone delegation)
    pub fn get_ds_records(&self, zone_name: &str) -> Option<Vec<DnsRecord>> {
        let zones = self.zones.read().ok()?;
        let zone = zones.zones.get(zone_name)?;
        
        if !zone.dnssec_enabled || zone.signed_zone.is_none() {
            return None;
        }
        
        let signed_zone = zone.signed_zone.as_ref()?;
        let mut ds_records = Vec::new();
        
        for ds in &signed_zone.ds_records {
            ds_records.push(DnsRecord::Ds {
                domain: zone_name.to_string(),
                key_tag: ds.key_tag,
                algorithm: ds.algorithm as u8,
                digest_type: ds.digest_type as u8,
                digest: ds.digest.clone(),
                ttl: TransientTtl(3600),
            });
        }
        
        Some(ds_records)
    }

    /// Perform DNSSEC key rollover for a zone
    pub fn rollover_dnssec_keys(&self, zone_name: &str) -> Result<()> {
        if !self.get_dnssec_status(zone_name).unwrap_or(false) {
            return Err(AuthorityError::NoSuchZone(format!("DNSSEC not enabled for zone {}", zone_name)));
        }
        
        let mut signer = self.dnssec_signer.write().map_err(|_| AuthorityError::PoisonedLock)?;
        signer.rollover_keys(zone_name)
            .map_err(|e| AuthorityError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
        
        // Re-sign the zone with new keys
        self.enable_dnssec(zone_name)?;
        
        Ok(())
    }

    /// Get DNSSEC statistics
    pub fn get_dnssec_stats(&self) -> Result<serde_json::Value> {
        let signer = self.dnssec_signer.read().map_err(|_| AuthorityError::PoisonedLock)?;
        let stats = signer.get_statistics();

        let zones = self.zones.read().map_err(|_| AuthorityError::PoisonedLock)?;
        let total_zones = zones.zones.len();
        let signed_zones = zones.zones.values()
            .filter(|z| z.dnssec_enabled)
            .count();

        Ok(serde_json::json!({
            "total_zones": total_zones,
            "signed_zones": signed_zones,
            "signatures_created": stats.signatures_created,
            "keys_generated": stats.keys_generated,
            "key_rollovers": stats.key_rollovers,
            "validation_failures": stats.validation_failures,
            "avg_signing_time_ms": stats.avg_signing_time_ms,
        }))
    }

    /// Set the DNSSEC validation mode at runtime.
    pub fn set_validation_mode(&self, mode: ValidationMode) -> Result<()> {
        let mut signer = self.dnssec_signer.write().map_err(|_| AuthorityError::PoisonedLock)?;
        signer.set_validation_mode(mode);
        Ok(())
    }

    /// Return the current DNSSEC validation mode.
    pub fn get_validation_mode(&self) -> ValidationMode {
        self.dnssec_signer
            .read()
            .map(|s| s.validation_mode())
            .unwrap_or(ValidationMode::Off)
    }

    /// Return the full DNSSEC validation status (mode, trust anchor, counters).
    pub fn get_dnssec_validation_status(&self) -> DnssecValidationStatus {
        self.dnssec_signer
            .read()
            .map(|s| s.get_validation_status())
            .unwrap_or_else(|_| DnssecValidationStatus {
                validation_mode: "unknown".to_string(),
                trust_anchor_key_tag: crate::dns::dnssec::IANA_ROOT_KSK_TAG,
                stats: crate::dns::dnssec::ValidationStatsSnapshot {
                    queries_seen: 0,
                    validated_ok: 0,
                    validated_fail: 0,
                    unsigned_responses: 0,
                },
                signing_stats: crate::dns::dnssec::SigningStatistics::default(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::protocol::{DnsRecord, QueryType, TransientTtl};

    fn make_zone(domain: &str) -> Zone {
        Zone::new(domain.to_string(), format!("ns1.{domain}"), format!("admin.{domain}"))
    }

    #[test]
    fn test_zone_add_and_delete_record() {
        let mut zone = make_zone("example.com");
        let rec = DnsRecord::A {
            domain: "www.example.com".to_string(),
            addr: "1.2.3.4".parse().unwrap(),
            ttl: TransientTtl(300),
        };
        assert!(zone.add_record(&rec));
        assert_eq!(zone.records.len(), 1);
        assert!(!zone.add_record(&rec)); // duplicate returns false
        assert!(zone.delete_record(&rec));
        assert!(zone.records.is_empty());
    }

    #[test]
    fn test_zones_add_and_get() {
        let mut zones = Zones::new();
        let zone = make_zone("example.com");
        zones.add_zone(zone);
        assert!(zones.get_zone("example.com").is_some());
        assert!(zones.get_zone("other.com").is_none());
    }

    #[test]
    fn test_zones_list() {
        let mut zones = Zones::new();
        zones.add_zone(make_zone("alpha.com"));
        zones.add_zone(make_zone("beta.com"));
        let list: Vec<_> = zones.zones().iter().map(|z| z.domain.as_str()).collect();
        assert!(list.contains(&"alpha.com"));
        assert!(list.contains(&"beta.com"));
    }

    #[test]
    fn test_authority_query_a_record() {
        let authority = Authority::new();

        let mut zone = make_zone("example.com");
        let rec = DnsRecord::A {
            domain: "www.example.com".to_string(),
            addr: "9.8.7.6".parse().unwrap(),
            ttl: TransientTtl(3600),
        };
        zone.add_record(&rec);

        authority.write().unwrap().add_zone(zone);

        let result = authority.query("www.example.com", QueryType::A);
        assert!(result.is_some());
        let packet = result.unwrap();
        assert!(!packet.answers.is_empty());
    }

    #[test]
    fn test_authority_query_missing_domain() {
        let authority = Authority::new();
        let mut zone = make_zone("example.com");
        let rec = DnsRecord::A {
            domain: "www.example.com".to_string(),
            addr: "1.2.3.4".parse().unwrap(),
            ttl: TransientTtl(3600),
        };
        zone.add_record(&rec);
        authority.write().unwrap().add_zone(zone);

        // Query for a domain not in any zone
        assert!(authority.query("notexist.org", QueryType::A).is_none());
    }

    #[test]
    fn test_authority_query_wrong_qtype() {
        let authority = Authority::new();
        let mut zone = make_zone("example.com");
        let rec = DnsRecord::A {
            domain: "host.example.com".to_string(),
            addr: "1.2.3.4".parse().unwrap(),
            ttl: TransientTtl(3600),
        };
        zone.add_record(&rec);
        authority.write().unwrap().add_zone(zone);

        // AAAA query for an A-only record should return empty answers
        let packet = authority.query("host.example.com", QueryType::Aaaa);
        if let Some(p) = packet {
            assert!(p.answers.is_empty());
        }
    }

    #[test]
    fn test_authority_zone_exists() {
        let authority = Authority::new();
        authority.write().unwrap().add_zone(make_zone("present.com"));
        assert!(authority.zone_exists("present.com"));
        assert!(!authority.zone_exists("absent.com"));
    }

    // ------------------------------------------------------------------
    // Storage-backed integration tests
    // ------------------------------------------------------------------

    fn make_storage() -> Arc<crate::storage::PersistentStorage> {
        Arc::new(crate::storage::PersistentStorage::open(":memory:")
            .expect("in-memory storage"))
    }

    #[test]
    fn test_with_storage_loads_persisted_zones() {
        let storage = make_storage();

        // Pre-populate storage with a zone
        let mut zone = make_zone("persist.com");
        zone.add_record(&DnsRecord::A {
            domain: "www.persist.com".to_string(),
            addr: "1.2.3.4".parse().unwrap(),
            ttl: TransientTtl(3600),
        });
        storage.save_zone(&zone).unwrap();

        // Authority::with_storage should load that zone immediately
        let authority = Authority::with_storage(storage);
        assert!(authority.zone_exists("persist.com"));

        let packet = authority.query("www.persist.com", QueryType::A);
        assert!(packet.is_some());
        assert!(!packet.unwrap().answers.is_empty());
    }

    #[test]
    fn test_create_zone_persists_to_storage() {
        let storage = make_storage();
        let authority = Authority::with_storage(storage.clone());

        // create_zone goes through the Authority API which calls persist_zone
        authority.create_zone("new.com", "ns1.new.com", "admin.new.com").unwrap();

        // Zone must be visible in the storage backend
        let stored = storage.load_all_zones().unwrap();
        assert!(stored.iter().any(|z| z.domain == "new.com"));
    }

    #[test]
    fn test_delete_zone_removes_from_storage() {
        let storage = make_storage();

        // Pre-seed storage
        storage.save_zone(&make_zone("gone.com")).unwrap();

        let authority = Authority::with_storage(storage.clone());
        assert!(authority.zone_exists("gone.com"));

        authority.delete_zone("gone.com").unwrap();
        assert!(!authority.zone_exists("gone.com"));

        // Also gone from persistent storage
        let stored = storage.load_all_zones().unwrap();
        assert!(stored.iter().all(|z| z.domain != "gone.com"));
    }
}
