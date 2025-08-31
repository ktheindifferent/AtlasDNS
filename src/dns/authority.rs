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
use std::sync::{LockResult, RwLock, RwLockReadGuard, RwLockWriteGuard};

use derive_more::{Display, From, Error};

use crate::dns::buffer::{PacketBuffer, StreamPacketBuffer, VectorPacketBuffer};
use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, ResultCode, TransientTtl};
use crate::dns::dnssec::{DnssecSigner, SigningConfig, SignedZone};

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

#[derive(Clone, Debug, Default)]
pub struct Zone {
    pub domain: String,
    pub m_name: String,
    pub r_name: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
    pub records: BTreeSet<DnsRecord>,
    pub dnssec_enabled: bool,
    pub signed_zone: Option<SignedZone>,
}

impl Zone {
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

    pub fn add_record(&mut self, rec: &DnsRecord) -> bool {
        self.records.insert(rec.clone())
    }

    pub fn delete_record(&mut self, rec: &DnsRecord) -> bool {
        self.records.remove(rec)
    }
}

#[derive(Default)]
pub struct Zones {
    zones: BTreeMap<String, Zone>,
}

impl<'a> Zones {
    pub fn new() -> Zones {
        Zones {
            zones: BTreeMap::new(),
        }
    }

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

    pub fn zones(&self) -> Vec<&Zone> {
        self.zones.values().collect()
    }

    pub fn add_zone(&mut self, zone: Zone) {
        self.zones.insert(zone.domain.clone(), zone);
    }

    pub fn get_zone(&'a self, domain: &str) -> Option<&'a Zone> {
        self.zones.get(domain)
    }

    pub fn get_zone_mut(&'a mut self, domain: &str) -> Option<&'a mut Zone> {
        self.zones.get_mut(domain)
    }
}

#[derive(Default)]
pub struct Authority {
    zones: RwLock<Zones>,
    dnssec_signer: RwLock<DnssecSigner>,
}

impl Authority {
    pub fn new() -> Authority {
        let signing_config = SigningConfig::default();
        Authority {
            zones: RwLock::new(Zones::new()),
            dnssec_signer: RwLock::new(DnssecSigner::new(signing_config)),
        }
    }

    pub fn load(&self, zones_dir: &str) -> Result<()> {
        let mut zones = self
            .zones
            .write()
            .map_err(|_| AuthorityError::PoisonedLock)?;
        zones.load(zones_dir)?;

        Ok(())
    }

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

    pub fn read(&self) -> LockResult<RwLockReadGuard<'_, Zones>> {
        self.zones.read()
    }

    pub fn write(&self) -> LockResult<RwLockWriteGuard<'_, Zones>> {
        self.zones.write()
    }
    
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
        
        Ok(())
    }
    
    pub fn delete_records(&self, zone_name: &str, domain: &str) -> Result<()> {
        let mut zones = self
            .zones
            .write()
            .map_err(|_| AuthorityError::PoisonedLock)?;
        
        if let Some(zone) = zones.zones.get_mut(zone_name) {
            zone.records.retain(|r| r.get_domain() != Some(domain.to_string()));
        }
        
        Ok(())
    }

    pub fn get_zone_records(&self, zone_name: &str) -> Option<Vec<DnsRecord>> {
        let zones = self.zones.read().ok()?;
        zones.zones.get(zone_name).map(|zone| {
            zone.records.iter().cloned().collect()
        })
    }

    /// List all zone names
    pub fn list_zones(&self) -> Vec<String> {
        let zones = self.zones.read().unwrap();
        zones.zones.keys().cloned().collect()
    }

    /// Check if a zone exists
    pub fn zone_exists(&self, zone_name: &str) -> bool {
        let zones = self.zones.read().unwrap();
        zones.zones.contains_key(zone_name)
    }

    /// Create a new zone
    pub fn create_zone(&self, zone_name: &str, m_name: &str, r_name: &str) -> Result<()> {
        let mut zones = self.zones.write().unwrap();
        if zones.zones.contains_key(zone_name) {
            return Err(AuthorityError::ZoneExists(zone_name.to_string()));
        }
        let zone = Zone::new(zone_name.to_string(), m_name.to_string(), r_name.to_string());
        zones.zones.insert(zone_name.to_string(), zone);
        Ok(())
    }

    /// Delete a zone
    pub fn delete_zone(&self, zone_name: &str) -> Result<()> {
        let mut zones = self.zones.write().unwrap();
        if zones.zones.remove(zone_name).is_none() {
            return Err(AuthorityError::NoSuchZone(zone_name.to_string()));
        }
        Ok(())
    }

    /// Add SOA record to a zone
    pub fn add_soa_record(&self, zone_name: &str, m_name: &str, r_name: &str, serial: u32, refresh: u32, retry: u32, expire: u32, minimum: u32) -> Result<()> {
        let mut zones = self.zones.write().unwrap();
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
        let mut zones = self.zones.write().unwrap();
        let zone = zones.zones.get_mut(zone_name)
            .ok_or_else(|| AuthorityError::NoSuchZone(zone_name.to_string()))?;
        
        // Find and update SOA record
        let mut records = zone.records.clone();
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
        let mut zones = self.zones.write().unwrap();
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
        let mut zones = self.zones.write().unwrap();
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
        let mut zones = self.zones.write().unwrap();
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
        let mut zones = self.zones.write().unwrap();
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
        let mut zones = self.zones.write().unwrap();
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
        let mut zones = self.zones.write().unwrap();
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
        let zones = self.zones.read().unwrap();
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

    /// Import zone from string
    pub fn import_zone(&self, zone_name: &str, _data: &str) -> Result<()> {
        // For now, just create an empty zone
        // TODO: Implement proper zone file parsing
        self.create_zone(zone_name, &format!("ns1.{}", zone_name), &format!("admin.{}", zone_name))
    }

    /// Enable DNSSEC for a zone
    pub fn enable_dnssec(&self, zone_name: &str) -> Result<()> {
        let mut signer = self.dnssec_signer.write().unwrap();
        
        // Get zone records
        let records = self.get_zone_records(zone_name)
            .ok_or_else(|| AuthorityError::NoSuchZone(zone_name.to_string()))?;
        
        // Sign the zone
        let signed_zone = signer.enable_zone(zone_name, self)
            .map_err(|e| AuthorityError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
        
        // Store signed zone data
        let mut zones = self.zones.write().unwrap();
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
        let mut zones = self.zones.write().unwrap();
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
        
        let mut signer = self.dnssec_signer.write().unwrap();
        signer.rollover_keys(zone_name)
            .map_err(|e| AuthorityError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
        
        // Re-sign the zone with new keys
        self.enable_dnssec(zone_name)?;
        
        Ok(())
    }

    /// Get DNSSEC statistics
    pub fn get_dnssec_stats(&self) -> serde_json::Value {
        let signer = self.dnssec_signer.read().unwrap();
        let stats = signer.get_statistics();
        
        let zones = self.zones.read().unwrap();
        let total_zones = zones.zones.len();
        let signed_zones = zones.zones.values()
            .filter(|z| z.dnssec_enabled)
            .count();
        
        serde_json::json!({
            "total_zones": total_zones,
            "signed_zones": signed_zones,
            "signatures_created": stats.signatures_created,
            "keys_generated": stats.keys_generated,
            "key_rollovers": stats.key_rollovers,
            "validation_failures": stats.validation_failures,
            "avg_signing_time_ms": stats.avg_signing_time_ms,
        })
    }
}

#[cfg(test)]
mod authority_test;
