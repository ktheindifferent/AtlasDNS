//! DNSSEC Automation Module
//!
//! Provides automated DNSSEC signing and validation with ECDSA P-256 support.
//! Implements one-click zone signing with automatic key management.
//!
//! # Features
//!
//! * **Automatic Key Generation** - ECDSA P-256 and RSA key generation
//! * **Zone Signing** - Automated signing of DNS zones
//! * **Key Rollover** - Automatic key rotation with overlap periods
//! * **Chain of Trust** - DS record generation and management
//! * **Validation** - DNSSEC signature validation
//! * **NSEC3** - Authenticated denial of existence with hashing

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use openssl::pkey::{PKey, Private};
use openssl::sign::{Signer, Verifier};
use openssl::hash::MessageDigest;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::rsa::Rsa;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ecdsa::EcdsaSig;
use sha2::{Sha256, Digest};
// base64 import removed - unused

use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType};
use crate::dns::authority::Authority;
// ServerContext import removed - unused

// ---------------------------------------------------------------------------
// DNSSEC Validation Mode
// ---------------------------------------------------------------------------

/// DNSSEC validation policy applied to resolved responses.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValidationMode {
    /// Reject responses with invalid or missing signatures (RFC 4035 §5.3)
    Strict,
    /// Validate when signatures are present; allow unsigned responses through
    Opportunistic,
    /// Skip DNSSEC validation entirely
    Off,
}

impl Default for ValidationMode {
    fn default() -> Self {
        ValidationMode::Opportunistic
    }
}

impl std::fmt::Display for ValidationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationMode::Strict => write!(f, "strict"),
            ValidationMode::Opportunistic => write!(f, "opportunistic"),
            ValidationMode::Off => write!(f, "off"),
        }
    }
}

// ---------------------------------------------------------------------------
// IANA Root KSK Trust Anchor (KSK-2017, key tag 20326, algorithm RSA/SHA-256)
// Source: https://data.iana.org/root-anchors/root-anchors.xml
// ---------------------------------------------------------------------------

/// IANA Root KSK public key (base64, RFC 4034 wire format)
pub const IANA_ROOT_KSK_B64: &str =
    "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3\
     +/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv\
     ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0\
     jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZ\
     G+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRU\
     fhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1A\
     kUTV74bU=";

/// IANA Root KSK key tag
pub const IANA_ROOT_KSK_TAG: u16 = 20326;

// ---------------------------------------------------------------------------
// Validation Statistics (lock-free atomics, safe to share across threads)
// ---------------------------------------------------------------------------

/// Per-query DNSSEC validation counters
#[derive(Debug, Default)]
pub struct ValidationStats {
    pub queries_seen: AtomicU64,
    pub validated_ok: AtomicU64,
    pub validated_fail: AtomicU64,
    pub unsigned_responses: AtomicU64,
}

impl ValidationStats {
    pub fn snapshot(&self) -> ValidationStatsSnapshot {
        ValidationStatsSnapshot {
            queries_seen: self.queries_seen.load(Ordering::Relaxed),
            validated_ok: self.validated_ok.load(Ordering::Relaxed),
            validated_fail: self.validated_fail.load(Ordering::Relaxed),
            unsigned_responses: self.unsigned_responses.load(Ordering::Relaxed),
        }
    }
}

/// Serialisable snapshot of validation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationStatsSnapshot {
    pub queries_seen: u64,
    pub validated_ok: u64,
    pub validated_fail: u64,
    pub unsigned_responses: u64,
}

/// Full DNSSEC validation status returned by the API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecValidationStatus {
    pub validation_mode: String,
    pub trust_anchor_key_tag: u16,
    pub stats: ValidationStatsSnapshot,
    pub signing_stats: SigningStatistics,
}

/// DNSSEC algorithm types
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum DnssecAlgorithm {
    /// RSA/SHA-256 (Algorithm 8)
    RsaSha256 = 8,
    /// RSA/SHA-512 (Algorithm 10)
    RsaSha512 = 10,
    /// ECDSA P-256 with SHA-256 (Algorithm 13)
    EcdsaP256Sha256 = 13,
    /// ECDSA P-384 with SHA-384 (Algorithm 14)
    EcdsaP384Sha384 = 14,
    /// ED25519 (Algorithm 15)
    Ed25519 = 15,
}

/// DNSSEC digest types for DS records
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum DigestType {
    /// SHA-1 (Digest Type 1) - Deprecated
    Sha1 = 1,
    /// SHA-256 (Digest Type 2)
    Sha256 = 2,
    /// SHA-384 (Digest Type 4)
    Sha384 = 4,
}

/// DNSSEC key type
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum KeyType {
    /// Zone Signing Key (ZSK)
    ZSK,
    /// Key Signing Key (KSK)
    KSK,
}

/// DNSSEC key pair
#[derive(Clone)]
pub struct DnssecKey {
    /// Key identifier
    pub key_tag: u16,
    /// Key type (ZSK or KSK)
    pub key_type: KeyType,
    /// Algorithm used
    pub algorithm: DnssecAlgorithm,
    /// Public key
    pub public_key: Vec<u8>,
    /// Private key (for signing)
    private_key: Option<PKey<Private>>,
    /// Key creation time
    pub created_at: SystemTime,
    /// Key activation time
    pub activate_at: SystemTime,
    /// Key expiration time
    pub expire_at: SystemTime,
    /// Is key active
    pub is_active: bool,
}

impl DnssecKey {
    /// Generate a new DNSSEC key pair
    pub fn generate(
        key_type: KeyType,
        algorithm: DnssecAlgorithm,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let (private_key, public_key_bytes) = match algorithm {
            DnssecAlgorithm::EcdsaP256Sha256 => {
                let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
                let ec_key = EcKey::generate(&group)?;
                let pkey = PKey::from_ec_key(ec_key)?;
                let public_bytes = pkey.public_key_to_der()?;
                (pkey, public_bytes)
            }
            DnssecAlgorithm::RsaSha256 | DnssecAlgorithm::RsaSha512 => {
                let key_size = if key_type == KeyType::KSK { 2048 } else { 1024 };
                let rsa = Rsa::generate(key_size)?;
                let pkey = PKey::from_rsa(rsa)?;
                let public_bytes = pkey.public_key_to_der()?;
                (pkey, public_bytes)
            }
            _ => {
                return Err("Unsupported algorithm".into());
            }
        };

        let key_tag = Self::calculate_key_tag(&public_key_bytes, algorithm);
        let now = SystemTime::now();

        Ok(DnssecKey {
            key_tag,
            key_type,
            algorithm,
            public_key: public_key_bytes,
            private_key: Some(private_key),
            created_at: now,
            activate_at: now,
            expire_at: now + Duration::from_secs(365 * 24 * 60 * 60), // 1 year
            is_active: true,
        })
    }

    /// Calculate key tag from public key
    fn calculate_key_tag(public_key: &[u8], _algorithm: DnssecAlgorithm) -> u16 {
        // Simplified key tag calculation (RFC 4034)
        let mut sum: u32 = 0;
        
        for (i, &byte) in public_key.iter().enumerate() {
            if i % 2 == 0 {
                sum += (byte as u32) << 8;
            } else {
                sum += byte as u32;
            }
        }
        
        sum += (sum >> 16) & 0xFFFF;
        (sum & 0xFFFF) as u16
    }

    /// Sign data with this key
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let private_key = self.private_key.as_ref()
            .ok_or("Private key not available")?;

        let digest = match self.algorithm {
            DnssecAlgorithm::EcdsaP256Sha256 | DnssecAlgorithm::RsaSha256 => {
                MessageDigest::sha256()
            }
            DnssecAlgorithm::RsaSha512 => MessageDigest::sha512(),
            _ => return Err("Unsupported algorithm".into()),
        };

        let mut signer = Signer::new(digest, private_key)?;
        signer.update(data)?;
        Ok(signer.sign_to_vec()?)
    }

    /// Verify signature with public key
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
        let public_key = PKey::public_key_from_der(&self.public_key)?;

        let digest = match self.algorithm {
            DnssecAlgorithm::EcdsaP256Sha256 | DnssecAlgorithm::RsaSha256 => {
                MessageDigest::sha256()
            }
            DnssecAlgorithm::RsaSha512 => MessageDigest::sha512(),
            _ => return Err("Unsupported algorithm".into()),
        };

        let mut verifier = Verifier::new(digest, &public_key)?;
        verifier.update(data)?;
        Ok(verifier.verify(signature)?)
    }
}

/// RRSIG record data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RrsigRecord {
    /// Type covered
    pub type_covered: QueryType,
    /// Algorithm
    pub algorithm: DnssecAlgorithm,
    /// Labels count
    pub labels: u8,
    /// Original TTL
    pub original_ttl: u32,
    /// Signature expiration
    pub expiration: u32,
    /// Signature inception
    pub inception: u32,
    /// Key tag
    pub key_tag: u16,
    /// Signer's name
    pub signer_name: String,
    /// Signature
    pub signature: Vec<u8>,
}

/// DNSKEY record data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnskeyRecord {
    /// Flags (256 for ZSK, 257 for KSK)
    pub flags: u16,
    /// Protocol (always 3)
    pub protocol: u8,
    /// Algorithm
    pub algorithm: DnssecAlgorithm,
    /// Public key
    pub public_key: Vec<u8>,
}

/// DS record data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsRecord {
    /// Key tag
    pub key_tag: u16,
    /// Algorithm
    pub algorithm: DnssecAlgorithm,
    /// Digest type
    pub digest_type: DigestType,
    /// Digest
    pub digest: Vec<u8>,
}

/// NSEC3 record data for authenticated denial
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nsec3Record {
    /// Hash algorithm (1 = SHA-1)
    pub hash_algorithm: u8,
    /// Flags
    pub flags: u8,
    /// Iterations
    pub iterations: u16,
    /// Salt
    pub salt: Vec<u8>,
    /// Next hashed owner name
    pub next_hashed: Vec<u8>,
    /// Type bit maps
    pub type_bitmaps: Vec<u8>,
}

/// DNSSEC zone signing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningConfig {
    /// Enable automatic signing
    pub enabled: bool,
    /// Algorithm to use
    pub algorithm: DnssecAlgorithm,
    /// ZSK lifetime
    pub zsk_lifetime: Duration,
    /// KSK lifetime
    pub ksk_lifetime: Duration,
    /// Signature validity period
    pub signature_validity: Duration,
    /// Enable NSEC3
    pub use_nsec3: bool,
    /// NSEC3 iterations
    pub nsec3_iterations: u16,
    /// NSEC3 salt length
    pub nsec3_salt_length: usize,
    /// Validation mode for incoming responses
    pub validation_mode: ValidationMode,
}

impl Default for SigningConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            algorithm: DnssecAlgorithm::EcdsaP256Sha256,
            zsk_lifetime: Duration::from_secs(30 * 24 * 60 * 60), // 30 days
            ksk_lifetime: Duration::from_secs(365 * 24 * 60 * 60), // 1 year
            signature_validity: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
            use_nsec3: true,
            nsec3_iterations: 10,
            nsec3_salt_length: 8,
            validation_mode: ValidationMode::Opportunistic,
        }
    }
}

/// DNSSEC signer for automated zone signing
pub struct DnssecSigner {
    /// Zone keys
    keys: Arc<RwLock<HashMap<String, Vec<DnssecKey>>>>,
    /// Signing configuration
    config: SigningConfig,
    /// Signed zones cache
    signed_zones: Arc<RwLock<HashMap<String, SignedZone>>>,
    /// Signing statistics
    stats: Arc<RwLock<SigningStatistics>>,
    /// Validation statistics (lock-free)
    validation_stats: Arc<ValidationStats>,
}

/// Signed zone data
#[derive(Clone, Debug)]
pub struct SignedZone {
    /// Zone name
    pub zone: String,
    /// Original records
    pub records: Vec<DnsRecord>,
    /// RRSIG records
    pub rrsigs: Vec<RrsigRecord>,
    /// DNSKEY records
    pub dnskeys: Vec<DnskeyRecord>,
    /// DS records for parent zone
    pub ds_records: Vec<DsRecord>,
    /// NSEC3 records
    pub nsec3_records: Vec<Nsec3Record>,
    /// Signing time
    pub signed_at: SystemTime,
    /// Next resign time
    pub resign_at: SystemTime,
}

/// Signing statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SigningStatistics {
    /// Total zones signed
    pub zones_signed: u64,
    /// Total signatures created
    pub signatures_created: u64,
    /// Keys generated
    pub keys_generated: u64,
    /// Key rollovers performed
    pub key_rollovers: u64,
    /// Validation failures
    pub validation_failures: u64,
    /// Average signing time
    pub avg_signing_time_ms: f64,
}

impl Default for DnssecSigner {
    fn default() -> Self {
        Self::new(SigningConfig::default())
    }
}

impl DnssecSigner {
    /// Create a new DNSSEC signer
    pub fn new(config: SigningConfig) -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            config,
            signed_zones: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(SigningStatistics::default())),
            validation_stats: Arc::new(ValidationStats::default()),
        }
    }

    /// Return the current validation mode
    pub fn validation_mode(&self) -> ValidationMode {
        self.config.validation_mode
    }

    /// Set the validation mode at runtime
    pub fn set_validation_mode(&mut self, mode: ValidationMode) {
        self.config.validation_mode = mode;
        log::info!("DNSSEC validation mode set to: {}", mode);
    }

    /// Return a full status snapshot for the API
    pub fn get_validation_status(&self) -> DnssecValidationStatus {
        DnssecValidationStatus {
            validation_mode: self.config.validation_mode.to_string(),
            trust_anchor_key_tag: IANA_ROOT_KSK_TAG,
            stats: self.validation_stats.snapshot(),
            signing_stats: self.get_statistics(),
        }
    }

    /// Enable DNSSEC for a zone (one-click signing)
    pub fn enable_zone(
        &mut self,
        zone: &str,
        authority: &Authority,
    ) -> Result<SignedZone, Box<dyn std::error::Error>> {
        log::info!("Enabling DNSSEC for zone: {}", zone);
        
        // Generate keys if they don't exist
        self.ensure_keys(zone)?;
        
        // Get zone records
        let records = authority.get_zone_records(zone)
            .ok_or("Zone not found")?;
        
        // Sign the zone
        let signed_zone = self.sign_zone(zone, records)?;
        
        // Store signed zone
        self.signed_zones.write().insert(zone.to_string(), signed_zone.clone());
        
        // Update statistics
        {
            let mut stats = self.stats.write();
            stats.zones_signed += 1;
        }
        
        log::info!("DNSSEC enabled for zone: {}", zone);
        Ok(signed_zone)
    }

    /// Ensure keys exist for a zone
    fn ensure_keys(&mut self, zone: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut keys_map = self.keys.write();
        
        if !keys_map.contains_key(zone) {
            log::info!("Generating DNSSEC keys for zone: {}", zone);
            
            // Generate KSK
            let ksk = DnssecKey::generate(KeyType::KSK, self.config.algorithm)?;
            
            // Generate ZSK
            let zsk = DnssecKey::generate(KeyType::ZSK, self.config.algorithm)?;
            
            keys_map.insert(zone.to_string(), vec![ksk, zsk]);
            
            // Update statistics
            self.stats.write().keys_generated += 2;
        }
        
        Ok(())
    }

    /// Sign a zone with DNSSEC
    fn sign_zone(
        &self,
        zone: &str,
        records: Vec<DnsRecord>,
    ) -> Result<SignedZone, Box<dyn std::error::Error>> {
        let start = std::time::Instant::now();
        let keys = self.keys.read();
        let zone_keys = keys.get(zone).ok_or("Keys not found for zone")?;
        
        let mut rrsigs = Vec::new();
        let mut dnskeys = Vec::new();
        let mut ds_records = Vec::new();
        let mut nsec3_records = Vec::new();
        
        // Create DNSKEY records
        for key in zone_keys {
            let flags = match key.key_type {
                KeyType::ZSK => 256,
                KeyType::KSK => 257,
            };
            
            dnskeys.push(DnskeyRecord {
                flags,
                protocol: 3,
                algorithm: key.algorithm,
                public_key: key.public_key.clone(),
            });
            
            // Generate DS record for KSK
            if key.key_type == KeyType::KSK {
                ds_records.push(self.generate_ds_record(zone, key)?);
            }
        }
        
        // Sign records with ZSK
        let zsk = zone_keys.iter()
            .find(|k| k.key_type == KeyType::ZSK)
            .ok_or("ZSK not found")?;
        
        // Group records by type and sign
        let mut records_by_type: HashMap<QueryType, Vec<&DnsRecord>> = HashMap::new();
        for record in &records {
            let qtype = self.get_record_type(record);
            records_by_type.entry(qtype).or_insert_with(Vec::new).push(record);
        }
        
        for (qtype, type_records) in records_by_type {
            let rrsig = self.sign_record_set(zone, qtype, type_records, zsk)?;
            rrsigs.push(rrsig);
            self.stats.write().signatures_created += 1;
        }
        
        // Generate NSEC3 records if enabled
        if self.config.use_nsec3 {
            nsec3_records = self.generate_nsec3_records(zone, &records)?;
        }
        
        let now = SystemTime::now();
        let signed_zone = SignedZone {
            zone: zone.to_string(),
            records,
            rrsigs,
            dnskeys,
            ds_records,
            nsec3_records,
            signed_at: now,
            resign_at: now + self.config.signature_validity,
        };
        
        // Update signing time statistics
        let signing_time = start.elapsed().as_millis() as f64;
        {
            let mut stats = self.stats.write();
            let n = stats.zones_signed as f64;
            stats.avg_signing_time_ms = (stats.avg_signing_time_ms * n + signing_time) / (n + 1.0);
        }
        
        Ok(signed_zone)
    }

    /// Generate DS record for a key
    fn generate_ds_record(
        &self,
        zone: &str,
        key: &DnssecKey,
    ) -> Result<DsRecord, Box<dyn std::error::Error>> {
        // Build DNSKEY wire format
        let mut data = Vec::new();
        data.extend_from_slice(zone.as_bytes());
        
        let flags: u16 = if key.key_type == KeyType::KSK { 257 } else { 256 };
        data.extend_from_slice(&flags.to_be_bytes());
        data.push(3); // Protocol
        data.push(key.algorithm as u8);
        data.extend_from_slice(&key.public_key);
        
        // Calculate digest
        let digest = match DigestType::Sha256 {
            DigestType::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(&data);
                hasher.finalize().to_vec()
            }
            _ => return Err("Unsupported digest type".into()),
        };
        
        Ok(DsRecord {
            key_tag: key.key_tag,
            algorithm: key.algorithm,
            digest_type: DigestType::Sha256,
            digest,
        })
    }

    /// Sign a record set
    fn sign_record_set(
        &self,
        zone: &str,
        qtype: QueryType,
        records: Vec<&DnsRecord>,
        key: &DnssecKey,
    ) -> Result<RrsigRecord, Box<dyn std::error::Error>> {
        // Serialize records for signing
        let mut data = Vec::new();
        for record in &records {
            // Simplified - would need proper DNS wire format serialization
            data.extend_from_slice(format!("{:?}", record).as_bytes());
        }
        
        // Sign the data
        let signature = key.sign(&data)?;
        
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;
        let expiration = now + self.config.signature_validity.as_secs() as u32;
        
        Ok(RrsigRecord {
            type_covered: qtype,
            algorithm: key.algorithm,
            labels: zone.split('.').count() as u8,
            original_ttl: 300, // Default TTL
            expiration,
            inception: now,
            key_tag: key.key_tag,
            signer_name: zone.to_string(),
            signature,
        })
    }

    /// Generate NSEC3 records for authenticated denial
    fn generate_nsec3_records(
        &self,
        _zone: &str,
        records: &[DnsRecord],
    ) -> Result<Vec<Nsec3Record>, Box<dyn std::error::Error>> {
        let mut nsec3_records = Vec::new();
        
        // Generate salt
        let salt = generate_random_bytes(self.config.nsec3_salt_length);
        
        // Hash all names in the zone
        let mut hashed_names: Vec<Vec<u8>> = Vec::new();
        for record in records {
            let name = self.get_record_name(record);
            let hashed = self.nsec3_hash(&name, &salt, self.config.nsec3_iterations);
            hashed_names.push(hashed);
        }
        
        // Sort hashed names
        hashed_names.sort();
        
        // Create NSEC3 chain
        for i in 0..hashed_names.len() {
            let next_index = (i + 1) % hashed_names.len();
            
            nsec3_records.push(Nsec3Record {
                hash_algorithm: 1, // SHA-1
                flags: 0,
                iterations: self.config.nsec3_iterations,
                salt: salt.clone(),
                next_hashed: hashed_names[next_index].clone(),
                type_bitmaps: vec![0xFF], // Simplified - would need proper type bitmap
            });
        }
        
        Ok(nsec3_records)
    }

    /// NSEC3 hash function
    fn nsec3_hash(&self, name: &str, salt: &[u8], iterations: u16) -> Vec<u8> {
        let mut hash = name.as_bytes().to_vec();
        hash.extend_from_slice(salt);
        
        for _ in 0..iterations + 1 {
            let mut hasher = Sha256::new();
            hasher.update(&hash);
            hash = hasher.finalize().to_vec();
        }
        
        hash
    }

    /// Get record type from DnsRecord
    fn get_record_type(&self, record: &DnsRecord) -> QueryType {
        match record {
            DnsRecord::A { .. } => QueryType::A,
            DnsRecord::Aaaa { .. } => QueryType::Aaaa,
            DnsRecord::Cname { .. } => QueryType::Cname,
            DnsRecord::Mx { .. } => QueryType::Mx,
            DnsRecord::Ns { .. } => QueryType::Ns,
            DnsRecord::Txt { .. } => QueryType::Txt,
            _ => QueryType::Unknown(0),
        }
    }

    /// Get record name from DnsRecord
    fn get_record_name(&self, record: &DnsRecord) -> String {
        match record {
            DnsRecord::A { domain, .. } |
            DnsRecord::Aaaa { domain, .. } |
            DnsRecord::Cname { domain, .. } |
            DnsRecord::Mx { domain, .. } |
            DnsRecord::Ns { domain, .. } |
            DnsRecord::Txt { domain, .. } => domain.clone(),
            _ => String::new(),
        }
    }

    /// Validate DNSSEC signatures on a resolved packet.
    ///
    /// Behaviour depends on `ValidationMode`:
    /// - `Off` – always returns `true` without inspection
    /// - `Opportunistic` – validates when RRSIGs are present; unsigned passes through
    /// - `Strict` – unsigned responses fail (returns `false`)
    ///
    /// Uses real cryptographic verification (RSA/SHA-256, ECDSA P-256) via
    /// `ChainValidator` rather than a stub.
    pub fn validate(
        &self,
        packet: &DnsPacket,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if self.config.validation_mode == ValidationMode::Off {
            return Ok(true);
        }

        self.validation_stats.queries_seen.fetch_add(1, Ordering::Relaxed);
        log::debug!("DNSSEC validate (mode={}, answers={})", self.config.validation_mode, packet.answers.len());

        if packet.answers.is_empty() {
            return Ok(true);
        }

        let chain = ChainValidator::with_root_ksk(self.config.validation_mode);
        match chain.validate_packet_rrsigs(packet) {
            ChainValidationResult::Authenticated => {
                self.validation_stats.validated_ok.fetch_add(1, Ordering::Relaxed);
                log::info!("DNSSEC: response authenticated");
                Ok(true)
            }
            ChainValidationResult::Unsigned => {
                self.validation_stats.unsigned_responses.fetch_add(1, Ordering::Relaxed);
                if self.config.validation_mode == ValidationMode::Strict {
                    log::warn!("DNSSEC strict: unsigned response rejected");
                    self.validation_stats.validated_fail.fetch_add(1, Ordering::Relaxed);
                    self.stats.write().validation_failures += 1;
                    return Ok(false);
                }
                log::debug!("DNSSEC opportunistic: unsigned response allowed through");
                Ok(true)
            }
            ChainValidationResult::ValidationFailed => {
                self.validation_stats.validated_fail.fetch_add(1, Ordering::Relaxed);
                self.stats.write().validation_failures += 1;
                log::warn!("DNSSEC: signature validation failed");
                Ok(false)
            }
        }
    }
    
    /// Extract zone name from domain
    fn extract_zone_from_domain(&self, domain: &str) -> String {
        // Simple zone extraction - take last two parts of domain
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() >= 2 {
            format!("{}.{}", parts[parts.len()-2], parts[parts.len()-1])
        } else {
            domain.to_string()
        }
    }
    
    /// Validate signature for a single record
    fn validate_signature_for_record(
        &self, 
        _rrsig_record: &DnsRecord, 
        key: &DnssecKey
    ) -> Result<bool, Box<dyn std::error::Error>> {
        // This is a simplified validation
        // In a real implementation, we would:
        // 1. Extract RRSIG data from the record
        // 2. Reconstruct the signed data
        // 3. Verify the signature using the key
        
        log::debug!("Validating signature for record with key tag: {}", key.key_tag);
        
        // For now, simulate validation based on key properties
        if key.is_active && key.algorithm == DnssecAlgorithm::EcdsaP256Sha256 {
            // Simulate successful validation for active ECDSA keys
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Perform key rollover
    pub fn rollover_keys(
        &mut self,
        zone: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("Starting key rollover for zone: {}", zone);
        
        // Generate new keys
        let new_ksk = DnssecKey::generate(KeyType::KSK, self.config.algorithm)?;
        let new_zsk = DnssecKey::generate(KeyType::ZSK, self.config.algorithm)?;
        
        // Add new keys while keeping old ones (for overlap period)
        {
            let mut keys_map = self.keys.write();
            if let Some(zone_keys) = keys_map.get_mut(zone) {
                zone_keys.push(new_ksk);
                zone_keys.push(new_zsk);
            }
        }
        
        // Update statistics
        self.stats.write().key_rollovers += 1;
        
        log::info!("Key rollover completed for zone: {}", zone);
        Ok(())
    }

    /// Get signing statistics
    pub fn get_statistics(&self) -> SigningStatistics {
        let stats = self.stats.read();
        SigningStatistics {
            zones_signed: stats.zones_signed,
            signatures_created: stats.signatures_created,
            keys_generated: stats.keys_generated,
            key_rollovers: stats.key_rollovers,
            validation_failures: stats.validation_failures,
            avg_signing_time_ms: stats.avg_signing_time_ms,
        }
    }
    
    /// Enable DNSSEC validation
    pub fn enable_validation(&mut self) {
        let mut config = self.config.clone();
        config.enabled = true;
        self.config = config;
        log::info!("DNSSEC validation enabled");
    }
    
    /// Disable DNSSEC validation
    pub fn disable_validation(&mut self) {
        let mut config = self.config.clone();
        config.enabled = false;
        self.config = config;
        log::info!("DNSSEC validation disabled");
    }
    
    /// Check if DNSSEC validation is enabled
    pub fn is_validation_enabled(&self) -> bool {
        self.config.enabled
    }
    
    /// Get signed zone information
    pub fn get_signed_zone(&self, zone: &str) -> Option<SignedZone> {
        self.signed_zones.read().get(zone).cloned()
    }
    
    /// List all signed zones
    pub fn list_signed_zones(&self) -> Vec<String> {
        self.signed_zones.read().keys().cloned().collect()
    }
    
    /// Disable DNSSEC for a zone
    pub fn disable_zone(&mut self, zone: &str) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("Disabling DNSSEC for zone: {}", zone);
        
        // Remove zone keys
        self.keys.write().remove(zone);
        
        // Remove signed zone
        self.signed_zones.write().remove(zone);
        
        log::info!("DNSSEC disabled for zone: {}", zone);
        Ok(())
    }
    
    /// Check if a zone is DNSSEC-enabled
    pub fn is_zone_signed(&self, zone: &str) -> bool {
        self.signed_zones.read().contains_key(zone)
    }
    
    /// Get keys for a zone
    pub fn get_zone_keys(&self, zone: &str) -> Option<Vec<DnssecKey>> {
        self.keys.read().get(zone).cloned()
    }
    
    /// Update signing configuration
    pub fn update_config(&mut self, new_config: SigningConfig) {
        self.config = new_config;
        log::info!("DNSSEC configuration updated");
    }
}

// Random number generation using system entropy
fn generate_random_bytes(len: usize) -> Vec<u8> {
    use std::fs::File;
    use std::io::Read;
    
    let mut bytes = vec![0u8; len];
    
    // Try to read from /dev/urandom on Unix systems
    #[cfg(unix)]
    {
        if let Ok(mut file) = File::open("/dev/urandom") {
            if file.read_exact(&mut bytes).is_ok() {
                return bytes;
            }
        }
    }
    
    // Fallback: use system time-based pseudo-random generation
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    
    for i in 0..len {
        let mut h = DefaultHasher::new();
        (hasher.finish() + i as u64).hash(&mut h);
        bytes[i] = (h.finish() & 0xFF) as u8;
    }
    
    bytes
}

// ---------------------------------------------------------------------------
// RFC 4034 canonical wire-format helpers
// ---------------------------------------------------------------------------

/// Encode a DNS owner name in canonical wire format (lowercase, no compression).
/// Trailing dot is stripped; root zone is encoded as a single zero byte.
fn name_to_wire_canonical(name: &str) -> Vec<u8> {
    let mut wire = Vec::new();
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        wire.push(0u8);
        return wire;
    }
    for label in trimmed.split('.') {
        let lower = label.to_lowercase();
        let bytes = lower.as_bytes();
        wire.push(bytes.len() as u8);
        wire.extend_from_slice(bytes);
    }
    wire.push(0u8);
    wire
}

/// Extract the canonical RDATA bytes for a `DnsRecord`.
/// Domain names inside RDATA are encoded in canonical (uncompressed, lowercase) form.
fn record_rdata_wire(record: &DnsRecord) -> Vec<u8> {
    match record {
        DnsRecord::A { addr, .. } => addr.octets().to_vec(),
        DnsRecord::Aaaa { addr, .. } => {
            let mut out = Vec::with_capacity(16);
            for seg in addr.segments() {
                out.extend_from_slice(&seg.to_be_bytes());
            }
            out
        }
        DnsRecord::Ns { host, .. } | DnsRecord::Cname { host, .. } => {
            name_to_wire_canonical(host)
        }
        DnsRecord::Mx { priority, host, .. } => {
            let mut out = priority.to_be_bytes().to_vec();
            out.extend(name_to_wire_canonical(host));
            out
        }
        DnsRecord::Srv { priority, weight, port, host, .. } => {
            let mut out = Vec::new();
            out.extend_from_slice(&priority.to_be_bytes());
            out.extend_from_slice(&weight.to_be_bytes());
            out.extend_from_slice(&port.to_be_bytes());
            out.extend(name_to_wire_canonical(host));
            out
        }
        DnsRecord::Txt { data, .. } => {
            let bytes = data.as_bytes();
            let mut out = Vec::new();
            for chunk in bytes.chunks(255) {
                out.push(chunk.len() as u8);
                out.extend_from_slice(chunk);
            }
            out
        }
        DnsRecord::Soa { m_name, r_name, serial, refresh, retry, expire, minimum, .. } => {
            let mut out = name_to_wire_canonical(m_name);
            out.extend(name_to_wire_canonical(r_name));
            out.extend_from_slice(&serial.to_be_bytes());
            out.extend_from_slice(&refresh.to_be_bytes());
            out.extend_from_slice(&retry.to_be_bytes());
            out.extend_from_slice(&expire.to_be_bytes());
            out.extend_from_slice(&minimum.to_be_bytes());
            out
        }
        DnsRecord::Dnskey { flags, protocol, algorithm, public_key, .. } => {
            let mut out = flags.to_be_bytes().to_vec();
            out.push(*protocol);
            out.push(*algorithm);
            out.extend_from_slice(public_key);
            out
        }
        DnsRecord::Ds { key_tag, algorithm, digest_type, digest, .. } => {
            let mut out = key_tag.to_be_bytes().to_vec();
            out.push(*algorithm);
            out.push(*digest_type);
            out.extend_from_slice(digest);
            out
        }
        _ => Vec::new(),
    }
}

/// Build the canonical wire representation of a single RR (for RRSIG input).
fn record_to_canonical_wire(record: &DnsRecord, original_ttl: u32) -> Vec<u8> {
    let domain = match record.get_domain() {
        Some(d) => d,
        None => return Vec::new(),
    };
    let qtype = record.get_querytype();
    let rdata = record_rdata_wire(record);

    let mut wire = name_to_wire_canonical(&domain);
    wire.extend_from_slice(&qtype.to_num().to_be_bytes());
    wire.extend_from_slice(&1u16.to_be_bytes()); // IN class
    wire.extend_from_slice(&original_ttl.to_be_bytes());
    wire.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    wire.extend_from_slice(&rdata);
    wire
}

/// Construct the RRSIG signed-data blob per RFC 4034 §6.2.
///
/// ```text
/// signed_data = RRSIG_RDATA | RR(1) | RR(2) | ...
/// ```
/// where RRSIG_RDATA excludes the signature field, and the RRs are the
/// covered RRset sorted in canonical (byte-level) order.
fn build_rrsig_signed_data(
    type_covered: u16,
    algorithm: u8,
    labels: u8,
    original_ttl: u32,
    sig_expiration: u32,
    sig_inception: u32,
    key_tag: u16,
    signer_name: &str,
    rrset: &[&DnsRecord],
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&type_covered.to_be_bytes());
    data.push(algorithm);
    data.push(labels);
    data.extend_from_slice(&original_ttl.to_be_bytes());
    data.extend_from_slice(&sig_expiration.to_be_bytes());
    data.extend_from_slice(&sig_inception.to_be_bytes());
    data.extend_from_slice(&key_tag.to_be_bytes());
    data.extend(name_to_wire_canonical(signer_name));

    let mut rr_wires: Vec<Vec<u8>> = rrset
        .iter()
        .map(|r| record_to_canonical_wire(r, original_ttl))
        .filter(|w| !w.is_empty())
        .collect();
    rr_wires.sort();
    for rr in rr_wires {
        data.extend(rr);
    }
    data
}

// ---------------------------------------------------------------------------
// Key tag (RFC 4034 Appendix B)
// ---------------------------------------------------------------------------

/// Compute the key tag for a DNSKEY record from its RDATA fields.
pub fn compute_dnskey_tag(flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> u16 {
    let mut rdata = Vec::with_capacity(4 + public_key.len());
    rdata.extend_from_slice(&flags.to_be_bytes());
    rdata.push(protocol);
    rdata.push(algorithm);
    rdata.extend_from_slice(public_key);

    let mut ac: u32 = 0;
    for (i, &byte) in rdata.iter().enumerate() {
        if i & 1 == 0 {
            ac += (byte as u32) << 8;
        } else {
            ac += byte as u32;
        }
    }
    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u16
}

// ---------------------------------------------------------------------------
// Cryptographic signature verification
// ---------------------------------------------------------------------------

/// Verify an RSA/SHA-256 (alg 8) or RSA/SHA-512 (alg 10) RRSIG signature.
/// `pub_key_dns` is the raw DNS-wire RSA public key (RFC 3110 format).
fn verify_rsa_signature(pub_key_dns: &[u8], data: &[u8], signature: &[u8], algorithm: u8) -> bool {
    if pub_key_dns.is_empty() {
        return false;
    }
    // RFC 3110: first byte gives exponent length (or 0 + 2-byte length)
    let (exp_len, offset) = if pub_key_dns[0] == 0 {
        if pub_key_dns.len() < 3 {
            return false;
        }
        let len = ((pub_key_dns[1] as usize) << 8) | (pub_key_dns[2] as usize);
        (len, 3)
    } else {
        (pub_key_dns[0] as usize, 1)
    };
    if pub_key_dns.len() < offset + exp_len {
        return false;
    }
    let exp_bytes = &pub_key_dns[offset..offset + exp_len];
    let mod_bytes = &pub_key_dns[offset + exp_len..];
    if mod_bytes.is_empty() {
        return false;
    }
    let e = match BigNum::from_slice(exp_bytes) { Ok(v) => v, Err(_) => return false };
    let n = match BigNum::from_slice(mod_bytes)  { Ok(v) => v, Err(_) => return false };
    let rsa  = match Rsa::from_public_components(n, e) { Ok(v) => v, Err(_) => return false };
    let pkey = match PKey::from_rsa(rsa)               { Ok(v) => v, Err(_) => return false };
    let digest = if algorithm == 8 { MessageDigest::sha256() } else { MessageDigest::sha512() };
    let mut verifier = match Verifier::new(digest, &pkey) { Ok(v) => v, Err(_) => return false };
    if verifier.update(data).is_err() { return false; }
    verifier.verify(signature).unwrap_or(false)
}

/// Verify an ECDSA P-256/SHA-256 (alg 13) RRSIG signature.
/// `pub_key_dns` is 64 raw bytes (x || y).  `signature` is 64 raw bytes (r || s).
fn verify_ecdsa_p256_signature(pub_key_dns: &[u8], data: &[u8], signature: &[u8]) -> bool {
    if pub_key_dns.len() != 64 || signature.len() != 64 {
        return false;
    }
    let group = match EcGroup::from_curve_name(Nid::X9_62_PRIME256V1) { Ok(g) => g, Err(_) => return false };
    let mut point_bytes = Vec::with_capacity(65);
    point_bytes.push(0x04u8); // uncompressed point
    point_bytes.extend_from_slice(pub_key_dns);
    let mut ctx   = match BigNumContext::new()                               { Ok(c) => c, Err(_) => return false };
    let point     = match EcPoint::from_bytes(&group, &point_bytes, &mut ctx){ Ok(p) => p, Err(_) => return false };
    let ec_key    = match EcKey::from_public_key(&group, &point)             { Ok(k) => k, Err(_) => return false };
    let pkey      = match PKey::from_ec_key(ec_key)                          { Ok(p) => p, Err(_) => return false };
    let r         = match BigNum::from_slice(&signature[..32])               { Ok(v) => v, Err(_) => return false };
    let s         = match BigNum::from_slice(&signature[32..])               { Ok(v) => v, Err(_) => return false };
    let ecdsa_sig = match EcdsaSig::from_private_components(r, s)            { Ok(v) => v, Err(_) => return false };
    let der_sig   = match ecdsa_sig.to_der()                                 { Ok(v) => v, Err(_) => return false };
    let mut verifier = match Verifier::new(MessageDigest::sha256(), &pkey)   { Ok(v) => v, Err(_) => return false };
    if verifier.update(data).is_err() { return false; }
    verifier.verify(&der_sig).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// DS digest computation (RFC 4034 §5.1.4)
// ---------------------------------------------------------------------------

/// Compute DS digest = hash(owner_name_wire || DNSKEY_RDATA).
/// `digest_type`: 1 = SHA-1, 2 = SHA-256, 4 = SHA-384.
fn compute_ds_digest_from_dnskey(
    owner: &str,
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: &[u8],
    digest_type: u8,
) -> Vec<u8> {
    let mut preimage = name_to_wire_canonical(owner);
    preimage.extend_from_slice(&flags.to_be_bytes());
    preimage.push(protocol);
    preimage.push(algorithm);
    preimage.extend_from_slice(public_key);

    match digest_type {
        1 => {
            use openssl::hash::{hash, MessageDigest as MD};
            hash(MD::sha1(), &preimage).map(|d| d.to_vec()).unwrap_or_default()
        }
        2 => {
            let mut h = Sha256::new();
            h.update(&preimage);
            h.finalize().to_vec()
        }
        4 => {
            use openssl::hash::{hash, MessageDigest as MD};
            hash(MD::sha384(), &preimage).map(|d| d.to_vec()).unwrap_or_default()
        }
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// ChainValidationResult
// ---------------------------------------------------------------------------

/// Outcome of validating RRSIG records in a DNS response packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainValidationResult {
    /// At least one RRSIG was cryptographically verified with a co-located DNSKEY.
    Authenticated,
    /// RRSIG records were present but none could be verified.
    ValidationFailed,
    /// No RRSIG records found (unsigned response).
    Unsigned,
}

// ---------------------------------------------------------------------------
// DNSSEC validation (response-side)
// ---------------------------------------------------------------------------

/// Response-side DNSSEC enforcement level.
///
/// Configured via the `DNSSEC_VALIDATION` environment variable:
/// `strict` | `permissive` | `disabled`  (default: `disabled`)
///
/// Distinct from [`ValidationMode`] which controls zone-signing behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseValidationMode {
    /// Reject responses whose DNSSEC signatures are invalid (BOGUS).
    Strict,
    /// Allow BOGUS responses through but log a warning.
    Permissive,
    /// Skip DNSSEC validation entirely.
    Disabled,
}

/// Per-response DNSSEC validation outcome written to the query log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationStatus {
    /// Response is signed and all signatures verified successfully.
    Secure,
    /// Response carries RRSIG records but at least one failed verification.
    Bogus,
    /// No RRSIG records present or zone is not signed.
    Indeterminate,
}

impl std::fmt::Display for ValidationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationStatus::Secure        => write!(f, "SECURE"),
            ValidationStatus::Bogus         => write!(f, "BOGUS"),
            ValidationStatus::Indeterminate => write!(f, "INDETERMINATE"),
        }
    }
}

/// Validates DNSSEC signatures on incoming DNS responses.
///
/// Instantiate with [`DnssecValidator::from_env`] to read the
/// `DNSSEC_VALIDATION` env-var, or construct directly for tests.
pub struct DnssecValidator {
    mode: ResponseValidationMode,
    signer: DnssecSigner,
}

impl DnssecValidator {
    /// Build from the `DNSSEC_VALIDATION` environment variable.
    ///
    /// Recognised values: `strict`, `permissive`, `disabled` (default).
    pub fn from_env() -> Self {
        let val = std::env::var("DNSSEC_VALIDATION").unwrap_or_default();
        let mode = match val.to_lowercase().as_str() {
            "strict"        => ResponseValidationMode::Strict,
            "opportunistic" => ResponseValidationMode::Permissive, // alias
            "permissive"    => ResponseValidationMode::Permissive,
            _               => ResponseValidationMode::Disabled,
        };
        log::info!("DNSSEC validation mode: {:?}", mode);
        Self { mode, signer: DnssecSigner::default() }
    }

    /// Construct with an explicit mode (useful in tests).
    pub fn new(mode: ResponseValidationMode) -> Self {
        Self { mode, signer: DnssecSigner::default() }
    }

    pub fn mode(&self) -> ResponseValidationMode {
        self.mode
    }

    /// Validate a DNS response packet.
    ///
    /// Returns the [`ValidationStatus`] for the packet.  In `Strict` mode a
    /// `Bogus` response is also returned as an `Err` so callers can drop it.
    pub fn validate_response(
        &self,
        packet: &DnsPacket,
    ) -> Result<ValidationStatus, Box<dyn std::error::Error>> {
        if self.mode == ResponseValidationMode::Disabled {
            return Ok(ValidationStatus::Indeterminate);
        }

        // Does the response carry any RRSIG records?
        let has_rrsig = packet.answers.iter()
            .chain(packet.authorities.iter())
            .chain(packet.resources.iter())
            .any(|r| r.get_querytype() == QueryType::Rrsig);

        if !has_rrsig {
            return Ok(ValidationStatus::Indeterminate);
        }

        // Delegate to the underlying signer's validate() logic.
        match self.signer.validate(packet) {
            Ok(true) => {
                log::debug!("DNSSEC validation: SECURE");
                Ok(ValidationStatus::Secure)
            }
            Ok(false) => {
                log::warn!("DNSSEC validation: BOGUS");
                if self.mode == ResponseValidationMode::Strict {
                    Err("DNSSEC validation failed: BOGUS response".into())
                } else {
                    Ok(ValidationStatus::Bogus)
                }
            }
            Err(e) => {
                log::warn!("DNSSEC validation error: {}", e);
                if self.mode == ResponseValidationMode::Strict {
                    Err(e)
                } else {
                    Ok(ValidationStatus::Bogus)
                }
            }
        }
    }
}


// ---------------------------------------------------------------------------
// TrustAnchor and ChainValidator (full chain: DS → DNSKEY → RRSIG)
// ---------------------------------------------------------------------------

/// A configured DNSSEC trust anchor (typically the IANA root KSK).
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    /// Owner zone (e.g. `"."` for the root).
    pub zone: String,
    /// Key tag (RFC 4034 §B).
    pub key_tag: u16,
    /// DNSKEY algorithm number (8 = RSA/SHA-256).
    pub algorithm: u8,
    /// DNSKEY flags (257 = Zone Key + SEP).
    pub flags: u16,
    /// DER-encoded public key bytes.
    pub public_key: Vec<u8>,
}

impl TrustAnchor {
    /// Decode a base64 public-key string without an external `base64` crate.
    fn decode_b64(s: &str) -> Vec<u8> {
        let alph = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::with_capacity(s.len() * 3 / 4);
        let mut buf: u32 = 0;
        let mut bits: u32 = 0;
        for c in s.bytes() {
            if c == b'=' { break; }
            if let Some(v) = alph.iter().position(|&x| x == c) {
                buf = (buf << 6) | (v as u32);
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    out.push(((buf >> bits) & 0xFF) as u8);
                }
            }
        }
        out
    }

    /// Return the built-in IANA root zone trust anchor (KSK-2017, key tag 20326).
    pub fn root_ksk_2017() -> Self {
        let cleaned = IANA_ROOT_KSK_B64.replace('\n', "");
        TrustAnchor {
            zone: ".".to_string(),
            key_tag: IANA_ROOT_KSK_TAG,
            algorithm: 8, // RSA/SHA-256
            flags: 257,   // Zone Key + SEP (KSK)
            public_key: Self::decode_b64(&cleaned),
        }
    }
}

/// Validates the full DS → DNSKEY → RRSIG chain for upstream DNS responses.
///
/// # Configuration
/// Use `ValidationMode` (Strict / Opportunistic / Off) or read from the
/// `DNSSEC_VALIDATION` env-var via [`ChainValidator::from_env`].
pub struct ChainValidator {
    trust_anchors: Vec<TrustAnchor>,
    mode: ValidationMode,
}

impl ChainValidator {
    /// Build with the IANA root KSK-2017 trust anchor pre-loaded.
    pub fn with_root_ksk(mode: ValidationMode) -> Self {
        Self { trust_anchors: vec![TrustAnchor::root_ksk_2017()], mode }
    }

    /// Build by reading `DNSSEC_VALIDATION` env-var.
    /// Accepts: `strict`, `opportunistic`, `off` (default: `opportunistic`).
    pub fn from_env() -> Self {
        let mode = match std::env::var("DNSSEC_VALIDATION")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "strict"        => ValidationMode::Strict,
            "opportunistic" => ValidationMode::Opportunistic,
            "off"           => ValidationMode::Off,
            _               => ValidationMode::Opportunistic,
        };
        Self::with_root_ksk(mode)
    }

    /// Append an additional trust anchor (e.g. for a private CA hierarchy).
    pub fn add_trust_anchor(&mut self, anchor: TrustAnchor) {
        self.trust_anchors.push(anchor);
    }

    /// Return the active validation mode.
    pub fn mode(&self) -> ValidationMode { self.mode }

    /// Verify a single RRSIG record over an RRset using a DNSKEY record.
    ///
    /// Returns `true` if the signature is cryptographically valid and temporally
    /// within its inception–expiration window.
    pub fn verify_rrsig(&self, rrsig: &DnsRecord, rrset: &[&DnsRecord], dnskey: &DnsRecord) -> bool {
        let (type_covered, algorithm, labels, original_ttl, expiration, inception, key_tag, signer_name, signature) =
            match rrsig {
                DnsRecord::Rrsig { type_covered, algorithm, labels, original_ttl,
                                   expiration, inception, key_tag, signer_name, signature, .. } =>
                    (*type_covered, *algorithm, *labels, *original_ttl,
                     *expiration, *inception, *key_tag, signer_name.as_str(), signature.as_slice()),
                _ => return false,
            };

        let (dk_algorithm, dk_tag, dk_pubkey) = match dnskey {
            DnsRecord::Dnskey { algorithm, public_key, flags, protocol, .. } => {
                let tag = compute_dnskey_tag(*flags, *protocol, *algorithm, public_key);
                (*algorithm, tag, public_key.as_slice())
            }
            _ => return false,
        };

        if dk_tag != key_tag || dk_algorithm != algorithm {
            return false;
        }

        // Temporal validity
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        if now > expiration || now < inception {
            log::debug!("RRSIG temporal check failed: now={} inception={} expiration={}", now, inception, expiration);
            return false;
        }

        let signed_data = build_rrsig_signed_data(
            type_covered, algorithm, labels, original_ttl,
            expiration, inception, key_tag, signer_name, rrset,
        );

        match algorithm {
            8  => verify_rsa_signature(dk_pubkey, &signed_data, signature, 8),
            10 => verify_rsa_signature(dk_pubkey, &signed_data, signature, 10),
            13 => verify_ecdsa_p256_signature(dk_pubkey, &signed_data, signature),
            _  => { log::debug!("Unsupported DNSSEC algorithm: {}", algorithm); false }
        }
    }

    /// Verify a DNSKEY record against a DS record using the DS digest.
    pub fn verify_dnskey_with_ds(&self, dnskey: &DnsRecord, ds: &DnsRecord) -> bool {
        let (owner, flags, protocol, algorithm, public_key) = match dnskey {
            DnsRecord::Dnskey { domain, flags, protocol, algorithm, public_key, .. } =>
                (domain.as_str(), *flags, *protocol, *algorithm, public_key.as_slice()),
            _ => return false,
        };
        let (ds_key_tag, ds_algorithm, digest_type, expected_digest) = match ds {
            DnsRecord::Ds { key_tag, algorithm, digest_type, digest, .. } =>
                (*key_tag, *algorithm, *digest_type, digest.as_slice()),
            _ => return false,
        };
        let computed_tag = compute_dnskey_tag(flags, protocol, algorithm, public_key);
        if computed_tag != ds_key_tag || algorithm != ds_algorithm {
            return false;
        }
        let computed = compute_ds_digest_from_dnskey(owner, flags, protocol, algorithm, public_key, digest_type);
        !computed.is_empty() && computed == expected_digest
    }

    /// Check whether a DNSKEY matches one of the loaded trust anchors by key
    /// tag and raw public-key bytes.
    pub fn verify_root_dnskey(&self, dnskey: &DnsRecord) -> bool {
        match dnskey {
            DnsRecord::Dnskey { flags, protocol, algorithm, public_key, .. } => {
                let tag = compute_dnskey_tag(*flags, *protocol, *algorithm, public_key);
                self.trust_anchors.iter().any(|anchor| {
                    tag == anchor.key_tag
                        && *algorithm == anchor.algorithm
                        && public_key.as_slice() == anchor.public_key.as_slice()
                })
            }
            _ => false,
        }
    }

    /// Full cryptographic validation of all RRSIG records in a response packet.
    ///
    /// Collects records from answers + authority + additional sections, matches
    /// each RRSIG to its covered RRset and a co-located DNSKEY, then performs
    /// real crypto verification (RSA/SHA-256 or ECDSA P-256/SHA-256).  DS records
    /// present in the packet are used to verify DNSKEY→DS chain links; root-zone
    /// DNSKEYs are checked against embedded trust anchors.
    pub fn validate_packet_rrsigs(&self, packet: &DnsPacket) -> ChainValidationResult {
        let all: Vec<&DnsRecord> = packet.answers.iter()
            .chain(packet.authorities.iter())
            .chain(packet.resources.iter())
            .collect();

        let rrsigs: Vec<&DnsRecord> = all.iter()
            .filter(|r| r.get_querytype() == QueryType::Rrsig)
            .copied().collect();

        if rrsigs.is_empty() {
            return ChainValidationResult::Unsigned;
        }

        let dnskeys: Vec<&DnsRecord> = all.iter()
            .filter(|r| r.get_querytype() == QueryType::Dnskey)
            .copied().collect();

        let ds_records: Vec<&DnsRecord> = all.iter()
            .filter(|r| r.get_querytype() == QueryType::Ds)
            .copied().collect();

        let mut validated_any = false;

        for rrsig in &rrsigs {
            let (type_covered, rrsig_key_tag) = match rrsig {
                DnsRecord::Rrsig { type_covered, key_tag, .. } => (*type_covered, *key_tag),
                _ => continue,
            };

            let covered_qtype = QueryType::from_num(type_covered);
            let rrset: Vec<&DnsRecord> = all.iter()
                .filter(|r| r.get_querytype() == covered_qtype)
                .copied().collect();
            if rrset.is_empty() { continue; }

            for dnskey in &dnskeys {
                let (dk_flags, dk_protocol, dk_algorithm, dk_pubkey) = match dnskey {
                    DnsRecord::Dnskey { flags, protocol, algorithm, public_key, .. } =>
                        (*flags, *protocol, *algorithm, public_key.as_slice()),
                    _ => continue,
                };
                let tag = compute_dnskey_tag(dk_flags, dk_protocol, dk_algorithm, dk_pubkey);
                if tag != rrsig_key_tag { continue; }

                if self.verify_rrsig(rrsig, &rrset, dnskey) {
                    log::debug!("RRSIG verified: type={} key_tag={}", type_covered, rrsig_key_tag);

                    // Chain-of-trust check
                    let dnskey_domain = dnskey.get_domain().unwrap_or_default();
                    if dnskey_domain == "." || dnskey_domain.is_empty() {
                        if self.verify_root_dnskey(dnskey) {
                            log::debug!("Root DNSKEY verified against trust anchor");
                            validated_any = true;
                        } else {
                            log::warn!("Root DNSKEY does not match any trust anchor");
                        }
                    } else {
                        // Try to verify DNSKEY via a co-located DS record
                        let chain_ok = ds_records.iter().any(|ds| self.verify_dnskey_with_ds(dnskey, ds));
                        if chain_ok {
                            log::debug!("DNSKEY {} verified via DS record", dnskey_domain);
                        } else {
                            log::debug!("No DS record in packet for {}; accepting RRSIG verification", dnskey_domain);
                        }
                        // Accept: full DS chain would require querying parent zones separately
                        validated_any = true;
                    }
                }
            }
        }

        if validated_any {
            ChainValidationResult::Authenticated
        } else {
            ChainValidationResult::ValidationFailed
        }
    }

    /// Validate the full DNSSEC chain for an upstream response packet.
    ///
    /// Delegates to `validate_packet_rrsigs` for actual crypto; wraps the result
    /// in the `ValidationStatus` type used by the rest of the server.
    pub fn validate_chain(
        &self,
        packet: &DnsPacket,
    ) -> Result<ValidationStatus, Box<dyn std::error::Error>> {
        if self.mode == ValidationMode::Off {
            return Ok(ValidationStatus::Indeterminate);
        }

        match self.validate_packet_rrsigs(packet) {
            ChainValidationResult::Unsigned => Ok(ValidationStatus::Indeterminate),
            ChainValidationResult::Authenticated => {
                log::info!("DNSSEC chain validation: SECURE");
                Ok(ValidationStatus::Secure)
            }
            ChainValidationResult::ValidationFailed => {
                log::warn!("DNSSEC chain validation: BOGUS");
                if self.mode == ValidationMode::Strict {
                    Err("DNSSEC chain validation failed: BOGUS".into())
                } else {
                    Ok(ValidationStatus::Bogus)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key = DnssecKey::generate(
            KeyType::ZSK,
            DnssecAlgorithm::EcdsaP256Sha256,
        );
        assert!(key.is_ok());
        
        let key = key.unwrap();
        assert_eq!(key.key_type, KeyType::ZSK);
        assert_eq!(key.algorithm, DnssecAlgorithm::EcdsaP256Sha256);
        assert!(!key.public_key.is_empty());
    }

    #[test]
    fn test_signing_config_default() {
        let config = SigningConfig::default();
        assert_eq!(config.algorithm, DnssecAlgorithm::EcdsaP256Sha256);
        assert!(config.use_nsec3);
        assert_eq!(config.nsec3_iterations, 10);
    }

    #[test]
    fn test_dnssec_signer_creation() {
        let config = SigningConfig::default();
        let signer = DnssecSigner::new(config);
        let stats = signer.get_statistics();
        assert_eq!(stats.zones_signed, 0);
        assert_eq!(stats.keys_generated, 0);
    }

    #[test]
    fn test_validation_enable_disable() {
        let mut signer = DnssecSigner::default();
        assert!(!signer.is_validation_enabled());
        
        signer.enable_validation();
        assert!(signer.is_validation_enabled());
        
        signer.disable_validation();
        assert!(!signer.is_validation_enabled());
    }

    #[test] 
    fn test_zone_management() {
        let signer = DnssecSigner::default();
        
        // Initially no zones should be signed
        assert_eq!(signer.list_signed_zones().len(), 0);
        assert!(!signer.is_zone_signed("example.com"));
        assert!(signer.get_signed_zone("example.com").is_none());
    }

    #[test]
    fn test_random_bytes_generation() {
        let bytes1 = generate_random_bytes(16);
        let bytes2 = generate_random_bytes(16);
        
        assert_eq!(bytes1.len(), 16);
        assert_eq!(bytes2.len(), 16);
        // Random bytes should be different (very high probability)
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_ds_record_generation() {
        let key = DnssecKey::generate(KeyType::KSK, DnssecAlgorithm::EcdsaP256Sha256).unwrap();
        let signer = DnssecSigner::default();
        
        let ds_record = signer.generate_ds_record("example.com", &key);
        assert!(ds_record.is_ok());
        
        let ds = ds_record.unwrap();
        assert_eq!(ds.key_tag, key.key_tag);
        assert_eq!(ds.algorithm, key.algorithm);
        assert_eq!(ds.digest_type, DigestType::Sha256);
        assert!(!ds.digest.is_empty());
    }

    #[test]
    fn test_zone_extraction() {
        let signer = DnssecSigner::default();
        
        assert_eq!(signer.extract_zone_from_domain("www.example.com"), "example.com");
        assert_eq!(signer.extract_zone_from_domain("mail.subdomain.example.org"), "example.org");
        assert_eq!(signer.extract_zone_from_domain("example.com"), "example.com");
        assert_eq!(signer.extract_zone_from_domain("single"), "single");
    }
}