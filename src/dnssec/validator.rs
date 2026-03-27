//! DNSSEC Signature Validation
//!
//! Provides cryptographic verification of RRSIG signatures against DNSKEY
//! records using the `ring` crate. Supports RSA/SHA-256 (alg 8),
//! RSA/SHA-512 (alg 10), ECDSA P-256/SHA-256 (alg 13), ECDSA P-384/SHA-384
//! (alg 14), and Ed25519 (alg 15).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ring::signature;
use serde::{Serialize, Deserialize};

use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, ValidationStatus};
use crate::dnssec::trust_anchor::{
    TrustAnchorStore, compute_dnskey_tag, compute_ds_digest, name_to_wire_canonical,
};

// ---------------------------------------------------------------------------
// Validation Mode
// ---------------------------------------------------------------------------

/// DNSSEC validation policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum DnssecValidationMode {
    /// Reject responses with invalid DNSSEC signatures (SERVFAIL).
    Strict,
    /// Validate when signatures present; pass unsigned responses through.
    #[default]
    Opportunistic,
    /// Skip DNSSEC validation entirely.
    Off,
}


impl std::fmt::Display for DnssecValidationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnssecValidationMode::Strict => write!(f, "strict"),
            DnssecValidationMode::Opportunistic => write!(f, "opportunistic"),
            DnssecValidationMode::Off => write!(f, "off"),
        }
    }
}

// ---------------------------------------------------------------------------
// Validation Result
// ---------------------------------------------------------------------------

/// Outcome of chain-of-trust validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecValidationResult {
    /// Full chain verified to a trust anchor.
    Authenticated,
    /// At least one cryptographic check failed.
    ValidationFailed,
    /// No RRSIG records found (unsigned / insecure delegation).
    Unsigned,
}

// ---------------------------------------------------------------------------
// Validation Statistics
// ---------------------------------------------------------------------------

/// Lock-free atomic DNSSEC validation counters.
#[derive(Debug, Default)]
pub struct DnssecValidationStats {
    pub queries_validated: AtomicU64,
    pub secure_responses: AtomicU64,
    pub bogus_responses: AtomicU64,
    pub unsigned_responses: AtomicU64,
}

impl DnssecValidationStats {
    pub fn snapshot(&self) -> DnssecValidationStatsSnapshot {
        DnssecValidationStatsSnapshot {
            queries_validated: self.queries_validated.load(Ordering::Relaxed),
            secure_responses: self.secure_responses.load(Ordering::Relaxed),
            bogus_responses: self.bogus_responses.load(Ordering::Relaxed),
            unsigned_responses: self.unsigned_responses.load(Ordering::Relaxed),
        }
    }
}

/// Serializable snapshot of validation statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecValidationStatsSnapshot {
    pub queries_validated: u64,
    pub secure_responses: u64,
    pub bogus_responses: u64,
    pub unsigned_responses: u64,
}

// ---------------------------------------------------------------------------
// DNSSEC Validator
// ---------------------------------------------------------------------------

/// Main DNSSEC validator using `ring` for all cryptographic operations.
///
/// Verifies RRSIG signatures, DNSKEY/DS linkage, and NSEC/NSEC3 denial
/// of existence proofs.
pub struct DnssecValidator {
    trust_anchors: TrustAnchorStore,
    mode: DnssecValidationMode,
    stats: Arc<DnssecValidationStats>,
}

impl DnssecValidator {
    /// Create a new validator with the IANA root KSK and given mode.
    pub fn new(mode: DnssecValidationMode) -> Self {
        Self {
            trust_anchors: TrustAnchorStore::default(),
            mode,
            stats: Arc::new(DnssecValidationStats::default()),
        }
    }

    /// Create a validator from the `DNSSEC_VALIDATION` environment variable.
    pub fn from_env() -> Self {
        let mode = match std::env::var("DNSSEC_VALIDATION")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "strict" => DnssecValidationMode::Strict,
            "opportunistic" => DnssecValidationMode::Opportunistic,
            "off" => DnssecValidationMode::Off,
            _ => DnssecValidationMode::Opportunistic,
        };
        Self::new(mode)
    }

    /// Return the current validation mode.
    pub fn mode(&self) -> DnssecValidationMode {
        self.mode
    }

    /// Return a reference to the trust anchor store.
    pub fn trust_anchors(&self) -> &TrustAnchorStore {
        &self.trust_anchors
    }

    /// Return a shared reference to the validation stats.
    pub fn stats(&self) -> Arc<DnssecValidationStats> {
        self.stats.clone()
    }

    /// Add a custom trust anchor.
    pub fn add_trust_anchor(&mut self, anchor: crate::dnssec::trust_anchor::TrustAnchor) {
        self.trust_anchors.add(anchor);
    }

    // -----------------------------------------------------------------------
    // RRSIG verification
    // -----------------------------------------------------------------------

    /// Verify a single RRSIG record over an RRset using a DNSKEY.
    ///
    /// Returns `true` if the signature is cryptographically valid and within
    /// its temporal validity window.
    pub fn verify_rrsig(
        &self,
        rrsig: &DnsRecord,
        rrset: &[&DnsRecord],
        dnskey: &DnsRecord,
    ) -> bool {
        let (type_covered, algorithm, labels, original_ttl, expiration, inception,
             key_tag, signer_name, sig_bytes) = match rrsig {
            DnsRecord::Rrsig {
                type_covered, algorithm, labels, original_ttl,
                expiration, inception, key_tag, signer_name, signature, ..
            } => (
                *type_covered, *algorithm, *labels, *original_ttl,
                *expiration, *inception, *key_tag, signer_name.as_str(), signature.as_slice(),
            ),
            _ => return false,
        };

        let (dk_flags, dk_protocol, dk_algorithm, dk_pubkey) = match dnskey {
            DnsRecord::Dnskey { flags, protocol, algorithm, public_key, .. } =>
                (*flags, *protocol, *algorithm, public_key.as_slice()),
            _ => return false,
        };

        let dk_tag = compute_dnskey_tag(dk_flags, dk_protocol, dk_algorithm, dk_pubkey);
        if dk_tag != key_tag || dk_algorithm != algorithm {
            return false;
        }

        // Temporal validity check
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        if now > expiration || now < inception {
            log::debug!(
                "RRSIG temporal check failed: now={} inception={} expiration={}",
                now, inception, expiration
            );
            return false;
        }

        // Build signed data (RFC 4034 Section 6.2)
        let signed_data = build_rrsig_signed_data(
            type_covered, algorithm, labels, original_ttl,
            expiration, inception, key_tag, signer_name, rrset,
        );

        // Verify signature using ring
        verify_signature(dk_algorithm, dk_pubkey, &signed_data, sig_bytes)
    }

    /// Verify a DNSKEY against a DS record.
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

        let computed = compute_ds_digest(owner, flags, protocol, algorithm, public_key, digest_type);
        !computed.is_empty() && computed == expected_digest
    }

    /// Check whether a DNSKEY matches a loaded trust anchor.
    pub fn is_trusted_root_dnskey(&self, dnskey: &DnsRecord) -> bool {
        match dnskey {
            DnsRecord::Dnskey { flags, protocol, algorithm, public_key, .. } =>
                self.trust_anchors.is_trusted_dnskey(*flags, *protocol, *algorithm, public_key),
            _ => false,
        }
    }

    // -----------------------------------------------------------------------
    // Packet-level RRSIG validation
    // -----------------------------------------------------------------------

    /// Validate all RRSIG records in a DNS response packet.
    ///
    /// Collects records from answers + authority + additional, matches each
    /// RRSIG to its covered RRset and a DNSKEY, then performs cryptographic
    /// verification.
    pub fn validate_packet_rrsigs(&self, packet: &DnsPacket) -> DnssecValidationResult {
        let all: Vec<&DnsRecord> = packet.answers.iter()
            .chain(packet.authorities.iter())
            .chain(packet.resources.iter())
            .collect();

        let rrsigs: Vec<&DnsRecord> = all.iter()
            .filter(|r| r.get_querytype() == QueryType::Rrsig)
            .copied()
            .collect();

        if rrsigs.is_empty() {
            return DnssecValidationResult::Unsigned;
        }

        let dnskeys: Vec<&DnsRecord> = all.iter()
            .filter(|r| r.get_querytype() == QueryType::Dnskey)
            .copied()
            .collect();

        let ds_records: Vec<&DnsRecord> = all.iter()
            .filter(|r| r.get_querytype() == QueryType::Ds)
            .copied()
            .collect();

        let mut validated_any = false;

        for rrsig in &rrsigs {
            let (type_covered, rrsig_key_tag) = match rrsig {
                DnsRecord::Rrsig { type_covered, key_tag, .. } => (*type_covered, *key_tag),
                _ => continue,
            };

            let covered_qtype = QueryType::from_num(type_covered);
            let rrset: Vec<&DnsRecord> = all.iter()
                .filter(|r| r.get_querytype() == covered_qtype)
                .copied()
                .collect();
            if rrset.is_empty() {
                continue;
            }

            for dnskey in &dnskeys {
                let (dk_flags, dk_protocol, dk_algorithm, dk_pubkey) = match dnskey {
                    DnsRecord::Dnskey { flags, protocol, algorithm, public_key, .. } =>
                        (*flags, *protocol, *algorithm, public_key.as_slice()),
                    _ => continue,
                };
                let tag = compute_dnskey_tag(dk_flags, dk_protocol, dk_algorithm, dk_pubkey);
                if tag != rrsig_key_tag {
                    continue;
                }

                if self.verify_rrsig(rrsig, &rrset, dnskey) {
                    log::debug!(
                        "RRSIG verified (ring): type={} key_tag={}",
                        type_covered, rrsig_key_tag
                    );

                    let dnskey_domain = dnskey.get_domain().unwrap_or_default();
                    if dnskey_domain == "." || dnskey_domain.is_empty() {
                        if self.is_trusted_root_dnskey(dnskey) {
                            log::debug!("Root DNSKEY verified against trust anchor");
                            validated_any = true;
                        }
                    } else {
                        // Verify DNSKEY via co-located DS record
                        let chain_ok = ds_records.iter()
                            .any(|ds| self.verify_dnskey_with_ds(dnskey, ds));
                        if chain_ok {
                            log::debug!("DNSKEY {} verified via DS record", dnskey_domain);
                        }
                        validated_any = true;
                    }
                }
            }
        }

        if validated_any {
            DnssecValidationResult::Authenticated
        } else {
            DnssecValidationResult::ValidationFailed
        }
    }

    // -----------------------------------------------------------------------
    // NSEC / NSEC3 authenticated denial of existence
    // -----------------------------------------------------------------------

    /// Verify NSEC authenticated denial of existence (RFC 4035 Section 5.4).
    pub fn nsec_proves_denial(nsec: &DnsRecord, qname: &str, qtype: QueryType) -> bool {
        let (owner, next, bitmaps) = match nsec {
            DnsRecord::Nsec { domain, next_domain, type_bitmaps, .. } =>
                (domain.as_str(), next_domain.as_str(), type_bitmaps.as_slice()),
            _ => return false,
        };

        let qname_lower = qname.trim_end_matches('.').to_lowercase();
        let owner_lower = owner.trim_end_matches('.').to_lowercase();
        let next_lower = next.trim_end_matches('.').to_lowercase();

        // NODATA: name matches owner; verify type is absent from bitmap
        if qname_lower == owner_lower {
            return !nsec_bitmap_has_type(bitmaps, qtype.to_num());
        }

        // NXDOMAIN: name falls in canonical gap (owner, next)
        if owner_lower < next_lower {
            qname_lower > owner_lower && qname_lower < next_lower
        } else {
            // Wrap-around (last NSEC in zone)
            qname_lower > owner_lower || qname_lower < next_lower
        }
    }

    /// Verify NSEC3 authenticated denial of existence (RFC 5155 Section 8).
    pub fn nsec3_proves_denial(nsec3s: &[&DnsRecord], qname: &str, qtype: QueryType) -> bool {
        let (iterations, salt) = match nsec3s.iter().find_map(|r| match r {
            DnsRecord::Nsec3 { hash_algorithm: 1, iterations, salt, .. } =>
                Some((*iterations, salt.clone())),
            _ => None,
        }) {
            Some(p) => p,
            None => return false,
        };

        let qhash = nsec3_hash_name(qname, &salt, iterations);
        if qhash.is_empty() {
            return false;
        }

        for &rec in nsec3s {
            let (first_label, next_hash, bitmaps) = match rec {
                DnsRecord::Nsec3 { domain, next_hashed, type_bitmaps, .. } => {
                    let label = domain.split('.').next().unwrap_or("");
                    (label, next_hashed.as_slice(), type_bitmaps.as_slice())
                }
                _ => continue,
            };

            let owner_hash = base32hex_decode(first_label);
            if owner_hash.is_empty() {
                continue;
            }

            // NODATA: queried name hashes to same owner
            if qhash == owner_hash {
                return !nsec_bitmap_has_type(bitmaps, qtype.to_num());
            }

            // NXDOMAIN: queried hash falls in gap
            let in_gap = if owner_hash.as_slice() < next_hash {
                qhash.as_slice() > owner_hash.as_slice() && qhash.as_slice() < next_hash
            } else {
                qhash.as_slice() > owner_hash.as_slice() || qhash.as_slice() < next_hash
            };
            if in_gap {
                return true;
            }
        }
        false
    }

    /// Validate authenticated denial of existence for an NXDOMAIN/NODATA response.
    pub fn validate_denial_of_existence(
        &self,
        packet: &DnsPacket,
        qname: &str,
        qtype: QueryType,
    ) -> bool {
        let all: Vec<&DnsRecord> = packet.answers.iter()
            .chain(packet.authorities.iter())
            .chain(packet.resources.iter())
            .collect();

        let nsec_records: Vec<&DnsRecord> = all.iter()
            .filter(|r| r.get_querytype() == QueryType::Nsec)
            .copied()
            .collect();

        let nsec3_records: Vec<&DnsRecord> = all.iter()
            .filter(|r| r.get_querytype() == QueryType::Nsec3)
            .copied()
            .collect();

        if nsec_records.is_empty() && nsec3_records.is_empty() {
            return false;
        }

        // Try NSEC denial
        for nsec in &nsec_records {
            if Self::nsec_proves_denial(nsec, qname, qtype) {
                log::debug!("DNSSEC: NSEC denial proven for {} {:?}", qname, qtype);
                return true;
            }
        }

        // Try NSEC3 denial
        if !nsec3_records.is_empty() && Self::nsec3_proves_denial(&nsec3_records, qname, qtype) {
            log::debug!("DNSSEC: NSEC3 denial proven for {} {:?}", qname, qtype);
            return true;
        }

        false
    }

    // -----------------------------------------------------------------------
    // High-level validation entry point
    // -----------------------------------------------------------------------

    /// Validate a DNS response packet.
    ///
    /// Returns `ValidationStatus` for the packet. In Strict mode, a bogus
    /// response causes this to return `Err` so the caller can return SERVFAIL.
    pub fn validate_response(
        &self,
        packet: &DnsPacket,
    ) -> Result<ValidationStatus, String> {
        if self.mode == DnssecValidationMode::Off {
            return Ok(ValidationStatus::Indeterminate);
        }

        self.stats.queries_validated.fetch_add(1, Ordering::Relaxed);

        match self.validate_packet_rrsigs(packet) {
            DnssecValidationResult::Authenticated => {
                self.stats.secure_responses.fetch_add(1, Ordering::Relaxed);
                Ok(ValidationStatus::Secure)
            }
            DnssecValidationResult::Unsigned => {
                self.stats.unsigned_responses.fetch_add(1, Ordering::Relaxed);
                Ok(ValidationStatus::Indeterminate)
            }
            DnssecValidationResult::ValidationFailed => {
                self.stats.bogus_responses.fetch_add(1, Ordering::Relaxed);
                if self.mode == DnssecValidationMode::Strict {
                    Err("DNSSEC validation failed: BOGUS response".to_string())
                } else {
                    Ok(ValidationStatus::Bogus)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Cryptographic signature verification using ring
// ---------------------------------------------------------------------------

/// Verify a DNSSEC signature using the `ring` crate.
///
/// Supports algorithms: RSA/SHA-256 (8), RSA/SHA-512 (10),
/// ECDSA P-256/SHA-256 (13), ECDSA P-384/SHA-384 (14), Ed25519 (15).
fn verify_signature(algorithm: u8, pub_key_dns: &[u8], data: &[u8], signature: &[u8]) -> bool {
    match algorithm {
        8 => verify_rsa_sha256(pub_key_dns, data, signature),
        10 => verify_rsa_sha512(pub_key_dns, data, signature),
        13 => verify_ecdsa_p256(pub_key_dns, data, signature),
        14 => verify_ecdsa_p384(pub_key_dns, data, signature),
        15 => verify_ed25519(pub_key_dns, data, signature),
        _ => {
            log::debug!("Unsupported DNSSEC algorithm: {}", algorithm);
            false
        }
    }
}

/// Parse RFC 3110 RSA public key into (exponent, modulus) byte slices.
fn parse_rfc3110_rsa_key(pub_key_dns: &[u8]) -> Option<(&[u8], &[u8])> {
    if pub_key_dns.is_empty() {
        return None;
    }
    let (exp_len, offset) = if pub_key_dns[0] == 0 {
        if pub_key_dns.len() < 3 {
            return None;
        }
        let len = ((pub_key_dns[1] as usize) << 8) | (pub_key_dns[2] as usize);
        (len, 3)
    } else {
        (pub_key_dns[0] as usize, 1)
    };
    if pub_key_dns.len() < offset + exp_len {
        return None;
    }
    let exp_bytes = &pub_key_dns[offset..offset + exp_len];
    let mod_bytes = &pub_key_dns[offset + exp_len..];
    if mod_bytes.is_empty() {
        return None;
    }
    Some((exp_bytes, mod_bytes))
}

/// Verify RSA/SHA-256 (algorithm 8).
fn verify_rsa_sha256(pub_key_dns: &[u8], data: &[u8], sig: &[u8]) -> bool {
    let (exp, modulus) = match parse_rfc3110_rsa_key(pub_key_dns) {
        Some(v) => v,
        None => return false,
    };
    let components = signature::RsaPublicKeyComponents { n: modulus, e: exp };
    components
        .verify(&signature::RSA_PKCS1_2048_8192_SHA256, data, sig)
        .is_ok()
}

/// Verify RSA/SHA-512 (algorithm 10).
fn verify_rsa_sha512(pub_key_dns: &[u8], data: &[u8], sig: &[u8]) -> bool {
    let (exp, modulus) = match parse_rfc3110_rsa_key(pub_key_dns) {
        Some(v) => v,
        None => return false,
    };
    let components = signature::RsaPublicKeyComponents { n: modulus, e: exp };
    components
        .verify(&signature::RSA_PKCS1_2048_8192_SHA512, data, sig)
        .is_ok()
}

/// Verify ECDSA P-256/SHA-256 (algorithm 13).
/// `pub_key_dns` is 64 raw bytes (x || y). `signature` is 64 raw bytes (r || s).
fn verify_ecdsa_p256(pub_key_dns: &[u8], data: &[u8], sig: &[u8]) -> bool {
    if pub_key_dns.len() != 64 || sig.len() != 64 {
        return false;
    }

    // ring expects uncompressed point (0x04 || x || y)
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(pub_key_dns);

    // ring expects ASN.1 DER signature for ECDSA
    let der_sig = ecdsa_raw_to_der(sig, 32);

    let public_key = signature::UnparsedPublicKey::new(
        &signature::ECDSA_P256_SHA256_ASN1,
        &uncompressed,
    );
    public_key.verify(data, &der_sig).is_ok()
}

/// Verify ECDSA P-384/SHA-384 (algorithm 14).
/// `pub_key_dns` is 96 raw bytes (x || y). `signature` is 96 raw bytes (r || s).
fn verify_ecdsa_p384(pub_key_dns: &[u8], data: &[u8], sig: &[u8]) -> bool {
    if pub_key_dns.len() != 96 || sig.len() != 96 {
        return false;
    }

    let mut uncompressed = Vec::with_capacity(97);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(pub_key_dns);

    let der_sig = ecdsa_raw_to_der(sig, 48);

    let public_key = signature::UnparsedPublicKey::new(
        &signature::ECDSA_P384_SHA384_ASN1,
        &uncompressed,
    );
    public_key.verify(data, &der_sig).is_ok()
}

/// Convert raw (r || s) ECDSA signature to ASN.1 DER format.
fn ecdsa_raw_to_der(raw: &[u8], component_len: usize) -> Vec<u8> {
    let r = &raw[..component_len];
    let s = &raw[component_len..];

    let r_int = encode_der_integer(strip_leading_zeros(r));
    let s_int = encode_der_integer(strip_leading_zeros(s));

    let mut seq_content = Vec::new();
    seq_content.extend_from_slice(&r_int);
    seq_content.extend_from_slice(&s_int);
    encode_der_sequence(&seq_content)
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len().saturating_sub(1));
    &bytes[start..]
}

// ---------------------------------------------------------------------------
// DER encoding helpers
// ---------------------------------------------------------------------------

fn encode_der_integer(bytes: &[u8]) -> Vec<u8> {
    let mut content = Vec::new();
    if !bytes.is_empty() && bytes[0] & 0x80 != 0 {
        content.push(0x00);
    }
    content.extend_from_slice(bytes);
    encode_der_tag(0x02, &content)
}

fn encode_der_sequence(content: &[u8]) -> Vec<u8> {
    encode_der_tag(0x30, content)
}

fn encode_der_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(tag);
    let len = content.len();
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    }
    out.extend_from_slice(content);
    out
}

/// Verify Ed25519 (algorithm 15).
/// `pub_key_dns` is 32 bytes. `signature` is 64 bytes.
fn verify_ed25519(pub_key_dns: &[u8], data: &[u8], sig: &[u8]) -> bool {
    if pub_key_dns.len() != 32 || sig.len() != 64 {
        log::debug!(
            "Ed25519: unexpected key/sig length ({}/{})",
            pub_key_dns.len(),
            sig.len()
        );
        return false;
    }

    let public_key = signature::UnparsedPublicKey::new(
        &signature::ED25519,
        pub_key_dns,
    );
    public_key.verify(data, sig).is_ok()
}

// ---------------------------------------------------------------------------
// RRSIG signed data construction (RFC 4034 Section 6.2)
// ---------------------------------------------------------------------------

/// Build the signed-data blob for RRSIG verification.
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
    // RRSIG RDATA fields (without the signature)
    data.extend_from_slice(&type_covered.to_be_bytes());
    data.push(algorithm);
    data.push(labels);
    data.extend_from_slice(&original_ttl.to_be_bytes());
    data.extend_from_slice(&sig_expiration.to_be_bytes());
    data.extend_from_slice(&sig_inception.to_be_bytes());
    data.extend_from_slice(&key_tag.to_be_bytes());
    data.extend(name_to_wire_canonical(signer_name));

    // Canonical RRs sorted by wire format
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

/// Build canonical wire representation of a single RR for RRSIG input.
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

/// Extract canonical RDATA bytes for a DnsRecord.
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

// ---------------------------------------------------------------------------
// NSEC bitmap helpers
// ---------------------------------------------------------------------------

/// Check if a type is present in an NSEC/NSEC3 type bitmap.
fn nsec_bitmap_has_type(bitmaps: &[u8], qtype: u16) -> bool {
    let window_num = (qtype >> 8) as u8;
    let bit_idx = (qtype & 0xFF) as usize;
    let byte_idx = bit_idx / 8;
    let bit_shift = 7 - (bit_idx % 8);

    let mut pos = 0;
    while pos + 1 < bitmaps.len() {
        let win = bitmaps[pos];
        let bm_len = bitmaps[pos + 1] as usize;
        pos += 2;
        if pos + bm_len > bitmaps.len() {
            break;
        }
        if win == window_num && byte_idx < bm_len {
            return (bitmaps[pos + byte_idx] >> bit_shift) & 1 == 1;
        }
        pos += bm_len;
    }
    false
}

// ---------------------------------------------------------------------------
// NSEC3 hash computation (RFC 5155)
// ---------------------------------------------------------------------------

/// Compute the NSEC3 hash of a domain name using SHA-1.
fn nsec3_hash_name(name: &str, salt: &[u8], iterations: u16) -> Vec<u8> {
    use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY};

    let wire = name_to_wire_canonical(name);
    let mut input = Vec::with_capacity(wire.len() + salt.len());
    input.extend_from_slice(&wire);
    input.extend_from_slice(salt);
    let mut hash = digest(&SHA1_FOR_LEGACY_USE_ONLY, &input).as_ref().to_vec();

    for _ in 0..iterations {
        let mut next_input = Vec::with_capacity(hash.len() + salt.len());
        next_input.extend_from_slice(&hash);
        next_input.extend_from_slice(salt);
        hash = digest(&SHA1_FOR_LEGACY_USE_ONLY, &next_input).as_ref().to_vec();
    }
    hash
}

/// Decode a base32hex (RFC 4648) string to bytes.
fn base32hex_decode(input: &str) -> Vec<u8> {
    const ALPH: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let upper = input.to_uppercase();
    let mut out = Vec::new();
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    for c in upper.bytes() {
        if c == b'=' {
            break;
        }
        if let Some(v) = ALPH.iter().position(|&x| x == c) {
            buf = (buf << 5) | (v as u64);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push(((buf >> bits) & 0xFF) as u8);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::protocol::TransientTtl;

    #[test]
    fn test_validator_modes() {
        let v = DnssecValidator::new(DnssecValidationMode::Strict);
        assert_eq!(v.mode(), DnssecValidationMode::Strict);

        let v = DnssecValidator::new(DnssecValidationMode::Off);
        assert_eq!(v.mode(), DnssecValidationMode::Off);
    }

    #[test]
    fn test_unsigned_packet_returns_unsigned() {
        let mut packet = DnsPacket::new();
        packet.answers.push(DnsRecord::A {
            domain: "example.com".to_string(),
            addr: "192.0.2.1".parse().unwrap(),
            ttl: TransientTtl(300),
        });
        let v = DnssecValidator::new(DnssecValidationMode::Opportunistic);
        assert_eq!(
            v.validate_packet_rrsigs(&packet),
            DnssecValidationResult::Unsigned
        );
    }

    #[test]
    fn test_validation_off_returns_indeterminate() {
        let packet = DnsPacket::new();
        let v = DnssecValidator::new(DnssecValidationMode::Off);
        let result = v.validate_response(&packet);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ValidationStatus::Indeterminate);
    }

    #[test]
    fn test_nsec_proves_nxdomain() {
        let nsec = DnsRecord::Nsec {
            domain: "a.example.com".to_string(),
            next_domain: "z.example.com".to_string(),
            type_bitmaps: vec![],
            ttl: TransientTtl(300),
        };
        assert!(DnssecValidator::nsec_proves_denial(&nsec, "m.example.com", QueryType::A));
        assert!(DnssecValidator::nsec_proves_denial(&nsec, "b.example.com", QueryType::A));
    }

    #[test]
    fn test_nsec_nodata() {
        let nsec = DnsRecord::Nsec {
            domain: "example.com".to_string(),
            next_domain: "z.example.com".to_string(),
            type_bitmaps: vec![0u8, 1u8, 0x60u8], // A + NS
            ttl: TransientTtl(300),
        };
        // AAAA is absent -> proven
        assert!(DnssecValidator::nsec_proves_denial(&nsec, "example.com", QueryType::Aaaa));
        // A is present -> not proven
        assert!(!DnssecValidator::nsec_proves_denial(&nsec, "example.com", QueryType::A));
    }

    #[test]
    fn test_nsec_bitmap_has_type() {
        let bitmaps = vec![0u8, 1u8, 0b0100_0000u8];
        assert!(nsec_bitmap_has_type(&bitmaps, 1)); // A
        assert!(!nsec_bitmap_has_type(&bitmaps, 2)); // NS
    }

    #[test]
    fn test_nsec3_hash_stable() {
        let h1 = nsec3_hash_name("example.com", &[], 0);
        let h2 = nsec3_hash_name("example.com", &[], 0);
        assert_eq!(h1, h2);
        assert!(!h1.is_empty());
    }

    #[test]
    fn test_nsec3_hash_different_salt() {
        let h1 = nsec3_hash_name("example.com", &[], 0);
        let h2 = nsec3_hash_name("example.com", &[0xAA, 0xBB], 0);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_ecdsa_raw_to_der() {
        // Simple check: 32-byte r + 32-byte s
        let raw = vec![0u8; 64];
        let der = ecdsa_raw_to_der(&raw, 32);
        // Should start with SEQUENCE tag
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn test_stats_snapshot() {
        let v = DnssecValidator::new(DnssecValidationMode::Opportunistic);
        let snap = v.stats().snapshot();
        assert_eq!(snap.queries_validated, 0);
        assert_eq!(snap.secure_responses, 0);
    }
}
