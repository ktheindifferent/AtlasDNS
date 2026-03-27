//! DNSSEC Trust Anchor Management
//!
//! Stores and manages DNSSEC trust anchors used as the root of the
//! chain-of-trust validation. The default configuration includes the
//! IANA root KSK (KSK-2017, key tag 20326, RSA/SHA-256).

use ring::digest;

/// A DNSSEC trust anchor entry.
///
/// Trust anchors are the pre-configured public keys (or DS digests) that
/// form the starting point for chain-of-trust validation. The primary
/// anchor is always the IANA root zone KSK.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    /// Owner zone (e.g. `"."` for the root).
    pub zone: String,
    /// Key tag (RFC 4034 Appendix B).
    pub key_tag: u16,
    /// DNSKEY algorithm number (8 = RSA/SHA-256).
    pub algorithm: u8,
    /// DNSKEY flags (257 = Zone Key + SEP for KSK).
    pub flags: u16,
    /// Raw public key bytes (DNS wire format, RFC 3110 for RSA).
    pub public_key: Vec<u8>,
}

/// IANA Root KSK public key (base64, RFC 4034 wire format).
/// Source: <https://data.iana.org/root-anchors/root-anchors.xml>
const IANA_ROOT_KSK_B64: &str =
    "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3\
     +/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv\
     ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0\
     jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZ\
     G+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRU\
     fhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1A\
     kUTV74bU=";

/// IANA Root KSK key tag.
pub const IANA_ROOT_KSK_TAG: u16 = 20326;

impl TrustAnchor {
    /// Return the built-in IANA root zone trust anchor (KSK-2017, key tag 20326).
    pub fn root_ksk_2017() -> Self {
        let cleaned = IANA_ROOT_KSK_B64.replace('\n', "");
        TrustAnchor {
            zone: ".".to_string(),
            key_tag: IANA_ROOT_KSK_TAG,
            algorithm: 8, // RSA/SHA-256
            flags: 257,   // Zone Key + SEP (KSK)
            public_key: decode_b64(&cleaned),
        }
    }

    /// Check whether a DNSKEY record matches this trust anchor.
    pub fn matches_dnskey(&self, flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> bool {
        let tag = compute_dnskey_tag(flags, protocol, algorithm, public_key);
        tag == self.key_tag
            && algorithm == self.algorithm
            && public_key == self.public_key.as_slice()
    }
}

/// A collection of trust anchors used for DNSSEC validation.
#[derive(Debug, Clone)]
pub struct TrustAnchorStore {
    anchors: Vec<TrustAnchor>,
}

impl TrustAnchorStore {
    /// Create a new store pre-loaded with the IANA root KSK.
    pub fn with_root_ksk() -> Self {
        Self {
            anchors: vec![TrustAnchor::root_ksk_2017()],
        }
    }

    /// Create an empty store (for testing).
    pub fn empty() -> Self {
        Self { anchors: Vec::new() }
    }

    /// Add a custom trust anchor.
    pub fn add(&mut self, anchor: TrustAnchor) {
        self.anchors.push(anchor);
    }

    /// Check if a DNSKEY matches any loaded trust anchor.
    pub fn is_trusted_dnskey(&self, flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> bool {
        self.anchors.iter().any(|a| a.matches_dnskey(flags, protocol, algorithm, public_key))
    }

    /// Return all trust anchors.
    pub fn anchors(&self) -> &[TrustAnchor] {
        &self.anchors
    }
}

impl Default for TrustAnchorStore {
    fn default() -> Self {
        Self::with_root_ksk()
    }
}

// ---------------------------------------------------------------------------
// Key tag computation (RFC 4034 Appendix B)
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
// DS digest computation (RFC 4034 Section 5.1.4)
// ---------------------------------------------------------------------------

/// Compute DS digest = hash(owner_name_wire || DNSKEY_RDATA).
///
/// `digest_type`: 1 = SHA-1, 2 = SHA-256, 4 = SHA-384.
pub fn compute_ds_digest(
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
            // SHA-1 via ring
            digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &preimage)
                .as_ref()
                .to_vec()
        }
        2 => {
            digest::digest(&digest::SHA256, &preimage)
                .as_ref()
                .to_vec()
        }
        4 => {
            digest::digest(&digest::SHA384, &preimage)
                .as_ref()
                .to_vec()
        }
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// DNS name wire-format encoding
// ---------------------------------------------------------------------------

/// Encode a domain name in canonical (lowercase, uncompressed) wire format.
pub fn name_to_wire_canonical(name: &str) -> Vec<u8> {
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

// ---------------------------------------------------------------------------
// Base64 decoding (self-contained, no external dependency)
// ---------------------------------------------------------------------------

fn decode_b64(s: &str) -> Vec<u8> {
    const ALPH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        if let Some(v) = ALPH.iter().position(|&x| x == c) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_ksk_non_empty() {
        let anchor = TrustAnchor::root_ksk_2017();
        assert_eq!(anchor.key_tag, IANA_ROOT_KSK_TAG);
        assert_eq!(anchor.algorithm, 8);
        assert!(!anchor.public_key.is_empty());
        assert_eq!(anchor.zone, ".");
    }

    #[test]
    fn test_compute_dnskey_tag_root_ksk() {
        let anchor = TrustAnchor::root_ksk_2017();
        let tag = compute_dnskey_tag(anchor.flags, 3, anchor.algorithm, &anchor.public_key);
        assert_eq!(tag, IANA_ROOT_KSK_TAG);
    }

    #[test]
    fn test_trust_anchor_store_default() {
        let store = TrustAnchorStore::default();
        assert_eq!(store.anchors().len(), 1);
        let anchor = &store.anchors()[0];
        assert_eq!(anchor.key_tag, IANA_ROOT_KSK_TAG);
    }

    #[test]
    fn test_name_to_wire_canonical() {
        let wire = name_to_wire_canonical("Example.COM.");
        // 7 "example" 3 "com" 0
        assert_eq!(wire[0], 7);
        assert_eq!(&wire[1..8], b"example");
        assert_eq!(wire[8], 3);
        assert_eq!(&wire[9..12], b"com");
        assert_eq!(wire[12], 0);
    }

    #[test]
    fn test_name_to_wire_canonical_root() {
        let wire = name_to_wire_canonical(".");
        assert_eq!(wire, vec![0u8]);
    }

    #[test]
    fn test_ds_digest_sha256() {
        // Just verify it produces non-empty output
        let digest = compute_ds_digest("example.com", 257, 3, 8, &[1, 2, 3], 2);
        assert_eq!(digest.len(), 32); // SHA-256
    }
}
