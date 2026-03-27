//! Chain of Trust Verification
//!
//! Implements full iterative DNSSEC chain-of-trust walking from a queried
//! zone up to the root trust anchor. This module fetches missing DNSKEY and
//! DS records on demand during validation.

use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, ResultCode, ValidationStatus};
use crate::dnssec::validator::{DnssecValidationMode, DnssecValidationResult, DnssecValidator};

/// Maximum chain depth to prevent infinite loops.
const MAX_CHAIN_DEPTH: u8 = 16;

/// Full chain-of-trust validator.
///
/// Extends `DnssecValidator` with the ability to walk the DS → DNSKEY chain
/// from the queried zone up to the root, fetching missing records on demand.
pub struct ChainOfTrustValidator {
    validator: DnssecValidator,
}

impl ChainOfTrustValidator {
    /// Create a new chain validator with the given mode.
    pub fn new(mode: DnssecValidationMode) -> Self {
        Self {
            validator: DnssecValidator::new(mode),
        }
    }

    /// Return the underlying validator.
    pub fn validator(&self) -> &DnssecValidator {
        &self.validator
    }

    /// Return the current validation mode.
    pub fn mode(&self) -> DnssecValidationMode {
        self.validator.mode()
    }

    /// Full iterative chain-of-trust validation.
    ///
    /// Unlike `validate_packet_rrsigs` which only validates records already in
    /// the response, this method fetches missing DNSKEY and DS records by
    /// calling `fetch` for each zone in the hierarchy.
    ///
    /// `fetch(qname, qtype)` should send a DNS query and return the response,
    /// or `None` on failure.
    pub fn validate_chain_with_fetcher<F>(
        &self,
        packet: &DnsPacket,
        qname: &str,
        qtype: QueryType,
        fetch: F,
    ) -> DnssecValidationResult
    where
        F: Fn(&str, QueryType) -> Option<DnsPacket>,
    {
        if self.validator.mode() == DnssecValidationMode::Off {
            return DnssecValidationResult::Unsigned;
        }

        let all: Vec<&DnsRecord> = packet.answers.iter()
            .chain(packet.authorities.iter())
            .chain(packet.resources.iter())
            .collect();

        // Require at least one RRSIG in the response
        let has_rrsig = all.iter().any(|r| r.get_querytype() == QueryType::Rrsig);
        if !has_rrsig {
            return DnssecValidationResult::Unsigned;
        }

        // Collect distinct signer names from RRSIGs covering the queried type
        let signers: Vec<String> = all.iter()
            .filter_map(|r| match r {
                DnsRecord::Rrsig { type_covered, signer_name, .. }
                    if QueryType::from_num(*type_covered) == qtype =>
                        Some(signer_name.trim_end_matches('.').to_lowercase()),
                _ => None,
            })
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        if signers.is_empty() {
            return DnssecValidationResult::Unsigned;
        }

        // Build the RRset for the queried type
        let rrset: Vec<&DnsRecord> = all.iter()
            .filter(|r| r.get_querytype() == qtype)
            .copied()
            .collect();

        // Try each signer; succeed if any chain validates
        for signer in &signers {
            let dnskeys_owned: Vec<DnsRecord>;
            let dnskeys: Vec<&DnsRecord> = {
                let in_pkt: Vec<&DnsRecord> = all.iter()
                    .filter(|r| r.get_querytype() == QueryType::Dnskey
                        && r.get_domain()
                            .map(|d| d.trim_end_matches('.').to_lowercase() == *signer)
                            .unwrap_or(false))
                    .copied()
                    .collect();
                if !in_pkt.is_empty() {
                    in_pkt
                } else {
                    dnskeys_owned = fetch_dnskeys_for_zone(signer, &fetch);
                    dnskeys_owned.iter().collect()
                }
            };

            if dnskeys.is_empty() {
                log::debug!("DNSSEC chain: no DNSKEY for signer {}", signer);
                continue;
            }

            // Verify RRSIG on the answer RRset
            let answer_rrsigs: Vec<&DnsRecord> = all.iter()
                .filter(|r| match r {
                    DnsRecord::Rrsig { type_covered, signer_name, .. } =>
                        QueryType::from_num(*type_covered) == qtype
                        && signer_name.trim_end_matches('.').to_lowercase() == *signer,
                    _ => false,
                })
                .copied()
                .collect();

            let sig_ok = answer_rrsigs.iter()
                .any(|rrsig| dnskeys.iter().any(|dk| self.validator.verify_rrsig(rrsig, &rrset, dk)));

            if !sig_ok {
                log::debug!("DNSSEC chain: RRSIG on answer failed for signer {}", signer);
                continue;
            }

            // Walk the chain from signer up to root trust anchor
            if self.walk_chain_up(signer, &dnskeys, &all, &fetch, 0) {
                log::info!(
                    "DNSSEC chain: authenticated for {} (signer {})",
                    qname, signer
                );
                return DnssecValidationResult::Authenticated;
            }
        }

        DnssecValidationResult::ValidationFailed
    }

    /// Full validation including negative response denial proofs.
    ///
    /// This is the main entry point for DNSSEC validation in the resolver.
    /// Returns `ValidationStatus` and `Err` in Strict mode for bogus responses.
    pub fn dnssec_validate<F>(
        &self,
        packet: &DnsPacket,
        qname: &str,
        qtype: QueryType,
        fetch: F,
    ) -> Result<ValidationStatus, String>
    where
        F: Fn(&str, QueryType) -> Option<DnsPacket>,
    {
        if self.validator.mode() == DnssecValidationMode::Off {
            return Ok(ValidationStatus::Indeterminate);
        }

        let mut chain_result = self.validate_chain_with_fetcher(packet, qname, qtype, &fetch);

        // For negative responses, validate NSEC/NSEC3 denial proof
        let is_negative = packet.header.rescode == ResultCode::NXDOMAIN
            || packet.answers.is_empty();

        if is_negative && chain_result == DnssecValidationResult::Authenticated {
            let denial_ok = self.validator.validate_denial_of_existence(packet, qname, qtype);
            log::debug!("DNSSEC: denial proof for {} {:?}: {}", qname, qtype, denial_ok);

            if !denial_ok {
                log::warn!(
                    "DNSSEC: negative response missing valid NSEC/NSEC3 denial for {} {:?}",
                    qname, qtype
                );
                chain_result = if self.validator.mode() == DnssecValidationMode::Strict {
                    DnssecValidationResult::ValidationFailed
                } else {
                    DnssecValidationResult::Unsigned
                };
            }
        }

        match chain_result {
            DnssecValidationResult::Authenticated => {
                log::info!("DNSSEC chain: SECURE for {} {:?}", qname, qtype);
                Ok(ValidationStatus::Secure)
            }
            DnssecValidationResult::Unsigned => {
                log::debug!("DNSSEC chain: unsigned for {} {:?}", qname, qtype);
                Ok(ValidationStatus::Indeterminate)
            }
            DnssecValidationResult::ValidationFailed => {
                log::warn!("DNSSEC chain: BOGUS for {} {:?}", qname, qtype);
                if self.validator.mode() == DnssecValidationMode::Strict {
                    Err(format!("DNSSEC chain validation failed for {}", qname))
                } else {
                    Ok(ValidationStatus::Bogus)
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Chain walking internals
    // -----------------------------------------------------------------------

    /// Recursively walk the chain from `zone` up to the root.
    fn walk_chain_up<F>(
        &self,
        zone: &str,
        dnskeys: &[&DnsRecord],
        all_in_pkt: &[&DnsRecord],
        fetch: &F,
        depth: u8,
    ) -> bool
    where
        F: Fn(&str, QueryType) -> Option<DnsPacket>,
    {
        if depth > MAX_CHAIN_DEPTH {
            log::warn!("DNSSEC chain: max depth exceeded at zone {}", zone);
            return false;
        }

        let zone_norm = zone.trim_end_matches('.').to_lowercase();

        // Root zone: verify DNSKEY(s) directly against trust anchors
        if zone_norm.is_empty() {
            return dnskeys.iter().any(|dk| self.validator.is_trusted_root_dnskey(dk));
        }

        // Get DS records for this zone
        let ds_owned: Vec<DnsRecord>;
        let ds_records: Vec<&DnsRecord> = {
            let in_pkt: Vec<&DnsRecord> = all_in_pkt.iter()
                .filter(|r| r.get_querytype() == QueryType::Ds
                    && r.get_domain()
                        .map(|d| d.trim_end_matches('.').to_lowercase() == zone_norm)
                        .unwrap_or(false))
                .copied()
                .collect();
            if !in_pkt.is_empty() {
                in_pkt
            } else {
                ds_owned = fetch_ds_records_for_zone(zone, fetch);
                ds_owned.iter().collect()
            }
        };

        if ds_records.is_empty() {
            log::debug!("DNSSEC chain: no DS for zone {} (depth {})", zone, depth);
            return self.validator.mode() == DnssecValidationMode::Opportunistic;
        }

        // At least one DNSKEY must match a DS record
        let dnskey_matched = dnskeys.iter()
            .any(|dk| ds_records.iter().any(|ds| self.validator.verify_dnskey_with_ds(dk, ds)));

        if !dnskey_matched {
            log::debug!("DNSSEC chain: DNSKEY/DS mismatch for zone {}", zone);
            return false;
        }

        // Verify DS records are signed by the parent zone's DNSKEY
        let parent = parent_zone_of(zone);
        let parent_norm = parent.trim_end_matches('.').to_lowercase();

        let parent_dnskeys_owned = fetch_dnskeys_for_zone(&parent, fetch);
        if parent_dnskeys_owned.is_empty() {
            if parent_norm.is_empty() {
                // Zone is a TLD; DS must be signed by root
                let root_dnskeys = fetch_dnskeys_for_zone(".", fetch);
                if root_dnskeys.is_empty() {
                    return self.validator.mode() == DnssecValidationMode::Opportunistic;
                }
                let root_trusted = root_dnskeys.iter()
                    .any(|dk| self.validator.is_trusted_root_dnskey(dk));
                if !root_trusted {
                    log::debug!("DNSSEC chain: root DNSKEY does not match trust anchor for TLD {}", zone);
                    return false;
                }
                let ds_rrsig_ok = verify_ds_rrsigs_with_parent(
                    zone, &root_dnskeys, fetch, &self.validator,
                );
                return ds_rrsig_ok && dnskey_matched;
            }
            log::debug!("DNSSEC chain: cannot fetch parent DNSKEYs for {}", parent);
            return self.validator.mode() == DnssecValidationMode::Opportunistic;
        }

        // Verify DS RRSIG with parent DNSKEYs
        let ds_rrsig_ok = verify_ds_rrsigs_with_parent(
            zone, &parent_dnskeys_owned, fetch, &self.validator,
        );

        if !ds_rrsig_ok {
            log::debug!("DNSSEC chain: DS RRSIG verification failed for zone {}", zone);
            return false;
        }

        // Recurse: validate parent's DNSKEY chain
        let parent_refs: Vec<&DnsRecord> = parent_dnskeys_owned.iter().collect();
        let empty: Vec<&DnsRecord> = vec![];
        self.walk_chain_up(&parent, &parent_refs, &empty, fetch, depth + 1)
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Extract the parent zone of `zone`.
/// `"example.com."` -> `"com."`, `"com."` -> `"."`, `"."` -> `""`.
fn parent_zone_of(zone: &str) -> String {
    let norm = zone.trim_end_matches('.');
    if norm.is_empty() {
        return String::new();
    }
    match norm.find('.') {
        Some(idx) => format!("{}.", &norm[idx + 1..]),
        None => ".".to_string(),
    }
}

/// Fetch DNSKEY records for a zone.
fn fetch_dnskeys_for_zone<F>(zone: &str, fetch: &F) -> Vec<DnsRecord>
where
    F: Fn(&str, QueryType) -> Option<DnsPacket>,
{
    if let Some(pkt) = fetch(zone, QueryType::Dnskey) {
        pkt.answers.into_iter()
            .filter(|r| r.get_querytype() == QueryType::Dnskey)
            .collect()
    } else {
        Vec::new()
    }
}

/// Fetch DS records for a zone.
fn fetch_ds_records_for_zone<F>(zone: &str, fetch: &F) -> Vec<DnsRecord>
where
    F: Fn(&str, QueryType) -> Option<DnsPacket>,
{
    if let Some(pkt) = fetch(zone, QueryType::Ds) {
        pkt.answers.iter()
            .chain(pkt.authorities.iter())
            .filter(|r| r.get_querytype() == QueryType::Ds)
            .cloned()
            .collect()
    } else {
        Vec::new()
    }
}

/// Verify that DS RRSIGs for `zone` are signed by one of the parent DNSKEYs.
fn verify_ds_rrsigs_with_parent<F>(
    zone: &str,
    parent_dnskeys: &[DnsRecord],
    fetch: &F,
    validator: &DnssecValidator,
) -> bool
where
    F: Fn(&str, QueryType) -> Option<DnsPacket>,
{
    if let Some(ds_pkt) = fetch(zone, QueryType::Ds) {
        let ds_ans: Vec<&DnsRecord> = ds_pkt.answers.iter()
            .filter(|r| r.get_querytype() == QueryType::Ds)
            .collect();
        let ds_sigs: Vec<&DnsRecord> = ds_pkt.answers.iter()
            .chain(ds_pkt.authorities.iter())
            .filter(|r| r.get_querytype() == QueryType::Rrsig)
            .collect();
        let parent_dk_refs: Vec<&DnsRecord> = parent_dnskeys.iter().collect();
        ds_sigs.iter().any(|rrsig| {
            parent_dk_refs.iter().any(|dk| validator.verify_rrsig(rrsig, &ds_ans, dk))
        })
    } else {
        validator.mode() == DnssecValidationMode::Opportunistic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::protocol::TransientTtl;

    #[test]
    fn test_parent_zone_of() {
        assert_eq!(parent_zone_of("example.com."), "com.");
        assert_eq!(parent_zone_of("com."), ".");
        assert_eq!(parent_zone_of("."), "");
        assert_eq!(parent_zone_of("sub.example.com."), "example.com.");
    }

    #[test]
    fn test_chain_validator_off_mode() {
        let cv = ChainOfTrustValidator::new(DnssecValidationMode::Off);
        let packet = DnsPacket::new();
        let fetch = |_: &str, _: QueryType| -> Option<DnsPacket> { None };
        let result = cv.validate_chain_with_fetcher(&packet, "example.com", QueryType::A, fetch);
        assert_eq!(result, DnssecValidationResult::Unsigned);
    }

    #[test]
    fn test_chain_unsigned_packet() {
        let cv = ChainOfTrustValidator::new(DnssecValidationMode::Opportunistic);
        let mut packet = DnsPacket::new();
        packet.answers.push(DnsRecord::A {
            domain: "example.com".to_string(),
            addr: "192.0.2.1".parse().unwrap(),
            ttl: TransientTtl(300),
        });
        let fetch = |_: &str, _: QueryType| -> Option<DnsPacket> { None };
        let result = cv.validate_chain_with_fetcher(&packet, "example.com", QueryType::A, fetch);
        assert_eq!(result, DnssecValidationResult::Unsigned);
    }

    #[test]
    fn test_dnssec_validate_off() {
        let cv = ChainOfTrustValidator::new(DnssecValidationMode::Off);
        let packet = DnsPacket::new();
        let fetch = |_: &str, _: QueryType| -> Option<DnsPacket> { None };
        let result = cv.dnssec_validate(&packet, "example.com", QueryType::A, fetch);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ValidationStatus::Indeterminate);
    }
}
