//! DNSSEC Full Validation Chain
//!
//! This module provides production-quality DNSSEC validation using the `ring`
//! crate for all cryptographic operations (RSA, ECDSA, Ed25519).
//!
//! # Architecture
//!
//! * [`trust_anchor`] - Root trust anchor management (IANA root KSK)
//! * [`validator`] - Signature verification and NSEC/NSEC3 denial proofs
//! * [`chain`] - Full chain-of-trust walking (DS -> DNSKEY -> RRSIG)
//!
//! # Usage
//!
//! The primary entry point is [`chain::ChainOfTrustValidator::dnssec_validate`],
//! which performs full chain-of-trust validation including negative response
//! proofs. It returns `ValidationStatus::Secure` on success, or `Err` in
//! strict mode when validation fails.
//!
//! # Supported Algorithms
//!
//! * RSA/SHA-256 (Algorithm 8)
//! * RSA/SHA-512 (Algorithm 10)
//! * ECDSA P-256/SHA-256 (Algorithm 13)
//! * ECDSA P-384/SHA-384 (Algorithm 14)
//! * Ed25519 (Algorithm 15)

/// Root trust anchor management (IANA root KSK).
pub mod trust_anchor;

/// DNSSEC signature verification and denial-of-existence proofs.
pub mod validator;

/// Full chain-of-trust walking from zone to root.
pub mod chain;

// Re-export primary types for convenience
pub use chain::ChainOfTrustValidator;
pub use trust_anchor::{TrustAnchor, TrustAnchorStore, compute_dnskey_tag, compute_ds_digest};
pub use validator::{
    DnssecValidationMode, DnssecValidationResult, DnssecValidationStats,
    DnssecValidationStatsSnapshot, DnssecValidator,
};
