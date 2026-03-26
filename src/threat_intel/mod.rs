//! Threat Intelligence module for Atlas DNS.
//!
//! Provides integration with external threat intelligence feeds to block
//! queries to known-malicious domains:
//!
//! - **abuse.ch URLhaus** — fetches the plain-text online-hosts list and
//!   extracts domains currently distributing malware.
//! - **Spamhaus ZEN DNSBL** — performs reverse-IP lookups against
//!   `zen.spamhaus.org` for IP reputation checks.
//!
//! # Sub-modules
//!
//! - [`feeds`] — feed fetching, parsing, and DNSBL lookup helpers.
//! - [`blocklist`] — in-memory domain blocklist with periodic background
//!   refresh and stats tracking.
//!
//! # Re-exports
//!
//! The core threat-intel types from `dns::security::threat_intel` are
//! re-exported here for convenience so that callers can import everything
//! from a single path.

pub mod feeds;
pub mod blocklist;

// Re-export the existing core threat-intel types so external code that was
// importing from `atlas::threat_intel::*` continues to work.
pub use crate::dns::security::threat_intel::{
    ThreatIntelManager,
    ThreatIntelConfig,
    ThreatIntelHit,
    ThreatEntry,
    IpBlockEntry,
    ThreatCategory,
    DomainReputation,
    ReputationLevel,
    FeedDescriptor,
    BlockAction,
    CustomFeed,
};
