//! Threat Intelligence - public re-export of `dns::security::threat_intel`.
//!
//! This module exposes the threat intelligence types and manager at the crate
//! root so that binaries and external integrations can import them without
//! descending into the DNS-internal module tree.

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
