//! Top-level Atlas DNS configuration types.
//!
//! Re-exports the most commonly used configuration structs so callers can
//! import from a single, stable location:
//!
//! ```rust,ignore
//! use atlas::config::{ClusterConfig, ClusterRole};
//! ```

pub use crate::dns::clustering::{ClusterConfig, ClusterRole};
pub use crate::dns::rate_limit::{RateLimitConfig, RateLimiter};
pub use crate::dns::rebinding::RebindingProtection;
pub use crate::dns::rpz::{RpzEngine, RpzAction, RpzTriggerType, RpzRule, ThreatCategory};
