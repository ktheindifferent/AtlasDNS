//! Structured query logging with daily rotation.
//!
//! Logs every DNS query as a JSON line to a rotating file
//! (daily rotation, 7-day retention).

pub mod query_log;
