//! HA cluster synchronization via gRPC.
//!
//! The `sync` sub-module implements a `ZoneSync` gRPC service that allows
//! the primary node to broadcast zone updates to replicas.

pub mod sync;
