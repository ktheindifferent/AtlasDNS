//! DNS Cluster Management - Primary/Replica HA setup
//!
//! Provides primary/replica coordination, heartbeat monitoring,
//! graceful drain support, and config sync across cluster nodes.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};

/// Role of this node in the cluster
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterRole {
    Primary,
    Replica,
    Standalone,
}

/// Configuration for cluster setup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub enabled: bool,
    pub role: ClusterRole,
    pub node_id: String,
    pub primary_url: Option<String>,
    pub replica_urls: Vec<String>,
    pub heartbeat_interval_secs: u64,
    pub sync_interval_secs: u64,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            role: ClusterRole::Standalone,
            node_id: uuid::Uuid::new_v4().to_string(),
            primary_url: None,
            replica_urls: Vec::new(),
            heartbeat_interval_secs: 5,
            sync_interval_secs: 30,
        }
    }
}

/// Status of a cluster peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub node_id: String,
    pub url: String,
    pub role: ClusterRole,
    pub healthy: bool,
    pub last_heartbeat: u64,
    pub lag_secs: u64,
}

/// Cluster manager - coordinates HA setup
pub struct ClusterManager {
    config: Arc<RwLock<ClusterConfig>>,
    /// Whether this node is draining (stops accepting new queries)
    pub is_draining: Arc<AtomicBool>,
    /// Queries completed during drain
    drain_completed: Arc<AtomicU64>,
    /// Peer statuses
    peers: Arc<RwLock<HashMap<String, PeerStatus>>>,
    /// This node's last heartbeat sent
    last_heartbeat: Arc<RwLock<u64>>,
}

impl ClusterManager {
    pub fn new(config: ClusterConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            is_draining: Arc::new(AtomicBool::new(false)),
            drain_completed: Arc::new(AtomicU64::new(0)),
            peers: Arc::new(RwLock::new(HashMap::new())),
            last_heartbeat: Arc::new(RwLock::new(0)),
        }
    }

    /// Start graceful drain - stop accepting new queries
    pub fn start_drain(&self) {
        self.is_draining.store(true, Ordering::SeqCst);
        log::info!("Cluster: graceful drain started");
    }

    /// Stop drain - resume accepting queries
    pub fn stop_drain(&self) {
        self.is_draining.store(false, Ordering::SeqCst);
        log::info!("Cluster: drain stopped, resuming queries");
    }

    /// Check if node is draining
    pub fn is_draining(&self) -> bool {
        self.is_draining.load(Ordering::SeqCst)
    }

    /// Increment drain completed counter
    pub fn increment_drain_completed(&self) {
        self.drain_completed.fetch_add(1, Ordering::Relaxed);
    }

    /// Get drain completed count
    pub fn drain_completed_count(&self) -> u64 {
        self.drain_completed.load(Ordering::Relaxed)
    }

    /// Send heartbeat to all replicas (called by primary)
    pub fn send_heartbeat(&self) -> Vec<(String, bool)> {
        let config = self.config.read();
        let now = current_timestamp();
        *self.last_heartbeat.write() = now;

        let mut results = Vec::new();
        for url in &config.replica_urls {
            let heartbeat_url = format!("{}/api/v2/cluster/heartbeat", url);
            let payload = serde_json::json!({
                "node_id": config.node_id,
                "role": "Primary",
                "timestamp": now,
                "draining": self.is_draining(),
            });
            // Use reqwest blocking client
            let ok = reqwest::blocking::Client::new()
                .post(&heartbeat_url)
                .json(&payload)
                .timeout(Duration::from_secs(3))
                .send()
                .map(|r| r.status().is_success())
                .unwrap_or(false);

            log::debug!("Heartbeat to {}: {}", url, if ok { "ok" } else { "failed" });
            results.push((url.clone(), ok));
        }
        results
    }

    /// Receive heartbeat from primary (called by replica)
    pub fn receive_heartbeat(&self, node_id: &str, url: &str, timestamp: u64, _draining: bool) {
        let now = current_timestamp();
        let mut peers = self.peers.write();
        peers.insert(node_id.to_string(), PeerStatus {
            node_id: node_id.to_string(),
            url: url.to_string(),
            role: ClusterRole::Primary,
            healthy: true,
            last_heartbeat: timestamp,
            lag_secs: now.saturating_sub(timestamp),
        });
    }

    /// Sync config to all replicas
    pub fn sync_config_to_replicas(&self, config_json: &str) -> Vec<(String, bool)> {
        let config = self.config.read();
        let mut results = Vec::new();

        for url in &config.replica_urls {
            let sync_url = format!("{}/api/v2/cluster/sync", url);
            let ok = reqwest::blocking::Client::new()
                .post(&sync_url)
                .header("Content-Type", "application/json")
                .body(config_json.to_string())
                .timeout(Duration::from_secs(10))
                .send()
                .map(|r| r.status().is_success())
                .unwrap_or(false);

            log::info!("Config sync to {}: {}", url, if ok { "ok" } else { "failed" });
            results.push((url.clone(), ok));
        }
        results
    }

    /// Get cluster status
    pub fn get_status(&self) -> ClusterStatus {
        let config = self.config.read();
        let peers = self.peers.read();
        let now = current_timestamp();

        ClusterStatus {
            node_id: config.node_id.clone(),
            role: config.role,
            is_draining: self.is_draining(),
            peers: peers.values().cloned().collect(),
            last_heartbeat: *self.last_heartbeat.read(),
            uptime_secs: now,
        }
    }

    /// Get cluster config
    pub fn get_config(&self) -> ClusterConfig {
        self.config.read().clone()
    }

    /// Update cluster config
    pub fn update_config(&self, new_config: ClusterConfig) {
        *self.config.write() = new_config;
    }
}

/// Cluster status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterStatus {
    pub node_id: String,
    pub role: ClusterRole,
    pub is_draining: bool,
    pub peers: Vec<PeerStatus>,
    pub last_heartbeat: u64,
    pub uptime_secs: u64,
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
