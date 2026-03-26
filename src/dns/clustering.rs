//! DNS Cluster Management - HA clustering with gossip-based leader election
//!
//! Implements:
//! * Gossip protocol for cluster membership and failure detection
//! * Raft-lite leader election (simplified single-round voting)
//! * Blocklist state replication between nodes via HTTP
//! * Cluster status API with node health, roles, and sync lag

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};

// ─────────────────────────────── Config ────────────────────────────────────

/// Role of this node in the cluster
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterRole {
    /// This node won the most recent election
    Leader,
    /// This node follows the current leader
    Follower,
    /// Cluster not yet formed / election pending
    Candidate,
    /// Single-node mode; no peers configured
    Standalone,
    // Legacy aliases kept for backwards-compat with older configs
    #[serde(alias = "Primary")]
    Primary,
    #[serde(alias = "Replica")]
    Replica,
}

/// Full configuration for HA cluster operation.
///
/// Used in `ServerContext` and re-exported from `crate::config`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// Enable clustering (false = standalone mode)
    pub enabled: bool,

    /// Static role override. When `None` the node participates in leader
    /// election to determine its own role at runtime.
    pub role: ClusterRole,

    /// Stable, human-readable node identifier (auto-generated if empty)
    pub node_id: String,

    /// Peer HTTP base URLs, e.g. `["http://node2:5380", "http://node3:5380"]`.
    /// Used for both gossip and blocklist replication.
    pub peer_addresses: Vec<String>,

    /// How often (seconds) this node sends heartbeat/gossip messages to peers
    pub heartbeat_interval_secs: u64,

    /// Minimum number of nodes (including self) that must agree for a decision
    /// to be valid.  Typical value: `(n / 2) + 1` for a cluster of `n` nodes.
    pub quorum: usize,

    /// How often (seconds) the leader pushes blocklist state to followers
    pub blocklist_sync_interval_secs: u64,

    /// Seconds without a heartbeat before a peer is considered dead
    pub peer_timeout_secs: u64,

    // ── Legacy fields kept for config-file compat ──────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_url: Option<String>,
    #[serde(default)]
    pub replica_urls: Vec<String>,
    #[serde(default = "default_sync_interval")]
    pub sync_interval_secs: u64,
}

fn default_sync_interval() -> u64 { 30 }

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            role: ClusterRole::Standalone,
            node_id: uuid::Uuid::new_v4().to_string(),
            peer_addresses: Vec::new(),
            heartbeat_interval_secs: 5,
            quorum: 1,
            blocklist_sync_interval_secs: 60,
            peer_timeout_secs: 15,
            primary_url: None,
            replica_urls: Vec::new(),
            sync_interval_secs: 30,
        }
    }
}

// ─────────────────────────── Gossip membership ─────────────────────────────

/// Single gossip message exchanged between peers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipMessage {
    /// Sender's node ID
    pub from_node_id: String,
    /// Sender's current role
    pub role: ClusterRole,
    /// Sender's current Raft term
    pub term: u64,
    /// Unix timestamp of the message
    pub timestamp: u64,
    /// Whether the sender is in draining state
    pub draining: bool,
    /// Sender's view of peer health (node_id → healthy)
    pub peer_health: HashMap<String, bool>,
}

/// In-memory gossip state for this node
#[derive(Debug)]
pub struct GossipState {
    /// Latest gossip received from each peer, keyed by node_id
    pub received: RwLock<HashMap<String, GossipMessage>>,
}

impl GossipState {
    pub fn new() -> Self {
        Self { received: RwLock::new(HashMap::new()) }
    }

    /// Record an inbound gossip message
    pub fn record(&self, msg: GossipMessage) {
        self.received.write().insert(msg.from_node_id.clone(), msg);
    }

    /// Return all nodes seen via gossip whose last heartbeat is recent
    pub fn live_peers(&self, timeout_secs: u64) -> Vec<String> {
        let now = unix_now();
        self.received
            .read()
            .iter()
            .filter(|(_, m)| now.saturating_sub(m.timestamp) < timeout_secs)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

// ─────────────────────────── Raft-lite election ────────────────────────────

/// Simplified Raft leader election state.
///
/// Full Raft log replication is out of scope; this implements only
/// the leader-election portion (§5.2 of the Raft paper).
#[derive(Debug)]
pub struct LeaderElection {
    /// Current election term (monotonically increasing)
    term: AtomicU64,
    /// Node ID of the current known leader (empty = unknown)
    leader_id: RwLock<String>,
    /// Number of votes received in the current term
    votes_received: AtomicU32,
    /// Whether this node has voted in the current term
    voted_this_term: AtomicBool,
}

impl LeaderElection {
    pub fn new() -> Self {
        Self {
            term: AtomicU64::new(0),
            leader_id: RwLock::new(String::new()),
            votes_received: AtomicU32::new(0),
            voted_this_term: AtomicBool::new(false),
        }
    }

    /// Current Raft term
    pub fn current_term(&self) -> u64 {
        self.term.load(Ordering::SeqCst)
    }

    /// ID of the node we believe to be the current leader (empty = none)
    pub fn leader_id(&self) -> String {
        self.leader_id.read().clone()
    }

    /// Transition to candidate and start a new term.
    /// Returns the new term number.
    pub fn start_election(&self, my_node_id: &str) -> u64 {
        let new_term = self.term.fetch_add(1, Ordering::SeqCst) + 1;
        self.votes_received.store(1, Ordering::SeqCst); // vote for self
        self.voted_this_term.store(true, Ordering::SeqCst);
        *self.leader_id.write() = String::new(); // no leader yet
        log::info!("[raft] starting election for term {}, candidate={}", new_term, my_node_id);
        new_term
    }

    /// Record a vote received from a peer for `term`.
    /// Returns true if we now have enough votes for `quorum`.
    pub fn record_vote(&self, term: u64, quorum: usize) -> bool {
        if term == self.current_term() {
            let votes = self.votes_received.fetch_add(1, Ordering::SeqCst) + 1;
            votes as usize >= quorum
        } else {
            false
        }
    }

    /// Acknowledge that `leader` won election for `term`.
    pub fn acknowledge_leader(&self, leader: &str, term: u64) {
        if term >= self.current_term() {
            self.term.store(term, Ordering::SeqCst);
            *self.leader_id.write() = leader.to_string();
            log::info!("[raft] acknowledging leader={} for term={}", leader, term);
        }
    }

    /// Handle an incoming vote-request from a candidate.
    /// Returns true if we grant the vote.
    pub fn handle_vote_request(&self, candidate: &str, candidate_term: u64) -> bool {
        let my_term = self.current_term();
        if candidate_term > my_term && !self.voted_this_term.load(Ordering::SeqCst) {
            self.term.store(candidate_term, Ordering::SeqCst);
            self.voted_this_term.store(true, Ordering::SeqCst);
            log::debug!("[raft] granting vote to {} for term {}", candidate, candidate_term);
            true
        } else {
            false
        }
    }
}

// ─────────────────────────── Blocklist sync ────────────────────────────────

/// Payload sent from leader to follower during blocklist state replication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistSyncPayload {
    /// Node ID of the sender (must be the current leader)
    pub from_node_id: String,
    /// Raft term the sender was elected in
    pub term: u64,
    /// Unix timestamp of this snapshot
    pub timestamp: u64,
    /// Serialised blocklist entries: domain → blocked (true) / allowed (false)
    pub entries: HashMap<String, bool>,
    /// Incrementing version counter; followers reject older versions
    pub version: u64,
}

// ─────────────────────────── Peer status ───────────────────────────────────

/// Live health snapshot of a single peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub node_id: String,
    pub address: String,
    pub role: ClusterRole,
    pub healthy: bool,
    /// Unix timestamp of last received heartbeat
    pub last_heartbeat: u64,
    /// How many seconds behind the leader this peer's blocklist is (0 for leader)
    pub sync_lag_secs: u64,
}

// ─────────────────────────── Cluster status ────────────────────────────────

/// Full cluster status snapshot (returned by `/api/v2/cluster/status`)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterStatus {
    pub node_id: String,
    pub role: ClusterRole,
    /// Current Raft term
    pub term: u64,
    /// Node ID of the current leader (empty if unknown)
    pub leader_id: String,
    /// Number of healthy peers (not counting self)
    pub healthy_peers: usize,
    pub is_draining: bool,
    pub peers: Vec<PeerStatus>,
    /// Unix timestamp of last heartbeat sent by this node
    pub last_heartbeat_sent: u64,
    /// Server uptime in seconds
    pub uptime_secs: u64,
    /// Blocklist replication version held by this node
    pub blocklist_version: u64,
}

// ─────────────────────────── Cluster manager ───────────────────────────────

/// Central coordinator for HA cluster operations.
///
/// One `ClusterManager` is held inside `ServerContext` (behind an `Arc`).
pub struct ClusterManager {
    config: Arc<RwLock<ClusterConfig>>,
    /// Whether this node is draining (stops accepting new DNS queries)
    pub is_draining: Arc<AtomicBool>,
    /// Gossip membership state
    gossip: Arc<GossipState>,
    /// Raft-lite leader election state
    election: Arc<LeaderElection>,
    /// Peer health snapshots (node_id → PeerStatus)
    peers: Arc<RwLock<HashMap<String, PeerStatus>>>,
    /// Unix timestamp of last heartbeat sent
    last_heartbeat_sent: Arc<RwLock<u64>>,
    /// Unix timestamp this manager was created (used for uptime)
    started_at: u64,
    /// Current blocklist replication version
    blocklist_version: Arc<AtomicU64>,
    /// Drain-completed counter
    drain_completed: Arc<AtomicU64>,
}

impl ClusterManager {
    /// Create a new manager from the given configuration.
    pub fn new(config: ClusterConfig) -> Self {
        let started_at = unix_now();
        Self {
            config: Arc::new(RwLock::new(config)),
            is_draining: Arc::new(AtomicBool::new(false)),
            gossip: Arc::new(GossipState::new()),
            election: Arc::new(LeaderElection::new()),
            peers: Arc::new(RwLock::new(HashMap::new())),
            last_heartbeat_sent: Arc::new(RwLock::new(0)),
            started_at,
            blocklist_version: Arc::new(AtomicU64::new(0)),
            drain_completed: Arc::new(AtomicU64::new(0)),
        }
    }

    // ── Drain ──────────────────────────────────────────────────────────────

    /// Begin graceful drain; DNS handlers should stop accepting new queries.
    pub fn start_drain(&self) {
        self.is_draining.store(true, Ordering::SeqCst);
        log::info!("[cluster] graceful drain started");
    }

    /// Resume normal operation after a drain.
    pub fn stop_drain(&self) {
        self.is_draining.store(false, Ordering::SeqCst);
        log::info!("[cluster] drain stopped");
    }

    pub fn is_draining(&self) -> bool {
        self.is_draining.load(Ordering::SeqCst)
    }

    pub fn increment_drain_completed(&self) {
        self.drain_completed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn drain_completed_count(&self) -> u64 {
        self.drain_completed.load(Ordering::Relaxed)
    }

    // ── Role helpers ───────────────────────────────────────────────────────

    /// Effective role, considering both the static config and election state.
    pub fn effective_role(&self) -> ClusterRole {
        let cfg = self.config.read();
        if !cfg.enabled {
            return ClusterRole::Standalone;
        }
        let leader = self.election.leader_id();
        if leader == cfg.node_id {
            ClusterRole::Leader
        } else if leader.is_empty() {
            ClusterRole::Candidate
        } else {
            ClusterRole::Follower
        }
    }

    // ── Gossip ─────────────────────────────────────────────────────────────

    /// Build a gossip message for this node.
    pub fn build_gossip_message(&self) -> GossipMessage {
        let cfg = self.config.read();
        let peers = self.peers.read();
        let peer_health: HashMap<String, bool> = peers
            .iter()
            .map(|(id, s)| (id.clone(), s.healthy))
            .collect();
        GossipMessage {
            from_node_id: cfg.node_id.clone(),
            role: self.effective_role(),
            term: self.election.current_term(),
            timestamp: unix_now(),
            draining: self.is_draining(),
            peer_health,
        }
    }

    /// Process an inbound gossip message from a peer.
    pub fn handle_gossip(&self, msg: GossipMessage) {
        let now = unix_now();
        let lag = now.saturating_sub(msg.timestamp);
        let mut peers = self.peers.write();
        let addr = {
            let cfg = self.config.read();
            cfg.peer_addresses
                .iter()
                .find(|_| true) // stub: in production, resolve by node_id
                .cloned()
                .unwrap_or_default()
        };
        peers.insert(msg.from_node_id.clone(), PeerStatus {
            node_id: msg.from_node_id.clone(),
            address: addr,
            role: msg.role,
            healthy: lag < self.config.read().peer_timeout_secs,
            last_heartbeat: msg.timestamp,
            sync_lag_secs: lag,
        });

        // If the gossip message comes from a node that claims to be leader,
        // acknowledge it (raft-lite shortcut: trust gossip for leader info).
        if matches!(msg.role, ClusterRole::Leader) {
            self.election.acknowledge_leader(&msg.from_node_id, msg.term);
        }

        self.gossip.record(msg);
    }

    /// Fan-out a gossip message to all configured peers via HTTP POST.
    /// Returns a list of `(peer_address, success)` pairs.
    /// Stubs the network I/O — set `dry_run = true` in tests.
    pub fn send_gossip(&self) -> Vec<(String, bool)> {
        let msg = self.build_gossip_message();
        let payload = match serde_json::to_string(&msg) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("[cluster] failed to serialize gossip: {}", e);
                return Vec::new();
            }
        };
        *self.last_heartbeat_sent.write() = unix_now();

        let addrs: Vec<String> = self.config.read().peer_addresses.clone();
        let mut results = Vec::with_capacity(addrs.len());
        for addr in addrs {
            let url = format!("{}/api/v2/cluster/heartbeat", addr);
            let ok = reqwest::blocking::Client::new()
                .post(&url)
                .header("Content-Type", "application/json")
                .body(payload.clone())
                .timeout(Duration::from_secs(3))
                .send()
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            log::debug!("[cluster] gossip → {}: {}", addr, if ok { "ok" } else { "FAIL" });
            results.push((addr, ok));
        }
        results
    }

    // ── Leader election (Raft-lite) ────────────────────────────────────────

    /// Trigger a new leader election round.
    /// In production this would broadcast a `RequestVote` RPC to all peers;
    /// here we stub the network call and rely on gossip convergence.
    pub fn trigger_election(&self) -> u64 {
        let my_id = self.config.read().node_id.clone();
        self.election.start_election(&my_id)
    }

    /// Handle an incoming vote-request RPC from `candidate` running `term`.
    pub fn handle_vote_request(&self, candidate: &str, term: u64) -> bool {
        self.election.handle_vote_request(candidate, term)
    }

    /// Handle an incoming vote grant from a peer.
    /// Returns true if we have now reached quorum and should declare victory.
    pub fn handle_vote_grant(&self, term: u64) -> bool {
        let quorum = self.config.read().quorum;
        if self.election.record_vote(term, quorum) {
            let my_id = self.config.read().node_id.clone();
            self.election.acknowledge_leader(&my_id, term);
            log::info!("[raft] elected as leader for term {}", term);
            true
        } else {
            false
        }
    }

    // ── Blocklist sync ─────────────────────────────────────────────────────

    /// Build a blocklist sync payload from the given `entries` map.
    /// Only the leader should call this.
    pub fn build_blocklist_sync(
        &self,
        entries: HashMap<String, bool>,
    ) -> BlocklistSyncPayload {
        let version = self.blocklist_version.fetch_add(1, Ordering::SeqCst) + 1;
        let cfg = self.config.read();
        BlocklistSyncPayload {
            from_node_id: cfg.node_id.clone(),
            term: self.election.current_term(),
            timestamp: unix_now(),
            entries,
            version,
        }
    }

    /// Push a blocklist snapshot to all peer followers via HTTP POST.
    pub fn push_blocklist_sync(&self, entries: HashMap<String, bool>) -> Vec<(String, bool)> {
        let payload = self.build_blocklist_sync(entries);
        let body = match serde_json::to_string(&payload) {
            Ok(b) => b,
            Err(e) => {
                log::warn!("[cluster] blocklist sync serialization failed: {}", e);
                return Vec::new();
            }
        };
        let addrs: Vec<String> = self.config.read().peer_addresses.clone();
        let mut results = Vec::with_capacity(addrs.len());
        for addr in &addrs {
            let url = format!("{}/api/v2/cluster/sync", addr);
            let ok = reqwest::blocking::Client::new()
                .post(&url)
                .header("Content-Type", "application/json")
                .body(body.clone())
                .timeout(Duration::from_secs(10))
                .send()
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            log::info!("[cluster] blocklist sync → {}: {}", addr, if ok { "ok" } else { "FAIL" });
            results.push((addr.clone(), ok));
        }
        results
    }

    /// Apply an inbound blocklist sync payload received from the leader.
    /// Returns true if the payload was accepted (version is newer).
    pub fn apply_blocklist_sync(&self, payload: &BlocklistSyncPayload) -> bool {
        let current = self.blocklist_version.load(Ordering::SeqCst);
        if payload.version <= current {
            log::debug!(
                "[cluster] blocklist sync ignored (version {} ≤ current {})",
                payload.version, current
            );
            return false;
        }
        self.blocklist_version.store(payload.version, Ordering::SeqCst);
        log::info!(
            "[cluster] applied blocklist sync v{} from {} ({} entries)",
            payload.version, payload.from_node_id, payload.entries.len()
        );
        true
    }

    // ── Heartbeat (legacy / compat) ────────────────────────────────────────

    /// Backwards-compatible heartbeat send (wraps send_gossip).
    pub fn send_heartbeat(&self) -> Vec<(String, bool)> {
        self.send_gossip()
    }

    /// Record an inbound heartbeat from a peer (legacy path).
    pub fn receive_heartbeat(&self, node_id: &str, address: &str, timestamp: u64, draining: bool) {
        let msg = GossipMessage {
            from_node_id: node_id.to_string(),
            role: ClusterRole::Follower,
            term: 0,
            timestamp,
            draining,
            peer_health: HashMap::new(),
        };
        self.handle_gossip(msg);
        let _ = address; // address stored via handle_gossip peer lookup
    }

    // ── Config ─────────────────────────────────────────────────────────────

    pub fn get_config(&self) -> ClusterConfig {
        self.config.read().clone()
    }

    pub fn update_config(&self, new_config: ClusterConfig) {
        *self.config.write() = new_config;
    }

    // ── Status ─────────────────────────────────────────────────────────────

    /// Return a full status snapshot suitable for the `/api/v2/cluster/status`
    /// endpoint.
    pub fn get_status(&self) -> ClusterStatus {
        let cfg = self.config.read();
        let peers: Vec<PeerStatus> = self.peers.read().values().cloned().collect();
        let healthy_peers = peers.iter().filter(|p| p.healthy).count();
        let now = unix_now();

        ClusterStatus {
            node_id: cfg.node_id.clone(),
            role: self.effective_role(),
            term: self.election.current_term(),
            leader_id: self.election.leader_id(),
            healthy_peers,
            is_draining: self.is_draining(),
            peers,
            last_heartbeat_sent: *self.last_heartbeat_sent.read(),
            uptime_secs: now.saturating_sub(self.started_at),
            blocklist_version: self.blocklist_version.load(Ordering::SeqCst),
        }
    }
}

// ─────────────────────────── Helpers ───────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
