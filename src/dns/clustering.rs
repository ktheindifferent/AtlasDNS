//! DNS Cluster Management - HA clustering with gossip-based leader election
//!
//! Implements:
//! * Gossip protocol for cluster membership and failure detection
//! * UDP gossip heartbeat (5s interval, 15s dead timeout)
//! * Raft-lite leader election (simplified single-round voting)
//! * Zone transfer: secondaries pull full zone set from primary via TCP
//! * Blocklist state replication between nodes via HTTP
//! * Cluster status API with node health, roles, and sync lag

use std::collections::HashMap;
use std::io::{Read as IoRead, Write as IoWrite};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
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

    /// Address to bind the UDP gossip listener on (e.g. "0.0.0.0:5382")
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,

    /// Peer HTTP base URLs, e.g. `["http://node2:5380", "http://node3:5380"]`.
    /// Used for both gossip and blocklist replication.
    pub peer_addresses: Vec<String>,

    /// Query-per-second threshold above which this node is considered overloaded.
    /// When overloaded and peers are available, DNS queries would be forwarded.
    #[serde(default = "default_overload_threshold")]
    pub overload_threshold: u64,

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
fn default_bind_addr() -> String { format!("0.0.0.0:{}", CLUSTER_GOSSIP_PORT) }
fn default_overload_threshold() -> u64 { 10000 }

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            role: ClusterRole::Standalone,
            node_id: uuid::Uuid::new_v4().to_string(),
            bind_addr: default_bind_addr(),
            peer_addresses: Vec::new(),
            overload_threshold: default_overload_threshold(),
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

// ─────────────────────────── Cluster node / state ───────────────────────────

/// A node in the HA cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNode {
    /// Unique node identifier
    pub id: String,
    /// Network address (host:port) used for gossip and zone transfer
    pub addr: String,
    /// Current role of this node
    pub role: ClusterRole,
    /// Unix timestamp of the last heartbeat received from this node
    pub last_heartbeat: u64,
    /// Total queries handled by this node (reported via heartbeat)
    pub query_count: u64,
}

impl ClusterNode {
    pub fn new(id: String, addr: String, role: ClusterRole) -> Self {
        Self {
            id,
            addr,
            role,
            last_heartbeat: unix_now(),
            query_count: 0,
        }
    }

    /// Returns true if the node has been seen within `timeout_secs`.
    pub fn is_alive(&self, timeout_secs: u64) -> bool {
        unix_now().saturating_sub(self.last_heartbeat) < timeout_secs
    }
}

/// Tracks all known nodes in the cluster.
#[derive(Debug)]
pub struct ClusterState {
    nodes: RwLock<HashMap<String, ClusterNode>>,
}

impl Default for ClusterState {
    fn default() -> Self {
        Self::new()
    }
}

impl ClusterState {
    pub fn new() -> Self {
        Self {
            nodes: RwLock::new(HashMap::new()),
        }
    }

    /// Update or insert a node.
    pub fn upsert(&self, node: ClusterNode) {
        self.nodes.write().insert(node.id.clone(), node);
    }

    /// Record a heartbeat from the given node, updating its timestamp, role, and stats.
    pub fn record_heartbeat(&self, node_id: &str, addr: &str, role: ClusterRole) {
        self.record_heartbeat_with_stats(node_id, addr, role, 0);
    }

    /// Record a heartbeat with query stats.
    pub fn record_heartbeat_with_stats(&self, node_id: &str, addr: &str, role: ClusterRole, query_count: u64) {
        let mut nodes = self.nodes.write();
        if let Some(n) = nodes.get_mut(node_id) {
            n.last_heartbeat = unix_now();
            n.role = role;
            n.addr = addr.to_string();
            if query_count > 0 {
                n.query_count = query_count;
            }
        } else {
            nodes.insert(node_id.to_string(), ClusterNode {
                id: node_id.to_string(),
                addr: addr.to_string(),
                role,
                last_heartbeat: unix_now(),
                query_count,
            });
        }
    }

    /// Return all nodes considered alive within `timeout_secs`.
    pub fn live_nodes(&self, timeout_secs: u64) -> Vec<ClusterNode> {
        self.nodes.read().values()
            .filter(|n| n.is_alive(timeout_secs))
            .cloned()
            .collect()
    }

    /// Return all nodes (alive or dead).
    pub fn all_nodes(&self) -> Vec<ClusterNode> {
        self.nodes.read().values().cloned().collect()
    }

    /// Mark nodes that haven't heartbeated within `timeout_secs` with a stale timestamp.
    /// Returns the list of node IDs that are now considered dead.
    pub fn dead_nodes(&self, timeout_secs: u64) -> Vec<String> {
        self.nodes.read().values()
            .filter(|n| !n.is_alive(timeout_secs))
            .map(|n| n.id.clone())
            .collect()
    }

    /// Remove a node by ID.
    pub fn remove(&self, node_id: &str) {
        self.nodes.write().remove(node_id);
    }
}

// ─────────────────────────── UDP heartbeat ──────────────────────────────────

/// Compact UDP heartbeat packet (JSON-encoded for simplicity).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpHeartbeat {
    pub node_id: String,
    pub addr: String,
    pub role: ClusterRole,
    pub term: u64,
    pub timestamp: u64,
    /// Total queries handled by this node
    #[serde(default)]
    pub query_count: u64,
}

/// Default UDP port used for cluster gossip heartbeats.
pub const CLUSTER_GOSSIP_PORT: u16 = 5382;

/// Default TCP port used for zone transfer.
pub const CLUSTER_ZONE_TRANSFER_PORT: u16 = 5383;

// ─────────────────────────── Zone transfer ──────────────────────────────────

/// Represents a full zone snapshot for transfer from primary to secondary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneTransferPayload {
    /// Node ID of the sender (primary)
    pub from_node_id: String,
    /// Unix timestamp of this snapshot
    pub timestamp: u64,
    /// Serialized zones: each entry is (domain, zone_json)
    pub zones: Vec<ZoneTransferEntry>,
}

/// A single zone in a transfer payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneTransferEntry {
    pub domain: String,
    pub m_name: String,
    pub r_name: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
    /// Records serialized as JSON strings (using DnsRecord's Serialize impl)
    pub records: Vec<String>,
}

/// Zone sync status for the status API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct ZoneSyncStatus {
    /// Whether zone sync has completed at least once
    pub synced: bool,
    /// Unix timestamp of last successful zone sync
    pub last_sync: u64,
    /// Number of zones received in last sync
    pub zone_count: usize,
    /// Total records received in last sync
    pub record_count: usize,
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

impl Default for GossipState {
    fn default() -> Self {
        Self::new()
    }
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

impl Default for LeaderElection {
    fn default() -> Self {
        Self::new()
    }
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
    /// HA cluster node tracker
    pub cluster_state: Arc<ClusterState>,
    /// Zone sync status (for secondary nodes)
    pub zone_sync_status: Arc<RwLock<ZoneSyncStatus>>,
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
            cluster_state: Arc::new(ClusterState::new()),
            zone_sync_status: Arc::new(RwLock::new(ZoneSyncStatus::default())),
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

    /// Return the zone sync status (for secondary nodes).
    pub fn get_zone_sync_status(&self) -> ZoneSyncStatus {
        self.zone_sync_status.read().clone()
    }

    /// Return all known cluster nodes with health and query stats.
    /// Used by `GET /api/cluster/nodes`.
    pub fn get_all_nodes(&self) -> Vec<ClusterNode> {
        self.cluster_state.all_nodes()
    }

    /// Check cluster quorum health: majority of known nodes must be alive.
    /// Returns `(healthy: bool, alive_count, total_count, quorum_required)`.
    pub fn quorum_health(&self) -> (bool, usize, usize, usize) {
        let cfg = self.config.read();
        let all = self.cluster_state.all_nodes();
        // Total includes self + peers
        let total = all.len() + 1;
        let alive = all.iter().filter(|n| n.is_alive(cfg.peer_timeout_secs)).count() + 1; // +1 for self
        let quorum = cfg.quorum;
        (alive >= quorum, alive, total, quorum)
    }

    /// Check if the node is overloaded based on query count vs threshold.
    /// If overloaded and peers are available, logs that it would forward.
    /// Returns true if overloaded.
    pub fn check_overload(&self, current_qps: u64) -> bool {
        let cfg = self.config.read();
        if !cfg.enabled || current_qps < cfg.overload_threshold {
            return false;
        }
        let live = self.cluster_state.live_nodes(cfg.peer_timeout_secs);
        if !live.is_empty() {
            let peer = &live[0];
            log::warn!(
                "[cluster] node overloaded ({} qps > {} threshold) — would forward to peer {} ({})",
                current_qps, cfg.overload_threshold, peer.id, peer.addr
            );
        } else {
            log::warn!(
                "[cluster] node overloaded ({} qps > {} threshold) but no live peers available",
                current_qps, cfg.overload_threshold
            );
        }
        true
    }

    /// Update zone sync status after a successful transfer.
    pub fn record_zone_sync(&self, zone_count: usize, record_count: usize) {
        let mut status = self.zone_sync_status.write();
        status.synced = true;
        status.last_sync = unix_now();
        status.zone_count = zone_count;
        status.record_count = record_count;
    }

    // ── UDP gossip heartbeat ──────────────────────────────────────────────

    /// Send a UDP heartbeat ping to all configured peers.
    /// Each peer address in config should include the gossip port (e.g. "10.0.0.2:5382").
    pub fn send_udp_heartbeat(&self) -> Vec<(String, bool)> {
        let cfg = self.config.read();
        let hb = UdpHeartbeat {
            node_id: cfg.node_id.clone(),
            addr: String::new(), // filled by receiver from packet source
            role: self.effective_role(),
            term: self.election.current_term(),
            timestamp: unix_now(),
            query_count: 0, // caller can update via set_heartbeat_query_count
        };
        let payload = match serde_json::to_vec(&hb) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("[cluster/udp] failed to serialize heartbeat: {}", e);
                return Vec::new();
            }
        };
        *self.last_heartbeat_sent.write() = unix_now();

        let sock = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                log::warn!("[cluster/udp] failed to bind socket: {}", e);
                return Vec::new();
            }
        };
        let _ = sock.set_write_timeout(Some(Duration::from_secs(2)));

        let mut results = Vec::with_capacity(cfg.peer_addresses.len());
        for addr in &cfg.peer_addresses {
            // Extract host and build gossip address (use gossip port)
            let gossip_addr = peer_gossip_addr(addr);
            let ok = sock.send_to(&payload, &gossip_addr).is_ok();
            log::debug!("[cluster/udp] heartbeat → {}: {}", gossip_addr, if ok { "ok" } else { "FAIL" });
            results.push((gossip_addr, ok));
        }
        results
    }

    /// Start the UDP heartbeat listener. This should be spawned in a background thread.
    /// Listens on `bind_addr` (e.g. "0.0.0.0:5382") for incoming heartbeats.
    pub fn run_udp_listener(&self, bind_addr: &str) {
        let sock = match UdpSocket::bind(bind_addr) {
            Ok(s) => s,
            Err(e) => {
                log::error!("[cluster/udp] failed to bind listener on {}: {}", bind_addr, e);
                return;
            }
        };
        let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
        log::info!("[cluster/udp] heartbeat listener started on {}", bind_addr);

        let mut buf = [0u8; 4096];
        loop {
            match sock.recv_from(&mut buf) {
                Ok((len, src)) => {
                    if let Ok(hb) = serde_json::from_slice::<UdpHeartbeat>(&buf[..len]) {
                        let addr = if hb.addr.is_empty() { src.to_string() } else { hb.addr.clone() };
                        self.cluster_state.record_heartbeat_with_stats(&hb.node_id, &addr, hb.role, hb.query_count);
                        // Also feed into the existing gossip/peer tracking
                        self.receive_heartbeat(&hb.node_id, &addr, hb.timestamp, false);
                        log::debug!("[cluster/udp] heartbeat ← {} ({})", hb.node_id, addr);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {
                    // Normal timeout, check for dead nodes
                    let timeout = self.config.read().peer_timeout_secs;
                    let dead = self.cluster_state.dead_nodes(timeout);
                    for nid in &dead {
                        log::warn!("[cluster/udp] node {} marked dead (no heartbeat for {}s)", nid, timeout);
                    }
                }
                Err(e) => {
                    log::warn!("[cluster/udp] recv error: {}", e);
                }
            }
        }
    }

    /// Run the background heartbeat sender loop (every `heartbeat_interval_secs`).
    pub fn run_heartbeat_sender(&self) {
        loop {
            let interval = self.config.read().heartbeat_interval_secs;
            // Send both UDP and HTTP gossip
            self.send_udp_heartbeat();
            self.send_gossip();
            std::thread::sleep(Duration::from_secs(interval));
        }
    }

    // ── Zone transfer (TCP) ───────────────────────────────────────────────

    /// Start a TCP listener that serves zone transfer requests from secondaries.
    /// Primary nodes should call this in a background thread.
    pub fn run_zone_transfer_server<F>(&self, bind_addr: &str, get_zones: F)
    where
        F: Fn() -> Option<ZoneTransferPayload> + Send + Sync + 'static,
    {
        let listener = match TcpListener::bind(bind_addr) {
            Ok(l) => l,
            Err(e) => {
                log::error!("[cluster/xfr] failed to bind zone transfer server on {}: {}", bind_addr, e);
                return;
            }
        };
        log::info!("[cluster/xfr] zone transfer server listening on {}", bind_addr);

        for stream in listener.incoming() {
            match stream {
                Ok(mut conn) => {
                    let peer = conn.peer_addr().map(|a| a.to_string()).unwrap_or_default();
                    log::info!("[cluster/xfr] zone transfer request from {}", peer);

                    // Read the request line (expects "ZONE_TRANSFER_REQUEST\n")
                    let mut req_buf = [0u8; 128];
                    let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
                    match conn.read(&mut req_buf) {
                        Ok(n) if n > 0 => {
                            let req = String::from_utf8_lossy(&req_buf[..n]);
                            if !req.trim().starts_with("ZONE_TRANSFER_REQUEST") {
                                log::warn!("[cluster/xfr] invalid request from {}: {}", peer, req.trim());
                                continue;
                            }
                        }
                        _ => {
                            log::warn!("[cluster/xfr] failed to read request from {}", peer);
                            continue;
                        }
                    }

                    if let Some(payload) = get_zones() {
                        match serde_json::to_vec(&payload) {
                            Ok(data) => {
                                // Send length-prefixed JSON
                                let len_bytes = (data.len() as u32).to_be_bytes();
                                let _ = conn.write_all(&len_bytes);
                                let _ = conn.write_all(&data);
                                let _ = conn.flush();
                                log::info!(
                                    "[cluster/xfr] sent {} zones to {} ({} bytes)",
                                    payload.zones.len(), peer, data.len()
                                );
                            }
                            Err(e) => {
                                log::error!("[cluster/xfr] serialization failed: {}", e);
                            }
                        }
                    } else {
                        // Send zero-length to indicate no zones
                        let _ = conn.write_all(&0u32.to_be_bytes());
                        let _ = conn.flush();
                    }
                }
                Err(e) => {
                    log::warn!("[cluster/xfr] accept error: {}", e);
                }
            }
        }
    }

    /// Request a full zone transfer from the primary node.
    /// `primary_addr` should be "host:port" of the zone transfer server.
    /// Returns the payload on success.
    pub fn request_zone_transfer(&self, primary_addr: &str) -> Option<ZoneTransferPayload> {
        log::info!("[cluster/xfr] requesting zone transfer from {}", primary_addr);
        let mut conn = match TcpStream::connect_timeout(
            &primary_addr.parse::<SocketAddr>().ok()?,
            Duration::from_secs(10),
        ) {
            Ok(c) => c,
            Err(e) => {
                log::error!("[cluster/xfr] failed to connect to {}: {}", primary_addr, e);
                return None;
            }
        };
        let _ = conn.set_read_timeout(Some(Duration::from_secs(30)));
        let _ = conn.set_write_timeout(Some(Duration::from_secs(5)));

        // Send request
        if conn.write_all(b"ZONE_TRANSFER_REQUEST\n").is_err() {
            log::error!("[cluster/xfr] failed to send request to {}", primary_addr);
            return None;
        }
        let _ = conn.flush();

        // Read length prefix
        let mut len_buf = [0u8; 4];
        if conn.read_exact(&mut len_buf).is_err() {
            log::error!("[cluster/xfr] failed to read length from {}", primary_addr);
            return None;
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 {
            log::info!("[cluster/xfr] primary has no zones to transfer");
            return None;
        }

        // Read payload
        let mut data = vec![0u8; len];
        if conn.read_exact(&mut data).is_err() {
            log::error!("[cluster/xfr] failed to read payload from {}", primary_addr);
            return None;
        }

        match serde_json::from_slice::<ZoneTransferPayload>(&data) {
            Ok(payload) => {
                let zone_count = payload.zones.len();
                let record_count: usize = payload.zones.iter().map(|z| z.records.len()).sum();
                self.record_zone_sync(zone_count, record_count);
                log::info!(
                    "[cluster/xfr] received {} zones ({} records) from {}",
                    zone_count, record_count, primary_addr
                );
                Some(payload)
            }
            Err(e) => {
                log::error!("[cluster/xfr] failed to parse zone transfer payload: {}", e);
                None
            }
        }
    }

    /// Find the primary node address from cluster state for zone transfer.
    /// Returns the address suitable for TCP zone transfer connection.
    pub fn find_primary_transfer_addr(&self) -> Option<String> {
        let timeout = self.config.read().peer_timeout_secs;
        let nodes = self.cluster_state.live_nodes(timeout);
        nodes.iter()
            .find(|n| matches!(n.role, ClusterRole::Leader | ClusterRole::Primary))
            .map(|n| {
                // Convert peer HTTP addr to zone transfer port
                peer_zone_transfer_addr(&n.addr)
            })
    }
}

// ─────────────────────────── Helpers ───────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Convert a peer HTTP base URL (e.g. "http://10.0.0.2:5380") to a gossip UDP address.
/// Extracts the host and uses `CLUSTER_GOSSIP_PORT`.
fn peer_gossip_addr(peer_url: &str) -> String {
    extract_host(peer_url, CLUSTER_GOSSIP_PORT)
}

/// Convert a peer address to a zone transfer TCP address.
fn peer_zone_transfer_addr(peer_url: &str) -> String {
    extract_host(peer_url, CLUSTER_ZONE_TRANSFER_PORT)
}

/// Extract host from a URL-like string and pair with the given port.
fn extract_host(addr: &str, port: u16) -> String {
    // Strip scheme
    let stripped = addr
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    // Strip path
    let host_port = stripped.split('/').next().unwrap_or(stripped);
    // Strip existing port
    let host = if let Some(colon) = host_port.rfind(':') {
        // Check it's not an IPv6 bracket
        if host_port.ends_with(']') {
            host_port
        } else {
            &host_port[..colon]
        }
    } else {
        host_port
    };
    format!("{}:{}", host, port)
}
