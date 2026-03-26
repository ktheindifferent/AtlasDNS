//! Per-client DNS blocking rules.
//!
//! [`ClientRulesStore`] holds per-IP override rules that take precedence over
//! the global blocklist. A rule can Allow, Block, or Redirect a domain pattern
//! for a specific client IP.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Action to take when a client rule matches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "value")]
pub enum RuleAction {
    /// Block the query (NXDOMAIN).
    Block,
    /// Allow the query (bypass global blocklist).
    Allow,
    /// Redirect to a different IP address.
    Redirect(String),
}

/// A single per-client DNS rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRule {
    /// Unique rule ID.
    pub id: String,
    /// Client IP this rule applies to.
    pub client_ip: String,
    /// Domain pattern: exact domain or wildcard prefix `*.example.com`.
    pub domain_pattern: String,
    /// Action to take when the rule matches.
    pub action: RuleAction,
    /// Unix timestamp when the rule was created.
    pub created_at: u64,
}

impl ClientRule {
    /// Return true if `domain` matches this rule's pattern.
    pub fn matches(&self, domain: &str) -> bool {
        let domain = domain.to_ascii_lowercase();
        let pattern = self.domain_pattern.to_ascii_lowercase();
        if let Some(suffix) = pattern.strip_prefix("*.") {
            domain == suffix || domain.ends_with(&format!(".{}", suffix))
        } else {
            domain == pattern
        }
    }
}

/// Thread-safe store for per-client rules.
pub struct ClientRulesStore {
    /// client_ip → Vec<ClientRule>
    rules: RwLock<HashMap<String, Vec<ClientRule>>>,
}

impl ClientRulesStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { rules: RwLock::new(HashMap::new()) })
    }

    /// Add a rule, generating an ID if not set.
    pub fn add_rule(&self, mut rule: ClientRule) {
        if rule.id.is_empty() {
            rule.id = uuid::Uuid::new_v4().to_string();
        }
        if rule.created_at == 0 {
            rule.created_at = now_secs();
        }
        let mut map = self.rules.write();
        map.entry(rule.client_ip.clone()).or_default().push(rule);
    }

    /// Return all rules for a client IP.
    pub fn get_rules(&self, client_ip: &str) -> Vec<ClientRule> {
        self.rules.read().get(client_ip).cloned().unwrap_or_default()
    }

    /// Return all rules across all clients.
    pub fn all_rules(&self) -> Vec<ClientRule> {
        self.rules.read().values().flatten().cloned().collect()
    }

    /// Delete a rule by (client_ip, rule_id). Returns true if found and deleted.
    pub fn delete_rule(&self, client_ip: &str, rule_id: &str) -> bool {
        let mut map = self.rules.write();
        if let Some(list) = map.get_mut(client_ip) {
            let before = list.len();
            list.retain(|r| r.id != rule_id);
            return list.len() < before;
        }
        false
    }

    /// Check whether `domain` from `client_ip` matches any rule.
    /// Returns the matching action if found.
    pub fn check_query(&self, client_ip: &str, domain: &str) -> Option<RuleAction> {
        let map = self.rules.read();
        map.get(client_ip)?
            .iter()
            .find(|r| r.matches(domain))
            .map(|r| r.action.clone())
    }

    /// Bulk-load rules (called during startup from persistent storage).
    pub fn load_from_storage(&self, rules: Vec<ClientRule>) {
        let mut map = self.rules.write();
        map.clear();
        for rule in rules {
            map.entry(rule.client_ip.clone()).or_default().push(rule);
        }
    }
}
