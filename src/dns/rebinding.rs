//! DNS rebinding attack protection.
//!
//! Blocks DNS responses that return private/RFC1918 IP addresses for public
//! domain names, preventing DNS rebinding attacks.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};

/// Check if an IPv4 address is in a private/RFC1918/loopback/link-local range.
pub fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 10.0.0.0/8
    if octets[0] == 10 { return true; }
    // 172.16.0.0/12
    if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) { return true; }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 { return true; }
    // 127.0.0.0/8 loopback
    if octets[0] == 127 { return true; }
    // 169.254.0.0/16 link-local
    if octets[0] == 169 && octets[1] == 254 { return true; }
    false
}

/// Check if an IpAddr is private.
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(*v4),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// DNS rebinding protection configuration and state.
pub struct RebindingProtection {
    /// Whether rebinding protection is enabled.
    pub enabled: bool,
    /// Domains allowed to return private IPs (e.g., internal services, split-horizon DNS).
    pub whitelist: Arc<RwLock<HashSet<String>>>,
}

impl RebindingProtection {
    pub fn new() -> Self {
        Self {
            enabled: true,
            whitelist: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Returns true if the response for `domain` returning `ip` should be blocked.
    pub fn should_block(&self, domain: &str, ip: &IpAddr) -> bool {
        if !self.enabled {
            return false;
        }
        if !is_private_ip(ip) {
            return false; // Public IP - fine
        }
        // Private IP - check if domain is whitelisted
        if let Ok(wl) = self.whitelist.read() {
            // Check exact match and suffix match
            if wl.contains(domain) {
                return false;
            }
            // Check suffix: if whitelist has "example.com", allow "foo.example.com"
            for allowed in wl.iter() {
                if domain.ends_with(&format!(".{}", allowed)) || domain == allowed.as_str() {
                    return false;
                }
            }
        }
        true
    }

    pub fn add_to_whitelist(&self, domain: String) {
        if let Ok(mut wl) = self.whitelist.write() {
            wl.insert(domain);
        }
    }
}

impl Default for RebindingProtection {
    fn default() -> Self {
        Self::new()
    }
}
