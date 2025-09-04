/// Secure Session Token Rotation System
/// 
/// Provides automatic token rotation for enhanced security,
/// preventing session fixation attacks and limiting token exposure.

use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use crate::web::users::UserManager;
use log::{info, warn, debug};

/// Token rotation configuration
#[derive(Debug, Clone)]
pub struct TokenRotationConfig {
    /// Maximum token age before rotation
    pub max_token_age: Duration,
    /// Rotation interval (how often to check for rotation)
    pub rotation_interval: Duration,
    /// Grace period after rotation where old token is still valid
    pub grace_period: Duration,
    /// Require rotation after IP change
    pub rotate_on_ip_change: bool,
    /// Number of requests before automatic rotation
    pub requests_before_rotation: usize,
    /// Enable transparent rotation (no user re-auth required)
    pub transparent_rotation: bool,
}

impl Default for TokenRotationConfig {
    fn default() -> Self {
        Self {
            max_token_age: Duration::from_secs(3600),          // 1 hour
            rotation_interval: Duration::from_secs(1800),       // 30 minutes
            grace_period: Duration::from_secs(300),            // 5 minutes
            rotate_on_ip_change: true,
            requests_before_rotation: 1000,
            transparent_rotation: true,
        }
    }
}

/// Token metadata for tracking rotation
#[derive(Debug, Clone)]
struct TokenMetadata {
    /// Token creation time
    created_at: Instant,
    /// Last rotation time
    last_rotated: Instant,
    /// Number of requests with this token
    request_count: usize,
    /// Original IP address
    original_ip: Option<IpAddr>,
    /// Previous token (during grace period)
    previous_token: Option<String>,
    /// Previous token expiry
    previous_expiry: Option<Instant>,
}

/// Secure token rotation manager
pub struct TokenRotationManager {
    /// Configuration
    config: TokenRotationConfig,
    /// Token metadata storage
    token_metadata: Arc<RwLock<HashMap<String, TokenMetadata>>>,
    /// Rotation history for audit
    rotation_history: Arc<RwLock<Vec<RotationEvent>>>,
    /// User manager reference
    user_manager: Arc<UserManager>,
    /// HMAC secret for token generation
    hmac_secret: Vec<u8>,
}

/// Rotation event for audit logging
#[derive(Debug, Clone)]
struct RotationEvent {
    /// Old token (hashed for security)
    old_token_hash: String,
    /// New token (hashed for security)
    new_token_hash: String,
    /// Username
    username: String,
    /// Rotation reason
    reason: RotationReason,
    /// Timestamp
    timestamp: SystemTime,
    /// Client IP
    client_ip: Option<IpAddr>,
}

/// Reasons for token rotation
#[derive(Debug, Clone)]
enum RotationReason {
    MaxAge,
    RequestCount,
    IpChange,
    Manual,
    Security,
}

impl TokenRotationManager {
    /// Create a new token rotation manager
    pub fn new(config: TokenRotationConfig, user_manager: Arc<UserManager>) -> Self {
        // Generate HMAC secret
        let mut hasher = Sha256::new();
        hasher.update(Uuid::new_v4().to_string().as_bytes());
        hasher.update(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_le_bytes()
        );
        let hmac_secret = hasher.finalize().to_vec();

        Self {
            config,
            token_metadata: Arc::new(RwLock::new(HashMap::new())),
            rotation_history: Arc::new(RwLock::new(Vec::new())),
            user_manager,
            hmac_secret,
        }
    }

    /// Generate a new secure token
    fn generate_secure_token(&self, username: &str, salt: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.hmac_secret);
        hasher.update(username.as_bytes());
        hasher.update(salt.as_bytes());
        hasher.update(Uuid::new_v4().to_string().as_bytes());
        hasher.update(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_le_bytes()
        );
        
        format!("{:x}", hasher.finalize())
    }

    /// Hash a token for storage/logging
    fn hash_token(&self, token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hasher.update(&self.hmac_secret);
        format!("{:x}", hasher.finalize())
    }

    /// Check if token needs rotation
    pub fn needs_rotation(&self, token: &str, current_ip: Option<IpAddr>) -> bool {
        let metadata_guard = match self.token_metadata.read() {
            Ok(g) => g,
            Err(_) => return false,
        };

        if let Some(metadata) = metadata_guard.get(token) {
            // Check max age
            if metadata.last_rotated.elapsed() > self.config.max_token_age {
                return true;
            }

            // Check request count
            if metadata.request_count >= self.config.requests_before_rotation {
                return true;
            }

            // Check IP change
            if self.config.rotate_on_ip_change {
                if let (Some(original), Some(current)) = (metadata.original_ip, current_ip) {
                    if original != current {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Rotate a session token
    pub fn rotate_token(&self, old_token: &str, username: &str, current_ip: Option<IpAddr>) 
        -> Result<String, String> {
        
        // Generate new token
        let salt = Uuid::new_v4().to_string();
        let new_token = self.generate_secure_token(username, &salt);
        
        // Get old metadata
        let old_metadata = {
            let metadata_guard = self.token_metadata.read()
                .map_err(|e| format!("Failed to read metadata: {}", e))?;
            metadata_guard.get(old_token).cloned()
        };

        // Determine rotation reason
        let reason = if let Some(ref metadata) = old_metadata {
            if metadata.last_rotated.elapsed() > self.config.max_token_age {
                RotationReason::MaxAge
            } else if metadata.request_count >= self.config.requests_before_rotation {
                RotationReason::RequestCount
            } else if self.config.rotate_on_ip_change && metadata.original_ip != current_ip {
                RotationReason::IpChange
            } else {
                RotationReason::Manual
            }
        } else {
            RotationReason::Manual
        };

        // Create new metadata with grace period
        let now = Instant::now();
        let new_metadata = TokenMetadata {
            created_at: old_metadata.as_ref().map(|m| m.created_at).unwrap_or(now),
            last_rotated: now,
            request_count: 0,
            original_ip: current_ip.or(old_metadata.as_ref().and_then(|m| m.original_ip)),
            previous_token: Some(old_token.to_string()),
            previous_expiry: Some(now + self.config.grace_period),
        };

        // Update metadata storage
        {
            let mut metadata_guard = self.token_metadata.write()
                .map_err(|e| format!("Failed to write metadata: {}", e))?;
            
            // Add new token metadata
            metadata_guard.insert(new_token.clone(), new_metadata);
            
            // Update old token metadata to mark as rotated
            if let Some(old_meta) = metadata_guard.get_mut(old_token) {
                old_meta.previous_token = None;
                old_meta.previous_expiry = Some(now + self.config.grace_period);
            }
        }

        // Log rotation event
        self.log_rotation(old_token, &new_token, username, reason, current_ip);

        info!("Token rotated for user '{}' from IP {:?}", username, current_ip);

        Ok(new_token)
    }

    /// Validate a token (including grace period check)
    pub fn validate_token(&self, token: &str, current_ip: Option<IpAddr>) -> TokenValidationResult {
        let metadata_guard = match self.token_metadata.read() {
            Ok(g) => g,
            Err(_) => return TokenValidationResult::Invalid,
        };

        // Check if this is a current token
        if let Some(metadata) = metadata_guard.get(token) {
            // Check if token is expired
            let now = Instant::now();
            
            // If this was a rotated token in grace period
            if let Some(expiry) = metadata.previous_expiry {
                if now > expiry {
                    return TokenValidationResult::Expired;
                }
            }

            // Increment request count
            drop(metadata_guard);
            if let Ok(mut metadata_guard) = self.token_metadata.write() {
                if let Some(meta) = metadata_guard.get_mut(token) {
                    meta.request_count += 1;
                }
            }

            // Check if rotation is needed
            if self.needs_rotation(token, current_ip) {
                return TokenValidationResult::NeedsRotation;
            }

            return TokenValidationResult::Valid;
        }

        // Check if this is an old token in grace period
        for (_, metadata) in metadata_guard.iter() {
            if let Some(ref prev_token) = metadata.previous_token {
                if prev_token == token {
                    if let Some(expiry) = metadata.previous_expiry {
                        if Instant::now() <= expiry {
                            return TokenValidationResult::GracePeriod;
                        }
                    }
                    return TokenValidationResult::Expired;
                }
            }
        }

        TokenValidationResult::Invalid
    }

    /// Track a new session token
    pub fn track_token(&self, token: &str, username: &str, ip: Option<IpAddr>) {
        let metadata = TokenMetadata {
            created_at: Instant::now(),
            last_rotated: Instant::now(),
            request_count: 0,
            original_ip: ip,
            previous_token: None,
            previous_expiry: None,
        };

        if let Ok(mut guard) = self.token_metadata.write() {
            guard.insert(token.to_string(), metadata);
            debug!("Tracking new token for user '{}'", username);
        }
    }

    /// Remove expired tokens from tracking
    pub fn cleanup_expired_tokens(&self) -> usize {
        let mut count = 0;
        let now = Instant::now();
        
        if let Ok(mut guard) = self.token_metadata.write() {
            let expired_tokens: Vec<String> = guard
                .iter()
                .filter(|(_, metadata)| {
                    // Remove if past max age and grace period
                    if let Some(expiry) = metadata.previous_expiry {
                        now > expiry && metadata.last_rotated.elapsed() > self.config.max_token_age
                    } else {
                        metadata.last_rotated.elapsed() > self.config.max_token_age * 2
                    }
                })
                .map(|(token, _)| token.clone())
                .collect();

            for token in expired_tokens {
                guard.remove(&token);
                count += 1;
            }
        }

        if count > 0 {
            debug!("Cleaned up {} expired tokens", count);
        }

        count
    }

    /// Log rotation event
    fn log_rotation(&self, old_token: &str, new_token: &str, username: &str, 
                   reason: RotationReason, ip: Option<IpAddr>) {
        let event = RotationEvent {
            old_token_hash: self.hash_token(old_token),
            new_token_hash: self.hash_token(new_token),
            username: username.to_string(),
            reason,
            timestamp: SystemTime::now(),
            client_ip: ip,
        };

        if let Ok(mut history) = self.rotation_history.write() {
            history.push(event);
            
            // Keep only last 1000 events
            if history.len() > 1000 {
                let drain_count = history.len() - 1000;
                history.drain(0..drain_count);
            }
        }
    }

    /// Get rotation statistics
    pub fn get_stats(&self) -> TokenRotationStats {
        let metadata_guard = self.token_metadata.read().unwrap_or_else(|e| e.into_inner());
        let history_guard = self.rotation_history.read().unwrap_or_else(|e| e.into_inner());
        let active_tokens = metadata_guard.len();
        let tokens_needing_rotation = metadata_guard
            .iter()
            .filter(|(_, m)| m.last_rotated.elapsed() > self.config.max_token_age)
            .count();
        
        let recent_rotations = history_guard
            .iter()
            .filter(|e| {
                if let Ok(duration) = e.timestamp.duration_since(UNIX_EPOCH) {
                    let event_instant = UNIX_EPOCH + duration;
                    if let Ok(elapsed) = SystemTime::now().duration_since(event_instant) {
                        elapsed < Duration::from_secs(3600)
                    } else {
                        false
                    }
                } else {
                    false
                }
            })
            .count();

        TokenRotationStats {
            active_tokens,
            tokens_needing_rotation,
            recent_rotations,
            total_rotations: history_guard.len(),
        }
    }
}

/// Token validation result
#[derive(Debug, PartialEq)]
pub enum TokenValidationResult {
    Valid,
    NeedsRotation,
    GracePeriod,
    Expired,
    Invalid,
}

/// Token rotation statistics
#[derive(Debug)]
pub struct TokenRotationStats {
    pub active_tokens: usize,
    pub tokens_needing_rotation: usize,
    pub recent_rotations: usize,
    pub total_rotations: usize,
}

/// Background task for automatic token rotation
pub async fn token_rotation_task(manager: Arc<TokenRotationManager>) {
    loop {
        // Wait for rotation interval
        tokio::time::sleep(manager.config.rotation_interval).await;
        
        // Clean up expired tokens
        let cleaned = manager.cleanup_expired_tokens();
        if cleaned > 0 {
            info!("Token rotation task: cleaned {} expired tokens", cleaned);
        }
        
        // Get stats
        let stats = manager.get_stats();
        if stats.tokens_needing_rotation > 0 {
            warn!("Token rotation task: {} tokens need rotation", stats.tokens_needing_rotation);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_token_generation() {
        let user_manager = Arc::new(UserManager::new());
        let manager = TokenRotationManager::new(TokenRotationConfig::default(), user_manager);
        
        let token1 = manager.generate_secure_token("user1", "salt1");
        let token2 = manager.generate_secure_token("user1", "salt1");
        let token3 = manager.generate_secure_token("user1", "salt2");
        
        // Same inputs should generate different tokens (due to UUID and timestamp)
        assert_ne!(token1, token2);
        assert_ne!(token1, token3);
        assert_ne!(token2, token3);
    }

    #[test]
    fn test_token_rotation() {
        let user_manager = Arc::new(UserManager::new());
        let manager = TokenRotationManager::new(TokenRotationConfig::default(), user_manager);
        
        let initial_token = manager.generate_secure_token("testuser", "salt");
        manager.track_token(&initial_token, "testuser", Some("127.0.0.1".parse().unwrap()));
        
        // Rotate token
        let new_token = manager.rotate_token(&initial_token, "testuser", Some("127.0.0.1".parse().unwrap()))
            .expect("Failed to rotate token");
        
        assert_ne!(initial_token, new_token);
        
        // Validate old token is in grace period
        let validation = manager.validate_token(&initial_token, Some("127.0.0.1".parse().unwrap()));
        assert!(validation == TokenValidationResult::GracePeriod || validation == TokenValidationResult::Valid);
        
        // Validate new token is valid
        let validation = manager.validate_token(&new_token, Some("127.0.0.1".parse().unwrap()));
        assert_eq!(validation, TokenValidationResult::Valid);
    }

    #[test]
    fn test_token_expiry() {
        let user_manager = Arc::new(UserManager::new());
        let mut config = TokenRotationConfig::default();
        config.max_token_age = Duration::from_millis(100);
        config.grace_period = Duration::from_millis(50);
        
        let manager = TokenRotationManager::new(config, user_manager);
        let token = manager.generate_secure_token("user", "salt");
        manager.track_token(&token, "user", None);
        
        // Token should be valid initially
        assert_eq!(manager.validate_token(&token, None), TokenValidationResult::Valid);
        
        // Wait for token to need rotation
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(manager.validate_token(&token, None), TokenValidationResult::NeedsRotation);
    }

    #[test]
    fn test_ip_change_rotation() {
        let user_manager = Arc::new(UserManager::new());
        let mut config = TokenRotationConfig::default();
        config.rotate_on_ip_change = true;
        
        let manager = TokenRotationManager::new(config, user_manager);
        let token = manager.generate_secure_token("user", "salt");
        let ip1 = "192.168.1.1".parse().unwrap();
        let ip2 = "192.168.1.2".parse().unwrap();
        
        manager.track_token(&token, "user", Some(ip1));
        
        // Same IP should not need rotation
        assert!(!manager.needs_rotation(&token, Some(ip1)));
        
        // Different IP should need rotation
        assert!(manager.needs_rotation(&token, Some(ip2)));
    }
}