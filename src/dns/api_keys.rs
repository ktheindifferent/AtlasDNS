//! API Key Management System
//! 
//! This module provides secure API key generation, validation, and management
//! functionality for the Atlas DNS server.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

/// API key permissions
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiPermission {
    /// Read-only access to DNS records and zones
    Read,
    /// Write access to DNS records and zones
    Write,
    /// Administrative access to server configuration
    Admin,
    /// Access to metrics and analytics
    Metrics,
    /// Access to cache management
    Cache,
    /// Access to user management
    Users,
}

impl ApiPermission {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApiPermission::Read => "read",
            ApiPermission::Write => "write",
            ApiPermission::Admin => "admin",
            ApiPermission::Metrics => "metrics",
            ApiPermission::Cache => "cache",
            ApiPermission::Users => "users",
        }
    }
}

/// API key status
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiKeyStatus {
    Active,
    Disabled,
    Expired,
}

impl ApiKeyStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApiKeyStatus::Active => "active",
            ApiKeyStatus::Disabled => "disabled",
            ApiKeyStatus::Expired => "expired",
        }
    }
}

/// API key information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiKey {
    /// Unique key ID
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Optional description
    pub description: String,
    /// The actual API key (hashed for security)
    pub key_hash: String,
    /// Key preview (first 8 characters + ...)
    pub key_preview: String,
    /// Permissions granted to this key
    pub permissions: Vec<ApiPermission>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last used timestamp
    pub last_used: Option<DateTime<Utc>>,
    /// Current status
    pub status: ApiKeyStatus,
    /// Request count
    pub request_count: u64,
}

impl ApiKey {
    /// Create a new API key
    pub fn new(name: String, description: String, permissions: Vec<ApiPermission>) -> (Self, String) {
        let id = Uuid::new_v4().to_string();
        let raw_key = Self::generate_key();
        let key_hash = Self::hash_key(&raw_key);
        let key_preview = format!("{}...", &raw_key[..8]);
        
        let api_key = ApiKey {
            id,
            name,
            description,
            key_hash,
            key_preview,
            permissions,
            created_at: Utc::now(),
            last_used: None,
            status: ApiKeyStatus::Active,
            request_count: 0,
        };
        
        (api_key, raw_key)
    }
    
    /// Generate a secure random API key
    fn generate_key() -> String {
        let key_id = Uuid::new_v4().to_string().replace("-", "");
        format!("atlas_{}", key_id)
    }
    
    /// Hash an API key for secure storage
    fn hash_key(key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        format!("{:x}", hasher.finalize())
    }
    
    /// Update last used timestamp
    pub fn update_last_used(&mut self) {
        self.last_used = Some(Utc::now());
        self.request_count += 1;
    }
    
    /// Check if key has a specific permission
    pub fn has_permission(&self, permission: &ApiPermission) -> bool {
        self.permissions.contains(permission) || self.permissions.contains(&ApiPermission::Admin)
    }
    
    /// Check if key is valid (active and not expired)
    pub fn is_valid(&self) -> bool {
        matches!(self.status, ApiKeyStatus::Active)
    }
}

/// API Key Manager
pub struct ApiKeyManager {
    keys: Arc<RwLock<HashMap<String, ApiKey>>>, // key_hash -> ApiKey
    key_by_id: Arc<RwLock<HashMap<String, String>>>, // id -> key_hash
}

impl ApiKeyManager {
    /// Create a new API key manager
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            key_by_id: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Generate a new API key
    pub fn generate_key(&self, name: String, description: String, permissions: Vec<ApiPermission>) -> Result<(String, String), String> {
        let (api_key, raw_key) = ApiKey::new(name, description, permissions);
        
        // Store in both maps
        {
            let mut keys = self.keys.write().map_err(|_| "Failed to acquire write lock")?;
            let mut key_by_id = self.key_by_id.write().map_err(|_| "Failed to acquire write lock")?;
            
            keys.insert(api_key.key_hash.clone(), api_key.clone());
            key_by_id.insert(api_key.id.clone(), api_key.key_hash.clone());
        }
        
        log::info!("Generated new API key: {} ({})", api_key.name, api_key.id);
        Ok((api_key.id, raw_key))
    }
    
    /// Validate an API key and return the associated permissions
    pub fn validate_key(&self, raw_key: &str) -> Option<(String, Vec<ApiPermission>)> {
        let key_hash = ApiKey::hash_key(raw_key);
        
        let mut keys = match self.keys.write() {
            Ok(keys) => keys,
            Err(_) => return None,
        };
        
        if let Some(api_key) = keys.get_mut(&key_hash) {
            if api_key.is_valid() {
                api_key.update_last_used();
                return Some((api_key.id.clone(), api_key.permissions.clone()));
            }
        }
        
        None
    }
    
    /// Get all API keys (without sensitive information)
    pub fn list_keys(&self) -> Vec<ApiKey> {
        match self.keys.read() {
            Ok(keys) => keys.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }
    
    /// Get API key by ID
    pub fn get_key_by_id(&self, id: &str) -> Option<ApiKey> {
        let key_by_id = self.key_by_id.read().ok()?;
        let key_hash = key_by_id.get(id)?;
        
        let keys = self.keys.read().ok()?;
        keys.get(key_hash).cloned()
    }
    
    /// Revoke an API key
    pub fn revoke_key(&self, id: &str) -> Result<(), String> {
        let key_by_id = self.key_by_id.read().map_err(|_| "Failed to acquire read lock")?;
        let key_hash = key_by_id.get(id).ok_or("API key not found")?;
        
        let mut keys = self.keys.write().map_err(|_| "Failed to acquire write lock")?;
        if let Some(api_key) = keys.get_mut(key_hash) {
            api_key.status = ApiKeyStatus::Disabled;
            log::info!("Revoked API key: {} ({})", api_key.name, api_key.id);
            Ok(())
        } else {
            Err("API key not found".to_string())
        }
    }
    
    /// Delete an API key
    pub fn delete_key(&self, id: &str) -> Result<(), String> {
        let mut key_by_id = self.key_by_id.write().map_err(|_| "Failed to acquire write lock")?;
        let key_hash = key_by_id.remove(id).ok_or("API key not found")?;
        
        let mut keys = self.keys.write().map_err(|_| "Failed to acquire write lock")?;
        if let Some(api_key) = keys.remove(&key_hash) {
            log::info!("Deleted API key: {} ({})", api_key.name, api_key.id);
            Ok(())
        } else {
            Err("API key not found".to_string())
        }
    }
    
    /// Get count of active API keys
    pub fn get_active_count(&self) -> usize {
        match self.keys.read() {
            Ok(keys) => keys.values()
                .filter(|key| matches!(key.status, ApiKeyStatus::Active))
                .count(),
            Err(_) => 0,
        }
    }
    
    /// Get total request count across all keys
    pub fn get_total_requests(&self) -> u64 {
        match self.keys.read() {
            Ok(keys) => keys.values().map(|key| key.request_count).sum(),
            Err(_) => 0,
        }
    }
}

impl Default for ApiKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// API key authentication middleware result
pub struct AuthResult {
    pub api_key_id: String,
    pub permissions: Vec<ApiPermission>,
}

impl AuthResult {
    pub fn has_permission(&self, permission: &ApiPermission) -> bool {
        self.permissions.contains(permission) || self.permissions.contains(&ApiPermission::Admin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_api_key_generation() {
        let manager = ApiKeyManager::new();
        let permissions = vec![ApiPermission::Read, ApiPermission::Write];
        
        let result = manager.generate_key(
            "Test Key".to_string(),
            "A test API key".to_string(),
            permissions.clone()
        );
        
        assert!(result.is_ok());
        let (id, raw_key) = result.unwrap();
        
        // Test validation
        let auth_result = manager.validate_key(&raw_key);
        assert!(auth_result.is_some());
        
        let (validated_id, validated_permissions) = auth_result.unwrap();
        assert_eq!(id, validated_id);
        assert_eq!(permissions, validated_permissions);
    }
    
    #[test]
    fn test_key_permissions() {
        let permissions = vec![ApiPermission::Read];
        let (api_key, _) = ApiKey::new(
            "Test".to_string(), 
            "Test".to_string(), 
            permissions
        );
        
        assert!(api_key.has_permission(&ApiPermission::Read));
        assert!(!api_key.has_permission(&ApiPermission::Write));
        
        // Admin permission should grant access to everything
        let admin_permissions = vec![ApiPermission::Admin];
        let (admin_key, _) = ApiKey::new(
            "Admin".to_string(),
            "Admin".to_string(),
            admin_permissions
        );
        
        assert!(admin_key.has_permission(&ApiPermission::Read));
        assert!(admin_key.has_permission(&ApiPermission::Write));
        assert!(admin_key.has_permission(&ApiPermission::Cache));
    }
    
    #[test]
    fn test_key_revocation() {
        let manager = ApiKeyManager::new();
        let (id, _) = manager.generate_key(
            "Test".to_string(),
            "Test".to_string(),
            vec![ApiPermission::Read]
        ).unwrap();
        
        // Key should be active initially
        let key = manager.get_key_by_id(&id).unwrap();
        assert_eq!(key.status, ApiKeyStatus::Active);
        
        // Revoke the key
        manager.revoke_key(&id).unwrap();
        
        // Key should now be disabled
        let key = manager.get_key_by_id(&id).unwrap();
        assert_eq!(key.status, ApiKeyStatus::Disabled);
        assert!(!key.is_valid());
    }
}