/// Secure Password Storage and Handling
/// 
/// Provides secure password handling to avoid storing plaintext passwords
/// in memory, using zeroing, encryption at rest, and secure comparison.

use std::sync::Arc;
use std::fmt;
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Secure string that zeros memory on drop
#[derive(Clone)]
pub struct SecureString {
    data: Vec<u8>,
}

impl SecureString {
    /// Create a new secure string from a regular string
    pub fn new(s: &str) -> Self {
        Self {
            data: s.as_bytes().to_vec(),
        }
    }

    /// Create from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { data: bytes }
    }

    /// Get the string value (use carefully)
    pub fn reveal(&self) -> String {
        String::from_utf8_lossy(&self.data).to_string()
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Clear the memory
    pub fn clear(&mut self) {
        // Overwrite with zeros
        for byte in self.data.iter_mut() {
            *byte = 0;
        }
        self.data.clear();
    }

    /// Secure comparison (constant time)
    pub fn secure_compare(&self, other: &SecureString) -> bool {
        if self.data.len() != other.data.len() {
            return false;
        }

        let mut result = 0u8;
        for (a, b) in self.data.iter().zip(other.data.iter()) {
            result |= a ^ b;
        }
        result == 0
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.clear();
    }
}

impl fmt::Debug for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureString[REDACTED]")
    }
}

impl fmt::Display for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

/// Encrypted password storage
pub struct SecurePasswordStore {
    /// Encrypted password hashes
    passwords: Arc<RwLock<Vec<EncryptedPassword>>>,
    /// Encryption key (derived from system entropy)
    encryption_key: Vec<u8>,
}

#[derive(Clone)]
struct EncryptedPassword {
    /// Username (not encrypted for lookup)
    username: String,
    /// Encrypted bcrypt hash
    encrypted_hash: Vec<u8>,
    /// Nonce for encryption
    nonce: Vec<u8>,
}

impl SecurePasswordStore {
    /// Create a new secure password store
    pub fn new() -> Self {
        // Derive encryption key from system entropy
        let mut hasher = Sha256::new();
        hasher.update(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_le_bytes()
        );
        
        // Add more entropy from memory addresses
        let ptr1 = &hasher as *const _ as usize;
        let ptr2 = Box::new(42);
        let ptr2_addr = &*ptr2 as *const i32 as usize;
        
        hasher.update(ptr1.to_le_bytes());
        hasher.update(ptr2_addr.to_le_bytes());
        hasher.update(std::process::id().to_le_bytes());
        
        let encryption_key = hasher.finalize().to_vec();

        Self {
            passwords: Arc::new(RwLock::new(Vec::new())),
            encryption_key,
        }
    }

    /// Store a password hash securely
    pub fn store_password(&self, username: &str, password_hash: &[u8]) -> Result<(), String> {
        let nonce = self.generate_nonce();
        let encrypted_hash = self.encrypt_data(password_hash, &nonce);
        
        let encrypted_password = EncryptedPassword {
            username: username.to_string(),
            encrypted_hash,
            nonce,
        };

        let mut passwords = self.passwords.write();
        
        // Remove old entry if exists
        passwords.retain(|p| p.username != username);
        
        // Add new entry
        passwords.push(encrypted_password);
        
        Ok(())
    }

    /// Retrieve and decrypt a password hash
    pub fn get_password_hash(&self, username: &str) -> Option<SecureString> {
        let passwords = self.passwords.read();
        
        passwords.iter()
            .find(|p| p.username == username)
            .map(|p| {
                let decrypted = self.decrypt_data(&p.encrypted_hash, &p.nonce);
                SecureString::from_bytes(decrypted)
            })
    }

    /// Remove a password from storage
    pub fn remove_password(&self, username: &str) -> bool {
        let mut passwords = self.passwords.write();
        let initial_len = passwords.len();
        passwords.retain(|p| p.username != username);
        passwords.len() != initial_len
    }

    /// Generate a nonce for encryption
    fn generate_nonce(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_le_bytes()
        );
        hasher.update(&self.encryption_key);
        hasher.finalize()[..16].to_vec()
    }

    /// Simple XOR encryption (should use AES in production)
    fn encrypt_data(&self, data: &[u8], nonce: &[u8]) -> Vec<u8> {
        let mut key_stream = Vec::new();
        let mut hasher = Sha256::new();
        hasher.update(&self.encryption_key);
        hasher.update(nonce);
        
        // Generate key stream
        for i in 0..((data.len() / 32) + 1) {
            let mut h = hasher.clone();
            h.update(i.to_le_bytes());
            key_stream.extend_from_slice(&h.finalize());
        }
        
        // XOR with data
        data.iter()
            .zip(key_stream.iter())
            .map(|(d, k)| d ^ k)
            .collect()
    }

    /// Decrypt data
    fn decrypt_data(&self, encrypted: &[u8], nonce: &[u8]) -> Vec<u8> {
        // XOR encryption is symmetric
        self.encrypt_data(encrypted, nonce)
    }

    /// Clear all stored passwords
    pub fn clear_all(&self) {
        let mut passwords = self.passwords.write();
        
        // Clear each encrypted hash
        for password in passwords.iter_mut() {
            for byte in password.encrypted_hash.iter_mut() {
                *byte = 0;
            }
            for byte in password.nonce.iter_mut() {
                *byte = 0;
            }
        }
        
        passwords.clear();
    }
}

impl Drop for SecurePasswordStore {
    fn drop(&mut self) {
        self.clear_all();
    }
}

/// Password validator with secure handling
pub struct SecurePasswordValidator {
    /// Minimum password length
    min_length: usize,
    /// Require uppercase
    require_uppercase: bool,
    /// Require lowercase
    require_lowercase: bool,
    /// Require digits
    require_digits: bool,
    /// Require special characters
    require_special: bool,
}

impl Default for SecurePasswordValidator {
    fn default() -> Self {
        Self {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_digits: true,
            require_special: false,
        }
    }
}

impl SecurePasswordValidator {
    /// Validate a password securely
    pub fn validate(&self, password: &SecureString) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        let password_str = password.reveal();
        
        if password_str.len() < self.min_length {
            errors.push(format!("Password must be at least {} characters", self.min_length));
        }
        
        if self.require_uppercase && !password_str.chars().any(|c| c.is_uppercase()) {
            errors.push("Password must contain at least one uppercase letter".to_string());
        }
        
        if self.require_lowercase && !password_str.chars().any(|c| c.is_lowercase()) {
            errors.push("Password must contain at least one lowercase letter".to_string());
        }
        
        if self.require_digits && !password_str.chars().any(|c| c.is_digit(10)) {
            errors.push("Password must contain at least one digit".to_string());
        }
        
        if self.require_special && !password_str.chars().any(|c| !c.is_alphanumeric()) {
            errors.push("Password must contain at least one special character".to_string());
        }
        
        // Clear the temporary string
        drop(password_str);
        
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Generate a secure password
    pub fn generate_password(&self, length: usize) -> SecureString {
        use rand::Rng;
        
        let charset: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()"
            .chars()
            .collect();
        
        let mut rng = rand::thread_rng();
        let password: String = (0..length)
            .map(|_| charset[rng.gen_range(0, charset.len())])
            .collect();
        
        SecureString::new(&password)
    }
}

/// Temporary password holder that auto-clears
pub struct TemporaryPassword {
    password: Option<SecureString>,
    created_at: SystemTime,
    ttl_seconds: u64,
}

impl TemporaryPassword {
    /// Create a new temporary password holder
    pub fn new(password: SecureString, ttl_seconds: u64) -> Self {
        Self {
            password: Some(password),
            created_at: SystemTime::now(),
            ttl_seconds,
        }
    }

    /// Get the password if not expired
    pub fn get(&mut self) -> Option<&SecureString> {
        if let Ok(elapsed) = self.created_at.elapsed() {
            if elapsed.as_secs() > self.ttl_seconds {
                self.password = None;
            }
        }
        self.password.as_ref()
    }

    /// Clear the password immediately
    pub fn clear(&mut self) {
        self.password = None;
    }
}

impl Drop for TemporaryPassword {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_string() {
        let mut secure = SecureString::new("test_password");
        assert_eq!(secure.reveal(), "test_password");
        
        secure.clear();
        assert_eq!(secure.reveal(), "");
    }

    #[test]
    fn test_secure_compare() {
        let secure1 = SecureString::new("password123");
        let secure2 = SecureString::new("password123");
        let secure3 = SecureString::new("different");
        
        assert!(secure1.secure_compare(&secure2));
        assert!(!secure1.secure_compare(&secure3));
    }

    #[test]
    fn test_password_store() {
        let store = SecurePasswordStore::new();
        let hash = b"$2b$12$test_hash";
        
        // Store password
        store.store_password("testuser", hash).unwrap();
        
        // Retrieve password
        let retrieved = store.get_password_hash("testuser").unwrap();
        assert_eq!(retrieved.as_bytes(), hash);
        
        // Remove password
        assert!(store.remove_password("testuser"));
        assert!(store.get_password_hash("testuser").is_none());
    }

    #[test]
    fn test_password_validation() {
        let validator = SecurePasswordValidator::default();
        
        let weak = SecureString::new("weak");
        assert!(validator.validate(&weak).is_err());
        
        let strong = SecureString::new("Strong1Password");
        assert!(validator.validate(&strong).is_ok());
    }

    #[test]
    fn test_temporary_password() {
        let password = SecureString::new("temporary");
        let mut temp = TemporaryPassword::new(password, 1);
        
        assert!(temp.get().is_some());
        
        std::thread::sleep(std::time::Duration::from_secs(2));
        assert!(temp.get().is_none());
    }
}