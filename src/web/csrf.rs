/// CSRF Protection Module
/// 
/// Provides Cross-Site Request Forgery (CSRF) protection for web forms
/// using synchronizer token pattern.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use base64;
use uuid::Uuid;
use tiny_http::{Request, Header};

use crate::web::{WebError, Result};

type HmacSha256 = Hmac<Sha256>;

/// CSRF token expiration time (1 hour)
const TOKEN_EXPIRY_SECONDS: u64 = 3600;

/// CSRF token header name
const CSRF_HEADER: &str = "X-CSRF-Token";

/// CSRF token form field name
const CSRF_FIELD: &str = "csrf_token";

/// CSRF token cookie name
const CSRF_COOKIE: &str = "csrf_token";

/// CSRF Protection Manager
pub struct CsrfProtection {
    /// Secret key for signing tokens
    secret_key: Vec<u8>,
    /// Store of valid tokens with expiration times
    tokens: Arc<RwLock<HashMap<String, u64>>>,
}

impl CsrfProtection {
    /// Create a new CSRF protection manager
    pub fn new(secret_key: &str) -> Self {
        Self {
            secret_key: secret_key.as_bytes().to_vec(),
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate a new CSRF token for a session
    pub fn generate_token(&self, session_id: &str) -> Result<String> {
        // Create unique token ID
        let token_id = Uuid::new_v4().to_string();
        
        // Get current timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| WebError::InternalError(format!("Time error: {}", e)))?
            .as_secs();
        
        // Create token payload
        let payload = format!("{}:{}:{}", token_id, session_id, timestamp);
        
        // Sign the token
        let signature = self.sign_token(&payload)?;
        
        // Combine payload and signature
        let token = format!("{}.{}", 
            base64::encode(&payload), 
            base64::encode(&signature)
        );
        
        // Store token with expiration
        let mut tokens = self.tokens.write()
            .map_err(|_| WebError::LockError)?;
        tokens.insert(token_id, timestamp + TOKEN_EXPIRY_SECONDS);
        
        // Clean expired tokens periodically
        self.cleanup_expired_tokens(&mut tokens);
        
        Ok(token)
    }
    
    /// Validate a CSRF token
    pub fn validate_token(&self, token: &str, session_id: &str) -> Result<bool> {
        // Split token into payload and signature
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 2 {
            log::warn!("Invalid CSRF token format");
            return Ok(false);
        }
        
        // Decode payload
        let payload = base64::decode(parts[0])
            .map_err(|e| WebError::InvalidInput(format!("Invalid token encoding: {}", e)))?;
        let payload = String::from_utf8(payload)
            .map_err(|e| WebError::InvalidInput(format!("Invalid token payload: {}", e)))?;
        
        // Verify signature
        let expected_signature = self.sign_token(&payload)?;
        let provided_signature = base64::decode(parts[1])
            .map_err(|e| WebError::InvalidInput(format!("Invalid signature encoding: {}", e)))?;
        
        if expected_signature != provided_signature {
            log::warn!("CSRF token signature mismatch");
            return Ok(false);
        }
        
        // Parse payload
        let payload_parts: Vec<&str> = payload.split(':').collect();
        if payload_parts.len() != 3 {
            log::warn!("Invalid CSRF token payload format");
            return Ok(false);
        }
        
        let token_id = payload_parts[0];
        let token_session_id = payload_parts[1];
        let _timestamp = payload_parts[2].parse::<u64>()
            .map_err(|e| WebError::InvalidInput(format!("Invalid timestamp: {}", e)))?;
        
        // Verify session ID matches
        if token_session_id != session_id {
            log::warn!("CSRF token session ID mismatch");
            return Ok(false);
        }
        
        // Check if token exists and is not expired
        let tokens = self.tokens.read()
            .map_err(|_| WebError::LockError)?;
        
        if let Some(&expiry) = tokens.get(token_id) {
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| WebError::InternalError(format!("Time error: {}", e)))?
                .as_secs();
            
            if current_time <= expiry {
                return Ok(true);
            } else {
                log::debug!("CSRF token expired");
            }
        } else {
            log::debug!("CSRF token not found in store");
        }
        
        Ok(false)
    }
    
    /// Sign a token payload
    fn sign_token(&self, payload: &str) -> Result<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(&self.secret_key)
            .map_err(|e| WebError::InternalError(format!("HMAC error: {}", e)))?;
        mac.update(payload.as_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }
    
    /// Clean up expired tokens
    fn cleanup_expired_tokens(&self, tokens: &mut HashMap<String, u64>) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        tokens.retain(|_, &mut expiry| expiry > current_time);
    }
    
    /// Extract CSRF token from request
    pub fn extract_token_from_request(&self, request: &Request) -> Option<String> {
        // Check header first
        for header in request.headers() {
            if header.field.to_string().eq_ignore_ascii_case(CSRF_HEADER) {
                return Some(header.value.to_string());
            }
        }
        
        // Check form data (would need to be extracted from body)
        // This would require parsing the request body
        
        // Check cookie
        for header in request.headers() {
            if header.field.to_string().eq_ignore_ascii_case("Cookie") {
                let cookies = header.value.as_str();
                for cookie in cookies.split(';') {
                    let cookie = cookie.trim();
                    if cookie.starts_with(&format!("{}=", CSRF_COOKIE)) {
                        return Some(cookie[CSRF_COOKIE.len() + 1..].to_string());
                    }
                }
            }
        }
        
        None
    }
    
    /// Validate request with CSRF protection
    pub fn validate_request(&self, request: &Request, session_id: &str) -> Result<bool> {
        // Skip CSRF check for safe methods
        let method = request.method().as_str();
        if method == "GET" || method == "HEAD" || method == "OPTIONS" {
            return Ok(true);
        }
        
        // Extract token from request
        let token = self.extract_token_from_request(request)
            .ok_or_else(|| WebError::InvalidRequest)?;
        
        // Validate token
        self.validate_token(&token, session_id)
    }
    
    /// Invalidate a CSRF token
    pub fn invalidate_token(&self, token: &str) -> Result<()> {
        // Parse token to get ID
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 2 {
            return Err(WebError::InvalidInput("Invalid token format".to_string()));
        }
        
        let payload = base64::decode(parts[0])
            .map_err(|e| WebError::InvalidInput(format!("Invalid token encoding: {}", e)))?;
        let payload = String::from_utf8(payload)
            .map_err(|e| WebError::InvalidInput(format!("Invalid token payload: {}", e)))?;
        
        let payload_parts: Vec<&str> = payload.split(':').collect();
        if payload_parts.len() != 3 {
            return Err(WebError::InvalidInput("Invalid token payload".to_string()));
        }
        
        let token_id = payload_parts[0];
        
        // Remove token from store
        let mut tokens = self.tokens.write()
            .map_err(|_| WebError::LockError)?;
        tokens.remove(token_id);
        
        Ok(())
    }
    
    /// Generate HTML meta tag for CSRF token
    pub fn generate_meta_tag(&self, session_id: &str) -> Result<String> {
        let token = self.generate_token(session_id)?;
        Ok(format!(
            r#"<meta name="csrf-token" content="{}" />"#,
            html_escape(&token)
        ))
    }
    
    /// Generate HTML hidden input for CSRF token
    pub fn generate_hidden_input(&self, session_id: &str) -> Result<String> {
        let token = self.generate_token(session_id)?;
        Ok(format!(
            r#"<input type="hidden" name="{}" value="{}" />"#,
            CSRF_FIELD,
            html_escape(&token)
        ))
    }
}

/// HTML escape helper
fn html_escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#x27;".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

/// Middleware for automatic CSRF protection
pub struct CsrfMiddleware {
    csrf_protection: Arc<CsrfProtection>,
}

impl CsrfMiddleware {
    pub fn new(csrf_protection: Arc<CsrfProtection>) -> Self {
        Self { csrf_protection }
    }
    
    /// Check CSRF protection for request
    pub fn check_request(&self, request: &Request, session_id: &str) -> Result<()> {
        if !self.csrf_protection.validate_request(request, session_id)? {
            log::warn!("CSRF validation failed for session {}", session_id);
            return Err(WebError::AuthorizationError(
                "CSRF validation failed".to_string()
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_csrf_token_generation_and_validation() {
        let csrf = CsrfProtection::new("test-secret-key");
        
        let session_id = "test-session-123";
        
        // Generate token
        let token = csrf.generate_token(session_id).unwrap();
        assert!(!token.is_empty());
        
        // Validate correct token
        assert!(csrf.validate_token(&token, session_id).unwrap());
        
        // Validate with wrong session ID
        assert!(!csrf.validate_token(&token, "wrong-session").unwrap());
        
        // Validate with tampered token
        let tampered = format!("{}x", token);
        assert!(!csrf.validate_token(&tampered, session_id).unwrap());
    }
    
    #[test]
    fn test_token_expiry() {
        let csrf = CsrfProtection::new("test-secret-key");
        
        let session_id = "test-session-456";
        let token = csrf.generate_token(session_id).unwrap();
        
        // Token should be valid immediately
        assert!(csrf.validate_token(&token, session_id).unwrap());
        
        // Invalidate token
        csrf.invalidate_token(&token).unwrap();
        
        // Token should no longer be valid
        assert!(!csrf.validate_token(&token, session_id).unwrap());
    }
    
    #[test]
    fn test_html_generation() {
        let csrf = CsrfProtection::new("test-secret-key");
        
        let session_id = "test-session-789";
        
        // Test meta tag generation
        let meta_tag = csrf.generate_meta_tag(session_id).unwrap();
        assert!(meta_tag.contains("csrf-token"));
        assert!(meta_tag.contains("<meta"));
        
        // Test hidden input generation
        let hidden_input = csrf.generate_hidden_input(session_id).unwrap();
        assert!(hidden_input.contains("csrf_token"));
        assert!(hidden_input.contains("hidden"));
    }
    
    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("test"), "test");
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("&\"'<>"), "&amp;&quot;&#x27;&lt;&gt;");
    }
}