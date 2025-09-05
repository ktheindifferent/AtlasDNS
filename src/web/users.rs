use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use rand::{Rng, distributions::Alphanumeric};
use sha2::{Sha256, Digest};
use bcrypt::{hash, verify, DEFAULT_COST};
use crate::web::util::FormDataDecodable;
use crate::web::WebError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: UserRole,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
    pub failed_login_attempts: u32,
    pub last_failed_login: Option<DateTime<Utc>>,
    pub account_locked_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum UserRole {
    Admin,
    User,
    ReadOnly,
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            UserRole::Admin => "Admin",
            UserRole::User => "User", 
            UserRole::ReadOnly => "ReadOnly",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub token: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub role: UserRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub password: Option<String>,
    pub role: Option<UserRole>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAuditEvent {
    pub id: String,
    pub event_type: SecurityEventType,
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub details: Option<String>,
    pub success: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum SecurityEventType {
    LoginAttempt,
    LoginSuccess,
    LoginFailure,
    AccountLocked,
    AccountUnlocked,
    PasswordChanged,
    UserCreated,
    UserUpdated,
    UserDeleted,
    SessionCreated,
    SessionExpired,
    SessionInvalidated,
    PermissionDenied,
}

impl FormDataDecodable<LoginRequest> for LoginRequest {
    fn from_formdata(fields: Vec<(String, String)>) -> crate::web::Result<LoginRequest> {
        let data: HashMap<_, _> = fields.into_iter().collect();
        Ok(LoginRequest {
            username: data.get("username")
                .ok_or(WebError::MissingField("username"))?
                .clone(),
            password: data.get("password")
                .ok_or(WebError::MissingField("password"))?
                .clone(),
        })
    }
}

impl FormDataDecodable<CreateUserRequest> for CreateUserRequest {
    fn from_formdata(fields: Vec<(String, String)>) -> crate::web::Result<CreateUserRequest> {
        let data: HashMap<_, _> = fields.into_iter().collect();
        Ok(CreateUserRequest {
            username: data.get("username")
                .ok_or(WebError::MissingField("username"))?
                .clone(),
            email: data.get("email")
                .ok_or(WebError::MissingField("email"))?
                .clone(),
            password: data.get("password")
                .ok_or(WebError::MissingField("password"))?
                .clone(),
            role: match data.get("role").map(|s| s.as_str()) {
                Some("Admin") => UserRole::Admin,
                Some("ReadOnly") => UserRole::ReadOnly,
                _ => UserRole::User,
            },
        })
    }
}

pub struct UserManager {
    users: Arc<RwLock<HashMap<String, User>>>,
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    audit_log: Arc<RwLock<Vec<SecurityAuditEvent>>>,
}

impl UserManager {
    pub fn new() -> Self {
        let mut manager = UserManager {
            users: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            audit_log: Arc::new(RwLock::new(Vec::new())),
        };
        
        manager.create_default_admin();
        manager
    }
    
    fn create_default_admin(&mut self) {
        // Check for development mode environment variables
        let force_admin = std::env::var("FORCE_ADMIN").unwrap_or_default().to_lowercase() == "true";
        let admin_password = std::env::var("ADMIN_PASSWORD").ok();

        let password = if force_admin {
            if let Some(dev_password) = admin_password {
                log::warn!("🚨 DEVELOPMENT MODE: Using ADMIN_PASSWORD environment variable");
                log::warn!("🚨 FORCE_ADMIN=true detected - admin password is FIXED and cannot be changed");
                log::warn!("🚨 This should ONLY be used in development environments!");
                log::info!("Creating admin user with fixed development password");
                dev_password
            } else {
                log::warn!("🚨 FORCE_ADMIN=true but ADMIN_PASSWORD not set, generating random password");
                rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(16)
                    .map(char::from)
                    .collect()
            }
        } else {
            // Generate a secure random password for production
            let random_password: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(16)
                .map(char::from)
                .collect();
            
            log::warn!("🔐 IMPORTANT: Generated admin password: {}", random_password);
            log::warn!("🔐 Please log in with username 'admin' and change this password immediately!");
            log::warn!("🔐 This password will not be shown again.");
            random_password
        };
            
        let admin_user = User {
            id: Uuid::new_v4().to_string(),
            username: "admin".to_string(),
            email: "admin@localhost".to_string(),
            password_hash: Self::hash_password(&password),
            role: UserRole::Admin,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_active: true,
            failed_login_attempts: 0,
            last_failed_login: None,
            account_locked_until: None,
        };
        
        log::info!("Creating default admin user with username: admin");
        
        if let Ok(mut users) = self.users.write() {
            users.insert(admin_user.id.clone(), admin_user.clone());
            log::info!("Default admin user created successfully: {}", admin_user.username);
        } else {
            log::error!("Failed to create default admin user - could not acquire lock");
        }
    }
    
    pub fn hash_password(password: &str) -> String {
        match hash(password, DEFAULT_COST) {
            Ok(hashed) => hashed,
            Err(e) => {
                log::error!("Critical: Password hashing failed: {}", e);
                // Return a fallback hash that will never match but won't crash
                // This allows the system to continue running while logging the error
                format!("HASH_ERROR_{}", chrono::Utc::now().timestamp())
            }
        }
    }
    
    pub fn verify_password(password: &str, hash: &str) -> bool {
        // Handle legacy SHA256 hashes during migration
        if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            log::warn!("Legacy SHA256 hash detected, please update password");
            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            let legacy_hash = format!("{:x}", hasher.finalize());
            return legacy_hash == hash;
        }
        
        // Use bcrypt for new hashes
        verify(password, hash).unwrap_or(false)
    }
    
    // Constants for account lockout
    const MAX_FAILED_ATTEMPTS: u32 = 5;
    const LOCKOUT_DURATION_MINUTES: i64 = 30;
    
    // Audit logging methods
    fn log_security_event(
        &self,
        event_type: SecurityEventType,
        user_id: Option<String>,
        username: Option<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        details: Option<String>,
        success: bool,
    ) {
        let event = SecurityAuditEvent {
            id: Uuid::new_v4().to_string(),
            event_type,
            user_id,
            username: username.clone(),
            ip_address: ip_address.clone(),
            user_agent,
            timestamp: Utc::now(),
            details,
            success,
        };
        
        if let Ok(mut audit_log) = self.audit_log.write() {
            audit_log.push(event.clone());
            
            // Log to system logs as well
            let log_msg = format!(
                "Security Event - Type: {:?}, User: {}, IP: {}, Success: {}, Details: {}",
                event.event_type,
                username.unwrap_or("unknown".to_string()),
                ip_address.unwrap_or("unknown".to_string()),
                success,
                event.details.unwrap_or("none".to_string())
            );
            
            if success {
                log::info!("{}", log_msg);
            } else {
                log::warn!("{}", log_msg);
            }
        }
    }
    
    fn is_account_locked(&self, user: &User) -> bool {
        if let Some(locked_until) = user.account_locked_until {
            Utc::now() < locked_until
        } else {
            false
        }
    }
    
    fn should_lock_account(&self, user: &User) -> bool {
        user.failed_login_attempts >= Self::MAX_FAILED_ATTEMPTS
    }
    
    fn reset_failed_attempts(&self, user_id: &str) -> Result<(), String> {
        let mut users = self.users.write().map_err(|_| "Failed to acquire lock")?;
        if let Some(user) = users.get_mut(user_id) {
            user.failed_login_attempts = 0;
            user.last_failed_login = None;
            user.account_locked_until = None;
            user.updated_at = Utc::now();
        }
        Ok(())
    }
    
    fn increment_failed_attempts(&self, user_id: &str, ip_address: Option<String>, user_agent: Option<String>) -> Result<(), String> {
        let mut users = self.users.write().map_err(|_| "Failed to acquire lock")?;
        if let Some(user) = users.get_mut(user_id) {
            user.failed_login_attempts += 1;
            user.last_failed_login = Some(Utc::now());
            user.updated_at = Utc::now();
            
            if self.should_lock_account(user) {
                user.account_locked_until = Some(Utc::now() + Duration::minutes(Self::LOCKOUT_DURATION_MINUTES));
                
                // Log account lockout
                self.log_security_event(
                    SecurityEventType::AccountLocked,
                    Some(user.id.clone()),
                    Some(user.username.clone()),
                    ip_address,
                    user_agent,
                    Some(format!("Account locked after {} failed attempts", user.failed_login_attempts)),
                    true,
                );
                
                log::warn!("Account locked for user: {} after {} failed attempts", user.username, user.failed_login_attempts);
            }
        }
        Ok(())
    }
    
    pub fn create_user(&self, request: CreateUserRequest) -> Result<User, String> {
        let mut users = self.users.write().map_err(|_| "Failed to acquire lock")?;
        
        if users.values().any(|u| u.username == request.username) {
            return Err("Username already exists".to_string());
        }
        
        let user = User {
            id: Uuid::new_v4().to_string(),
            username: request.username.clone(),
            email: request.email,
            password_hash: Self::hash_password(&request.password),
            role: request.role,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_active: true,
            failed_login_attempts: 0,
            last_failed_login: None,
            account_locked_until: None,
        };
        
        let user_clone = user.clone();
        users.insert(user.id.clone(), user);
        drop(users);
        
        // Log user creation
        self.log_security_event(
            SecurityEventType::UserCreated,
            Some(user_clone.id.clone()),
            Some(request.username),
            None,
            None,
            Some(format!("User created with role: {:?}", request.role)),
            true,
        );
        
        Ok(user_clone)
    }
    
    pub fn authenticate(&self, username: &str, password: &str, ip_address: Option<String>, user_agent: Option<String>) -> Result<User, String> {
        let users = self.users.read().map_err(|_| "Failed to acquire lock")?;
        
        log::debug!("Authentication attempt for username: {}", username);
        
        let user = users
            .values()
            .find(|u| u.username == username && u.is_active);
            
        match user {
            Some(u) => {
                // Check if account is locked
                if self.is_account_locked(u) {
                    let locked_until = u.account_locked_until.unwrap();
                    let remaining_minutes = (locked_until - Utc::now()).num_minutes();
                    
                    let user_id = u.id.clone();
                    drop(users);
                    
                    self.log_security_event(
                        SecurityEventType::LoginAttempt,
                        Some(user_id),
                        Some(username.to_string()),
                        ip_address,
                        user_agent,
                        Some(format!("Login attempt on locked account, {} minutes remaining", remaining_minutes)),
                        false,
                    );
                    
                    return Err(format!("Account is locked. Try again in {} minutes.", remaining_minutes));
                }
                
                let user_id = u.id.clone();
                let username_str = u.username.clone();
                let password_hash = u.password_hash.clone();
                drop(users);
                
                if Self::verify_password(password, &password_hash) {
                    // Reset failed attempts on successful login
                    let _ = self.reset_failed_attempts(&user_id);
                    
                    // Log successful login
                    self.log_security_event(
                        SecurityEventType::LoginSuccess,
                        Some(user_id.clone()),
                        Some(username_str.clone()),
                        ip_address,
                        user_agent,
                        None,
                        true,
                    );
                    
                    log::info!("Authentication successful for user: {}", username);
                    
                    // Re-read user after reset
                    let users = self.users.read().map_err(|_| "Failed to acquire lock")?;
                    let updated_user = users.get(&user_id).unwrap().clone();
                    Ok(updated_user)
                } else {
                    // Increment failed attempts
                    let _ = self.increment_failed_attempts(&user_id, ip_address.clone(), user_agent.clone());
                    
                    // Log failed login
                    self.log_security_event(
                        SecurityEventType::LoginFailure,
                        Some(user_id),
                        Some(username_str),
                        ip_address,
                        user_agent,
                        Some("Incorrect password".to_string()),
                        false,
                    );
                    
                    log::warn!("Authentication failed for user: {} - incorrect password", username);
                    Err("Invalid credentials".to_string())
                }
            },
            None => {
                drop(users);
                
                // Log failed login attempt for non-existent user
                self.log_security_event(
                    SecurityEventType::LoginFailure,
                    None,
                    Some(username.to_string()),
                    ip_address,
                    user_agent,
                    Some("User not found".to_string()),
                    false,
                );
                
                log::warn!("Authentication failed - user not found: {}", username);
                Err("Invalid credentials".to_string())
            }
        }
    }
    
    pub fn create_session(&self, user_id: String, ip_address: Option<String>, user_agent: Option<String>) -> Result<Session, String> {
        let session = Session {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.clone(),
            token: Uuid::new_v4().to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: ip_address.clone(),
            user_agent: user_agent.clone(),
        };
        
        let mut sessions = self.sessions.write().map_err(|_| "Failed to acquire lock")?;
        let session_clone = session.clone();
        sessions.insert(session.token.clone(), session);
        drop(sessions);
        
        // Get username for logging
        let username = {
            let users = self.users.read().map_err(|_| "Failed to acquire lock")?;
            users.get(&user_id).map(|u| u.username.clone())
        };
        
        // Log session creation
        self.log_security_event(
            SecurityEventType::SessionCreated,
            Some(user_id),
            username,
            ip_address,
            user_agent,
            Some(format!("Session expires at: {}", session_clone.expires_at)),
            true,
        );
        
        Ok(session_clone)
    }
    
    pub fn validate_session(&self, token: &str) -> Result<(Session, User), String> {
        let sessions = self.sessions.read().map_err(|_| "Failed to acquire lock")?;
        
        let session = sessions
            .get(token)
            .filter(|s| s.expires_at > Utc::now())
            .ok_or_else(|| "Invalid or expired session".to_string())?
            .clone();
        
        drop(sessions);
        
        let users = self.users.read().map_err(|_| "Failed to acquire lock")?;
        let user = users
            .get(&session.user_id)
            .filter(|u| u.is_active)
            .ok_or_else(|| "User not found or inactive".to_string())?
            .clone();
        
        Ok((session, user))
    }
    
    pub fn invalidate_session(&self, token: &str) -> Result<(), String> {
        let mut sessions = self.sessions.write().map_err(|_| "Failed to acquire lock")?;
        sessions.remove(token);
        Ok(())
    }
    
    pub fn get_user(&self, user_id: &str) -> Result<User, String> {
        let users = self.users.read().map_err(|_| "Failed to acquire lock")?;
        users.get(user_id).cloned().ok_or_else(|| "User not found".to_string())
    }
    
    pub fn update_user(&self, user_id: &str, request: UpdateUserRequest) -> Result<User, String> {
        let mut users = self.users.write().map_err(|_| "Failed to acquire lock")?;
        
        let user = users.get_mut(user_id).ok_or_else(|| "User not found".to_string())?;
        
        // Check for development mode restrictions
        let force_admin = std::env::var("FORCE_ADMIN").unwrap_or_default().to_lowercase() == "true";
        let admin_password_env = std::env::var("ADMIN_PASSWORD").is_ok();
        
        if let Some(email) = request.email {
            user.email = email;
        }
        if let Some(password) = request.password {
            // Prevent password changes for admin in development mode
            if force_admin && admin_password_env && user.username == "admin" {
                log::warn!("🚨 DEVELOPMENT MODE: Password change blocked for admin user");
                log::warn!("🚨 Admin password is fixed via ADMIN_PASSWORD environment variable");
                return Err("Password cannot be changed for admin user in development mode".to_string());
            }
            user.password_hash = Self::hash_password(&password);
        }
        if let Some(role) = request.role {
            user.role = role;
        }
        if let Some(is_active) = request.is_active {
            user.is_active = is_active;
        }
        
        user.updated_at = Utc::now();
        Ok(user.clone())
    }
    
    pub fn delete_user(&self, user_id: &str) -> Result<(), String> {
        let mut users = self.users.write().map_err(|_| "Failed to acquire lock")?;
        users.remove(user_id).ok_or_else(|| "User not found".to_string())?;
        
        let mut sessions = self.sessions.write().map_err(|_| "Failed to acquire lock")?;
        sessions.retain(|_, s| s.user_id != user_id);
        
        Ok(())
    }
    
    pub fn list_users(&self) -> Result<Vec<User>, String> {
        let users = self.users.read().map_err(|_| "Failed to acquire lock")?;
        Ok(users.values().cloned().collect())
    }
    
    pub fn list_sessions(&self, user_id: Option<&str>) -> Result<Vec<Session>, String> {
        let sessions = self.sessions.read().map_err(|_| "Failed to acquire lock")?;
        
        let result: Vec<Session> = if let Some(uid) = user_id {
            sessions.values().filter(|s| s.user_id == uid).cloned().collect()
        } else {
            sessions.values().cloned().collect()
        };
        
        Ok(result)
    }
    
    pub fn cleanup_expired_sessions(&self) -> Result<usize, String> {
        let mut sessions = self.sessions.write().map_err(|_| "Failed to acquire lock")?;
        let now = Utc::now();
        let initial_count = sessions.len();
        
        sessions.retain(|_, s| s.expires_at > now);
        
        Ok(initial_count - sessions.len())
    }
    
    /// Get the count of active sessions (not expired)
    pub fn get_active_session_count(&self) -> usize {
        if let Ok(sessions) = self.sessions.read() {
            let now = Utc::now();
            sessions.values().filter(|s| s.expires_at > now).count()
        } else {
            0
        }
    }
    
    /// Get the count of unique active users (users with at least one active session)
    pub fn get_active_user_count(&self) -> usize {
        if let Ok(sessions) = self.sessions.read() {
            let now = Utc::now();
            let active_user_ids: std::collections::HashSet<_> = sessions
                .values()
                .filter(|s| s.expires_at > now)
                .map(|s| s.user_id.clone())
                .collect();
            active_user_ids.len()
        } else {
            0
        }
    }
    
    /// Get total user count
    pub fn get_total_user_count(&self) -> usize {
        if let Ok(users) = self.users.read() {
            users.len()
        } else {
            0
        }
    }
    
    /// Get security audit events (most recent first)
    pub fn get_audit_log(&self, limit: Option<usize>) -> Result<Vec<SecurityAuditEvent>, String> {
        let audit_log = self.audit_log.read().map_err(|_| "Failed to acquire lock")?;
        let mut events = audit_log.clone();
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp)); // Most recent first
        
        if let Some(limit) = limit {
            events.truncate(limit);
        }
        
        Ok(events)
    }
    
    /// Get security audit events for a specific user
    pub fn get_user_audit_log(&self, user_id: &str, limit: Option<usize>) -> Result<Vec<SecurityAuditEvent>, String> {
        let audit_log = self.audit_log.read().map_err(|_| "Failed to acquire lock")?;
        let mut events: Vec<SecurityAuditEvent> = audit_log
            .iter()
            .filter(|event| event.user_id.as_ref().map_or(false, |id| id == user_id))
            .cloned()
            .collect();
        
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        if let Some(limit) = limit {
            events.truncate(limit);
        }
        
        Ok(events)
    }
    
    /// Manually unlock a user account (admin function)
    pub fn unlock_user_account(&self, user_id: &str, admin_user_id: &str) -> Result<(), String> {
        let mut users = self.users.write().map_err(|_| "Failed to acquire lock")?;
        let user = users.get_mut(user_id).ok_or_else(|| "User not found".to_string())?;
        
        let username = user.username.clone();
        user.failed_login_attempts = 0;
        user.last_failed_login = None;
        user.account_locked_until = None;
        user.updated_at = Utc::now();
        
        drop(users);
        
        // Get admin username for logging
        let admin_username = {
            let users = self.users.read().map_err(|_| "Failed to acquire lock")?;
            users.get(admin_user_id).map(|u| u.username.clone())
        };
        
        // Log account unlock
        self.log_security_event(
            SecurityEventType::AccountUnlocked,
            Some(user_id.to_string()),
            Some(username),
            None,
            None,
            Some(format!("Account manually unlocked by admin: {}", admin_username.unwrap_or("unknown".to_string()))),
            true,
        );
        
        Ok(())
    }
}

/// XSS Protection utilities
pub struct XSSProtection;

impl XSSProtection {
    /// Escape HTML entities to prevent XSS
    pub fn escape_html(input: &str) -> String {
        input
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;")
            .replace('/', "&#x2F;")
    }
    
    /// Escape JavaScript strings to prevent XSS
    pub fn escape_javascript(input: &str) -> String {
        input
            .replace('\\', "\\\\")
            .replace('\'', "\\'")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
            .replace('<', "\\u003C")
            .replace('>', "\\u003E")
    }
    
    /// Sanitize user input by removing potentially dangerous characters
    pub fn sanitize_input(input: &str) -> String {
        // Remove script tags and other dangerous HTML
        let dangerous_patterns = [
            "<script", "</script>", "javascript:", "vbscript:", "onload=", "onerror=", 
            "onclick=", "onmouseover=", "<iframe", "</iframe>", "<object", "</object>",
            "data:", "file:", "ftp:"
        ];
        
        let mut sanitized = input.to_string();
        for pattern in &dangerous_patterns {
            sanitized = sanitized.replace(pattern, "");
        }
        
        // Remove control characters but keep basic whitespace
        sanitized.chars()
            .filter(|&c| c == ' ' || c == '\t' || c == '\n' || c == '\r' || (c >= ' ' && c != '\x7f'))
            .collect()
    }
    
    /// Generate a Content Security Policy header value
    pub fn generate_csp_header() -> String {
        [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://browser.sentry-cdn.com",
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net",
            "img-src 'self' data: https:",
            "connect-src 'self' https://sentry.alpha.opensam.foundation",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "upgrade-insecure-requests"
        ].join("; ")
    }
}