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
use crate::storage::PersistentStorage;

/// A registered user account in the Atlas DNS management system.
///
/// Passwords are stored only as bcrypt hashes and are excluded from
/// serialization (`#[serde(skip_serializing)]`) to prevent accidental
/// exposure in API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// UUID v4 identifier, generated at creation time.
    pub id: String,
    /// Unique login name.
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: UserRole,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Whether the account can log in. Admins can deactivate accounts without deleting them.
    pub is_active: bool,
    /// Incremented on each failed login; reset to 0 on success.
    pub failed_login_attempts: u32,
    pub last_failed_login: Option<DateTime<Utc>>,
    /// When set, login attempts are rejected until this time passes.
    pub account_locked_until: Option<DateTime<Utc>>,
    /// Per-user API keys for programmatic access
    pub api_keys: Vec<UserApiKey>,
    /// IP subnets this user can access query logs for (None = all, admins only)
    pub allowed_subnets: Option<Vec<String>>,
    /// TOTP 2FA configuration (None = 2FA not set up)
    pub totp_config: Option<TotpConfig>,
}

/// Access level granted to a user account.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum UserRole {
    /// Full access: manage users, zones, cache, and server configuration.
    Admin,
    /// Standard access: manage zones and cache but not other users.
    User,
    /// View-only access: can query data but cannot make changes.
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

/// An active login session identified by a random bearer token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// UUID v4 identifier.
    pub id: String,
    pub user_id: String,
    /// Random alphanumeric bearer token stored in the session cookie.
    pub token: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Credentials supplied when a user logs in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Parameters for creating a new user account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub role: UserRole,
}

/// Partial-update payload for an existing user account.
/// Fields set to `None` are left unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub password: Option<String>,
    pub role: Option<UserRole>,
    pub is_active: Option<bool>,
}

/// A per-user API key for programmatic access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserApiKey {
    /// Key ID (public, used to identify the key)
    pub id: String,
    /// SHA-256 hash of the actual key (never store raw key)
    pub key_hash: String,
    /// Human-readable name for this key
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    /// Scopes/permissions for this key
    pub scopes: Vec<String>,
    /// Whether key is active
    pub is_active: bool,
}

/// An invite link that allows a new user to register
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteLink {
    pub id: String,
    /// The token embedded in the invite URL
    pub token: String,
    /// User ID of the admin who created the invite
    pub created_by: String,
    /// Pre-assigned role for the invited user
    pub role: UserRole,
    /// Optional email this invite is for
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Whether this invite has been used
    pub used: bool,
    pub used_by: Option<String>,
}

/// TOTP (Time-based OTP) configuration stub for 2FA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    /// Base32-encoded TOTP secret (for QR code generation)
    pub secret: String,
    /// Whether 2FA is currently enabled
    pub enabled: bool,
    /// Backup codes (each is a one-time use token)
    pub backup_codes: Vec<String>,
}

/// A single entry in the security audit log.
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

/// Thread-safe manager for user accounts and login sessions.
///
/// Holds all users and sessions in memory (behind `RwLock`-protected
/// `HashMap`s) for fast access, and optionally writes every mutation
/// through to a [`PersistentStorage`] backend so state survives restarts.
///
/// Construct with [`UserManager::new`] for in-memory-only mode, or
/// [`UserManager::with_storage`] to enable SQLite persistence.
pub struct UserManager {
    users: Arc<RwLock<HashMap<String, User>>>,
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    audit_log: Arc<RwLock<Vec<SecurityAuditEvent>>>,
    /// Optional persistent storage backend. When set, every mutation is
    /// immediately written through to the database.
    storage: Option<Arc<PersistentStorage>>,
}

impl UserManager {
    /// Create an in-memory-only `UserManager` with a default admin account.
    pub fn new() -> Self {
        let mut manager = UserManager {
            users: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            audit_log: Arc::new(RwLock::new(Vec::new())),
            storage: None,
        };

        manager.create_default_admin();
        manager
    }

    /// Create a `UserManager` backed by `storage`.
    ///
    /// Existing users are loaded from the database on construction.
    /// If the database has no users, a default admin account is created and
    /// immediately persisted.
    pub fn with_storage(storage: Arc<PersistentStorage>) -> Self {
        let mut manager = UserManager {
            users: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            audit_log: Arc::new(RwLock::new(Vec::new())),
            storage: Some(storage.clone()),
        };

        // Load persisted sessions
        match storage.load_active_sessions() {
            Ok(persisted) => {
                if let Ok(mut sessions) = manager.sessions.write() {
                    for session in persisted {
                        sessions.insert(session.token.clone(), session);
                    }
                }
            }
            Err(e) => log::warn!("Failed to load sessions from storage: {}", e),
        }

        // Load persisted users
        match storage.load_all_users() {
            Ok(persisted) if !persisted.is_empty() => {
                if let Ok(mut users) = manager.users.write() {
                    for user in persisted {
                        log::info!("Loaded persisted user: {}", user.username);
                        users.insert(user.id.clone(), user);
                    }
                }
            }
            Ok(_) => {
                // No users in DB — create and persist the default admin
                manager.create_default_admin();
                if let Ok(users) = manager.users.read() {
                    for user in users.values() {
                        if let Err(e) = storage.save_user(user) {
                            log::error!("Failed to persist default admin: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to load users from storage: {}", e);
                manager.create_default_admin();
            }
        }

        manager
    }

    /// Persist `user` to the storage backend if one is configured.
    fn persist_user(&self, user: &User) {
        if let Some(storage) = &self.storage {
            if let Err(e) = storage.save_user(user) {
                log::error!("Failed to persist user {}: {}", user.username, e);
            }
        }
    }

    /// Remove `user_id` from the storage backend if one is configured.
    fn remove_persisted_user(&self, user_id: &str) {
        if let Some(storage) = &self.storage {
            if let Err(e) = storage.delete_user(user_id) {
                log::error!("Failed to delete user {} from storage: {}", user_id, e);
            }
        }
    }

    /// Persist `session` to the storage backend if one is configured.
    fn persist_session(&self, session: &Session) {
        if let Some(storage) = &self.storage {
            if let Err(e) = storage.save_session(session) {
                log::error!("Failed to persist session {}: {}", session.id, e);
            }
        }
    }

    /// Remove a session by token from the storage backend if one is configured.
    fn remove_persisted_session(&self, token: &str) {
        if let Some(storage) = &self.storage {
            if let Err(e) = storage.delete_session(token) {
                log::error!("Failed to delete session from storage: {}", e);
            }
        }
    }

    /// Remove all sessions for a user from the storage backend if one is configured.
    fn remove_persisted_sessions_for_user(&self, user_id: &str) {
        if let Some(storage) = &self.storage {
            if let Err(e) = storage.delete_sessions_for_user(user_id) {
                log::error!("Failed to delete sessions for user {} from storage: {}", user_id, e);
            }
        }
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
                    .take(16).collect()
            }
        } else {
            // Generate a secure random password for production
            let random_password: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(16).collect();
            
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
            api_keys: vec![],
            allowed_subnets: None,
            totp_config: None,
        };
        
        log::info!("Creating default admin user with username: admin");
        
        if let Ok(mut users) = self.users.write() {
            users.insert(admin_user.id.clone(), admin_user.clone());
            log::info!("Default admin user created successfully: {}", admin_user.username);
        } else {
            log::error!("Failed to create default admin user - could not acquire lock");
        }
    }
    
    /// Hash a plaintext password using bcrypt with the default work factor.
    ///
    /// On bcrypt failure (extremely unlikely), falls back to a SHA-256 hex
    /// hash to avoid a panic; a warning is logged in that case.
    /// Generate a cryptographically secure session token (64 hex chars = 256 bits).
    fn generate_secure_token() -> String {
        use rand::Rng;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill(&mut bytes);
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
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
    
    /// Verify a plaintext `password` against a stored `hash`.
    ///
    /// Supports both bcrypt hashes (current) and legacy 64-char hex SHA-256
    /// hashes (migration path from older Atlas versions).
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
            let snapshot = user.clone();
            drop(users);
            self.persist_user(&snapshot);
            return Ok(());
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

            let snapshot = user.clone();
            drop(users);
            self.persist_user(&snapshot);
            return Ok(());
        }
        Ok(())
    }
    
    /// Create a new user account and persist it to storage.
    ///
    /// Returns `Err` if the username is already taken or if any lock cannot be
    /// acquired.  The password is hashed before storage.
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
            api_keys: vec![],
            allowed_subnets: None,
            totp_config: None,
        };
        
        let user_clone = user.clone();
        users.insert(user.id.clone(), user);
        drop(users);

        // Persist to storage
        self.persist_user(&user_clone);

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
    
    /// Authenticate a user by username and password.
    ///
    /// On success the failed-login counter is reset and a security event is
    /// logged.  On failure the counter is incremented; after 5 consecutive
    /// failures the account is locked for 30 minutes.
    ///
    /// Returns `Err` with a human-readable message for invalid credentials,
    /// locked accounts, or lock-acquisition failures.
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
                    // account_locked_until is guaranteed Some when is_account_locked returns true
                    let locked_until = u.account_locked_until.unwrap_or_else(Utc::now);
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
                    let updated_user = users.get(&user_id)
                        .ok_or_else(|| "User disappeared after successful login".to_string())?
                        .clone();
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
    
    /// Create a new 24-hour session for `user_id` and persist it to storage.
    pub fn create_session(&self, user_id: String, ip_address: Option<String>, user_agent: Option<String>) -> Result<Session, String> {
        let session = Session {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.clone(),
            token: Self::generate_secure_token(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: ip_address.clone(),
            user_agent: user_agent.clone(),
        };
        
        let mut sessions = self.sessions.write().map_err(|_| "Failed to acquire lock")?;
        let session_clone = session.clone();
        sessions.insert(session.token.clone(), session);
        drop(sessions);

        // Persist to storage
        self.persist_session(&session_clone);

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
    
    /// Look up an active session by bearer `token`.
    ///
    /// Returns `(session, user)` if the token exists, has not expired, and
    /// belongs to an active user account.  Returns `Err` otherwise.
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
        drop(sessions);
        self.remove_persisted_session(token);
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
        let updated = user.clone();
        drop(users);

        // Persist updated user
        self.persist_user(&updated);

        Ok(updated)
    }

    pub fn delete_user(&self, user_id: &str) -> Result<(), String> {
        let mut users = self.users.write().map_err(|_| "Failed to acquire lock")?;
        users.remove(user_id).ok_or_else(|| "User not found".to_string())?;
        drop(users);

        let mut sessions = self.sessions.write().map_err(|_| "Failed to acquire lock")?;
        sessions.retain(|_, s| s.user_id != user_id);
        drop(sessions);

        // Remove from storage
        self.remove_persisted_user(user_id);
        self.remove_persisted_sessions_for_user(user_id);

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
            .filter(|event| event.user_id.as_ref().is_some_and(|id| id == user_id))
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
        let snapshot = user.clone();
        drop(users);
        self.persist_user(&snapshot);

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

    // ===== Invite System =====

    /// Generate an invite link. Only admins should call this.
    pub fn create_invite(
        &self,
        created_by: &str,
        role: UserRole,
        email: Option<String>,
        expires_in_hours: i64,
    ) -> InviteLink {
        let token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32).collect();
        InviteLink {
            id: Uuid::new_v4().to_string(),
            token,
            created_by: created_by.to_string(),
            role,
            email,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(expires_in_hours),
            used: false,
            used_by: None,
        }
    }

    /// Use an invite token to create a new user. Returns the created user or error.
    pub fn create_user_from_invite(
        &self,
        invite: &mut InviteLink,
        username: String,
        email: String,
        password: String,
    ) -> crate::web::Result<User> {
        if invite.used {
            return Err(WebError::MissingField("invite already used"));
        }
        if invite.expires_at < Utc::now() {
            return Err(WebError::MissingField("invite expired"));
        }
        let req = CreateUserRequest {
            username,
            email,
            password,
            role: invite.role,
        };
        let user = self.create_user(req).map_err(WebError::InternalError)?;
        invite.used = true;
        invite.used_by = Some(user.id.clone());
        Ok(user)
    }

    // ===== Per-user API Keys =====

    /// Create a new API key for a user. Returns (key_id, raw_key).
    /// The raw_key is only returned once and never stored.
    pub fn create_user_api_key(
        &self,
        user_id: &str,
        name: String,
        scopes: Vec<String>,
    ) -> crate::web::Result<(String, String)> {
        let raw_key: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(48).collect();

        let key_hash = hash(&raw_key, DEFAULT_COST)
            .map_err(|e| WebError::InternalError(format!("API key hash failed: {}", e)))?;

        let api_key = UserApiKey {
            id: Uuid::new_v4().to_string(),
            key_hash,
            name,
            created_at: Utc::now(),
            last_used: None,
            scopes,
            is_active: true,
        };

        let key_id = api_key.id.clone();

        let mut users = self.users.write().map_err(|_| WebError::InternalError("Lock error".to_string()))?;
        if let Some(user) = users.get_mut(user_id) {
            user.api_keys.push(api_key);
            let snapshot = user.clone();
            drop(users);
            self.persist_user(&snapshot);
            Ok((key_id, raw_key))
        } else {
            Err(WebError::MissingField("user not found"))
        }
    }

    /// Validate a raw API key. Returns (user_id, key_id) if valid.
    pub fn validate_user_api_key(&self, raw_key: &str) -> Option<(String, String)> {
        let users = self.users.read().ok()?;
        for user in users.values() {
            if !user.is_active {
                continue;
            }
            for api_key in &user.api_keys {
                if !api_key.is_active {
                    continue;
                }
                // Support both bcrypt hashes (new) and legacy SHA-256 hex hashes
                let matches = if api_key.key_hash.starts_with("$2") {
                    verify(raw_key, &api_key.key_hash).unwrap_or(false)
                } else {
                    // Legacy SHA-256 path (migration)
                    let mut hasher = Sha256::new();
                    hasher.update(raw_key.as_bytes());
                    let legacy = format!("{:x}", hasher.finalize());
                    legacy == api_key.key_hash
                };
                if matches {
                    return Some((user.id.clone(), api_key.id.clone()));
                }
            }
        }
        None
    }

    /// Revoke an API key for a user
    pub fn revoke_user_api_key(&self, user_id: &str, key_id: &str) -> crate::web::Result<()> {
        let mut users = self.users.write().map_err(|_| WebError::InternalError("Lock error".to_string()))?;
        if let Some(user) = users.get_mut(user_id) {
            for key in &mut user.api_keys {
                if key.id == key_id {
                    key.is_active = false;
                    let snapshot = user.clone();
                    drop(users);
                    self.persist_user(&snapshot);
                    return Ok(());
                }
            }
            Err(WebError::MissingField("key not found"))
        } else {
            Err(WebError::MissingField("user not found"))
        }
    }

    // ===== TOTP 2FA stub =====

    /// Set up TOTP for a user. Returns the TOTP secret for QR code generation.
    /// The user must then verify with a valid TOTP code to activate.
    pub fn setup_totp(&self, user_id: &str) -> crate::web::Result<String> {
        // Generate a random base32 secret (stub: just use random alphanumeric)
        let secret: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32).collect();

        let backup_codes: Vec<String> = (0..8)
            .map(|_| {
                rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(8).collect()
            })
            .collect();

        let totp = TotpConfig {
            secret: secret.clone(),
            enabled: false, // disabled until verified
            backup_codes,
        };

        let mut users = self.users.write().map_err(|_| WebError::InternalError("Lock error".to_string()))?;
        if let Some(user) = users.get_mut(user_id) {
            user.totp_config = Some(totp);
            let snapshot = user.clone();
            drop(users);
            self.persist_user(&snapshot);
            Ok(secret)
        } else {
            Err(WebError::MissingField("user not found"))
        }
    }

    /// Activate TOTP after user verifies the first code.
    /// (Stub: accepts any non-empty code as valid for now)
    pub fn activate_totp(&self, user_id: &str, _code: &str) -> crate::web::Result<()> {
        let mut users = self.users.write().map_err(|_| WebError::InternalError("Lock error".to_string()))?;
        if let Some(user) = users.get_mut(user_id) {
            if let Some(totp) = &mut user.totp_config {
                totp.enabled = true;
                let snapshot = user.clone();
                drop(users);
                self.persist_user(&snapshot);
                Ok(())
            } else {
                Err(WebError::MissingField("TOTP not configured"))
            }
        } else {
            Err(WebError::MissingField("user not found"))
        }
    }

    /// Check TOTP code during login.
    /// (Stub: always returns true if TOTP is configured but not yet implemented)
    pub fn check_totp(&self, user_id: &str, _code: &str) -> bool {
        let users = match self.users.read() {
            Ok(u) => u,
            Err(_) => return false,
        };
        if let Some(user) = users.get(user_id) {
            if let Some(totp) = &user.totp_config {
                // Stub: TOTP verification not yet implemented
                // In production, use a TOTP library to verify the code
                log::warn!("[2FA-STUB] TOTP check for user {} - returning true (stub)", user.username);
                return totp.enabled; // stub: always pass if enabled
            }
        }
        true // no TOTP configured = pass
    }

    /// Get allowed subnets for a user (for query log filtering)
    pub fn get_allowed_subnets(&self, user_id: &str) -> Option<Vec<String>> {
        let users = self.users.read().ok()?;
        users.get(user_id)?.allowed_subnets.clone()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::PersistentStorage;
    use std::sync::Arc;

    fn make_storage() -> Arc<PersistentStorage> {
        Arc::new(PersistentStorage::open(":memory:").expect("in-memory storage"))
    }

    /// Build a `UserManager` backed by an in-memory SQLite database.
    fn manager_with_storage() -> UserManager {
        UserManager::with_storage(make_storage())
    }

    #[test]
    fn test_with_storage_loads_persisted_users() {
        let storage = make_storage();

        // Pre-seed user directly in storage
        let user = User {
            id: uuid::Uuid::new_v4().to_string(),
            username: "preseeded".to_string(),
            email: "pre@example.com".to_string(),
            password_hash: UserManager::hash_password("pass"),
            role: UserRole::User,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            is_active: true,
            failed_login_attempts: 0,
            last_failed_login: None,
            account_locked_until: None,
            api_keys: vec![],
            allowed_subnets: None,
            totp_config: None,
        };
        storage.save_user(&user).unwrap();

        // Manager should load the pre-seeded user on construction
        let manager = UserManager::with_storage(storage);
        let users = manager.list_users().unwrap();
        assert!(users.iter().any(|u| u.username == "preseeded"));
    }

    #[test]
    fn test_create_user_persists_to_storage() {
        let storage = make_storage();
        let manager = UserManager::with_storage(storage.clone());

        manager.create_user(CreateUserRequest {
            username: "carol".to_string(),
            email: "carol@example.com".to_string(),
            password: "secret123".to_string(),
            role: UserRole::User,
        }).unwrap();

        // User should now be in the persistent backend
        let stored_users = storage.load_all_users().unwrap();
        assert!(stored_users.iter().any(|u| u.username == "carol"));
    }

    #[test]
    fn test_delete_user_removes_from_storage() {
        let storage = make_storage();
        let manager = UserManager::with_storage(storage.clone());

        let user = manager.create_user(CreateUserRequest {
            username: "dave".to_string(),
            email: "dave@example.com".to_string(),
            password: "pass".to_string(),
            role: UserRole::ReadOnly,
        }).unwrap();

        manager.delete_user(&user.id).unwrap();

        let stored = storage.load_all_users().unwrap();
        assert!(stored.iter().all(|u| u.id != user.id));
    }

    #[test]
    fn test_authenticate_with_storage_backed_manager() {
        let manager = manager_with_storage();

        manager.create_user(CreateUserRequest {
            username: "eve".to_string(),
            email: "eve@example.com".to_string(),
            password: "correct_password".to_string(),
            role: UserRole::User,
        }).unwrap();

        // Correct credentials succeed
        assert!(manager.authenticate("eve", "correct_password", None, None).is_ok());
        // Wrong password fails
        assert!(manager.authenticate("eve", "wrong_password", None, None).is_err());
    }

    #[test]
    fn test_session_persists_to_storage() {
        let storage = make_storage();
        let manager = UserManager::with_storage(storage.clone());

        let user = manager.create_user(CreateUserRequest {
            username: "frank".to_string(),
            email: "frank@example.com".to_string(),
            password: "pass".to_string(),
            role: UserRole::User,
        }).unwrap();

        let session = manager.create_session(user.id.clone(), None, None).unwrap();

        let stored_sessions = storage.load_active_sessions().unwrap();
        assert!(stored_sessions.iter().any(|s| s.token == session.token));
    }
}