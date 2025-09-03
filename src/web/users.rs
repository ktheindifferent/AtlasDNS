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
}

impl UserManager {
    pub fn new() -> Self {
        let mut manager = UserManager {
            users: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        };
        
        manager.create_default_admin();
        manager
    }
    
    fn create_default_admin(&mut self) {
        // Check for development mode environment variables
        let force_admin = std::env::var("FORCE_ADMIN").unwrap_or_default().to_lowercase() == "true";
        let admin_password = std::env::var("ADMIN_PASSWORD").ok();

        let password = if force_admin && admin_password.is_some() {
            let dev_password = admin_password.unwrap();
            log::warn!("🚨 DEVELOPMENT MODE: Using ADMIN_PASSWORD environment variable");
            log::warn!("🚨 FORCE_ADMIN=true detected - admin password is FIXED and cannot be changed");
            log::warn!("🚨 This should ONLY be used in development environments!");
            log::info!("Creating admin user with fixed development password");
            dev_password
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
        hash(password, DEFAULT_COST)
            .expect("Failed to hash password")
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
    
    pub fn create_user(&self, request: CreateUserRequest) -> Result<User, String> {
        let mut users = self.users.write().map_err(|_| "Failed to acquire lock")?;
        
        if users.values().any(|u| u.username == request.username) {
            return Err("Username already exists".to_string());
        }
        
        let user = User {
            id: Uuid::new_v4().to_string(),
            username: request.username,
            email: request.email,
            password_hash: Self::hash_password(&request.password),
            role: request.role,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_active: true,
        };
        
        let user_clone = user.clone();
        users.insert(user.id.clone(), user);
        Ok(user_clone)
    }
    
    pub fn authenticate(&self, username: &str, password: &str) -> Result<User, String> {
        let users = self.users.read().map_err(|_| "Failed to acquire lock")?;
        
        log::debug!("Authentication attempt for username: {}", username);
        log::debug!("Total users in database: {}", users.len());
        
        // List all users for debugging
        for user in users.values() {
            log::debug!("User in DB: {} (active: {})", user.username, user.is_active);
        }
        
        let user = users
            .values()
            .find(|u| u.username == username && u.is_active);
            
        match user {
            Some(u) => {
                log::debug!("User found: {}", u.username);
                let password_hash = Self::hash_password(password);
                log::debug!("Provided password hash: {}", password_hash);
                log::debug!("Stored password hash: {}", u.password_hash);
                
                if Self::verify_password(password, &u.password_hash) {
                    log::info!("Authentication successful for user: {}", username);
                    Ok(u.clone())
                } else {
                    log::warn!("Authentication failed for user: {} - incorrect password", username);
                    Err("Invalid credentials".to_string())
                }
            },
            None => {
                log::warn!("Authentication failed - user not found: {}", username);
                Err("Invalid credentials".to_string())
            }
        }
    }
    
    pub fn create_session(&self, user_id: String, ip_address: Option<String>, user_agent: Option<String>) -> Result<Session, String> {
        let session = Session {
            id: Uuid::new_v4().to_string(),
            user_id,
            token: Uuid::new_v4().to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address,
            user_agent,
        };
        
        let mut sessions = self.sessions.write().map_err(|_| "Failed to acquire lock")?;
        let session_clone = session.clone();
        sessions.insert(session.token.clone(), session);
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
}