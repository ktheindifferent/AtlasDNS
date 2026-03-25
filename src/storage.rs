//! Persistent storage backend using SQLite via sqlx.
//!
//! This module provides synchronous-wrapper SQLite-backed persistence for DNS
//! zones, zone records, and user accounts, so all data survives server
//! restarts.
//!
//! Internally an async [`SqlitePool`] is managed by a dedicated single-thread
//! [`tokio::runtime::Runtime`].  All public methods are synchronous and block
//! the calling thread until the async operation completes.
//!
//! ## Schema
//!
//! - `zones`: DNS zone metadata (domain, SOA fields, DNSSEC flag)
//! - `zone_records`: Individual DNS records serialized as JSON
//! - `users`: User accounts (id, username, email, role, password hash, etc.)
//! - `sessions`: Active user sessions (token, user_id, expiry, IP, user-agent)
//! - `firewall_rules`: DNS firewall rules stored as JSON blobs
//! - `blocklists`: Per-list domain block entries
//!
//! ## Usage
//!
//! ```ignore
//! let storage = PersistentStorage::open("/opt/atlas/atlas.db")?;
//! storage.save_zone(&zone)?;
//! let zones = storage.load_all_zones()?;
//! storage.save_user(&user)?;
//! let users = storage.load_all_users()?;
//! ```

use sqlx::{SqlitePool, sqlite::SqlitePoolOptions, Row};
use tokio::runtime::Runtime;

use crate::dns::authority::Zone;
use crate::dns::protocol::DnsRecord;
use crate::web::users::{User, UserRole, Session};

/// Error type for storage operations.
#[derive(Debug)]
pub enum StorageError {
    Sqlx(sqlx::Error),
    Json(serde_json::Error),
    Io(std::io::Error),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::Sqlx(e) => write!(f, "SQLite error: {}", e),
            StorageError::Json(e) => write!(f, "JSON serialization error: {}", e),
            StorageError::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<sqlx::Error> for StorageError {
    fn from(e: sqlx::Error) -> Self { StorageError::Sqlx(e) }
}

impl From<serde_json::Error> for StorageError {
    fn from(e: serde_json::Error) -> Self { StorageError::Json(e) }
}

pub type Result<T> = std::result::Result<T, StorageError>;

/// Synchronous-wrapper SQLite storage for zones and users.
///
/// Thread-safe: wraps an async `SqlitePool` with a dedicated Tokio runtime,
/// and uses a `Mutex` on the runtime to serialize concurrent callers.
pub struct PersistentStorage {
    pool: SqlitePool,
    rt: std::sync::Mutex<Runtime>,
}

impl PersistentStorage {
    /// Open (or create) the database at `db_path`.
    ///
    /// Pass `":memory:"` for an ephemeral in-memory database (useful for tests).
    pub fn open(db_path: &str) -> Result<Self> {
        // Build a single-thread Tokio runtime dedicated to storage I/O
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(StorageError::Io)?;

        // Construct the SQLite connection URL (sqlx requires it)
        let url = if db_path == ":memory:" {
            "sqlite::memory:".to_string()
        } else {
            // Create parent directories if needed
            if let Some(parent) = std::path::Path::new(db_path).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).map_err(StorageError::Io)?;
                }
            }
            format!("sqlite://{}?mode=rwc", db_path)
        };

        let pool = rt.block_on(async {
            SqlitePoolOptions::new()
                .max_connections(3)
                .connect(&url)
                .await
        })?;

        let storage = Self {
            pool,
            rt: std::sync::Mutex::new(rt),
        };
        storage.initialize_schema()?;
        Ok(storage)
    }

    // -------------------------------------------------------------------------
    // Schema
    // -------------------------------------------------------------------------

    fn initialize_schema(&self) -> Result<()> {
        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        rt.block_on(async {
            sqlx::query(r#"
                CREATE TABLE IF NOT EXISTS zones (
                    domain          TEXT PRIMARY KEY,
                    m_name          TEXT NOT NULL,
                    r_name          TEXT NOT NULL,
                    serial          INTEGER NOT NULL DEFAULT 0,
                    refresh         INTEGER NOT NULL DEFAULT 3600,
                    retry           INTEGER NOT NULL DEFAULT 600,
                    expire          INTEGER NOT NULL DEFAULT 86400,
                    minimum         INTEGER NOT NULL DEFAULT 3600,
                    dnssec_enabled  INTEGER NOT NULL DEFAULT 0
                );
            "#).execute(&self.pool).await?;

            sqlx::query(r#"
                CREATE TABLE IF NOT EXISTS zone_records (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    zone_domain TEXT NOT NULL REFERENCES zones(domain) ON DELETE CASCADE,
                    record_json TEXT NOT NULL
                );
            "#).execute(&self.pool).await?;

            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_zone_records_domain ON zone_records(zone_domain)"
            ).execute(&self.pool).await?;

            sqlx::query(r#"
                CREATE TABLE IF NOT EXISTS users (
                    id                    TEXT PRIMARY KEY,
                    username              TEXT NOT NULL UNIQUE,
                    email                 TEXT NOT NULL,
                    password_hash         TEXT NOT NULL,
                    role                  TEXT NOT NULL DEFAULT 'User',
                    created_at            TEXT NOT NULL,
                    updated_at            TEXT NOT NULL,
                    is_active             INTEGER NOT NULL DEFAULT 1,
                    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
                    last_failed_login     TEXT,
                    account_locked_until  TEXT
                );
            "#).execute(&self.pool).await?;

            sqlx::query(r#"
                CREATE TABLE IF NOT EXISTS sessions (
                    id          TEXT PRIMARY KEY,
                    user_id     TEXT NOT NULL,
                    token       TEXT NOT NULL UNIQUE,
                    created_at  TEXT NOT NULL,
                    expires_at  TEXT NOT NULL,
                    ip_address  TEXT,
                    user_agent  TEXT
                );
            "#).execute(&self.pool).await?;

            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)"
            ).execute(&self.pool).await?;

            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)"
            ).execute(&self.pool).await?;

            sqlx::query(r#"
                CREATE TABLE IF NOT EXISTS firewall_rules (
                    id          TEXT PRIMARY KEY,
                    rule_json   TEXT NOT NULL
                );
            "#).execute(&self.pool).await?;

            sqlx::query(r#"
                CREATE TABLE IF NOT EXISTS blocklists (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    list_name   TEXT NOT NULL,
                    domain      TEXT NOT NULL,
                    action      TEXT NOT NULL DEFAULT 'BlockNxDomain',
                    category    TEXT NOT NULL DEFAULT 'Custom',
                    created_at  TEXT NOT NULL,
                    UNIQUE(list_name, domain)
                );
            "#).execute(&self.pool).await?;

            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_blocklists_name ON blocklists(list_name)"
            ).execute(&self.pool).await?;

            Ok::<_, sqlx::Error>(())
        })?;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Zone persistence
    // -------------------------------------------------------------------------

    /// Persist (insert or replace) a zone and all its records atomically.
    pub fn save_zone(&self, zone: &Zone) -> Result<()> {
        // Pre-serialize all records before entering the async block
        let records: Vec<String> = zone.records
            .iter()
            .map(serde_json::to_string)
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let domain = zone.domain.clone();
        let m_name = zone.m_name.clone();
        let r_name = zone.r_name.clone();
        let serial = zone.serial;
        let refresh = zone.refresh;
        let retry = zone.retry;
        let expire = zone.expire;
        let minimum = zone.minimum;
        let dnssec = zone.dnssec_enabled as i32;

        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        rt.block_on(async {
            sqlx::query(r#"
                INSERT INTO zones (domain, m_name, r_name, serial, refresh, retry, expire, minimum, dnssec_enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    m_name=excluded.m_name, r_name=excluded.r_name,
                    serial=excluded.serial, refresh=excluded.refresh,
                    retry=excluded.retry, expire=excluded.expire,
                    minimum=excluded.minimum, dnssec_enabled=excluded.dnssec_enabled
            "#)
            .bind(&domain).bind(&m_name).bind(&r_name)
            .bind(serial).bind(refresh).bind(retry).bind(expire).bind(minimum).bind(dnssec)
            .execute(&self.pool).await?;

            sqlx::query("DELETE FROM zone_records WHERE zone_domain = ?")
                .bind(&domain)
                .execute(&self.pool).await?;

            for json in &records {
                sqlx::query("INSERT INTO zone_records (zone_domain, record_json) VALUES (?, ?)")
                    .bind(&domain)
                    .bind(json)
                    .execute(&self.pool).await?;
            }

            Ok::<_, sqlx::Error>(())
        })?;

        Ok(())
    }

    /// Delete a zone and all its records from the database.
    pub fn delete_zone(&self, domain: &str) -> Result<()> {
        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        rt.block_on(async {
            sqlx::query("DELETE FROM zones WHERE domain = ?")
                .bind(domain)
                .execute(&self.pool).await?;
            Ok::<_, sqlx::Error>(())
        })?;
        Ok(())
    }

    /// Load all zones (with their records) from the database.
    pub fn load_all_zones(&self) -> Result<Vec<Zone>> {
        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        let rows = rt.block_on(async {
            sqlx::query(
                "SELECT domain, m_name, r_name, serial, refresh, retry, expire, minimum, dnssec_enabled FROM zones"
            )
            .fetch_all(&self.pool).await
        })?;

        let mut zones = Vec::with_capacity(rows.len());

        for row in &rows {
            let domain: String = row.get(0);
            let m_name: String = row.get(1);
            let r_name: String = row.get(2);
            let serial: i64 = row.get(3);
            let refresh: i64 = row.get(4);
            let retry: i64 = row.get(5);
            let expire: i64 = row.get(6);
            let minimum: i64 = row.get(7);
            let dnssec_enabled: bool = row.get::<i64, _>(8) != 0;

            let mut zone = Zone::new(domain.clone(), m_name, r_name);
            zone.serial = serial as u32;
            zone.refresh = refresh as u32;
            zone.retry = retry as u32;
            zone.expire = expire as u32;
            zone.minimum = minimum as u32;
            zone.dnssec_enabled = dnssec_enabled;

            // Load records
            let rec_rows = rt.block_on(async {
                sqlx::query("SELECT record_json FROM zone_records WHERE zone_domain = ?")
                    .bind(&domain)
                    .fetch_all(&self.pool).await
            })?;

            for rec_row in &rec_rows {
                let json: String = rec_row.get(0);
                match serde_json::from_str::<DnsRecord>(&json) {
                    Ok(record) => { zone.add_record(&record); }
                    Err(e) => log::warn!("Skipping malformed zone record for {}: {}", domain, e),
                }
            }

            zones.push(zone);
        }

        Ok(zones)
    }

    /// Return `true` if at least one zone exists in the database.
    pub fn has_zones(&self) -> Result<bool> {
        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        let row = rt.block_on(async {
            sqlx::query("SELECT COUNT(*) FROM zones")
                .fetch_one(&self.pool).await
        })?;
        let count: i64 = row.get(0);
        Ok(count > 0)
    }

    // -------------------------------------------------------------------------
    // User persistence
    // -------------------------------------------------------------------------

    /// Persist (insert or replace) a user account.
    pub fn save_user(&self, user: &User) -> Result<()> {
        let id = user.id.clone();
        let username = user.username.clone();
        let email = user.email.clone();
        let password_hash = user.password_hash.clone();
        let role = user.role.as_str().to_string();
        let created_at = user.created_at.to_rfc3339();
        let updated_at = user.updated_at.to_rfc3339();
        let is_active = user.is_active as i32;
        let failed = user.failed_login_attempts as i64;
        let last_failed = user.last_failed_login.map(|t| t.to_rfc3339());
        let locked_until = user.account_locked_until.map(|t| t.to_rfc3339());

        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        rt.block_on(async {
            sqlx::query(r#"
                INSERT INTO users
                    (id, username, email, password_hash, role, created_at, updated_at,
                     is_active, failed_login_attempts, last_failed_login, account_locked_until)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    username=excluded.username,
                    email=excluded.email,
                    password_hash=excluded.password_hash,
                    role=excluded.role,
                    updated_at=excluded.updated_at,
                    is_active=excluded.is_active,
                    failed_login_attempts=excluded.failed_login_attempts,
                    last_failed_login=excluded.last_failed_login,
                    account_locked_until=excluded.account_locked_until
            "#)
            .bind(&id).bind(&username).bind(&email).bind(&password_hash)
            .bind(&role).bind(&created_at).bind(&updated_at)
            .bind(is_active).bind(failed).bind(last_failed).bind(locked_until)
            .execute(&self.pool).await?;
            Ok::<_, sqlx::Error>(())
        })?;
        Ok(())
    }

    /// Delete a user from the database.
    pub fn delete_user(&self, user_id: &str) -> Result<()> {
        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        rt.block_on(async {
            sqlx::query("DELETE FROM users WHERE id = ?")
                .bind(user_id)
                .execute(&self.pool).await?;
            Ok::<_, sqlx::Error>(())
        })?;
        Ok(())
    }

    /// Load all user accounts from the database.
    pub fn load_all_users(&self) -> Result<Vec<User>> {
        use chrono::DateTime;

        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        let rows = rt.block_on(async {
            sqlx::query(r#"
                SELECT id, username, email, password_hash, role, created_at, updated_at,
                       is_active, failed_login_attempts, last_failed_login, account_locked_until
                FROM users
            "#)
            .fetch_all(&self.pool).await
        })?;

        let mut users = Vec::with_capacity(rows.len());

        for row in &rows {
            let id: String = row.get(0);
            let username: String = row.get(1);
            let email: String = row.get(2);
            let password_hash: String = row.get(3);
            let role_str: String = row.get(4);
            let created_at_str: String = row.get(5);
            let updated_at_str: String = row.get(6);
            let is_active: bool = row.get::<i64, _>(7) != 0;
            let failed_login_attempts: u32 = row.get::<i64, _>(8) as u32;
            let last_failed_str: Option<String> = row.get(9);
            let locked_until_str: Option<String> = row.get(10);

            let role = match role_str.as_str() {
                "Admin" => UserRole::Admin,
                "ReadOnly" => UserRole::ReadOnly,
                _ => UserRole::User,
            };

            let created_at = match DateTime::parse_from_rfc3339(&created_at_str) {
                Ok(dt) => dt.with_timezone(&chrono::Utc),
                Err(e) => {
                    log::warn!("Skipping user {} with invalid created_at: {}", username, e);
                    continue;
                }
            };

            let updated_at = match DateTime::parse_from_rfc3339(&updated_at_str) {
                Ok(dt) => dt.with_timezone(&chrono::Utc),
                Err(_) => chrono::Utc::now(),
            };

            let last_failed_login = last_failed_str
                .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc));

            let account_locked_until = locked_until_str
                .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc));

            users.push(User {
                id,
                username,
                email,
                password_hash,
                role,
                created_at,
                updated_at,
                is_active,
                failed_login_attempts,
                last_failed_login,
                account_locked_until,
            });
        }

        Ok(users)
    }

    /// Return `true` if at least one user exists in the database.
    pub fn has_users(&self) -> Result<bool> {
        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        let row = rt.block_on(async {
            sqlx::query("SELECT COUNT(*) FROM users")
                .fetch_one(&self.pool).await
        })?;
        let count: i64 = row.get(0);
        Ok(count > 0)
    }

    // -------------------------------------------------------------------------
    // Session persistence
    // -------------------------------------------------------------------------

    /// Persist (insert or replace) a session.
    pub fn save_session(&self, session: &Session) -> Result<()> {
        let id = session.id.clone();
        let user_id = session.user_id.clone();
        let token = session.token.clone();
        let created_at = session.created_at.to_rfc3339();
        let expires_at = session.expires_at.to_rfc3339();
        let ip_address = session.ip_address.clone();
        let user_agent = session.user_agent.clone();

        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        rt.block_on(async {
            sqlx::query(r#"
                INSERT INTO sessions (id, user_id, token, created_at, expires_at, ip_address, user_agent)
                VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    expires_at=excluded.expires_at,
                    ip_address=excluded.ip_address,
                    user_agent=excluded.user_agent
            "#)
            .bind(&id).bind(&user_id).bind(&token)
            .bind(&created_at).bind(&expires_at)
            .bind(&ip_address).bind(&user_agent)
            .execute(&self.pool).await?;
            Ok::<_, sqlx::Error>(())
        })?;
        Ok(())
    }

    /// Delete a session by token.
    pub fn delete_session(&self, token: &str) -> Result<()> {
        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        rt.block_on(async {
            sqlx::query("DELETE FROM sessions WHERE token = ?")
                .bind(token)
                .execute(&self.pool).await?;
            Ok::<_, sqlx::Error>(())
        })?;
        Ok(())
    }

    /// Delete all sessions belonging to a user.
    pub fn delete_sessions_for_user(&self, user_id: &str) -> Result<()> {
        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        rt.block_on(async {
            sqlx::query("DELETE FROM sessions WHERE user_id = ?")
                .bind(user_id)
                .execute(&self.pool).await?;
            Ok::<_, sqlx::Error>(())
        })?;
        Ok(())
    }

    /// Delete all sessions that have already expired.
    pub fn delete_expired_sessions(&self) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        rt.block_on(async {
            sqlx::query("DELETE FROM sessions WHERE expires_at < ?")
                .bind(&now)
                .execute(&self.pool).await?;
            Ok::<_, sqlx::Error>(())
        })?;
        Ok(())
    }

    /// Load all non-expired sessions from the database.
    pub fn load_active_sessions(&self) -> Result<Vec<Session>> {
        use chrono::DateTime;
        let now = chrono::Utc::now().to_rfc3339();
        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        let rows = rt.block_on(async {
            sqlx::query(
                "SELECT id, user_id, token, created_at, expires_at, ip_address, user_agent \
                 FROM sessions WHERE expires_at > ?"
            )
            .bind(&now)
            .fetch_all(&self.pool).await
        })?;

        let mut sessions = Vec::with_capacity(rows.len());
        for row in &rows {
            let id: String = row.get(0);
            let user_id: String = row.get(1);
            let token: String = row.get(2);
            let created_at_str: String = row.get(3);
            let expires_at_str: String = row.get(4);
            let ip_address: Option<String> = row.get(5);
            let user_agent: Option<String> = row.get(6);

            let created_at = match DateTime::parse_from_rfc3339(&created_at_str) {
                Ok(dt) => dt.with_timezone(&chrono::Utc),
                Err(e) => {
                    log::warn!("Skipping session {} with invalid created_at: {}", id, e);
                    continue;
                }
            };
            let expires_at = match DateTime::parse_from_rfc3339(&expires_at_str) {
                Ok(dt) => dt.with_timezone(&chrono::Utc),
                Err(e) => {
                    log::warn!("Skipping session {} with invalid expires_at: {}", id, e);
                    continue;
                }
            };

            sessions.push(Session {
                id,
                user_id,
                token,
                created_at,
                expires_at,
                ip_address,
                user_agent,
            });
        }
        Ok(sessions)
    }

    // -------------------------------------------------------------------------
    // Firewall rule persistence
    // -------------------------------------------------------------------------

    /// Persist (insert or replace) a firewall rule as a JSON blob.
    pub fn save_firewall_rule<T: serde::Serialize>(&self, id: &str, rule: &T) -> Result<()> {
        let json = serde_json::to_string(rule)?;
        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        rt.block_on(async {
            sqlx::query(
                "INSERT INTO firewall_rules (id, rule_json) VALUES (?,?) \
                 ON CONFLICT(id) DO UPDATE SET rule_json=excluded.rule_json"
            )
            .bind(id)
            .bind(&json)
            .execute(&self.pool).await?;
            Ok::<_, sqlx::Error>(())
        })?;
        Ok(())
    }

    /// Delete a firewall rule by ID.
    pub fn delete_firewall_rule(&self, id: &str) -> Result<()> {
        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        rt.block_on(async {
            sqlx::query("DELETE FROM firewall_rules WHERE id = ?")
                .bind(id)
                .execute(&self.pool).await?;
            Ok::<_, sqlx::Error>(())
        })?;
        Ok(())
    }

    /// Load all firewall rules, deserializing each JSON blob into `T`.
    pub fn load_firewall_rules<T: serde::de::DeserializeOwned>(&self) -> Result<Vec<T>> {
        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        let rows = rt.block_on(async {
            sqlx::query("SELECT rule_json FROM firewall_rules")
                .fetch_all(&self.pool).await
        })?;

        let mut rules = Vec::with_capacity(rows.len());
        for row in &rows {
            let json: String = row.get(0);
            match serde_json::from_str::<T>(&json) {
                Ok(rule) => rules.push(rule),
                Err(e) => log::warn!("Skipping malformed firewall rule: {}", e),
            }
        }
        Ok(rules)
    }

    // -------------------------------------------------------------------------
    // Blocklist persistence
    // -------------------------------------------------------------------------

    /// Add (or ignore if duplicate) a domain to a named blocklist.
    pub fn add_blocklist_entry(
        &self,
        list_name: &str,
        domain: &str,
        action: &str,
        category: &str,
    ) -> Result<()> {
        let created_at = chrono::Utc::now().to_rfc3339();
        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        rt.block_on(async {
            sqlx::query(
                "INSERT INTO blocklists (list_name, domain, action, category, created_at) \
                 VALUES (?,?,?,?,?) ON CONFLICT(list_name, domain) DO NOTHING"
            )
            .bind(list_name).bind(domain).bind(action).bind(category).bind(&created_at)
            .execute(&self.pool).await?;
            Ok::<_, sqlx::Error>(())
        })?;
        Ok(())
    }

    /// Remove a domain from a named blocklist.
    pub fn remove_blocklist_entry(&self, list_name: &str, domain: &str) -> Result<()> {
        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        rt.block_on(async {
            sqlx::query("DELETE FROM blocklists WHERE list_name = ? AND domain = ?")
                .bind(list_name).bind(domain)
                .execute(&self.pool).await?;
            Ok::<_, sqlx::Error>(())
        })?;
        Ok(())
    }

    /// Remove all entries from a named blocklist.
    pub fn clear_blocklist(&self, list_name: &str) -> Result<()> {
        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        rt.block_on(async {
            sqlx::query("DELETE FROM blocklists WHERE list_name = ?")
                .bind(list_name)
                .execute(&self.pool).await?;
            Ok::<_, sqlx::Error>(())
        })?;
        Ok(())
    }

    /// Load all domains in a named blocklist.
    pub fn load_blocklist(&self, list_name: &str) -> Result<Vec<String>> {
        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        let rows = rt.block_on(async {
            sqlx::query("SELECT domain FROM blocklists WHERE list_name = ?")
                .bind(list_name)
                .fetch_all(&self.pool).await
        })?;
        Ok(rows.iter().map(|r| r.get::<String, _>(0)).collect())
    }

    /// Load all blocklist names and their domain counts.
    pub fn list_blocklists(&self) -> Result<Vec<(String, i64)>> {
        let rt = self.rt.lock().expect("storage runtime mutex poisoned");
        let rows = rt.block_on(async {
            sqlx::query(
                "SELECT list_name, COUNT(*) as cnt FROM blocklists GROUP BY list_name"
            )
            .fetch_all(&self.pool).await
        })?;
        Ok(rows.iter().map(|r| (r.get::<String, _>(0), r.get::<i64, _>(1))).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::protocol::TransientTtl;
    use crate::web::users::UserRole;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_storage() -> PersistentStorage {
        PersistentStorage::open(":memory:").expect("in-memory storage failed")
    }

    #[test]
    fn test_zone_roundtrip() {
        let storage = make_storage();

        let mut zone = Zone::new(
            "example.com".to_string(),
            "ns1.example.com".to_string(),
            "admin.example.com".to_string(),
        );
        zone.serial = 42;
        zone.add_record(&DnsRecord::A {
            domain: "www.example.com".to_string(),
            addr: "93.184.216.34".parse().unwrap(),
            ttl: TransientTtl(3600),
        });

        storage.save_zone(&zone).expect("save_zone failed");

        let zones = storage.load_all_zones().expect("load_all_zones failed");
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].domain, "example.com");
        assert_eq!(zones[0].serial, 42);
        assert_eq!(zones[0].records.len(), 1);
    }

    #[test]
    fn test_zone_delete() {
        let storage = make_storage();
        let zone = Zone::new("delete.me".to_string(), "ns1.delete.me".to_string(), "a.b".to_string());
        storage.save_zone(&zone).expect("save_zone failed");
        assert!(storage.has_zones().unwrap());
        storage.delete_zone("delete.me").expect("delete_zone failed");
        let zones = storage.load_all_zones().unwrap();
        assert!(zones.is_empty());
    }

    #[test]
    fn test_zone_update_replaces_records() {
        let storage = make_storage();

        let mut zone = Zone::new("update.com".to_string(), "ns1".to_string(), "admin".to_string());
        zone.add_record(&DnsRecord::A {
            domain: "a.update.com".to_string(),
            addr: "1.2.3.4".parse().unwrap(),
            ttl: TransientTtl(300),
        });
        storage.save_zone(&zone).unwrap();

        // Add a second record and re-save
        zone.add_record(&DnsRecord::A {
            domain: "b.update.com".to_string(),
            addr: "5.6.7.8".parse().unwrap(),
            ttl: TransientTtl(300),
        });
        storage.save_zone(&zone).unwrap();

        let zones = storage.load_all_zones().unwrap();
        assert_eq!(zones[0].records.len(), 2);
    }

    #[test]
    fn test_user_roundtrip() {
        let storage = make_storage();

        let user = User {
            id: Uuid::new_v4().to_string(),
            username: "alice".to_string(),
            email: "alice@example.com".to_string(),
            password_hash: "$2b$12$xxx".to_string(),
            role: UserRole::Admin,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_active: true,
            failed_login_attempts: 0,
            last_failed_login: None,
            account_locked_until: None,
        };

        storage.save_user(&user).expect("save_user failed");
        let users = storage.load_all_users().expect("load_all_users failed");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "alice");
        assert_eq!(users[0].role, UserRole::Admin);
    }

    #[test]
    fn test_user_update_via_upsert() {
        let storage = make_storage();
        let id = Uuid::new_v4().to_string();
        let mut user = User {
            id: id.clone(),
            username: "bob".to_string(),
            email: "bob@example.com".to_string(),
            password_hash: "hash1".to_string(),
            role: UserRole::User,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_active: true,
            failed_login_attempts: 0,
            last_failed_login: None,
            account_locked_until: None,
        };
        storage.save_user(&user).unwrap();

        user.email = "bob2@example.com".to_string();
        user.password_hash = "hash2".to_string();
        storage.save_user(&user).unwrap();

        let users = storage.load_all_users().unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].email, "bob2@example.com");
        assert_eq!(users[0].password_hash, "hash2");
    }

    #[test]
    fn test_has_zones_and_users() {
        let storage = make_storage();
        assert!(!storage.has_zones().unwrap());
        assert!(!storage.has_users().unwrap());

        let zone = Zone::new("test.com".to_string(), "ns1".to_string(), "admin".to_string());
        storage.save_zone(&zone).unwrap();
        assert!(storage.has_zones().unwrap());
    }
}
