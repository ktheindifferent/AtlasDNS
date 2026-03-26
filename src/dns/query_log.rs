//! SQLite-backed DNS query log with per-client policies.
//!
//! [`QueryLog`] records DNS queries to a persistent SQLite database and supports
//! querying by client, time range, and blocked status.  It mirrors the pattern
//! used by [`crate::storage::PersistentStorage`] (single-thread tokio runtime +
//! SqlitePool + Mutex<Runtime>).

use std::sync::Arc;
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions, Row};
use tokio::runtime::Builder;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum QueryLogError {
    Sqlx(sqlx::Error),
    Json(serde_json::Error),
    Runtime(std::io::Error),
}

impl std::fmt::Display for QueryLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryLogError::Sqlx(e)    => write!(f, "SQLite error: {}", e),
            QueryLogError::Json(e)    => write!(f, "JSON error: {}", e),
            QueryLogError::Runtime(e) => write!(f, "Runtime error: {}", e),
        }
    }
}

impl std::error::Error for QueryLogError {}

impl From<sqlx::Error> for QueryLogError {
    fn from(e: sqlx::Error) -> Self { QueryLogError::Sqlx(e) }
}

impl From<serde_json::Error> for QueryLogError {
    fn from(e: serde_json::Error) -> Self { QueryLogError::Json(e) }
}

pub type Result<T> = std::result::Result<T, QueryLogError>;

// ---------------------------------------------------------------------------
// Public data types
// ---------------------------------------------------------------------------

/// One logged DNS query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryLogEntry {
    pub id: i64,
    pub timestamp: i64,
    pub client_ip: String,
    pub domain: String,
    pub query_type: String,
    pub resolved_ip: Option<String>,
    pub blocked: bool,
    pub response_ms: i64,
    /// DNSSEC validation outcome: SECURE | BOGUS | INDETERMINATE | null
    pub dnssec_status: Option<String>,
}

/// Aggregate statistics for one client IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientStats {
    pub client_ip: String,
    pub query_count: i64,
    pub blocked_count: i64,
    pub last_seen: i64,
}

/// Per-client DNS policy stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPolicy {
    /// If true, skip all blocklist checks for this client.
    pub bypass_all: bool,
    /// Extra domain patterns to block for this client (in addition to global lists).
    pub extra_block: Vec<String>,
    /// Hours of the day (0–23) during which DNS is blocked for this client.
    pub blocked_hours: Vec<u32>,
}

impl Default for ClientPolicy {
    fn default() -> Self {
        Self {
            bypass_all: false,
            extra_block: Vec::new(),
            blocked_hours: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// QueryLog
// ---------------------------------------------------------------------------

/// Synchronous-wrapper SQLite query log.
///
/// Thread-safe: wraps an async `SqlitePool` with a dedicated single-thread
/// Tokio runtime and serialises concurrent callers via a `Mutex<Runtime>`.
pub struct QueryLog {
    pool: SqlitePool,
    rt: std::sync::Mutex<tokio::runtime::Runtime>,
}

impl QueryLog {
    /// Open (or create) the query-log database at `db_path`.
    ///
    /// Pass `":memory:"` for an ephemeral in-memory database (useful for tests).
    pub fn open(db_path: &str) -> Result<Arc<Self>> {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(QueryLogError::Runtime)?;

        let url = if db_path == ":memory:" {
            "sqlite::memory:".to_string()
        } else {
            if let Some(parent) = std::path::Path::new(db_path).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)
                        .map_err(QueryLogError::Runtime)?;
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

        let ql = Arc::new(Self {
            pool,
            rt: std::sync::Mutex::new(rt),
        });
        ql.initialize_schema()?;
        ql.migrate_schema()?;
        Ok(ql)
    }

    // -----------------------------------------------------------------------
    // Schema
    // -----------------------------------------------------------------------

    fn initialize_schema(&self) -> Result<()> {
        let rt = self.rt.lock().expect("query_log runtime mutex poisoned");
        rt.block_on(async {
            sqlx::query(r#"
                CREATE TABLE IF NOT EXISTS query_log (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp      INTEGER NOT NULL,
                    client_ip      TEXT    NOT NULL,
                    domain         TEXT    NOT NULL,
                    query_type     TEXT    NOT NULL,
                    resolved_ip    TEXT,
                    blocked        INTEGER NOT NULL DEFAULT 0,
                    response_ms    INTEGER NOT NULL DEFAULT 0,
                    dnssec_status  TEXT
                );
            "#).execute(&self.pool).await?;

            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_ql_timestamp  ON query_log(timestamp)"
            ).execute(&self.pool).await?;

            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_ql_client_ip  ON query_log(client_ip)"
            ).execute(&self.pool).await?;

            sqlx::query(r#"
                CREATE TABLE IF NOT EXISTS client_policies (
                    ip            TEXT    PRIMARY KEY,
                    bypass_all    INTEGER NOT NULL DEFAULT 0,
                    extra_block   TEXT    NOT NULL DEFAULT '[]',
                    blocked_hours TEXT    NOT NULL DEFAULT '[]'
                );
            "#).execute(&self.pool).await?;

            Ok::<_, sqlx::Error>(())
        })?;
        Ok(())
    }

    /// Add columns introduced after initial schema creation (idempotent).
    fn migrate_schema(&self) -> Result<()> {
        let rt = self.rt.lock().expect("query_log runtime mutex poisoned");
        rt.block_on(async {
            // Ignore error – column already exists on fresh DBs.
            let _ = sqlx::query(
                "ALTER TABLE query_log ADD COLUMN dnssec_status TEXT"
            ).execute(&self.pool).await;
            Ok::<_, sqlx::Error>(())
        })?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Write
    // -----------------------------------------------------------------------

    /// Insert a new query log entry and prune entries older than 30 days.
    pub fn log_query(
        &self,
        client_ip: &str,
        domain: &str,
        query_type: &str,
        resolved_ip: Option<&str>,
        blocked: bool,
        response_ms: i64,
    ) {
        self.log_query_with_dnssec(client_ip, domain, query_type, resolved_ip, blocked, response_ms, None);
    }

    /// Like [`log_query`] but also records the DNSSEC validation status
    /// (`"SECURE"`, `"BOGUS"`, `"INDETERMINATE"`, or `None`).
    pub fn log_query_with_dnssec(
        &self,
        client_ip: &str,
        domain: &str,
        query_type: &str,
        resolved_ip: Option<&str>,
        blocked: bool,
        response_ms: i64,
        dnssec_status: Option<&str>,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let cutoff = now - 30 * 86400;
        let blocked_i = blocked as i64;

        let client_ip = client_ip.to_string();
        let domain = domain.to_string();
        let query_type = query_type.to_string();
        let resolved_ip = resolved_ip.map(|s| s.to_string());
        let dnssec_status = dnssec_status.map(|s| s.to_string());

        let rt = match self.rt.lock() {
            Ok(r) => r,
            Err(_) => return,
        };

        let _ = rt.block_on(async {
            let _ = sqlx::query(
                "INSERT INTO query_log \
                 (timestamp, client_ip, domain, query_type, resolved_ip, blocked, response_ms, dnssec_status) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(now)
            .bind(&client_ip)
            .bind(&domain)
            .bind(&query_type)
            .bind(resolved_ip.as_deref())
            .bind(blocked_i)
            .bind(response_ms)
            .bind(dnssec_status.as_deref())
            .execute(&self.pool)
            .await;

            let _ = sqlx::query("DELETE FROM query_log WHERE timestamp < ?")
                .bind(cutoff)
                .execute(&self.pool)
                .await;
        });
    }

    // -----------------------------------------------------------------------
    // Read
    // -----------------------------------------------------------------------

    /// Return up to `limit` recent entries (newest first) with optional filters.
    pub fn get_log(
        &self,
        limit: usize,
        client_filter: Option<&str>,
        blocked_filter: Option<bool>,
    ) -> Vec<QueryLogEntry> {
        let limit = limit as i64;
        let client_filter = client_filter.map(|s| s.to_string());
        let blocked_filter = blocked_filter.map(|b| b as i64);

        let rt = match self.rt.lock() {
            Ok(r) => r,
            Err(_) => return vec![],
        };

        rt.block_on(async {
            // Build query dynamically based on filters
            let mut query_str = String::from(
                "SELECT id, timestamp, client_ip, domain, query_type, resolved_ip, blocked, response_ms, dnssec_status \
                 FROM query_log WHERE 1=1"
            );
            if client_filter.is_some() {
                query_str.push_str(" AND client_ip = ?");
            }
            if blocked_filter.is_some() {
                query_str.push_str(" AND blocked = ?");
            }
            query_str.push_str(" ORDER BY timestamp DESC LIMIT ?");

            let mut q = sqlx::query(&query_str);
            if let Some(ref cf) = client_filter {
                q = q.bind(cf);
            }
            if let Some(bf) = blocked_filter {
                q = q.bind(bf);
            }
            q = q.bind(limit);

            let rows = q.fetch_all(&self.pool).await.unwrap_or_default();
            rows.iter().map(|row| {
                let blocked_i: i64 = row.get::<i64, _>(6);
                QueryLogEntry {
                    id:            row.get::<i64, _>(0),
                    timestamp:     row.get::<i64, _>(1),
                    client_ip:     row.get::<String, _>(2),
                    domain:        row.get::<String, _>(3),
                    query_type:    row.get::<String, _>(4),
                    resolved_ip:   row.get::<Option<String>, _>(5),
                    blocked:       blocked_i != 0,
                    response_ms:   row.get::<i64, _>(7),
                    dnssec_status: row.get::<Option<String>, _>(8),
                }
            }).collect()
        })
    }

    /// Return all entries with timestamp >= `since`.
    pub fn queries_since(&self, since: i64) -> Vec<QueryLogEntry> {
        let rt = match self.rt.lock() {
            Ok(r) => r,
            Err(_) => return vec![],
        };

        rt.block_on(async {
            let rows = sqlx::query(
                "SELECT id, timestamp, client_ip, domain, query_type, resolved_ip, blocked, response_ms, dnssec_status \
                 FROM query_log WHERE timestamp >= ? ORDER BY timestamp DESC"
            )
            .bind(since)
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default();

            rows.iter().map(|row| {
                let blocked_i: i64 = row.get::<i64, _>(6);
                QueryLogEntry {
                    id:            row.get::<i64, _>(0),
                    timestamp:     row.get::<i64, _>(1),
                    client_ip:     row.get::<String, _>(2),
                    domain:        row.get::<String, _>(3),
                    query_type:    row.get::<String, _>(4),
                    resolved_ip:   row.get::<Option<String>, _>(5),
                    blocked:       blocked_i != 0,
                    response_ms:   row.get::<i64, _>(7),
                    dnssec_status: row.get::<Option<String>, _>(8),
                }
            }).collect()
        })
    }

    /// Return the top `n` blocked domains by frequency.
    pub fn top_blocked_domains(&self, n: usize) -> Vec<(String, u64)> {
        let n = n as i64;
        let rt = match self.rt.lock() {
            Ok(r) => r,
            Err(_) => return vec![],
        };

        rt.block_on(async {
            let rows = sqlx::query(
                "SELECT domain, COUNT(*) as cnt FROM query_log \
                 WHERE blocked = 1 GROUP BY domain ORDER BY cnt DESC LIMIT ?"
            )
            .bind(n)
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default();

            rows.iter().map(|row| {
                let domain: String = row.get::<String, _>(0);
                let cnt: i64 = row.get::<i64, _>(1);
                (domain, cnt as u64)
            }).collect()
        })
    }

    /// Return (hour_timestamp, query_count) pairs for the past `hours` hours.
    pub fn timeline_by_hour(&self, hours: u64) -> Vec<(u64, u64)> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let since = now - (hours as i64) * 3600;

        let rt = match self.rt.lock() {
            Ok(r) => r,
            Err(_) => return vec![],
        };

        rt.block_on(async {
            let rows = sqlx::query(
                "SELECT (timestamp/3600)*3600 as hour_ts, COUNT(*) as cnt \
                 FROM query_log WHERE timestamp >= ? \
                 GROUP BY hour_ts ORDER BY hour_ts ASC"
            )
            .bind(since)
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default();

            rows.iter().map(|row| {
                let hour_ts: i64 = row.get::<i64, _>(0);
                let cnt: i64 = row.get::<i64, _>(1);
                (hour_ts as u64, cnt as u64)
            }).collect()
        })
    }

    /// Return per-client aggregate statistics.
    pub fn get_clients(&self) -> Vec<ClientStats> {
        let rt = match self.rt.lock() {
            Ok(r) => r,
            Err(_) => return vec![],
        };

        rt.block_on(async {
            let rows = sqlx::query(
                "SELECT client_ip, COUNT(*) as query_count, \
                        SUM(blocked) as blocked_count, MAX(timestamp) as last_seen \
                 FROM query_log GROUP BY client_ip ORDER BY query_count DESC"
            )
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default();

            rows.iter().map(|row| {
                ClientStats {
                    client_ip:     row.get::<String, _>(0),
                    query_count:   row.get::<i64, _>(1),
                    blocked_count: row.get::<i64, _>(2),
                    last_seen:     row.get::<i64, _>(3),
                }
            }).collect()
        })
    }

    // -----------------------------------------------------------------------
    // Client policies
    // -----------------------------------------------------------------------

    /// Return the policy for `ip`, or `None` if no policy has been set.
    pub fn get_client_policy(&self, ip: &str) -> Option<ClientPolicy> {
        let ip = ip.to_string();
        let rt = self.rt.lock().ok()?;

        rt.block_on(async {
            let row = sqlx::query(
                "SELECT bypass_all, extra_block, blocked_hours FROM client_policies WHERE ip = ?"
            )
            .bind(&ip)
            .fetch_optional(&self.pool)
            .await
            .ok()??;

            let bypass_all: i64 = row.get::<i64, _>(0);
            let extra_block_json: String = row.get::<String, _>(1);
            let blocked_hours_json: String = row.get::<String, _>(2);

            let extra_block: Vec<String> = serde_json::from_str(&extra_block_json).unwrap_or_default();
            let blocked_hours: Vec<u32> = serde_json::from_str(&blocked_hours_json).unwrap_or_default();

            Some(ClientPolicy {
                bypass_all: bypass_all != 0,
                extra_block,
                blocked_hours,
            })
        })
    }

    /// Upsert the policy for `ip`.
    pub fn set_client_policy(&self, ip: &str, policy: &ClientPolicy) -> Result<()> {
        let ip = ip.to_string();
        let bypass_all = policy.bypass_all as i64;
        let extra_block = serde_json::to_string(&policy.extra_block)?;
        let blocked_hours = serde_json::to_string(&policy.blocked_hours)?;

        let rt = self.rt.lock().expect("query_log runtime mutex poisoned");
        rt.block_on(async {
            sqlx::query(
                "INSERT INTO client_policies (ip, bypass_all, extra_block, blocked_hours) \
                 VALUES (?, ?, ?, ?) \
                 ON CONFLICT(ip) DO UPDATE SET \
                     bypass_all    = excluded.bypass_all, \
                     extra_block   = excluded.extra_block, \
                     blocked_hours = excluded.blocked_hours"
            )
            .bind(&ip)
            .bind(bypass_all)
            .bind(&extra_block)
            .bind(&blocked_hours)
            .execute(&self.pool)
            .await?;
            Ok::<_, sqlx::Error>(())
        })?;
        Ok(())
    }
}
