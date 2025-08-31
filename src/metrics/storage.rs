//! Time-series storage for metrics using SQLite

use super::{DnsQueryMetric, SystemMetric, SecurityEvent};
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions, Row};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

/// Time-series data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesData {
    pub timestamp: i64,
    pub metric_type: String,
    pub metric_name: String,
    pub value: f64,
    pub labels: Option<String>,
}

/// Metrics storage using SQLite
pub struct MetricsStorage {
    pool: SqlitePool,
}

impl MetricsStorage {
    /// Create a new metrics storage instance
    pub async fn new(db_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(db_path)
            .await?;

        let storage = Self { pool };
        storage.initialize_schema().await?;
        Ok(storage)
    }

    /// Initialize database schema
    async fn initialize_schema(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Main metrics table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS metrics (
                timestamp INTEGER NOT NULL,
                metric_type TEXT NOT NULL,
                metric_name TEXT NOT NULL,
                value REAL NOT NULL,
                labels TEXT,
                PRIMARY KEY (timestamp, metric_type, metric_name)
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        // Indices for efficient queries
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_metrics_time ON metrics(timestamp)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_metrics_type ON metrics(metric_type)")
            .execute(&self.pool)
            .await?;

        // DNS query log table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS dns_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                domain TEXT NOT NULL,
                query_type TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                response_code TEXT NOT NULL,
                response_time_ms REAL NOT NULL,
                cache_hit INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                upstream_server TEXT,
                dnssec_validated INTEGER
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_queries_time ON dns_queries(timestamp)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_queries_domain ON dns_queries(domain)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_queries_client ON dns_queries(client_ip)")
            .execute(&self.pool)
            .await?;

        // System metrics table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS system_metrics (
                timestamp INTEGER PRIMARY KEY,
                cpu_usage REAL NOT NULL,
                memory_usage_mb INTEGER NOT NULL,
                network_rx_bytes INTEGER NOT NULL,
                network_tx_bytes INTEGER NOT NULL,
                active_connections INTEGER NOT NULL,
                cache_entries INTEGER NOT NULL
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        // Security events table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                target_domain TEXT,
                action_taken TEXT NOT NULL,
                severity TEXT NOT NULL
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_security_time ON security_events(timestamp)")
            .execute(&self.pool)
            .await?;

        // Aggregated metrics table for faster queries
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS aggregated_metrics (
                timestamp INTEGER NOT NULL,
                interval TEXT NOT NULL,
                query_count INTEGER NOT NULL,
                unique_clients INTEGER NOT NULL,
                cache_hits INTEGER NOT NULL,
                cache_misses INTEGER NOT NULL,
                avg_response_time_ms REAL NOT NULL,
                p50_response_time_ms REAL,
                p95_response_time_ms REAL,
                p99_response_time_ms REAL,
                PRIMARY KEY (timestamp, interval)
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Store a time-series data point
    pub async fn store_metric(&self, data: &TimeSeriesData) -> Result<(), Box<dyn std::error::Error>> {
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO metrics (timestamp, metric_type, metric_name, value, labels)
            VALUES (?, ?, ?, ?, ?)
            "#
        )
        .bind(data.timestamp)
        .bind(&data.metric_type)
        .bind(&data.metric_name)
        .bind(data.value)
        .bind(&data.labels)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Store a DNS query metric
    pub async fn store_query_metric(&self, metric: &DnsQueryMetric) -> Result<(), Box<dyn std::error::Error>> {
        let timestamp = metric.timestamp.duration_since(UNIX_EPOCH)?.as_secs() as i64;
        
        sqlx::query(
            r#"
            INSERT INTO dns_queries (
                timestamp, domain, query_type, client_ip, response_code,
                response_time_ms, cache_hit, protocol, upstream_server, dnssec_validated
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(timestamp)
        .bind(&metric.domain)
        .bind(&metric.query_type)
        .bind(&metric.client_ip)
        .bind(&metric.response_code)
        .bind(metric.response_time_ms)
        .bind(metric.cache_hit as i32)
        .bind(&metric.protocol)
        .bind(&metric.upstream_server)
        .bind(metric.dnssec_validated.map(|v| v as i32))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Store a system metric
    pub async fn store_system_metric(&self, metric: &SystemMetric) -> Result<(), Box<dyn std::error::Error>> {
        let timestamp = metric.timestamp.duration_since(UNIX_EPOCH)?.as_secs() as i64;
        
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO system_metrics (
                timestamp, cpu_usage, memory_usage_mb, network_rx_bytes,
                network_tx_bytes, active_connections, cache_entries
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(timestamp)
        .bind(metric.cpu_usage)
        .bind(metric.memory_usage_mb as i64)
        .bind(metric.network_rx_bytes as i64)
        .bind(metric.network_tx_bytes as i64)
        .bind(metric.active_connections as i64)
        .bind(metric.cache_entries as i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Store a security event
    pub async fn store_security_event(&self, event: &SecurityEvent) -> Result<(), Box<dyn std::error::Error>> {
        let timestamp = event.timestamp.duration_since(UNIX_EPOCH)?.as_secs() as i64;
        
        sqlx::query(
            r#"
            INSERT INTO security_events (
                timestamp, event_type, source_ip, target_domain, action_taken, severity
            )
            VALUES (?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(timestamp)
        .bind(&event.event_type)
        .bind(&event.source_ip)
        .bind(&event.target_domain)
        .bind(&event.action_taken)
        .bind(&event.severity)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Store a metrics snapshot for aggregation
    pub async fn store_snapshot(&self, snapshot: &super::collector::MetricsSnapshot) -> Result<(), Box<dyn std::error::Error>> {
        let timestamp = snapshot.timestamp.duration_since(UNIX_EPOCH)?.as_secs() as i64;
        
        // Store individual metrics
        for (query_type, count) in &snapshot.query_types {
            let data = TimeSeriesData {
                timestamp,
                metric_type: "query_type".to_string(),
                metric_name: query_type.clone(),
                value: *count as f64,
                labels: None,
            };
            self.store_metric(&data).await?;
        }

        for (response_code, count) in &snapshot.response_codes {
            let data = TimeSeriesData {
                timestamp,
                metric_type: "response_code".to_string(),
                metric_name: response_code.clone(),
                value: *count as f64,
                labels: None,
            };
            self.store_metric(&data).await?;
        }

        // Store system metrics
        let system_metric = SystemMetric {
            timestamp: snapshot.timestamp,
            cpu_usage: snapshot.system_metrics.cpu_usage,
            memory_usage_mb: snapshot.system_metrics.memory_usage_mb,
            network_rx_bytes: snapshot.system_metrics.network_rx_bytes,
            network_tx_bytes: snapshot.system_metrics.network_tx_bytes,
            active_connections: snapshot.system_metrics.active_connections,
            cache_entries: snapshot.system_metrics.cache_entries,
        };
        self.store_system_metric(&system_metric).await?;

        Ok(())
    }

    /// Query metrics within a time range
    pub async fn query_metrics(
        &self,
        metric_type: &str,
        start_time: SystemTime,
        end_time: SystemTime,
    ) -> Result<Vec<TimeSeriesData>, Box<dyn std::error::Error>> {
        let start = start_time.duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let end = end_time.duration_since(UNIX_EPOCH)?.as_secs() as i64;

        let rows = sqlx::query(
            r#"
            SELECT timestamp, metric_type, metric_name, value, labels
            FROM metrics
            WHERE metric_type = ? AND timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp ASC
            "#
        )
        .bind(metric_type)
        .bind(start)
        .bind(end)
        .fetch_all(&self.pool)
        .await?;

        let mut results = Vec::new();
        for row in rows {
            results.push(TimeSeriesData {
                timestamp: row.get("timestamp"),
                metric_type: row.get("metric_type"),
                metric_name: row.get("metric_name"),
                value: row.get("value"),
                labels: row.get("labels"),
            });
        }

        Ok(results)
    }

    /// Get DNS query analytics for a time range
    pub async fn get_query_analytics(
        &self,
        start_time: SystemTime,
        end_time: SystemTime,
    ) -> Result<Vec<DnsQueryMetric>, Box<dyn std::error::Error>> {
        let start = start_time.duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let end = end_time.duration_since(UNIX_EPOCH)?.as_secs() as i64;

        let rows = sqlx::query(
            r#"
            SELECT * FROM dns_queries
            WHERE timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp ASC
            "#
        )
        .bind(start)
        .bind(end)
        .fetch_all(&self.pool)
        .await?;

        let mut results = Vec::new();
        for row in rows {
            let timestamp_secs: i64 = row.get("timestamp");
            results.push(DnsQueryMetric {
                timestamp: UNIX_EPOCH + Duration::from_secs(timestamp_secs as u64),
                domain: row.get("domain"),
                query_type: row.get("query_type"),
                client_ip: row.get("client_ip"),
                response_code: row.get("response_code"),
                response_time_ms: row.get("response_time_ms"),
                cache_hit: row.get::<i32, _>("cache_hit") != 0,
                protocol: row.get("protocol"),
                upstream_server: row.get("upstream_server"),
                dnssec_validated: row.get::<Option<i32>, _>("dnssec_validated").map(|v| v != 0),
            });
        }

        Ok(results)
    }

    /// Get top queried domains
    pub async fn get_top_domains(
        &self,
        start_time: SystemTime,
        end_time: SystemTime,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, Box<dyn std::error::Error>> {
        let start = start_time.duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let end = end_time.duration_since(UNIX_EPOCH)?.as_secs() as i64;

        let rows = sqlx::query(
            r#"
            SELECT domain, COUNT(*) as count
            FROM dns_queries
            WHERE timestamp >= ? AND timestamp <= ?
            GROUP BY domain
            ORDER BY count DESC
            LIMIT ?
            "#
        )
        .bind(start)
        .bind(end)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        let mut results = Vec::new();
        for row in rows {
            results.push((
                row.get("domain"),
                row.get::<i64, _>("count") as u64,
            ));
        }

        Ok(results)
    }

    /// Get unique client count for a time range
    pub async fn get_unique_clients(
        &self,
        start_time: SystemTime,
        end_time: SystemTime,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let start = start_time.duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let end = end_time.duration_since(UNIX_EPOCH)?.as_secs() as i64;

        let row = sqlx::query(
            r#"
            SELECT COUNT(DISTINCT client_ip) as count
            FROM dns_queries
            WHERE timestamp >= ? AND timestamp <= ?
            "#
        )
        .bind(start)
        .bind(end)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.get::<i64, _>("count") as usize)
    }

    /// Clean up old data based on retention policy
    pub async fn cleanup_old_data(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Default retention: 30 days for detailed data, 90 days for aggregated
        let cutoff_detailed = (SystemTime::now() - Duration::from_secs(30 * 24 * 3600))
            .duration_since(UNIX_EPOCH)?
            .as_secs() as i64;
        let cutoff_aggregated = (SystemTime::now() - Duration::from_secs(90 * 24 * 3600))
            .duration_since(UNIX_EPOCH)?
            .as_secs() as i64;

        // Clean detailed data
        sqlx::query("DELETE FROM dns_queries WHERE timestamp < ?")
            .bind(cutoff_detailed)
            .execute(&self.pool)
            .await?;

        sqlx::query("DELETE FROM metrics WHERE timestamp < ?")
            .bind(cutoff_detailed)
            .execute(&self.pool)
            .await?;

        sqlx::query("DELETE FROM system_metrics WHERE timestamp < ?")
            .bind(cutoff_detailed)
            .execute(&self.pool)
            .await?;

        sqlx::query("DELETE FROM security_events WHERE timestamp < ?")
            .bind(cutoff_detailed)
            .execute(&self.pool)
            .await?;

        // Clean aggregated data
        sqlx::query("DELETE FROM aggregated_metrics WHERE timestamp < ?")
            .bind(cutoff_aggregated)
            .execute(&self.pool)
            .await?;

        // Vacuum to reclaim space
        sqlx::query("VACUUM")
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_storage_initialization() {
        let storage = MetricsStorage::new(":memory:").await.unwrap();
        assert!(storage.pool.acquire().await.is_ok());
    }

    #[tokio::test]
    async fn test_store_and_query_metrics() {
        let storage = MetricsStorage::new(":memory:").await.unwrap();
        
        let data = TimeSeriesData {
            timestamp: 1000,
            metric_type: "test".to_string(),
            metric_name: "counter".to_string(),
            value: 42.0,
            labels: Some("{\"env\":\"test\"}".to_string()),
        };
        
        storage.store_metric(&data).await.unwrap();
        
        let results = storage.query_metrics(
            "test",
            UNIX_EPOCH,
            SystemTime::now(),
        ).await.unwrap();
        
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, 42.0);
    }
}