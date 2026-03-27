//! Structured DNS query logger with daily file rotation.
//!
//! Every DNS query is logged as a single JSON line:
//! ```json
//! {"ts":"2026-03-27T14:05:32.123Z","client_ip":"10.0.0.5","qname":"example.com",
//!  "qtype":"A","rcode":"NOERROR","latency_ms":2.4,"cache_hit":true,"upstream":"8.8.8.8"}
//! ```
//!
//! Files are written to `<log_dir>/queries-YYYY-MM-DD.jsonl`.
//! On each write the logger checks if the date rolled over and opens a new file.
//! Files older than `retention_days` are deleted on rotation.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{NaiveDate, Utc};
use serde::Serialize;

/// A single structured query log entry.
#[derive(Debug, Clone, Serialize)]
pub struct QueryLogEntry {
    /// ISO-8601 timestamp
    pub ts: String,
    /// Client IP address
    pub client_ip: String,
    /// Query name (domain)
    pub qname: String,
    /// Query type (A, AAAA, MX, …)
    pub qtype: String,
    /// Response code (NOERROR, NXDOMAIN, SERVFAIL, …)
    pub rcode: String,
    /// Query latency in milliseconds
    pub latency_ms: f64,
    /// Whether the response was served from cache
    pub cache_hit: bool,
    /// Upstream server used (empty string if authoritative / cached)
    pub upstream: String,
}

/// Thread-safe rotating query logger.
pub struct RotatingQueryLog {
    inner: Mutex<Inner>,
}

struct Inner {
    log_dir: PathBuf,
    retention_days: i64,
    current_date: NaiveDate,
    writer: BufWriter<File>,
}

impl RotatingQueryLog {
    /// Create a new rotating query logger.
    ///
    /// * `log_dir`        – directory for log files (created if missing)
    /// * `retention_days` – delete files older than this (default 7)
    pub fn new(log_dir: impl AsRef<Path>, retention_days: u32) -> std::io::Result<Self> {
        let log_dir = log_dir.as_ref().to_path_buf();
        fs::create_dir_all(&log_dir)?;

        let today = Utc::now().date_naive();
        let file = open_log_file(&log_dir, today)?;

        Ok(Self {
            inner: Mutex::new(Inner {
                log_dir,
                retention_days: retention_days as i64,
                current_date: today,
                writer: BufWriter::new(file),
            }),
        })
    }

    /// Log a single query entry.  Rotates the file if the date changed.
    pub fn log(&self, entry: &QueryLogEntry) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(e) => {
                log::error!("query_log lock poisoned: {}", e);
                return;
            }
        };

        let today = Utc::now().date_naive();
        if today != inner.current_date {
            // Flush old writer
            let _ = inner.writer.flush();

            // Open new file
            match open_log_file(&inner.log_dir, today) {
                Ok(f) => {
                    inner.writer = BufWriter::new(f);
                    inner.current_date = today;
                }
                Err(e) => {
                    log::error!("query_log: failed to rotate: {}", e);
                    return;
                }
            }

            // Prune old files
            prune_old_files(&inner.log_dir, inner.retention_days);
        }

        match serde_json::to_string(entry) {
            Ok(json) => {
                let _ = inner.writer.write_all(json.as_bytes());
                let _ = inner.writer.write_all(b"\n");
                // Flush periodically is handled by BufWriter; explicit flush
                // every 64 entries would be an option but we keep it simple.
            }
            Err(e) => {
                log::error!("query_log: serialize error: {}", e);
            }
        }
    }

    /// Flush the writer (call on graceful shutdown).
    pub fn flush(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            let _ = inner.writer.flush();
        }
    }
}

fn log_file_name(date: NaiveDate) -> String {
    format!("queries-{}.jsonl", date.format("%Y-%m-%d"))
}

fn open_log_file(dir: &Path, date: NaiveDate) -> std::io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(log_file_name(date)))
}

fn prune_old_files(dir: &Path, retention_days: i64) {
    let cutoff = Utc::now().date_naive() - chrono::Duration::days(retention_days);

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        // Parse date from "queries-YYYY-MM-DD.jsonl"
        if let Some(date_str) = name_str
            .strip_prefix("queries-")
            .and_then(|s| s.strip_suffix(".jsonl"))
        {
            if let Ok(file_date) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
                if file_date < cutoff {
                    let _ = fs::remove_file(entry.path());
                    log::info!("query_log: pruned old log {}", name_str);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn test_log_and_read() {
        let dir = std::env::temp_dir().join("atlas_qlog_test");
        let _ = fs::remove_dir_all(&dir);

        let logger = RotatingQueryLog::new(&dir, 7).unwrap();
        let entry = QueryLogEntry {
            ts: "2026-03-27T00:00:00Z".into(),
            client_ip: "10.0.0.1".into(),
            qname: "example.com".into(),
            qtype: "A".into(),
            rcode: "NOERROR".into(),
            latency_ms: 1.5,
            cache_hit: false,
            upstream: "8.8.8.8".into(),
        };
        logger.log(&entry);
        logger.flush();

        let today = Utc::now().date_naive();
        let path = dir.join(log_file_name(today));
        let mut content = String::new();
        File::open(&path).unwrap().read_to_string(&mut content).unwrap();

        assert!(content.contains("example.com"));
        assert!(content.contains("NOERROR"));

        let _ = fs::remove_dir_all(&dir);
    }
}
