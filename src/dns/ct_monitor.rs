//! Certificate Transparency Log Monitor
//!
//! Monitors certificate transparency logs for domains you own.
//! Fetches from crt.sh every 6 hours and alerts via webhook when
//! a new certificate is issued (potential phishing indicator).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// A certificate entry from CT logs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertEntry {
    /// Certificate ID from crt.sh
    pub id: i64,
    /// Common name (CN) in the certificate
    pub common_name: String,
    /// Subject alternative names
    pub name_value: String,
    /// Issuer
    pub issuer_name: String,
    /// Certificate not-before date
    pub not_before: Option<String>,
    /// Certificate not-after date
    pub not_after: Option<String>,
    /// When we first observed this cert
    pub observed_at: DateTime<Utc>,
}

/// Alert sent when a new cert is detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtAlert {
    pub timestamp: DateTime<Utc>,
    pub monitored_domain: String,
    pub cert: CertEntry,
}

/// CT Monitor configuration
#[derive(Debug, Clone)]
pub struct CtMonitorConfig {
    /// Enable CT monitoring
    pub enabled: bool,
    /// Domains to monitor (e.g. ["yourdomain.com"])
    pub monitored_domains: Vec<String>,
    /// Webhook URL for new-cert alerts
    pub webhook_url: Option<String>,
    /// Check interval (default: 6 hours)
    pub check_interval: Duration,
    /// crt.sh base URL
    pub crtsh_url: String,
}

impl Default for CtMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            monitored_domains: vec![],
            webhook_url: None,
            check_interval: Duration::from_secs(6 * 3600),
            crtsh_url: "https://crt.sh".to_string(),
        }
    }
}

/// crt.sh JSON API response entry
#[derive(Debug, Deserialize)]
struct CrtShEntry {
    id: i64,
    #[serde(rename = "common_name")]
    common_name: String,
    #[serde(rename = "name_value")]
    name_value: String,
    #[serde(rename = "issuer_name")]
    issuer_name: String,
    not_before: Option<String>,
    not_after: Option<String>,
}

/// Certificate transparency monitor
pub struct CertTransparencyMonitor {
    config: CtMonitorConfig,
    /// domain -> set of cert IDs we've already seen
    known_certs: Arc<RwLock<HashMap<String, HashSet<i64>>>>,
    /// Recent alerts
    alerts: Arc<RwLock<Vec<CtAlert>>>,
}

impl CertTransparencyMonitor {
    pub fn new(config: CtMonitorConfig) -> Self {
        Self {
            config,
            known_certs: Arc::new(RwLock::new(HashMap::new())),
            alerts: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Check a single domain against crt.sh and return any new certificates
    pub async fn check_domain(&self, domain: &str) -> Result<Vec<CertEntry>, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("AtlasDNS/1.0 (ct-monitor)")
            .build()?;

        let url = format!("{}/?q={}&output=json", self.config.crtsh_url, domain);
        log::debug!("[CT-MONITOR] Querying crt.sh for domain: {}", domain);

        let resp = client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Err(format!("crt.sh returned {}", resp.status()).into());
        }

        let entries: Vec<CrtShEntry> = resp.json().await.unwrap_or_default();
        let mut new_certs = vec![];

        let mut known = self.known_certs.write();
        let seen = known.entry(domain.to_string()).or_insert_with(HashSet::new);

        for entry in entries {
            if seen.contains(&entry.id) {
                continue;
            }
            seen.insert(entry.id);
            let cert = CertEntry {
                id: entry.id,
                common_name: entry.common_name,
                name_value: entry.name_value,
                issuer_name: entry.issuer_name,
                not_before: entry.not_before,
                not_after: entry.not_after,
                observed_at: Utc::now(),
            };
            new_certs.push(cert);
        }

        Ok(new_certs)
    }

    /// Check all monitored domains and fire alerts for new certs
    pub async fn run_check(&self) {
        for domain in &self.config.monitored_domains {
            match self.check_domain(domain).await {
                Ok(new_certs) if !new_certs.is_empty() => {
                    log::warn!(
                        "[CT-MONITOR] {} new cert(s) found for domain: {}",
                        new_certs.len(), domain
                    );
                    for cert in &new_certs {
                        log::warn!(
                            "[CT-MONITOR] New cert: id={} cn={} issuer={}",
                            cert.id, cert.common_name, cert.issuer_name
                        );
                        let alert = CtAlert {
                            timestamp: Utc::now(),
                            monitored_domain: domain.clone(),
                            cert: cert.clone(),
                        };
                        {
                            let mut alerts = self.alerts.write();
                            alerts.push(alert.clone());
                            if alerts.len() > 1000 {
                                alerts.drain(0..100);
                            }
                        }
                        if let Some(webhook_url) = &self.config.webhook_url {
                            if let Err(e) = Self::send_webhook(webhook_url, &alert).await {
                                log::error!("[CT-MONITOR] Webhook failed: {}", e);
                            }
                        }
                    }
                }
                Ok(_) => {
                    log::debug!("[CT-MONITOR] No new certs for {}", domain);
                }
                Err(e) => {
                    log::error!("[CT-MONITOR] Failed to check domain {}: {}", domain, e);
                }
            }
        }
    }

    async fn send_webhook(url: &str, alert: &CtAlert) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;

        let payload = serde_json::json!({
            "event": "new_certificate",
            "timestamp": alert.timestamp.to_rfc3339(),
            "monitored_domain": alert.monitored_domain,
            "cert_id": alert.cert.id,
            "common_name": alert.cert.common_name,
            "name_value": alert.cert.name_value,
            "issuer": alert.cert.issuer_name,
            "not_before": alert.cert.not_before,
            "not_after": alert.cert.not_after,
        });

        client.post(url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        Ok(())
    }

    /// Get recent alerts
    pub fn get_alerts(&self, limit: usize) -> Vec<CtAlert> {
        let alerts = self.alerts.read();
        let start = alerts.len().saturating_sub(limit);
        alerts[start..].to_vec()
    }

    /// Get stats
    pub fn get_stats(&self) -> serde_json::Value {
        let known = self.known_certs.read();
        let total_certs: usize = known.values().map(|s| s.len()).sum();
        serde_json::json!({
            "enabled": self.config.enabled,
            "monitored_domains": self.config.monitored_domains,
            "total_certs_tracked": total_certs,
            "total_alerts": self.alerts.read().len(),
            "check_interval_secs": self.config.check_interval.as_secs(),
        })
    }

    /// Start background monitoring loop
    pub fn start_monitoring(self: Arc<Self>) {
        if !self.config.enabled || self.config.monitored_domains.is_empty() {
            return;
        }
        let interval = self.config.check_interval;
        tokio::spawn(async move {
            loop {
                self.run_check().await;
                tokio::time::sleep(interval).await;
            }
        });
    }
}
