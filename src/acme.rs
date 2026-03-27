//! ACME v2 certificate management using the `instant-acme` crate.
//!
//! Provides automatic certificate issuance and renewal via DNS-01 challenges
//! for Let's Encrypt, ZeroSSL, or any RFC 8555-compliant CA.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy, ZeroSsl,
};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::dns::authority::Authority;
use crate::dns::protocol::{DnsRecord, TransientTtl};

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

/// Supported ACME providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AcmeProvider {
    LetsEncrypt,
    LetsEncryptStaging,
    ZeroSsl,
    Custom { directory_url: String },
}

impl AcmeProvider {
    pub fn directory_url(&self) -> &str {
        match self {
            Self::LetsEncrypt => LetsEncrypt::Production.url(),
            Self::LetsEncryptStaging => LetsEncrypt::Staging.url(),
            Self::ZeroSsl => ZeroSsl::Production.url(),
            Self::Custom { directory_url } => directory_url,
        }
    }
}

/// Configuration for the ACME certificate manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    pub provider: AcmeProvider,
    pub email: String,
    pub domains: Vec<String>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub credentials_path: PathBuf,
    pub renew_days_before_expiry: u32,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            provider: AcmeProvider::LetsEncrypt,
            email: String::new(),
            domains: Vec::new(),
            cert_path: PathBuf::from("/opt/atlas/certs/cert.pem"),
            key_path: PathBuf::from("/opt/atlas/certs/key.pem"),
            credentials_path: PathBuf::from("/opt/atlas/certs/acme_credentials.json"),
            renew_days_before_expiry: 30,
        }
    }
}

/// Result of a certificate issuance or renewal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateResult {
    pub success: bool,
    pub message: String,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

// ---------------------------------------------------------------------------
// ACME Certificate Manager
// ---------------------------------------------------------------------------

/// Manages ACME certificate lifecycle: issuance, DNS-01 challenges, and renewal.
pub struct AcmeCertificateManager {
    config: AcmeConfig,
    authority: Arc<Authority>,
}

impl AcmeCertificateManager {
    pub fn new(config: AcmeConfig, authority: Arc<Authority>) -> Self {
        Self { config, authority }
    }

    /// Check whether the current certificate needs renewal.
    pub fn needs_renewal(&self) -> bool {
        if !self.config.cert_path.exists() {
            return true;
        }
        match self.days_until_expiry() {
            Some(days) => days < self.config.renew_days_before_expiry as i64,
            None => true,
        }
    }

    /// Days until the current certificate expires, or None if unreadable.
    fn days_until_expiry(&self) -> Option<i64> {
        let pem = fs::read(&self.config.cert_path).ok()?;
        let cert = openssl::x509::X509::from_pem(&pem).ok()?;
        let not_after = cert.not_after();
        let now = openssl::asn1::Asn1Time::days_from_now(0).ok()?;
        let diff = now.diff(not_after).ok()?;
        Some(diff.days as i64)
    }

    /// Obtain or renew a certificate via ACME DNS-01 challenge.
    pub async fn obtain_certificate(&self) -> Result<CertificateResult, Box<dyn std::error::Error>> {
        log::info!("[ACME] Starting certificate issuance for {:?}", self.config.domains);

        if let Some(parent) = self.config.cert_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let account = self.get_or_create_account().await?;

        let identifiers: Vec<Identifier> = self
            .config
            .domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();

        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await?;

        // Process each authorization — set up DNS-01 challenges
        let mut authorizations = order.authorizations();
        while let Some(authz_result) = authorizations.next().await {
            let mut authz = authz_result?;

            // AuthorizationHandle derefs to AuthorizationState
            if authz.status == instant_acme::AuthorizationStatus::Valid {
                continue;
            }

            let domain = authz.identifier().to_string();

            // Get DNS-01 challenge handle
            let mut challenge = match authz.challenge(ChallengeType::Dns01) {
                Some(c) => c,
                None => {
                    return Err(format!("No DNS-01 challenge for {}", domain).into());
                }
            };

            // Compute the DNS TXT value
            let key_auth = challenge.key_authorization();
            let digest = key_auth.dns_value();
            let challenge_fqdn = format!(
                "_acme-challenge.{}",
                domain.strip_prefix("*.").unwrap_or(&domain)
            );

            log::info!("[ACME] Setting TXT {} = {}", challenge_fqdn, digest);

            // Extract the zone name (base domain) for authority upsert
            let zone = extract_zone(&domain);
            let _ = self.authority.upsert(
                &zone,
                DnsRecord::Txt {
                    domain: challenge_fqdn.clone(),
                    data: digest,
                    ttl: TransientTtl(60),
                },
            );

            // Allow DNS propagation
            sleep(Duration::from_secs(2)).await;

            // Notify the ACME server
            challenge.set_ready().await?;
        }
        drop(authorizations);

        // Poll until the order is ready
        let retry = RetryPolicy::default();
        let status = order.poll_ready(&retry).await?;
        if status != OrderStatus::Ready {
            return Err(format!("Order not ready, status: {:?}", status).into());
        }

        // Finalize — generates CSR internally and returns private key PEM
        let private_key_pem = order.finalize().await?;

        // Retrieve the certificate chain
        let cert_chain = order.poll_certificate(&retry).await?;

        // Write to disk
        fs::write(&self.config.cert_path, cert_chain.as_bytes())?;
        fs::write(&self.config.key_path, private_key_pem.as_bytes())?;

        // Clean up challenge TXT records
        for d in &self.config.domains {
            let bare = d.strip_prefix("*.").unwrap_or(d);
            let challenge_fqdn = format!("_acme-challenge.{}", bare);
            let zone = extract_zone(d);
            let _ = self.authority.delete_records(&zone, &challenge_fqdn);
        }

        log::info!("[ACME] Certificate saved to {}", self.config.cert_path.display());

        Ok(CertificateResult {
            success: true,
            message: format!("Certificate issued for {} domain(s)", self.config.domains.len()),
            cert_path: Some(self.config.cert_path.to_string_lossy().into_owned()),
            key_path: Some(self.config.key_path.to_string_lossy().into_owned()),
        })
    }

    /// Load existing credentials or create a new ACME account.
    async fn get_or_create_account(&self) -> Result<Account, Box<dyn std::error::Error>> {
        if self.config.credentials_path.exists() {
            let data = fs::read_to_string(&self.config.credentials_path)?;
            let credentials: AccountCredentials = serde_json::from_str(&data)?;
            let account = Account::builder()
                .map_err(|e| format!("Failed to build ACME client: {}", e))?
                .from_credentials(credentials)
                .await
                .map_err(|e| format!("Failed to restore account: {}", e))?;
            log::info!("[ACME] Restored existing account");
            return Ok(account);
        }

        let url = self.config.provider.directory_url().to_string();
        let contact = format!("mailto:{}", self.config.email);
        let new_account = NewAccount {
            contact: &[&contact],
            terms_of_service_agreed: true,
            only_return_existing: false,
        };

        let (account, credentials) = Account::builder()
            .map_err(|e| format!("Failed to build ACME client: {}", e))?
            .create(&new_account, url, None)
            .await
            .map_err(|e| format!("Failed to create account: {}", e))?;

        if let Some(parent) = self.config.credentials_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let cred_json = serde_json::to_string_pretty(&credentials)?;
        fs::write(&self.config.credentials_path, cred_json)?;
        log::info!("[ACME] Created new account, credentials saved");

        Ok(account)
    }

    /// Start a background renewal loop that checks daily and renews if needed.
    pub fn start_renewal_loop(config: AcmeConfig, authority: Arc<Authority>) {
        tokio::spawn(async move {
            let manager = AcmeCertificateManager::new(config, authority);
            loop {
                if manager.needs_renewal() {
                    log::info!("[ACME] Certificate needs renewal, starting...");
                    match manager.obtain_certificate().await {
                        Ok(result) => log::info!("[ACME] Renewal: {}", result.message),
                        Err(e) => log::error!("[ACME] Renewal failed: {}", e),
                    }
                } else {
                    log::debug!("[ACME] Certificate OK, next check in 24h");
                }
                sleep(Duration::from_secs(86400)).await;
            }
        });
    }
}

/// Extract the base zone from a domain (e.g. "sub.example.com" -> "example.com").
fn extract_zone(domain: &str) -> String {
    let d = domain.strip_prefix("*.").unwrap_or(domain);
    let parts: Vec<&str> = d.split('.').collect();
    if parts.len() >= 2 {
        parts[parts.len() - 2..].join(".")
    } else {
        d.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acme_config_default() {
        let config = AcmeConfig::default();
        assert_eq!(config.renew_days_before_expiry, 30);
        assert!(config.domains.is_empty());
    }

    #[test]
    fn test_provider_urls() {
        let le = AcmeProvider::LetsEncrypt;
        assert!(le.directory_url().contains("letsencrypt"));

        let staging = AcmeProvider::LetsEncryptStaging;
        assert!(staging.directory_url().contains("staging"));

        let custom = AcmeProvider::Custom {
            directory_url: "https://custom.example.com/dir".to_string(),
        };
        assert_eq!(custom.directory_url(), "https://custom.example.com/dir");
    }

    #[test]
    fn test_extract_zone() {
        assert_eq!(extract_zone("example.com"), "example.com");
        assert_eq!(extract_zone("sub.example.com"), "example.com");
        assert_eq!(extract_zone("*.example.com"), "example.com");
    }
}
