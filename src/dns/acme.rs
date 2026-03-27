use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use serde_derive::{Deserialize, Serialize};
extern crate sentry;

use crate::dns::context::ServerContext;
use crate::dns::protocol::{DnsRecord, TransientTtl};

// ---------------------------------------------------------------------------
// ACME provider
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AcmeProvider {
    LetsEncrypt,
    LetsEncryptStaging,
    ZeroSSL,
    Custom { url: String },
}

impl AcmeProvider {
    pub fn get_directory_url(&self) -> &str {
        match self {
            AcmeProvider::LetsEncrypt => "https://acme-v02.api.letsencrypt.org/directory",
            AcmeProvider::LetsEncryptStaging => "https://acme-staging-v02.api.letsencrypt.org/directory",
            AcmeProvider::ZeroSSL => "https://acme.zerossl.com/v2/DV90",
            AcmeProvider::Custom { url } => url,
        }
    }
}

// ---------------------------------------------------------------------------
// ACME configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    pub provider: AcmeProvider,
    pub email: String,
    pub domains: Vec<String>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub account_key_path: PathBuf,
    pub renew_days_before_expiry: u32,
    pub use_dns_challenge: bool,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        AcmeConfig {
            provider: AcmeProvider::LetsEncrypt,
            email: String::new(),
            domains: Vec::new(),
            cert_path: PathBuf::from("/opt/atlas/certs/cert.pem"),
            key_path: PathBuf::from("/opt/atlas/certs/key.pem"),
            account_key_path: PathBuf::from("/opt/atlas/certs/account.pem"),
            renew_days_before_expiry: 30,
            use_dns_challenge: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Certificate status
// ---------------------------------------------------------------------------

/// Certificate status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateStatus {
    pub valid: bool,
    pub days_until_expiry: i64,
    pub needs_renewal: bool,
    pub issuer: String,
    pub subject: String,
}

// ---------------------------------------------------------------------------
// AcmeCertificateManager  (powered by the `acme2` crate)
// ---------------------------------------------------------------------------

pub struct AcmeCertificateManager {
    config: AcmeConfig,
    context: Arc<ServerContext>,
}

impl AcmeCertificateManager {
    pub fn new(config: AcmeConfig, context: Arc<ServerContext>) -> Result<Self, Box<dyn std::error::Error>> {
        if let Some(parent) = config.cert_path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(AcmeCertificateManager { config, context })
    }

    // ── Public helpers ──────────────────────────────────────────────────────

    /// Return true if the cert doesn't exist or expires within renew_days_before_expiry.
    pub fn needs_renewal(&self) -> bool {
        if !self.config.cert_path.exists() {
            return true;
        }
        match self.days_until_expiry() {
            Some(days) => days < self.config.renew_days_before_expiry as i64,
            None => true,
        }
    }

    fn days_until_expiry(&self) -> Option<i64> {
        let cert = self.load_certificate().ok()?;
        let not_after = cert.not_after();
        let now = openssl::asn1::Asn1Time::days_from_now(0).ok()?;
        let diff = now.diff(not_after).ok()?;
        Some(diff.days as i64)
    }

    /// Get certificate status information.
    pub fn get_certificate_status(&self) -> CertificateStatus {
        match self.load_certificate() {
            Ok(cert) => {
                let days = self.days_until_expiry().unwrap_or(0);
                let issuer = cert
                    .issuer_name()
                    .entries()
                    .map(|e| e.data().as_utf8().map(|s| s.to_string()).unwrap_or_default())
                    .collect::<Vec<_>>()
                    .join(", ");
                let subject = cert
                    .subject_name()
                    .entries()
                    .map(|e| e.data().as_utf8().map(|s| s.to_string()).unwrap_or_default())
                    .collect::<Vec<_>>()
                    .join(", ");
                CertificateStatus {
                    valid: days > 0,
                    days_until_expiry: days,
                    needs_renewal: self.needs_renewal(),
                    issuer,
                    subject,
                }
            }
            Err(_) => CertificateStatus {
                valid: false,
                days_until_expiry: 0,
                needs_renewal: true,
                issuer: "Unknown".to_string(),
                subject: "No Certificate".to_string(),
            },
        }
    }

    pub fn load_certificate(&self) -> Result<X509, Box<dyn std::error::Error>> {
        let cert_pem = fs::read_to_string(&self.config.cert_path).map_err(|e| {
            sentry::capture_message(
                &format!("Failed to load certificate from {}: {}", self.config.cert_path.display(), e),
                sentry::Level::Error,
            );
            e
        })?;
        let cert = X509::from_pem(cert_pem.as_bytes()).map_err(|e| {
            sentry::capture_message(
                &format!("Failed to parse certificate from {}: {}", self.config.cert_path.display(), e),
                sentry::Level::Error,
            );
            e
        })?;
        Ok(cert)
    }

    pub fn load_private_key(&self) -> Result<PKey<Private>, Box<dyn std::error::Error>> {
        let key_pem = fs::read_to_string(&self.config.key_path)?;
        Ok(PKey::private_key_from_pem(key_pem.as_bytes())?)
    }

    // ── Main entry point ────────────────────────────────────────────────────

    /// Obtain or renew the certificate via ACME v2 DNS-01 challenge.
    pub fn obtain_certificate(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        log::info!(
            "Starting ACME certificate issuance for {:?} via {:?}",
            self.config.domains,
            self.config.provider,
        );

        match self.run_acme_flow() {
            Ok(()) => {
                log::info!("ACME certificate obtained successfully");
                Ok(())
            }
            Err(e) => {
                sentry::capture_message(
                    &format!("ACME certificate obtainment failed: {e}"),
                    sentry::Level::Error,
                );
                log::error!("ACME failed ({}); falling back to self-signed certificate", e);
                self.create_self_signed_certificate()
            }
        }
    }

    /// Spawn a background renewal thread (check daily, renew if < renew_days_before_expiry days remain).
    pub fn start_renewal_thread(config: AcmeConfig, context: Arc<ServerContext>) {
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(86_400));
                match AcmeCertificateManager::new(config.clone(), context.clone()) {
                    Ok(mut mgr) => {
                        if mgr.needs_renewal() {
                            log::info!("[ACME renewal] Certificate needs renewal; starting process");
                            if let Err(e) = mgr.obtain_certificate() {
                                log::error!("[ACME renewal] Renewal failed: {}", e);
                            }
                        } else {
                            let days = mgr.days_until_expiry().unwrap_or(999);
                            log::debug!("[ACME renewal] Certificate OK ({} days remaining)", days);
                        }
                    }
                    Err(e) => log::error!("[ACME renewal] Could not create manager: {}", e),
                }
            }
        });
    }

    // ── Internal ACME v2 flow (using acme2 crate) ──────────────────────────

    fn run_acme_flow(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // acme2 is async — create a dedicated tokio runtime for this blocking thread
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let config = self.config.clone();
        let context = self.context.clone();

        rt.block_on(async move {
            Self::run_acme_flow_async(&config, &context).await
        })
    }

    async fn run_acme_flow_async(
        config: &AcmeConfig,
        context: &Arc<ServerContext>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 1. Connect to ACME directory
        let dir = acme2::DirectoryBuilder::new(config.provider.get_directory_url().to_string())
            .build()
            .await?;

        // 2. Create or retrieve ACME account
        let mut account_builder = acme2::AccountBuilder::new(dir.clone());
        account_builder.contact(vec![format!("mailto:{}", config.email)]);
        account_builder.terms_of_service_agreed(true);

        // Load existing account key if present, otherwise let acme2 generate one
        if config.account_key_path.exists() {
            let pem = fs::read(&config.account_key_path)?;
            let pkey = PKey::private_key_from_pem(&pem)?;
            account_builder.private_key(pkey);
        }

        let account = account_builder.build().await?;

        // Save account key for future use
        if let Some(parent) = config.account_key_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let account_key = account.private_key();
        fs::write(&config.account_key_path, account_key.private_key_to_pem_pkcs8()?)?;
        log::info!("ACME account registered/loaded");

        // 3. Create order for all domains
        let mut order_builder = acme2::OrderBuilder::new(account.clone());
        for domain in &config.domains {
            order_builder.add_dns_identifier(domain.clone());
        }
        let order = order_builder.build().await?;
        log::info!("ACME order created");

        // 4. Process authorizations — set up DNS-01 challenges
        let authorizations = order.authorizations().await?;
        let mut challenge_records: Vec<String> = Vec::new();

        for auth in authorizations {
            let dns_challenge = auth
                .get_challenge("dns-01")
                .ok_or("No dns-01 challenge found for authorization")?;

            // Get the DNS TXT value for dns-01 (base64url-encoded SHA-256 of key authorization)
            let txt_value = dns_challenge
                .key_authorization_encoded()?
                .ok_or("No key authorization available")?;

            // Determine the challenge domain name
            let domain = &auth.identifier.value;
            let txt_name = challenge_domain(domain);

            // Install TXT record via authority
            Self::add_dns_record(context, &txt_name, &txt_value)?;
            challenge_records.push(txt_name.clone());
            log::info!("Installed DNS-01 challenge: {} = \"{}\"", txt_name, txt_value);

            // Wait for DNS propagation
            log::info!("Waiting 30s for DNS propagation of {}", txt_name);
            tokio::time::sleep(Duration::from_secs(30)).await;

            // Tell ACME server to validate
            let challenge = dns_challenge.validate().await?;

            // Poll until challenge is valid
            challenge.wait_done(Duration::from_secs(5), 20).await?;
            log::info!("DNS-01 challenge validated for {}", domain);

            // Poll authorization until done
            auth.wait_done(Duration::from_secs(5), 20).await?;
        }

        // 5. Wait for order to be ready
        let order = order.wait_ready(Duration::from_secs(5), 20).await?;
        log::info!("ACME order ready for finalization");

        // 6. Generate domain key and finalize with CSR
        let domain_key = acme2::gen_rsa_private_key(2048)?;
        let order = order.finalize(acme2::Csr::Automatic(domain_key.clone())).await?;

        // 7. Wait for order to be done
        let order = order.wait_done(Duration::from_secs(5), 20).await?;

        // 8. Download certificate chain
        let certs = order
            .certificate()
            .await?
            .ok_or("Order has no certificate")?;

        // Convert certificate chain to PEM
        let mut cert_pem = Vec::new();
        for cert in &certs {
            cert_pem.extend_from_slice(&cert.to_pem()?);
        }

        // Write cert and key to disk
        if let Some(parent) = config.cert_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&config.cert_path, &cert_pem)?;
        fs::write(&config.key_path, domain_key.private_key_to_pem_pkcs8()?)?;

        log::info!("Certificate saved to {}", config.cert_path.display());
        log::info!("Private key saved to {}", config.key_path.display());

        // 9. Clean up DNS challenge records
        for name in &challenge_records {
            if let Err(e) = Self::remove_dns_record(context, name) {
                log::warn!("Failed to remove ACME challenge record {}: {}", name, e);
            }
        }

        Ok(())
    }

    // ── Self-signed fallback ────────────────────────────────────────────────

    fn create_self_signed_certificate(&self) -> Result<(), Box<dyn std::error::Error>> {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509NameBuilder};

        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa)?;

        let mut x509_builder = X509Builder::new()?;
        x509_builder.set_version(2)?;

        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("CN", &self.config.domains[0])?;
        let name = name_builder.build();
        x509_builder.set_subject_name(&name)?;
        x509_builder.set_issuer_name(&name)?;

        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(90)?;
        x509_builder.set_not_before(&not_before)?;
        x509_builder.set_not_after(&not_after)?;
        x509_builder.set_pubkey(&pkey)?;
        x509_builder.sign(&pkey, MessageDigest::sha256())?;

        let cert = x509_builder.build();
        if let Some(parent) = self.config.cert_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.config.cert_path, cert.to_pem()?)?;
        fs::write(&self.config.key_path, pkey.private_key_to_pem_pkcs8()?)?;

        log::info!(
            "Created self-signed certificate (ACME fallback) for {}",
            self.config.domains[0]
        );
        Ok(())
    }

    // ── DNS challenge helpers ───────────────────────────────────────────────

    fn add_dns_record(context: &Arc<ServerContext>, name: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        let parts: Vec<&str> = name.split('.').collect();
        if parts.len() < 2 {
            return Err("Invalid record name".into());
        }
        let zone = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
        let record = DnsRecord::Txt {
            domain: name.to_string(),
            data: value.to_string(),
            ttl: TransientTtl(60),
        };
        context.authority.upsert(&zone, record)?;
        log::info!("Added ACME DNS challenge record: {} = {}", name, value);
        Ok(())
    }

    fn remove_dns_record(context: &Arc<ServerContext>, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let parts: Vec<&str> = name.split('.').collect();
        if parts.len() < 2 {
            return Err("Invalid record name".into());
        }
        let zone = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
        context.authority.delete_records(&zone, name)?;
        log::info!("Removed ACME DNS challenge record: {}", name);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Wildcard domain helpers
// ---------------------------------------------------------------------------

/// Check whether a domain is a wildcard (e.g. `*.example.com`).
pub fn is_wildcard_domain(domain: &str) -> bool {
    domain.starts_with("*.")
}

/// Return the base domain for ACME DNS-01 challenges.
/// For wildcard `*.example.com` the challenge record is
/// `_acme-challenge.example.com` (without the `*.` prefix).
pub fn challenge_domain(domain: &str) -> String {
    let base = if is_wildcard_domain(domain) {
        &domain[2..] // strip "*."
    } else {
        domain
    };
    format!("_acme-challenge.{}", base)
}

// ---------------------------------------------------------------------------
// SSL Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslConfig {
    pub enabled: bool,
    pub port: u16,
    pub acme: Option<AcmeConfig>,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
}

impl Default for SslConfig {
    fn default() -> Self {
        SslConfig {
            enabled: false,
            port: 5343,
            acme: None,
            cert_path: None,
            key_path: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_directory_urls() {
        assert!(AcmeProvider::LetsEncrypt.get_directory_url().contains("acme-v02"));
        assert!(AcmeProvider::LetsEncryptStaging.get_directory_url().contains("staging"));
        assert!(AcmeProvider::ZeroSSL.get_directory_url().contains("zerossl"));
        let custom = AcmeProvider::Custom { url: "https://example.com/dir".to_string() };
        assert_eq!(custom.get_directory_url(), "https://example.com/dir");
    }

    #[test]
    fn test_wildcard_domain_detection() {
        assert!(is_wildcard_domain("*.example.com"));
        assert!(!is_wildcard_domain("example.com"));
        assert!(!is_wildcard_domain("www.example.com"));
    }

    #[test]
    fn test_challenge_domain() {
        assert_eq!(challenge_domain("example.com"), "_acme-challenge.example.com");
        assert_eq!(challenge_domain("*.example.com"), "_acme-challenge.example.com");
        assert_eq!(challenge_domain("sub.example.com"), "_acme-challenge.sub.example.com");
    }

    #[test]
    fn test_default_acme_config() {
        let cfg = AcmeConfig::default();
        assert_eq!(cfg.renew_days_before_expiry, 30);
        assert!(cfg.use_dns_challenge);
        assert!(cfg.domains.is_empty());
    }

    #[test]
    fn test_default_ssl_config() {
        let cfg = SslConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.port, 5343);
        assert!(cfg.acme.is_none());
    }
}
