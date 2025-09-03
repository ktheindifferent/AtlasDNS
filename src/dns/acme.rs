use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use serde_derive::{Deserialize, Serialize};
extern crate sentry;

use crate::dns::context::ServerContext;
use crate::dns::protocol::{DnsRecord, TransientTtl};

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

pub struct AcmeCertificateManager {
    config: AcmeConfig,
    #[allow(dead_code)]
    context: Arc<ServerContext>,
}

impl AcmeCertificateManager {
    pub fn new(config: AcmeConfig, context: Arc<ServerContext>) -> Result<Self, Box<dyn std::error::Error>> {
        // Ensure certificate directory exists
        if let Some(parent) = config.cert_path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        Ok(AcmeCertificateManager {
            config,
            context,
        })
    }
    
    pub fn needs_renewal(&self) -> bool {
        if !self.config.cert_path.exists() {
            return true;
        }
        
        match self.load_certificate() {
            Ok(_cert) => {
                // Check certificate expiry
                // Note: In a real implementation, we'd parse the certificate's notAfter field
                // For now, we'll just return false if the certificate exists
                false
            }
            Err(_) => true,
        }
    }
    
    pub fn load_certificate(&self) -> Result<X509, Box<dyn std::error::Error>> {
        let cert_pem = fs::read_to_string(&self.config.cert_path).map_err(|e| {
            // Report certificate loading error to Sentry
            sentry::configure_scope(|scope| {
                scope.set_tag("component", "acme");
                scope.set_tag("operation", "load_certificate");
                scope.set_tag("provider", &format!("{:?}", self.config.provider));
                scope.set_extra("cert_path", self.config.cert_path.display().to_string().into());
                scope.set_extra("error_type", "file_read_error".into());
            });
            sentry::capture_message(
                &format!("Failed to load certificate from {}: {}", self.config.cert_path.display(), e),
                sentry::Level::Error
            );
            e
        })?;
        
        let cert = X509::from_pem(cert_pem.as_bytes()).map_err(|e| {
            // Report certificate parsing error to Sentry
            sentry::configure_scope(|scope| {
                scope.set_tag("component", "acme");
                scope.set_tag("operation", "parse_certificate");
                scope.set_tag("provider", &format!("{:?}", self.config.provider));
                scope.set_extra("cert_path", self.config.cert_path.display().to_string().into());
                scope.set_extra("error_type", "certificate_parse_error".into());
            });
            sentry::capture_message(
                &format!("Failed to parse certificate from {}: {}", self.config.cert_path.display(), e),
                sentry::Level::Error
            );
            e
        })?;
        
        Ok(cert)
    }
    
    pub fn load_private_key(&self) -> Result<PKey<Private>, Box<dyn std::error::Error>> {
        let key_pem = fs::read_to_string(&self.config.key_path).map_err(|e| {
            // Report private key loading error to Sentry
            sentry::configure_scope(|scope| {
                scope.set_tag("component", "acme");
                scope.set_tag("operation", "load_private_key");
                scope.set_tag("provider", &format!("{:?}", self.config.provider));
                scope.set_extra("key_path", self.config.key_path.display().to_string().into());
                scope.set_extra("error_type", "file_read_error".into());
            });
            sentry::capture_message(
                &format!("Failed to load private key from {}: {}", self.config.key_path.display(), e),
                sentry::Level::Error
            );
            e
        })?;
        
        let key = PKey::private_key_from_pem(key_pem.as_bytes()).map_err(|e| {
            // Report private key parsing error to Sentry
            sentry::configure_scope(|scope| {
                scope.set_tag("component", "acme");
                scope.set_tag("operation", "parse_private_key");
                scope.set_tag("provider", &format!("{:?}", self.config.provider));
                scope.set_extra("key_path", self.config.key_path.display().to_string().into());
                scope.set_extra("error_type", "private_key_parse_error".into());
            });
            sentry::capture_message(
                &format!("Failed to parse private key from {}: {}", self.config.key_path.display(), e),
                sentry::Level::Error
            );
            e
        })?;
        
        Ok(key)
    }
    
    pub fn obtain_certificate(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // This is a placeholder for the actual ACME certificate obtaining logic
        // In a production implementation, this would:
        // 1. Contact the ACME server
        // 2. Create account if needed
        // 3. Request authorization for domains
        // 4. Complete DNS challenges using the DNS server
        // 5. Request and download certificate
        
        log::info!(
            "ACME certificate management configured for domains: {:?} with provider: {:?}",
            self.config.domains,
            self.config.provider
        );
        
        log::warn!(
            "Full ACME protocol implementation pending. Please provide certificates manually at: {} and {}",
            self.config.cert_path.display(),
            self.config.key_path.display()
        );
        
        // For now, we'll create self-signed certificates as a placeholder
        self.create_self_signed_certificate()?;
        
        Ok(())
    }
    
    fn create_self_signed_certificate(&self) -> Result<(), Box<dyn std::error::Error>> {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509NameBuilder};
        
        // Generate private key
        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa)?;
        
        // Create certificate
        let mut x509_builder = X509Builder::new()?;
        x509_builder.set_version(2)?;
        
        // Set subject and issuer
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("CN", &self.config.domains[0])?;
        let name = name_builder.build();
        x509_builder.set_subject_name(&name)?;
        x509_builder.set_issuer_name(&name)?;
        
        // Set validity period
        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(365)?;
        x509_builder.set_not_before(&not_before)?;
        x509_builder.set_not_after(&not_after)?;
        
        // Set public key
        x509_builder.set_pubkey(&pkey)?;
        
        // Sign the certificate
        x509_builder.sign(&pkey, MessageDigest::sha256())?;
        let cert = x509_builder.build();
        
        // Save certificate and key
        fs::write(&self.config.cert_path, cert.to_pem()?)?;
        fs::write(&self.config.key_path, pkey.private_key_to_pem_pkcs8()?)?;
        
        log::info!(
            "Created self-signed certificate for {} (placeholder for ACME implementation)",
            self.config.domains[0]
        );
        
        Ok(())
    }
    
    #[allow(dead_code)]
    fn add_dns_record(&mut self, name: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Extract zone from record name
        let parts: Vec<&str> = name.split('.').collect();
        if parts.len() < 2 {
            return Err("Invalid record name".into());
        }
        
        let zone = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
        
        // Add TXT record to authority
        let record = DnsRecord::Txt {
            domain: name.to_string(),
            data: value.to_string(),
            ttl: TransientTtl(60), // Short TTL for ACME challenges
        };
        
        self.context.authority.upsert(&zone, record)?;
        
        log::info!("Added ACME DNS challenge record: {} = {}", name, value);
        
        Ok(())
    }
    
    #[allow(dead_code)]
    fn remove_dns_record(&mut self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Extract zone from record name
        let parts: Vec<&str> = name.split('.').collect();
        if parts.len() < 2 {
            return Err("Invalid record name".into());
        }
        
        let zone = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
        
        // Remove TXT record from authority
        self.context.authority.delete_records(&zone, name)?;
        
        log::info!("Removed ACME DNS challenge record: {}", name);
        
        Ok(())
    }
}

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