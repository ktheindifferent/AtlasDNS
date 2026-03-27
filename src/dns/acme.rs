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
// Base64url helper (base64 0.13 API)
// ---------------------------------------------------------------------------

fn b64url(data: impl AsRef<[u8]>) -> String {
    base64::encode_config(data.as_ref(), base64::URL_SAFE_NO_PAD)
}

#[cfg(test)]
fn b64url_decode(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(base64::decode_config(s, base64::URL_SAFE_NO_PAD)?)
}

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
// ACME v2 wire types (JSON)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct AcmeDirectory {
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newOrder")]
    new_order: String,
}

#[derive(Debug, Deserialize)]
struct AcmeOrder {
    status: String,
    authorizations: Vec<String>,
    finalize: String,
    certificate: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AcmeAuthorization {
    identifier: AcmeIdentifier,
    challenges: Vec<AcmeChallenge>,
}

#[derive(Debug, Deserialize)]
struct AcmeIdentifier {
    value: String,
}

#[derive(Debug, Deserialize)]
struct AcmeChallenge {
    #[serde(rename = "type")]
    challenge_type: String,
    url: String,
    token: String,
    status: Option<String>,
}

// ---------------------------------------------------------------------------
// ACME key helpers
// ---------------------------------------------------------------------------

/// Load or generate an RSA account key.
fn load_or_create_account_key(path: &PathBuf) -> Result<PKey<Private>, Box<dyn std::error::Error>> {
    if path.exists() {
        let pem = fs::read(path)?;
        Ok(PKey::private_key_from_pem(&pem)?)
    } else {
        use openssl::rsa::Rsa;
        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, pkey.private_key_to_pem_pkcs8()?)?;
        log::info!("Generated new ACME account key at {}", path.display());
        Ok(pkey)
    }
}

/// Compute JWK (public key) for an RSA PKey.
fn rsa_jwk(pkey: &PKey<Private>) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let rsa = pkey.rsa()?;
    let n = b64url(rsa.n().to_vec());
    let e = b64url(rsa.e().to_vec());
    Ok(serde_json::json!({
        "kty": "RSA",
        "n": n,
        "e": e,
    }))
}

/// Compute JWK thumbprint (SHA-256) per RFC 7638.
fn jwk_thumbprint(jwk: &serde_json::Value) -> Result<String, Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};
    let canonical = serde_json::json!({
        "e": jwk["e"],
        "kty": jwk["kty"],
        "n": jwk["n"],
    });
    let bytes = serde_json::to_vec(&canonical)?;
    let hash = Sha256::digest(bytes);
    Ok(b64url(hash))
}

/// Sign a JWS payload with RSA-SHA256.
fn jws_sign(
    pkey: &PKey<Private>,
    protected: &str,
    payload: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use openssl::hash::MessageDigest;
    use openssl::sign::Signer;

    let signing_input = format!("{}.{}", protected, payload);
    let mut signer = Signer::new(MessageDigest::sha256(), pkey)?;
    signer.update(signing_input.as_bytes())?;
    let sig = signer.sign_to_vec()?;
    let sig_b64 = b64url(&sig);

    Ok(serde_json::json!({
        "protected": protected,
        "payload": payload,
        "signature": sig_b64,
    }))
}

/// Build protected header using JWK (for account creation).
fn protected_jwk(jwk: &serde_json::Value, nonce: &str, url: &str) -> String {
    let header = serde_json::json!({
        "alg": "RS256",
        "jwk": jwk,
        "nonce": nonce,
        "url": url,
    });
    b64url(serde_json::to_vec(&header).unwrap())
}

/// Build protected header using KID (for authenticated requests).
fn protected_kid(kid: &str, nonce: &str, url: &str) -> String {
    let header = serde_json::json!({
        "alg": "RS256",
        "kid": kid,
        "nonce": nonce,
        "url": url,
    });
    b64url(serde_json::to_vec(&header).unwrap())
}

/// Encode payload as base64url JSON.
fn encode_payload(payload: &serde_json::Value) -> String {
    b64url(serde_json::to_vec(payload).unwrap())
}

// ---------------------------------------------------------------------------
// AcmeCertificateManager
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

    // ── Internal ACME v2 flow ───────────────────────────────────────────────

    fn run_acme_flow(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        // 1. Fetch directory
        let dir: AcmeDirectory = client
            .get(self.config.provider.get_directory_url())
            .send()?
            .json()?;

        // 2. Load / create account key
        let account_key = load_or_create_account_key(&self.config.account_key_path)?;
        let jwk = rsa_jwk(&account_key)?;

        // 3. Get initial nonce
        let nonce = self.fetch_nonce(&client, &dir.new_nonce)?;

        // 4. Create / find account
        let (kid, nonce) = self.create_or_find_account(
            &client, &account_key, &jwk, &dir.new_account, nonce,
        )?;

        // 5. Create order
        let (order_url, mut order, nonce) = self.create_order(
            &client, &account_key, &kid, &dir.new_order, nonce,
        )?;

        // 6. Fulfil DNS-01 challenges
        let mut nonce = nonce;
        let thumbprint = jwk_thumbprint(&jwk)?;
        let mut challenge_records: Vec<String> = Vec::new();

        for auth_url in &order.authorizations.clone() {
            let (txt_name, ch_url, n) = self.setup_dns_challenge(
                &client, &account_key, &kid, auth_url, &thumbprint, nonce,
            )?;
            nonce = n;
            challenge_records.push(txt_name.clone());

            log::info!("Waiting 30s for DNS propagation of {}", txt_name);
            std::thread::sleep(Duration::from_secs(30));

            nonce = self.trigger_challenge(&client, &account_key, &kid, &ch_url, nonce)?;
            self.poll_challenge_ready(&client, &account_key, &kid, auth_url, nonce.clone())?;
        }

        // 7. Generate domain key + CSR
        let (domain_key, csr_der) = self.generate_csr()?;

        // 8. Finalize order
        nonce = self.finalize_order(&client, &account_key, &kid, &order.finalize, &csr_der, nonce)?;

        // 9. Poll order until valid
        order = self.poll_order_ready(&client, &account_key, &kid, &order_url, nonce)?;

        // 10. Download certificate
        let cert_url = order.certificate.ok_or("Order has no certificate URL")?;
        self.download_certificate(&client, &account_key, &kid, &cert_url, &domain_key)?;

        // 11. Clean up DNS challenge records
        for name in &challenge_records {
            if let Err(e) = self.remove_dns_record(name) {
                log::warn!("Failed to remove ACME challenge record {}: {}", name, e);
            }
        }

        Ok(())
    }

    // ── ACME v2 helper methods ──────────────────────────────────────────────

    fn fetch_nonce(
        &self,
        client: &reqwest::blocking::Client,
        nonce_url: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let resp = client.head(nonce_url).send()?;
        let nonce = resp
            .headers()
            .get("replay-nonce")
            .ok_or("Missing Replay-Nonce header")?
            .to_str()?
            .to_string();
        Ok(nonce)
    }

    fn extract_nonce(resp: &reqwest::blocking::Response) -> Option<String> {
        resp.headers()
            .get("replay-nonce")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    fn create_or_find_account(
        &self,
        client: &reqwest::blocking::Client,
        account_key: &PKey<Private>,
        jwk: &serde_json::Value,
        new_account_url: &str,
        nonce: String,
    ) -> Result<(String, String), Box<dyn std::error::Error>> {
        let payload = serde_json::json!({
            "termsOfServiceAgreed": true,
            "contact": [format!("mailto:{}", self.config.email)],
        });
        let protected = protected_jwk(jwk, &nonce, new_account_url);
        let payload_b64 = encode_payload(&payload);
        let body = jws_sign(account_key, &protected, &payload_b64)?;

        let resp = client
            .post(new_account_url)
            .header("Content-Type", "application/jose+json")
            .json(&body)
            .send()?;

        let new_nonce = Self::extract_nonce(&resp).unwrap_or_default();
        let kid = resp
            .headers()
            .get("location")
            .ok_or("Missing Location header in account response")?
            .to_str()?
            .to_string();

        log::info!("ACME account: {}", kid);
        Ok((kid, new_nonce))
    }

    fn create_order(
        &self,
        client: &reqwest::blocking::Client,
        account_key: &PKey<Private>,
        kid: &str,
        new_order_url: &str,
        nonce: String,
    ) -> Result<(String, AcmeOrder, String), Box<dyn std::error::Error>> {
        let identifiers: Vec<serde_json::Value> = self
            .config
            .domains
            .iter()
            .map(|d| serde_json::json!({ "type": "dns", "value": d }))
            .collect();

        let payload = serde_json::json!({ "identifiers": identifiers });
        let protected = protected_kid(kid, &nonce, new_order_url);
        let payload_b64 = encode_payload(&payload);
        let body = jws_sign(account_key, &protected, &payload_b64)?;

        let resp = client
            .post(new_order_url)
            .header("Content-Type", "application/jose+json")
            .json(&body)
            .send()?;

        let new_nonce = Self::extract_nonce(&resp).unwrap_or_default();
        let order_url = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(new_order_url)
            .to_string();
        let order: AcmeOrder = resp.json()?;
        log::info!("ACME order created, status: {}", order.status);
        Ok((order_url, order, new_nonce))
    }

    fn setup_dns_challenge(
        &mut self,
        client: &reqwest::blocking::Client,
        account_key: &PKey<Private>,
        kid: &str,
        auth_url: &str,
        thumbprint: &str,
        nonce: String,
    ) -> Result<(String, String, String), Box<dyn std::error::Error>> {
        // POST-as-GET with empty payload ""
        let protected = protected_kid(kid, &nonce, auth_url);
        let body = jws_sign(account_key, &protected, "")?;
        let resp = client
            .post(auth_url)
            .header("Content-Type", "application/jose+json")
            .json(&body)
            .send()?;

        let new_nonce = Self::extract_nonce(&resp).unwrap_or_default();
        let auth: AcmeAuthorization = resp.json()?;
        let domain = auth.identifier.value.clone();

        let dns_challenge = auth
            .challenges
            .iter()
            .find(|c| c.challenge_type == "dns-01")
            .ok_or_else(|| format!("No dns-01 challenge for {}", domain))?;

        // key-auth = token || '.' || thumbprint
        let key_auth = format!("{}.{}", dns_challenge.token, thumbprint);
        // TXT value = base64url(sha256(key_auth))
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(key_auth.as_bytes());
        let txt_value = b64url(digest);
        // For wildcard domains (*.example.com) the challenge is
        // _acme-challenge.example.com (without the *. prefix).
        let txt_name = challenge_domain(&domain);

        self.add_dns_record(&txt_name, &txt_value)?;
        log::info!("Installed DNS-01 challenge: {} = \"{}\"", txt_name, txt_value);

        Ok((txt_name, dns_challenge.url.clone(), new_nonce))
    }

    fn trigger_challenge(
        &self,
        client: &reqwest::blocking::Client,
        account_key: &PKey<Private>,
        kid: &str,
        challenge_url: &str,
        nonce: String,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let payload = serde_json::json!({});
        let protected = protected_kid(kid, &nonce, challenge_url);
        let payload_b64 = encode_payload(&payload);
        let body = jws_sign(account_key, &protected, &payload_b64)?;

        let resp = client
            .post(challenge_url)
            .header("Content-Type", "application/jose+json")
            .json(&body)
            .send()?;

        let new_nonce = Self::extract_nonce(&resp).unwrap_or_default();
        log::info!("Triggered DNS-01 challenge validation at {}", challenge_url);
        Ok(new_nonce)
    }

    fn poll_challenge_ready(
        &self,
        client: &reqwest::blocking::Client,
        account_key: &PKey<Private>,
        kid: &str,
        auth_url: &str,
        initial_nonce: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut nonce = initial_nonce;
        for attempt in 0..20 {
            std::thread::sleep(Duration::from_secs(5));
            let protected = protected_kid(kid, &nonce, auth_url);
            let body = jws_sign(account_key, &protected, "")?;
            let resp = client
                .post(auth_url)
                .header("Content-Type", "application/jose+json")
                .json(&body)
                .send()?;

            nonce = Self::extract_nonce(&resp).unwrap_or_default();
            let auth: AcmeAuthorization = resp.json()?;
            let dns_ch = auth.challenges.iter().find(|c| c.challenge_type == "dns-01");
            let status = dns_ch.and_then(|c| c.status.as_deref()).unwrap_or("pending");

            log::debug!("Challenge poll #{} status: {}", attempt, status);
            match status {
                "valid" => return Ok(()),
                "invalid" => return Err("Challenge validation failed (invalid)".into()),
                _ => continue,
            }
        }
        Err("Challenge did not become valid within timeout".into())
    }

    fn generate_csr(&self) -> Result<(PKey<Private>, Vec<u8>), Box<dyn std::error::Error>> {
        use openssl::hash::MessageDigest;
        use openssl::rsa::Rsa;
        use openssl::x509::extension::SubjectAlternativeName;
        use openssl::x509::{X509NameBuilder, X509ReqBuilder};

        let rsa = Rsa::generate(2048)?;
        let domain_key = PKey::from_rsa(rsa)?;

        let mut req_builder = X509ReqBuilder::new()?;
        req_builder.set_pubkey(&domain_key)?;

        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("CN", &self.config.domains[0])?;
        let name = name_builder.build();
        req_builder.set_subject_name(&name)?;

        // Add Subject Alternative Names for all domains (including wildcards)
        if !self.config.domains.is_empty() {
            let mut san = SubjectAlternativeName::new();
            for domain in &self.config.domains {
                san.dns(domain);
            }
            let san_ext = san.build(&req_builder.x509v3_context(None))?;

            let mut extensions = openssl::stack::Stack::new()?;
            extensions.push(san_ext)?;
            req_builder.add_extensions(&extensions)?;
        }

        req_builder.sign(&domain_key, MessageDigest::sha256())?;

        let csr = req_builder.build();
        let csr_der = csr.to_der()?;

        Ok((domain_key, csr_der))
    }

    fn finalize_order(
        &self,
        client: &reqwest::blocking::Client,
        account_key: &PKey<Private>,
        kid: &str,
        finalize_url: &str,
        csr_der: &[u8],
        nonce: String,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let csr_b64 = b64url(csr_der);
        let payload = serde_json::json!({ "csr": csr_b64 });
        let protected = protected_kid(kid, &nonce, finalize_url);
        let payload_b64 = encode_payload(&payload);
        let body = jws_sign(account_key, &protected, &payload_b64)?;

        let resp = client
            .post(finalize_url)
            .header("Content-Type", "application/jose+json")
            .json(&body)
            .send()?;

        let new_nonce = Self::extract_nonce(&resp).unwrap_or_default();
        log::info!("Sent CSR to finalize order");
        Ok(new_nonce)
    }

    fn poll_order_ready(
        &self,
        client: &reqwest::blocking::Client,
        account_key: &PKey<Private>,
        kid: &str,
        order_url: &str,
        initial_nonce: String,
    ) -> Result<AcmeOrder, Box<dyn std::error::Error>> {
        let mut nonce = initial_nonce;
        for attempt in 0..20 {
            std::thread::sleep(Duration::from_secs(5));
            let protected = protected_kid(kid, &nonce, order_url);
            let body = jws_sign(account_key, &protected, "")?;
            let resp = client
                .post(order_url)
                .header("Content-Type", "application/jose+json")
                .json(&body)
                .send()?;

            nonce = Self::extract_nonce(&resp).unwrap_or_default();
            let order: AcmeOrder = resp.json()?;
            log::debug!("Order poll #{} status: {}", attempt, order.status);
            match order.status.as_str() {
                "valid" => return Ok(order),
                "invalid" => return Err("Order became invalid".into()),
                _ => continue,
            }
        }
        Err("Order did not become valid within timeout".into())
    }

    fn download_certificate(
        &self,
        client: &reqwest::blocking::Client,
        account_key: &PKey<Private>,
        kid: &str,
        cert_url: &str,
        domain_key: &PKey<Private>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let nonce = self.fetch_nonce_from_any(client)?;
        let protected = protected_kid(kid, &nonce, cert_url);
        let body = jws_sign(account_key, &protected, "")?;

        let resp = client
            .post(cert_url)
            .header("Content-Type", "application/jose+json")
            .header("Accept", "application/pem-certificate-chain")
            .json(&body)
            .send()?;

        let cert_pem = resp.text()?;

        if let Some(parent) = self.config.cert_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.config.cert_path, cert_pem.as_bytes())?;
        fs::write(&self.config.key_path, domain_key.private_key_to_pem_pkcs8()?)?;

        log::info!("Certificate saved to {}", self.config.cert_path.display());
        log::info!("Private key saved to {}", self.config.key_path.display());
        Ok(())
    }

    fn fetch_nonce_from_any(
        &self,
        client: &reqwest::blocking::Client,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let dir_url = self.config.provider.get_directory_url();
        let r = client.head(dir_url).send()?;
        Self::extract_nonce(&r).ok_or_else(|| "Could not obtain nonce".into())
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

    fn add_dns_record(&mut self, name: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
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
        self.context.authority.upsert(&zone, record)?;
        log::info!("Added ACME DNS challenge record: {} = {}", name, value);
        Ok(())
    }

    fn remove_dns_record(&mut self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let parts: Vec<&str> = name.split('.').collect();
        if parts.len() < 2 {
            return Err("Invalid record name".into());
        }
        let zone = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
        self.context.authority.delete_records(&zone, name)?;
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
    fn test_default_acme_config() {
        let cfg = AcmeConfig::default();
        assert_eq!(cfg.renew_days_before_expiry, 30);
        assert!(cfg.use_dns_challenge);
        assert!(cfg.domains.is_empty());
    }

    #[test]
    fn test_encode_payload_roundtrip() {
        let v = serde_json::json!({ "hello": "world" });
        let encoded = encode_payload(&v);
        let decoded = b64url_decode(&encoded).unwrap();
        let back: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(back["hello"], "world");
    }

    #[test]
    fn test_jwk_thumbprint_stable() {
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let jwk = rsa_jwk(&pkey).unwrap();
        let t1 = jwk_thumbprint(&jwk).unwrap();
        let t2 = jwk_thumbprint(&jwk).unwrap();
        assert_eq!(t1, t2);
        assert!(!t1.is_empty());
    }

    #[test]
    fn test_b64url_roundtrip() {
        let data = b"hello world test 123";
        let encoded = b64url(data);
        let decoded = b64url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_jws_sign_produces_valid_structure() {
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let jwk = rsa_jwk(&pkey).unwrap();
        let protected = protected_jwk(&jwk, "test-nonce", "https://example.com/test");
        let payload = encode_payload(&serde_json::json!({"test": "value"}));
        let jws = jws_sign(&pkey, &protected, &payload).unwrap();
        assert!(jws.get("protected").is_some());
        assert!(jws.get("payload").is_some());
        assert!(jws.get("signature").is_some());
    }
}
