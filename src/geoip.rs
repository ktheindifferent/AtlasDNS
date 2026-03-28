//! GeoIP enrichment using MaxMind `.mmdb` databases.
//!
//! Loads a MaxMind GeoLite2 or GeoIP2 database and provides country/city
//! lookups for IP addresses, used to enrich DNS query logs.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use maxminddb::{self, geoip2, Reader};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// GeoIP configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpConfig {
    pub enabled: bool,
    pub database_path: PathBuf,
}

impl Default for GeoIpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            database_path: PathBuf::from("/opt/atlas/geoip/GeoLite2-City.mmdb"),
        }
    }
}

// ---------------------------------------------------------------------------
// Lookup result
// ---------------------------------------------------------------------------

/// Enriched geographic information for an IP address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoInfo {
    pub ip: String,
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub autonomous_system: Option<String>,
}

impl GeoInfo {
    fn empty(ip: &str) -> Self {
        Self {
            ip: ip.to_string(),
            country_code: None,
            country_name: None,
            city: None,
            latitude: None,
            longitude: None,
            autonomous_system: None,
        }
    }
}

// ---------------------------------------------------------------------------
// GeoIP database handle
// ---------------------------------------------------------------------------

/// Thread-safe GeoIP database reader.
pub struct GeoIpDatabase {
    reader: Reader<Vec<u8>>,
    config: GeoIpConfig,
}

impl GeoIpDatabase {
    /// Open a MaxMind `.mmdb` file from the configured path.
    pub fn open(config: GeoIpConfig) -> Result<Self, String> {
        let path = &config.database_path;
        if !path.exists() {
            return Err(format!("GeoIP database not found: {}", path.display()));
        }
        let reader = Reader::open_readfile(path)
            .map_err(|e| format!("Failed to open GeoIP database: {}", e))?;
        log::info!("[GeoIP] Loaded database from {}", path.display());
        Ok(Self { reader, config })
    }

    /// Open from a specific path (convenience).
    pub fn open_path(path: impl AsRef<Path>) -> Result<Self, String> {
        let config = GeoIpConfig {
            enabled: true,
            database_path: path.as_ref().to_path_buf(),
        };
        Self::open(config)
    }

    /// Look up geographic information for an IP address.
    pub fn lookup(&self, ip: IpAddr) -> GeoInfo {
        let ip_str = ip.to_string();

        let city_result: Result<geoip2::City, _> = self.reader.lookup(ip);
        match city_result {
            Ok(city) => {
                let country_code = city
                    .country
                    .as_ref()
                    .and_then(|c| c.iso_code.map(|s| s.to_string()));

                let country_name = city
                    .country
                    .as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|n| n.get("en").map(|s| s.to_string()));

                let city_name = city
                    .city
                    .as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|n| n.get("en").map(|s| s.to_string()));

                let (lat, lon) = city
                    .location
                    .as_ref()
                    .map(|loc| (loc.latitude, loc.longitude))
                    .unwrap_or((None, None));

                GeoInfo {
                    ip: ip_str,
                    country_code,
                    country_name,
                    city: city_name,
                    latitude: lat,
                    longitude: lon,
                    autonomous_system: None,
                }
            }
            Err(_) => GeoInfo::empty(&ip_str),
        }
    }

    /// Look up just the country code for an IP (fast path).
    pub fn country_code(&self, ip: IpAddr) -> Option<String> {
        let result: Result<geoip2::Country, _> = self.reader.lookup(ip);
        result
            .ok()
            .and_then(|c| c.country)
            .and_then(|c| c.iso_code.map(|s| s.to_string()))
    }

    /// Check if the database is loaded and functional.
    pub fn is_loaded(&self) -> bool {
        true
    }

    /// Return the database path.
    pub fn database_path(&self) -> &Path {
        &self.config.database_path
    }
}

/// Shared GeoIP handle for use across threads.
pub type SharedGeoIp = Arc<GeoIpDatabase>;

/// Create a shared GeoIP database, or None if not configured / file missing.
pub fn try_load(config: &GeoIpConfig) -> Option<SharedGeoIp> {
    if !config.enabled {
        return None;
    }
    match GeoIpDatabase::open(config.clone()) {
        Ok(db) => Some(Arc::new(db)),
        Err(e) => {
            log::warn!("[GeoIP] {}", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_geoip_config_default() {
        let config = GeoIpConfig::default();
        assert!(!config.enabled);
        assert!(config.database_path.to_string_lossy().contains("GeoLite2"));
    }

    #[test]
    fn test_geo_info_empty() {
        let info = GeoInfo::empty("1.2.3.4");
        assert_eq!(info.ip, "1.2.3.4");
        assert!(info.country_code.is_none());
        assert!(info.city.is_none());
    }

    #[test]
    fn test_open_missing_db() {
        let config = GeoIpConfig {
            enabled: true,
            database_path: PathBuf::from("/nonexistent/path.mmdb"),
        };
        assert!(GeoIpDatabase::open(config).is_err());
    }

    #[test]
    fn test_try_load_disabled() {
        let config = GeoIpConfig::default();
        assert!(try_load(&config).is_none());
    }
}
