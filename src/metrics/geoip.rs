//! Geographic IP analysis for DNS queries

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use maxminddb::{geoip2, Reader};

/// Geographic distribution data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeographicDistribution {
    pub country_code: String,
    pub country_name: String,
    pub region: Option<String>,
    pub city: Option<String>,
    pub query_count: u64,
    pub unique_clients: u32,
    pub percentage: f64,
}

/// Location data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub country_code: String,
    pub country_name: String,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
}

/// GeoIP analyzer
pub struct GeoIpAnalyzer {
    reader: Option<Arc<Reader<Vec<u8>>>>,
    cache: Arc<RwLock<HashMap<String, Location>>>,
}

impl GeoIpAnalyzer {
    /// Create a new GeoIP analyzer
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Try to load MaxMind GeoLite2 database if available
        let reader = Self::load_database()?;
        
        Ok(Self {
            reader,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Load GeoIP database
    fn load_database() -> Result<Option<Arc<Reader<Vec<u8>>>>, Box<dyn std::error::Error>> {
        // Common paths for GeoLite2 database
        let possible_paths = vec![
            "/usr/share/GeoIP/GeoLite2-City.mmdb",
            "/usr/local/share/GeoIP/GeoLite2-City.mmdb",
            "/var/lib/GeoIP/GeoLite2-City.mmdb",
            "./GeoLite2-City.mmdb",
        ];

        for path in possible_paths {
            if std::path::Path::new(path).exists() {
                match maxminddb::Reader::open_readfile(path) {
                    Ok(reader) => return Ok(Some(Arc::new(reader))),
                    Err(e) => {
                        log::warn!("Failed to load GeoIP database from {}: {}", path, e);
                    }
                }
            }
        }

        log::info!("GeoIP database not found. Geographic analytics will use mock data.");
        Ok(None)
    }

    /// Lookup location for an IP address
    pub async fn lookup(&self, ip_str: &str) -> Option<Location> {
        // Check cache first
        if let Some(location) = self.cache.read().await.get(ip_str) {
            return Some(location.clone());
        }

        // Parse IP address
        let ip = match ip_str.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => return None,
        };

        // If we have a GeoIP database, use it
        if let Some(reader) = &self.reader {
            if let Ok(city) = reader.lookup::<geoip2::City>(ip) {
                let location = Location {
                    country_code: city.country
                        .and_then(|c| c.iso_code)
                        .unwrap_or("XX")
                        .to_string(),
                    country_name: city.country
                        .and_then(|c| c.names)
                        .and_then(|n| n.get("en"))
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "Unknown".to_string()),
                    region: city.subdivisions
                        .and_then(|s| s.get(0))
                        .and_then(|s| s.names)
                        .and_then(|n| n.get("en"))
                        .map(|s| s.to_string()),
                    city: city.city
                        .and_then(|c| c.names)
                        .and_then(|n| n.get("en"))
                        .map(|s| s.to_string()),
                    latitude: city.location.as_ref().and_then(|l| l.latitude),
                    longitude: city.location.as_ref().and_then(|l| l.longitude),
                    timezone: city.location.and_then(|l| l.time_zone).map(|s| s.to_string()),
                };

                // Cache the result
                self.cache.write().await.insert(ip_str.to_string(), location.clone());
                return Some(location);
            }
        }

        // Fallback to mock data for private IPs or when database is not available
        self.get_mock_location(ip_str).await
    }

    /// Get mock location data for testing
    async fn get_mock_location(&self, ip_str: &str) -> Option<Location> {
        let location = if ip_str.starts_with("192.168.") || ip_str.starts_with("10.") {
            // Private IP - assume local
            Location {
                country_code: "US".to_string(),
                country_name: "United States".to_string(),
                region: Some("California".to_string()),
                city: Some("San Francisco".to_string()),
                latitude: Some(37.7749),
                longitude: Some(-122.4194),
                timezone: Some("America/Los_Angeles".to_string()),
            }
        } else if ip_str.starts_with("8.8.") {
            // Google DNS
            Location {
                country_code: "US".to_string(),
                country_name: "United States".to_string(),
                region: Some("California".to_string()),
                city: Some("Mountain View".to_string()),
                latitude: Some(37.4223),
                longitude: Some(-122.0840),
                timezone: Some("America/Los_Angeles".to_string()),
            }
        } else if ip_str.starts_with("1.1.") {
            // Cloudflare DNS
            Location {
                country_code: "AU".to_string(),
                country_name: "Australia".to_string(),
                region: Some("New South Wales".to_string()),
                city: Some("Sydney".to_string()),
                latitude: Some(-33.8688),
                longitude: Some(151.2093),
                timezone: Some("Australia/Sydney".to_string()),
            }
        } else {
            // Random mock locations for demo
            let mock_locations = vec![
                Location {
                    country_code: "GB".to_string(),
                    country_name: "United Kingdom".to_string(),
                    region: Some("England".to_string()),
                    city: Some("London".to_string()),
                    latitude: Some(51.5074),
                    longitude: Some(-0.1278),
                    timezone: Some("Europe/London".to_string()),
                },
                Location {
                    country_code: "DE".to_string(),
                    country_name: "Germany".to_string(),
                    region: Some("Berlin".to_string()),
                    city: Some("Berlin".to_string()),
                    latitude: Some(52.5200),
                    longitude: Some(13.4050),
                    timezone: Some("Europe/Berlin".to_string()),
                },
                Location {
                    country_code: "JP".to_string(),
                    country_name: "Japan".to_string(),
                    region: Some("Tokyo".to_string()),
                    city: Some("Tokyo".to_string()),
                    latitude: Some(35.6762),
                    longitude: Some(139.6503),
                    timezone: Some("Asia/Tokyo".to_string()),
                },
                Location {
                    country_code: "BR".to_string(),
                    country_name: "Brazil".to_string(),
                    region: Some("São Paulo".to_string()),
                    city: Some("São Paulo".to_string()),
                    latitude: Some(-23.5505),
                    longitude: Some(-46.6333),
                    timezone: Some("America/Sao_Paulo".to_string()),
                },
            ];

            // Use IP hash to consistently return same location for same IP
            let hash = ip_str.bytes().fold(0u32, |acc, b| acc.wrapping_add(b as u32));
            let index = (hash as usize) % mock_locations.len();
            mock_locations[index].clone()
        };

        self.cache.write().await.insert(ip_str.to_string(), location.clone());
        Some(location)
    }

    /// Analyze geographic distribution of IPs
    pub async fn analyze_distribution(&self, ips: Vec<String>) -> Vec<GeographicDistribution> {
        let mut country_stats: HashMap<String, (String, u64, std::collections::HashSet<String>)> = HashMap::new();
        
        for ip in &ips {
            if let Some(location) = self.lookup(ip).await {
                let entry = country_stats
                    .entry(location.country_code.clone())
                    .or_insert((location.country_name, 0, std::collections::HashSet::new()));
                entry.1 += 1;
                entry.2.insert(ip.clone());
            }
        }

        let total = ips.len() as f64;
        let mut distribution: Vec<GeographicDistribution> = country_stats
            .into_iter()
            .map(|(country_code, (country_name, query_count, unique_ips))| {
                GeographicDistribution {
                    country_code,
                    country_name,
                    region: None,
                    city: None,
                    query_count,
                    unique_clients: unique_ips.len() as u32,
                    percentage: if total > 0.0 {
                        (query_count as f64 / total) * 100.0
                    } else {
                        0.0
                    },
                }
            })
            .collect();

        distribution.sort_by(|a, b| b.query_count.cmp(&a.query_count));
        distribution
    }

    /// Get heatmap data for visualization
    pub async fn get_heatmap_data(&self, ips: Vec<String>) -> Vec<HeatmapPoint> {
        let mut points = Vec::new();
        let mut location_counts: HashMap<(String, String), u64> = HashMap::new();

        for ip in ips {
            if let Some(location) = self.lookup(&ip).await {
                let key = (
                    location.latitude.unwrap_or(0.0).to_string(),
                    location.longitude.unwrap_or(0.0).to_string(),
                );
                *location_counts.entry(key).or_insert(0) += 1;
            }
        }

        for ((lat_str, lon_str), count) in location_counts {
            if let (Ok(lat), Ok(lon)) = (lat_str.parse::<f64>(), lon_str.parse::<f64>()) {
                points.push(HeatmapPoint {
                    latitude: lat,
                    longitude: lon,
                    intensity: count as f64,
                });
            }
        }

        points
    }

    /// Clear the location cache
    pub async fn clear_cache(&self) {
        self.cache.write().await.clear();
    }
}

/// Heatmap data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatmapPoint {
    pub latitude: f64,
    pub longitude: f64,
    pub intensity: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_geoip_analyzer() {
        let analyzer = GeoIpAnalyzer::new().unwrap();
        
        // Test with a known IP
        let location = analyzer.lookup("8.8.8.8").await;
        assert!(location.is_some());
        
        let loc = location.unwrap();
        assert!(!loc.country_code.is_empty());
        assert!(!loc.country_name.is_empty());
    }

    #[tokio::test]
    async fn test_geographic_distribution() {
        let analyzer = GeoIpAnalyzer::new().unwrap();
        
        let ips = vec![
            "192.168.1.1".to_string(),
            "8.8.8.8".to_string(),
            "1.1.1.1".to_string(),
            "192.168.1.2".to_string(),
        ];
        
        let distribution = analyzer.analyze_distribution(ips).await;
        assert!(!distribution.is_empty());
        
        // Check that percentages add up to 100
        let total_percentage: f64 = distribution.iter().map(|d| d.percentage).sum();
        assert!((total_percentage - 100.0).abs() < 1.0);
    }

    #[tokio::test]
    async fn test_cache() {
        let analyzer = GeoIpAnalyzer::new().unwrap();
        
        // First lookup should cache
        let location1 = analyzer.lookup("192.168.1.1").await;
        assert!(location1.is_some());
        
        // Second lookup should use cache
        let location2 = analyzer.lookup("192.168.1.1").await;
        assert_eq!(location1.unwrap().country_code, location2.unwrap().country_code);
        
        // Clear cache
        analyzer.clear_cache().await;
        assert_eq!(analyzer.cache.read().await.len(), 0);
    }
}