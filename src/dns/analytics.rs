//! DNS Analytics Implementation
//!
//! Provides comprehensive analytics for DNS operations including response codes,
//! query patterns, geographic distribution, and performance metrics.
//!
//! # Features
//!
//! * **Response Code Analytics** - Track NOERROR, NXDOMAIN, SERVFAIL rates
//! * **Query Geography Mapping** - Visualize global query distribution
//! * **Top Queries Dashboard** - Real-time popular query tracking
//! * **Query Type Distribution** - A, AAAA, MX, etc. statistics
//! * **Time Series Data** - Historical trends and patterns
//! * **Anomaly Detection** - Identify unusual query patterns
//! * **Client Analytics** - Per-client query behavior

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};

use crate::dns::protocol::{DnsPacket, QueryType, ResultCode};

/// Analytics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsConfig {
    /// Enable analytics collection
    pub enabled: bool,
    /// Data retention period (hours)
    pub retention_hours: u32,
    /// Time bucket size for aggregation (seconds)
    pub bucket_size_secs: u64,
    /// Maximum top queries to track
    pub max_top_queries: usize,
    /// Maximum unique clients to track
    pub max_clients: usize,
    /// Enable geographic analytics
    pub geo_analytics: bool,
    /// Enable anomaly detection
    pub anomaly_detection: bool,
}

impl Default for AnalyticsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_hours: 24,
            bucket_size_secs: 60,  // 1 minute buckets
            max_top_queries: 100,
            max_clients: 10000,
            geo_analytics: true,
            anomaly_detection: true,
        }
    }
}

/// Response code analytics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ResponseCodeAnalytics {
    /// Total queries
    pub total_queries: u64,
    /// NOERROR responses
    pub noerror: u64,
    /// NXDOMAIN responses
    pub nxdomain: u64,
    /// SERVFAIL responses
    pub servfail: u64,
    /// REFUSED responses
    pub refused: u64,
    /// FORMERR responses
    pub formerr: u64,
    /// Other response codes
    pub other: HashMap<u8, u64>,
    /// Response code percentages
    pub percentages: ResponseCodePercentages,
}

/// Response code percentages
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ResponseCodePercentages {
    pub noerror_pct: f64,
    pub nxdomain_pct: f64,
    pub servfail_pct: f64,
    pub refused_pct: f64,
    pub formerr_pct: f64,
}

/// Query type analytics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct QueryTypeAnalytics {
    pub a_queries: u64,
    pub aaaa_queries: u64,
    pub mx_queries: u64,
    pub txt_queries: u64,
    pub ns_queries: u64,
    pub cname_queries: u64,
    pub soa_queries: u64,
    pub other_queries: u64,
}

/// Geographic analytics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GeographicAnalytics {
    /// Queries by country
    pub by_country: HashMap<String, u64>,
    /// Queries by continent
    pub by_continent: HashMap<String, u64>,
    /// Queries by city
    pub by_city: HashMap<String, u64>,
    /// Top geographic sources
    pub top_locations: Vec<LocationStat>,
}

/// Location statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationStat {
    pub location: String,
    pub country: String,
    pub queries: u64,
    pub percentage: f64,
}

/// Top queries dashboard
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TopQueriesAnalytics {
    /// Top queried domains
    pub top_domains: Vec<DomainStat>,
    /// Top query types
    pub top_types: Vec<QueryTypeStat>,
    /// Top clients
    pub top_clients: Vec<ClientStat>,
    /// Recently queried domains
    pub recent_domains: VecDeque<RecentQuery>,
}

/// Domain statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainStat {
    pub domain: String,
    pub count: u64,
    pub percentage: f64,
    pub last_queried: u64,
}

/// Query type statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryTypeStat {
    pub qtype: String,
    pub count: u64,
    pub percentage: f64,
}

/// Client statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientStat {
    pub client_ip: String,
    pub queries: u64,
    pub unique_domains: usize,
    pub error_rate: f64,
}

/// Recent query entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentQuery {
    pub domain: String,
    pub qtype: String,
    pub client: String,
    pub timestamp: u64,
    pub response_code: String,
}

/// Time series data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    pub timestamp: u64,
    pub value: f64,
}

/// Time series analytics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TimeSeriesAnalytics {
    /// Queries per minute
    pub queries_per_minute: Vec<TimeSeriesPoint>,
    /// Error rate over time
    pub error_rate: Vec<TimeSeriesPoint>,
    /// Average response time
    pub avg_response_time: Vec<TimeSeriesPoint>,
    /// Cache hit rate
    pub cache_hit_rate: Vec<TimeSeriesPoint>,
}

/// Analytics engine
pub struct AnalyticsEngine {
    /// Configuration
    config: Arc<RwLock<AnalyticsConfig>>,
    /// Response code analytics
    response_codes: Arc<RwLock<ResponseCodeAnalytics>>,
    /// Query type analytics
    query_types: Arc<RwLock<QueryTypeAnalytics>>,
    /// Geographic analytics
    geographic: Arc<RwLock<GeographicAnalytics>>,
    /// Top queries
    top_queries: Arc<RwLock<TopQueriesAnalytics>>,
    /// Time series data
    time_series: Arc<RwLock<TimeSeriesAnalytics>>,
    /// Domain counter
    domain_counter: Arc<RwLock<HashMap<String, u64>>>,
    /// Client data
    client_data: Arc<RwLock<HashMap<IpAddr, ClientData>>>,
    /// Current time bucket
    current_bucket: Arc<RwLock<TimeBucket>>,
}

/// Client data
#[derive(Debug, Clone)]
struct ClientData {
    total_queries: u64,
    error_queries: u64,
    unique_domains: HashSet<String>,
    last_seen: Instant,
}

use std::collections::HashSet;

/// Time bucket for aggregation
#[derive(Debug, Clone)]
struct TimeBucket {
    start_time: u64,
    queries: u64,
    errors: u64,
    total_response_time_us: u64,
    cache_hits: u64,
}

impl AnalyticsEngine {
    /// Create new analytics engine
    pub fn new(config: AnalyticsConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            response_codes: Arc::new(RwLock::new(ResponseCodeAnalytics::default())),
            query_types: Arc::new(RwLock::new(QueryTypeAnalytics::default())),
            geographic: Arc::new(RwLock::new(GeographicAnalytics::default())),
            top_queries: Arc::new(RwLock::new(TopQueriesAnalytics::default())),
            time_series: Arc::new(RwLock::new(TimeSeriesAnalytics::default())),
            domain_counter: Arc::new(RwLock::new(HashMap::new())),
            client_data: Arc::new(RwLock::new(HashMap::new())),
            current_bucket: Arc::new(RwLock::new(TimeBucket {
                start_time: Self::current_timestamp(),
                queries: 0,
                errors: 0,
                total_response_time_us: 0,
                cache_hits: 0,
            })),
        }
    }

    /// Record DNS query
    pub fn record_query(
        &self,
        packet: &DnsPacket,
        client_ip: IpAddr,
        response_code: ResultCode,
        response_time: Duration,
        cache_hit: bool,
    ) {
        let config = self.config.read();
        if !config.enabled {
            return;
        }

        // Update response code analytics
        self.update_response_codes(response_code);

        // Update query type analytics
        if let Some(question) = packet.questions.first() {
            self.update_query_types(question.qtype);
            self.update_domain_stats(&question.name);
            self.record_recent_query(&question.name, question.qtype, client_ip, response_code);
        }

        // Update client analytics
        self.update_client_stats(client_ip, response_code);

        // Update time series
        self.update_time_series(response_time, cache_hit, response_code);

        // Update geographic analytics if enabled
        if config.geo_analytics {
            self.update_geographic_stats(client_ip);
        }
    }

    /// Update response code statistics
    fn update_response_codes(&self, code: ResultCode) {
        let mut stats = self.response_codes.write();
        stats.total_queries += 1;

        match code {
            ResultCode::NOERROR => stats.noerror += 1,
            ResultCode::NXDOMAIN => stats.nxdomain += 1,
            ResultCode::SERVFAIL => stats.servfail += 1,
            ResultCode::REFUSED => stats.refused += 1,
            ResultCode::FORMERR => stats.formerr += 1,
            _ => {
                *stats.other.entry(code as u8).or_insert(0) += 1;
            }
        }

        // Update percentages
        let total = stats.total_queries as f64;
        if total > 0.0 {
            stats.percentages.noerror_pct = (stats.noerror as f64 / total) * 100.0;
            stats.percentages.nxdomain_pct = (stats.nxdomain as f64 / total) * 100.0;
            stats.percentages.servfail_pct = (stats.servfail as f64 / total) * 100.0;
            stats.percentages.refused_pct = (stats.refused as f64 / total) * 100.0;
            stats.percentages.formerr_pct = (stats.formerr as f64 / total) * 100.0;
        }
    }

    /// Update query type statistics
    fn update_query_types(&self, qtype: QueryType) {
        let mut stats = self.query_types.write();
        
        match qtype {
            QueryType::A => stats.a_queries += 1,
            QueryType::Aaaa => stats.aaaa_queries += 1,
            QueryType::Mx => stats.mx_queries += 1,
            QueryType::Txt => stats.txt_queries += 1,
            QueryType::Ns => stats.ns_queries += 1,
            QueryType::Cname => stats.cname_queries += 1,
            QueryType::Soa => stats.soa_queries += 1,
            _ => {
                stats.other_queries += 1;
            }
        }
    }

    /// Update domain statistics
    fn update_domain_stats(&self, domain: &str) {
        let mut counter = self.domain_counter.write();
        *counter.entry(domain.to_string()).or_insert(0) += 1;

        // Update top domains
        if counter.len() % 100 == 0 {
            self.update_top_domains();
        }
    }

    /// Update top domains list
    fn update_top_domains(&self) {
        let counter = self.domain_counter.read();
        let total: u64 = counter.values().sum();
        
        let mut domains: Vec<_> = counter.iter()
            .map(|(domain, count)| DomainStat {
                domain: domain.clone(),
                count: *count,
                percentage: (*count as f64 / total as f64) * 100.0,
                last_queried: Self::current_timestamp(),
            })
            .collect();

        domains.sort_by(|a, b| b.count.cmp(&a.count));
        domains.truncate(self.config.read().max_top_queries);

        self.top_queries.write().top_domains = domains;
    }

    /// Record recent query
    fn record_recent_query(
        &self,
        domain: &str,
        qtype: QueryType,
        client: IpAddr,
        response_code: ResultCode,
    ) {
        let mut top_queries = self.top_queries.write();
        
        top_queries.recent_domains.push_back(RecentQuery {
            domain: domain.to_string(),
            qtype: format!("{:?}", qtype),
            client: client.to_string(),
            timestamp: Self::current_timestamp(),
            response_code: format!("{:?}", response_code),
        });

        // Keep only last 100 queries
        while top_queries.recent_domains.len() > 100 {
            top_queries.recent_domains.pop_front();
        }
    }

    /// Update client statistics
    fn update_client_stats(&self, client_ip: IpAddr, response_code: ResultCode) {
        let mut clients = self.client_data.write();
        
        let client = clients.entry(client_ip).or_insert_with(|| ClientData {
            total_queries: 0,
            error_queries: 0,
            unique_domains: HashSet::new(),
            last_seen: Instant::now(),
        });

        client.total_queries += 1;
        if response_code != ResultCode::NOERROR {
            client.error_queries += 1;
        }
        client.last_seen = Instant::now();

        // Clean up old clients if needed
        if clients.len() > self.config.read().max_clients {
            let oldest = clients.iter()
                .min_by_key(|(_, data)| data.last_seen)
                .map(|(ip, _)| *ip);
            
            if let Some(ip) = oldest {
                clients.remove(&ip);
            }
        }
    }

    /// Update time series data
    fn update_time_series(
        &self,
        response_time: Duration,
        cache_hit: bool,
        response_code: ResultCode,
    ) {
        let mut bucket = self.current_bucket.write();
        let current_time = Self::current_timestamp();
        let config = self.config.read();

        // Check if we need a new bucket
        if current_time - bucket.start_time >= config.bucket_size_secs {
            // Save current bucket to time series
            let mut time_series = self.time_series.write();
            
            time_series.queries_per_minute.push(TimeSeriesPoint {
                timestamp: bucket.start_time,
                value: bucket.queries as f64,
            });

            let error_rate = if bucket.queries > 0 {
                (bucket.errors as f64 / bucket.queries as f64) * 100.0
            } else {
                0.0
            };
            time_series.error_rate.push(TimeSeriesPoint {
                timestamp: bucket.start_time,
                value: error_rate,
            });

            if bucket.queries > 0 {
                time_series.avg_response_time.push(TimeSeriesPoint {
                    timestamp: bucket.start_time,
                    value: (bucket.total_response_time_us / bucket.queries) as f64 / 1000.0,
                });
            }

            let hit_rate = if bucket.queries > 0 {
                (bucket.cache_hits as f64 / bucket.queries as f64) * 100.0
            } else {
                0.0
            };
            time_series.cache_hit_rate.push(TimeSeriesPoint {
                timestamp: bucket.start_time,
                value: hit_rate,
            });

            // Trim old data
            let retention_secs = config.retention_hours as u64 * 3600;
            let cutoff = current_time.saturating_sub(retention_secs);
            
            time_series.queries_per_minute.retain(|p| p.timestamp > cutoff);
            time_series.error_rate.retain(|p| p.timestamp > cutoff);
            time_series.avg_response_time.retain(|p| p.timestamp > cutoff);
            time_series.cache_hit_rate.retain(|p| p.timestamp > cutoff);

            // Reset bucket
            *bucket = TimeBucket {
                start_time: current_time,
                queries: 0,
                errors: 0,
                total_response_time_us: 0,
                cache_hits: 0,
            };
        }

        // Update current bucket
        bucket.queries += 1;
        if response_code != ResultCode::NOERROR {
            bucket.errors += 1;
        }
        bucket.total_response_time_us += response_time.as_micros() as u64;
        if cache_hit {
            bucket.cache_hits += 1;
        }
    }

    /// Update geographic statistics
    fn update_geographic_stats(&self, client_ip: IpAddr) {
        // Simplified - would use GeoIP database in production
        let country = self.get_country_for_ip(client_ip);
        let continent = self.get_continent_for_country(&country);

        let mut geo = self.geographic.write();
        *geo.by_country.entry(country.clone()).or_insert(0) += 1;
        *geo.by_continent.entry(continent).or_insert(0) += 1;

        // Update top locations periodically
        if geo.by_country.values().sum::<u64>() % 100 == 0 {
            self.update_top_locations();
        }
    }

    /// Get country for IP (simplified)
    fn get_country_for_ip(&self, ip: IpAddr) -> String {
        // Simplified mapping - would use MaxMind or similar
        match ip {
            IpAddr::V4(addr) => {
                let first_octet = addr.octets()[0];
                match first_octet {
                    1..=50 => "CN".to_string(),
                    51..=100 => "US".to_string(),
                    101..=150 => "EU".to_string(),
                    _ => "Unknown".to_string(),
                }
            }
            IpAddr::V6(_) => "Unknown".to_string(),
        }
    }

    /// Get continent for country
    fn get_continent_for_country(&self, country: &str) -> String {
        match country {
            "US" | "CA" | "MX" => "North America".to_string(),
            "CN" | "JP" | "IN" => "Asia".to_string(),
            "EU" | "UK" | "DE" => "Europe".to_string(),
            _ => "Unknown".to_string(),
        }
    }

    /// Update top locations
    fn update_top_locations(&self) {
        let geo = self.geographic.read();
        let total: u64 = geo.by_country.values().sum();
        
        let mut locations: Vec<_> = geo.by_country.iter()
            .map(|(country, count)| LocationStat {
                location: country.clone(),
                country: country.clone(),
                queries: *count,
                percentage: (*count as f64 / total as f64) * 100.0,
            })
            .collect();

        locations.sort_by(|a, b| b.queries.cmp(&a.queries));
        locations.truncate(10);

        drop(geo);
        self.geographic.write().top_locations = locations;
    }

    /// Get current timestamp
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Get analytics summary
    pub fn get_summary(&self) -> AnalyticsSummary {
        self.update_top_domains();
        self.update_top_locations();

        AnalyticsSummary {
            response_codes: self.response_codes.read().clone(),
            query_types: self.query_types.read().clone(),
            geographic: self.geographic.read().clone(),
            top_queries: self.top_queries.read().clone(),
            time_series: self.time_series.read().clone(),
        }
    }

    /// Detect anomalies
    pub fn detect_anomalies(&self) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();
        let stats = self.response_codes.read();

        // High error rate
        if stats.percentages.servfail_pct > 10.0 {
            anomalies.push(Anomaly {
                type_: "High SERVFAIL rate".to_string(),
                severity: "High".to_string(),
                description: format!("SERVFAIL rate is {:.1}%", stats.percentages.servfail_pct),
                timestamp: Self::current_timestamp(),
            });
        }

        // High NXDOMAIN rate
        if stats.percentages.nxdomain_pct > 30.0 {
            anomalies.push(Anomaly {
                type_: "High NXDOMAIN rate".to_string(),
                severity: "Medium".to_string(),
                description: format!("NXDOMAIN rate is {:.1}%", stats.percentages.nxdomain_pct),
                timestamp: Self::current_timestamp(),
            });
        }

        anomalies
    }
}

/// Analytics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsSummary {
    pub response_codes: ResponseCodeAnalytics,
    pub query_types: QueryTypeAnalytics,
    pub geographic: GeographicAnalytics,
    pub top_queries: TopQueriesAnalytics,
    pub time_series: TimeSeriesAnalytics,
}

/// Anomaly detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    #[serde(rename = "type")]
    pub type_: String,
    pub severity: String,
    pub description: String,
    pub timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_code_analytics() {
        let engine = AnalyticsEngine::new(AnalyticsConfig::default());
        
        // Record some queries
        let packet = DnsPacket::new();
        engine.record_query(
            &packet,
            IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            ResultCode::NOERROR,
            Duration::from_millis(5),
            false,
        );
        
        engine.record_query(
            &packet,
            IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 2)),
            ResultCode::NXDOMAIN,
            Duration::from_millis(3),
            true,
        );

        let stats = engine.response_codes.read();
        assert_eq!(stats.total_queries, 2);
        assert_eq!(stats.noerror, 1);
        assert_eq!(stats.nxdomain, 1);
    }

    #[test]
    fn test_anomaly_detection() {
        let engine = AnalyticsEngine::new(AnalyticsConfig::default());
        
        // Simulate high error rate
        let packet = DnsPacket::new();
        for _ in 0..20 {
            engine.record_query(
                &packet,
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
                ResultCode::SERVFAIL,
                Duration::from_millis(5),
                false,
            );
        }

        let anomalies = engine.detect_anomalies();
        assert!(!anomalies.is_empty());
    }
}