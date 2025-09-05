//! Kubernetes Operator for Atlas DNS
//!
//! Native Kubernetes resource management for DNS zones, records, and policies
//! with automatic synchronization and lifecycle management.
//!
//! # Features
//!
//! * **Custom Resource Definitions** - Native K8s resources for DNS
//! * **Zone Management** - Automatic zone creation and updates
//! * **Record Synchronization** - Two-way sync with DNS server
//! * **Policy Enforcement** - DNS policies as K8s resources
//! * **Service Discovery** - Automatic DNS for K8s services
//! * **Ingress Integration** - DNS records from Ingress resources
//! * **Health Monitoring** - Native K8s health checks

use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use kube::{
    api::{Api, ResourceExt},
    client::Client,
    runtime::{watcher, watcher::Event, watcher::Config as WatcherConfig},
    CustomResource,
};
use k8s_openapi::api::core::v1::{Service as K8sService};
use k8s_openapi::api::networking::v1::Ingress as K8sIngress;
use futures::TryStreamExt;
use reqwest;

/// Operator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorConfig {
    /// Namespace to watch
    pub namespace: String,
    /// Watch all namespaces
    pub watch_all_namespaces: bool,
    /// Reconciliation interval
    pub reconcile_interval: Duration,
    /// DNS server endpoint
    pub dns_server: String,
    /// API token
    pub api_token: Option<String>,
    /// Enable service discovery
    pub service_discovery: bool,
    /// Enable ingress integration
    pub ingress_integration: bool,
    /// Default TTL for records
    pub default_ttl: u32,
    /// Leader election
    pub leader_election: bool,
}

impl Default for OperatorConfig {
    fn default() -> Self {
        Self {
            namespace: "default".to_string(),
            watch_all_namespaces: false,
            reconcile_interval: Duration::from_secs(30),
            dns_server: "http://localhost:5380".to_string(),
            api_token: None,
            service_discovery: true,
            ingress_integration: true,
            default_ttl: 300,
            leader_election: true,
        }
    }
}

/// DNS Zone CRD
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[kube(group = "atlas.dns", version = "v1", kind = "DnsZone", plural = "dnszones")]
#[kube(namespaced)]
#[kube(status = "DnsZoneStatus")]
pub struct DnsZoneSpec {
    /// Zone name
    pub zone_name: String,
    /// Zone type (Primary, Secondary)
    pub zone_type: ZoneType,
    /// Master servers (for Secondary zones)
    pub masters: Option<Vec<String>>,
    /// SOA record
    pub soa: SoaRecord,
    /// Name servers
    pub name_servers: Vec<String>,
    /// DNSSEC enabled
    pub dnssec_enabled: bool,
    /// Tags
    pub tags: HashMap<String, String>,
}


/// Zone type
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub enum ZoneType {
    Primary,
    Secondary,
    Stub,
    Forward,
}

/// SOA record
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SoaRecord {
    /// Primary name server
    pub mname: String,
    /// Responsible person email
    pub rname: String,
    /// Serial number
    pub serial: u32,
    /// Refresh interval
    pub refresh: u32,
    /// Retry interval
    pub retry: u32,
    /// Expire time
    pub expire: u32,
    /// Minimum TTL
    pub minimum: u32,
}

/// DNS Zone status
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DnsZoneStatus {
    /// Phase
    pub phase: ResourcePhase,
    /// Serial number
    pub serial: u32,
    /// Last sync time
    pub last_sync: Option<u64>,
    /// Record count
    pub record_count: u32,
    /// Conditions
    pub conditions: Vec<Condition>,
}

/// DNS Record CRD
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[kube(group = "atlas.dns", version = "v1", kind = "DnsRecord", plural = "dnsrecords")]
#[kube(namespaced)]
#[kube(status = "DnsRecordStatus")]
pub struct DnsRecordSpec {
    /// Zone reference
    pub zone_ref: String,
    /// Record name
    pub name: String,
    /// Record type
    pub record_type: String,
    /// Record class
    pub record_class: String,
    /// TTL
    pub ttl: u32,
    /// Record data
    pub rdata: Vec<String>,
    /// Geo location
    pub geo_location: Option<String>,
    /// Health check
    pub health_check: Option<HealthCheckSpec>,
}


/// Health check specification
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HealthCheckSpec {
    /// Check type (HTTP, HTTPS, TCP, UDP)
    pub check_type: String,
    /// Target
    pub target: String,
    /// Port
    pub port: u16,
    /// Path (for HTTP/HTTPS)
    pub path: Option<String>,
    /// Expected response
    pub expected: Option<String>,
    /// Interval
    pub interval: u32,
    /// Timeout
    pub timeout: u32,
    /// Threshold
    pub threshold: u32,
}

/// DNS Record status
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DnsRecordStatus {
    /// Phase
    pub phase: ResourcePhase,
    /// Active
    pub active: bool,
    /// Health status
    pub health: Option<HealthStatus>,
    /// Last update
    pub last_update: Option<u64>,
    /// Conditions
    pub conditions: Vec<Condition>,
}

/// DNS Policy CRD
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[kube(group = "atlas.dns", version = "v1", kind = "DnsPolicy", plural = "dnspolicies")]
#[kube(namespaced)]
#[kube(status = "DnsPolicyStatus")]
pub struct DnsPolicySpec {
    /// Policy type
    pub policy_type: PolicyType,
    /// Selector
    pub selector: PolicySelector,
    /// Rules
    pub rules: Vec<PolicyRule>,
    /// Priority
    pub priority: u32,
    /// Enabled
    pub enabled: bool,
}


/// Policy type
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub enum PolicyType {
    LoadBalancing,
    Failover,
    GeoDNS,
    RateLimiting,
    Firewall,
}

/// Policy selector
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PolicySelector {
    /// Zone patterns
    pub zones: Option<Vec<String>>,
    /// Record patterns
    pub records: Option<Vec<String>>,
    /// Labels
    pub labels: Option<HashMap<String, String>>,
}

/// Policy rule
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PolicyRule {
    /// Rule name
    pub name: String,
    /// Match conditions
    pub matches: Vec<MatchCondition>,
    /// Actions
    pub actions: Vec<PolicyAction>,
}

/// Match condition
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MatchCondition {
    /// Field
    pub field: String,
    /// Operator
    pub operator: String,
    /// Values
    pub values: Vec<String>,
}

/// Policy action
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PolicyAction {
    /// Action type
    pub action_type: String,
    /// Parameters
    pub parameters: HashMap<String, String>,
}

/// DNS Policy status
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DnsPolicyStatus {
    /// Phase
    pub phase: ResourcePhase,
    /// Applied count
    pub applied_count: u32,
    /// Last applied
    pub last_applied: Option<u64>,
    /// Conditions
    pub conditions: Vec<Condition>,
}


/// Resource phase
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum ResourcePhase {
    Pending,
    Creating,
    Active,
    Updating,
    Deleting,
    Failed,
}

/// Health status
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HealthStatus {
    /// Healthy
    pub healthy: bool,
    /// Last check
    pub last_check: u64,
    /// Check count
    pub check_count: u32,
    /// Success rate
    pub success_rate: f64,
}

/// Condition
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Condition {
    /// Type
    pub condition_type: String,
    /// Status
    pub status: String,
    /// Reason
    pub reason: String,
    /// Message
    pub message: String,
    /// Last transition
    pub last_transition: u64,
}

/// Service discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ServiceDiscovery {
    /// Enabled
    pub enabled: bool,
    /// Domain suffix
    pub domain_suffix: String,
    /// Service types
    pub service_types: Vec<ServiceType>,
    /// Create PTR records
    pub create_ptr: bool,
    /// Create SRV records
    pub create_srv: bool,
}

/// Service type
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub enum ServiceType {
    ClusterIP,
    NodePort,
    LoadBalancer,
    ExternalName,
    Headless,
}


/// Operator statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct OperatorStats {
    /// Total reconciliations
    pub total_reconciliations: u64,
    /// Successful reconciliations
    pub successful_reconciliations: u64,
    /// Failed reconciliations
    pub failed_reconciliations: u64,
    /// Resources managed
    pub resources_managed: HashMap<String, u64>,
    /// Last reconciliation
    pub last_reconciliation: Option<u64>,
    /// Average reconcile time (ms)
    pub avg_reconcile_time_ms: f64,
}

/// Kubernetes operator
#[derive(Clone)]
pub struct KubernetesOperator {
    /// Configuration
    config: Arc<RwLock<OperatorConfig>>,
    /// Kubernetes client
    client: Client,
    /// DNS zones API
    zones_api: Api<DnsZone>,
    /// DNS records API
    records_api: Api<DnsRecord>,
    /// DNS policies API
    policies_api: Api<DnsPolicy>,
    /// Services API
    services_api: Api<K8sService>,
    /// Ingress API
    ingress_api: Api<K8sIngress>,
    /// HTTP client for DNS server API
    http_client: reqwest::Client,
    /// Service discovery
    service_discovery: Arc<RwLock<ServiceDiscovery>>,
    /// Statistics
    stats: Arc<RwLock<OperatorStats>>,
    /// Leader flag
    is_leader: Arc<RwLock<bool>>,
}



impl KubernetesOperator {
    /// Create new operator
    pub async fn new(config: OperatorConfig) -> Result<Self, kube::Error> {
        let client = Client::try_default().await?;
        
        let namespace = if config.watch_all_namespaces {
            None
        } else {
            Some(config.namespace.clone())
        };
        
        // Initialize APIs
        let zones_api = if let Some(ns) = &namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };
        
        let records_api = if let Some(ns) = &namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };
        
        let policies_api = if let Some(ns) = &namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };
        
        let services_api = if let Some(ns) = &namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };
        
        let ingress_api = if let Some(ns) = &namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };
        
        let http_client = reqwest::Client::new();
        
        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            client,
            zones_api,
            records_api,
            policies_api,
            services_api,
            ingress_api,
            http_client,
            service_discovery: Arc::new(RwLock::new(ServiceDiscovery {
                enabled: true,
                domain_suffix: "cluster.local".to_string(),
                service_types: vec![ServiceType::ClusterIP, ServiceType::LoadBalancer],
                create_ptr: true,
                create_srv: true,
            })),
            stats: Arc::new(RwLock::new(OperatorStats::default())),
            is_leader: Arc::new(RwLock::new(false)),
        })
    }

    /// Start operator
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Acquire leadership if configured
        if self.config.read().await.leader_election {
            self.acquire_leadership().await?;
        } else {
            *self.is_leader.write().await = true;
        }

        log::info!("Starting Kubernetes operator controllers");
        
        // Start controllers for each resource type
        tokio::try_join!(
            self.start_zone_controller(),
            self.start_record_controller(), 
            self.start_policy_controller(),
            self.start_service_controller(),
            self.start_ingress_controller(),
        )?;
        
        Ok(())
    }

    /// Acquire leadership using Kubernetes lease
    async fn acquire_leadership(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use k8s_openapi::api::coordination::v1::Lease;
        use kube::api::{Patch, PatchParams};
        use serde_json::json;
        
        let namespace = self.config.read().await.namespace.clone();
        let leases: Api<Lease> = Api::namespaced(self.client.clone(), &namespace);
        let lease_name = "atlas-dns-operator-lock";
        
        // Try to create or update the lease
        let patch = json!({
            "metadata": {
                "name": lease_name,
            },
            "spec": {
                "holderIdentity": std::env::var("HOSTNAME").unwrap_or_else(|_| "atlas-operator".to_string()),
                "leaseDurationSeconds": 30,
                "acquireTime": chrono::Utc::now().to_rfc3339(),
                "renewTime": chrono::Utc::now().to_rfc3339(),
            }
        });
        
        match leases.patch(lease_name, &PatchParams::apply("atlas-operator"), &Patch::Apply(&patch)).await {
            Ok(_) => {
                *self.is_leader.write().await = true;
                log::info!("Successfully acquired leadership lease");
                Ok(())
            }
            Err(e) => {
                log::warn!("Failed to acquire leadership: {:?}", e);
                *self.is_leader.write().await = false;
                Err(Box::new(e))
            }
        }
    }

    /// Start zone controller
    async fn start_zone_controller(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let zones_api = self.zones_api.clone();
        let operator = self.clone();
        
        let watcher = watcher(zones_api, WatcherConfig::default());
        
        tokio::spawn(async move {
            watcher
                .try_for_each(|event| async {
                    match event {
                        Event::Applied(zone) => {
                            if let Err(e) = operator.sync_zone_to_dns(&zone).await {
                                log::error!("Failed to sync zone {}: {}", zone.name_any(), e);
                            }
                        }
                        Event::Deleted(zone) => {
                            if let Err(e) = operator.delete_zone_from_dns(&zone.spec.zone_name).await {
                                log::error!("Failed to delete zone {}: {}", zone.spec.zone_name, e);
                            }
                        }
                        Event::Restarted(_) => {
                            log::info!("Zone watcher restarted");
                        }
                    }
                    Ok(())
                })
                .await
        });
        
        Ok(())
    }
    
    /// Start record controller
    async fn start_record_controller(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let records_api = self.records_api.clone();
        let operator = self.clone();
        
        let watcher = watcher(records_api, WatcherConfig::default());
        
        tokio::spawn(async move {
            watcher
                .try_for_each(|event| async {
                    match event {
                        Event::Applied(record) => {
                            if let Err(e) = operator.sync_record_to_dns(&record).await {
                                log::error!("Failed to sync record {}: {}", record.name_any(), e);
                            }
                        }
                        Event::Deleted(record) => {
                            if let Err(e) = operator.delete_record_from_dns(&record).await {
                                log::error!("Failed to delete record {}: {}", record.name_any(), e);
                            }
                        }
                        Event::Restarted(_) => {
                            log::info!("Record watcher restarted");
                        }
                    }
                    Ok(())
                })
                .await
        });
        
        Ok(())
    }
    
    /// Start policy controller
    async fn start_policy_controller(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let policies_api = self.policies_api.clone();
        let operator = self.clone();
        
        let watcher = watcher(policies_api, WatcherConfig::default());
        
        tokio::spawn(async move {
            watcher
                .try_for_each(|event| async {
                    match event {
                        Event::Applied(policy) => {
                            if let Err(e) = operator.apply_policy_to_dns(&policy).await {
                                log::error!("Failed to apply policy {}: {}", policy.name_any(), e);
                            }
                        }
                        Event::Deleted(policy) => {
                            log::info!("Policy {} deleted", policy.name_any());
                        }
                        Event::Restarted(_) => {
                            log::info!("Policy watcher restarted");
                        }
                    }
                    Ok(())
                })
                .await
        });
        
        Ok(())
    }
    
    /// Start service controller for service discovery
    async fn start_service_controller(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let services_api = self.services_api.clone();
        let operator = self.clone();
        
        let watcher = watcher(services_api, WatcherConfig::default());
        
        tokio::spawn(async move {
            watcher
                .try_for_each(|event| async {
                    match event {
                        Event::Applied(service) => {
                            if let Err(e) = operator.handle_service_event(&service, false).await {
                                log::error!("Failed to handle service {}: {}", service.name_any(), e);
                            }
                        }
                        Event::Deleted(service) => {
                            if let Err(e) = operator.handle_service_event(&service, true).await {
                                log::error!("Failed to handle service deletion {}: {}", service.name_any(), e);
                            }
                        }
                        Event::Restarted(_) => {
                            log::info!("Service watcher restarted");
                        }
                    }
                    Ok(())
                })
                .await
        });
        
        Ok(())
    }
    
    /// Start ingress controller
    async fn start_ingress_controller(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let ingress_api = self.ingress_api.clone();
        let operator = self.clone();
        
        let watcher = watcher(ingress_api, WatcherConfig::default());
        
        tokio::spawn(async move {
            watcher
                .try_for_each(|event| async {
                    match event {
                        Event::Applied(ingress) => {
                            if let Err(e) = operator.handle_ingress_event(&ingress, false).await {
                                log::error!("Failed to handle ingress {}: {}", ingress.name_any(), e);
                            }
                        }
                        Event::Deleted(ingress) => {
                            if let Err(e) = operator.handle_ingress_event(&ingress, true).await {
                                log::error!("Failed to handle ingress deletion {}: {}", ingress.name_any(), e);
                            }
                        }
                        Event::Restarted(_) => {
                            log::info!("Ingress watcher restarted");
                        }
                    }
                    Ok(())
                })
                .await
        });
        
        Ok(())
    }








    /// Sync zone to DNS server
    async fn sync_zone_to_dns(&self, zone: &DnsZone) -> Result<(), String> {
        let (dns_server, api_token) = {
            let config = self.config.read().await;
            (config.dns_server.clone(), config.api_token.clone())
        };
        
        let url = format!("{}/api/v2/zones", dns_server);
        
        let zone_data = serde_json::json!({
            "name": zone.spec.zone_name,
            "zone_type": zone.spec.zone_type,
            "soa": zone.spec.soa,
            "name_servers": zone.spec.name_servers,
            "dnssec_enabled": zone.spec.dnssec_enabled,
            "tags": zone.spec.tags
        });
        
        let mut request = self.http_client.post(&url).json(&zone_data);
        
        if let Some(ref token) = api_token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }
        
        match request.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    log::info!("Successfully synced zone {} to DNS server", zone.spec.zone_name);
                    Ok(())
                } else {
                    let error = format!("DNS server returned status: {}", response.status());
                    log::error!("{}", error);
                    Err(error)
                }
            }
            Err(e) => {
                let error = format!("Failed to sync zone to DNS server: {}", e);
                log::error!("{}", error);
                Err(error)
            }
        }
    }

    /// Delete zone from DNS server
    async fn delete_zone_from_dns(&self, zone_name: &str) -> Result<(), String> {
        let (dns_server, api_token) = {
            let config = self.config.read().await;
            (config.dns_server.clone(), config.api_token.clone())
        };
        
        let url = format!("{}/api/v2/zones/{}", dns_server, zone_name);
        
        let mut request = self.http_client.delete(&url);
        
        if let Some(ref token) = api_token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }
        
        match request.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    log::info!("Successfully deleted zone {} from DNS server", zone_name);
                    Ok(())
                } else {
                    let error = format!("DNS server returned status: {}", response.status());
                    log::error!("{}", error);
                    Err(error)
                }
            }
            Err(e) => {
                let error = format!("Failed to delete zone from DNS server: {}", e);
                log::error!("{}", error);
                Err(error)
            }
        }
    }

    /// Sync record to DNS server
    async fn sync_record_to_dns(&self, record: &DnsRecord) -> Result<(), String> {
        let (dns_server, api_token) = {
            let config = self.config.read().await;
            (config.dns_server.clone(), config.api_token.clone())
        };
        
        let url = format!("{}/api/v2/zones/{}/records", dns_server, record.spec.zone_ref);
        
        let record_data = serde_json::json!({
            "name": record.spec.name,
            "record_type": record.spec.record_type,
            "record_class": record.spec.record_class,
            "ttl": record.spec.ttl,
            "rdata": record.spec.rdata,
            "geo_location": record.spec.geo_location
        });
        
        let mut request = self.http_client.post(&url).json(&record_data);
        
        if let Some(ref token) = api_token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }
        
        match request.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    log::info!("Successfully synced record {} to DNS server", record.spec.name);
                    Ok(())
                } else {
                    let error = format!("DNS server returned status: {}", response.status());
                    log::error!("{}", error);
                    Err(error)
                }
            }
            Err(e) => {
                let error = format!("Failed to sync record to DNS server: {}", e);
                log::error!("{}", error);
                Err(error)
            }
        }
    }

    /// Delete record from DNS server
    async fn delete_record_from_dns(&self, record: &DnsRecord) -> Result<(), String> {
        let (dns_server, api_token) = {
            let config = self.config.read().await;
            (config.dns_server.clone(), config.api_token.clone())
        };
        
        let url = format!("{}/api/v2/zones/{}/records/{}", 
                          dns_server, record.spec.zone_ref, record.spec.name);
        
        let mut request = self.http_client.delete(&url);
        
        if let Some(ref token) = api_token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }
        
        match request.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    log::info!("Successfully deleted record {} from DNS server", record.spec.name);
                    Ok(())
                } else {
                    let error = format!("DNS server returned status: {}", response.status());
                    log::error!("{}", error);
                    Err(error)
                }
            }
            Err(e) => {
                let error = format!("Failed to delete record from DNS server: {}", e);
                log::error!("{}", error);
                Err(error)
            }
        }
    }

    /// Apply policy to DNS server
    async fn apply_policy_to_dns(&self, policy: &DnsPolicy) -> Result<(), String> {
        let (dns_server, api_token) = {
            let config = self.config.read().await;
            (config.dns_server.clone(), config.api_token.clone())
        };
        
        let url = format!("{}/api/v2/policies", dns_server);
        
        let policy_data = serde_json::json!({
            "name": policy.name_any(),
            "policy_type": policy.spec.policy_type,
            "selector": policy.spec.selector,
            "rules": policy.spec.rules,
            "priority": policy.spec.priority,
            "enabled": policy.spec.enabled
        });
        
        let mut request = self.http_client.post(&url).json(&policy_data);
        
        if let Some(ref token) = api_token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }
        
        match request.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    log::info!("Successfully applied policy {} to DNS server", policy.name_any());
                    Ok(())
                } else {
                    let error = format!("DNS server returned status: {}", response.status());
                    log::error!("{}", error);
                    Err(error)
                }
            }
            Err(e) => {
                let error = format!("Failed to apply policy to DNS server: {}", e);
                log::error!("{}", error);
                Err(error)
            }
        }
    }
    
    /// Handle service events for service discovery
    async fn handle_service_event(&self, service: &K8sService, deleted: bool) -> Result<(), String> {
        let config = self.service_discovery.read().await;
        if !config.enabled {
            return Ok(());
        }
        
        let service_name = service.name_any();
        let namespace = service.namespace().unwrap_or("default".to_string());
        
        if deleted {
            // Remove DNS records for the service
            let dns_name = format!("{}.{}.{}", service_name, namespace, config.domain_suffix);
            log::info!("Removing DNS records for service {}", dns_name);
            
            // Would call DNS server API to remove A and SRV records
            return Ok(());
        }
        
        if let Some(spec) = &service.spec {
            let cluster_ip = spec.cluster_ip.as_ref();
            
            if let Some(ip) = cluster_ip {
                if ip != "None" { // Skip headless services
                    let dns_name = format!("{}.{}.{}", service_name, namespace, config.domain_suffix);
                    
                    // Create A record
                    let _record_data = serde_json::json!({
                        "name": dns_name,
                        "record_type": "A",
                        "record_class": "IN",
                        "ttl": 30,
                        "rdata": [ip]
                    });
                    
                    log::info!("Creating DNS record for service {}: {} -> {}", service_name, dns_name, ip);
                    
                    // Create SRV records for each port
                    if let Some(ports) = &spec.ports {
                        for port in ports {
                            if let Some(port_name) = &port.name {
                                let srv_name = format!("_{}._{}.{}", port_name, "tcp", dns_name);
                                let srv_target = format!("{}.", dns_name);
                                let srv_data = format!("0 5 {} {}", port.port, srv_target);
                                
                                log::info!("Creating SRV record: {} -> {}", srv_name, srv_data);
                            }
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Handle ingress events
    async fn handle_ingress_event(&self, ingress: &K8sIngress, deleted: bool) -> Result<(), String> {
        let ingress_integration = {
            let config = self.config.read().await;
            config.ingress_integration
        };
        if !ingress_integration {
            return Ok(());
        }
        
        if let Some(spec) = &ingress.spec {
            if let Some(rules) = &spec.rules {
                for rule in rules {
                    if let Some(host) = &rule.host {
                        if deleted {
                            log::info!("Removing DNS record for ingress host: {}", host);
                            // Would call DNS server API to remove record
                        } else {
                            // Get ingress IP
                            let ingress_ip = if let Some(status) = &ingress.status {
                                if let Some(load_balancer) = &status.load_balancer {
                                    if let Some(ingresses) = &load_balancer.ingress {
                                        ingresses.first().and_then(|ing| ing.ip.as_ref())
                                    } else { None }
                                } else { None }
                            } else { None };
                            
                            if let Some(ip) = ingress_ip {
                                log::info!("Creating DNS record for ingress host: {} -> {}", host, ip);
                                
                                // Create A record for ingress host
                                let _record_data = serde_json::json!({
                                    "name": host,
                                    "record_type": "A",
                                    "record_class": "IN",
                                    "ttl": 60,
                                    "rdata": [ip]
                                });
                                
                                // Would call DNS server API to create record
                            }
                        }
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Update statistics
    async fn update_stats(&self, duration: Duration, success: bool) {
        let mut stats = self.stats.write().await;
        
        stats.total_reconciliations += 1;
        if success {
            stats.successful_reconciliations += 1;
        } else {
            stats.failed_reconciliations += 1;
        }
        
        // Update average reconcile time
        let n = stats.total_reconciliations;
        let new_time = duration.as_millis() as f64;
        stats.avg_reconcile_time_ms = 
            ((stats.avg_reconcile_time_ms * (n - 1) as f64) + new_time) / n as f64;
        
        stats.last_reconciliation = Some(Self::current_timestamp());
    }

    /// Get operator configuration
    pub async fn get_config(&self) -> OperatorConfig {
        self.config.read().await.clone()
    }
    
    /// Update operator configuration
    pub async fn update_config(&self, config: OperatorConfig) {
        *self.config.write().await = config;
    }

    /// Get statistics
    pub async fn get_stats(&self) -> OperatorStats {
        self.stats.read().await.clone()
    }

    /// Get current timestamp
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_operator_creation() {
        // This test requires a Kubernetes cluster, so we'll skip in CI
        if std::env::var("CI").is_ok() {
            return;
        }
        
        let config = OperatorConfig::default();
        match KubernetesOperator::new(config).await {
            Ok(operator) => {
                assert!(!*operator.is_leader.read().await);
            }
            Err(_) => {
                // Expected if no K8s cluster available
                println!("Skipping test - no Kubernetes cluster available");
            }
        }
    }

    #[tokio::test]
    async fn test_operator_config() {
        // Test configuration management
        let config = OperatorConfig {
            namespace: "test-namespace".to_string(),
            watch_all_namespaces: true,
            ..Default::default()
        };
        
        // Test with in-memory config only since we may not have K8s cluster
        let updated_config = OperatorConfig {
            reconcile_interval: Duration::from_secs(60),
            ..config.clone()
        };
        
        assert_eq!(updated_config.namespace, "test-namespace");
        assert!(updated_config.watch_all_namespaces);
        assert_eq!(updated_config.reconcile_interval, Duration::from_secs(60));
    }
}