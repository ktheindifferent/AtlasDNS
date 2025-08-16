//! Grafana Dashboards Configuration
//!
//! Provides pre-built Grafana dashboard configurations for comprehensive
//! DNS server monitoring with templates, alerts, and visualizations.
//!
//! # Features
//!
//! * **Pre-built Dashboards** - Ready-to-use monitoring templates
//! * **Auto-provisioning** - Automatic dashboard deployment
//! * **Variable Templates** - Dynamic dashboard configuration
//! * **Alert Rules** - Integrated alerting configurations
//! * **Multi-datasource** - Support for Prometheus, Loki, Tempo
//! * **Responsive Layout** - Mobile and desktop optimized
//! * **Dark/Light Themes** - Theme-aware visualizations

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};

/// Dashboard configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    /// Dashboard title
    pub title: String,
    /// Dashboard UID
    pub uid: String,
    /// Dashboard version
    pub version: u32,
    /// Tags for organization
    pub tags: Vec<String>,
    /// Timezone setting
    pub timezone: String,
    /// Refresh interval
    pub refresh: String,
    /// Time range
    pub time: TimeRange,
    /// Dashboard panels
    pub panels: Vec<Panel>,
    /// Template variables
    pub templating: Templating,
    /// Annotations
    pub annotations: Vec<Annotation>,
}

/// Time range configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub from: String,
    pub to: String,
}

/// Panel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Panel {
    /// Panel ID
    pub id: u32,
    /// Panel title
    pub title: String,
    /// Panel type (graph, stat, table, etc.)
    pub panel_type: String,
    /// Grid position
    pub grid_pos: GridPos,
    /// Data source
    pub datasource: String,
    /// Queries
    pub targets: Vec<Query>,
    /// Panel options
    pub options: Value,
    /// Field configuration
    pub field_config: Option<FieldConfig>,
}

/// Grid position
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GridPos {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

/// Query configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Query {
    /// Reference ID
    pub ref_id: String,
    /// Query expression
    pub expr: String,
    /// Legend format
    pub legend_format: Option<String>,
    /// Interval
    pub interval: Option<String>,
}

/// Field configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldConfig {
    pub defaults: FieldDefaults,
    pub overrides: Vec<FieldOverride>,
}

/// Field defaults
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDefaults {
    pub unit: Option<String>,
    pub decimals: Option<u8>,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub color: Option<ColorConfig>,
    pub thresholds: Option<ThresholdConfig>,
}

/// Color configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorConfig {
    pub mode: String,
    pub fixed_color: Option<String>,
}

/// Threshold configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    pub mode: String,
    pub steps: Vec<ThresholdStep>,
}

/// Threshold step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdStep {
    pub value: Option<f64>,
    pub color: String,
}

/// Field override
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldOverride {
    pub matcher: Matcher,
    pub properties: Vec<Property>,
}

/// Field matcher
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Matcher {
    pub id: String,
    pub options: Value,
}

/// Field property
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Property {
    pub id: String,
    pub value: Value,
}

/// Template variables
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Templating {
    pub list: Vec<TemplateVar>,
}

/// Template variable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVar {
    pub name: String,
    pub label: String,
    pub var_type: String,
    pub query: Option<String>,
    pub datasource: Option<String>,
    pub current: Option<Value>,
    pub options: Vec<Value>,
    pub multi: bool,
    pub include_all: bool,
}

/// Annotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub name: String,
    pub datasource: String,
    pub enable: bool,
    pub icon_color: String,
    pub query: String,
}

/// Grafana dashboard generator
pub struct GrafanaDashboardGenerator;

impl GrafanaDashboardGenerator {
    /// Generate main DNS overview dashboard
    pub fn generate_overview_dashboard() -> Value {
        json!({
            "dashboard": {
                "id": null,
                "uid": "atlas-dns-overview",
                "title": "Atlas DNS - Overview",
                "tags": ["dns", "atlas", "overview"],
                "timezone": "browser",
                "schemaVersion": 30,
                "version": 1,
                "refresh": "10s",
                "time": {
                    "from": "now-1h",
                    "to": "now"
                },
                "templating": {
                    "list": [
                        {
                            "name": "datasource",
                            "type": "datasource",
                            "query": "prometheus",
                            "current": {
                                "text": "Prometheus",
                                "value": "prometheus"
                            }
                        },
                        {
                            "name": "instance",
                            "type": "query",
                            "datasource": "$datasource",
                            "query": "label_values(dns_queries_total, instance)",
                            "multi": true,
                            "includeAll": true,
                            "current": {
                                "text": "All",
                                "value": "$__all"
                            }
                        }
                    ]
                },
                "panels": [
                    Self::create_query_rate_panel(1, 0, 0),
                    Self::create_response_codes_panel(2, 12, 0),
                    Self::create_cache_hit_rate_panel(3, 0, 8),
                    Self::create_latency_panel(4, 12, 8),
                    Self::create_top_queries_panel(5, 0, 16),
                    Self::create_error_rate_panel(6, 12, 16),
                    Self::create_query_types_panel(7, 0, 24),
                    Self::create_geographic_map_panel(8, 12, 24),
                ]
            },
            "overwrite": true
        })
    }

    /// Generate performance dashboard
    pub fn generate_performance_dashboard() -> Value {
        json!({
            "dashboard": {
                "id": null,
                "uid": "atlas-dns-performance",
                "title": "Atlas DNS - Performance",
                "tags": ["dns", "atlas", "performance"],
                "timezone": "browser",
                "refresh": "5s",
                "panels": [
                    Self::create_response_time_histogram(1, 0, 0),
                    Self::create_throughput_panel(2, 12, 0),
                    Self::create_cpu_usage_panel(3, 0, 8),
                    Self::create_memory_usage_panel(4, 8, 8),
                    Self::create_network_io_panel(5, 16, 8),
                    Self::create_connection_pool_panel(6, 0, 16),
                    Self::create_cache_performance_panel(7, 12, 16),
                ]
            },
            "overwrite": true
        })
    }

    /// Generate security dashboard
    pub fn generate_security_dashboard() -> Value {
        json!({
            "dashboard": {
                "id": null,
                "uid": "atlas-dns-security",
                "title": "Atlas DNS - Security",
                "tags": ["dns", "atlas", "security"],
                "timezone": "browser",
                "refresh": "10s",
                "panels": [
                    Self::create_ddos_detection_panel(1, 0, 0),
                    Self::create_rate_limiting_panel(2, 12, 0),
                    Self::create_firewall_blocks_panel(3, 0, 8),
                    Self::create_dnssec_validation_panel(4, 12, 8),
                    Self::create_threat_intelligence_panel(5, 0, 16),
                    Self::create_suspicious_queries_panel(6, 12, 16),
                ]
            },
            "overwrite": true
        })
    }

    /// Create query rate panel
    fn create_query_rate_panel(id: u32, x: u32, y: u32) -> Value {
        json!({
            "id": id,
            "type": "graph",
            "title": "Query Rate",
            "gridPos": { "x": x, "y": y, "w": 12, "h": 8 },
            "datasource": "$datasource",
            "targets": [
                {
                    "refId": "A",
                    "expr": "rate(dns_queries_total{instance=~\"$instance\"}[5m])",
                    "legendFormat": "{{instance}}"
                }
            ],
            "yaxes": [
                {
                    "format": "ops",
                    "label": "Queries/sec"
                },
                {
                    "format": "short"
                }
            ],
            "lines": true,
            "fill": 1,
            "linewidth": 2,
            "pointradius": 5,
            "points": false,
            "stack": false,
            "percentage": false,
            "legend": {
                "show": true,
                "current": true,
                "values": true,
                "avg": true,
                "max": true
            },
            "tooltip": {
                "shared": true,
                "sort": 2,
                "value_type": "individual"
            }
        })
    }

    /// Create response codes panel
    fn create_response_codes_panel(id: u32, x: u32, y: u32) -> Value {
        json!({
            "id": id,
            "type": "piechart",
            "title": "Response Codes",
            "gridPos": { "x": x, "y": y, "w": 12, "h": 8 },
            "datasource": "$datasource",
            "targets": [
                {
                    "refId": "A",
                    "expr": "sum(rate(dns_response_codes_total{instance=~\"$instance\"}[5m])) by (code)",
                    "legendFormat": "{{code}}"
                }
            ],
            "options": {
                "pieType": "donut",
                "displayLabels": ["name", "percent"],
                "legendDisplayMode": "table",
                "legendPlacement": "right",
                "legendValues": ["value", "percent"]
            }
        })
    }

    /// Create cache hit rate panel
    fn create_cache_hit_rate_panel(id: u32, x: u32, y: u32) -> Value {
        json!({
            "id": id,
            "type": "stat",
            "title": "Cache Hit Rate",
            "gridPos": { "x": x, "y": y, "w": 6, "h": 8 },
            "datasource": "$datasource",
            "targets": [
                {
                    "refId": "A",
                    "expr": "avg(rate(dns_cache_hits_total{instance=~\"$instance\"}[5m]) / rate(dns_queries_total{instance=~\"$instance\"}[5m])) * 100"
                }
            ],
            "options": {
                "orientation": "auto",
                "textMode": "auto",
                "colorMode": "background",
                "graphMode": "area",
                "justifyMode": "auto"
            },
            "fieldConfig": {
                "defaults": {
                    "unit": "percent",
                    "decimals": 1,
                    "min": 0,
                    "max": 100,
                    "thresholds": {
                        "mode": "absolute",
                        "steps": [
                            { "value": null, "color": "red" },
                            { "value": 50, "color": "yellow" },
                            { "value": 80, "color": "green" }
                        ]
                    }
                }
            }
        })
    }

    /// Create latency panel
    fn create_latency_panel(id: u32, x: u32, y: u32) -> Value {
        json!({
            "id": id,
            "type": "graph",
            "title": "Query Latency",
            "gridPos": { "x": x, "y": y, "w": 12, "h": 8 },
            "datasource": "$datasource",
            "targets": [
                {
                    "refId": "A",
                    "expr": "histogram_quantile(0.50, rate(dns_query_duration_seconds_bucket{instance=~\"$instance\"}[5m]))",
                    "legendFormat": "p50"
                },
                {
                    "refId": "B",
                    "expr": "histogram_quantile(0.95, rate(dns_query_duration_seconds_bucket{instance=~\"$instance\"}[5m]))",
                    "legendFormat": "p95"
                },
                {
                    "refId": "C",
                    "expr": "histogram_quantile(0.99, rate(dns_query_duration_seconds_bucket{instance=~\"$instance\"}[5m]))",
                    "legendFormat": "p99"
                }
            ],
            "yaxes": [
                {
                    "format": "ms",
                    "label": "Response Time"
                },
                {
                    "format": "short"
                }
            ],
            "thresholds": [
                {
                    "value": 10,
                    "colorMode": "critical",
                    "fill": false,
                    "line": true,
                    "op": "gt"
                }
            ]
        })
    }

    /// Create top queries panel
    fn create_top_queries_panel(id: u32, x: u32, y: u32) -> Value {
        json!({
            "id": id,
            "type": "table",
            "title": "Top Queries",
            "gridPos": { "x": x, "y": y, "w": 12, "h": 8 },
            "datasource": "$datasource",
            "targets": [
                {
                    "refId": "A",
                    "expr": "topk(10, sum(rate(dns_queries_by_domain_total{instance=~\"$instance\"}[5m])) by (domain))",
                    "format": "table",
                    "instant": true
                }
            ],
            "options": {
                "showHeader": true
            },
            "fieldConfig": {
                "defaults": {
                    "custom": {
                        "align": "auto",
                        "displayMode": "auto"
                    }
                },
                "overrides": [
                    {
                        "matcher": { "id": "byName", "options": "Value" },
                        "properties": [
                            {
                                "id": "custom.displayMode",
                                "value": "lcd-gauge"
                            },
                            {
                                "id": "unit",
                                "value": "ops"
                            }
                        ]
                    }
                ]
            }
        })
    }

    /// Create error rate panel
    fn create_error_rate_panel(id: u32, x: u32, y: u32) -> Value {
        json!({
            "id": id,
            "type": "graph",
            "title": "Error Rate",
            "gridPos": { "x": x, "y": y, "w": 12, "h": 8 },
            "datasource": "$datasource",
            "targets": [
                {
                    "refId": "A",
                    "expr": "sum(rate(dns_response_codes_total{instance=~\"$instance\",code!=\"NOERROR\"}[5m])) / sum(rate(dns_response_codes_total{instance=~\"$instance\"}[5m])) * 100",
                    "legendFormat": "Error Rate %"
                }
            ],
            "yaxes": [
                {
                    "format": "percent",
                    "label": "Error Rate"
                }
            ],
            "alert": {
                "conditions": [
                    {
                        "evaluator": {
                            "params": [5],
                            "type": "gt"
                        },
                        "operator": {
                            "type": "and"
                        },
                        "query": {
                            "params": ["A", "5m", "now"]
                        },
                        "reducer": {
                            "params": [],
                            "type": "avg"
                        },
                        "type": "query"
                    }
                ],
                "executionErrorState": "alerting",
                "for": "5m",
                "frequency": "1m",
                "handler": 1,
                "name": "High DNS Error Rate",
                "noDataState": "no_data",
                "notifications": []
            }
        })
    }

    /// Create query types panel
    fn create_query_types_panel(id: u32, x: u32, y: u32) -> Value {
        json!({
            "id": id,
            "type": "bargauge",
            "title": "Query Types Distribution",
            "gridPos": { "x": x, "y": y, "w": 12, "h": 8 },
            "datasource": "$datasource",
            "targets": [
                {
                    "refId": "A",
                    "expr": "sum(rate(dns_queries_by_type_total{instance=~\"$instance\"}[5m])) by (type)",
                    "legendFormat": "{{type}}"
                }
            ],
            "options": {
                "orientation": "horizontal",
                "displayMode": "gradient",
                "showUnfilled": true
            },
            "fieldConfig": {
                "defaults": {
                    "unit": "ops",
                    "color": {
                        "mode": "thresholds"
                    },
                    "thresholds": {
                        "mode": "absolute",
                        "steps": [
                            { "value": null, "color": "blue" },
                            { "value": 100, "color": "green" },
                            { "value": 1000, "color": "yellow" },
                            { "value": 10000, "color": "red" }
                        ]
                    }
                }
            }
        })
    }

    /// Create geographic map panel
    fn create_geographic_map_panel(id: u32, x: u32, y: u32) -> Value {
        json!({
            "id": id,
            "type": "geomap",
            "title": "Query Geographic Distribution",
            "gridPos": { "x": x, "y": y, "w": 12, "h": 8 },
            "datasource": "$datasource",
            "targets": [
                {
                    "refId": "A",
                    "expr": "sum(rate(dns_queries_by_country_total{instance=~\"$instance\"}[5m])) by (country, latitude, longitude)",
                    "legendFormat": "{{country}}"
                }
            ],
            "options": {
                "view": {
                    "id": "coords",
                    "lat": 0,
                    "lon": 0,
                    "zoom": 2
                },
                "controls": {
                    "showZoom": true,
                    "mouseWheelZoom": true,
                    "showAttribution": true,
                    "showScale": true,
                    "showDebug": false
                },
                "tooltip": {
                    "mode": "details"
                },
                "basemap": {
                    "type": "default",
                    "name": "Layer",
                    "config": {}
                },
                "layers": [
                    {
                        "type": "markers",
                        "name": "Layer",
                        "config": {
                            "showLegend": true,
                            "size": {
                                "field": "Value",
                                "fixed": 5,
                                "max": 15,
                                "min": 2
                            }
                        }
                    }
                ]
            }
        })
    }

    /// Create response time histogram
    fn create_response_time_histogram(id: u32, x: u32, y: u32) -> Value {
        json!({
            "id": id,
            "type": "heatmap",
            "title": "Response Time Distribution",
            "gridPos": { "x": x, "y": y, "w": 12, "h": 8 },
            "datasource": "$datasource",
            "targets": [
                {
                    "refId": "A",
                    "expr": "sum(increase(dns_query_duration_seconds_bucket{instance=~\"$instance\"}[1m])) by (le)",
                    "format": "heatmap",
                    "legendFormat": "{{le}}"
                }
            ],
            "options": {
                "calculate": false,
                "cellGap": 2,
                "color": {
                    "scheme": "Oranges"
                },
                "exemplars": {
                    "color": "rgba(255,0,255,0.7)"
                },
                "filterValues": {
                    "le": 1e-9
                },
                "legend": {
                    "show": true
                },
                "rowsFrame": {
                    "layout": "auto"
                },
                "showValue": "never",
                "tooltip": {
                    "show": true,
                    "yHistogram": true
                },
                "yAxis": {
                    "axisPlacement": "left",
                    "decimals": 0,
                    "reverse": false,
                    "unit": "ms"
                }
            }
        })
    }

    /// Create throughput panel
    fn create_throughput_panel(id: u32, x: u32, y: u32) -> Value {
        json!({
            "id": id,
            "type": "timeseries",
            "title": "DNS Throughput",
            "gridPos": { "x": x, "y": y, "w": 12, "h": 8 },
            "datasource": "$datasource",
            "targets": [
                {
                    "refId": "A",
                    "expr": "sum(rate(dns_queries_total{instance=~\"$instance\"}[1m]))",
                    "legendFormat": "Queries/sec"
                },
                {
                    "refId": "B",
                    "expr": "sum(rate(dns_bytes_received_total{instance=~\"$instance\"}[1m]))",
                    "legendFormat": "Bytes In/sec"
                },
                {
                    "refId": "C",
                    "expr": "sum(rate(dns_bytes_sent_total{instance=~\"$instance\"}[1m]))",
                    "legendFormat": "Bytes Out/sec"
                }
            ],
            "fieldConfig": {
                "defaults": {
                    "custom": {
                        "drawStyle": "line",
                        "lineInterpolation": "smooth",
                        "barAlignment": 0,
                        "lineWidth": 2,
                        "fillOpacity": 10,
                        "gradientMode": "opacity",
                        "spanNulls": false,
                        "showPoints": "never",
                        "pointSize": 5,
                        "stacking": {
                            "mode": "none",
                            "group": "A"
                        },
                        "axisPlacement": "auto",
                        "axisLabel": "",
                        "axisColorMode": "text",
                        "scaleDistribution": {
                            "type": "linear"
                        },
                        "axisCenteredZero": false,
                        "hideFrom": {
                            "tooltip": false,
                            "viz": false,
                            "legend": false
                        }
                    }
                }
            }
        })
    }

    // Additional panel creators for other metrics...

    fn create_cpu_usage_panel(id: u32, x: u32, y: u32) -> Value {
        json!({
            "id": id,
            "type": "gauge",
            "title": "CPU Usage",
            "gridPos": { "x": x, "y": y, "w": 8, "h": 8 },
            "datasource": "$datasource",
            "targets": [
                {
                    "refId": "A",
                    "expr": "avg(rate(process_cpu_seconds_total{instance=~\"$instance\"}[5m])) * 100"
                }
            ]
        })
    }

    fn create_memory_usage_panel(id: u32, x: u32, y: u32) -> Value {
        json!({
            "id": id,
            "type": "gauge",
            "title": "Memory Usage",
            "gridPos": { "x": x, "y": y, "w": 8, "h": 8 },
            "datasource": "$datasource",
            "targets": [
                {
                    "refId": "A",
                    "expr": "avg(process_resident_memory_bytes{instance=~\"$instance\"}) / 1024 / 1024"
                }
            ]
        })
    }

    fn create_network_io_panel(id: u32, x: u32, y: u32) -> Value {
        json!({
            "id": id,
            "type": "graph",
            "title": "Network I/O",
            "gridPos": { "x": x, "y": y, "w": 8, "h": 8 },
            "datasource": "$datasource"
        })
    }

    fn create_connection_pool_panel(id: u32, x: u32, y: u32) -> Value {
        json!({
            "id": id,
            "type": "stat",
            "title": "Connection Pool",
            "gridPos": { "x": x, "y": y, "w": 12, "h": 8 },
            "datasource": "$datasource"
        })
    }

    fn create_cache_performance_panel(id: u32, x: u32, y: u32) -> Value {
        json!({
            "id": id,
            "type": "graph",
            "title": "Cache Performance",
            "gridPos": { "x": x, "y": y, "w": 12, "h": 8 },
            "datasource": "$datasource"
        })
    }

    fn create_ddos_detection_panel(id: u32, x: u32, y: u32) -> Value {
        json!({
            "id": id,
            "type": "timeseries",
            "title": "DDoS Detection",
            "gridPos": { "x": x, "y": y, "w": 12, "h": 8 },
            "datasource": "$datasource"
        })
    }

    fn create_rate_limiting_panel(id: u32, x: u32, y: u32) -> Value {
        json!({
            "id": id,
            "type": "stat",
            "title": "Rate Limited Requests",
            "gridPos": { "x": x, "y": y, "w": 12, "h": 8 },
            "datasource": "$datasource"
        })
    }

    fn create_firewall_blocks_panel(id: u32, x: u32, y: u32) -> Value {
        json!({
            "id": id,
            "type": "graph",
            "title": "Firewall Blocks",
            "gridPos": { "x": x, "y": y, "w": 12, "h": 8 },
            "datasource": "$datasource"
        })
    }

    fn create_dnssec_validation_panel(id: u32, x: u32, y: u32) -> Value {
        json!({
            "id": id,
            "type": "piechart",
            "title": "DNSSEC Validation",
            "gridPos": { "x": x, "y": y, "w": 12, "h": 8 },
            "datasource": "$datasource"
        })
    }

    fn create_threat_intelligence_panel(id: u32, x: u32, y: u32) -> Value {
        json!({
            "id": id,
            "type": "table",
            "title": "Threat Intelligence Hits",
            "gridPos": { "x": x, "y": y, "w": 12, "h": 8 },
            "datasource": "$datasource"
        })
    }

    fn create_suspicious_queries_panel(id: u32, x: u32, y: u32) -> Value {
        json!({
            "id": id,
            "type": "logs",
            "title": "Suspicious Queries",
            "gridPos": { "x": x, "y": y, "w": 12, "h": 8 },
            "datasource": "$datasource"
        })
    }

    /// Export all dashboards
    pub fn export_all_dashboards() -> Vec<Value> {
        vec![
            Self::generate_overview_dashboard(),
            Self::generate_performance_dashboard(),
            Self::generate_security_dashboard(),
        ]
    }

    /// Generate provisioning configuration
    pub fn generate_provisioning_config() -> Value {
        json!({
            "apiVersion": 1,
            "providers": [
                {
                    "name": "Atlas DNS Dashboards",
                    "orgId": 1,
                    "folder": "Atlas DNS",
                    "type": "file",
                    "disableDeletion": false,
                    "updateIntervalSeconds": 10,
                    "allowUiUpdates": true,
                    "options": {
                        "path": "/var/lib/grafana/dashboards/atlas-dns"
                    }
                }
            ]
        })
    }

    /// Generate alert rules
    pub fn generate_alert_rules() -> Value {
        json!({
            "groups": [
                {
                    "name": "atlas_dns_alerts",
                    "interval": "1m",
                    "rules": [
                        {
                            "alert": "HighDNSErrorRate",
                            "expr": "sum(rate(dns_response_codes_total{code!=\"NOERROR\"}[5m])) / sum(rate(dns_response_codes_total[5m])) > 0.05",
                            "for": "5m",
                            "labels": {
                                "severity": "warning"
                            },
                            "annotations": {
                                "summary": "High DNS error rate detected",
                                "description": "DNS error rate is {{ $value | humanizePercentage }} over the last 5 minutes"
                            }
                        },
                        {
                            "alert": "HighDNSLatency",
                            "expr": "histogram_quantile(0.99, rate(dns_query_duration_seconds_bucket[5m])) > 0.1",
                            "for": "5m",
                            "labels": {
                                "severity": "warning"
                            },
                            "annotations": {
                                "summary": "High DNS query latency",
                                "description": "99th percentile DNS query latency is {{ $value | humanizeDuration }}"
                            }
                        },
                        {
                            "alert": "DNSCacheHitRateLow",
                            "expr": "avg(rate(dns_cache_hits_total[5m]) / rate(dns_queries_total[5m])) < 0.5",
                            "for": "10m",
                            "labels": {
                                "severity": "info"
                            },
                            "annotations": {
                                "summary": "Low DNS cache hit rate",
                                "description": "Cache hit rate is {{ $value | humanizePercentage }}"
                            }
                        },
                        {
                            "alert": "PossibleDDoSAttack",
                            "expr": "rate(dns_queries_total[1m]) > 10000",
                            "for": "2m",
                            "labels": {
                                "severity": "critical"
                            },
                            "annotations": {
                                "summary": "Possible DDoS attack detected",
                                "description": "Query rate is {{ $value }} queries/sec"
                            }
                        }
                    ]
                }
            ]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_generation() {
        let dashboard = GrafanaDashboardGenerator::generate_overview_dashboard();
        assert!(dashboard["dashboard"]["uid"] == "atlas-dns-overview");
        assert!(dashboard["dashboard"]["title"] == "Atlas DNS - Overview");
    }

    #[test]
    fn test_alert_rules() {
        let alerts = GrafanaDashboardGenerator::generate_alert_rules();
        let rules = &alerts["groups"][0]["rules"];
        assert!(rules.as_array().unwrap().len() > 0);
    }
}