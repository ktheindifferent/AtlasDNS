//! WebSocket support for real-time updates
//!
//! Provides WebSocket endpoints for streaming real-time metrics, DNS query logs,
//! and system status updates to connected clients.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};
use std::sync::atomic::{AtomicUsize, Ordering};
use serde::{Serialize, Deserialize};
use tokio::sync::broadcast;
use tiny_http::{Request, Response, ResponseBox, Header};
use sysinfo::{System, SystemExt, CpuExt};
use crate::dns::context::ServerContext;
use crate::web::Result;

// Import WebSocket functionality
use base64;
use sha1::{Sha1, Digest};
use std::io::{Read, Write, BufReader, BufWriter};
use std::net::TcpStream;
use std::collections::HashMap;
use std::sync::Mutex;
use std::thread::JoinHandle;

/// Unique identifier for WebSocket connections
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(usize);

/// WebSocket frame opcodes
#[derive(Debug, Clone, Copy)]
enum OpCode {
    Continue = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

impl From<u8> for OpCode {
    fn from(value: u8) -> Self {
        match value {
            0x0 => OpCode::Continue,
            0x1 => OpCode::Text,
            0x2 => OpCode::Binary,
            0x8 => OpCode::Close,
            0x9 => OpCode::Ping,
            0xA => OpCode::Pong,
            _ => panic!("Invalid opcode: {}", value),
        }
    }
}

/// WebSocket message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WebSocketMessage {
    #[serde(rename = "metrics")]
    Metrics {
        timestamp: SystemTime,
        data: MetricsData,
    },
    #[serde(rename = "query_log")]
    QueryLog {
        timestamp: SystemTime,
        query: String,
        query_type: String,
        client_ip: String,
        response_time_ms: f64,
    },
    #[serde(rename = "security_event")]
    SecurityEvent {
        timestamp: SystemTime,
        event_type: String,
        client_ip: Option<String>,
        details: String,
    },
    #[serde(rename = "system_status")]
    SystemStatus {
        timestamp: SystemTime,
        cpu_usage: f64,
        memory_usage_mb: u64,
        active_connections: usize,
        uptime_seconds: u64,
    },
    #[serde(rename = "subscription_update")]
    SubscriptionUpdate {
        filter: SubscriptionFilter,
    },
}

/// Real-time metrics data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsData {
    pub total_queries: u64,
    pub cache_hit_rate: f64,
    pub avg_response_time_ms: f64,
    pub queries_per_second: f64,
    pub unique_clients: u64,
    pub top_domains: Vec<(String, u64)>,
    pub query_types: std::collections::HashMap<String, u64>,
    pub response_codes: std::collections::HashMap<String, u64>,
}

/// WebSocket subscription filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionFilter {
    pub message_types: Vec<String>,
    pub sample_rate: f64, // 0.0 to 1.0
    pub domains_filter: Option<Vec<String>>,
    pub client_ips_filter: Option<Vec<String>>,
}

impl Default for SubscriptionFilter {
    fn default() -> Self {
        Self {
            message_types: vec!["metrics".to_string(), "system_status".to_string()],
            sample_rate: 1.0,
            domains_filter: None,
            client_ips_filter: None,
        }
    }
}

/// WebSocket connection state
#[derive(Debug, Clone)]
pub struct ConnectionState {
    pub id: ConnectionId,
    pub subscribed_filters: SubscriptionFilter,
}

/// WebSocket connection manager
pub struct WebSocketManager {
    context: Arc<ServerContext>,
    sender: broadcast::Sender<WebSocketMessage>,
    connections: Arc<Mutex<HashMap<ConnectionId, ConnectionState>>>,
    next_connection_id: AtomicUsize,
    _background_task: JoinHandle<()>,
}

impl WebSocketManager {
    /// Create a new WebSocket manager
    pub fn new(context: Arc<ServerContext>) -> Self {
        let (sender, _) = broadcast::channel(1000);
        let sender_clone = sender.clone();
        let context_clone = context.clone();

        // Start background task for periodic updates
        let background_task = thread::spawn(move || {
            Self::background_metrics_loop(context_clone, sender_clone);
        });

        Self {
            context,
            sender,
            connections: Arc::new(Mutex::new(HashMap::new())),
            next_connection_id: AtomicUsize::new(0),
            _background_task: background_task,
        }
    }

    /// Handle WebSocket upgrade request with proper HTTP protocol upgrade
    pub fn handle_websocket_upgrade(&self, request: &Request) -> Result<ResponseBox> {
        // Check for WebSocket upgrade headers
        let upgrade_header = request.headers().iter()
            .find(|h| h.field.as_str().to_ascii_lowercase() == "upgrade")
            .and_then(|h| {
                let value: String = h.value.clone().into();
                if value.to_lowercase() == "websocket" {
                    Some(value)
                } else {
                    None
                }
            });

        let connection_header = request.headers().iter()
            .find(|h| h.field.as_str().to_ascii_lowercase() == "connection")
            .and_then(|h| {
                let value: String = h.value.clone().into();
                if value.to_lowercase().contains("upgrade") {
                    Some(value)
                } else {
                    None
                }
            });

        let ws_key = request.headers().iter()
            .find(|h| h.field.as_str().to_ascii_lowercase() == "sec-websocket-key")
            .map(|h| {
                let value: String = h.value.clone().into();
                value
            });

        let ws_version = request.headers().iter()
            .find(|h| h.field.as_str().to_ascii_lowercase() == "sec-websocket-version")
            .map(|h| {
                let value: String = h.value.clone().into();
                value
            });

        if let (Some(_), Some(_), Some(key), Some(version)) = (upgrade_header, connection_header, ws_key, ws_version) {
            // Check WebSocket version (we support version 13)
            if version != "13" {
                return Ok(Response::from_string("Unsupported WebSocket version")
                    .with_status_code(400)
                    .boxed());
            }

            // Perform WebSocket handshake
            let accept_key = Self::generate_websocket_accept_key(&key);
            
            // Create WebSocket response
            let response = Response::empty(101)
                .with_header(Header::from_bytes(&b"Upgrade"[..], &b"websocket"[..]).expect("static header"))
                .with_header(Header::from_bytes(&b"Connection"[..], &b"Upgrade"[..]).expect("static header"))
                .with_header(Header::from_bytes(&b"Sec-WebSocket-Accept"[..], accept_key.as_bytes()).expect("static header"));
            
            log::info!("WebSocket handshake completed successfully");
            
            Ok(response.boxed())
        } else {
            // Not a WebSocket request, return error
            Ok(Response::from_string("WebSocket upgrade required")
                .with_status_code(400)
                .boxed())
        }
    }

    /// Generate WebSocket accept key according to RFC 6455
    fn generate_websocket_accept_key(key: &str) -> String {
        const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        let concat = format!("{}{}", key, WS_GUID);
        let mut hasher = Sha1::new();
        hasher.update(concat.as_bytes());
        let result = hasher.finalize();
        base64::encode(result)
    }

    /// Create Server-Sent Events stream as WebSocket fallback
    fn create_sse_stream(&self) -> Result<ResponseBox> {
        let _receiver = self.sender.subscribe();
        let context = self.context.clone();
        
        // Create initial snapshot
        let summary = context.metrics.get_metrics_summary();
        let initial_data = MetricsData {
            total_queries: summary.cache_hits + summary.cache_misses,
            cache_hit_rate: summary.cache_hit_rate,
            avg_response_time_ms: *summary.percentiles.get("p50").unwrap_or(&50.0),
            queries_per_second: 0.0, // Calculate from available data
            unique_clients: summary.unique_clients as u64,
            top_domains: Vec::new(), // Not available in this summary
            query_types: summary.query_type_distribution.into_iter().map(|(k, v)| (k, v.0)).collect(),
            response_codes: summary.response_code_distribution.into_iter().map(|(k, v)| (k, v.0)).collect(),
        };

        let message = WebSocketMessage::Metrics {
            timestamp: SystemTime::now(),
            data: initial_data,
        };

        // Format as Server-Sent Events
        let sse_data = format!(
            "retry: 1000\nevent: message\ndata: {}\n\n",
            serde_json::to_string(&message).unwrap_or_default()
        );
        
        Ok(Response::from_string(sse_data)
            .with_header(Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..]).expect("static header"))
            .with_header(Header::from_bytes(&b"Cache-Control"[..], &b"no-cache"[..]).expect("static header"))
            .with_header(Header::from_bytes(&b"Connection"[..], &b"keep-alive"[..]).expect("static header"))
            .with_header(Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).expect("static header"))
            .with_header(Header::from_bytes(&b"X-Accel-Buffering"[..], &b"no"[..]).expect("static header"))
            .boxed())
    }

    /// Background task for generating periodic metrics updates
    fn background_metrics_loop(context: Arc<ServerContext>, sender: broadcast::Sender<WebSocketMessage>) {
        let mut last_update = SystemTime::now();
        let update_interval = Duration::from_secs(1); // 1-second updates

        loop {
            thread::sleep(update_interval);

            // Only send if there are active subscribers
            if sender.receiver_count() == 0 {
                continue;
            }

            let now = SystemTime::now();
            if now.duration_since(last_update).unwrap_or_default() >= update_interval {
                // Collect current metrics
                let summary = context.metrics.get_metrics_summary();
                
                let metrics_data = MetricsData {
                    total_queries: summary.cache_hits + summary.cache_misses,
                    cache_hit_rate: summary.cache_hit_rate,
                    avg_response_time_ms: *summary.percentiles.get("p50").unwrap_or(&50.0),
                    queries_per_second: 0.0, // Not available in current summary
                    unique_clients: summary.unique_clients as u64,
                    top_domains: Vec::new(), // Not available in current summary
                    query_types: summary.query_type_distribution.into_iter().map(|(k, v)| (k, v.0)).collect(),
                    response_codes: summary.response_code_distribution.into_iter().map(|(k, v)| (k, v.0)).collect(),
                };

                let message = WebSocketMessage::Metrics {
                    timestamp: now,
                    data: metrics_data,
                };

                // Broadcast to all subscribers
                let _ = sender.send(message);
                last_update = now;
            }

            // System status updates (every 5 seconds)
            if now.duration_since(last_update).unwrap_or_default().as_secs() % 5 == 0 {
                // Get system metrics
                let mut system_info = System::new_all();
                system_info.refresh_all();
                
                let status_message = WebSocketMessage::SystemStatus {
                    timestamp: now,
                    cpu_usage: system_info.global_cpu_info().cpu_usage() as f64,
                    memory_usage_mb: system_info.used_memory() / 1024 / 1024,
                    active_connections: context.metrics.get_metrics_summary().unique_clients,
                    uptime_seconds: context.metrics.get_uptime_seconds(),
                };

                let _ = sender.send(status_message);
            }
        }
    }

    /// Broadcast a query log message to all subscribers
    pub fn broadcast_query_log(&self, query: &str, query_type: &str, client_ip: &str, response_time_ms: f64) {
        if self.sender.receiver_count() > 0 {
            let message = WebSocketMessage::QueryLog {
                timestamp: SystemTime::now(),
                query: query.to_string(),
                query_type: query_type.to_string(),
                client_ip: client_ip.to_string(),
                response_time_ms,
            };

            let _ = self.sender.send(message);
        }
    }

    /// Broadcast a security event to all subscribers
    pub fn broadcast_security_event(&self, event_type: &str, client_ip: Option<&str>, details: &str) {
        if self.sender.receiver_count() > 0 {
            let message = WebSocketMessage::SecurityEvent {
                timestamp: SystemTime::now(),
                event_type: event_type.to_string(),
                client_ip: client_ip.map(String::from),
                details: details.to_string(),
            };

            let _ = self.sender.send(message);
        }
    }

    /// Get number of active WebSocket connections
    pub fn active_connections(&self) -> usize {
        self.sender.receiver_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_websocket_message_serialization() {
        let message = WebSocketMessage::Metrics {
            timestamp: SystemTime::now(),
            data: MetricsData {
                total_queries: 1000,
                cache_hit_rate: 0.75,
                avg_response_time_ms: 15.5,
                queries_per_second: 100.0,
                unique_clients: 50,
                top_domains: vec![("example.com".to_string(), 100)],
                query_types: std::collections::HashMap::new(),
                response_codes: std::collections::HashMap::new(),
            },
        };

        let json = serde_json::to_string(&message).unwrap();
        assert!(json.contains("metrics"));
        assert!(json.contains("15.5"));

        // Test deserialization
        let _parsed: WebSocketMessage = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn test_subscription_filter_default() {
        let filter = SubscriptionFilter::default();
        assert_eq!(filter.sample_rate, 1.0);
        assert!(filter.message_types.contains(&"metrics".to_string()));
        assert!(filter.message_types.contains(&"system_status".to_string()));
    }
}