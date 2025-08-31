//! Real-time metrics streaming via WebSocket

use super::collector::MetricsSnapshot;
use tokio::sync::{broadcast, RwLock};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Metrics update message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsUpdate {
    pub timestamp: SystemTime,
    pub update_type: UpdateType,
    pub data: serde_json::Value,
}

/// Type of metrics update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpdateType {
    Snapshot,
    QueryMetric,
    SystemMetric,
    SecurityEvent,
    CacheHitRate,
    ResponseTimePercentiles,
}

/// Subscription filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionFilter {
    pub update_types: Vec<UpdateType>,
    pub sample_rate: f64, // 0.0 to 1.0
    pub domains: Option<Vec<String>>,
    pub client_ips: Option<Vec<String>>,
}

impl Default for SubscriptionFilter {
    fn default() -> Self {
        Self {
            update_types: vec![UpdateType::Snapshot],
            sample_rate: 1.0,
            domains: None,
            client_ips: None,
        }
    }
}

/// Metrics subscriber
pub struct MetricsSubscriber {
    id: String,
    filter: SubscriptionFilter,
    receiver: broadcast::Receiver<MetricsUpdate>,
}

impl MetricsSubscriber {
    /// Receive the next metrics update
    pub async fn recv(&mut self) -> Result<MetricsUpdate, broadcast::error::RecvError> {
        loop {
            let update = self.receiver.recv().await?;
            
            // Apply filter
            if self.should_receive(&update) {
                return Ok(update);
            }
        }
    }

    /// Check if this subscriber should receive the update
    fn should_receive(&self, update: &MetricsUpdate) -> bool {
        // Check update type
        if !self.filter.update_types.iter().any(|t| std::mem::discriminant(t) == std::mem::discriminant(&update.update_type)) {
            return false;
        }

        // Apply sampling
        if self.filter.sample_rate < 1.0 {
            let random: f64 = rand::random();
            if random > self.filter.sample_rate {
                return false;
            }
        }

        true
    }
}

/// Real-time metrics stream manager
pub struct MetricsStream {
    sender: broadcast::Sender<MetricsUpdate>,
    subscribers: Arc<RwLock<Vec<String>>>,
    backpressure_limit: usize,
}

impl MetricsStream {
    /// Create a new metrics stream
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(1000);
        Self {
            sender,
            subscribers: Arc::new(RwLock::new(Vec::new())),
            backpressure_limit: 100,
        }
    }

    /// Subscribe to metrics updates
    pub async fn subscribe(&self, filter: SubscriptionFilter) -> MetricsSubscriber {
        let id = uuid::Uuid::new_v4().to_string();
        let receiver = self.sender.subscribe();
        
        self.subscribers.write().await.push(id.clone());
        
        MetricsSubscriber {
            id,
            filter,
            receiver,
        }
    }

    /// Broadcast a metrics update
    pub async fn broadcast_update(&self, snapshot: &MetricsSnapshot) {
        let update = MetricsUpdate {
            timestamp: snapshot.timestamp,
            update_type: UpdateType::Snapshot,
            data: serde_json::to_value(snapshot).unwrap_or(serde_json::Value::Null),
        };

        // Check for backpressure
        if self.sender.receiver_count() > 0 && self.sender.len() < self.backpressure_limit {
            let _ = self.sender.send(update);
        }
    }

    /// Broadcast a specific metric update
    pub async fn broadcast_metric(&self, update_type: UpdateType, data: serde_json::Value) {
        let update = MetricsUpdate {
            timestamp: SystemTime::now(),
            update_type,
            data,
        };

        if self.sender.receiver_count() > 0 && self.sender.len() < self.backpressure_limit {
            let _ = self.sender.send(update);
        }
    }

    /// Get number of active subscribers
    pub async fn subscriber_count(&self) -> usize {
        self.subscribers.read().await.len()
    }

    /// Remove a subscriber
    pub async fn unsubscribe(&self, id: &str) {
        self.subscribers.write().await.retain(|s| s != id);
    }
}

/// WebSocket handler for metrics streaming
pub mod websocket {
    use super::*;
    use axum::{
        extract::{ws::{WebSocket, WebSocketUpgrade}, State},
        response::Response,
    };
    use std::sync::Arc;

    /// WebSocket state
    pub struct WebSocketState {
        pub stream: Arc<MetricsStream>,
    }

    /// Handle WebSocket upgrade request
    pub async fn handle_metrics_ws(
        ws: WebSocketUpgrade,
        State(state): State<Arc<WebSocketState>>,
    ) -> Response {
        ws.on_upgrade(move |socket| handle_socket(socket, state))
    }

    /// Handle WebSocket connection
    async fn handle_socket(mut socket: WebSocket, state: Arc<WebSocketState>) {
        // Default subscription
        let filter = SubscriptionFilter::default();
        let mut subscriber = state.stream.subscribe(filter).await;

        // Send updates to client
        loop {
            tokio::select! {
                // Receive metrics updates
                update = subscriber.recv() => {
                    match update {
                        Ok(update) => {
                            let msg = serde_json::to_string(&update).unwrap_or_default();
                            if socket.send(axum::extract::ws::Message::Text(msg)).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                
                // Handle client messages
                msg = socket.recv() => {
                    match msg {
                        Some(Ok(axum::extract::ws::Message::Text(text))) => {
                            // Parse subscription filter updates
                            if let Ok(new_filter) = serde_json::from_str::<SubscriptionFilter>(&text) {
                                subscriber.filter = new_filter;
                            }
                        }
                        Some(Ok(axum::extract::ws::Message::Close(_))) | None => break,
                        _ => {}
                    }
                }
            }
        }

        // Clean up
        state.stream.unsubscribe(&subscriber.id).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_stream() {
        let stream = MetricsStream::new();
        
        let filter = SubscriptionFilter::default();
        let mut subscriber = stream.subscribe(filter).await;
        
        assert_eq!(stream.subscriber_count().await, 1);
        
        // Broadcast an update
        let snapshot = MetricsSnapshot {
            timestamp: SystemTime::now(),
            query_count: 100,
            cache_hits: 70,
            cache_misses: 30,
            avg_response_time_ms: 15.0,
            unique_clients: 10,
            query_types: Default::default(),
            response_codes: Default::default(),
            protocols: Default::default(),
            top_domains: Vec::new(),
            system_metrics: super::super::collector::SystemMetricSnapshot {
                cpu_usage: 25.0,
                memory_usage_mb: 512,
                network_rx_bytes: 1000000,
                network_tx_bytes: 500000,
                active_connections: 50,
                cache_entries: 1000,
            },
        };
        
        stream.broadcast_update(&snapshot).await;
        
        // Receive the update
        let update = subscriber.recv().await.unwrap();
        assert!(matches!(update.update_type, UpdateType::Snapshot));
    }

    #[tokio::test]
    async fn test_subscription_filter() {
        let filter = SubscriptionFilter {
            update_types: vec![UpdateType::QueryMetric],
            sample_rate: 0.5,
            domains: Some(vec!["example.com".to_string()]),
            client_ips: None,
        };
        
        assert_eq!(filter.update_types.len(), 1);
        assert_eq!(filter.sample_rate, 0.5);
    }
}