//! Test for WebSocket functionality

use atlas::web::websocket::{WebSocketManager, WebSocketMessage, SubscriptionFilter};
use atlas::dns::context::ServerContext;
use std::sync::Arc;
use tokio::sync::broadcast;

#[test]
fn test_websocket_manager_creation() {
    // Create a mock server context
    let context = Arc::new(ServerContext::test_context());
    
    // Create WebSocket manager
    let manager = WebSocketManager::new(context);
    
    // Verify it was created successfully
    assert_eq!(manager.active_connections(), 0);
}

#[test]
fn test_websocket_message_serialization() {
    use std::time::SystemTime;
    use serde_json;
    
    let message = WebSocketMessage::Metrics {
        timestamp: SystemTime::now(),
        data: atlas::web::websocket::MetricsData {
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
    let parsed: WebSocketMessage = serde_json::from_str(&json).unwrap();
    match parsed {
        WebSocketMessage::Metrics { data, .. } => {
            assert_eq!(data.total_queries, 1000);
            assert_eq!(data.cache_hit_rate, 0.75);
        }
        _ => panic!("Wrong message type"),
    }
}

#[test]
fn test_subscription_filter_default() {
    let filter = SubscriptionFilter::default();
    assert_eq!(filter.sample_rate, 1.0);
    assert!(filter.message_types.contains(&"metrics".to_string()));
    assert!(filter.message_types.contains(&"system_status".to_string()));
}