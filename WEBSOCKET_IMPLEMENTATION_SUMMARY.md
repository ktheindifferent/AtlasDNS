# WebSocket Implementation Summary

## Current State

The WebSocket module (`src/web/websocket.rs`) currently provides:

1. **WebSocket Handshake**: Properly handles the HTTP to WebSocket upgrade handshake according to RFC 6455
2. **Message Types**: Defines various WebSocket message types for metrics, query logs, security events, and system status
3. **Background Metrics**: Implements a background thread that periodically generates metrics updates
4. **Broadcast System**: Uses tokio's broadcast channel to distribute messages to subscribers
5. **Connection Tracking**: Basic infrastructure for tracking WebSocket connections

## Missing Functionality

The main TODO that needs to be addressed is implementing the "actual WebSocket server" functionality, which involves:

1. **Connection Handling**: After the HTTP handshake, taking control of the underlying TCP connection to process WebSocket frames
2. **Frame Parsing**: Implementing the WebSocket protocol to parse incoming frames (ping, pong, text, binary, close)
3. **Message Processing**: Handling incoming messages from clients (such as subscription updates)
4. **Connection Lifecycle**: Properly managing connection establishment, maintenance, and cleanup
5. **Error Handling**: Robust error handling for network issues, malformed frames, etc.

## Technical Challenges

The main challenge is that the current web server uses `tiny_http`, which:
- Doesn't expose the underlying TCP connection after the HTTP handshake
- Doesn't have built-in WebSocket support
- Makes it difficult to implement the low-level WebSocket protocol

## Recommended Solutions

### Option 1: Integrate with Existing Axum WebSocket Implementation
The project already has a working WebSocket implementation using axum in `src/metrics/streaming.rs`. This could be extended to handle the web UI WebSocket needs.

### Option 2: Custom TCP Connection Handling
Implement a solution that can take over the TCP connection from tiny_http after the handshake:
- Modify tiny_http or use a fork that exposes the underlying connection
- Implement the complete WebSocket RFC 6455 protocol
- Handle connection lifecycle, ping/pong, fragmentation, etc.

### Option 3: Hybrid Approach
Use tiny_http for regular HTTP requests and axum (or another framework) for WebSocket endpoints:
- Route `/api/websocket` to axum-based WebSocket handler
- Keep existing tiny_http routes unchanged
- Requires setting up multiple servers or a proxy

## Implementation Plan

To fully implement the WebSocket server:

1. **Choose Framework**: Decide whether to extend the existing axum implementation or build on tiny_http
2. **Connection Takeover**: Implement logic to take control of the TCP connection after handshake
3. **Protocol Implementation**: Implement WebSocket frame parsing and generation
4. **Message Routing**: Connect incoming WebSocket messages to the appropriate handlers
5. **Testing**: Add comprehensive tests for the WebSocket functionality
6. **Documentation**: Document the WebSocket API for client developers

## Dependencies

The project already includes necessary dependencies:
- `tokio-tungstenite` for WebSocket support
- `tokio` with full features for async runtime
- `serde` for message serialization
- `base64` and `sha1` for handshake processing

## Testing Considerations

- Unit tests for WebSocket frame encoding/decoding
- Integration tests for connection lifecycle
- Performance tests for high-concurrency scenarios
- Compatibility tests with different WebSocket clients