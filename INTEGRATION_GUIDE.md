# Atlas DNS Server - Enhancement Integration Guide

This guide demonstrates how to integrate the new error handling, rate limiting, and health monitoring features into the Atlas DNS server.

## 🚀 Quick Start

### 1. Update Dependencies

Add the following to your `Cargo.toml`:

```toml
[dependencies]
parking_lot = "0.12"
tokio = { version = "1.0", features = ["full"] }
prometheus = "0.13"  # Optional: for metrics
```

### 2. Import New Modules

```rust
use atlas::dns::errors::{DnsError, DnsResult};
use atlas::dns::rate_limit::{RateLimiter, RateLimitConfig};
use atlas::dns::health::{HealthMonitor, health_check_response};
```

## 📝 Integration Examples

### Enhanced Error Handling

Replace generic error handling with contextual errors:

```rust
// Before:
socket.bind(addr).map_err(|e| ServerError::Io(e))?;

// After:
socket.bind(addr).map_err(|e| {
    DnsError::Network(NetworkError {
        kind: NetworkErrorKind::BindFailed,
        endpoint: Some(addr.to_string()),
        retry_after: None,
        source: Some(e),
    })
})?;
```

### Rate Limiting Integration

Add rate limiting to your DNS server:

```rust
// In your server initialization
let rate_config = RateLimitConfig {
    client_limit: 100,
    client_window: Duration::from_secs(1),
    global_limit: 10000,
    global_window: Duration::from_secs(1),
    adaptive: true,
    cleanup_interval: Duration::from_secs(60),
};
let rate_limiter = Arc::new(RateLimiter::new(rate_config));

// In your query handler
fn handle_query(client_addr: SocketAddr, packet: &[u8]) -> Result<Vec<u8>> {
    // Check rate limits
    if let Err(e) = rate_limiter.check_allowed(client_addr.ip()) {
        log::warn!("Rate limit exceeded for {}: {}", client_addr, e);
        return create_refused_response(packet);
    }
    
    // Record the query
    rate_limiter.record_query(client_addr.ip());
    
    // Process normally...
}
```

### Health Monitoring Integration

Add health checks to your server:

```rust
// Initialize health monitor
let health_monitor = Arc::new(HealthMonitor::new());

// In your main server loop
health_monitor.set_ready(true);

// Record metrics
match process_query(packet) {
    Ok(response) => {
        health_monitor.record_query_success(start_time.elapsed());
        Ok(response)
    }
    Err(e) => {
        health_monitor.record_query_failure();
        Err(e)
    }
}

// Add HTTP health endpoint
fn handle_health_check(monitor: &HealthMonitor, cache_size: usize) -> Response {
    let (status_code, body) = health_check_response(monitor, cache_size);
    Response::from_string(body)
        .with_status_code(status_code)
        .with_header("Content-Type", "application/json")
}
```

## 🔧 Complete Server Example

Here's a complete example integrating all features:

```rust
use std::sync::Arc;
use std::net::UdpSocket;
use atlas::dns::{
    errors::{DnsError, DnsResult},
    rate_limit::{RateLimiter, RateLimitConfig},
    health::HealthMonitor,
    server::DnsServer,
    context::ServerContext,
};

pub struct ImprovedDnsServer {
    context: Arc<ServerContext>,
    rate_limiter: Arc<RateLimiter>,
    health_monitor: Arc<HealthMonitor>,
}

impl ImprovedDnsServer {
    pub fn new() -> DnsResult<Self> {
        let context = Arc::new(ServerContext::new()?);
        
        let rate_config = RateLimitConfig::default();
        let rate_limiter = Arc::new(RateLimiter::new(rate_config));
        
        let health_monitor = Arc::new(HealthMonitor::new());
        
        Ok(ImprovedDnsServer {
            context,
            rate_limiter,
            health_monitor,
        })
    }
    
    pub fn run(&self) -> DnsResult<()> {
        // Mark as ready
        self.health_monitor.set_ready(true);
        
        // Bind socket with better error handling
        let socket = UdpSocket::bind(("0.0.0.0", 53))
            .map_err(|e| DnsError::from(e))?;
        
        log::info!("DNS server started on port 53");
        
        loop {
            let mut buf = [0u8; 4096];
            
            match socket.recv_from(&mut buf) {
                Ok((len, src)) => {
                    let start = std::time::Instant::now();
                    
                    // Check rate limits
                    if let Err(e) = self.rate_limiter.check_allowed(src.ip()) {
                        log::warn!("Rate limited: {}", e);
                        self.health_monitor.record_query_failure();
                        continue;
                    }
                    
                    // Record query
                    self.rate_limiter.record_query(src.ip());
                    
                    // Process query (simplified)
                    match self.process_query(&buf[..len]) {
                        Ok(response) => {
                            socket.send_to(&response, src)?;
                            self.health_monitor.record_query_success(start.elapsed());
                        }
                        Err(e) => {
                            log::error!("Query failed: {}", e);
                            self.health_monitor.record_query_failure();
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Non-blocking socket, continue
                    continue;
                }
                Err(e) => {
                    log::error!("Socket error: {}", e);
                    self.health_monitor.set_healthy(false);
                    return Err(DnsError::from(e));
                }
            }
        }
    }
    
    fn process_query(&self, data: &[u8]) -> DnsResult<Vec<u8>> {
        // Your query processing logic here
        todo!()
    }
}
```

## 🌐 HTTP Health Endpoints

Add HTTP endpoints for health monitoring:

```rust
use tiny_http::{Server, Response};

fn start_health_server(monitor: Arc<HealthMonitor>) {
    let server = Server::http("0.0.0.0:8080").unwrap();
    
    for request in server.incoming_requests() {
        let response = match request.url() {
            "/health" => {
                let (status, body) = health_check_response(&monitor, 0);
                Response::from_string(body).with_status_code(status)
            }
            "/ready" => {
                let (status, body) = readiness_probe(&monitor);
                Response::from_string(body).with_status_code(status)
            }
            "/live" => {
                let (status, body) = liveness_probe(&monitor);
                Response::from_string(body).with_status_code(status)
            }
            _ => Response::from_string("Not Found").with_status_code(404)
        };
        
        let _ = request.respond(response);
    }
}
```

## 📊 Monitoring Dashboard

Example health check response:

```json
{
  "status": "healthy",
  "uptime_seconds": 3600,
  "queries_total": 150000,
  "queries_failed": 12,
  "cache_size": 5000,
  "cache_hit_rate": 0.85,
  "latency_ms": {
    "p50": 2.5,
    "p90": 8.3,
    "p99": 25.1,
    "mean": 4.2
  },
  "checks": [
    {
      "name": "upstream_dns",
      "status": "pass",
      "message": "Upstream DNS servers reachable"
    },
    {
      "name": "memory",
      "status": "pass",
      "message": "Memory usage within limits"
    },
    {
      "name": "error_rate",
      "status": "pass",
      "message": "Error rate normal: 0.01%"
    }
  ]
}
```

## 🔍 Testing the Enhancements

### Rate Limiting Test

```bash
# Test rate limiting with parallel queries
for i in {1..200}; do
  dig @localhost example.com &
done

# Check server logs for rate limiting messages
```

### Health Check Test

```bash
# Check health endpoint
curl http://localhost:8080/health

# Check readiness
curl http://localhost:8080/ready

# Check liveness
curl http://localhost:8080/live
```

### Error Recovery Test

```bash
# Send malformed packet
echo -n "invalid_dns_packet" | nc -u localhost 53

# Server should log error but continue running
```

## 🚦 Production Deployment

### Environment Variables

```bash
# Rate limiting configuration
export DNS_RATE_LIMIT_CLIENT=100
export DNS_RATE_LIMIT_GLOBAL=10000
export DNS_RATE_LIMIT_ADAPTIVE=true

# Health check configuration
export DNS_HEALTH_PORT=8080
export DNS_HEALTH_INTERVAL=30

# Error handling
export DNS_MAX_RETRIES=3
export DNS_RETRY_BACKOFF=exponential
```

### Docker Integration

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
COPY --from=builder /app/target/release/atlas /usr/local/bin/
EXPOSE 53/udp 53/tcp 8080/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

CMD ["atlas"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: atlas-dns
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: atlas
        image: atlas-dns:latest
        ports:
        - containerPort: 53
          protocol: UDP
        - containerPort: 53
          protocol: TCP
        - containerPort: 8080
          protocol: TCP
        livenessProbe:
          httpGet:
            path: /live
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5
        resources:
          limits:
            memory: "1Gi"
            cpu: "1000m"
          requests:
            memory: "256Mi"
            cpu: "250m"
```

## 📈 Metrics and Observability

### Prometheus Integration

```rust
use prometheus::{Counter, Histogram, register_counter, register_histogram};

lazy_static! {
    static ref DNS_QUERIES_TOTAL: Counter = register_counter!(
        "dns_queries_total",
        "Total number of DNS queries received"
    ).unwrap();
    
    static ref DNS_QUERY_DURATION: Histogram = register_histogram!(
        "dns_query_duration_seconds",
        "DNS query processing duration"
    ).unwrap();
}

// In your query handler
DNS_QUERIES_TOTAL.inc();
let timer = DNS_QUERY_DURATION.start_timer();
// ... process query ...
timer.observe_duration();
```

### Grafana Dashboard

Create dashboards to visualize:
- Query rate and trends
- Error rates and types
- Cache hit ratio
- Response time percentiles
- Rate limiting triggers
- Health check status

## 🔒 Security Best Practices

1. **Rate Limiting**: Always enforce rate limits in production
2. **Input Validation**: Validate all DNS queries before processing
3. **Resource Limits**: Set maximum memory and CPU limits
4. **Monitoring**: Alert on unusual patterns or high error rates
5. **Logging**: Log all security-relevant events
6. **Updates**: Keep dependencies updated for security patches

## 📚 Additional Resources

- [DNS RFC Standards](https://www.ietf.org/standards/rfcs/)
- [DNSSEC Implementation Guide](https://www.dnssec-tools.org/)
- [DNS Performance Best Practices](https://www.dns-oarc.net/)
- [Security Considerations for DNS](https://www.rfc-editor.org/rfc/rfc3833.html)

## 🤝 Contributing

To contribute enhancements:
1. Follow the error handling patterns in `src/dns/errors.rs`
2. Add appropriate health checks for new features
3. Include rate limiting for new query types
4. Write comprehensive tests
5. Update documentation

## 📄 License

This enhancement guide is part of the Atlas DNS server project.