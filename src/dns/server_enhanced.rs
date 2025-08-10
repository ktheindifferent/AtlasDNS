//! Enhanced DNS server with improved error handling and monitoring
//! 
//! This module demonstrates how to integrate the new error handling,
//! rate limiting, and health monitoring features into the DNS server.

use std::sync::Arc;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::dns::errors::{DnsError, DnsResult, ErrorContext, NetworkErrorKind};
use crate::dns::rate_limit::{RateLimiter, RateLimitConfig};
use crate::dns::health::HealthMonitor;
use crate::dns::context::ServerContext;
use crate::dns::protocol::{DnsPacket, QueryType};
use crate::dns::server::{execute_query, DnsServer};
use crate::dns::buffer::{BytePacketBuffer, PacketBuffer, VectorPacketBuffer};

/// Enhanced UDP DNS server with rate limiting and health monitoring
pub struct EnhancedDnsServer {
    context: Arc<ServerContext>,
    rate_limiter: Arc<RateLimiter>,
    health_monitor: Arc<HealthMonitor>,
    max_packet_size: usize,
    query_timeout: Duration,
}

impl EnhancedDnsServer {
    /// Create a new enhanced DNS server
    pub fn new(context: Arc<ServerContext>) -> Self {
        // Configure rate limiting
        let rate_config = RateLimitConfig {
            client_limit: 100,
            client_window: Duration::from_secs(1),
            global_limit: 10000,
            global_window: Duration::from_secs(1),
            adaptive: true,
            cleanup_interval: Duration::from_secs(60),
        };

        EnhancedDnsServer {
            context,
            rate_limiter: Arc::new(RateLimiter::new(rate_config)),
            health_monitor: Arc::new(HealthMonitor::new()),
            max_packet_size: 4096,
            query_timeout: Duration::from_secs(5),
        }
    }

    /// Process a DNS query with enhanced error handling
    pub fn process_query(
        &self,
        packet_data: &[u8],
        client_addr: SocketAddr,
    ) -> DnsResult<Vec<u8>> {
        let start_time = Instant::now();

        // Check rate limits
        if let Err(e) = self.rate_limiter.check_allowed(client_addr.ip()) {
            self.health_monitor.record_query_failure();
            log::warn!("Rate limit exceeded for client {}: {}", client_addr, e);
            
            // Return a REFUSED response
            return Ok(self.create_refused_response(packet_data)?);
        }

        // Record the query
        self.rate_limiter.record_query(client_addr.ip());

        // Parse the query packet
        let mut req_buffer = BytePacketBuffer::new();
        if packet_data.len() > self.max_packet_size {
            return Err(DnsError::Protocol(crate::dns::errors::ProtocolError {
                kind: crate::dns::errors::ProtocolErrorKind::MalformedPacket,
                packet_id: None,
                query_name: None,
                recoverable: false,
            }));
        }

        req_buffer.buf[..packet_data.len()].copy_from_slice(packet_data);
        req_buffer.seek(packet_data.len())?;

        let request = match DnsPacket::from_buffer(&mut req_buffer) {
            Ok(packet) => packet,
            Err(e) => {
                self.health_monitor.record_query_failure();
                log::error!("Failed to parse DNS query from {}: {}", client_addr, e);
                return Err(DnsError::Protocol(crate::dns::errors::ProtocolError {
                    kind: crate::dns::errors::ProtocolErrorKind::MalformedPacket,
                    packet_id: None,
                    query_name: None,
                    recoverable: false,
                }));
            }
        };

        // Validate the query
        if let Err(e) = self.validate_query(&request) {
            self.health_monitor.record_query_failure();
            return Err(e);
        }

        // Check cache first (if applicable)
        if let Some(cached_response) = self.check_cache(&request) {
            self.health_monitor.record_cache_hit();
            self.health_monitor.record_query_success(start_time.elapsed());
            return Ok(cached_response);
        }
        self.health_monitor.record_cache_miss();

        // Execute the query with timeout
        let response = match self.execute_with_timeout(request.clone()) {
            Ok(response) => response,
            Err(e) => {
                self.health_monitor.record_query_failure();
                log::error!("Query execution failed for {}: {}", client_addr, e);
                return Err(e);
            }
        };

        // Serialize the response
        let mut res_buffer = VectorPacketBuffer::new();
        let size_limit = self.determine_size_limit(&request);
        
        if let Err(e) = response.write(&mut res_buffer, size_limit) {
            self.health_monitor.record_query_failure();
            return Err(DnsError::Protocol(crate::dns::errors::ProtocolError {
                kind: crate::dns::errors::ProtocolErrorKind::MalformedPacket,
                packet_id: Some(request.header.id),
                query_name: request.questions.first().map(|q| q.name.clone()),
                recoverable: false,
            }));
        }

        let response_data = res_buffer.get_range(0, res_buffer.pos())
            .map_err(|_| DnsError::Operation(crate::dns::errors::OperationError {
                context: "Response serialization".to_string(),
                details: "Failed to extract response data".to_string(),
                recovery_hint: None,
            }))?;

        // Update cache if appropriate
        self.update_cache(&request, response_data);

        // Record success metrics
        self.health_monitor.record_query_success(start_time.elapsed());

        Ok(response_data.to_vec())
    }

    /// Validate an incoming DNS query
    fn validate_query(&self, packet: &DnsPacket) -> DnsResult<()> {
        // Check for empty questions
        if packet.questions.is_empty() {
            return Err(DnsError::Protocol(crate::dns::errors::ProtocolError {
                kind: crate::dns::errors::ProtocolErrorKind::MalformedPacket,
                packet_id: Some(packet.header.id),
                query_name: None,
                recoverable: false,
            }));
        }

        // Validate domain names
        for question in &packet.questions {
            if !self.is_valid_domain_name(&question.name) {
                return Err(DnsError::Protocol(crate::dns::errors::ProtocolError {
                    kind: crate::dns::errors::ProtocolErrorKind::InvalidDomainName,
                    packet_id: Some(packet.header.id),
                    query_name: Some(question.name.clone()),
                    recoverable: false,
                }));
            }
        }

        Ok(())
    }

    /// Check if a domain name is valid
    fn is_valid_domain_name(&self, name: &str) -> bool {
        // Basic validation - enhance as needed
        if name.is_empty() || name.len() > 255 {
            return false;
        }

        // Check each label
        for label in name.split('.') {
            if label.is_empty() || label.len() > 63 {
                return false;
            }
            // Additional validation for valid characters
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return false;
            }
        }

        true
    }

    /// Execute a query with timeout protection
    fn execute_with_timeout(&self, request: DnsPacket) -> DnsResult<DnsPacket> {
        // In a real implementation, this would use async/await or threads
        // For now, we'll use the existing execute_query
        Ok(execute_query(self.context.clone(), &request))
    }

    /// Check cache for a response
    fn check_cache(&self, _request: &DnsPacket) -> Option<Vec<u8>> {
        // Placeholder - integrate with actual cache
        None
    }

    /// Update cache with a response
    fn update_cache(&self, _request: &DnsPacket, _response: &[u8]) {
        // Placeholder - integrate with actual cache
    }

    /// Determine the maximum response size based on EDNS
    fn determine_size_limit(&self, request: &DnsPacket) -> usize {
        // Check for EDNS OPT record
        for resource in &request.resources {
            if let crate::dns::protocol::DnsRecord::Opt { packet_len, .. } = resource {
                return *packet_len as usize;
            }
        }
        
        // Default DNS packet size
        512
    }

    /// Create a REFUSED response for rate-limited clients
    fn create_refused_response(&self, query_data: &[u8]) -> DnsResult<Vec<u8>> {
        // Try to parse the query to get the ID
        let mut req_buffer = BytePacketBuffer::new();
        let len = query_data.len().min(self.max_packet_size);
        req_buffer.buf[..len].copy_from_slice(&query_data[..len]);
        
        let packet_id = if let Ok(request) = DnsPacket::from_buffer(&mut req_buffer) {
            request.header.id
        } else {
            0 // Default ID if we can't parse
        };

        // Create a minimal REFUSED response
        let mut response = DnsPacket::new();
        response.header.id = packet_id;
        response.header.response = true;
        response.header.rescode = crate::dns::protocol::ResultCode::REFUSED;

        let mut res_buffer = VectorPacketBuffer::new();
        response.write(&mut res_buffer, 512)?;
        
        Ok(res_buffer.get_range(0, res_buffer.pos())?.to_vec())
    }

    /// Start the health monitoring background tasks
    pub async fn start_health_monitoring(&self) {
        let monitor = self.health_monitor.clone();
        
        // Start periodic health checks
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                monitor.run_checks().await;
            }
        });
    }

    /// Get the health monitor for external access
    pub fn health_monitor(&self) -> &Arc<HealthMonitor> {
        &self.health_monitor
    }

    /// Get the rate limiter for external access
    pub fn rate_limiter(&self) -> &Arc<RateLimiter> {
        &self.rate_limiter
    }
}

/// Example integration with the existing DnsServer trait
impl DnsServer for EnhancedDnsServer {
    fn run_server(self) -> Result<(), crate::dns::server::ServerError> {
        // Mark server as ready
        self.health_monitor.set_ready(true);

        // Bind the socket with enhanced error handling
        let socket = match UdpSocket::bind(("0.0.0.0", self.context.dns_port)) {
            Ok(s) => s,
            Err(e) => {
                self.health_monitor.set_healthy(false);
                log::error!("Failed to bind UDP socket on port {}: {}", 
                           self.context.dns_port, e);
                return Err(crate::dns::server::ServerError::Io(e));
            }
        };

        log::info!("Enhanced DNS server listening on port {}", self.context.dns_port);

        // Main server loop with panic recovery
        loop {
            let mut buf = [0u8; 4096];
            
            match socket.recv_from(&mut buf) {
                Ok((len, src)) => {
                    let packet_data = &buf[..len];
                    
                    // Process in a separate thread to avoid blocking
                    let server = self.clone();
                    let socket_clone = socket.try_clone().expect("Failed to clone socket");
                    
                    std::thread::spawn(move || {
                        match server.process_query(packet_data, src) {
                            Ok(response) => {
                                if let Err(e) = socket_clone.send_to(&response, src) {
                                    log::error!("Failed to send response to {}: {}", src, e);
                                }
                            }
                            Err(e) => {
                                log::error!("Failed to process query from {}: {}", src, e);
                            }
                        }
                    });
                }
                Err(e) => {
                    log::error!("Failed to receive packet: {}", e);
                    
                    // Check if this is a recoverable error
                    if !self.is_recoverable_error(&e) {
                        self.health_monitor.set_healthy(false);
                        return Err(crate::dns::server::ServerError::Io(e));
                    }
                }
            }
        }
    }
}

impl EnhancedDnsServer {
    /// Check if an I/O error is recoverable
    fn is_recoverable_error(&self, error: &std::io::Error) -> bool {
        use std::io::ErrorKind;
        
        matches!(
            error.kind(),
            ErrorKind::WouldBlock | 
            ErrorKind::Interrupted |
            ErrorKind::TimedOut
        )
    }
}

// Make the server cloneable for thread spawning
impl Clone for EnhancedDnsServer {
    fn clone(&self) -> Self {
        EnhancedDnsServer {
            context: self.context.clone(),
            rate_limiter: self.rate_limiter.clone(),
            health_monitor: self.health_monitor.clone(),
            max_packet_size: self.max_packet_size,
            query_timeout: self.query_timeout,
        }
    }
}

// Add tokio for async support (would need to add to Cargo.toml)
use tokio;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_domain_validation() {
        let context = Arc::new(ServerContext::new().unwrap());
        let server = EnhancedDnsServer::new(context);

        assert!(server.is_valid_domain_name("example.com"));
        assert!(server.is_valid_domain_name("sub.domain.example.com"));
        assert!(server.is_valid_domain_name("example-with-dash.com"));
        
        assert!(!server.is_valid_domain_name(""));
        assert!(!server.is_valid_domain_name("."));
        assert!(!server.is_valid_domain_name("example..com"));
        assert!(!server.is_valid_domain_name("invalid@domain.com"));
        
        // Test label length limits
        let long_label = "a".repeat(64);
        assert!(!server.is_valid_domain_name(&format!("{}.com", long_label)));
    }

    #[test]
    fn test_size_limit_detection() {
        let context = Arc::new(ServerContext::new().unwrap());
        let server = EnhancedDnsServer::new(context);

        let mut packet = DnsPacket::new();
        assert_eq!(server.determine_size_limit(&packet), 512);

        // Add EDNS OPT record
        packet.resources.push(crate::dns::protocol::DnsRecord::Opt {
            packet_len: 4096,
            flags: 0,
            data: vec![],
        });
        assert_eq!(server.determine_size_limit(&packet), 4096);
    }
}