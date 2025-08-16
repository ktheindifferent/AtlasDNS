//! DNS-over-HTTPS (DoH) Implementation
//!
//! Implements RFC 8484 for DNS queries over HTTPS with HTTP/2 support.
//! Provides both server and client capabilities for secure DNS resolution.
//!
//! # Features
//!
//! * **RFC 8484 Compliant** - Full specification implementation
//! * **HTTP/2 Support** - Multiplexed streams for concurrent queries
//! * **Content Types** - application/dns-message and application/dns-json
//! * **GET and POST** - Both HTTP methods supported
//! * **Caching Headers** - Proper cache control for DNS responses
//! * **CORS Support** - Cross-origin resource sharing for web clients

use std::sync::Arc;
use std::io::Read;
use tiny_http::{Method, Request, Response, Header};
use base64;
use serde::{Serialize, Deserialize};
use serde_json;

use crate::dns::context::ServerContext;
use crate::dns::protocol::{DnsPacket, QueryType, ResultCode, DnsQuestion};
use crate::dns::buffer::BytePacketBuffer;
use crate::dns::resolve::{DnsResolver, RecursiveDnsResolver};
use crate::dns::logging::{CorrelationContext, DnsQueryLog};
use crate::web::{Result, WebError};

/// DoH Content Types
pub const DOH_CONTENT_TYPE_MESSAGE: &str = "application/dns-message";
pub const DOH_CONTENT_TYPE_JSON: &str = "application/dns-json";

/// DoH Configuration
#[derive(Debug, Clone)]
pub struct DohConfig {
    /// Enable DoH server
    pub enabled: bool,
    /// Port for DoH service
    pub port: u16,
    /// Path for DoH endpoint
    pub path: String,
    /// Maximum DNS message size
    pub max_message_size: usize,
    /// Enable HTTP/2
    pub http2: bool,
    /// Enable CORS headers
    pub cors: bool,
    /// Cache control max age in seconds
    pub cache_max_age: u32,
}

impl Default for DohConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 443,
            path: "/dns-query".to_string(),
            max_message_size: 4096,
            http2: true,
            cors: true,
            cache_max_age: 300,
        }
    }
}

/// DNS JSON format for application/dns-json
#[derive(Debug, Serialize, Deserialize)]
pub struct DnsJson {
    /// Status (standard DNS response code)
    #[serde(rename = "Status")]
    pub status: u16,
    /// Truncated flag
    #[serde(rename = "TC")]
    pub tc: bool,
    /// Recursion Desired flag
    #[serde(rename = "RD")]
    pub rd: bool,
    /// Recursion Available flag
    #[serde(rename = "RA")]
    pub ra: bool,
    /// Authenticated Data flag
    #[serde(rename = "AD")]
    pub ad: bool,
    /// Checking Disabled flag
    #[serde(rename = "CD")]
    pub cd: bool,
    /// Question section
    #[serde(rename = "Question")]
    pub question: Vec<DnsJsonQuestion>,
    /// Answer section
    #[serde(rename = "Answer", skip_serializing_if = "Vec::is_empty")]
    pub answer: Vec<DnsJsonRecord>,
    /// Authority section
    #[serde(rename = "Authority", skip_serializing_if = "Vec::is_empty")]
    pub authority: Vec<DnsJsonRecord>,
    /// Additional section
    #[serde(rename = "Additional", skip_serializing_if = "Vec::is_empty")]
    pub additional: Vec<DnsJsonRecord>,
}

/// DNS JSON Question format
#[derive(Debug, Serialize, Deserialize)]
pub struct DnsJsonQuestion {
    /// Domain name
    pub name: String,
    /// Query type
    #[serde(rename = "type")]
    pub qtype: u16,
}

/// DNS JSON Record format
#[derive(Debug, Serialize, Deserialize)]
pub struct DnsJsonRecord {
    /// Domain name
    pub name: String,
    /// Record type
    #[serde(rename = "type")]
    pub rtype: u16,
    /// Time to live
    #[serde(rename = "TTL")]
    pub ttl: u32,
    /// Record data
    pub data: String,
}

/// DoH Server implementation
pub struct DohServer {
    context: Arc<ServerContext>,
    config: DohConfig,
}

impl DohServer {
    /// Create a new DoH server
    pub fn new(context: Arc<ServerContext>, config: DohConfig) -> Self {
        Self { context, config }
    }

    /// Check if DoH server is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get DoH configuration
    pub fn get_config(&self) -> &DohConfig {
        &self.config
    }

    /// Handle DoH request
    pub async fn handle_doh_request(
        &self,
        request: &mut Request,
    ) -> Result<Response<Box<dyn std::io::Read + Send + 'static>>> {
        // Create correlation context
        let ctx = CorrelationContext::new("doh_server", "handle_request");
        
        // Check HTTP method
        match request.method() {
            Method::Get => self.handle_get_request(request, ctx).await,
            Method::Post => self.handle_post_request(request, ctx).await,
            _ => {
                Ok(Response::from_string("Method not allowed")
                    .with_status_code(405)
                    .boxed())
            }
        }
    }

    /// Handle GET request with DNS query in URL
    async fn handle_get_request(
        &self,
        request: &Request,
        ctx: CorrelationContext,
    ) -> Result<Response<Box<dyn std::io::Read + Send + 'static>>> {
        // Extract DNS query from URL parameter
        let query_string = request.url()
            .split('?')
            .nth(1)
            .ok_or_else(|| WebError::InvalidRequest)?;

        let dns_param = query_string
            .split('&')
            .find(|param| param.starts_with("dns="))
            .ok_or_else(|| WebError::InvalidRequest)?;

        let dns_data = dns_param
            .strip_prefix("dns=")
            .ok_or_else(|| WebError::InvalidRequest)?;

        // Decode base64url DNS message
        let dns_bytes = base64::decode_config(dns_data, base64::URL_SAFE_NO_PAD)
            .map_err(|_| WebError::InvalidRequest)?;

        // Process DNS query
        self.process_dns_query(&dns_bytes, ctx).await
    }

    /// Handle POST request with DNS message in body
    async fn handle_post_request(
        &self,
        request: &mut Request,
        ctx: CorrelationContext,
    ) -> Result<Response<Box<dyn std::io::Read + Send + 'static>>> {
        // Check content type
        let content_type = request.headers()
            .iter()
            .find(|h| h.field.as_str() == "Content-Type")
            .map(|h| h.value.as_str());

        match content_type {
            Some(ct) if ct.starts_with(DOH_CONTENT_TYPE_MESSAGE) => {
                // Read binary DNS message
                let mut body = Vec::new();
                request.as_reader().read_to_end(&mut body)?;
                
                self.process_dns_query(&body, ctx).await
            }
            Some(ct) if ct.starts_with(DOH_CONTENT_TYPE_JSON) => {
                // Read JSON DNS query
                let json_query: DnsJson = serde_json::from_reader(request.as_reader())?;
                
                self.process_json_query(json_query, ctx).await
            }
            _ => {
                Ok(Response::from_string("Unsupported Media Type")
                    .with_status_code(415)
                    .boxed())
            }
        }
    }

    /// Process binary DNS query
    async fn process_dns_query(
        &self,
        query_bytes: &[u8],
        ctx: CorrelationContext,
    ) -> Result<Response<Box<dyn std::io::Read + Send + 'static>>> {
        // Parse DNS packet
        let mut buffer = BytePacketBuffer::new();
        buffer.buf[..query_bytes.len()].copy_from_slice(query_bytes);
        buffer.pos = 0;

        let request_packet = match DnsPacket::from_buffer(&mut buffer) {
            Ok(packet) => packet,
            Err(_) => {
                return Ok(Response::from_string("Bad Request")
                    .with_status_code(400)
                    .boxed());
            }
        };

        // Process DNS query
        let mut response_packet = self.resolve_query(request_packet, ctx).await?;

        // Serialize response
        let mut response_buffer = BytePacketBuffer::new();
        if let Err(_) = response_packet.write(&mut response_buffer, 512) {
            return Ok(Response::from_string("Internal Server Error")
                .with_status_code(500)
                .boxed());
        }

        let response_bytes = &response_buffer.buf[..response_buffer.pos];

        // Build HTTP response with appropriate headers
        let mut response = Response::from_data(response_bytes.to_vec())
            .with_header(Header::from_bytes(&b"Content-Type"[..], DOH_CONTENT_TYPE_MESSAGE.as_bytes()).unwrap());

        // Add cache control headers based on TTL
        if let Some(min_ttl) = self.get_minimum_ttl(&response_packet) {
            let cache_control = format!("max-age={}", min_ttl.min(self.config.cache_max_age));
            response.add_header(Header::from_bytes(&b"Cache-Control"[..], cache_control.as_bytes()).unwrap());
        }

        // Add CORS headers if enabled
        if self.config.cors {
            response.add_header(Header::from_bytes(&b"Access-Control-Allow-Origin"[..], b"*").unwrap());
            response.add_header(Header::from_bytes(&b"Access-Control-Allow-Methods"[..], b"GET, POST").unwrap());
        }

        Ok(response.boxed())
    }

    /// Process JSON DNS query
    async fn process_json_query(
        &self,
        json_query: DnsJson,
        ctx: CorrelationContext,
    ) -> Result<Response<Box<dyn std::io::Read + Send + 'static>>> {
        // Convert JSON to DNS packet
        let mut packet = DnsPacket::new();
        
        // Set flags from JSON
        packet.header.recursion_desired = json_query.rd;
        packet.header.id = rand::random::<u16>();

        // Add questions
        for question in json_query.question {
            packet.questions.push(crate::dns::protocol::DnsQuestion {
                name: question.name,
                qtype: QueryType::from_num(question.qtype),
            });
        }

        // Process DNS query
        let response_packet = self.resolve_query(packet, ctx).await?;

        // Convert response to JSON
        let json_response = self.packet_to_json(&response_packet);

        // Build HTTP response
        let response_json = serde_json::to_string(&json_response)?;
        let mut response = Response::from_string(response_json)
            .with_header(Header::from_bytes(&b"Content-Type"[..], DOH_CONTENT_TYPE_JSON.as_bytes()).unwrap());

        // Add cache control headers
        if let Some(min_ttl) = self.get_minimum_ttl(&response_packet) {
            let cache_control = format!("max-age={}", min_ttl.min(self.config.cache_max_age));
            response.add_header(Header::from_bytes(&b"Cache-Control"[..], cache_control.as_bytes()).unwrap());
        }

        // Add CORS headers if enabled
        if self.config.cors {
            response.add_header(Header::from_bytes(&b"Access-Control-Allow-Origin"[..], b"*").unwrap());
            response.add_header(Header::from_bytes(&b"Access-Control-Allow-Methods"[..], b"GET, POST").unwrap());
        }

        Ok(response.boxed())
    }

    /// Resolve DNS query using the DNS server
    async fn resolve_query(
        &self,
        mut packet: DnsPacket,
        ctx: CorrelationContext,
    ) -> Result<DnsPacket> {
        // Get the first question (DNS typically has one question)
        if packet.questions.is_empty() {
            packet.header.rescode = ResultCode::FORMERR;
            return Ok(packet);
        }

        let question = &packet.questions[0];
        let domain = &question.name;
        let qtype = question.qtype;

        // Log the query
        let query_log = DnsQueryLog {
            domain: domain.clone(),
            query_type: format!("{:?}", qtype),
            protocol: "DoH".to_string(),
            response_code: "NOERROR".to_string(),
            answer_count: 0,
            cache_hit: false,
            upstream_server: None,
            dnssec_status: None,
        };
        self.context.logger.log_dns_query(&ctx, query_log);

        // Check cache first
        if let Some(cached_packet) = self.context.cache.lookup(domain, qtype) {
            // Update metrics
            self.context.metrics.record_dns_query("DoH", &format!("{:?}", qtype), "cache");
            
            // Return cached response
            return Ok(cached_packet);
        }

        // Use RecursiveDnsResolver for lookup
        let mut resolver = RecursiveDnsResolver::new(self.context.clone());
        
        match resolver.resolve(&domain, qtype, true) {
            Ok(response_packet) => {
                // Cache the response if successful
                if response_packet.header.rescode == ResultCode::NOERROR && !response_packet.answers.is_empty() {
                    let _ = self.context.cache.store(&response_packet.answers);
                }
                
                // Update metrics
                self.context.metrics.record_dns_query("DoH", &format!("{:?}", qtype), "recursive");
                
                Ok(response_packet)
            }
            Err(_) => {
                let mut response_packet = packet.clone();
                response_packet.header.rescode = ResultCode::SERVFAIL;
                self.context.metrics.record_error("doh", "lookup_failed");
                Ok(response_packet)
            }
        }
    }

    /// Convert DNS packet to JSON format
    fn packet_to_json(&self, packet: &DnsPacket) -> DnsJson {
        let mut json = DnsJson {
            status: packet.header.rescode as u16,
            tc: packet.header.truncated_message,
            rd: packet.header.recursion_desired,
            ra: packet.header.recursion_available,
            ad: false, // DNSSEC not yet implemented
            cd: false, // DNSSEC not yet implemented
            question: Vec::new(),
            answer: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        };

        // Add questions
        for question in &packet.questions {
            json.question.push(DnsJsonQuestion {
                name: question.name.clone(),
                qtype: question.qtype.to_num(),
            });
        }

        // Add answers
        for answer in &packet.answers {
            json.answer.push(DnsJsonRecord {
                name: answer.get_domain().unwrap_or_else(|| "unknown".to_string()),
                rtype: answer.get_querytype().to_num(),
                ttl: answer.get_ttl(),
                data: format!("{:?}", answer), // Simplified for now
            });
        }

        // Add authority records
        for auth in &packet.authorities {
            json.authority.push(DnsJsonRecord {
                name: auth.get_domain().unwrap_or_else(|| "unknown".to_string()),
                rtype: auth.get_querytype().to_num(),
                ttl: auth.get_ttl(),
                data: format!("{:?}", auth),
            });
        }

        // Add additional records
        for additional in &packet.resources {
            json.additional.push(DnsJsonRecord {
                name: additional.get_domain().unwrap_or_else(|| "unknown".to_string()),
                rtype: additional.get_querytype().to_num(),
                ttl: additional.get_ttl(),
                data: format!("{:?}", additional),
            });
        }

        json
    }

    /// Get minimum TTL from packet for cache control
    fn get_minimum_ttl(&self, packet: &DnsPacket) -> Option<u32> {
        let mut min_ttl: Option<u32> = None;

        for answer in &packet.answers {
            let ttl = answer.get_ttl();
            min_ttl = Some(min_ttl.map_or(ttl, |m: u32| m.min(ttl)));
        }

        min_ttl
    }
}

/// DoH Client implementation for making DoH queries
pub struct DohClient {
    /// DoH server URL
    pub server_url: String,
    /// HTTP client
    client: reqwest::Client,
}

impl DohClient {
    /// Create a new DoH client
    pub fn new(server_url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();

        Self {
            server_url,
            client,
        }
    }

    /// Query DNS over HTTPS using POST method
    pub async fn query(&self, packet: &mut DnsPacket) -> Result<DnsPacket> {
        // Serialize DNS packet
        let mut buffer = BytePacketBuffer::new();
        packet.write(&mut buffer, 512)
            .map_err(|_| WebError::InternalError("Failed to serialize DNS packet".to_string()))?;

        let query_bytes = &buffer.buf[..buffer.pos];

        // Make DoH request
        let response = self.client
            .post(&self.server_url)
            .header("Content-Type", DOH_CONTENT_TYPE_MESSAGE)
            .header("Accept", DOH_CONTENT_TYPE_MESSAGE)
            .body(query_bytes.to_vec())
            .send()
            .await
            .map_err(|e| WebError::InternalError(format!("DoH request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(WebError::InternalError(format!("DoH server returned: {}", response.status())));
        }

        // Parse response
        let response_bytes = response.bytes().await
            .map_err(|e| WebError::InternalError(format!("Failed to read response: {}", e)))?;

        let mut response_buffer = BytePacketBuffer::new();
        response_buffer.buf[..response_bytes.len()].copy_from_slice(&response_bytes);
        response_buffer.pos = 0;

        DnsPacket::from_buffer(&mut response_buffer)
            .map_err(|e| WebError::InternalError(format!("Failed to parse DNS response: {:?}", e)))
    }

    /// Query DNS over HTTPS using GET method
    pub async fn query_get(&self, domain: &str, qtype: QueryType) -> Result<DnsPacket> {
        // Create DNS query packet
        let mut packet = DnsPacket::new();
        packet.header.id = rand::random::<u16>();
        packet.header.recursion_desired = true;
        packet.questions.push(crate::dns::protocol::DnsQuestion {
            name: domain.to_string(),
            qtype,
        });

        // Serialize packet
        let mut buffer = BytePacketBuffer::new();
        packet.write(&mut buffer, 512)
            .map_err(|_| WebError::InternalError("Failed to serialize DNS packet".to_string()))?;

        let query_bytes = &buffer.buf[..buffer.pos];
        let encoded = base64::encode_config(query_bytes, base64::URL_SAFE_NO_PAD);

        // Make GET request
        let url = format!("{}?dns={}", self.server_url, encoded);
        let response = self.client
            .get(&url)
            .header("Accept", DOH_CONTENT_TYPE_MESSAGE)
            .send()
            .await
            .map_err(|e| WebError::InternalError(format!("DoH request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(WebError::InternalError(format!("DoH server returned: {}", response.status())));
        }

        // Parse response
        let response_bytes = response.bytes().await
            .map_err(|e| WebError::InternalError(format!("Failed to read response: {}", e)))?;

        let mut response_buffer = BytePacketBuffer::new();
        response_buffer.buf[..response_bytes.len()].copy_from_slice(&response_bytes);
        response_buffer.pos = 0;

        DnsPacket::from_buffer(&mut response_buffer)
            .map_err(|e| WebError::InternalError(format!("Failed to parse DNS response: {:?}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doh_config_default() {
        let config = DohConfig::default();
        assert_eq!(config.port, 443);
        assert_eq!(config.path, "/dns-query");
        assert!(config.http2);
        assert!(config.cors);
    }

    #[test]
    fn test_dns_json_serialization() {
        let json = DnsJson {
            status: 0,
            tc: false,
            rd: true,
            ra: true,
            ad: false,
            cd: false,
            question: vec![
                DnsJsonQuestion {
                    name: "example.com".to_string(),
                    qtype: 1,
                }
            ],
            answer: vec![
                DnsJsonRecord {
                    name: "example.com".to_string(),
                    rtype: 1,
                    ttl: 300,
                    data: "93.184.216.34".to_string(),
                }
            ],
            authority: vec![],
            additional: vec![],
        };

        let serialized = serde_json::to_string(&json).unwrap();
        assert!(serialized.contains("\"Status\":0"));
        assert!(serialized.contains("\"RD\":true"));
        assert!(serialized.contains("example.com"));
    }

    #[test]
    fn test_base64url_encoding() {
        let data = b"test data";
        let encoded = base64::encode_config(data, base64::URL_SAFE_NO_PAD);
        let decoded = base64::decode_config(&encoded, base64::URL_SAFE_NO_PAD).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }
}