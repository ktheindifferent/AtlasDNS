//! resolver implementations implementing different strategies for answering
//! incoming queries

use std::sync::Arc;
use std::vec::Vec;

use derive_more::{Display, Error, From};

use crate::dns::context::ServerContext;
use crate::dns::protocol::{DnsPacket, DnsQuestion, QueryType, ResultCode, ValidationStatus};
use crate::dns::buffer::BytePacketBuffer;
use crate::dns::dnssec::{ChainValidator, ValidationMode};

#[derive(Debug, Display, From, Error)]
pub enum ResolveError {
    Client(crate::dns::client::ClientError),
    Cache(crate::dns::cache::CacheError),
    Io(std::io::Error),
    NoServerFound,
    MaxIterationsExceeded,
}

type Result<T> = std::result::Result<T, ResolveError>;

/// Trait for DNS resolution strategies
/// 
/// Implementors of this trait provide different strategies for resolving DNS queries,
/// such as recursive resolution, forwarding to upstream servers, or authoritative responses.
pub trait DnsResolver {
    /// Get the server context for accessing cache, authority, and configuration
    fn get_context(&self) -> Arc<ServerContext>;

    /// Resolve a DNS query
    /// 
    /// # Arguments
    /// 
    /// * `qname` - The domain name to resolve
    /// * `qtype` - The type of DNS record to query (A, AAAA, MX, etc.)
    /// * `recursive` - Whether to perform recursive resolution
    /// 
    /// # Returns
    /// 
    /// A DNS packet containing the response, or an error if resolution fails
    fn resolve(&mut self, qname: &str, qtype: QueryType, recursive: bool) -> Result<DnsPacket> {
        // Add Sentry breadcrumb for DNS resolution
        let mut data = std::collections::BTreeMap::new();
        data.insert("qname".to_string(), qname.into());
        data.insert("qtype".to_string(), format!("{:?}", qtype).into());
        data.insert("recursive".to_string(), recursive.into());
        
        sentry::add_breadcrumb(|| {
            sentry::Breadcrumb {
                ty: "dns".to_string(),
                category: Some("dns.resolve".to_string()),
                message: Some(format!("Resolving {} {:?} (recursive: {})", qname, qtype, recursive)),
                level: sentry::Level::Info,
                data,
                ..Default::default()
            }
        });

        log::info!("attempting to resolve: {:?}", qname);

        if let QueryType::Unknown(_) = qtype {
            log::info!("unknown");
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::NOTIMP;
            return Ok(packet);
        }

        let context = self.get_context();

        // Threat intelligence: block queries to known-malicious domains
        if let Some(ref ti) = context.threat_intel {
            if let Some(entry) = ti.check_domain(qname) {
                ti.record_hit(qname, "dns-query", &entry);
                log::warn!(
                    "[THREAT-INTEL] Blocked DNS query: domain={} category={} source={}",
                    qname, entry.category, entry.source
                );
                use crate::dns::security::threat_intel::BlockAction;
                let mut packet = DnsPacket::new();
                match ti.block_action() {
                    BlockAction::Nxdomain => {
                        packet.header.rescode = ResultCode::NXDOMAIN;
                    }
                    BlockAction::RedirectIp(ip_str) => {
                        use crate::dns::protocol::{DnsRecord, TransientTtl};
                        if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                            packet.header.rescode = ResultCode::NOERROR;
                            packet.answers.push(DnsRecord::A {
                                domain: qname.to_string(),
                                addr: ip,
                                ttl: TransientTtl(60),
                            });
                        } else {
                            packet.header.rescode = ResultCode::NXDOMAIN;
                        }
                    }
                }
                return Ok(packet);
            }
        }

        if let Some(qr) = context.authority.query(qname, qtype) {
            log::info!("context.authority.query");
            return Ok(qr);
        }

        if !recursive || !context.allow_recursive {
            log::info!("REFUSED !allow_recursive");
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::REFUSED;
            return Ok(packet);
        }

        if let Some(qr) = context.cache.lookup(qname, qtype) {
            log::info!("context.cache.lookup");
            return Ok(qr);
        }

        if qtype == QueryType::A || qtype == QueryType::Aaaa {
            log::info!("context.cache.lookup2");
            if let Some(qr) = context.cache.lookup(qname, QueryType::Cname) {
                return Ok(qr);
            }
        }

        let mut result = self.perform(qname, qtype)?;

        // DNSSEC chain-of-trust validation
        {
            let context = self.get_context();
            if context.dnssec_enabled {
                let mode = context.dnssec_validation_mode;
                let validator = ChainValidator::with_root_ksk(mode);
                match validator.validate_chain_for_query(&result, qname, qtype) {
                    Ok(status) => {
                        result.dnssec_status = Some(status);
                        log::debug!("DNSSEC validation for {} {:?}: {}", qname, qtype, status);
                    }
                    Err(e) => {
                        // Strict mode returns Err on BOGUS; other modes should not reach here.
                        log::warn!("DNSSEC chain validation failed for {} {:?}: {}", qname, qtype, e);
                        result.dnssec_status = Some(ValidationStatus::Bogus);
                        if mode == ValidationMode::Strict {
                            return Err(ResolveError::Io(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("DNSSEC validation failed: {}", e),
                            )));
                        }
                    }
                }
            }
        }

        // DNS rebinding protection: block responses returning private IPs for public domains
        let context = self.get_context();
        let rebind = &context.rebinding_protection;
        if rebind.enabled {
            let blocked_addrs: Vec<_> = result.answers.iter()
                .filter_map(|r| match r {
                    crate::dns::protocol::DnsRecord::A { addr, .. } => {
                        Some(std::net::IpAddr::V4(*addr))
                    }
                    crate::dns::protocol::DnsRecord::Aaaa { addr, .. } => {
                        Some(std::net::IpAddr::V6(*addr))
                    }
                    _ => None,
                })
                .filter(|ip| rebind.should_block(qname, ip))
                .collect();

            if !blocked_addrs.is_empty() {
                log::warn!(
                    "DNS rebinding protection: blocked {} private IP(s) in response for {} ({:?})",
                    blocked_addrs.len(), qname, blocked_addrs
                );
                let mut blocked = crate::dns::protocol::DnsPacket::new();
                blocked.header.rescode = crate::dns::protocol::ResultCode::REFUSED;
                return Ok(blocked);
            }
        }

        Ok(result)
    }

    fn perform(&mut self, qname: &str, qtype: QueryType) -> Result<DnsPacket>;
}

/// A Forwarding DNS Resolver
///
/// This resolver uses an external DNS server to service a query
pub struct ForwardingDnsResolver {
    context: Arc<ServerContext>,
    server: (String, u16),
}

impl ForwardingDnsResolver {
    pub fn new(context: Arc<ServerContext>, server: (String, u16)) -> ForwardingDnsResolver {
        ForwardingDnsResolver {
            context,
            server,
        }
    }
}

impl DnsResolver for ForwardingDnsResolver {
    fn get_context(&self) -> Arc<ServerContext> {
        self.context.clone()
    }

    fn perform(&mut self, qname: &str, qtype: QueryType) -> Result<DnsPacket> {
        let &(ref host, port) = &self.server;
        
        // Add breadcrumb for forwarding query
        let mut data = std::collections::BTreeMap::new();
        data.insert("qname".to_string(), qname.into());
        data.insert("qtype".to_string(), format!("{:?}", qtype).into());
        data.insert("forward_host".to_string(), host.clone().into());
        data.insert("forward_port".to_string(), port.into());
        
        sentry::add_breadcrumb(|| {
            sentry::Breadcrumb {
                ty: "dns".to_string(),
                category: Some("dns.forward".to_string()),
                message: Some(format!("Forwarding query to {}:{}", host, port)),
                level: sentry::Level::Info,
                data,
                ..Default::default()
            }
        });
        
        let result = self
            .context
            .client
            .send_query(qname, qtype, (host.as_str(), port), true)
            .map_err(|e| {
                // Report forwarding error to Sentry
                sentry::configure_scope(|scope| {
                    scope.set_tag("dns_operation", "forward");
                    scope.set_tag("qname", qname);
                    scope.set_tag("qtype", &format!("{:?}", qtype));
                    scope.set_tag("forward_server", &format!("{}:{}", host, port));
                });
                sentry::capture_message(
                    &format!("DNS forwarding failed for {} {:?}: {}", qname, qtype, e), 
                    sentry::Level::Error
                );
                e
            })?;

        // Success breadcrumb
        let mut data = std::collections::BTreeMap::new();
        data.insert("answer_count".to_string(), result.answers.len().into());
        
        sentry::add_breadcrumb(|| {
            sentry::Breadcrumb {
                ty: "dns".to_string(),
                category: Some("dns.forward.success".to_string()),
                message: Some(format!("Successfully forwarded query for {}", qname)),
                level: sentry::Level::Info,
                data,
                ..Default::default()
            }
        });

        if let Err(e) = self.context.cache.store(&result.answers) {
            // Report cache storage error
            sentry::configure_scope(|scope| {
                scope.set_tag("dns_operation", "cache_store");
            });
            sentry::capture_message(
                &format!("Failed to cache DNS answers: {}", e), 
                sentry::Level::Warning
            );
            // Don't fail the query due to cache issues, just log and continue
            log::warn!("Failed to cache DNS answers: {}", e);
        }

        Ok(result)
    }
}

/// A DNS resolver that queries upstream via DNS-over-HTTPS (DoH), falling back
/// to standard UDP forwarding when the DoH request fails.
///
/// The DoH URL is typically one of:
/// * `https://cloudflare-dns.com/dns-query`
/// * `https://dns.google/dns-query`
pub struct DohForwardingDnsResolver {
    context: Arc<ServerContext>,
    doh_url: String,
    fallback: (String, u16),
}

impl DohForwardingDnsResolver {
    pub fn new(
        context: Arc<ServerContext>,
        doh_url: String,
        fallback: (String, u16),
    ) -> Self {
        Self { context, doh_url, fallback }
    }

    /// Attempt a single DNS-over-HTTPS POST query.  Returns `None` on any
    /// transport, encoding, or parsing error.
    fn query_doh(&self, qname: &str, qtype: QueryType) -> Option<DnsPacket> {
        // Serialise a minimal DNS wire-format query
        let mut packet = DnsPacket::new();
        packet.header.id = rand::random::<u16>();
        packet.header.recursion_desired = true;
        packet.questions.push(DnsQuestion {
            name: qname.to_string(),
            qtype,
        });

        let mut buffer = BytePacketBuffer::new();
        packet.write(&mut buffer, 512).ok()?;
        let body = buffer.buf[..buffer.pos].to_vec();

        let url = self.doh_url.clone();

        // Run the blocking HTTP call on a dedicated thread so it is safe to
        // call from both sync and async contexts.
        let bytes = std::thread::spawn(move || {
            reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .user_agent("AtlasDNS/1.0 doh-upstream")
                .build()
                .and_then(|c| {
                    c.post(&url)
                        .header("Content-Type", "application/dns-message")
                        .header("Accept", "application/dns-message")
                        .body(body)
                        .send()
                })
                .and_then(|r| r.bytes())
        })
        .join()
        .ok()?
        .ok()?;

        if bytes.len() > 512 {
            return None; // oversized – fall back to UDP
        }

        let mut resp_buf = BytePacketBuffer::new();
        resp_buf.buf[..bytes.len()].copy_from_slice(&bytes);
        resp_buf.pos = 0;
        DnsPacket::from_buffer(&mut resp_buf).ok()
    }
}

impl DnsResolver for DohForwardingDnsResolver {
    fn get_context(&self) -> Arc<ServerContext> {
        self.context.clone()
    }

    fn perform(&mut self, qname: &str, qtype: QueryType) -> Result<DnsPacket> {
        // Try DoH first
        if let Some(response) = self.query_doh(qname, qtype) {
            if let Err(e) = self.context.cache.store(&response.answers) {
                log::warn!("DoH: failed to cache response for {}: {}", qname, e);
            }
            return Ok(response);
        }

        // Fall back to UDP forwarding
        log::warn!(
            "DoH upstream failed for {} {:?}, falling back to UDP {}:{}",
            qname, qtype, self.fallback.0, self.fallback.1
        );
        let (ref host, port) = self.fallback;
        let result = self
            .context
            .client
            .send_query(qname, qtype, (host.as_str(), port), true)?;

        if let Err(e) = self.context.cache.store(&result.answers) {
            log::warn!("DoH fallback: failed to cache UDP response: {}", e);
        }
        Ok(result)
    }
}

/// A Recursive DNS resolver
///
/// This resolver can answer any request using the root servers of the internet
pub struct RecursiveDnsResolver {
    context: Arc<ServerContext>,
}

impl RecursiveDnsResolver {
    pub fn new(context: Arc<ServerContext>) -> RecursiveDnsResolver {
        RecursiveDnsResolver { context }
    }
    
    /// Find the closest cached nameserver for a domain
    fn find_closest_nameserver(&self, qname: &str) -> Option<String> {
        let labels = qname.split('.').collect::<Vec<&str>>();
        
        for lbl_idx in 0..labels.len() + 1 {
            let domain = labels[lbl_idx..].join(".");
            
            if let Some(addr) = self
                .context
                .cache
                .lookup(&domain, QueryType::Ns)
                .and_then(|qr| qr.get_unresolved_ns(&domain))
                .and_then(|ns| self.context.cache.lookup(&ns, QueryType::A))
                .and_then(|qr| qr.get_random_a())
            {
                return Some(addr);
            }
        }
        
        None
    }
    
    /// Store response records in cache
    fn cache_response(&self, response: &DnsPacket) {
        let _ = self.context.cache.store(&response.answers);
        let _ = self.context.cache.store(&response.authorities);
        let _ = self.context.cache.store(&response.resources);
    }
    
    /// Check if response contains a valid answer
    fn is_valid_answer(&self, response: &DnsPacket) -> bool {
        !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR
    }
    /// Query a nameserver and process the response
    fn query_nameserver(&mut self, qname: &str, qtype: QueryType, ns: &str) -> Result<DnsPacket> {
        log::info!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);
        let server = (ns, 53);
        Ok(self.context.client.send_query(qname, qtype, server, false)?)
    }

    /// Handle a successful answer response
    fn handle_answer(&mut self, response: DnsPacket) -> Result<DnsPacket> {
        self.cache_response(&response);
        Ok(response)
    }

    /// Handle an NXDOMAIN response
    fn handle_nxdomain(&mut self, qname: &str, qtype: QueryType, response: DnsPacket) -> Result<DnsPacket> {
        if let Some(ttl) = response.get_ttl_from_soa() {
            let _ = self.context.cache.store_nxdomain(qname, qtype, ttl);
        }
        Ok(response)
    }

    /// Try to find the next nameserver from the response
    fn find_next_nameserver(&mut self, response: &DnsPacket, qname: &str) -> Result<Option<String>> {
        // Check for resolved NS in additional section
        if let Some(new_ns) = response.get_resolved_ns(qname) {
            self.cache_response(response);
            return Ok(Some(new_ns));
        }

        // Check for unresolved NS that needs recursive resolution
        if let Some(new_ns_name) = response.get_unresolved_ns(qname) {
            let recursive_response = self.resolve(&new_ns_name, QueryType::A, true)?;
            return Ok(recursive_response.get_random_a());
        }

        Ok(None)
    }
}

impl DnsResolver for RecursiveDnsResolver {
    fn get_context(&self) -> Arc<ServerContext> {
        self.context.clone()
    }

    fn perform(&mut self, qname: &str, qtype: QueryType) -> Result<DnsPacket> {
        // Find the closest cached nameserver
        let tentative_ns = self.find_closest_nameserver(qname);
        log::info!("tentative_ns: {:?}", tentative_ns.clone());
        
        let mut ns = tentative_ns.ok_or(ResolveError::NoServerFound)?;
        
        // Add maximum iteration limit to prevent infinite loops
        const MAX_ITERATIONS: u32 = 30;
        let mut iterations = 0;

        // Start querying name servers
        loop {
            iterations += 1;
            if iterations > MAX_ITERATIONS {
                log::warn!("Maximum iteration limit reached while resolving {} {:?}", qname, qtype);
                return Err(ResolveError::MaxIterationsExceeded);
            }
            
            let response = self.query_nameserver(qname, qtype, &ns)?;

            // Check if we have a valid answer
            if self.is_valid_answer(&response) {
                return self.handle_answer(response);
            }

            // Check for NXDOMAIN
            if response.header.rescode == ResultCode::NXDOMAIN {
                return self.handle_nxdomain(qname, qtype, response);
            }

            // Try to find the next nameserver
            match self.find_next_nameserver(&response, qname)? {
                Some(new_ns) => ns = new_ns,
                None => return Ok(response),
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, ResultCode, TransientTtl};

    use super::*;

    use crate::dns::context::tests::create_test_context;
    use crate::dns::context::ResolveStrategy;

    #[test]
    fn test_forwarding_resolver() {
        let mut context = create_test_context(Box::new(|qname, _, _, _| {
            let mut packet = DnsPacket::new();

            if qname == "google.com" {
                packet.answers.push(DnsRecord::A {
                    domain: "google.com".to_string(),
                    addr: "127.0.0.1".parse().unwrap(),
                    ttl: TransientTtl(3600),
                });
            } else {
                packet.header.rescode = ResultCode::NXDOMAIN;
            }

            Ok(packet)
        }));

        match Arc::get_mut(&mut context) {
            Some(ctx) => {
                ctx.resolve_strategy = ResolveStrategy::Forward {
                    host: "127.0.0.1".to_string(),
                    port: 53,
                };
            }
            None => {
                panic!("Failed to get mutable reference to ServerContext in test");
            }
        }

        let mut resolver = context.create_resolver(context.clone());

        // First verify that we get a match back
        {
            let res = match resolver.resolve("google.com", QueryType::A, true) {
                Ok(x) => x,
                Err(e) => panic!("Expected successful DNS resolution but got error: {}", e),
            };

            assert_eq!(1, res.answers.len());

            match res.answers[0] {
                DnsRecord::A { ref domain, .. } => {
                    assert_eq!("google.com", domain);
                }
                _ => panic!("Expected A record but got different record type"),
            }
        };

        // Do the same lookup again, and verify that it's present in the cache
        // and that the counter has been updated
        {
            let res = match resolver.resolve("google.com", QueryType::A, true) {
                Ok(x) => x,
                Err(e) => panic!("Expected successful operation but got error: {}", e),
            };

            assert_eq!(1, res.answers.len());

            let list = match context.cache.list() {
                Ok(x) => x,
                Err(e) => panic!("Expected successful operation but got error: {}", e),
            };

            assert_eq!(1, list.len());

            assert_eq!("google.com", list[0].domain);
            assert_eq!(1, list[0].record_types.len());
            assert_eq!(1, list[0].hits);
        };

        // Do a failed lookup
        {
            let res = match resolver.resolve("yahoo.com", QueryType::A, true) {
                Ok(x) => x,
                Err(e) => panic!("Expected successful operation but got error: {}", e),
            };

            assert_eq!(0, res.answers.len());
            assert_eq!(ResultCode::NXDOMAIN, res.header.rescode);
        };
    }

    #[test]
    fn test_recursive_resolver_with_no_nameserver() {
        let context = create_test_context(Box::new(|_, _, _, _| {
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::NXDOMAIN;
            Ok(packet)
        }));

        let mut resolver = context.create_resolver(context.clone());

        // Expect failure when no name servers are available
        if resolver.resolve("google.com", QueryType::A, true).is_ok() {
            panic!("Expected DNS resolution to fail but it succeeded");
        }
    }

    #[test]
    fn test_recursive_resolver_with_missing_a_record() {
        let context = create_test_context(Box::new(|_, _, _, _| {
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::NXDOMAIN;
            Ok(packet)
        }));

        let mut resolver = context.create_resolver(context.clone());

        // Expect failure when no name servers are available
        if resolver.resolve("google.com", QueryType::A, true).is_ok() {
            panic!("Expected DNS resolution to fail but it succeeded");
        }

        // Insert name server, but no corresponding A record
        let mut nameservers = Vec::new();
        nameservers.push(DnsRecord::Ns {
            domain: "".to_string(),
            host: "a.myroot.net".to_string(),
            ttl: TransientTtl(3600),
        });

        let _ = context.cache.store(&nameservers);

        if resolver.resolve("google.com", QueryType::A, true).is_ok() {
            panic!("Expected DNS resolution to fail but it succeeded");
        }
    }

    #[test]
    fn test_recursive_resolver_match_order() {
        let context = create_test_context(Box::new(|_, _, (server, _), _| {
            let mut packet = DnsPacket::new();

            if server == "127.0.0.1" {
                packet.header.id = 1;

                packet.answers.push(DnsRecord::A {
                    domain: "a.google.com".to_string(),
                    addr: "127.0.0.1".parse().unwrap(),
                    ttl: TransientTtl(3600),
                });

                return Ok(packet);
            } else if server == "127.0.0.2" {
                packet.header.id = 2;

                packet.answers.push(DnsRecord::A {
                    domain: "b.google.com".to_string(),
                    addr: "127.0.0.1".parse().unwrap(),
                    ttl: TransientTtl(3600),
                });

                return Ok(packet);
            } else if server == "127.0.0.3" {
                packet.header.id = 3;

                packet.answers.push(DnsRecord::A {
                    domain: "c.google.com".to_string(),
                    addr: "127.0.0.1".parse().unwrap(),
                    ttl: TransientTtl(3600),
                });

                return Ok(packet);
            }

            packet.header.id = 999;
            packet.header.rescode = ResultCode::NXDOMAIN;
            Ok(packet)
        }));

        let mut resolver = context.create_resolver(context.clone());

        // Expect failure when no name servers are available
        if resolver.resolve("google.com", QueryType::A, true).is_ok() {
            panic!("Expected DNS resolution to fail but it succeeded");
        }

        // Insert root servers
        {
            let mut nameservers = Vec::new();
            nameservers.push(DnsRecord::Ns {
                domain: "".to_string(),
                host: "a.myroot.net".to_string(),
                ttl: TransientTtl(3600),
            });
            nameservers.push(DnsRecord::A {
                domain: "a.myroot.net".to_string(),
                addr: "127.0.0.1".parse().unwrap(),
                ttl: TransientTtl(3600),
            });

            let _ = context.cache.store(&nameservers);
        }

        match resolver.resolve("google.com", QueryType::A, true) {
            Ok(packet) => {
                assert_eq!(1, packet.header.id);
            }
            Err(_) => panic!(),
        }

        // Insert TLD servers
        {
            let mut nameservers = Vec::new();
            nameservers.push(DnsRecord::Ns {
                domain: "com".to_string(),
                host: "a.mytld.net".to_string(),
                ttl: TransientTtl(3600),
            });
            nameservers.push(DnsRecord::A {
                domain: "a.mytld.net".to_string(),
                addr: "127.0.0.2".parse().unwrap(),
                ttl: TransientTtl(3600),
            });

            let _ = context.cache.store(&nameservers);
        }

        match resolver.resolve("google.com", QueryType::A, true) {
            Ok(packet) => {
                assert_eq!(2, packet.header.id);
            }
            Err(_) => panic!(),
        }

        // Insert authoritative servers
        {
            let mut nameservers = Vec::new();
            nameservers.push(DnsRecord::Ns {
                domain: "google.com".to_string(),
                host: "ns1.google.com".to_string(),
                ttl: TransientTtl(3600),
            });
            nameservers.push(DnsRecord::A {
                domain: "ns1.google.com".to_string(),
                addr: "127.0.0.3".parse().unwrap(),
                ttl: TransientTtl(3600),
            });

            let _ = context.cache.store(&nameservers);
        }

        match resolver.resolve("google.com", QueryType::A, true) {
            Ok(packet) => {
                assert_eq!(3, packet.header.id);
            }
            Err(_) => panic!(),
        }
    }

    #[test]
    fn test_recursive_resolver_successfully() {
        let context = create_test_context(Box::new(|qname, _, _, _| {
            let mut packet = DnsPacket::new();

            if qname == "google.com" {
                packet.answers.push(DnsRecord::A {
                    domain: "google.com".to_string(),
                    addr: "127.0.0.1".parse().unwrap(),
                    ttl: TransientTtl(3600),
                });
            } else {
                packet.header.rescode = ResultCode::NXDOMAIN;

                packet.authorities.push(DnsRecord::Soa {
                    domain: "google.com".to_string(),
                    r_name: "google.com".to_string(),
                    m_name: "google.com".to_string(),
                    serial: 0,
                    refresh: 3600,
                    retry: 3600,
                    expire: 3600,
                    minimum: 3600,
                    ttl: TransientTtl(3600),
                });
            }

            Ok(packet)
        }));

        let mut resolver = context.create_resolver(context.clone());

        // Insert name servers
        let mut nameservers = Vec::new();
        nameservers.push(DnsRecord::Ns {
            domain: "google.com".to_string(),
            host: "ns1.google.com".to_string(),
            ttl: TransientTtl(3600),
        });
        nameservers.push(DnsRecord::A {
            domain: "ns1.google.com".to_string(),
            addr: "127.0.0.1".parse().unwrap(),
            ttl: TransientTtl(3600),
        });

        let _ = context.cache.store(&nameservers);

        // Check that we can successfully resolve
        {
            let res = match resolver.resolve("google.com", QueryType::A, true) {
                Ok(x) => x,
                Err(e) => panic!("Expected successful operation but got error: {}", e),
            };

            assert_eq!(1, res.answers.len());

            match res.answers[0] {
                DnsRecord::A { ref domain, .. } => {
                    assert_eq!("google.com", domain);
                }
                _ => panic!("Expected A record but got different record type"),
            }
        };

        // And that we won't find anything for a domain that isn't present
        {
            let res = match resolver.resolve("foobar.google.com", QueryType::A, true) {
                Ok(x) => x,
                Err(e) => panic!("Expected successful operation but got error: {}", e),
            };

            assert_eq!(ResultCode::NXDOMAIN, res.header.rescode);
            assert_eq!(0, res.answers.len());
        };

        // Perform another successful query, that should hit the cache
        {
            let res = match resolver.resolve("google.com", QueryType::A, true) {
                Ok(x) => x,
                Err(e) => panic!("Expected successful operation but got error: {}", e),
            };

            assert_eq!(1, res.answers.len());
        };

        // Now check that the cache is used, and that the statistics is correct
        {
            let list = match context.cache.list() {
                Ok(x) => x,
                Err(e) => panic!("Expected successful operation but got error: {}", e),
            };

            assert_eq!(3, list.len());

            // Check statistics for google entry
            assert_eq!("google.com", list[1].domain);

            // Should have a Ns record and an A record for a total of 2 record types
            assert_eq!(2, list[1].record_types.len());

            // Should have been hit two times for Ns google.com and once for
            // A google.com
            assert_eq!(3, list[1].hits);

            assert_eq!("ns1.google.com", list[2].domain);
            assert_eq!(1, list[2].record_types.len());
            assert_eq!(2, list[2].hits);
        };
    }

    // -----------------------------------------------------------------------
    // DNSSEC integration tests
    // -----------------------------------------------------------------------

    /// When dnssec_enabled=true and the response has no RRSIG records, the
    /// resolver sets dnssec_status to Some(Indeterminate).
    #[test]
    fn test_resolver_sets_dnssec_status_indeterminate_for_unsigned_response() {
        use crate::dns::protocol::ValidationStatus;

        let mut context = create_test_context(Box::new(|qname, _, _, _| {
            let mut packet = DnsPacket::new();
            if qname == "example.com" {
                packet.answers.push(DnsRecord::A {
                    domain: "example.com".to_string(),
                    addr: "93.184.216.34".parse().unwrap(),
                    ttl: TransientTtl(300),
                });
            }
            Ok(packet)
        }));

        match Arc::get_mut(&mut context) {
            Some(ctx) => {
                ctx.resolve_strategy = ResolveStrategy::Forward {
                    host: "127.0.0.1".to_string(),
                    port: 53,
                };
                ctx.dnssec_enabled = true;
            }
            None => panic!("Failed to get mutable reference to ServerContext in test"),
        }

        let mut resolver = context.create_resolver(context.clone());
        let result = resolver.resolve("example.com", QueryType::A, true)
            .expect("resolution should succeed");

        // Unsigned response → Indeterminate (not an error in Opportunistic mode)
        assert_eq!(
            result.dnssec_status,
            Some(ValidationStatus::Indeterminate),
            "unsigned response must yield Indeterminate DNSSEC status"
        );
    }

    /// When dnssec_enabled=false the resolver must leave dnssec_status as None.
    #[test]
    fn test_resolver_skips_dnssec_when_disabled() {
        let mut context = create_test_context(Box::new(|_, _, _, _| {
            let mut packet = DnsPacket::new();
            packet.answers.push(DnsRecord::A {
                domain: "example.com".to_string(),
                addr: "93.184.216.34".parse().unwrap(),
                ttl: TransientTtl(300),
            });
            Ok(packet)
        }));

        match Arc::get_mut(&mut context) {
            Some(ctx) => {
                ctx.resolve_strategy = ResolveStrategy::Forward {
                    host: "127.0.0.1".to_string(),
                    port: 53,
                };
                ctx.dnssec_enabled = false;
            }
            None => panic!("Failed to get mutable reference to ServerContext in test"),
        }

        let mut resolver = context.create_resolver(context.clone());
        let result = resolver.resolve("example.com", QueryType::A, true)
            .expect("resolution should succeed");

        assert_eq!(
            result.dnssec_status,
            None,
            "dnssec_status must be None when DNSSEC is disabled"
        );
    }

    /// ValidationStatus::Insecure is a named variant reachable from resolve module.
    #[test]
    fn test_validation_status_insecure_variant_accessible() {
        use crate::dns::protocol::ValidationStatus;
        let status = ValidationStatus::Insecure;
        assert_eq!(status.to_string(), "INSECURE");
    }
}
