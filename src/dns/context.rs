//! The `ServerContext in this thread holds the common state across the server

use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use derive_more::{Display, Error, From};

use crate::dns::authority::Authority;
use crate::dns::cache::SynchronizedCache;
use crate::dns::client::{DnsClient, DnsNetworkClient};
use crate::dns::resolve::{DnsResolver, ForwardingDnsResolver, RecursiveDnsResolver};
use crate::dns::acme::SslConfig;

#[derive(Debug, Display, From, Error)]
pub enum ContextError {
    Authority(crate::dns::authority::AuthorityError),
    Client(crate::dns::client::ClientError),
    Io(std::io::Error),
}

type Result<T> = std::result::Result<T, ContextError>;

pub struct ServerStatistics {
    pub tcp_query_count: AtomicUsize,
    pub udp_query_count: AtomicUsize,
}

impl ServerStatistics {
    pub fn get_tcp_query_count(&self) -> usize {
        self.tcp_query_count.load(Ordering::Acquire)
    }

    pub fn get_udp_query_count(&self) -> usize {
        self.udp_query_count.load(Ordering::Acquire)
    }
}

/// DNS resolution strategy configuration
#[derive(Clone, Debug)]
pub enum ResolveStrategy {
    /// Perform recursive resolution starting from root servers
    Recursive,
    /// Forward all queries to an upstream DNS server
    Forward { host: String, port: u16 },
}

/// Main server context containing configuration and shared state
/// 
/// This struct holds all the configuration and runtime state needed by the DNS server,
/// including the authority zones, cache, resolution strategy, and server settings.
pub struct ServerContext {
    pub authority: Authority,
    pub cache: SynchronizedCache,
    pub client: Box<dyn DnsClient + Sync + Send>,
    pub dns_port: u16,
    pub api_port: u16,
    pub ssl_api_port: u16,
    pub resolve_strategy: ResolveStrategy,
    pub allow_recursive: bool,
    pub enable_udp: bool,
    pub enable_tcp: bool,
    pub enable_api: bool,
    pub statistics: ServerStatistics,
    pub zones_dir: &'static str,
    pub ssl_config: SslConfig
}

impl Default for ServerContext {
    fn default() -> Self {
        ServerContext::new().expect("Failed to create default ServerContext")
    }
}

impl ServerContext {
    pub fn new() -> Result<ServerContext> {
        Ok(ServerContext {
            authority: Authority::new(),
            cache: SynchronizedCache::new(),
            client: Box::new(DnsNetworkClient::new(0)?), // Use port 0 to let OS choose available port
            dns_port: 53,
            api_port: 5380,
            ssl_api_port: 5343,
            resolve_strategy: ResolveStrategy::Recursive,
            allow_recursive: true,
            enable_udp: true,
            enable_tcp: true,
            enable_api: true,
            statistics: ServerStatistics {
                tcp_query_count: AtomicUsize::new(0),
                udp_query_count: AtomicUsize::new(0),
            },
            zones_dir: "/opt/atlas/zones",
            ssl_config: SslConfig::default(),
        })
    }

    pub fn initialize(&mut self) -> Result<()> {
        // Create zones directory if it doesn't exist
        fs::create_dir_all(self.zones_dir)?;

        // Start UDP client thread
        self.client.run()?;

        // Load authority data
        self.authority.load()?;

        Ok(())
    }

    pub fn create_resolver(&self, ptr: Arc<ServerContext>) -> Box<dyn DnsResolver> {
        match self.resolve_strategy {
            ResolveStrategy::Recursive => Box::new(RecursiveDnsResolver::new(ptr)),
            ResolveStrategy::Forward { ref host, port } => {
                Box::new(ForwardingDnsResolver::new(ptr, (host.clone(), port)))
            }
        }
    }
}

#[cfg(test)]
pub mod tests {

    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    use crate::dns::authority::Authority;
    use crate::dns::cache::SynchronizedCache;

    use crate::dns::client::tests::{DnsStubClient, StubCallback};

    use super::*;

    pub fn create_test_context(callback: Box<StubCallback>) -> Arc<ServerContext> {
        Arc::new(ServerContext {
            authority: Authority::new(),
            cache: SynchronizedCache::new(),
            client: Box::new(DnsStubClient::new(callback)),
            dns_port: 53,
            api_port: 5380,
            ssl_api_port: 5343,
            resolve_strategy: ResolveStrategy::Recursive,
            allow_recursive: true,
            enable_udp: true,
            enable_tcp: true,
            enable_api: true,
            statistics: ServerStatistics {
                tcp_query_count: AtomicUsize::new(0),
                udp_query_count: AtomicUsize::new(0),
            },
            zones_dir: "/opt/atlas/zones",
            ssl_config: SslConfig::default(),
        })
    }
}
