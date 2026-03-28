use std::env;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread;

use getopts::Options;
extern crate sentry;

use atlas::dns::protocol::{DnsRecord, TransientTtl};
use atlas::dns::context::{ResolveStrategy, ServerContext};
use atlas::dns::dnssec::ValidationMode;
use atlas::dns::server::{DnsServer, DnsTcpServer, DnsUdpServer};
use atlas::dns::acme::{AcmeConfig, AcmeProvider};
use atlas::dns::dot::{DotConfig, DotServer};
use atlas::dns::doq::{DoqConfig, DoqServer};
use atlas::dns::prometheus_server::PrometheusServer;
use atlas::web::server::WebServer;
use atlas::privilege_escalation::{has_admin_privileges, escalate_privileges, port_requires_privileges};
use atlas::dns::security::{ThreatIntelManager, ThreatIntelConfig};
use atlas::dns::mdns::{MdnsListener, MdnsRegistry};
use atlas::dns::clustering::{ClusterConfig, ClusterRole, ZoneTransferPayload, ZoneTransferEntry, CLUSTER_GOSSIP_PORT, CLUSTER_ZONE_TRANSFER_PORT};
use atlas::dns::bench::{BenchConfig, run_bench};
use atlas::dns::protocol::QueryType;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

/// Main entry point for the Atlas DNS server
fn main() {
    // Initialize Sentry for error tracking and monitoring
    // Use environment variable for Sentry DSN to avoid exposing credentials
    let sentry_dsn = std::env::var("SENTRY_DSN").unwrap_or_default();
    let _guard = if !sentry_dsn.is_empty() {
        Some(sentry::init(sentry_dsn))
    } else {
        // No Sentry DSN provided, skip initialization
        None
    };
    
    // Set up Sentry context
    sentry::configure_scope(|scope| {
        scope.set_tag("service", "atlas-dns");
        scope.set_tag("version", env!("CARGO_PKG_VERSION"));
        scope.set_context("application", sentry::protocol::Context::Other({
            let mut map = std::collections::BTreeMap::new();
            map.insert("name".to_string(), "Atlas DNS Server".into());
            map.insert("version".to_string(), env!("CARGO_PKG_VERSION").into());
            map
        }));
    });
    
    // Set up panic handler to report to Sentry
    std::panic::set_hook(Box::new(|panic_info| {
        sentry::integrations::panic::panic_handler(panic_info);
        
        // Also log to stderr for local debugging
        eprintln!("PANIC: {}", panic_info);
        
        // Add some context about the panic
        sentry::configure_scope(|scope| {
            scope.set_tag("event_type", "panic");
            
            if let Some(location) = panic_info.location() {
                scope.set_tag("panic_file", location.file());
                scope.set_tag("panic_line", location.line().to_string());
            }
        });
        
        let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic".to_string()
        };
        
        sentry::capture_message(&format!("Panic: {}", message), sentry::Level::Fatal);
    }));
    
    // Initialize logger - check if already initialized to avoid double initialization warning
    match simple_logger::init() {
        Ok(_) => {
            log::info!("Logger initialized successfully");
        }
        Err(_) => {
            // Logger already initialized, this is expected when Sentry sets up its own tracing subscriber
            // Don't log here to avoid potential issues if logging isn't properly set up yet
            eprintln!("Logger already initialized (likely by Sentry integration)");
        }
    }
    
    log::info!("Atlas DNS Server starting with Sentry monitoring enabled");

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    // Handle "bench" subcommand: atlas bench [--count N] [--domain D] [--server S] [--port P] [--type T]
    if args.len() >= 2 && args[1] == "bench" {
        run_bench_subcommand(&args[1..]);
        return;
    }

    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optopt(
        "f",
        "forward-address",
        "Upstream DNS server for forwarding (e.g. 8.8.8.8)",
        "FORWARDIP",
    );
    opts.optflag(
        "x",
        "disable-api",
        "Disable the Atlas web server API",
    );
    opts.optopt(
        "j",
        "zones-dir",
        "The directory for the zone files",
        "DIRECTORY",
    );
    opts.optflag(
        "s",
        "ssl",
        "Enable SSL/TLS for the web server",
    );
    opts.optopt(
        "",
        "acme-provider",
        "ACME provider (letsencrypt, letsencrypt-staging, zerossl)",
        "PROVIDER",
    );
    opts.optopt(
        "",
        "acme-email",
        "Email address for ACME registration",
        "EMAIL",
    );
    opts.optopt(
        "",
        "acme-domains",
        "Comma-separated list of domains for ACME certificate",
        "DOMAINS",
    );
    opts.optopt(
        "",
        "ssl-cert",
        "Path to SSL certificate file (if not using ACME)",
        "PATH",
    );
    opts.optopt(
        "",
        "ssl-key",
        "Path to SSL private key file (if not using ACME)",
        "PATH",
    );
    opts.optflag(
        "",
        "skip-privilege-check",
        "Skip privilege escalation check (for development)",
    );
    opts.optopt(
        "",
        "db",
        "Path to SQLite database for persistent storage (default: /opt/atlas/atlas.db)",
        "PATH",
    );
    opts.optflag(
        "",
        "doh-server",
        "Enable DNS-over-HTTPS server at /dns-query (enabled by default; kept for compatibility)",
    );
    opts.optflag(
        "",
        "no-doh-server",
        "Disable the DNS-over-HTTPS server at /dns-query",
    );
    opts.optflag(
        "",
        "dot",
        "Enable DNS-over-TLS server on port 853",
    );
    opts.optopt(
        "",
        "dot-cert",
        "Path to TLS certificate for DoT (default: /opt/atlas/certs/cert.pem)",
        "PATH",
    );
    opts.optopt(
        "",
        "dot-key",
        "Path to TLS private key for DoT (default: /opt/atlas/certs/key.pem)",
        "PATH",
    );
    opts.optflag(
        "",
        "doq",
        "Enable DNS-over-QUIC (DoQ) server on UDP port 853 (RFC 9250)",
    );
    opts.optopt(
        "",
        "doq-port",
        "UDP port for the DoQ server (default 853)",
        "PORT",
    );
    opts.optopt(
        "",
        "doq-cert",
        "Path to TLS certificate for DoQ (default: auto-generate self-signed)",
        "PATH",
    );
    opts.optopt(
        "",
        "doq-key",
        "Path to TLS private key for DoQ (default: auto-generate self-signed)",
        "PATH",
    );
    opts.optopt(
        "",
        "metrics-port",
        "Port for the Prometheus metrics HTTP server (default 9153)",
        "PORT",
    );
    opts.optflag(
        "",
        "no-metrics",
        "Disable the standalone Prometheus metrics HTTP server",
    );
    opts.optopt(
        "",
        "dnssec-validation",
        "DNSSEC validation mode: strict, opportunistic, or off (default: opportunistic)",
        "MODE",
    );
    opts.optflag(
        "",
        "threat-intel",
        "Enable threat intelligence feed blocking (abuse.ch, Spamhaus DROP/EDROP)",
    );
    opts.optopt(
        "",
        "threat-intel-refresh",
        "Threat intelligence feed refresh interval in seconds (default: 3600)",
        "SECS",
    );
    opts.optopt(
        "",
        "threat-intel-feeds",
        "Comma-separated list of additional threat feed URLs to load",
        "URLS",
    );
    opts.optopt(
        "",
        "threat-intel-block-action",
        "Block action for threat intel matches: nxdomain (default) or redirect:<IP>",
        "ACTION",
    );
    opts.optflag(
        "",
        "mdns",
        "Enable passive mDNS listener for local device discovery (port 5353)",
    );
    opts.optflag(
        "",
        "geoip",
        "Enable GeoIP enrichment for DNS query logs (requires MaxMind .mmdb)",
    );
    opts.optopt(
        "",
        "geoip-db",
        "Path to MaxMind GeoLite2-City.mmdb database (default: /opt/atlas/geoip/GeoLite2-City.mmdb)",
        "PATH",
    );
    opts.optflag(
        "",
        "cluster",
        "Enable HA clustering with gossip heartbeat and zone transfer",
    );
    opts.optopt(
        "",
        "cluster-peers",
        "Comma-separated list of peer addresses (e.g. http://node2:5380,http://node3:5380)",
        "PEERS",
    );
    opts.optopt(
        "",
        "cluster-role",
        "Cluster role: auto (default, uses leader election), primary, or secondary",
        "ROLE",
    );
    opts.optopt(
        "",
        "cluster-node-id",
        "Unique node ID for this cluster member (default: auto-generated UUID)",
        "ID",
    );

    let opt_matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            eprintln!("Error parsing arguments: {}", f);
            print_usage(&program, opts);
            std::process::exit(1);
        }
    };

    if opt_matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    // Check if we need elevated privileges for DNS port (53)
    let dns_port = 53u16; // Default DNS port
    let skip_privilege_check = opt_matches.opt_present("skip-privilege-check");
    
    if !skip_privilege_check && port_requires_privileges(dns_port) && !has_admin_privileges() {
        log::info!("DNS server requires elevated privileges to bind to port {}.", dns_port);
        log::info!("Attempting automatic privilege escalation...");
        
        match escalate_privileges() {
            Ok(_) => {
                // This should not be reached as escalate_privileges exits the process
                log::info!("Privilege escalation successful");
            }
            Err(e) => {
                log::warn!("Automatic privilege escalation failed: {}", e);
                log::info!("\n=== Administrator Privileges Required ===");
                log::info!("The DNS server needs to bind to port 53, which requires elevated privileges.");
                log::info!("\nPlease run the application with administrator/root privileges:");
                #[cfg(unix)]
                log::info!("  sudo {}", args.join(" "));
                #[cfg(windows)]
                log::info!("  Run as Administrator: {}", args.join(" "));
                log::info!("\nAlternatively, for development, you can skip this check with:");
                log::info!("  {} --skip-privilege-check", args[0]);
                log::info!("  (Note: The server may fail to bind to port 53 without privileges)");
                log::info!("========================================\n");
                std::process::exit(1);
            }
        }
    } else if skip_privilege_check && !has_admin_privileges() {
        log::warn!("Skipping privilege check - server may fail to bind to privileged ports");
    }

    let mut context = Arc::new(ServerContext::new().expect("Failed to initialize DNS server context"));

    if let Some(ctx) = Arc::get_mut(&mut context) {
        let mut index_rootservers = true;
        if opt_matches.opt_present("f") {
            match opt_matches
                .opt_str("f")
                .and_then(|x| x.parse::<Ipv4Addr>().ok())
            {
                Some(addr) => {
                    ctx.resolve_strategy = ResolveStrategy::Forward {
                        host: addr.to_string(),
                        port: 53,
                    };
                    index_rootservers = false;
                }
                None => {
                    log::info!("Forward address is not a valid IP - disabling forwarding");
                }
            }
        }

        if opt_matches.opt_present("x") {
            ctx.enable_api = false;
        }

        // DoH is enabled by default; --no-doh-server disables it
        if opt_matches.opt_present("no-doh-server") {
            ctx.doh_server_enabled = false;
        }

        if opt_matches.opt_present("no-metrics") {
            ctx.metrics_enabled = false;
        }

        if let Some(port_str) = opt_matches.opt_str("metrics-port") {
            match port_str.parse::<u16>() {
                Ok(p) => ctx.metrics_port = p,
                Err(_) => log::warn!("Invalid --metrics-port value '{}', using default {}", port_str, ctx.metrics_port),
            }
        }

        // Configure DNSSEC validation mode (default: opportunistic, enabled)
        {
            let (mode, enabled) = match opt_matches.opt_str("dnssec-validation")
                .as_deref()
                .unwrap_or("opportunistic")
            {
                "strict"        => (ValidationMode::Strict,        true),
                "opportunistic" => (ValidationMode::Opportunistic, true),
                "off"           => (ValidationMode::Off,           false),
                other => {
                    log::warn!("Unknown --dnssec-validation value '{}'; using opportunistic", other);
                    (ValidationMode::Opportunistic, true)
                }
            };
            ctx.dnssec_enabled = enabled;
            ctx.dnssec_validation_mode = mode;
            if let Err(e) = ctx.authority.set_validation_mode(mode) {
                log::warn!("Failed to set DNSSEC validation mode: {}", e);
            }
            log::info!("DNSSEC validation: {:?} (enabled={})", mode, enabled);
        }

        match opt_matches.opt_str("j") {
            Some(zones_dir) => {
                ctx.zones_dir = Arc::from(zones_dir.as_str());
            }
            None => {
                log::info!("Zones dir not specified, using default: {}", ctx.zones_dir);
            }
        }
        
        // Configure SSL if enabled
        if opt_matches.opt_present("s") {
            ctx.ssl_config.enabled = true;
            
            // Check for ACME configuration
            if let (Some(email), Some(domains)) = (
                opt_matches.opt_str("acme-email"),
                opt_matches.opt_str("acme-domains")
            ) {
                let provider = match opt_matches.opt_str("acme-provider").as_deref() {
                    Some("letsencrypt") => AcmeProvider::LetsEncrypt,
                    Some("letsencrypt-staging") => AcmeProvider::LetsEncryptStaging,
                    Some("zerossl") => AcmeProvider::ZeroSSL,
                    _ => AcmeProvider::LetsEncrypt, // Default to Let's Encrypt
                };
                
                let domain_list: Vec<String> = domains.split(',').map(|s| s.trim().to_string()).collect();
                
                ctx.ssl_config.acme = Some(AcmeConfig {
                    provider: provider.clone(),
                    email,
                    domains: domain_list,
                    ..Default::default()
                });
                
                log::info!("ACME configured with provider: {:?}", provider);

                // Obtain certificate on startup if missing or expiring
                // (clone config before ctx is moved into Arc)
                let acme_cfg_startup = ctx.ssl_config.acme.clone();
                if let Some(ref acme_cfg) = acme_cfg_startup {
                    // We need a temporary Arc for the manager; we'll build it from ctx directly
                    // Note: ctx is not yet Arc'd here, so we use a dummy context approach:
                    // Just log that renewal will be handled post-startup via the renewal thread.
                    log::info!("ACME renewal thread will start after server context is ready");
                    let _ = acme_cfg; // used below after Arc::new(ctx)
                }
            } 
            // Check for manual certificate configuration
            else if let (Some(cert), Some(key)) = (
                opt_matches.opt_str("ssl-cert"),
                opt_matches.opt_str("ssl-key")
            ) {
                ctx.ssl_config.cert_path = Some(cert.into());
                ctx.ssl_config.key_path = Some(key.into());
                log::info!("SSL configured with manual certificate");
            } else {
                log::warn!("SSL enabled but no certificate configuration provided");
                ctx.ssl_config.enabled = false;
            }
        }

        // Skip trying to load zones from network - function not available

        // Attach persistent storage (create DB if it doesn't exist)
        let db_path = opt_matches.opt_str("db")
            .unwrap_or_else(|| "/opt/atlas/atlas.db".to_string());
        match ctx.attach_storage(&db_path) {
            Ok(_) => log::info!("Persistent storage ready at {}", db_path),
            Err(e) => {
                log::warn!("Could not attach persistent storage ({}): running in-memory only", e);
            }
        }

        match ctx.initialize() {
            Ok(_) => {}
            Err(e) => {
                log::info!("Server failed to initialize: {:?}", e);
                return;
            }
        }

        if index_rootservers {
            let _ = ctx.cache.store(&get_rootservers());
        }

        // Initialize threat intelligence if enabled
        if opt_matches.opt_present("threat-intel") {
            let refresh_secs = opt_matches.opt_str("threat-intel-refresh")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(3600);

            // Parse custom feed URLs from --threat-intel-feeds
            let custom_feeds: Vec<atlas::dns::security::threat_intel::CustomFeed> =
                opt_matches.opt_str("threat-intel-feeds")
                    .map(|s| {
                        s.split(',')
                            .filter(|u| !u.is_empty())
                            .enumerate()
                            .map(|(i, url)| atlas::dns::security::threat_intel::CustomFeed {
                                id: format!("custom_{}", i + 1),
                                name: format!("Custom Feed {}", i + 1),
                                url: url.trim().to_string(),
                                category: atlas::dns::security::threat_intel::ThreatCategory::Unknown,
                            })
                            .collect()
                    })
                    .unwrap_or_default();

            // Parse block action
            let block_action = match opt_matches.opt_str("threat-intel-block-action").as_deref() {
                Some(s) if s.starts_with("redirect:") => {
                    atlas::dns::security::threat_intel::BlockAction::RedirectIp(
                        s.trim_start_matches("redirect:").to_string()
                    )
                }
                Some("refused") => atlas::dns::security::threat_intel::BlockAction::Refused,
                _ => atlas::dns::security::threat_intel::BlockAction::Nxdomain,
            };

            let cache_dir = opt_matches.opt_str("db")
                .as_deref()
                .and_then(|p| std::path::Path::new(p).parent())
                .and_then(|p| p.to_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "/opt/atlas".to_string());
            let cache_path = format!("{}/threat_intel_cache.json", cache_dir);

            let ti_config = ThreatIntelConfig {
                enabled: true,
                update_interval: std::time::Duration::from_secs(refresh_secs),
                custom_feeds,
                block_action,
                cache_path: Some(cache_path.clone()),
                ..ThreatIntelConfig::default()
            };

            let ti = Arc::new(ThreatIntelManager::new(ti_config));
            ctx.threat_intel = Some(ti.clone());

            // Try loading from flat-file cache first; fall back to HTTP fetch
            let cache_age = std::time::Duration::from_secs(refresh_secs);
            let cache_loaded = ti.load_cache(&cache_path, cache_age);
            if !cache_loaded {
                // Initial feed fetch (blocking, before server starts)
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                if let Ok(rt) = rt {
                    rt.block_on(async {
                        let results = ti.refresh_all().await;
                        for (id, res) in &results {
                            match res {
                                Ok(n) => log::info!("[THREAT-INTEL] Feed '{}' loaded {} entries", id, n),
                                Err(e) => log::warn!("[THREAT-INTEL] Feed '{}' failed: {}", id, e),
                            }
                        }
                    });
                }
            }

            log::info!(
                "[THREAT-INTEL] Enabled: {} domains + {} IP blocks loaded; refresh every {}s",
                ti.total_domains(), ti.total_ip_blocks(), refresh_secs
            );

            // Spawn background auto-refresh thread
            let ti_bg = ti.clone();
            thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("tokio runtime for threat-intel auto-update");
                rt.block_on(async move {
                    // start_auto_update spawns a tokio task; keep the runtime alive
                    ti_bg.start_auto_update();
                    // Park this thread forever so the runtime stays alive for the spawned task
                    std::future::pending::<()>().await;
                });
            });
        }
    }

    // Start ACME certificate renewal background thread
    if let Some(acme_cfg) = context.ssl_config.acme.clone() {
        let acme_context = context.clone();
        atlas::dns::acme::AcmeCertificateManager::start_renewal_thread(acme_cfg, acme_context);
        log::info!("ACME certificate renewal thread started (checks daily)");
    }

    // Initialize GeoIP enrichment if requested
    if opt_matches.opt_present("geoip") {
        let db_path = opt_matches.opt_str("geoip-db")
            .unwrap_or_else(|| "/opt/atlas/geoip/GeoLite2-City.mmdb".to_string());
        let geoip_config = atlas::geoip::GeoIpConfig {
            enabled: true,
            database_path: std::path::PathBuf::from(&db_path),
        };
        match atlas::geoip::try_load(&geoip_config) {
            Some(db) => {
                if let Some(ctx) = Arc::get_mut(&mut context) {
                    ctx.geoip = Some(db);
                }
                log::info!("[GeoIP] Query log enrichment enabled (db: {})", db_path);
            }
            None => {
                log::warn!("[GeoIP] Failed to load database from {}; enrichment disabled", db_path);
            }
        }
    }

    // Start passive mDNS listener if requested
    if opt_matches.opt_present("mdns") {
        let registry = Arc::new(MdnsRegistry::new());
        if let Some(ctx) = Arc::get_mut(&mut context) {
            ctx.mdns_registry = Some(registry.clone());
        }
        thread::spawn(move || {
            let listener = MdnsListener::new(registry);
            listener.run();
        });
        log::info!("mDNS passive listener enabled — local device discovery active");
    }

    // Enable HA clustering if requested
    if opt_matches.opt_present("cluster") {
        let peers: Vec<String> = opt_matches.opt_str("cluster-peers")
            .map(|s| s.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect())
            .unwrap_or_default();

        let role = match opt_matches.opt_str("cluster-role").as_deref() {
            Some("primary") => ClusterRole::Primary,
            Some("secondary") => ClusterRole::Replica,
            _ => ClusterRole::Candidate, // "auto" — use leader election
        };

        let node_id = opt_matches.opt_str("cluster-node-id")
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let quorum = peers.len().div_ceil(2) + 1; // majority quorum

        let cluster_config = ClusterConfig {
            enabled: true,
            role,
            node_id: node_id.clone(),
            peer_addresses: peers.clone(),
            heartbeat_interval_secs: 5,
            quorum,
            peer_timeout_secs: 15,
            ..ClusterConfig::default()
        };

        if let Some(ctx) = Arc::get_mut(&mut context) {
            ctx.enable_clustering(cluster_config);
        }

        if let Some(cm) = &context.cluster_manager {
            // Register self in cluster state
            let self_addr = format!("0.0.0.0:{}", CLUSTER_GOSSIP_PORT);
            cm.cluster_state.upsert(atlas::dns::clustering::ClusterNode::new(
                node_id.clone(), self_addr, role,
            ));

            // Spawn UDP heartbeat listener
            let cm_listener = cm.clone();
            let bind_addr = format!("0.0.0.0:{}", CLUSTER_GOSSIP_PORT);
            thread::spawn(move || {
                cm_listener.run_udp_listener(&bind_addr);
            });

            // Spawn heartbeat sender
            let cm_sender = cm.clone();
            thread::spawn(move || {
                cm_sender.run_heartbeat_sender();
            });

            // If this is a secondary/replica, request initial zone transfer from primary
            let is_secondary = matches!(role, ClusterRole::Replica | ClusterRole::Follower);
            if is_secondary && !peers.is_empty() {
                let cm_xfr = cm.clone();
                let ctx_xfr = context.clone();
                let peers_xfr = peers.clone();
                thread::spawn(move || {
                    // Give primary a moment to start
                    std::thread::sleep(std::time::Duration::from_secs(3));
                    for peer in &peers_xfr {
                        let xfr_addr = format!(
                            "{}:{}",
                            peer.trim_start_matches("http://")
                                .trim_start_matches("https://")
                                .split('/')
                                .next()
                                .unwrap_or("")
                                .split(':')
                                .next()
                                .unwrap_or(""),
                            CLUSTER_ZONE_TRANSFER_PORT
                        );
                        if let Some(payload) = cm_xfr.request_zone_transfer(&xfr_addr) {
                            // Apply received zones to authority
                            apply_zone_transfer(&ctx_xfr, &payload);
                            log::info!("[cluster] initial zone transfer complete: {} zones", payload.zones.len());
                            break;
                        }
                    }
                });
            }

            // If this is a primary, start zone transfer server
            let is_primary = matches!(role, ClusterRole::Primary | ClusterRole::Leader);
            if is_primary {
                let cm_srv = cm.clone();
                let ctx_srv = context.clone();
                let bind = format!("0.0.0.0:{}", CLUSTER_ZONE_TRANSFER_PORT);
                thread::spawn(move || {
                    cm_srv.run_zone_transfer_server(&bind, move || {
                        build_zone_transfer_payload(&ctx_srv)
                    });
                });
            }

            log::info!(
                "[cluster] HA clustering enabled: node_id={}, role={:?}, peers={}, gossip_port={}, xfr_port={}",
                node_id, role, peers.len(), CLUSTER_GOSSIP_PORT, CLUSTER_ZONE_TRANSFER_PORT
            );
        }
    }

    log::info!("Listening on port {}", context.dns_port);

    // Start DNS servers in background threads
    let mut dns_handles = Vec::new();

    if context.enable_udp {
        let ctx = context.clone();
        let handle = thread::spawn(move || {
            let udp_server = DnsUdpServer::new(ctx.clone(), 20);
            match udp_server.run_server() {
                Ok(_) => log::info!("UDP DNS server completed"),
                Err(e) => {
                    log::error!("Failed to bind UDP DNS server on port {}: {:?}", ctx.dns_port, e);
                    sentry::capture_message(&format!("UDP DNS server failed to bind on port {}: {:?}", ctx.dns_port, e), sentry::Level::Error);
                }
            }
        });
        dns_handles.push(handle);
        log::info!("UDP DNS server started successfully on port {}", context.dns_port);
    }

    if context.enable_tcp {
        let ctx = context.clone();
        let handle = thread::spawn(move || {
            let tcp_server = DnsTcpServer::new(ctx.clone(), 20);
            match tcp_server.run_server() {
                Ok(_) => log::info!("TCP DNS server completed"),
                Err(e) => {
                    log::error!("Failed to bind TCP DNS server on port {}: {:?}", ctx.dns_port, e);
                    sentry::capture_message(&format!("TCP DNS server failed to bind on port {}: {:?}", ctx.dns_port, e), sentry::Level::Error);
                }
            }
        });
        dns_handles.push(handle);
        log::info!("TCP DNS server started successfully on port {}", context.dns_port);
    }

    // Start DNS-over-TLS server on port 853 if enabled
    if opt_matches.opt_present("dot") {
        // Resolution order: --dot-cert/--dot-key CLI flags → TLS_CERT_PATH/TLS_KEY_PATH env
        // vars → auto-generate self-signed (handled inside DotServer::new).
        let dot_config = DotConfig {
            enabled: true,
            cert_path: opt_matches.opt_str("dot-cert")
                .or_else(|| std::env::var("TLS_CERT_PATH").ok()),
            key_path: opt_matches.opt_str("dot-key")
                .or_else(|| std::env::var("TLS_KEY_PATH").ok()),
            ..DotConfig::default()
        };
        let ctx = context.clone();
        match DotServer::new(ctx.clone(), dot_config) {
            Ok(dot_server) => {
                if let Some(ctx_mut) = Arc::get_mut(&mut context) {
                    ctx_mut.dot_enabled = true;
                }
                thread::spawn(move || {
                    if let Err(e) = dot_server.run() {
                        log::error!("DNS-over-TLS server error: {:?}", e);
                    }
                });
                log::info!("DNS-over-TLS (rustls) server started on port 853");
            }
            Err(e) => {
                log::warn!("Failed to start DNS-over-TLS server: {:?}", e);
            }
        }
    }

    // Start DNS-over-QUIC server on UDP port 853 if enabled (RFC 9250)
    if opt_matches.opt_present("doq") {
        let doq_port = opt_matches.opt_str("doq-port")
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(853);
        let doq_config = DoqConfig {
            enabled: true,
            port: doq_port,
            cert_path: opt_matches.opt_str("doq-cert")
                .or_else(|| std::env::var("DOQ_CERT_PATH").ok()),
            key_path: opt_matches.opt_str("doq-key")
                .or_else(|| std::env::var("DOQ_KEY_PATH").ok()),
            ..DoqConfig::default()
        };
        let ctx = context.clone();
        thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime for DoQ server");
            rt.block_on(async move {
                let mut server = match DoqServer::new(ctx, doq_config) {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("Failed to create DoQ server: {:?}", e);
                        return;
                    }
                };
                if let Err(e) = server.initialize().await {
                    log::error!("Failed to initialize DoQ server: {:?}", e);
                    return;
                }
                if let Err(e) = server.start().await {
                    log::error!("DoQ server error: {:?}", e);
                }
            });
        });
        log::info!("DNS-over-QUIC (DoQ) server started on UDP port {}", doq_port);
    }

    // Start dedicated Prometheus metrics server (port 9153 by default)
    if context.metrics_enabled {
        let ctx = context.clone();
        thread::spawn(move || {
            PrometheusServer::new(ctx).run();
        });
        log::info!("Prometheus metrics server started on port {}", context.metrics_port);
    }

    // Start web server (this blocks to keep the process alive)
    if context.enable_api {
        let webserver = WebServer::new(context.clone());
        log::info!("Starting web server - this will keep the process alive for DNS servers");
        webserver.run_webserver(true);
    } else {
        log::info!("Web server disabled, waiting for DNS servers to complete...");
        // Wait for all DNS server threads to complete
        for handle in dns_handles {
            if let Err(e) = handle.join() {
                log::error!("DNS server thread panicked: {:?}", e);
            }
        }
        log::info!("All DNS servers have stopped");
    }
}

/// Build a ZoneTransferPayload from the current authority zones.
fn build_zone_transfer_payload(ctx: &Arc<ServerContext>) -> Option<ZoneTransferPayload> {
    let zones_guard = match ctx.authority.read() {
        Ok(z) => z,
        Err(_) => return None,
    };
    let zone_list = zones_guard.zones();
    if zone_list.is_empty() {
        return None;
    }

    let entries: Vec<ZoneTransferEntry> = zone_list.iter().map(|zone| {
        let records: Vec<String> = zone.records.iter()
            .filter_map(|r| serde_json::to_string(r).ok())
            .collect();
        ZoneTransferEntry {
            domain: zone.domain.clone(),
            m_name: zone.m_name.clone(),
            r_name: zone.r_name.clone(),
            serial: zone.serial,
            refresh: zone.refresh,
            retry: zone.retry,
            expire: zone.expire,
            minimum: zone.minimum,
            records,
        }
    }).collect();

    Some(ZoneTransferPayload {
        from_node_id: String::new(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        zones: entries,
    })
}

/// Apply a received zone transfer payload to the authority.
fn apply_zone_transfer(ctx: &Arc<ServerContext>, payload: &ZoneTransferPayload) {
    for entry in &payload.zones {
        // Create zone if it doesn't exist
        if !ctx.authority.zone_exists(&entry.domain) {
            if let Err(e) = ctx.authority.create_zone(&entry.domain, &entry.m_name, &entry.r_name) {
                log::error!("[cluster/xfr] failed to create zone {}: {:?}", entry.domain, e);
                continue;
            }
        }

        // Apply records
        for record_json in &entry.records {
            if let Ok(record) = serde_json::from_str::<atlas::dns::protocol::DnsRecord>(record_json) {
                if let Err(e) = ctx.authority.upsert(&entry.domain, record) {
                    log::warn!("[cluster/xfr] failed to upsert record in {}: {:?}", entry.domain, e);
                }
            }
        }
        log::info!("[cluster/xfr] applied zone {} ({} records)", entry.domain, entry.records.len());
    }
}

/// Returns the DNS records for all 13 root nameservers
/// 
/// This function creates NS, A, and AAAA records for the 13 root servers (a-m.root-servers.net)
/// as defined by IANA. These records are essential for DNS resolution when starting from scratch.
fn get_rootservers() -> Vec<DnsRecord> {
    // Root server data: (letter, IPv4, IPv6)
    const ROOT_SERVERS: &[(&str, &str, Option<&str>)] = &[
        ("a", "198.41.0.4", Some("2001:503:ba3e::2:30")),
        ("b", "192.228.79.201", Some("2001:500:84::b")),
        ("c", "192.33.4.12", Some("2001:500:2::c")),
        ("d", "199.7.91.13", Some("2001:500:2d::d")),
        ("e", "192.203.230.10", Some("2001:500:a8::e")),
        ("f", "192.5.5.241", Some("2001:500:2f::f")),
        ("g", "192.112.36.4", None),  // No IPv6 for g.root-servers.net
        ("h", "128.63.2.53", Some("2001:500:1::803f:235")),
        ("i", "192.36.148.17", Some("2001:7fe::53")),
        ("j", "192.58.128.30", Some("2001:503:c27::2:30")),
        ("k", "193.0.14.129", Some("2001:7fd::1")),
        ("l", "199.7.83.42", Some("2001:500:3::42")),
        ("m", "202.12.27.33", Some("2001:dc3::35")),
    ];
    
    const ROOT_TTL: u32 = 3600000; // 1000 hours
    let mut rootservers = Vec::with_capacity(ROOT_SERVERS.len() * 3);
    
    for &(letter, ipv4, ipv6_opt) in ROOT_SERVERS {
        let hostname = format!("{}.root-servers.net", letter);
        
        // Add NS record pointing to this root server
        rootservers.push(DnsRecord::Ns {
            domain: String::new(), // Root domain
            host: hostname.clone(),
            ttl: TransientTtl(ROOT_TTL),
        });
        
        // Add A (IPv4) record
        rootservers.push(DnsRecord::A {
            domain: hostname.clone(),
            addr: ipv4.parse().expect("Invalid IPv4 address for root server"),
            ttl: TransientTtl(ROOT_TTL),
        });
        
        // Add AAAA (IPv6) record if available
        if let Some(ipv6) = ipv6_opt {
            rootservers.push(DnsRecord::Aaaa {
                domain: hostname,
                addr: ipv6.parse().expect("Invalid IPv6 address for root server"),
                ttl: TransientTtl(ROOT_TTL),
            });
        }
    }
    
    rootservers
}

/// Handle the `atlas bench` subcommand.
fn run_bench_subcommand(args: &[String]) {
    let mut opts = getopts::Options::new();
    opts.optopt("", "count", "Number of queries to send (default: 1000)", "N");
    opts.optopt("", "domain", "Domain to query (default: google.com)", "DOMAIN");
    opts.optopt("", "server", "DNS server to target (default: 127.0.0.1)", "IP");
    opts.optopt("", "port", "DNS server port (default: 53)", "PORT");
    opts.optopt("", "type", "Query type: A, AAAA, MX, etc. (default: A)", "TYPE");
    opts.optopt("", "timeout", "Query timeout in ms (default: 2000)", "MS");
    opts.optflag("h", "help", "Print bench help");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("{}", opts.usage("Usage: atlas bench [options]"));
            std::process::exit(1);
        }
    };

    if matches.opt_present("h") {
        println!("{}", opts.usage("Usage: atlas bench [options]"));
        return;
    }

    let count = matches.opt_str("count")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(1000);

    let domain = matches.opt_str("domain")
        .unwrap_or_else(|| "google.com".to_string());

    let server = matches.opt_str("server")
        .unwrap_or_else(|| "127.0.0.1".to_string());

    let port = matches.opt_str("port")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(53);

    let timeout = matches.opt_str("timeout")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(2000);

    let qtype = match matches.opt_str("type").as_deref() {
        Some("AAAA") | Some("aaaa") => QueryType::Aaaa,
        Some("MX") | Some("mx") => QueryType::Mx,
        Some("NS") | Some("ns") => QueryType::Ns,
        Some("CNAME") | Some("cname") => QueryType::Cname,
        Some("TXT") | Some("txt") => QueryType::Txt,
        Some("SOA") | Some("soa") => QueryType::Soa,
        Some("SRV") | Some("srv") => QueryType::Srv,
        _ => QueryType::A,
    };

    let config = BenchConfig {
        server,
        port,
        domain,
        query_type: qtype,
        count,
        timeout_ms: timeout,
    };

    let results = run_bench(&config);
    results.print_report();

    std::process::exit(if results.failed == results.total { 1 } else { 0 });
}