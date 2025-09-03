use std::env;
use std::net::Ipv4Addr;
use std::sync::Arc;

use getopts::Options;
extern crate sentry;

use atlas::dns::protocol::{DnsRecord, TransientTtl};
use atlas::dns::context::{ResolveStrategy, ServerContext};
use atlas::dns::server::{DnsServer, DnsTcpServer, DnsUdpServer};
use atlas::dns::acme::{AcmeConfig, AcmeProvider};
use atlas::web::server::WebServer;
use atlas::privilege_escalation::{has_admin_privileges, escalate_privileges, port_requires_privileges};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

/// Main entry point for the Atlas DNS server
fn main() {
    // Initialize Sentry for error tracking and monitoring
    let _guard = sentry::init("http://5ec005d5f2b84ed5a5d4ce190900dc5e@sentry.alpha.opensam.foundation/4");
    
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
                scope.set_tag("panic_line", &location.line().to_string());
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
    
    simple_logger::init().expect("Failed to initialize logger");
    
    log::info!("Atlas DNS Server starting with Sentry monitoring enabled");

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

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

    let opt_matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!("{}", f.to_string()),
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
    }

    log::info!("Listening on port {}", context.dns_port);

    // Start DNS servers
    if context.enable_udp {
        let udp_server = DnsUdpServer::new(context.clone(), 20);
        if let Err(e) = udp_server.run_server() {
            log::info!("Failed to bind UDP listener: {:?}", e);
        }
    }

    if context.enable_tcp {
        let tcp_server = DnsTcpServer::new(context.clone(), 20);
        if let Err(e) = tcp_server.run_server() {
            log::info!("Failed to bind TCP listener: {:?}", e);
        }
    }

    // Start web server
    if context.enable_api {
        let webserver = WebServer::new(context.clone());
        webserver.run_webserver(true);
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