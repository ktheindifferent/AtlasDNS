# Atlas DNS Server - Codebase Documentation

## Project Overview

Atlas is a high-performance DNS server implementation in Rust with built-in SSL/TLS support, automatic certificate management via ACME protocol, and a comprehensive web-based management interface. The project is designed as an authoritative DNS server with recursive resolution capabilities and includes user authentication and session management.

## Codebase Structure

```
/root/repo/
├── src/
│   ├── bin/
│   │   └── atlas.rs              # Main application entry point
│   ├── dns/                      # DNS server implementation
│   │   ├── acme.rs              # ACME certificate management
│   │   ├── authority.rs         # Authoritative zone handling
│   │   ├── buffer.rs            # Buffer utilities for DNS packets
│   │   ├── cache.rs             # DNS response caching
│   │   ├── client.rs            # DNS client for recursive queries
│   │   ├── context.rs           # Server context and configuration
│   │   ├── error_utils.rs       # Error handling utilities
│   │   ├── errors.rs            # DNS error definitions
│   │   ├── health.rs            # Health check endpoints
│   │   ├── mod.rs               # Module definitions
│   │   ├── netutil.rs           # Network utilities
│   │   ├── protocol.rs          # DNS protocol implementation
│   │   ├── query_type.rs        # DNS query type definitions
│   │   ├── rate_limit.rs        # Rate limiting implementation
│   │   ├── record_parsers.rs    # DNS record parsing
│   │   ├── resolve.rs           # DNS resolution logic
│   │   ├── result_code.rs       # DNS result codes
│   │   ├── server.rs            # Core DNS server
│   │   └── server_enhanced.rs   # Enhanced server features
│   ├── web/                      # Web interface and API
│   │   ├── authority.rs         # Zone management API
│   │   ├── cache.rs             # Cache management API
│   │   ├── index.rs             # Main web routes
│   │   ├── mod.rs               # Web module definitions
│   │   ├── server.rs            # HTTP/HTTPS server
│   │   ├── sessions.rs          # Session management
│   │   ├── templates/           # HTML templates (Handlebars)
│   │   │   ├── authority.html   # Zone management UI
│   │   │   ├── cache.html       # Cache view UI
│   │   │   ├── index.html       # Dashboard
│   │   │   ├── layout.html      # Base layout template
│   │   │   ├── login.html       # Login page
│   │   │   ├── profile.html     # User profile page
│   │   │   ├── sessions.html    # Session management UI
│   │   │   ├── users.html       # User management UI
│   │   │   └── zone.html        # Zone editor UI
│   │   ├── users.rs             # User management system
│   │   └── util.rs              # Web utilities
│   ├── lib.rs                    # Library entry point
│   └── privilege_escalation.rs   # Privilege management for port binding
├── config/
│   └── ssl-example.json         # SSL configuration example
├── Cargo.toml                   # Rust dependencies
├── Cargo.lock                   # Dependency lock file
├── Dockerfile                   # Container build configuration
├── docker-compose.yml           # Container orchestration
├── captain-definition           # CapRover deployment config
└── README.md                    # Project documentation
```

## Key Components

### DNS Server (`src/dns/`)
- **Protocol Implementation**: Full DNS protocol support for UDP and TCP
- **Authoritative Zones**: Management of DNS zones with support for A, AAAA, NS, CNAME, MX, TXT, and other record types
- **Recursive Resolution**: Can act as a recursive resolver with forwarding support
- **Caching**: Built-in response caching with TTL management
- **Rate Limiting**: Protection against DNS amplification attacks
- **ACME Integration**: Automatic SSL certificate management via Let's Encrypt and ZeroSSL

### Web Interface (`src/web/`)
- **User Management**: Multi-user support with role-based access (Admin, User, ReadOnly)
- **Session Management**: Secure session handling with expiration
- **Zone Management**: Web-based DNS zone editing
- **Cache Viewer**: Monitor and manage DNS cache
- **Dashboard**: Real-time server statistics and monitoring
- **Bootstrap 5 UI**: Modern, responsive web interface

### Security Features
- **Privilege Escalation**: Automatic privilege handling for binding to port 53
- **SSL/TLS Support**: HTTPS for web interface with automatic certificate renewal
- **User Authentication**: Secure password hashing (SHA256)
- **Session Security**: Token-based authentication with IP validation
- **Rate Limiting**: Protection against abuse

## Dependencies

### Core Dependencies
- `chrono` (0.4.13): Date and time handling
- `handlebars` (3.3.0): HTML templating engine
- `tiny_http` (0.11.0): HTTP server with SSL support
- `tokio` (1.x): Async runtime
- `serde` (1.0.114): Serialization/deserialization
- `uuid` (1.4): Unique identifier generation
- `sha2` (0.10): Cryptographic hashing

### Security & Networking
- `openssl` (0.10): SSL/TLS support
- `reqwest` (0.11): HTTP client for ACME
- `parking_lot` (0.12): Synchronization primitives
- `sudo` (0.6): Privilege escalation

### Utilities
- `log` (0.4.14): Logging framework
- `simple_logger`: Console logging
- `regex` (1.3.9): Regular expressions
- `base64` (0.13): Base64 encoding/decoding
- `getopts` (0.2.21): Command-line argument parsing

## Data Storage

The application uses in-memory storage for:
- **User Database**: HashMap-based user storage with RwLock for thread safety
- **Session Store**: In-memory session management with automatic expiration
- **DNS Cache**: TTL-based cache for DNS responses
- **Zone Files**: File-based zone storage (configurable directory)

## Configuration

### Command-Line Options
- `--ssl, -s`: Enable SSL/TLS for web server
- `--acme-provider <PROVIDER>`: ACME provider selection
- `--acme-email <EMAIL>`: ACME registration email
- `--acme-domains <DOMAINS>`: Certificate domains (comma-separated)
- `--ssl-cert <PATH>`: Manual SSL certificate path
- `--ssl-key <PATH>`: Manual SSL private key path
- `--forward-address, -f <IP>`: Upstream DNS server for forwarding
- `--disable-api, -x`: Disable web interface
- `--zones-dir, -j <DIR>`: Zone files directory
- `--skip-privilege-check`: Skip privilege escalation (development)

### Default Ports
- **DNS**: Port 53 (UDP/TCP)
- **HTTP**: Port 5380
- **HTTPS**: Port 5343 (when SSL enabled)

### Certificate Storage
- Default location: `/opt/atlas/certs/`
- Files: `cert.pem`, `key.pem`, `account.pem`

## Build and Run Instructions

### Building
```bash
cargo build --release
```

### Running Examples

Basic DNS server:
```bash
./atlas
```

With SSL and Let's Encrypt:
```bash
./atlas --ssl --acme-provider letsencrypt --acme-email admin@example.com --acme-domains example.com
```

With forwarding to Google DNS:
```bash
./atlas -f 8.8.8.8
```

### Docker Deployment
```bash
docker-compose up -d
```

## Development Notes

### Architecture Decisions
- **Rust**: Chosen for memory safety and performance
- **In-Memory Storage**: Fast access, suitable for DNS operations
- **Handlebars Templates**: Server-side rendering for web UI
- **Bootstrap 5**: Modern, responsive UI framework

### Security Considerations
- Automatic privilege escalation for port 53 binding
- DNSSEC support planned but not yet implemented
- Rate limiting to prevent DNS amplification attacks
- Secure session management with token rotation

### Testing
Run tests with:
```bash
cargo test
```

Run with logging:
```bash
RUST_LOG=debug ./atlas
```

## Recent Updates
- Added comprehensive user authentication and session management
- Revamped UI with Bootstrap 5 for better user experience
- Enhanced DNS zone management interface
- Improved error handling and logging throughout the codebase

## Known Limitations
- In-memory storage (no persistence across restarts for users/sessions)
- DNSSEC not yet implemented
- Limited to DNS-01 challenge for ACME (no HTTP-01 support)

## Future Enhancements
- Database backend for persistent storage
- DNSSEC support
- Clustering and replication
- Advanced analytics and monitoring
- API rate limiting per user
- Zone transfer (AXFR/IXFR) support