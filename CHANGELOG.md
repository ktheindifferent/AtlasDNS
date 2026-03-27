# Changelog

All notable changes to Atlas DNS are documented in this file.

## [Unreleased] — 2026-03-27

### Stability & Polish
- Verified zero compiler warnings across the entire codebase
- Added CHANGELOG.md with comprehensive feature history
- Updated README.md with full feature table, config reference, and API summary
- Added resolver-level integration test scaffolding
- Updated Cargo.toml metadata (description, repository, license)

## [0.0.1] — 2026-03-27

### Core DNS
- Full DNS protocol implementation (UDP + TCP) with zero-copy packet parser
- Authoritative zone management with file-based persistence
- Recursive resolution with QNAME minimization (RFC 7816)
- Forwarding to upstream resolvers with configurable strategy
- Response caching with TTL management and adaptive eviction
- EDNS(0) support (RFC 6891) including client-subnet option
- Dynamic DNS updates (RFC 2136)
- CNAME flattening at zone apex
- Split-horizon / DNS views (different answers per client network)
- Zone transfer (AXFR) support
- Zone file parser compatible with BIND format
- Wildcard record support

### DNSSEC
- Full chain-of-trust validation (RFC 4034 / 4035 / 5155)
- Strict, opportunistic, and off validation modes
- Supported algorithms: RSA/SHA-256, RSA/SHA-512, ECDSA P-256, ECDSA P-384, Ed25519
- DNSKEY, RRSIG, DS, NSEC, NSEC3 record parsing and validation
- Automatic zone signing with KSK/ZSK generation and key rollover
- Authenticated denial of existence (NSEC + NSEC3)
- AD flag and CD bit handling

### Encrypted DNS
- **DNS-over-HTTPS (DoH)** — RFC 8484 with HTTP/2 connection pooling
- **DNS-over-TLS (DoT)** — RFC 7858 on port 853 via rustls
- **DNS-over-QUIC (DoQ)** — RFC 9250 via quinn/QUIC transport

### Security & Protection
- Rate limiting with per-client token bucket
- DDoS protection and traffic analysis
- Cache poisoning countermeasures (source-port randomization, 0x20 encoding)
- DNS rebinding protection
- Response Policy Zones (RPZ) for threat blocking
- SQL injection protection for API inputs
- CSRF protection on web endpoints
- Source validation and request-size limits
- Certificate Transparency log monitoring

### Blocklists & Filtering
- Blocklist engine with Bloom-filter acceleration
- Automatic blocklist updater (fetch, parse, merge popular ad/malware lists)
- Pi-hole v3/v4/v5 compatible API (`/admin/api.php`)
- Per-client allow/deny rules
- Captive portal detection support

### ACME / TLS Certificate Management
- Automatic certificate provisioning via Let's Encrypt and ZeroSSL
- DNS-01 challenge solver using built-in authoritative server
- Auto-renewal 30 days before expiry
- Manual certificate path support
- Real ACME v2 protocol via `instant-acme`

### Kubernetes Operator
- Custom Resource Definition: `DnsZone` / `DnsRecord`
- Reconciliation loop watches CRD changes and syncs to authority store
- Feature-gated behind `k8s` Cargo feature

### mDNS / Service Discovery
- Multicast DNS responder and browser (RFC 6762)
- Service registration and discovery via `mdns-sd`

### GeoIP & Traffic Steering
- MaxMind GeoIP2 database integration
- Geo-load balancing: route queries to nearest endpoint
- Proximity routing and multi-region failover
- Weighted and latency-based traffic steering

### High-Availability Clustering
- Cluster membership with heartbeat protocol
- Zone replication across nodes
- Leader election for write coordination
- Intelligent failover with health-check analytics

### Anomaly Detection & Threat Intelligence
- Statistical anomaly detector (query-rate spikes, entropy analysis)
- Threat intelligence feed integration
- Alert management with configurable thresholds
- DNS tunnel detection heuristics

### Observability
- Prometheus metrics endpoint on port 9153
- Structured query logging (JSON) with tracing spans
- OpenTelemetry / distributed tracing support
- Grafana dashboard templates
- Real-time WebSocket event stream
- Latency analytics and performance optimizer

### Web Management Interface
- Bootstrap 5 responsive dashboard
- Zone and record CRUD via UI
- User management (Admin / User / ReadOnly roles)
- Session management with token rotation
- Cache viewer and manual flush
- Activity log and audit trail
- Dark mode support

### API
- RESTful API v2 — full CRUD for zones, records, users, sessions
- GraphQL API (async-graphql) with subscriptions
- Webhook notifications for zone changes
- API key authentication (HMAC-signed)
- Bulk operations endpoint

### CLI Tools
- `atlas` — main server binary
- `atlas-cli` — management CLI (zone import/export, user admin, diagnostics)
- `atlas-admin` — administrative utilities
- `atlasdns-check` — configuration and health checker

### Infrastructure
- Docker and Docker Compose support
- CapRover one-click deployment
- Privilege escalation for port 53 binding
- Graceful shutdown with connection draining
- Memory pool for allocation-free hot paths
- Connection pooling for upstream queries
- Retry policies with exponential backoff
