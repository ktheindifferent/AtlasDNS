# Atlas DNS Server

![Rust](https://github.com/EmilHernvall/hermes/workflows/Rust/badge.svg)

A high-performance, feature-rich DNS server implementation in Rust with built-in SSL/TLS support, automatic certificate management via ACME protocol, and a comprehensive web-based management interface.

## 🚀 Features

### Core DNS Functionality
- **Full DNS Protocol Support**: UDP and TCP transport protocols
- **Authoritative Zone Management**: Host your own DNS zones
- **Recursive Resolution**: Full recursive DNS resolver capabilities
- **Forwarding Support**: Forward queries to upstream DNS servers
- **Response Caching**: Built-in cache with TTL management
- **Rate Limiting**: Protection against DNS amplification attacks

### Advanced Features
- **SSL/TLS Support with ACME**: Automatic certificate management
- **Web Management Interface**: Modern Bootstrap 5 UI
- **Multi-User Support**: Role-based access control (Admin, User, ReadOnly)
- **Session Management**: Secure token-based authentication
- **RESTful API v2**: Complete CRUD operations for DNS resources
- **DNS-over-HTTPS (DoH)**: Encrypted DNS queries over HTTPS
- **DNS-over-TLS (DoT)**: Encrypted DNS queries over TLS
- **Split-Horizon DNS**: Different responses based on client source
- **Geo-Load Balancing**: Route queries based on geographic location
- **CNAME Flattening**: Automatic CNAME resolution at zone apex
- **Dynamic DNS Updates**: RFC 2136 compliant dynamic updates
- **Health Checking**: Monitor endpoint availability
- **Alert Management**: Configurable alerts and notifications
- **Metrics & Analytics**: Comprehensive statistics and monitoring

## SSL/TLS Configuration

Atlas now supports SSL/TLS for the web management interface with automatic certificate management through ACME providers.

### Using Let's Encrypt (Recommended)

```bash
./atlas --ssl \
  --acme-provider letsencrypt \
  --acme-email admin@example.com \
  --acme-domains example.com,www.example.com
```

### Using ZeroSSL

```bash
./atlas --ssl \
  --acme-provider zerossl \
  --acme-email admin@example.com \
  --acme-domains example.com,www.example.com
```

### Using Manual Certificates

If you have existing SSL certificates:

```bash
./atlas --ssl \
  --ssl-cert /path/to/cert.pem \
  --ssl-key /path/to/key.pem
```

### Command Line Options

- `--ssl` or `-s`: Enable SSL/TLS for the web server
- `--acme-provider <PROVIDER>`: ACME provider (letsencrypt, letsencrypt-staging, zerossl)
- `--acme-email <EMAIL>`: Email address for ACME registration
- `--acme-domains <DOMAINS>`: Comma-separated list of domains for the certificate
- `--ssl-cert <PATH>`: Path to SSL certificate file (for manual configuration)
- `--ssl-key <PATH>`: Path to SSL private key file (for manual configuration)

### How It Works

1. **Automatic Certificate Management**: When configured with an ACME provider, Atlas will automatically:
   - Obtain certificates on first run
   - Renew certificates 30 days before expiry
   - Use DNS-01 challenges for domain validation
   
2. **DNS-01 Challenge**: Atlas uses its own DNS server to complete ACME DNS challenges:
   - Automatically creates required TXT records
   - Validates domain ownership
   - Removes challenge records after validation

3. **Certificate Storage**: Certificates are stored in `/opt/atlas/certs/` by default:
   - `cert.pem`: The certificate chain
   - `key.pem`: The private key
   - `account.pem`: ACME account key

### Configuration File

You can also configure SSL via a JSON configuration file. See `config/ssl-example.json` for an example.

## 📦 Installation

### Prerequisites

- Rust 1.70 or later
- OpenSSL development libraries
- Administrator/root privileges (for binding to port 53)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/ktheindifferent/AtlasDNS.git
cd AtlasDNS

# Build in release mode
cargo build --release

# The binary will be at target/release/atlas
```

## 🚀 Quick Start

### Basic DNS Server

```bash
# Run with default settings (requires sudo for port 53)
sudo ./target/release/atlas
```

### With Forwarding to Google DNS

```bash
sudo ./target/release/atlas --forward-address 8.8.8.8
```

### With Web Interface and SSL

```bash
sudo ./target/release/atlas --ssl \
  --acme-provider letsencrypt \
  --acme-email admin@example.com \
  --acme-domains example.com
```

## 🔧 Configuration Options

### Command Line Arguments

| Option | Short | Description | Example |
|--------|-------|-------------|---------|
| `--forward-address` | `-f` | Upstream DNS server for forwarding | `-f 8.8.8.8` |
| `--ssl` | `-s` | Enable SSL/TLS for web interface | `--ssl` |
| `--acme-provider` | | ACME provider (letsencrypt, zerossl) | `--acme-provider letsencrypt` |
| `--acme-email` | | Email for ACME registration | `--acme-email admin@example.com` |
| `--acme-domains` | | Domains for certificate (comma-separated) | `--acme-domains example.com,www.example.com` |
| `--ssl-cert` | | Path to SSL certificate (manual mode) | `--ssl-cert /path/to/cert.pem` |
| `--ssl-key` | | Path to SSL private key (manual mode) | `--ssl-key /path/to/key.pem` |
| `--disable-api` | `-x` | Disable web interface | `--disable-api` |
| `--zones-dir` | `-j` | Directory for zone files | `--zones-dir /etc/atlas/zones` |
| `--skip-privilege-check` | | Skip privilege escalation (development) | `--skip-privilege-check` |

### Default Ports

- **DNS**: Port 53 (UDP/TCP)
- **HTTP Web Interface**: Port 5380
- **HTTPS Web Interface**: Port 5343 (when SSL enabled)

## 🌐 Web Interface

The web interface provides:

- **Dashboard**: Real-time server statistics
- **Zone Management**: Create, edit, and delete DNS zones
- **Record Management**: Full CRUD operations for all record types
- **User Management**: Add and manage users with different roles
- **Session Monitoring**: View active sessions
- **Cache Viewer**: Monitor and manage DNS cache
- **API Documentation**: Interactive API explorer

Access the web interface at:
- HTTP: `http://your-server:5380`
- HTTPS: `https://your-server:5343` (when SSL enabled)

## 🔒 Security Features

- **Automatic Privilege Escalation**: Handles privilege requirements for port 53
- **Rate Limiting**: Protects against DNS amplification attacks
- **DNSSEC Support**: Planned for future release
- **Secure Session Management**: Token-based authentication with IP validation
- **TLS 1.2/1.3**: Modern encryption for web interface
- **Password Hashing**: SHA256 for user credentials

## 🐳 Docker Support

### Local Docker

```bash
# Build Docker image
docker build -t atlas-dns .

# Run with Docker Compose
docker-compose up -d
```

### CapRover Deployment

Atlas DNS Server now fully supports deployment on CapRover with TCP/UDP port mapping capabilities.

#### Prerequisites

- CapRover instance with version 1.11.0 or later (for TCP/UDP support)
- Domain configured for your CapRover instance
- DNS records pointing to your CapRover server

#### Deployment Steps

1. **Create the App in CapRover**
   ```bash
   # Using CapRover CLI
   caprover apps:create atlas-dns
   ```

2. **Configure Port Mapping**
   
   In the CapRover web interface, navigate to your `atlas-dns` app and configure:
   
   - **Container HTTP Port**: 5380 (for web interface)
   - **Additional Port Mappings** (⚠️ See DNS Port Conflict Warning below):
     - For Testing: `5353:53/tcp` and `5353:53/udp` - DNS on non-standard port
     - For Production: `53:53/tcp` and `53:53/udp` - DNS on standard port (requires systemd-resolved disabled)
     - `5343:5343/tcp` - HTTPS web interface (if SSL enabled)

3. **Set Environment Variables**
   
   In the CapRover web interface, navigate to your app and click on "App Configs" tab.
   Add these environment variables in the "Environmental Variables" section:
   
   | Variable | Default Value | Description |
   |----------|--------------|-------------|
   | `RUST_LOG` | `info` | Logging level (debug, info, warn, error) |
   | `ZONES_DIR` | `/opt/atlas/zones` | Directory for DNS zone files |
   | `FORWARD_ADDRESS` | *(empty)* | Optional: Upstream DNS server (e.g., 8.8.8.8) |
   | `SSL_ENABLED` | `false` | Set to `true` to enable SSL/TLS |
   | `ACME_PROVIDER` | *(empty)* | `letsencrypt` or `zerossl` (if SSL enabled) |
   | `ACME_EMAIL` | *(empty)* | Your email for ACME registration (if SSL enabled) |
   | `ACME_DOMAINS` | *(empty)* | Comma-separated domains for SSL cert (if SSL enabled) |
   
   **Note:** Environment variables must be configured through CapRover's web interface, 
   not in the Dockerfile. This allows for easy configuration without rebuilding the image.

4. **Deploy from GitHub**
   
   Option A: Deploy directly from GitHub
   ```bash
   caprover deploy -a atlas-dns -b master \
     -r https://github.com/ktheindifferent/AtlasDNS.git
   ```
   
   Option B: Deploy from local repository
   ```bash
   # From the project root directory
   caprover deploy -a atlas-dns
   ```

5. **Configure Persistent Storage (Optional)**
   
   For persistent DNS zones and certificates:
   
   - Add persistent directories in CapRover:
     - `/opt/atlas/zones` - For DNS zone files
     - `/opt/atlas/certs` - For SSL certificates

6. **Configure Firewall**
   
   Ensure your server firewall allows:
   - Port 53 TCP/UDP for DNS queries
   - Port 5380 TCP for HTTP web interface
   - Port 5343 TCP for HTTPS web interface (if SSL enabled)

#### Post-Deployment Configuration

1. **Access the Web Interface**
   
   Navigate to: `http://your-caprover-domain:5380`
   
   Default credentials:
   - Username: `admin`
   - Password: `admin123` (change immediately after first login)

2. **Configure DNS Zones**
   
   Use the web interface to:
   - Create authoritative zones
   - Add DNS records
   - Configure forwarding rules

3. **Test DNS Resolution**
   ```bash
   # Test DNS query
   dig @your-server-ip example.com
   
   # Test specific record type
   dig @your-server-ip example.com MX
   ```

#### Troubleshooting CapRover Deployment

- **Login Issues**: Default credentials are `admin` / `admin123` (not just "admin")
- **Port Binding Issues**: Ensure no other services are using port 53 on the host
- **Permission Errors**: The container runs as root for port 53 binding
- **DNS Not Responding**: Check CapRover's port mapping configuration
- **Logs**: View logs in CapRover web interface or via CLI:
  ```bash
  caprover logs -a atlas-dns
  ```
- **No Session Token**: If login redirects back, verify credentials and check logs
- **Web Interface Access**: Ensure port 5380 is accessible through CapRover

##### ⚠️ CRITICAL: DNS Port 53 Conflict Warning

**Problem**: Mapping port 53 on the host can break DNS resolution for Docker and the host system itself, as it conflicts with systemd-resolved (which listens on 127.0.0.53:53).

**Symptoms**: 
- Docker cannot pull images: `dial tcp: lookup registry-1.docker.io on 127.0.0.53:53: i/o timeout`
- Host system cannot resolve domain names
- CapRover deployment failures

**Solutions**:

1. **Option A: Use Non-Standard Port (Recommended for Testing)**
   - Map a different port like `5353:53/udp` and `5353:53/tcp`
   - Test DNS queries with: `dig @your-server-ip -p 5353 example.com`
   - This allows testing without breaking system DNS

2. **Option B: Disable systemd-resolved (Production)**
   ```bash
   # Stop and disable systemd-resolved
   sudo systemctl stop systemd-resolved
   sudo systemctl disable systemd-resolved
   
   # Remove symlink and create new resolv.conf
   sudo rm /etc/resolv.conf
   echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
   
   # Then you can safely use port 53
   ```

3. **Option C: Use External Server (Recommended for Production)**
   - Deploy Atlas DNS on a dedicated server or VM
   - Configure your main server to use the Atlas DNS server as its resolver
   - This separates DNS infrastructure from application infrastructure

4. **Option D: Bridge Network Mode (Advanced)**
   - Run the container with `--network host` mode (requires manual Docker setup)
   - This bypasses Docker's network stack but requires careful configuration

**Recovery if DNS is Broken**:
```bash
# If you've already mapped port 53 and broke DNS:
# 1. Remove the port mapping in CapRover web interface
# 2. Restart Docker service:
sudo systemctl restart docker
# 3. Restart systemd-resolved:
sudo systemctl restart systemd-resolved
```

#### Advanced CapRover Configuration

For production deployments, consider:

1. **Resource Limits**: Set appropriate CPU and memory limits
2. **Health Checks**: Configure CapRover health checks for the DNS service
3. **Backup Strategy**: Regular backups of `/opt/atlas/zones` directory
4. **Monitoring**: Set up monitoring for DNS query metrics
5. **Multi-Instance**: Deploy multiple instances for high availability

## 📊 API v2 Endpoints

The RESTful API provides complete DNS management capabilities:

- `GET /api/v2/zones` - List all zones
- `POST /api/v2/zones` - Create new zone
- `GET /api/v2/zones/{zone}` - Get zone details
- `PUT /api/v2/zones/{zone}` - Update zone
- `DELETE /api/v2/zones/{zone}` - Delete zone
- `GET /api/v2/zones/{zone}/records` - List zone records
- `POST /api/v2/zones/{zone}/records` - Create record
- Plus many more...

## 🔌 Pi-hole API Compatibility

AtlasDNS ships with a built-in Pi-hole v3/v4/v5 compatible API layer, enabled by
default via the `pihole-api` Cargo feature.  Third-party tools that speak to a
Pi-hole instance—Pi-hole Admin dashboards, Gravity Sync, mobile apps, and Grafana
Pi-hole data-source panels—can connect to AtlasDNS without any modification.

### Endpoint

All Pi-hole API calls go to:

```
GET http://<atlas-host>:5380/admin/api.php?<action>
```

No authentication is required (the `/admin/` path is intentionally public,
matching Pi-hole's own behavior).

### Supported Actions

| Query parameter | Description |
|---|---|
| `?summary` | Formatted statistics (domains blocked, queries today, cache size, …) |
| `?summaryRaw` | Same as `?summary` with raw numeric values |
| `?type` | Query-type percentage breakdown (A, AAAA, MX, PTR, …) |
| `?recentBlocked` | Plain-text most-recently-blocked domain |
| `?topItems[=N]` | Top *N* queried domains and top *N* blocked domains |
| `?getQuerySources[=N]` | Top *N* client IPs by query count |
| `?getQueryLog` / `?getAllQueries` | Recent query log (last 100 entries) |
| `?enable` | Report blocking as enabled (no-op in AtlasDNS) |
| `?disable` | Report blocking as disabled (no-op in AtlasDNS) |
| `?status` | Current blocking status |
| `?version` | API version (`5`) and server identifier |
| `?list=black&add=<domain>` | Add *domain* to the AtlasDNS blocklist |
| `?list=black&sub=<domain>` | Remove *domain* from the AtlasDNS blocklist |

### Disabling the Pi-hole API

If you don't need Pi-hole compatibility, compile without the default feature:

```bash
cargo build --release --no-default-features
```

## 🧪 Development

### Running Tests

```bash
cargo test
```

### Running with Debug Logging

```bash
RUST_LOG=debug sudo ./target/release/atlas
```

### Development Mode (without privilege escalation)

```bash
./target/release/atlas --skip-privilege-check
```

## 📝 License

This project is a fork of the original Hermes DNS server. See LICENSE file for details.

## ⚠️ Status

This is an active development fork with significant enhancements over the original project. The codebase has been extensively refactored and expanded with enterprise-grade features.

### Recent Updates
- ✅ Fixed all compilation errors
- ✅ Added comprehensive user authentication and session management
- ✅ Implemented RESTful API v2 with full CRUD operations
- ✅ Added DNS-over-HTTPS and DNS-over-TLS support
- ✅ Implemented split-horizon DNS and geo-load balancing
- ✅ Added CNAME flattening and dynamic DNS updates
- ✅ Revamped UI with Bootstrap 5
- ✅ Enhanced error handling and logging throughout

## Prometheus & Grafana Monitoring

Atlas DNS exposes a dedicated Prometheus metrics endpoint on **port 9153** (the standard port for DNS exporters, matching CoreDNS and BIND exporter conventions).

### Quick Start

The metrics server starts automatically alongside the DNS server:

```bash
# Default: metrics on :9153
./atlas

# Custom port
./atlas --metrics-port 9090

# Disable metrics server
./atlas --no-metrics
```

Verify it's working:

```bash
curl http://localhost:9153/metrics
```

### Prometheus scrape config

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: atlasdns
    static_configs:
      - targets: ['localhost:9153']
    scrape_interval: 15s
```

### Exposed metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `atlasdns_queries_total` | Counter | `type`, `status`, `upstream` | Total DNS queries processed |
| `atlasdns_query_duration_seconds` | Histogram | `type` | Query processing latency |
| `atlasdns_cache_hits_total` | Counter | — | DNS cache hits |
| `atlasdns_cache_misses_total` | Counter | — | DNS cache misses |
| `atlasdns_cache_size` | Gauge | — | Current entries in the DNS cache |
| `atlasdns_blocked_queries_total` | Counter | `list` | Queries blocked by blocklist |
| `atlasdns_upstream_errors_total` | Counter | `upstream` | Upstream DNS error count |
| `atlasdns_upstream_latency_seconds` | Histogram | `upstream` | Upstream query latency |
| `atlasdns_active_clients` | Gauge | — | Unique clients seen since start |
| `atlasdns_build_info` | Gauge | `version` | Build information (always 1) |

Atlas also exposes a rich set of `atlas_*` and `atlas_dns_*` metrics (cache operations, security events, thread pool stats, web request latency, DNSSEC operations, etc.) on the same endpoint.

### Grafana dashboard

Import the community [CoreDNS dashboard](https://grafana.com/grafana/dashboards/14981) and replace `coredns_` metric prefixes with `atlasdns_` to get instant visualisation. Key panels:

- **Query rate** — `rate(atlasdns_queries_total[5m])`
- **Cache hit ratio** — `rate(atlasdns_cache_hits_total[5m]) / (rate(atlasdns_cache_hits_total[5m]) + rate(atlasdns_cache_misses_total[5m]))`
- **p99 latency** — `histogram_quantile(0.99, rate(atlasdns_query_duration_seconds_bucket[5m]))`
- **Blocked queries** — `rate(atlasdns_blocked_queries_total[5m])`
- **Upstream errors** — `rate(atlasdns_upstream_errors_total[5m])`

### Docker Compose with Prometheus + Grafana

```yaml
version: '3.8'
services:
  atlasdns:
    image: atlasdns:latest
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "5380:5380"
      - "9153:9153"   # Prometheus metrics

  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## 📞 Support

For issues and questions, please use the GitHub issue tracker.