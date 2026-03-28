# AtlasDNS Deployment Guide

## Prerequisites

- Linux server (Debian/Ubuntu or RHEL-based)
- Rust toolchain (for building from source) or pre-built binary
- Root/sudo access
- Domain name pointing to your server (for TLS)

---

## 1. Build the Release Binary

```bash
# Clone and build
git clone https://github.com/ktheindifferent/AtlasDNS.git
cd AtlasDNS
cargo build --release

# Binaries are in target/release/
ls target/release/atlas target/release/atlasdns-feeder
```

Or use the Docker image:

```bash
docker build -t atlasdns:latest .
```

---

## 2. Create the `atlasdns` System User

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin atlasdns
```

---

## 3. Install Binaries and Configuration

```bash
# Install binaries
sudo install -m 0755 target/release/atlas /usr/local/bin/atlas
sudo install -m 0755 target/release/atlasdns-feeder /usr/local/bin/atlasdns-feeder

# Create directories
sudo mkdir -p /etc/atlasdns/zones /opt/atlas/certs /opt/atlas/data
sudo chown -R atlasdns:atlasdns /etc/atlasdns /opt/atlas

# Optional: environment file for overrides
sudo tee /etc/atlasdns/atlasdns.env > /dev/null <<'EOF'
RUST_LOG=info
# FORWARD_ADDRESS=8.8.8.8
# SSL_ENABLED=true
# ACME_PROVIDER=letsencrypt
# ACME_EMAIL=admin@example.com
# ACME_DOMAINS=dns.example.com
EOF
sudo chmod 640 /etc/atlasdns/atlasdns.env
sudo chown root:atlasdns /etc/atlasdns/atlasdns.env
```

---

## 4. Install and Enable the systemd Service

```bash
sudo install -m 0644 atlasdns.service /etc/systemd/system/atlasdns.service
sudo systemctl daemon-reload
sudo systemctl enable --now atlasdns

# Verify
sudo systemctl status atlasdns
journalctl -u atlasdns -f
```

The service uses `AmbientCapabilities=CAP_NET_BIND_SERVICE` so the unprivileged
`atlasdns` user can bind to port 53 without running as root.

---

## 5. Set Up nginx Reverse Proxy with TLS

Install nginx and certbot:

```bash
sudo apt install nginx certbot python3-certbot-nginx   # Debian/Ubuntu
# sudo dnf install nginx certbot python3-certbot-nginx  # RHEL/Fedora
```

Create the nginx site configuration:

```bash
sudo tee /etc/nginx/sites-available/atlasdns <<'EOF'
# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name dns.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name dns.example.com;

    # TLS (certbot will fill these in)
    ssl_certificate     /etc/letsencrypt/live/dns.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dns.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # Security headers
    add_header X-Frame-Options       DENY;
    add_header X-Content-Type-Options nosniff;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;

    # Web UI and HTTP API (port 8080)
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # DNS-over-HTTPS (DoH) endpoint
    location /dns-query {
        proxy_pass http://127.0.0.1:5353;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Health check (allow from anywhere for load balancers)
    location /health {
        proxy_pass http://127.0.0.1:8080/health;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/atlasdns /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Obtain a TLS certificate:

```bash
sudo certbot --nginx -d dns.example.com
```

---

## 6. Configure Firewall

### Using `ufw` (Debian/Ubuntu)

```bash
# DNS — open to the world
sudo ufw allow 53/udp comment "AtlasDNS UDP"
sudo ufw allow 53/tcp comment "AtlasDNS TCP"

# DoH via nginx — open to the world (TLS-terminated)
sudo ufw allow 443/tcp comment "HTTPS / DoH"

# HTTP API — restrict to trusted management IPs only
sudo ufw allow from 10.0.0.0/8 to any port 8080 proto tcp comment "AtlasDNS API (internal)"
sudo ufw deny 8080/tcp comment "Block external API access"

# DoH direct (bypass nginx) — trusted only
sudo ufw allow from 10.0.0.0/8 to any port 5353 proto tcp comment "DoH direct (internal)"
sudo ufw deny 5353/tcp comment "Block external DoH direct"

sudo ufw enable
```

### Using `firewalld` (RHEL/Fedora)

```bash
sudo firewall-cmd --permanent --add-service=dns
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.0.0.0/8" port port="8080" protocol="tcp" accept'
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.0.0.0/8" port port="5353" protocol="tcp" accept'
sudo firewall-cmd --reload
```

---

## 7. Threat Feed Updates (Cron)

Set up the feeder to run hourly:

```bash
sudo tee /etc/cron.d/atlasdns-feeder <<'EOF'
# Refresh threat intelligence feeds every hour
0 * * * * atlasdns /usr/local/bin/atlasdns-feeder --api-url http://localhost:8080 2>&1 | logger -t atlasdns-feeder
EOF
```

---

## 8. Docker Deployment (Alternative)

```bash
docker build -t atlasdns:latest .

docker run -d \
  --name atlasdns \
  --restart unless-stopped \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 5353:5353/tcp \
  -p 8080:8080/tcp \
  -v atlasdns-zones:/opt/atlas/zones \
  -v atlasdns-data:/opt/atlas/data \
  -v atlasdns-certs:/opt/atlas/certs \
  -e RUST_LOG=info \
  -e FORWARD_ADDRESS=8.8.8.8 \
  atlasdns:latest
```

---

## 9. Verify the Deployment

```bash
# Health check
curl -s http://localhost:8080/health | jq .

# DNS query test
dig @localhost example.com A

# Check systemd logs
journalctl -u atlasdns --since "5 minutes ago"
```

---

## 10. Security Checklist

- [ ] Change the default admin password immediately after first login
- [ ] Do NOT set `FORCE_ADMIN=true` in production
- [ ] Restrict port 8080 to trusted networks only
- [ ] Enable TLS via nginx or the built-in ACME provider
- [ ] Set up log rotation for `/opt/atlas/data/` logs
- [ ] Review firewall rules: only port 53 should be world-accessible
- [ ] Enable threat intelligence feeds via the feeder cron job
- [ ] Back up zone files regularly (`atlasdns-backup` CLI)
