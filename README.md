Atlas DNS server
=================

![Rust](https://github.com/EmilHernvall/hermes/workflows/Rust/badge.svg)

A high-performance DNS server with built-in SSL/TLS support and automatic certificate management via ACME protocol.

## Features

- Full DNS server implementation (UDP and TCP)
- Authoritative zone management
- Recursive and forwarding resolution
- Response caching
- Web-based management interface
- **SSL/TLS Support with ACME certificates**
  - Automatic certificate acquisition and renewal
  - Support for Let's Encrypt and ZeroSSL
  - DNS-01 challenge support for wildcard certificates
  - Manual certificate configuration option

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

## Building

```bash
cargo build --release
```

## Running

Basic usage:
```bash
./atlas
```

With SSL and Let's Encrypt:
```bash
./atlas --ssl --acme-provider letsencrypt --acme-email admin@example.com --acme-domains example.com
```

## Requirements

- Rust 1.56 or later
- OpenSSL development libraries
- Port 53 (DNS) and port 5380/5343 (HTTP/HTTPS) available

Fork in progress. Don't use!!!!!!