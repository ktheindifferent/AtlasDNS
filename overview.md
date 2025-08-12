# Atlas DNS Server - High-Level Overview

## Project Vision
Atlas aims to be a robust, high-performance DNS server implementation in Rust, providing both authoritative and recursive DNS resolution capabilities with modern features like caching, rate limiting, and health monitoring.

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Atlas DNS Server                      │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   UDP Server  │  │   TCP Server  │  │  Web Server   │ │
│  │   Port 2053   │  │   Port 2053   │  │  Port 5380    │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘ │
│         │                  │                  │          │
│  ┌──────▼──────────────────▼──────────────────▼───────┐ │
│  │            Core DNS Processing Engine               │ │
│  ├─────────────────────────────────────────────────────┤ │
│  │  • Protocol Handler  • Query Parser                 │ │
│  │  • Record Parsers    • Response Builder             │ │
│  │  • Error Handling    • Rate Limiting                │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │
│  │    Cache     │  │  Authority   │  │    Resolver      │ │
│  │   Manager    │  │    Zones     │  │  (Recursive)     │ │
│  └─────────────┘  └─────────────┘  └─────────────────┘ │
│                                                          │
│  ┌─────────────────────────────────────────────────────┐ │
│  │           Infrastructure & Support                   │ │
│  ├─────────────────────────────────────────────────────┤ │
│  │  • Health Monitor  • Logging      • Metrics         │ │
│  │  • Context Mgmt    • Threading    • Network Utils   │ │
│  └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

## Core Workflows

### 1. DNS Query Processing
1. **Receive Query**: UDP/TCP server receives DNS query packet
2. **Parse & Validate**: Protocol handler parses packet, validates format
3. **Check Cache**: Look for cached response (if caching enabled)
4. **Resolution Path**:
   - **Authoritative**: Check local zone files
   - **Recursive**: Query upstream DNS servers
   - **Forwarding**: Forward to configured DNS servers
5. **Build Response**: Construct DNS response packet
6. **Cache Response**: Store in cache with TTL
7. **Send Reply**: Return response to client

### 2. Zone Management
- Load zone files from disk
- Parse DNS records (A, AAAA, CNAME, MX, NS, etc.)
- Serve authoritative responses for managed zones
- Web interface for zone administration

### 3. Caching Strategy
- In-memory cache with configurable size limits
- TTL-based expiration
- Cache invalidation on zone updates
- Statistics and monitoring via web interface

## Key Design Principles

1. **Performance**: Async I/O, efficient packet parsing, minimal allocations
2. **Reliability**: Comprehensive error handling, panic recovery, health checks
3. **Security**: Rate limiting, input validation, DoS protection
4. **Extensibility**: Modular architecture, clean interfaces
5. **Observability**: Logging, metrics, health monitoring

## Module Responsibilities

### DNS Module (`src/dns/`)
- **Core**: Protocol implementation, packet handling
- **Server**: Network listeners, connection management
- **Client**: Outbound DNS queries for recursion
- **Cache**: Response caching with TTL management
- **Authority**: Zone file parsing and management
- **Resolution**: Query resolution strategies
- **Safety**: Rate limiting, error handling, health checks

### Web Module (`src/web/`)
- **API**: RESTful endpoints for management
- **UI**: HTML templates for web interface
- **Admin**: Cache management, zone administration
- **Monitoring**: Health status, metrics display

## Configuration & Deployment

### Default Configuration
- DNS Port: 2053 (UDP & TCP)
- Web Port: 5380 (HTTP)
- Upstream DNS: 8.8.8.8, 8.8.4.4 (Google DNS)
- Cache: Enabled with in-memory storage
- Logging: Console output with configurable levels

### Deployment Options
1. **Standalone Binary**: Direct execution via cargo run
2. **Docker Container**: Dockerfile provided for containerization
3. **Docker Compose**: Multi-container setup with networking
4. **CapRover**: PaaS deployment with captain-definition

## Current Development Focus

1. **Testing**: Building comprehensive test suite
2. **Error Handling**: Strengthening error recovery
3. **Performance**: Optimizing packet processing
4. **Features**: Completing partial implementations
5. **Documentation**: Improving code and user documentation

## Future Roadmap

### Short Term (Current Sprint)
- [ ] Complete test coverage for all modules
- [ ] Fix identified error handling gaps
- [ ] Implement missing DNS record types
- [ ] Add integration tests

### Medium Term
- [ ] DNSSEC support
- [ ] DNS-over-HTTPS (DoH)
- [ ] DNS-over-TLS (DoT)
- [ ] Prometheus metrics export
- [ ] Clustering support

### Long Term
- [ ] Full RFC compliance
- [ ] Performance benchmarking suite
- [ ] Production-ready release
- [ ] Enterprise features (LDAP, audit logs)