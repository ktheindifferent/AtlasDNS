# Atlas DNS Server - Project Description

## Project Summary
Atlas is a high-performance DNS server implementation written in Rust, forked from the Hermes DNS server project. The server provides comprehensive DNS functionality including both UDP and TCP protocol support, authoritative zone management, recursive resolution, response caching, and a web-based management interface.

## Current Development Status
- **Version**: 0.0.1 (Fork in progress - not production ready)
- **Language**: Rust (Edition 2018)
- **Primary Branch**: terragon/maintain-docs-testing-features
- **Base Branch**: master

## Recent Work Completed
1. **Enhanced DNS Record Parsing**: Comprehensive DNS record type support with proper parsing for A, AAAA, CNAME, MX, NS, PTR, SOA, TXT, and SRV records
2. **Error Handling Improvements**: Added robust error handling, validation, and recovery mechanisms throughout the DNS processing pipeline
3. **Rate Limiting**: Implemented rate limiting to prevent DoS attacks and resource exhaustion
4. **Health Monitoring**: Added health check endpoints and monitoring capabilities for service reliability

## Key Features
- **Multi-Protocol Support**: Both UDP (port 2053) and TCP DNS protocols
- **Caching System**: In-memory DNS response cache with TTL management
- **Authoritative Zones**: Support for managing authoritative DNS zones via zone files
- **Recursive Resolution**: Can forward queries to upstream DNS servers (8.8.8.8, 8.8.4.4 by default)
- **Web Management Interface**: HTTP API running on port 5380 for administration
- **Root Server Support**: Built-in root server hints for full recursive resolution

## Architecture Components
- **DNS Module** (`src/dns/`): Core DNS protocol implementation
  - `protocol.rs`: DNS packet structures and serialization
  - `server.rs` & `server_enhanced.rs`: UDP/TCP server implementations
  - `client.rs`: DNS client for recursive queries
  - `cache.rs`: Response caching with TTL support
  - `authority.rs`: Zone file management
  - `resolve.rs`: Resolution strategies
  - `record_parsers.rs`: DNS record type parsing
  - `rate_limit.rs`: Request rate limiting
  - `health.rs`: Health monitoring
  - `error_utils.rs` & `errors.rs`: Error handling utilities

- **Web Module** (`src/web/`): Management interface
  - `server.rs`: HTTP server implementation
  - `templates/`: Handlebars templates for web UI
  - `cache.rs` & `authority.rs`: Web endpoints for DNS management

## Dependencies
- Core: `ascii`, `chrono`, `derive_more`, `getopts`, `rand`, `regex`
- Serialization: `serde`, `serde_derive`, `serde_json`
- Web: `handlebars`, `tiny_http` (with SSL support)
- Concurrency: `parking_lot`
- Logging: `log`, `simple_logger`

## Build & Deployment
- **Container Support**: Dockerfile and docker-compose.yml for containerized deployment
- **CapRover Support**: captain-definition file for CapRover PaaS deployment
- **Binary**: Main binary entry point in `src/bin/`

## Testing Status
- **Unit Tests**: Need to be created for new functionality
- **Integration Tests**: Not yet implemented
- **Test Framework**: Standard Rust testing with `cargo test`

## Documentation
- README.md: Basic project introduction
- INTEGRATION_GUIDE.md: Integration documentation
- FEATURE_ENHANCEMENT_REPORT.md: Detailed enhancement analysis

## License
Licensed under standard open source terms (see LICENSE file)

## Development Team
- Original Authors: emil, p0indexter, PixelCoda
- Current Branch: Maintained by Terragon Labs

## Known Issues & TODOs
- Fork is not production ready (as noted in README)
- Need comprehensive test coverage
- Some partially implemented features need completion
- Resource exhaustion vulnerabilities need addressing
- Thread panic recovery mechanisms needed