# Atlas DNS CLI API Authentication

This document explains how to use API keys for authentication with the Atlas DNS CLI tool.

## Overview

The Atlas DNS CLI supports API key authentication for secure programmatic access to the DNS server. API keys provide fine-grained permissions control and can be managed through the web interface or API endpoints.

## Setting Up Authentication

### 1. Generate an API Key

You can generate an API key through the web interface:

1. Login to the Atlas DNS web interface
2. Navigate to "API & Keys" section  
3. Click "Generate New API Key"
4. Provide a name and description
5. Select required permissions
6. Copy the generated API key (shown only once)

### 2. Configure CLI Authentication

#### Environment Variable (Recommended)
```bash
export ATLAS_API_KEY="your_api_key_here"
export ATLAS_HOST="https://your-dns-server.com:5343"
```

#### Command Line Parameter
```bash
atlas -k your_api_key_here -H https://your-dns-server.com:5343 status
```

#### Configuration File
Create `~/.atlas/config.yaml`:
```yaml
host: https://your-dns-server.com:5343
api_key: your_api_key_here
```

## API Key Permissions

API keys support the following permission levels:

- **Admin**: Full administrative access to all operations
- **DnsRead**: Read DNS records and zones
- **DnsWrite**: Create, modify, and delete DNS records
- **CacheRead**: View cache statistics
- **CacheWrite**: Clear DNS cache
- **MetricsRead**: Access monitoring and metrics data
- **ZoneRead**: Read zone configurations
- **ZoneWrite**: Modify zone configurations

## Example Usage

### Basic Server Status
```bash
# Using environment variable
atlas status

# Using command line parameter
atlas -k sk_test_1234567890abcdef status
```

### Zone Management
```bash
# List zones
atlas zones list

# Get zone details
atlas zones get example.com

# Add DNS record
atlas records add example.com A www 192.168.1.100

# Delete DNS record  
atlas records delete example.com A www
```

### Cache Operations
```bash
# View cache statistics
atlas cache stats

# Clear DNS cache
atlas cache clear
```

### Metrics and Monitoring
```bash
# Get server metrics
atlas metrics

# Get zone-specific metrics
atlas metrics --zone example.com

# Get real-time statistics  
atlas stats --live
```

## Authentication Examples

### Web API Direct Access
```bash
# Get version info
curl -H "X-API-Key: your_api_key_here" \
     https://your-dns-server.com:5343/api/version

# Resolve DNS query
curl -X POST \
     -H "X-API-Key: your_api_key_here" \
     -H "Content-Type: application/json" \
     -d '{"domain": "example.com", "type": "A"}' \
     https://your-dns-server.com:5343/api/resolve

# Clear cache
curl -X POST \
     -H "X-API-Key: your_api_key_here" \
     https://your-dns-server.com:5343/cache/clear
```

### GraphQL Access
```bash
curl -X POST \
     -H "X-API-Key: your_api_key_here" \
     -H "Content-Type: application/json" \
     -d '{
       "query": "{ serverInfo { version uptime } }"
     }' \
     https://your-dns-server.com:5343/graphql
```

### Prometheus Metrics
```bash
# Access Prometheus metrics endpoint
curl -H "X-API-Key: your_api_key_here" \
     https://your-dns-server.com:5343/prometheus
```

## Security Best Practices

1. **Store keys securely**: Use environment variables or secure configuration files
2. **Use minimal permissions**: Only grant permissions your application needs
3. **Rotate keys regularly**: Generate new keys and revoke old ones periodically
4. **Monitor usage**: Check API key usage logs for suspicious activity
5. **Use HTTPS**: Always connect to the server over encrypted connections

## Troubleshooting

### Authentication Failures
```bash
# Error: Unauthorized (401)
# Check that your API key is valid and has required permissions
atlas -k invalid_key status
# Response: {"error": "Unauthorized", "message": "Valid API key required"}
```

### Permission Errors
```bash  
# Error: Forbidden (403) - insufficient permissions
# API key needs additional permissions for the operation
atlas cache clear
# Solution: Update API key permissions in web interface
```

### Network Issues
```bash
# Error: Connection refused
# Check that the server is running and accessible
atlas -H http://localhost:5380 status

# Error: SSL certificate issues
# Use --insecure flag for development or fix certificate issues
atlas --insecure status
```

## API Endpoints

The following endpoints support API key authentication:

- `GET /api/version` - Server version information
- `POST /api/resolve` - DNS resolution queries  
- `POST /cache/clear` - Clear DNS cache
- `GET /prometheus` - Prometheus metrics
- `POST /graphql` - GraphQL API access

## CLI Command Reference

```bash
# Server management
atlas status                    # Server status
atlas config show              # Show configuration
atlas config test              # Test configuration

# Zone management  
atlas zones list                # List all zones
atlas zones get <zone>          # Get zone details
atlas zones create <zone>       # Create new zone
atlas zones delete <zone>       # Delete zone

# Record management
atlas records list <zone>       # List records in zone
atlas records add <zone> <type> <name> <value>    # Add record
atlas records delete <zone> <type> <name>         # Delete record

# Cache management
atlas cache stats               # Cache statistics
atlas cache clear              # Clear cache
atlas cache get <domain>       # Get cached record

# Monitoring
atlas metrics                   # Server metrics  
atlas stats                     # Real-time statistics
atlas logs                      # Recent log entries
```

For more information, use `atlas --help` or `atlas <command> --help` for command-specific help.