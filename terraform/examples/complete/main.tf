# Complete Atlas DNS Infrastructure Example
# This example demonstrates a production-ready DNS setup with:
# - Multiple zones
# - Health checks
# - Load balancing
# - GeoDNS
# - Failover
# - Security policies

terraform {
  required_version = ">= 1.0"
  required_providers {
    atlas-dns = {
      source  = "atlas-dns/atlas-dns"
      version = "~> 1.0.0"
    }
  }
}

provider "atlas-dns" {
  endpoint = var.atlas_endpoint
  api_key  = var.atlas_api_key
}

# ========================================
# Variables
# ========================================

variable "atlas_endpoint" {
  description = "Atlas DNS API endpoint"
  type        = string
}

variable "atlas_api_key" {
  description = "Atlas DNS API key"
  type        = string
  sensitive   = true
}

variable "primary_domain" {
  description = "Primary domain name"
  type        = string
  default     = "example.com"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

# ========================================
# Primary Zone Configuration
# ========================================

resource "atlas-dns_zone" "primary" {
  name        = var.primary_domain
  description = "Primary production zone"
  
  soa {
    mname   = "ns1.${var.primary_domain}"
    rname   = "admin.${var.primary_domain}"
    serial  = formatdate("YYYYMMDD01", timestamp())
    refresh = 3600
    retry   = 600
    expire  = 604800
    minimum = 86400
  }
  
  name_servers = [
    "ns1.${var.primary_domain}",
    "ns2.${var.primary_domain}",
    "ns3.${var.primary_domain}",
    "ns4.${var.primary_domain}"
  ]
  
  dnssec_enabled = true
  
  tags = {
    environment = var.environment
    managed_by  = "terraform"
    purpose     = "primary"
  }
}

# ========================================
# Name Server Records
# ========================================

resource "atlas-dns_record" "ns1" {
  zone_id = atlas-dns_zone.primary.id
  name    = "ns1"
  type    = "A"
  ttl     = 86400
  values  = ["198.51.100.1"]
}

resource "atlas-dns_record" "ns2" {
  zone_id = atlas-dns_zone.primary.id
  name    = "ns2"
  type    = "A"
  ttl     = 86400
  values  = ["198.51.100.2"]
}

resource "atlas-dns_record" "ns3" {
  zone_id = atlas-dns_zone.primary.id
  name    = "ns3"
  type    = "A"
  ttl     = 86400
  values  = ["203.0.113.1"]
}

resource "atlas-dns_record" "ns4" {
  zone_id = atlas-dns_zone.primary.id
  name    = "ns4"
  type    = "A"
  ttl     = 86400
  values  = ["203.0.113.2"]
}

# ========================================
# Web Infrastructure
# ========================================

# Health checks for web servers
resource "atlas-dns_health_check" "web_us_east" {
  name        = "web-us-east-health"
  description = "Health check for US East web servers"
  
  type              = "HTTPS"
  target            = "web-us-east.${var.primary_domain}"
  port              = 443
  path              = "/health"
  interval          = 30
  timeout           = 10
  retries           = 3
  expected_response = "healthy"
  expected_status   = 200
  
  alert_enabled = true
  alert_email   = "ops@${var.primary_domain}"
}

resource "atlas-dns_health_check" "web_us_west" {
  name        = "web-us-west-health"
  description = "Health check for US West web servers"
  
  type              = "HTTPS"
  target            = "web-us-west.${var.primary_domain}"
  port              = 443
  path              = "/health"
  interval          = 30
  timeout           = 10
  retries           = 3
  expected_response = "healthy"
  expected_status   = 200
  
  alert_enabled = true
  alert_email   = "ops@${var.primary_domain}"
}

resource "atlas-dns_health_check" "web_eu" {
  name        = "web-eu-health"
  description = "Health check for EU web servers"
  
  type              = "HTTPS"
  target            = "web-eu.${var.primary_domain}"
  port              = 443
  path              = "/health"
  interval          = 30
  timeout           = 10
  retries           = 3
  expected_response = "healthy"
  expected_status   = 200
  
  alert_enabled = true
  alert_email   = "ops@${var.primary_domain}"
}

# GeoDNS configuration for web traffic
resource "atlas-dns_geodns_policy" "web" {
  name        = "web-geodns"
  description = "Geographic routing for web traffic"
  zone_id     = atlas-dns_zone.primary.id
  
  default_location = "US"
  
  # US East region
  region {
    name      = "us-east"
    countries = ["US"]
    states    = ["NY", "NJ", "PA", "MA", "CT", "VT", "NH", "ME", "RI"]
    records   = ["192.0.2.10", "192.0.2.11"]
    health_check_ids = [atlas-dns_health_check.web_us_east.id]
  }
  
  # US West region
  region {
    name      = "us-west"
    countries = ["US"]
    states    = ["CA", "OR", "WA", "NV", "AZ"]
    records   = ["192.0.2.20", "192.0.2.21"]
    health_check_ids = [atlas-dns_health_check.web_us_west.id]
  }
  
  # Europe region
  region {
    name      = "europe"
    countries = ["GB", "FR", "DE", "IT", "ES", "NL", "BE", "CH", "AT"]
    records   = ["192.0.2.30", "192.0.2.31"]
    health_check_ids = [atlas-dns_health_check.web_eu.id]
  }
  
  # Asia Pacific region
  region {
    name      = "asia-pacific"
    countries = ["JP", "AU", "NZ", "SG", "HK", "IN", "KR"]
    records   = ["192.0.2.40", "192.0.2.41"]
  }
  
  # Fallback chain
  fallback_chain = ["us-east", "us-west", "europe"]
}

# Traffic steering for canary deployments
resource "atlas-dns_traffic_policy" "canary" {
  name        = "web-canary"
  description = "Canary deployment traffic steering"
  zone_id     = atlas-dns_zone.primary.id
  
  type = "weighted"
  
  # Production pool (90% traffic)
  endpoint {
    name            = "production"
    value           = "192.0.2.10"
    weight          = 90
    health_check_id = atlas-dns_health_check.web_us_east.id
  }
  
  # Canary pool (10% traffic)
  endpoint {
    name            = "canary"
    value           = "192.0.2.100"
    weight          = 10
    health_check_id = atlas-dns_health_check.web_us_east.id
  }
  
  # Enable sticky sessions
  sticky_sessions {
    enabled = true
    ttl     = 3600
  }
}

# ========================================
# API Infrastructure
# ========================================

resource "atlas-dns_record" "api" {
  zone_id = atlas-dns_zone.primary.id
  name    = "api"
  type    = "A"
  ttl     = 60
  values  = ["192.0.2.50", "192.0.2.51", "192.0.2.52"]
  
  # Enable proximity routing
  proximity_routing = true
}

# Rate limiting for API
resource "atlas-dns_rate_limit" "api" {
  name        = "api-rate-limit"
  description = "Rate limiting for API endpoints"
  
  requests_per_second = 10000
  burst_size         = 20000
  
  apply_to {
    zones   = [atlas-dns_zone.primary.id]
    records = ["api.${var.primary_domain}"]
  }
  
  action = "refuse"
  
  # Whitelist internal networks
  whitelist = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
  ]
  
  # Enable adaptive rate limiting
  adaptive {
    enabled              = true
    increase_threshold   = 0.8
    decrease_threshold   = 0.5
    sampling_window      = 60
  }
}

# ========================================
# Email Configuration
# ========================================

resource "atlas-dns_record" "mx" {
  zone_id = atlas-dns_zone.primary.id
  name    = "@"
  type    = "MX"
  ttl     = 3600
  
  mx_record {
    priority = 10
    value    = "mail1.${var.primary_domain}"
  }
  
  mx_record {
    priority = 20
    value    = "mail2.${var.primary_domain}"
  }
  
  mx_record {
    priority = 30
    value    = "mail3.${var.primary_domain}"
  }
}

resource "atlas-dns_record" "spf" {
  zone_id = atlas-dns_zone.primary.id
  name    = "@"
  type    = "TXT"
  ttl     = 3600
  values  = ["v=spf1 mx include:_spf.google.com include:sendgrid.net ~all"]
}

resource "atlas-dns_record" "dmarc" {
  zone_id = atlas-dns_zone.primary.id
  name    = "_dmarc"
  type    = "TXT"
  ttl     = 3600
  values  = ["v=DMARC1; p=reject; rua=mailto:dmarc@${var.primary_domain}; ruf=mailto:forensics@${var.primary_domain}; pct=100"]
}

resource "atlas-dns_record" "dkim" {
  zone_id = atlas-dns_zone.primary.id
  name    = "google._domainkey"
  type    = "TXT"
  ttl     = 3600
  values  = ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."]
}

# ========================================
# CDN Configuration
# ========================================

resource "atlas-dns_record" "cdn" {
  zone_id = atlas-dns_zone.primary.id
  name    = "cdn"
  type    = "CNAME"
  ttl     = 300
  values  = ["cdn.cloudflare.com"]
}

resource "atlas-dns_record" "static" {
  zone_id = atlas-dns_zone.primary.id
  name    = "static"
  type    = "CNAME"
  ttl     = 300
  values  = ["d111111abcdef8.cloudfront.net"]
}

# ========================================
# Security Policies
# ========================================

# DNS Firewall for malware protection
resource "atlas-dns_firewall_rule" "malware_protection" {
  name        = "malware-protection"
  description = "Block known malware domains"
  
  type = "rpz"  # Response Policy Zone
  
  # Import threat feeds
  threat_feeds = [
    "https://threatfeeds.example.com/malware.txt",
    "https://threatfeeds.example.com/phishing.txt"
  ]
  
  action          = "nxdomain"
  log_enabled     = true
  alert_enabled   = true
  alert_threshold = 100
}

# DDoS protection
resource "atlas-dns_ddos_protection" "main" {
  name        = "main-ddos-protection"
  description = "DDoS protection for all zones"
  
  zones = [atlas-dns_zone.primary.id]
  
  # Protection settings
  syn_flood_protection     = true
  udp_flood_protection     = true
  dns_amplification_protection = true
  
  # Thresholds
  query_rate_threshold     = 100000
  packet_rate_threshold    = 1000000
  bandwidth_threshold_mbps = 1000
  
  # Mitigation actions
  mitigation {
    type      = "rate_limit"
    threshold = 0.8
    duration  = 300
  }
  
  mitigation {
    type      = "blackhole"
    threshold = 0.95
    duration  = 600
  }
}

# ========================================
# Monitoring and Alerting
# ========================================

resource "atlas-dns_monitor" "availability" {
  name        = "zone-availability"
  description = "Monitor zone availability"
  
  zone_id = atlas-dns_zone.primary.id
  
  # Check from multiple locations
  check_locations = ["us-east", "us-west", "europe", "asia"]
  
  # Alert configuration
  alert {
    enabled   = true
    threshold = 2  # Alert if 2+ locations fail
    channels  = ["email", "slack", "pagerduty"]
  }
}

# ========================================
# Backup and Disaster Recovery
# ========================================

resource "atlas-dns_backup_policy" "daily" {
  name        = "daily-backup"
  description = "Daily backup of all zones"
  
  zones = [atlas-dns_zone.primary.id]
  
  schedule {
    frequency = "daily"
    time      = "02:00"
    timezone  = "UTC"
  }
  
  retention {
    daily   = 7
    weekly  = 4
    monthly = 12
    yearly  = 5
  }
  
  destination {
    type   = "s3"
    bucket = "atlas-dns-backups"
    prefix = "production/"
  }
  
  encryption {
    enabled = true
    key_id  = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
  }
}

# ========================================
# Outputs
# ========================================

output "zone_id" {
  value       = atlas-dns_zone.primary.id
  description = "Primary zone ID"
}

output "nameservers" {
  value       = atlas-dns_zone.primary.name_servers
  description = "Zone nameservers"
}

output "geodns_regions" {
  value = {
    us_east = atlas-dns_geodns_policy.web.region[0].records
    us_west = atlas-dns_geodns_policy.web.region[1].records
    europe  = atlas-dns_geodns_policy.web.region[2].records
  }
  description = "GeoDNS regional endpoints"
}