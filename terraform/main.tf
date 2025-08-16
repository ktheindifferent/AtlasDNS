terraform {
  required_version = ">= 1.0"
  required_providers {
    atlas-dns = {
      source  = "atlas-dns/atlas-dns"
      version = "~> 1.0.0"
    }
  }
}

# Configure the Atlas DNS Provider
provider "atlas-dns" {
  # API endpoint for Atlas DNS server
  endpoint = var.atlas_endpoint

  # API authentication
  api_key = var.atlas_api_key

  # Optional: Skip TLS verification for development
  insecure = var.insecure_skip_verify

  # Optional: Request timeout
  timeout = 30
}

# Variables
variable "atlas_endpoint" {
  description = "Atlas DNS API endpoint"
  type        = string
  default     = "https://localhost:5380"
}

variable "atlas_api_key" {
  description = "Atlas DNS API key"
  type        = string
  sensitive   = true
}

variable "insecure_skip_verify" {
  description = "Skip TLS certificate verification"
  type        = bool
  default     = false
}

# Create a DNS zone
resource "atlas-dns_zone" "example" {
  name        = "example.com"
  description = "Example DNS zone managed by Terraform"
  
  # SOA record configuration
  soa {
    mname   = "ns1.example.com"
    rname   = "admin.example.com"
    serial  = 2024010101
    refresh = 3600
    retry   = 600
    expire  = 604800
    minimum = 86400
  }

  # Name servers
  name_servers = [
    "ns1.example.com",
    "ns2.example.com"
  ]

  # Enable DNSSEC
  dnssec_enabled = true

  # Tags for organization
  tags = {
    environment = "production"
    managed_by  = "terraform"
  }
}

# Create A records
resource "atlas-dns_record" "www" {
  zone_id = atlas-dns_zone.example.id
  name    = "www"
  type    = "A"
  ttl     = 300
  values  = ["192.168.1.10"]
}

resource "atlas-dns_record" "app" {
  zone_id = atlas-dns_zone.example.id
  name    = "app"
  type    = "A"
  ttl     = 300
  values  = ["192.168.1.20", "192.168.1.21"]
}

# Create CNAME record
resource "atlas-dns_record" "blog" {
  zone_id = atlas-dns_zone.example.id
  name    = "blog"
  type    = "CNAME"
  ttl     = 3600
  values  = ["www.example.com"]
}

# Create MX records
resource "atlas-dns_record" "mx" {
  zone_id  = atlas-dns_zone.example.id
  name     = "@"
  type     = "MX"
  ttl      = 3600
  
  mx_record {
    priority = 10
    value    = "mail1.example.com"
  }
  
  mx_record {
    priority = 20
    value    = "mail2.example.com"
  }
}

# Create TXT records for SPF and DMARC
resource "atlas-dns_record" "spf" {
  zone_id = atlas-dns_zone.example.id
  name    = "@"
  type    = "TXT"
  ttl     = 3600
  values  = ["v=spf1 include:_spf.google.com ~all"]
}

resource "atlas-dns_record" "dmarc" {
  zone_id = atlas-dns_zone.example.id
  name    = "_dmarc"
  type    = "TXT"
  ttl     = 3600
  values  = ["v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"]
}

# Create SRV record
resource "atlas-dns_record" "srv" {
  zone_id = atlas-dns_zone.example.id
  name    = "_sip._tcp"
  type    = "SRV"
  ttl     = 3600
  
  srv_record {
    priority = 10
    weight   = 60
    port     = 5060
    target   = "sip.example.com"
  }
}

# Create a health check
resource "atlas-dns_health_check" "web" {
  name        = "web-health-check"
  description = "Health check for web servers"
  
  # Check configuration
  type     = "HTTP"
  target   = "www.example.com"
  port     = 80
  path     = "/health"
  interval = 30
  timeout  = 10
  retries  = 3
  
  # Expected response
  expected_response = "OK"
  expected_status   = 200
  
  # Alert configuration
  alert_enabled = true
  alert_email   = "ops@example.com"
}

# Create a traffic policy
resource "atlas-dns_traffic_policy" "load_balancing" {
  name        = "web-load-balancing"
  description = "Load balancing policy for web servers"
  zone_id     = atlas-dns_zone.example.id
  
  # Policy type
  type = "weighted"
  
  # Endpoints
  endpoint {
    name   = "server1"
    value  = "192.168.1.10"
    weight = 50
    health_check_id = atlas-dns_health_check.web.id
  }
  
  endpoint {
    name   = "server2"
    value  = "192.168.1.11"
    weight = 50
    health_check_id = atlas-dns_health_check.web.id
  }
  
  # Failover configuration
  failover {
    enabled   = true
    threshold = 2
  }
}

# Create a GeoDNS policy
resource "atlas-dns_geodns_policy" "regional" {
  name        = "regional-routing"
  description = "Route traffic based on geographic location"
  zone_id     = atlas-dns_zone.example.id
  
  # Default location
  default_location = "US"
  
  # Regional configurations
  region {
    name      = "north-america"
    countries = ["US", "CA", "MX"]
    records   = ["192.168.1.10", "192.168.1.11"]
  }
  
  region {
    name      = "europe"
    countries = ["GB", "FR", "DE", "IT", "ES"]
    records   = ["192.168.2.10", "192.168.2.11"]
  }
  
  region {
    name      = "asia-pacific"
    countries = ["JP", "CN", "AU", "IN", "SG"]
    records   = ["192.168.3.10", "192.168.3.11"]
  }
}

# Create a rate limit rule
resource "atlas-dns_rate_limit" "api" {
  name        = "api-rate-limit"
  description = "Rate limiting for API endpoints"
  
  # Rate limit configuration
  requests_per_second = 1000
  burst_size         = 2000
  
  # Apply to specific zones or records
  apply_to {
    zones   = [atlas-dns_zone.example.id]
    records = ["api.example.com"]
  }
  
  # Action when limit exceeded
  action = "drop"  # drop, refuse, or truncate
  
  # Whitelist
  whitelist = [
    "192.168.0.0/16",
    "10.0.0.0/8"
  ]
}

# Create a firewall rule
resource "atlas-dns_firewall_rule" "block_malicious" {
  name        = "block-malicious"
  description = "Block known malicious domains"
  
  # Rule type
  type = "blacklist"
  
  # Domains to block
  domains = [
    "malicious1.com",
    "phishing-site.net",
    "*.suspicious-domain.org"
  ]
  
  # Action
  action = "nxdomain"  # nxdomain, refuse, or redirect
  
  # Optional: Redirect target
  # redirect_target = "blocked.example.com"
  
  # Enable logging
  log_enabled = true
}

# Apply a zone template
resource "atlas-dns_zone_from_template" "web_hosting" {
  template_id = "basic-web"
  zone_name   = "newsite.com"
  
  # Template variables
  variables = {
    web_ip      = "192.168.1.100"
    mail_server = "mail.newsite.com"
  }
  
  # Override template settings
  ttl_override = 600
  
  tags = {
    template = "basic-web"
    purpose  = "web-hosting"
  }
}

# Data source: Get existing zone
data "atlas-dns_zone" "existing" {
  name = "existing-domain.com"
}

# Data source: Query DNS records
data "atlas-dns_records" "all_a_records" {
  zone_id = data.atlas-dns_zone.existing.id
  type    = "A"
}

# Output zone information
output "zone_id" {
  value       = atlas-dns_zone.example.id
  description = "The ID of the created DNS zone"
}

output "zone_nameservers" {
  value       = atlas-dns_zone.example.name_servers
  description = "Name servers for the zone"
}

output "a_records" {
  value       = data.atlas-dns_records.all_a_records.records
  description = "All A records in the existing zone"
}