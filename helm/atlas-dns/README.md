# Atlas DNS Helm Chart

Enterprise-grade DNS server for Kubernetes with advanced features inspired by Cloudflare DNS.

## Features

- 🚀 **High Performance**: Sub-10ms response times with zero-copy networking
- 🔒 **Modern Protocols**: DoH, DoT, DNSSEC with automatic signing
- 🌍 **Global Load Balancing**: GeoDNS and proximity-based routing
- 📊 **Advanced Analytics**: Real-time metrics and Grafana dashboards
- 🎯 **Traffic Management**: A/B testing, canary deployments, blue-green
- 🛡️ **Security**: DDoS protection, DNS firewall, cache poisoning prevention
- ☸️ **K8s Native**: Operator, CRDs, service discovery, ingress integration

## Installation

### Add Helm Repository

```bash
helm repo add atlas-dns https://charts.atlas-dns.io
helm repo update
```

### Install Chart

```bash
# Install with default values
helm install atlas-dns atlas-dns/atlas-dns

# Install in specific namespace
helm install atlas-dns atlas-dns/atlas-dns --namespace dns-system --create-namespace

# Install with custom values
helm install atlas-dns atlas-dns/atlas-dns -f values.yaml
```

## Quick Start

### Basic DNS Server

```yaml
# values.yaml
deployment:
  replicaCount: 3

dns:
  forwarding:
    enabled: true
    servers:
      - "8.8.8.8"
      - "8.8.4.4"

service:
  dns:
    type: LoadBalancer
```

### With Web Interface

```yaml
web:
  enabled: true
  auth:
    enabled: true
    adminPassword: "secure-password-here"

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: dns.example.com
      paths:
        - path: /
          pathType: Prefix
```

### Production Configuration

```yaml
deployment:
  replicaCount: 5
  antiAffinity: hard

dns:
  cache:
    enabled: true
    size: "10000"
  rateLimit:
    enabled: true
    requestsPerSecond: 10000
  dnssec:
    enabled: true
    autoSign: true

autoscaling:
  enabled: true
  minReplicas: 5
  maxReplicas: 20
  targetCPUUtilizationPercentage: 70

resources:
  requests:
    cpu: 1000m
    memory: 1Gi
  limits:
    cpu: 4000m
    memory: 4Gi

monitoring:
  prometheus:
    enabled: true
    serviceMonitor:
      enabled: true
```

## Configuration

### Key Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `deployment.replicaCount` | Number of replicas | `3` |
| `dns.port` | DNS server port | `53` |
| `dns.forwarding.enabled` | Enable forwarding | `false` |
| `web.enabled` | Enable web interface | `true` |
| `service.dns.type` | DNS service type | `LoadBalancer` |
| `autoscaling.enabled` | Enable HPA | `false` |
| `monitoring.prometheus.enabled` | Enable metrics | `true` |

### Advanced Features

#### GeoDNS
```yaml
geodns:
  enabled: true
  database: "/usr/share/GeoIP/GeoLite2-City.mmdb"
  defaultLocation:
    continent: "NA"
    country: "US"
```

#### Traffic Steering
```yaml
trafficSteering:
  enabled: true
  mode: weighted
  pools:
    - name: production
      percentage: 90
    - name: canary
      percentage: 10
```

#### Multi-Region Failover
```yaml
multiRegion:
  enabled: true
  regions:
    - name: us-east
      priority: 1
      weight: 0.5
    - name: us-west
      priority: 2
      weight: 0.5
```

#### Kubernetes Operator
```yaml
operator:
  enabled: true
  watchAllNamespaces: true
  serviceDiscovery:
    enabled: true
    domainSuffix: "cluster.local"
```

## Persistence

### Zone Storage Options

1. **ConfigMap** (default)
```yaml
dns:
  zones:
    storage: configmap
```

2. **Persistent Volume**
```yaml
dns:
  zones:
    storage: persistent

persistence:
  enabled: true
  storageClass: "fast-ssd"
  size: 10Gi
```

3. **S3 Backend**
```yaml
dns:
  zones:
    storage: s3
    s3:
      bucket: "dns-zones"
      region: "us-east-1"
```

## Security

### TLS Configuration

#### Using cert-manager
```yaml
web:
  tls:
    enabled: true
    certManager:
      enabled: true
      issuer: "letsencrypt-prod"

ingress:
  tls:
    - secretName: atlas-dns-tls
      hosts:
        - dns.example.com
```

#### Manual Certificates
```yaml
web:
  tls:
    enabled: true
    cert: |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
    key: |
      -----BEGIN PRIVATE KEY-----
      ...
      -----END PRIVATE KEY-----
```

### DNSSEC
```yaml
dns:
  dnssec:
    enabled: true
    keyAlgorithm: "ECDSA256"
    autoSign: true
```

## Monitoring

### Prometheus Metrics
```yaml
monitoring:
  prometheus:
    enabled: true
    serviceMonitor:
      enabled: true
      interval: 30s
```

### Grafana Dashboards
```yaml
monitoring:
  grafana:
    enabled: true
    dashboards:
      enabled: true
      label: grafana_dashboard
```

## Backup and Recovery

```yaml
backup:
  enabled: true
  schedule: "0 2 * * *"  # Daily at 2 AM
  retention: 30
  storage:
    type: s3
    bucket: "dns-backups"
```

## Troubleshooting

### Check Pod Status
```bash
kubectl get pods -l app.kubernetes.io/name=atlas-dns
```

### View Logs
```bash
kubectl logs -l app.kubernetes.io/name=atlas-dns
```

### Test DNS Resolution
```bash
# Inside cluster
kubectl run -it --rm debug --image=busybox --restart=Never -- nslookup example.com atlas-dns-dns-udp

# External
dig @<EXTERNAL_IP> example.com
```

### Access Web Interface
```bash
kubectl port-forward svc/atlas-dns-web 8080:80
# Open http://localhost:8080
```

## Upgrade

```bash
# Upgrade to latest version
helm upgrade atlas-dns atlas-dns/atlas-dns

# Upgrade with new values
helm upgrade atlas-dns atlas-dns/atlas-dns -f values.yaml

# Rollback if needed
helm rollback atlas-dns
```

## Uninstall

```bash
helm uninstall atlas-dns
```

## Support

- Documentation: https://docs.atlas-dns.io
- GitHub: https://github.com/ktheindifferent/AtlasDNS
- Issues: https://github.com/ktheindifferent/AtlasDNS/issues

## License

MIT License - see LICENSE file for details