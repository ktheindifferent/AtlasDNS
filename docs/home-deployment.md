# AtlasDNS Home Network Deployment Guide

This guide covers deploying AtlasDNS as your home network DNS server for ad blocking,
device tracking, and DNS-over-HTTPS upstream privacy.

## Prerequisites

- A machine with a static IP on your home network (Linux/macOS)
- AtlasDNS built and ready to run (`cargo build --release`)
- Router admin access

---

## Step 1 — Assign a Static IP to the AtlasDNS Machine

The machine running AtlasDNS needs a predictable IP so every device on the network
can reach it. Two approaches:

**Option A — DHCP Reservation (recommended)**

Most routers let you pin a specific IP to a device by its MAC address.

1. Find the MAC address of your machine: `ip link` (Linux) or `ifconfig` (macOS).
2. Log into your router admin UI and navigate to DHCP/LAN settings.
3. Add a "static DHCP reservation" mapping your machine's MAC to e.g. `192.168.1.2`.
4. Reboot the machine to pick up the reserved address.

**Option B — Static IP on the machine itself**

Configure the NIC directly in `/etc/network/interfaces` (Debian/Ubuntu) or via
System Preferences → Network (macOS). Use an address outside the router's DHCP pool.

---

## Step 2 — Run AtlasDNS

```bash
# Basic: recursive resolver, web UI on port 5380
sudo ./target/release/atlas

# With DNS-over-HTTPS upstream (Cloudflare), UDP fallback to 1.1.1.1
sudo ./target/release/atlas --doh-url https://cloudflare-dns.com/dns-query --forward-address 1.1.1.1

# With a blocklist bundle applied via the API after startup
curl -X POST http://localhost:5380/api/v2/blocklists/bundle \
     -H 'Content-Type: application/json' \
     -d '{"bundle":"home_plus"}'
```

AtlasDNS binds to port 53 (DNS) and 5380 (web UI).  The `--skip-privilege-check`
flag lets you run on a high port during development without `sudo`.

---

## Step 3 — Point Your Router to AtlasDNS

Log into your router admin UI and set the **primary DNS server** to the static IP
of the AtlasDNS machine (e.g. `192.168.1.2`). Leave secondary DNS blank or set it
to a public resolver (e.g. `1.1.1.1`) as a fallback.

### Common Router Models

| Brand | How to find the setting |
|-------|------------------------|
| **Asus** | Advanced Settings → LAN → DHCP Server → DNS Server 1 |
| **Netgear** | Advanced → Setup → Internet Setup → Domain Name Server (DNS) Address |
| **TP-Link** | Advanced → Network → DHCP Server → Primary DNS |
| **Google Wifi / Nest** | App → Network → Advanced Networking → DNS |
| **Eero** | App → Settings → Network Settings → DNS |
| **pfSense / OPNsense** | Services → DHCP Server → DNS Servers |

After saving, devices that renew their DHCP lease (or reboot) will start using
AtlasDNS automatically.

---

## Step 4 — Testing

Verify resolution and blocking from any device on the network:

```bash
# Normal lookup should resolve successfully
nslookup google.com 192.168.1.2

# Ad domain should return NXDOMAIN or 0.0.0.0 when blocked
nslookup ads.example.com 192.168.1.2

# From Linux/macOS using dig
dig @192.168.1.2 google.com
dig @192.168.1.2 doubleclick.net
```

Check the web UI at `http://192.168.1.2:5380` for:
- Dashboard → query counts and blocked domains
- Query Log → per-device activity (`GET /api/v2/query-log?client=192.168.1.x`)
- Clients → top querying devices (`GET /api/v2/clients`)

---

## Troubleshooting

**Devices still use old DNS**

DHCP leases may not have expired yet.  Force renewal:

```bash
# Windows
ipconfig /release && ipconfig /renew

# macOS
sudo ipconfig set en0 DHCP

# Linux (NetworkManager)
nmcli connection down id "Wi-Fi" && nmcli connection up id "Wi-Fi"
```

**Port 53 permission denied**

On Linux, binding to port 53 requires root or the `CAP_NET_BIND_SERVICE` capability:

```bash
sudo setcap 'cap_net_bind_service=+ep' ./target/release/atlas
./target/release/atlas   # no sudo needed
```

**DNS resolution broken after pointing router to AtlasDNS**

Check that AtlasDNS is running and listening:

```bash
ss -ulnp | grep :53   # UDP
ss -tlnp | grep :53   # TCP
```

If AtlasDNS crashed, check its log output.  Ensure port 53 is not already in use
by `systemd-resolved` or another local resolver:

```bash
sudo systemctl disable --now systemd-resolved
sudo rm /etc/resolv.conf
echo "nameserver 192.168.1.2" | sudo tee /etc/resolv.conf
```

**Blocked sites that shouldn't be**

Some blocklists are aggressive. To remove a single entry:

```bash
curl -X DELETE http://localhost:5380/api/v2/blocklists/<id>
```

Or switch from `home_plus` to `home_basic` for fewer false positives.

---

## Applying Blocklist Bundles

Three preset bundles are available:

| Bundle | Lists included | Use case |
|--------|---------------|----------|
| `home_basic` | Hagezi Light + StevenBlack | Light blocking, fewest false positives |
| `home_plus` | Hagezi Pro + StevenBlack + URLhaus | Comprehensive — recommended for most homes |
| `strict` | Hagezi Pro + OISD Full + StevenBlack Extended + URLhaus | Aggressive — includes gambling/adult |

```bash
curl -X POST http://localhost:5380/api/v2/blocklists/bundle \
     -H 'Content-Type: application/json' \
     -d '{"bundle": "home_plus"}'
```

---

## DNS-over-HTTPS Upstream

To prevent your ISP from seeing your DNS queries, configure AtlasDNS to forward
upstream lookups over HTTPS:

```bash
# Cloudflare (privacy-first, no logging)
--doh-url https://cloudflare-dns.com/dns-query

# Google
--doh-url https://dns.google/dns-query

# Quad9 (with malware blocking)
--doh-url https://dns.quad9.net/dns-query
```

AtlasDNS will fall back to plain UDP if the DoH request fails.
