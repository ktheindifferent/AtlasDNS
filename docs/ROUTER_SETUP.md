# Router Setup Guide — Point Your Network at Atlas DNS

After running the setup wizard, you need to tell your router (or individual devices) to use Atlas DNS as their DNS resolver. Below are step-by-step instructions for the most common home routers and firewall platforms.

Replace `192.168.1.2` with the actual LAN IP of your Atlas DNS machine throughout.

---

## Table of Contents

1. [Asus (Merlin & stock firmware)](#1-asus-routers)
2. [Netgear (Nighthawk / Orbi)](#2-netgear-routers)
3. [TP-Link (Archer series)](#3-tp-link-archer-routers)
4. [pfSense / OPNsense](#4-pfsense--opnsense)
5. [OpenWrt / DD-WRT](#5-openwrt--dd-wrt)
6. [Per-device fallback (no router access)](#6-per-device-fallback)
7. [Verifying it works](#7-verifying-it-works)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Asus Routers

Tested on: RT-AX88U, RT-AC86U, ZenWiFi AX (XT8). Works the same on stock firmware and Asuswrt-Merlin.

### Method A — Override DHCP-advertised DNS (recommended)

This pushes Atlas DNS to every device that gets an IP from the router.

1. Log into the router admin panel: `http://192.168.1.1` (default) or `http://router.asus.com`.
2. Navigate to **LAN → DHCP Server**.
3. Set **DNS Server 1** to `192.168.1.2`.
4. Set **DNS Server 2** to `1.1.1.1` (fallback, in case Atlas DNS is unreachable).
5. Click **Apply**.
6. Under **LAN → DNS Director** (Merlin only), you can optionally force all DNS through Atlas DNS regardless of client settings.

### Method B — WAN DNS (only affects the router itself)

1. Go to **WAN → Internet Connection**.
2. Set **DNS Server 1** to `192.168.1.2`.
3. Set **DNS Server 2** to `1.1.1.1`.
4. Click **Apply**.

> **Note:** Method B only changes the router's own resolver, not what it advertises to DHCP clients. Use Method A to cover all devices.

### Merlin — DNS Director (block DoH bypass)

On Asuswrt-Merlin ≥ 386.x you can intercept and redirect all DNS traffic:

1. **WAN → DNS Director → Enable DNS Director**: On.
2. Set **Default redirect**: `192.168.1.2`.
3. Click **Apply**. All UDP/TCP port-53 traffic is now redirected to Atlas DNS.

---

## 2. Netgear Routers

Tested on: Nighthawk R7000, R8000, RAX80; Orbi RBR50.

### DHCP DNS override

1. Open the admin panel: `http://192.168.1.1` or `http://routerlogin.net`.
2. Go to **Advanced → Setup → LAN Setup** (some models: **Setup → LAN Setup**).
3. Under **Domain Name Server (DNS) Address**:
   - **Primary DNS**: `192.168.1.2`
   - **Secondary DNS**: `1.1.1.1`
4. Click **Apply**.

### Orbi

1. Log into Orbi: `http://orbilogin.com` or `http://192.168.1.1`.
2. Go to **Advanced → Setup → LAN Setup**.
3. Set the same Primary/Secondary DNS as above.
4. Click **Apply**. Orbi satellites pick up the change automatically.

> **Tip:** On newer Orbi (RBK863S, RBK953), you may also find **Internet → DNS Address**. Set both.

---

## 3. TP-Link Archer Routers

Tested on: Archer AX50, AX73, AX6000, C7; Deco mesh systems.

### Archer (non-Deco)

1. Log in at `http://192.168.0.1` or `http://tplinkwifi.net`.
2. Navigate to **Advanced → Network → DHCP Server**.
3. Set:
   - **Primary DNS**: `192.168.1.2`
   - **Secondary DNS**: `1.1.1.1`
4. Click **Save**.

### Deco (app or web)

**Via the Tether app:**
1. Open Tether → tap your Deco network → tap the gear icon → **Advanced**.
2. Tap **IPv4** (or **LAN**) → **DNS**.
3. Set **Primary DNS** to `192.168.1.2`, secondary to `1.1.1.1`.
4. Save.

**Via the web UI (Deco BE95 and later):**
1. Open `http://deco.tp-link.com`.
2. Go to **Network → DHCP → DNS Settings**.
3. Enter the same values and save.

---

## 4. pfSense / OPNsense

These platforms give you the most control. There are two approaches:

### Option A — Use Atlas DNS as the forwarding resolver (easiest)

Forward all DNS queries from pfSense's own Unbound/DNS Resolver to Atlas DNS.

**pfSense:**
1. Go to **Services → DNS Resolver**.
2. Uncheck **Enable DNSSEC Support** if Atlas DNS handles DNSSEC itself.
3. Under **Custom Options**, add:
   ```
   forward-zone:
     name: "."
     forward-addr: 192.168.1.2@53
   ```
4. Click **Save** → **Apply Changes**.

**OPNsense:**
1. Go to **Services → Unbound DNS → General**.
2. Enable **DNS Query Forwarding**.
3. Under **DNS Servers** (System → Settings → General), add `192.168.1.2`.
4. Apply.

### Option B — Advertise Atlas DNS via DHCP (clients use it directly)

**pfSense:**
1. Go to **Services → DHCP Server → LAN** (or your relevant interface).
2. Under **DNS Servers**, enter `192.168.1.2` as the first entry and `1.1.1.1` as fallback.
3. Save & apply.

**OPNsense:**
1. Go to **Services → ISC DHCPv4 → [LAN]**.
2. Set **DNS Servers** to `192.168.1.2, 1.1.1.1`.
3. Save.

### Force all DNS through Atlas DNS (prevent bypass)

In pfSense/OPNsense you can redirect port-53 traffic using a NAT rule:

1. Go to **Firewall → NAT → Port Forward**.
2. Add a rule:
   - Interface: LAN
   - Protocol: TCP/UDP
   - Destination: any, port 53
   - Redirect target IP: `192.168.1.2`, port 53
3. Save & apply.

This catches devices that hard-code a DNS server (e.g., smart TVs using `8.8.8.8`).

---

## 5. OpenWrt / DD-WRT

### OpenWrt

OpenWrt uses **dnsmasq** by default. You have two options:

#### Option A — Replace dnsmasq with Atlas DNS directly

If Atlas DNS is running on the OpenWrt router itself on port 53, that's all you need. Skip to [verification](#7-verifying-it-works).

#### Option B — Forward from dnsmasq to Atlas DNS (Atlas on a separate host)

1. SSH into OpenWrt: `ssh root@192.168.1.1`
2. Edit `/etc/dnsmasq.conf` (or create `/etc/dnsmasq.d/atlas.conf`):
   ```
   no-resolv
   server=192.168.1.2
   ```
3. Restart dnsmasq:
   ```bash
   /etc/init.d/dnsmasq restart
   ```

#### Option C — DHCP DNS via LuCI

1. Open LuCI: `http://192.168.1.1`.
2. Go to **Network → Interfaces → LAN → Edit**.
3. Scroll to **DHCP Server → Advanced Settings**.
4. Set **DHCP-Options**: `6,192.168.1.2,1.1.1.1`
   (option 6 = DNS servers, comma-separated list sent to clients)
5. Click **Save & Apply**.

### DD-WRT

1. Open admin panel: `http://192.168.1.1`.
2. Go to **Setup → Basic Setup**.
3. Under **Network Address Server Settings (DHCP)**:
   - **Static DNS 1**: `192.168.1.2`
   - **Static DNS 2**: `1.1.1.1`
4. Also set **Local DNS** to `192.168.1.2` to make the router itself use Atlas DNS.
5. Click **Save** → **Apply Settings**.

---

## 6. Per-device Fallback

If you cannot change the router, configure each device individually.

### Windows 11/10

1. **Settings → Network & Internet → [your connection] → DNS server assignment → Edit**.
2. Switch to **Manual**.
3. Enable IPv4, set **Preferred DNS** to `192.168.1.2`, **Alternate DNS** to `1.1.1.1`.
4. Save.

### macOS

1. **System Settings → Network → [your connection] → Details → DNS**.
2. Click **+** and add `192.168.1.2`.
3. Move it to the top of the list.
4. Click **OK** → **Apply**.

### Linux (systemd-resolved)

```bash
# Edit /etc/systemd/resolved.conf
[Resolve]
DNS=192.168.1.2
FallbackDNS=1.1.1.1
```
Then restart: `sudo systemctl restart systemd-resolved`

### Linux (NetworkManager)

```bash
nmcli con mod "Your Connection Name" ipv4.dns "192.168.1.2 1.1.1.1"
nmcli con mod "Your Connection Name" ipv4.ignore-auto-dns yes
nmcli con up "Your Connection Name"
```

---

## 7. Verifying It Works

### Quick DNS check

```bash
# Should return the IP of the domain from Atlas DNS
dig @192.168.1.2 google.com

# Check that a blocklisted domain is refused
dig @192.168.1.2 doubleclick.net
# Expected: NXDOMAIN or REFUSED
```

### Check from the Atlas DNS web UI

Open `http://192.168.1.2:5380/dashboard` — you should see:
- **Queries/sec** rising as devices make DNS requests
- **Blocked count** increasing when ads/trackers are queried
- **Resolver latency** in the single-digit milliseconds for cached results

### Test from a network device

```bash
# macOS / Linux
nslookup google.com 192.168.1.2

# Windows (PowerShell)
Resolve-DnsName google.com -Server 192.168.1.2
```

---

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| DNS queries time out | Atlas DNS not running | `sudo systemctl status atlas-dns` or `launchctl list \| grep atlas` |
| Devices still use old DNS | DHCP lease not renewed | Force-renew: `ipconfig /renew` (Windows), `sudo dhclient` (Linux), or reconnect to Wi-Fi |
| Everything resolves to NXDOMAIN | Forwarding misconfigured | Check `config.toml` `[forwarding]` section; verify upstream reachability: `dig @1.1.1.1 google.com` |
| Web UI unreachable | Firewall blocking port 5380 | Open the port: `sudo ufw allow 5380/tcp` (Linux) or add a macOS firewall rule |
| Port 53 permission denied | Binding to privileged port | Run as root, or use `AmbientCapabilities=CAP_NET_BIND_SERVICE` (already set in the systemd unit) |
| Blocklist not loading | Network issue or format mismatch | Run `scripts/update_blocklists.sh -v` to see errors |

### Enable debug logging

In `config.toml`:
```toml
[logging]
level = "debug"
```
Then `sudo systemctl restart atlas-dns` (Linux) or `launchctl stop/start com.atlas-dns.server` (macOS).

---

*For more details, see [docs/home-deployment.md](home-deployment.md) and the [Atlas DNS README](../README.md).*
