#!/usr/bin/env bash
# Atlas DNS — Interactive Setup Wizard
# Supports: Linux (systemd) and macOS (launchd)
# Usage: sudo bash scripts/setup.sh
set -euo pipefail

###############################################################################
# Colours & helpers
###############################################################################
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }

prompt() {
    # prompt <var_name> <message> <default>
    local __var="$1" msg="$2" default="$3"
    echo -ne "${BOLD}${msg}${RESET} [${CYAN}${default}${RESET}]: "
    read -r __input
    eval "$__var=\"${__input:-$default}\""
}

prompt_secret() {
    local __var="$1" msg="$2"
    echo -ne "${BOLD}${msg}${RESET}: "
    read -rs __input; echo
    eval "$__var=\"$__input\""
}

section() { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${RESET}"; }

###############################################################################
# Platform detection
###############################################################################
OS="$(uname -s)"
case "$OS" in
    Linux)  PLATFORM=linux ;;
    Darwin) PLATFORM=macos ;;
    *)      die "Unsupported OS: $OS. This wizard supports Linux and macOS." ;;
esac

# Require root on Linux for systemd install; on macOS we guide the user
if [[ $PLATFORM == linux && $EUID -ne 0 ]]; then
    warn "Not running as root. systemd unit installation will be skipped."
    warn "Re-run with sudo to install the service automatically."
    SKIP_SERVICE=1
else
    SKIP_SERVICE=0
fi

###############################################################################
# Banner
###############################################################################
echo -e "
${BOLD}${CYAN}
 █████╗ ████████╗██╗      █████╗ ███████╗    ██████╗ ███╗   ██╗███████╗
██╔══██╗╚══██╔══╝██║     ██╔══██╗██╔════╝    ██╔══██╗████╗  ██║██╔════╝
███████║   ██║   ██║     ███████║███████╗    ██║  ██║██╔██╗ ██║███████╗
██╔══██║   ██║   ██║     ██╔══██║╚════██║    ██║  ██║██║╚██╗██║╚════██║
██║  ██║   ██║   ███████╗██║  ██║███████║    ██████╔╝██║ ╚████║███████║
╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝
${RESET}
  Home Network Setup Wizard — Platform: ${BOLD}${PLATFORM}${RESET}
"

###############################################################################
# Detect install location of atlas binary
###############################################################################
section "Binary location"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Try release build first, then debug
if [[ -f "$REPO_ROOT/target/release/atlas" ]]; then
    DEFAULT_BINARY="$REPO_ROOT/target/release/atlas"
elif [[ -f "$REPO_ROOT/target/debug/atlas" ]]; then
    DEFAULT_BINARY="$REPO_ROOT/target/debug/atlas"
elif command -v atlas &>/dev/null; then
    DEFAULT_BINARY="$(command -v atlas)"
else
    DEFAULT_BINARY="/usr/local/bin/atlas"
fi

prompt ATLAS_BINARY "Path to atlas binary" "$DEFAULT_BINARY"
[[ -f "$ATLAS_BINARY" ]] || warn "Binary not found at '$ATLAS_BINARY'. You can build it with: cargo build --release"

###############################################################################
# Network interface detection
###############################################################################
section "Network interface detection"

detect_interfaces() {
    if [[ $PLATFORM == linux ]]; then
        ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' | head -10
    else
        ifconfig -l | tr ' ' '\n' | grep -v '^lo' | head -10
    fi
}

get_ip_for_iface() {
    local iface="$1"
    if [[ $PLATFORM == linux ]]; then
        ip -4 addr show "$iface" 2>/dev/null | awk '/inet / {split($2,a,"/"); print a[1]}' | head -1
    else
        ipconfig getifaddr "$iface" 2>/dev/null || echo ""
    fi
}

IFACES=()
while IFS= read -r line; do IFACES+=("$line"); done < <(detect_interfaces)

if [[ ${#IFACES[@]} -eq 0 ]]; then
    warn "Could not detect network interfaces. Defaulting to 0.0.0.0"
    SUGGESTED_IFACE="eth0"
    SUGGESTED_IP="0.0.0.0"
else
    echo "Detected network interfaces:"
    for i in "${!IFACES[@]}"; do
        iface="${IFACES[$i]}"
        ip="$(get_ip_for_iface "$iface")"
        echo "  $((i+1)). $iface  ${ip:+(IP: $ip)}"
    done

    # Pick the first non-loopback interface as default
    SUGGESTED_IFACE="${IFACES[0]}"
    SUGGESTED_IP="$(get_ip_for_iface "$SUGGESTED_IFACE")"
    [[ -z "$SUGGESTED_IP" ]] && SUGGESTED_IP="0.0.0.0"
fi

prompt LISTEN_IP "IP address to listen on (use 0.0.0.0 for all interfaces)" "${SUGGESTED_IP:-0.0.0.0}"

###############################################################################
# Port configuration
###############################################################################
section "Port configuration"

prompt DNS_PORT   "DNS port"      "53"
prompt WEB_PORT   "Web UI port"   "5380"
prompt HTTPS_PORT "HTTPS UI port (0 to disable)" "0"

###############################################################################
# Upstream / forwarding
###############################################################################
section "Upstream DNS forwarding"

echo "Common upstream servers:"
echo "  1. Cloudflare  — 1.1.1.1, 1.0.0.1"
echo "  2. Quad9        — 9.9.9.9, 149.112.112.112"
echo "  3. Google       — 8.8.8.8, 8.8.4.4"
echo "  4. None (authoritative-only mode)"
prompt FORWARD_CHOICE "Choose upstream (1-4, or type a custom IP)" "1"

case "$FORWARD_CHOICE" in
    1) FORWARD_SERVERS="1.1.1.1,1.0.0.1" ;;
    2) FORWARD_SERVERS="9.9.9.9,149.112.112.112" ;;
    3) FORWARD_SERVERS="8.8.8.8,8.8.4.4" ;;
    4) FORWARD_SERVERS="" ;;
    *) FORWARD_SERVERS="$FORWARD_CHOICE" ;;
esac

###############################################################################
# Blocklists
###############################################################################
section "Ad/malware blocking"

echo "Preset blocklists:"
echo "  1. Minimal    — Steven Black hosts (~130k domains)"
echo "  2. Standard   — + OISD basic (~100k domains)"
echo "  3. Aggressive — + abuse.ch URLhaus & Spamhaus DROP"
echo "  4. None"
prompt BLOCKLIST_PRESET "Choose preset (1-4)" "2"

BLOCKLIST_URLS=""
case "$BLOCKLIST_PRESET" in
    1)
        BLOCKLIST_URLS="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
        ;;
    2)
        BLOCKLIST_URLS="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
https://big.oisd.nl/domainswild"
        ;;
    3)
        BLOCKLIST_URLS="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
https://big.oisd.nl/domainswild
https://urlhaus.abuse.ch/downloads/hostfile/
https://www.spamhaus.org/drop/drop.txt"
        ;;
    *) ;;
esac

###############################################################################
# Admin credentials
###############################################################################
section "Admin account"

prompt ADMIN_USER "Admin username" "admin"
while true; do
    prompt_secret ADMIN_PASS "Admin password (min 8 chars)"
    if [[ ${#ADMIN_PASS} -lt 8 ]]; then
        warn "Password must be at least 8 characters."
    else
        prompt_secret ADMIN_PASS2 "Confirm password"
        [[ "$ADMIN_PASS" == "$ADMIN_PASS2" ]] && break
        warn "Passwords do not match. Try again."
    fi
done

###############################################################################
# Directories
###############################################################################
section "Storage directories"

if [[ $PLATFORM == linux ]]; then
    DEFAULT_CONFIG_DIR="/etc/atlas-dns"
    DEFAULT_ZONES_DIR="/var/lib/atlas-dns/zones"
    DEFAULT_LOG_DIR="/var/log/atlas-dns"
else
    DEFAULT_CONFIG_DIR="$HOME/.config/atlas-dns"
    DEFAULT_ZONES_DIR="$HOME/Library/Application Support/atlas-dns/zones"
    DEFAULT_LOG_DIR="$HOME/Library/Logs/atlas-dns"
fi

prompt CONFIG_DIR "Config directory" "$DEFAULT_CONFIG_DIR"
prompt ZONES_DIR  "Zones directory"  "$DEFAULT_ZONES_DIR"
prompt LOG_DIR    "Log directory"    "$DEFAULT_LOG_DIR"

###############################################################################
# Summary
###############################################################################
section "Configuration summary"

cat <<SUMMARY
  Binary       : $ATLAS_BINARY
  Listen IP    : $LISTEN_IP
  DNS port     : $DNS_PORT
  Web port     : $WEB_PORT
  Upstream DNS : ${FORWARD_SERVERS:-"(authoritative only)"}
  Blocklists   : ${BLOCKLIST_PRESET:-"none"}
  Config dir   : $CONFIG_DIR
  Zones dir    : $ZONES_DIR
  Log dir      : $LOG_DIR
SUMMARY

echo
echo -ne "${BOLD}Proceed with installation? [Y/n]: ${RESET}"
read -r CONFIRM
[[ "${CONFIRM,,}" =~ ^(n|no)$ ]] && { info "Aborted."; exit 0; }

###############################################################################
# Create directories
###############################################################################
section "Creating directories"

for dir in "$CONFIG_DIR" "$ZONES_DIR" "$LOG_DIR"; do
    if [[ ! -d "$dir" ]]; then
        if [[ $SKIP_SERVICE -eq 0 ]] || [[ "$dir" != /etc/* && "$dir" != /var/* ]]; then
            mkdir -p "$dir" && success "Created $dir"
        else
            warn "Skipping $dir (need root). Create manually: sudo mkdir -p $dir"
        fi
    else
        info "$dir already exists"
    fi
done

###############################################################################
# Generate config.toml
###############################################################################
section "Writing config.toml"

CONFIG_FILE="$CONFIG_DIR/config.toml"

# Build blocklist section
BLOCKLIST_SECTION=""
if [[ -n "$BLOCKLIST_URLS" ]]; then
    BLOCKLIST_SECTION=$'\n[blocklists]\nenabled = true\nauto_update = true\nupdate_interval_hours = 24\nurls = ['
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        BLOCKLIST_SECTION+=$'\n  "'"$url"'",'
    done <<< "$BLOCKLIST_URLS"
    BLOCKLIST_SECTION+=$'\n]\n'
fi

# Build forwarding section
FORWARD_SECTION=""
if [[ -n "$FORWARD_SERVERS" ]]; then
    FORWARD_SECTION=$'\n[forwarding]\nenabled = true\nservers = ['
    IFS=',' read -ra FWD_IPS <<< "$FORWARD_SERVERS"
    for ip in "${FWD_IPS[@]}"; do
        ip="${ip// /}"
        FORWARD_SECTION+=$'\n  "'"$ip"'",'
    done
    FORWARD_SECTION+=$'\n]\n'
fi

# HTTPS section
HTTPS_SECTION=""
if [[ "$HTTPS_PORT" != "0" && -n "$HTTPS_PORT" ]]; then
    HTTPS_SECTION="
[web.tls]
enabled = true
port = $HTTPS_PORT
# Provide paths to your certificates:
# cert_file = \"$CONFIG_DIR/certs/cert.pem\"
# key_file  = \"$CONFIG_DIR/certs/key.pem\"
"
fi

cat > "$CONFIG_FILE" <<EOF
# Atlas DNS — Configuration
# Generated by setup.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")

[server]
listen = "$LISTEN_IP"

[dns]
port = $DNS_PORT
enabled = true

[web]
enabled = true
port = $WEB_PORT
$HTTPS_SECTION
[auth]
enabled = true

[[auth.users]]
username = "$ADMIN_USER"
# Password is stored hashed at runtime; change via the web UI after first login.
# Initial password supplied during setup: (see below)
role = "admin"

[storage]
zones_dir = "$ZONES_DIR"

[logging]
level = "info"
file = "$LOG_DIR/atlas-dns.log"
$FORWARD_SECTION$BLOCKLIST_SECTION
EOF

success "Config written to $CONFIG_FILE"

# Write the initial admin password to a separate secrets file (chmod 600)
SECRETS_FILE="$CONFIG_DIR/.admin_password"
echo "$ADMIN_PASS" > "$SECRETS_FILE"
chmod 600 "$SECRETS_FILE"
success "Initial admin password saved to $SECRETS_FILE (chmod 600)"
info "Change your password via the web UI after first login, then delete this file."

###############################################################################
# systemd service (Linux)
###############################################################################
if [[ $PLATFORM == linux && $SKIP_SERVICE -eq 0 ]]; then
    section "Installing systemd service"

    SYSTEMD_UNIT="/etc/systemd/system/atlas-dns.service"
    FWDS=""
    if [[ -n "$FORWARD_SERVERS" ]]; then
        IFS=',' read -ra FWD_IPS <<< "$FORWARD_SERVERS"
        for ip in "${FWD_IPS[@]}"; do
            ip="${ip// /}"
            FWDS="$FWDS -f $ip"
        done
    fi

    cat > "$SYSTEMD_UNIT" <<EOF
[Unit]
Description=Atlas DNS Server
Documentation=https://github.com/your-org/atlas-dns
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=$ATLAS_BINARY \\
    --zones-dir $ZONES_DIR \\
    --forward-address $(echo "$FORWARD_SERVERS" | cut -d',' -f1) \\
    --listen $LISTEN_IP
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
StandardOutput=append:$LOG_DIR/atlas-dns.log
StandardError=append:$LOG_DIR/atlas-dns.log
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable atlas-dns
    success "systemd unit installed and enabled: $SYSTEMD_UNIT"
    info "Start the service with: sudo systemctl start atlas-dns"
    info "View logs with:         sudo journalctl -u atlas-dns -f"
fi

###############################################################################
# launchd plist (macOS)
###############################################################################
if [[ $PLATFORM == macos ]]; then
    section "Installing launchd service"

    PLIST_DIR="$HOME/Library/LaunchAgents"
    PLIST_FILE="$PLIST_DIR/com.atlas-dns.server.plist"
    mkdir -p "$PLIST_DIR"

    # Build ProgramArguments array
    ARGS_XML="    <string>$ATLAS_BINARY</string>"
    if [[ -n "$FORWARD_SERVERS" ]]; then
        IFS=',' read -ra FWD_IPS <<< "$FORWARD_SERVERS"
        for ip in "${FWD_IPS[@]}"; do
            ip="${ip// /}"
            ARGS_XML+="
    <string>--forward-address</string>
    <string>$ip</string>"
        done
    fi
    ARGS_XML+="
    <string>--zones-dir</string>
    <string>$ZONES_DIR</string>"

    cat > "$PLIST_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.atlas-dns.server</string>

  <key>ProgramArguments</key>
  <array>
$ARGS_XML
  </array>

  <key>RunAtLoad</key>
  <true/>

  <key>KeepAlive</key>
  <true/>

  <key>StandardOutPath</key>
  <string>$LOG_DIR/atlas-dns.log</string>

  <key>StandardErrorPath</key>
  <string>$LOG_DIR/atlas-dns.error.log</string>

  <key>WorkingDirectory</key>
  <string>$CONFIG_DIR</string>

  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
EOF

    success "launchd plist written to $PLIST_FILE"

    if [[ $EUID -eq 0 ]]; then
        launchctl load "$PLIST_FILE" 2>/dev/null || true
        success "Service loaded. Start with: launchctl start com.atlas-dns.server"
    else
        info "Load the service with:  launchctl load $PLIST_FILE"
        info "Start it with:          launchctl start com.atlas-dns.server"
        info "View logs with:         tail -f $LOG_DIR/atlas-dns.log"
    fi
fi

###############################################################################
# Log rotation
###############################################################################
section "Setting up log rotation"

if [[ $PLATFORM == linux ]]; then
    LOGROTATE_FILE="/etc/logrotate.d/atlas-dns"
    if [[ $SKIP_SERVICE -eq 0 ]]; then
        cat > "$LOGROTATE_FILE" <<EOF
$LOG_DIR/atlas-dns.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    postrotate
        systemctl kill --signal=HUP atlas-dns 2>/dev/null || true
    endscript
}
EOF
        success "logrotate config written to $LOGROTATE_FILE"
    else
        warn "Skipping /etc/logrotate.d/atlas-dns (need root)."
        warn "Manually create it with contents shown below:"
        cat <<EOF
$LOG_DIR/atlas-dns.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        systemctl kill --signal=HUP atlas-dns 2>/dev/null || true
    endscript
}
EOF
    fi
else
    # macOS — newsyslog
    NEWSYSLOG_CONF="$HOME/.newsyslog.d/atlas-dns.conf"
    mkdir -p "$(dirname "$NEWSYSLOG_CONF")"
    cat > "$NEWSYSLOG_CONF" <<EOF
# Atlas DNS log rotation
# logfile_name          owner:group  mode  count  size(KB)  when  flags  pid_file  sig_num
$LOG_DIR/atlas-dns.log   -:-         640   14     5120       *     JB    -         -
EOF
    success "newsyslog config written to $NEWSYSLOG_CONF"
    info "macOS does not auto-include ~/.newsyslog.d; consider using 'sudo newsyslog' or a periodic script."

    # Alternatively, write a simple logrotate-style shell script they can cron
    ROTATE_SCRIPT="$CONFIG_DIR/rotate-logs.sh"
    cat > "$ROTATE_SCRIPT" <<'EOF'
#!/usr/bin/env bash
# Simple log rotation for Atlas DNS on macOS
LOG="$HOME/Library/Logs/atlas-dns/atlas-dns.log"
MAX_FILES=14
[ -f "$LOG" ] || exit 0
for i in $(seq $((MAX_FILES-1)) -1 1); do
    [ -f "${LOG}.${i}.gz" ] && mv "${LOG}.${i}.gz" "${LOG}.$((i+1)).gz"
done
cp "$LOG" "${LOG}.1"
gzip -f "${LOG}.1"
: > "$LOG"  # truncate
# Signal Atlas to reopen log file if it supports it
pkill -HUP atlas 2>/dev/null || true
EOF
    chmod +x "$ROTATE_SCRIPT"
    success "macOS log rotation script: $ROTATE_SCRIPT"
    info "Add to cron for daily rotation: 0 0 * * * $ROTATE_SCRIPT"
fi

###############################################################################
# Blocklist update script reference
###############################################################################
section "Blocklist auto-update"

SCRIPTS_DIR="$REPO_ROOT/scripts"
if [[ -f "$SCRIPTS_DIR/update_blocklists.sh" ]]; then
    success "Blocklist updater found at: $SCRIPTS_DIR/update_blocklists.sh"
    info "Add to cron for daily updates:"
    echo "    0 3 * * * ATLAS_URL=http://127.0.0.1:$WEB_PORT $SCRIPTS_DIR/update_blocklists.sh"
else
    info "Blocklist updater script not found yet. Run: bash scripts/update_blocklists.sh"
fi

###############################################################################
# Done
###############################################################################
section "Setup complete"

echo -e "
${GREEN}${BOLD}Atlas DNS is configured!${RESET}

  Config file   : ${CYAN}$CONFIG_FILE${RESET}
  Web dashboard : ${CYAN}http://$LISTEN_IP:$WEB_PORT/dashboard${RESET}
  Web UI        : ${CYAN}http://$LISTEN_IP:$WEB_PORT/${RESET}

${BOLD}Next steps:${RESET}
  1. Review ${CYAN}$CONFIG_FILE${RESET} and adjust as needed.
  2. Start the service (see instructions above).
  3. Point your router's DNS to ${CYAN}$LISTEN_IP${RESET}.
     See ${CYAN}docs/ROUTER_SETUP.md${RESET} for router-specific instructions.
  4. Open the web UI and log in with username ${CYAN}$ADMIN_USER${RESET}.
     (Your initial password is in ${CYAN}$SECRETS_FILE${RESET} — change it and delete the file.)
"
