#!/usr/bin/env bash
# Atlas DNS — Blocklist Updater
#
# Downloads fresh blocklist files and reloads Atlas DNS without restarting.
# Cron-friendly: silent by default, exits 0 on success, non-zero on error.
#
# Usage:
#   ./update_blocklists.sh [OPTIONS]
#
# Options:
#   -v, --verbose     Print progress to stdout
#   -h, --help        Show this help
#   -d, --dir DIR     Directory to store downloaded blocklists
#                     (default: /var/lib/atlas-dns/blocklists  or  ~/.config/atlas-dns/blocklists)
#   -u, --url URL     Atlas DNS base URL  (default: http://127.0.0.1:5380)
#   -t, --token TOK   API bearer token (if auth is enabled)
#   -n, --no-reload   Download only; don't signal Atlas DNS to reload
#   --dry-run         Show what would be done without doing it
#
# Cron example (daily at 03:15):
#   15 3 * * * ATLAS_URL=http://127.0.0.1:5380 /opt/atlas-dns/scripts/update_blocklists.sh
#
# Environment variables (override defaults):
#   ATLAS_URL         Base URL of Atlas DNS web UI / API
#   ATLAS_TOKEN       Bearer token for API authentication
#   BLOCKLIST_DIR     Local directory for downloaded blocklists
#   BLOCKLIST_URLS    Space-separated list of URLs (overrides built-in defaults)

set -euo pipefail

###############################################################################
# Defaults
###############################################################################
VERBOSE=0
DRY_RUN=0
DO_RELOAD=1
ATLAS_URL="${ATLAS_URL:-http://127.0.0.1:5380}"
ATLAS_TOKEN="${ATLAS_TOKEN:-}"

# Pick a sensible default blocklist directory
if [[ -d /var/lib/atlas-dns ]]; then
    DEFAULT_DIR="/var/lib/atlas-dns/blocklists"
else
    DEFAULT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/atlas-dns/blocklists"
fi
BLOCKLIST_DIR="${BLOCKLIST_DIR:-$DEFAULT_DIR}"

# Default blocklist sources (hosts-file or plain domain format)
DEFAULT_URLS=(
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    "https://big.oisd.nl/domainswild"
    "https://urlhaus.abuse.ch/downloads/hostfile/"
)

###############################################################################
# CLI parsing
###############################################################################
usage() {
    sed -n '2,/^set -euo/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -v|--verbose)  VERBOSE=1; shift ;;
        -h|--help)     usage ;;
        -d|--dir)      BLOCKLIST_DIR="$2"; shift 2 ;;
        -u|--url)      ATLAS_URL="$2"; shift 2 ;;
        -t|--token)    ATLAS_TOKEN="$2"; shift 2 ;;
        -n|--no-reload) DO_RELOAD=0; shift ;;
        --dry-run)     DRY_RUN=1; VERBOSE=1; shift ;;
        *)             echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

###############################################################################
# Helpers
###############################################################################
log() { [[ $VERBOSE -eq 1 ]] && echo "[$(date '+%H:%M:%S')] $*" || true; }
err() { echo "[ERROR] $*" >&2; }

# Require a command to exist
need() {
    command -v "$1" &>/dev/null || { err "Required command not found: $1"; exit 1; }
}

need curl

# Build common curl flags
CURL_OPTS=(-fsSL --connect-timeout 15 --max-time 60 --retry 3 --retry-delay 5)
if [[ -n "$ATLAS_TOKEN" ]]; then
    CURL_OPTS+=(-H "Authorization: Bearer $ATLAS_TOKEN")
fi

###############################################################################
# Determine URLs to download
###############################################################################
if [[ -n "${BLOCKLIST_URLS:-}" ]]; then
    IFS=' ' read -ra URLS <<< "$BLOCKLIST_URLS"
else
    URLS=("${DEFAULT_URLS[@]}")
fi

log "Blocklist directory : $BLOCKLIST_DIR"
log "Atlas DNS URL       : $ATLAS_URL"
log "Sources             : ${#URLS[@]}"

###############################################################################
# Create working directories
###############################################################################
STAGING_DIR="$BLOCKLIST_DIR/.staging"

if [[ $DRY_RUN -eq 0 ]]; then
    mkdir -p "$BLOCKLIST_DIR" "$STAGING_DIR"
fi

###############################################################################
# Download each blocklist
###############################################################################
ERRORS=0
DOWNLOADED=0
SKIPPED=0

for url in "${URLS[@]}"; do
    # Derive a stable filename from the URL
    fname="$(echo "$url" | sha1sum | cut -c1-12).hosts"
    staging_path="$STAGING_DIR/$fname"
    dest_path="$BLOCKLIST_DIR/$fname"

    log "Fetching: $url"

    if [[ $DRY_RUN -eq 1 ]]; then
        log "  [dry-run] would save to $dest_path"
        continue
    fi

    # Download to staging
    if curl "${CURL_OPTS[@]}" -o "$staging_path" "$url" 2>/tmp/atlas_bl_curl_err; then
        new_size=$(wc -l < "$staging_path" 2>/dev/null || echo 0)
        log "  Downloaded $new_size lines"

        # Only replace if the file changed (avoid unnecessary reloads)
        if [[ -f "$dest_path" ]] && diff -q "$staging_path" "$dest_path" &>/dev/null; then
            log "  No change — skipping"
            rm -f "$staging_path"
            ((SKIPPED++)) || true
        else
            mv "$staging_path" "$dest_path"
            log "  Saved to $dest_path"
            ((DOWNLOADED++)) || true
        fi
    else
        err "Failed to download: $url"
        err "$(cat /tmp/atlas_bl_curl_err 2>/dev/null || true)"
        rm -f "$staging_path"
        ((ERRORS++)) || true
    fi
done

log "Summary: $DOWNLOADED updated, $SKIPPED unchanged, $ERRORS failed"

###############################################################################
# Reload Atlas DNS
###############################################################################
reload_via_api() {
    local endpoint="$ATLAS_URL/api/blocklists/reload"
    log "Reloading Atlas DNS via API: $endpoint"
    if [[ $DRY_RUN -eq 1 ]]; then
        log "  [dry-run] would POST to $endpoint"
        return 0
    fi

    local http_code
    http_code=$(curl "${CURL_OPTS[@]}" -o /dev/null -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d '{"action":"reload"}' \
        "$endpoint" 2>/dev/null) || true

    case "$http_code" in
        200|204) log "  API reload succeeded (HTTP $http_code)"; return 0 ;;
        401|403) err "API reload: authentication required (HTTP $http_code). Set ATLAS_TOKEN."; return 1 ;;
        404)
            # Endpoint may not exist in all versions — fall through to SIGHUP
            log "  /api/blocklists/reload not available; trying SIGHUP"
            return 1
            ;;
        *)
            err "API reload returned HTTP $http_code"
            return 1
            ;;
    esac
}

reload_via_sighup() {
    log "Reloading via SIGHUP to atlas process"
    if [[ $DRY_RUN -eq 1 ]]; then
        log "  [dry-run] would send SIGHUP to atlas"
        return 0
    fi

    if pkill -HUP -x atlas 2>/dev/null; then
        log "  SIGHUP sent"
        return 0
    elif systemctl is-active --quiet atlas-dns 2>/dev/null; then
        systemctl kill --signal=HUP atlas-dns
        log "  SIGHUP sent via systemctl"
        return 0
    elif launchctl list 2>/dev/null | grep -q com.atlas-dns; then
        # macOS launchd: stop + start to force a reload
        launchctl stop com.atlas-dns.server 2>/dev/null || true
        sleep 1
        launchctl start com.atlas-dns.server 2>/dev/null || true
        log "  Service restarted via launchctl"
        return 0
    else
        err "Could not find atlas process to signal"
        return 1
    fi
}

if [[ $DO_RELOAD -eq 1 && ( $DOWNLOADED -gt 0 || $DRY_RUN -eq 1 ) ]]; then
    log "Triggering reload ($DOWNLOADED blocklist(s) updated)"
    reload_via_api || reload_via_sighup || {
        err "Reload failed. Atlas DNS is still running with the old blocklists."
        err "Restart manually: sudo systemctl restart atlas-dns"
        ERRORS=$((ERRORS + 1))
    }
elif [[ $DO_RELOAD -eq 1 && $DOWNLOADED -eq 0 ]]; then
    log "No blocklists changed — reload not needed"
fi

###############################################################################
# Cleanup old staging files
###############################################################################
if [[ $DRY_RUN -eq 0 ]]; then
    rm -rf "$STAGING_DIR"
fi

###############################################################################
# Exit
###############################################################################
if [[ $ERRORS -gt 0 ]]; then
    err "$ERRORS error(s) occurred. Check output above."
    exit 1
fi

exit 0
