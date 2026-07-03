#!/usr/bin/env bash
set -euo pipefail

# wan-watchdog.sh
#
# Runs every 5 minutes via wan-watchdog.timer. Two independent checks:
#   1. WAN interface has an IP (self-recover only for our stack)
#   2. External DNS still resolves (tripwire for a silently-broken resolv.conf)
#
# Reachability is monitored but NOT self-healed: three consecutive ping
# failures with a valid WAN IP means the ISP is down, not us — invoking a
# DHCP client behind NetworkManager's back has historically wiped
# /etc/resolv.conf (2026-07-01 outage) and released NM's own lease, so we
# now log-only for that branch.
#
# State:
#   /var/lib/beaconbutty/wan-fails       — consecutive ping-failure count
#   /var/lib/beaconbutty/dns-fails       — consecutive DNS-failure count
#   /var/log/beaconbutty/watchdog.log    — human-readable log

WAN_IFACE="${WAN_IFACE:-eth0}"
NM_CONN="${NM_CONN:-bb-wan}"    # NetworkManager connection profile for WAN
FAIL_THRESHOLD=3
PROBE_HOSTS="1.1.1.1 8.8.8.8"
DNS_PROBE_HOST="${DNS_PROBE_HOST:-cloudflare.com}"

STATE_DIR="/var/lib/beaconbutty"
STATE_FILE="${STATE_DIR}/wan-fails"
DNS_STATE_FILE="${STATE_DIR}/dns-fails"
LOGFILE="/var/log/beaconbutty/watchdog.log"
ALERT_SH="/usr/local/bin/beaconbutty-alert.sh"

mkdir -p "$STATE_DIR" "$(dirname "$LOGFILE")"

log() {
    local msg="$*"
    echo "$(date --iso-8601=seconds)  $msg" >> "$LOGFILE"
    logger -t beaconbutty-watchdog "$msg"
}

read_count() { cat "$1" 2>/dev/null || echo 0; }
write_count() { echo "$2" > "$1"; }

# ── DHCP renewal via NetworkManager only ──────────────────────────────────────
# On bb0 NM owns eth0 (see scripts/07_router_mode.sh). NEVER invoke the
# `dhclient` or `dhcpcd` binaries directly — dhcpcd-base is installed as a
# transitive dep but running the daemon behind NM's back releases NM's lease
# and its 20-resolv.conf hook overwrites /etc/resolv.conf with an empty file.
renew_wan_lease() {
    if command -v nmcli >/dev/null 2>&1 \
       && nmcli -t -f NAME con show --active 2>/dev/null | grep -qx "$NM_CONN"; then
        log "Renewing $NM_CONN via nmcli (device reapply $WAN_IFACE)"
        nmcli device reapply "$WAN_IFACE" 2>/dev/null || \
            { nmcli connection down "$NM_CONN" 2>/dev/null || true;
              sleep 1;
              nmcli connection up   "$NM_CONN" 2>/dev/null || true; }
    else
        log "SKIPPED: no NetworkManager connection '$NM_CONN' active — refusing to invoke dhcpcd/dhclient (would wipe /etc/resolv.conf)"
    fi
}

# ── Check 1: WAN interface has an IP ──────────────────────────────────────────
WAN_IP=$(ip -4 addr show "$WAN_IFACE" 2>/dev/null | awk '/inet / {print $2}' | head -1)

if [[ -z "$WAN_IP" ]]; then
    FAILS=$(( $(read_count "$STATE_FILE") + 1 ))
    write_count "$STATE_FILE" "$FAILS"
    log "WAN ($WAN_IFACE) has no IP address. Fail ${FAILS}/${FAIL_THRESHOLD}"

    if [[ "$FAILS" -ge "$FAIL_THRESHOLD" ]]; then
        renew_wan_lease
        write_count "$STATE_FILE" 0
    fi
    exit 0
fi

# ── Check 2: Can we reach upstream hosts? ─────────────────────────────────────
REACHABLE=false
for host in $PROBE_HOSTS; do
    if ping -c 2 -W 3 -q "$host" &>/dev/null; then
        REACHABLE=true
        break
    fi
done

if $REACHABLE; then
    PREV_FAILS=$(read_count "$STATE_FILE")
    write_count "$STATE_FILE" 0
    [[ "$PREV_FAILS" -gt 0 ]] && log "WAN connectivity restored (was at ${PREV_FAILS} failures). WAN IP: $WAN_IP"
else
    FAILS=$(( $(read_count "$STATE_FILE") + 1 ))
    write_count "$STATE_FILE" "$FAILS"
    log "WAN unreachable (probed: $PROBE_HOSTS). WAN IP: $WAN_IP. Fail ${FAILS}/${FAIL_THRESHOLD} — likely ISP outage, no action"
    # Historic behaviour was to renew DHCP here; that helps nothing when the
    # ISP is down and, worse, ran dhcpcd behind NM's back and wiped
    # /etc/resolv.conf (2026-07-01 incident).
fi

# ── Check 3: DNS tripwire ─────────────────────────────────────────────────────
# Only runs when we actually have a WAN IP so that an ISP outage doesn't
# masquerade as a DNS fault.
if getent hosts "$DNS_PROBE_HOST" >/dev/null 2>&1; then
    PREV_DNS_FAILS=$(read_count "$DNS_STATE_FILE")
    write_count "$DNS_STATE_FILE" 0
    [[ "$PREV_DNS_FAILS" -ge "$FAIL_THRESHOLD" ]] && log "DNS resolution restored ($DNS_PROBE_HOST)"
else
    DNS_FAILS=$(( $(read_count "$DNS_STATE_FILE") + 1 ))
    write_count "$DNS_STATE_FILE" "$DNS_FAILS"
    NSLIST=$(grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ' | sed 's/ $//')
    log "DNS lookup for $DNS_PROBE_HOST failed. Fail ${DNS_FAILS}/${FAIL_THRESHOLD}. resolv.conf nameservers: '${NSLIST:-NONE}'"
    # Fire once when we cross the threshold. Detail is stable (no timestamps/counts)
    # so the Lambda dedup on (type,device,detail) collapses repeated fires.
    if [[ "$DNS_FAILS" -eq "$FAIL_THRESHOLD" && -x "$ALERT_SH" ]]; then
        "$ALERT_SH" service_down high bb0 "DNS resolution failing — /etc/resolv.conf nameservers: '${NSLIST:-NONE}'" \
            >>"$LOGFILE" 2>&1 || true
    fi
fi

# Under `set -e`, the trailing `[[ ]] && log` on line ~105 propagates its false
# result as the script's exit code. Terminate explicitly.
exit 0
