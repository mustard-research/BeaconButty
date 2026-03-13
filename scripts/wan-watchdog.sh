#!/usr/bin/env bash
set -euo pipefail

# wan-watchdog.sh
#
# Monitors WAN connectivity every 5 minutes (via wan-watchdog.timer).
# If the WAN is unreachable for FAIL_THRESHOLD consecutive checks,
# it attempts a DHCP renewal on the WAN interface.
#
# Unlike the bridge watchdog, this does NOT revert configuration —
# there is nothing to fall back to in router mode. Instead it tries
# to self-heal and logs persistently for operator review.
#
# State:
#   /var/lib/beaconbutty/wan-fails    — consecutive failure count
#   /var/log/beaconbutty/watchdog.log — human-readable log

WAN_IFACE="${WAN_IFACE:-eth0}"
FAIL_THRESHOLD=3              # Attempt DHCP renewal after this many consecutive failures
PROBE_HOSTS="1.1.1.1 8.8.8.8"  # Hosts to ping for connectivity check

STATE_DIR="/var/lib/beaconbutty"
STATE_FILE="${STATE_DIR}/wan-fails"
LOGFILE="/var/log/beaconbutty/watchdog.log"

mkdir -p "$STATE_DIR" "$(dirname "$LOGFILE")"

log() {
    local msg="$*"
    echo "$(date --iso-8601=seconds)  $msg" >> "$LOGFILE"
    logger -t beaconbutty-watchdog "$msg"
}

read_fails() { cat "$STATE_FILE" 2>/dev/null || echo 0; }
write_fails() { echo "$1" > "$STATE_FILE"; }

# ── Check 1: WAN interface has an IP ─────────────────────────────────────────
WAN_IP=$(ip -4 addr show "$WAN_IFACE" 2>/dev/null | awk '/inet / {print $2}' | head -1)

if [[ -z "$WAN_IP" ]]; then
    FAILS=$(( $(read_fails) + 1 ))
    write_fails "$FAILS"
    log "WAN ($WAN_IFACE) has no IP address. Fail ${FAILS}/${FAIL_THRESHOLD}"

    if [[ "$FAILS" -ge "$FAIL_THRESHOLD" ]]; then
        log "Attempting DHCP renewal on $WAN_IFACE..."
        dhclient -r "$WAN_IFACE" 2>/dev/null || true
        dhclient "$WAN_IFACE" 2>/dev/null || true
        write_fails 0
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
    # All good — reset failure counter silently
    PREV_FAILS=$(read_fails)
    write_fails 0
    if [[ "$PREV_FAILS" -gt 0 ]]; then
        log "WAN connectivity restored (was at ${PREV_FAILS} failures). WAN IP: $WAN_IP"
    fi
    exit 0
fi

# ── Connectivity failure ───────────────────────────────────────────────────────
FAILS=$(( $(read_fails) + 1 ))
write_fails "$FAILS"
log "WAN unreachable (probed: $PROBE_HOSTS). WAN IP: $WAN_IP. Fail ${FAILS}/${FAIL_THRESHOLD}"

if [[ "$FAILS" -ge "$FAIL_THRESHOLD" ]]; then
    log "Threshold reached — renewing DHCP on $WAN_IFACE"

    # Attempt DHCP renewal: release existing lease first, then request fresh one.
    # dhclient: -r releases, then re-run acquires.
    # dhcpcd:   -k sends RELEASE and exits, then re-run acquires.
    if command -v dhclient &>/dev/null; then
        dhclient -r "$WAN_IFACE" 2>/dev/null || true
        dhclient "$WAN_IFACE"   2>/dev/null || true
    elif command -v dhcpcd &>/dev/null; then
        dhcpcd -k "$WAN_IFACE"  2>/dev/null || true
        sleep 1
        dhcpcd "$WAN_IFACE"     2>/dev/null || true
    fi

    write_fails 0
    log "DHCP renewal attempted. Next check in 5 minutes."
fi
