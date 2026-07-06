#!/usr/bin/env bash
#
# l2-alert-check.sh — scan today's arp.log for L2 anomalies that warrant
# paging. Today: gateway impersonation only (any MAC other than bb0's eth1
# announcing 192.168.50.1).
#
# Lambda-side dedup means re-firing on every cron tick is safe — the alert
# pipeline collapses duplicate (type, device, detail) tuples.
#
# Run via beaconbutty-l2-alert-check.timer (every 5 minutes).

set -euo pipefail

# Site-local overrides (gateway IP/MAC, LAN subnet). See config/local.env.example.
if [[ -f /etc/beaconbutty/local.env ]]; then
    set -a; . /etc/beaconbutty/local.env; set +a
fi
GATEWAY_IP="${BB_LAN_GATEWAY_IP:-192.168.50.1}"
BB0_GW_MAC="${BB_LAN_GATEWAY_MAC:-aa:bb:cc:dd:ee:ff}"

ARP_LOG="/var/log/zeek/current/arp.log"
ALERT_BIN="/usr/local/bin/beaconbutty-alert.sh"

if [[ "$BB0_GW_MAC" == "aa:bb:cc:dd:ee:ff" ]]; then
    echo "l2-alert-check: BB_LAN_GATEWAY_MAC is unset (still the placeholder)." >&2
    echo "Set it in /etc/beaconbutty/local.env or every gateway ARP reply will" >&2
    echo "look like a takeover. Exiting without alerting." >&2
    exit 0
fi

[ -f "$ARP_LOG" ] || exit 0
[ -x "$ALERT_BIN" ] || exit 0

# Each row: ts \t operation \t src_mac \t src_ip \t dst_mac \t dst_ip \t info
# A "rogue" announcement is any row where src_ip is the gateway IP and
# src_mac is not bb0's eth1 MAC. Lowercase-compare to avoid case mismatch.
awk -F'\t' -v gw="$GATEWAY_IP" -v me="${BB0_GW_MAC,,}" '
    /^#/ { next }
    NF >= 4 && $4 == gw {
        m = tolower($3)
        if (m != "" && m != me && m != "-") print m
    }
' "$ARP_LOG" | sort -u | while read -r rogue_mac; do
    # || true: one alert.sh failure (Lambda 5xx, WAN down) must not abort
    # the subshell under set -e — later rogue MACs in the same batch would
    # never be alerted and the 5-min timer unit would flap into failed.
    "$ALERT_BIN" \
        gateway_impersonation \
        high \
        "$GATEWAY_IP" \
        "Rogue MAC ${rogue_mac} announced as gateway ${GATEWAY_IP} — possible router takeover (bb0 MAC is ${BB0_GW_MAC})" \
        || true
done
