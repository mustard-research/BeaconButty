#!/usr/bin/env bash
# alert.sh — send a BeaconButty alert to the AWS Lambda endpoint
#
# Usage:
#   alert.sh <type> <severity> <device> "<detail>"
#
# Types:    high_score_beacon | persistent_beacon | threat_intel_hit |
#           suricata_p1_lan | suricata_p1_repeated | new_device |
#           traffic_anomaly | tor_contact | service_down | disk_critical
#
# Severity: high | medium | low
#
# Examples:
#   alert.sh high_score_beacon high 192.168.50.42 "Score 0.97 → evil.com (first seen today)"
#   alert.sh service_down medium bb0 "Zeek is not running"
#   alert.sh new_device medium 192.168.50.201 "MAC aa:bb:cc:dd:ee:ff (unknown vendor)"

set -euo pipefail

# Site-local overrides — Lambda URL + shared secret live in /etc/beaconbutty/local.env
# (see config/local.env.example for the template).
if [[ -f /etc/beaconbutty/local.env ]]; then
    set -a; . /etc/beaconbutty/local.env; set +a
fi
LAMBDA_URL="${BB_ALERT_URL:-}"
SHARED_SECRET="${BB_ALERT_SECRET:-}"
LOGFILE="/var/log/beaconbutty/alerts.log"

if [[ -z "$LAMBDA_URL" || -z "$SHARED_SECRET" ]]; then
    echo "alert.sh: BB_ALERT_URL and BB_ALERT_SECRET must be set in /etc/beaconbutty/local.env" >&2
    exit 1
fi

if [[ $# -lt 4 ]]; then
    echo "Usage: alert.sh <type> <severity> <device> \"<detail>\""
    exit 1
fi

TYPE="$1"
SEVERITY="$2"
DEVICE="$3"
DETAIL="$4"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# ── Check per-type enable/disable config ──────────────────────────────────────
ALERT_CONFIG="/var/lib/beaconbutty/alert-config.json"
if [[ -f "$ALERT_CONFIG" ]]; then
    ENABLED=$(python3 -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(d.get('enabled', {}).get(sys.argv[2], True))
except Exception:
    print(True)
" "$ALERT_CONFIG" "$TYPE" 2>/dev/null || echo "True")
    if [[ "$ENABLED" == "False" ]]; then
        echo "Alert type '$TYPE' is disabled — skipping."
        exit 0
    fi
fi

PAYLOAD=$(python3 -c "
import json, sys
print(json.dumps({
    'type':      sys.argv[1],
    'severity':  sys.argv[2],
    'device':    sys.argv[3],
    'detail':    sys.argv[4],
    'timestamp': sys.argv[5],
}))
" "$TYPE" "$SEVERITY" "$DEVICE" "$DETAIL" "$TIMESTAMP")

# Per-invocation response file: a fixed /tmp path breaks under concurrent
# callers and is unwritable when a different user created it first.
RESPONSE_FILE=$(mktemp /tmp/alert_response.XXXXXX)
trap 'rm -f "$RESPONSE_FILE"' EXIT

# `|| HTTP_CODE=000` so a transport failure (DNS down, WAN out) still
# reaches the log line below instead of dying silently on set -e.
HTTP_CODE=$(curl -s -o "$RESPONSE_FILE" -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/json" \
    -H "X-BeaconButty-Secret: ${SHARED_SECRET}" \
    --data "$PAYLOAD" \
    --max-time 10 \
    "$LAMBDA_URL") || HTTP_CODE="000"

RESPONSE=$(cat "$RESPONSE_FILE" 2>/dev/null || echo "")

mkdir -p "$(dirname "$LOGFILE")"
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ")  $TYPE  $SEVERITY  $DEVICE  HTTP=$HTTP_CODE  $DETAIL" >> "$LOGFILE"

if [[ "$HTTP_CODE" == "200" ]]; then
    if [[ "$RESPONSE" == "Deduplicated" ]]; then
        echo "Alert suppressed (duplicate): $TYPE / $DEVICE"
    else
        echo "Alert sent: $TYPE / $SEVERITY / $DEVICE"
    fi
else
    echo "Alert failed (HTTP $HTTP_CODE): $RESPONSE" >&2
    exit 1
fi
