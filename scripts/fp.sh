#!/usr/bin/env bash
set -euo pipefail

# fp.sh — BeaconButty false positive registry manager
#
# Deploys to: /usr/local/bin/beaconbutty-fp.sh
#
# Usage:
#   beaconbutty-fp.sh list
#   beaconbutty-fp.sh add <ip> "<reason>"     (reason ≤ 50 chars)
#   beaconbutty-fp.sh remove <ip>
#
# False positives are stored in /var/lib/beaconbutty/false-positives.conf
# as a JSON object: { "ip": "reason", ... }
# The summary script suppresses these IPs from all tables and shows them
# in a dedicated FALSE POSITIVES table at the top of the report.

FP_FILE="/var/lib/beaconbutty/false-positives.conf"

usage() {
    echo "Usage:"
    echo "  beaconbutty-fp.sh list"
    echo "  beaconbutty-fp.sh add <ip> \"<reason>\"   (reason ≤ 50 chars)"
    echo "  beaconbutty-fp.sh remove <ip>"
    exit 1
}

[[ $# -lt 1 ]] && usage

CMD="$1"

case "$CMD" in

    list)
        python3 - "$FP_FILE" <<'PYEOF'
import json, sys

fp_file = sys.argv[1]
try:
    with open(fp_file) as f:
        fps = json.load(f)
except FileNotFoundError:
    fps = {}

if not fps:
    print("No false positives registered.")
    print("Add one with: beaconbutty-fp.sh add <ip> \"<reason>\"")
else:
    print(f"{'IP Address':<18}  Reason")
    print('\u2500' * 72)
    for ip, reason in sorted(fps.items()):
        print(f"{ip:<18}  {reason}")
    print()
    print(f"{len(fps)} registered. Remove with: beaconbutty-fp.sh remove <ip>")
PYEOF
        ;;

    add)
        if [[ $# -lt 3 ]]; then
            echo "Error: 'add' requires <ip> and \"<reason>\""
            usage
        fi
        IP="$2"
        REASON="$3"
        if [[ ${#REASON} -gt 50 ]]; then
            echo "Error: reason must be 50 characters or fewer (got ${#REASON})."
            echo "  \"${REASON}\""
            exit 1
        fi
        python3 - "$FP_FILE" "$IP" "$REASON" <<'PYEOF'
import json, sys, os

fp_file, ip, reason = sys.argv[1], sys.argv[2], sys.argv[3]

try:
    with open(fp_file) as f:
        fps = json.load(f)
except FileNotFoundError:
    fps = {}

already = ip in fps
fps[ip] = reason

os.makedirs(os.path.dirname(fp_file), exist_ok=True)
with open(fp_file, 'w') as f:
    json.dump(fps, f, indent=2, sort_keys=True)

if already:
    print(f"Updated: {ip}  \u2192  {reason}")
else:
    print(f"Added:   {ip}  \u2192  {reason}")
print(f"Run beaconbutty-summary.sh to see the updated report.")
PYEOF
        ;;

    remove)
        if [[ $# -lt 2 ]]; then
            echo "Error: 'remove' requires <ip>"
            usage
        fi
        IP="$2"
        python3 - "$FP_FILE" "$IP" <<'PYEOF'
import json, sys

fp_file, ip = sys.argv[1], sys.argv[2]

try:
    with open(fp_file) as f:
        fps = json.load(f)
except FileNotFoundError:
    fps = {}

if ip not in fps:
    print(f"Not found: {ip}  (not registered as a false positive)")
    sys.exit(1)

reason = fps.pop(ip)
with open(fp_file, 'w') as f:
    json.dump(fps, f, indent=2, sort_keys=True)

print(f"Removed: {ip}  (was: {reason})")
print(f"Run beaconbutty-summary.sh to see the updated report.")
PYEOF
        ;;

    *)
        echo "Unknown command: $CMD"
        usage
        ;;

esac
