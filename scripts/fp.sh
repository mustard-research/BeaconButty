#!/usr/bin/env bash
set -euo pipefail

# fp.sh — BeaconButty false positive registry manager
#
# Deploys to: /usr/local/bin/beaconbutty-fp.sh
#
# Usage:
#   beaconbutty-fp.sh list
#   beaconbutty-fp.sh add <ip|mac> "<reason>"     (reason ≤ 50 chars)
#   beaconbutty-fp.sh remove <ip|mac>
#   beaconbutty-fp.sh migrate                     (convert old IP-keyed conf to MAC-keyed)
#
# False positives are stored in /var/lib/beaconbutty/false-positives.conf
# as a JSON object: { "mac": "reason", ... } keyed by MAC address.
# This survives DHCP reassignment — the summary script resolves MACs to
# current IPs at runtime via dnsmasq leases.

FP_FILE="/var/lib/beaconbutty/false-positives.conf"
LEASES_FILE="/var/lib/misc/dnsmasq.leases"

usage() {
    echo "Usage:"
    echo "  beaconbutty-fp.sh list"
    echo "  beaconbutty-fp.sh add <ip|mac> \"<reason>\"   (reason ≤ 50 chars)"
    echo "  beaconbutty-fp.sh remove <ip|mac>"
    echo "  beaconbutty-fp.sh migrate                   (convert old IP-keyed conf)"
    exit 1
}

[[ $# -lt 1 ]] && usage

CMD="$1"

case "$CMD" in

    list)
        python3 - "$FP_FILE" "$LEASES_FILE" <<'PYEOF'
import json, sys

fp_file     = sys.argv[1]
leases_file = sys.argv[2]

try:
    with open(fp_file) as f:
        fps = json.load(f)
except FileNotFoundError:
    fps = {}

mac_to_ip = {}
try:
    with open(leases_file) as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3:
                mac_to_ip[parts[1].lower()] = parts[2]
except FileNotFoundError:
    pass

if not fps:
    print("No false positives registered.")
    print("Add one with: beaconbutty-fp.sh add <ip|mac> \"<reason>\"")
else:
    print(f"{'MAC Address':<20}  {'Current IP':<16}  Reason")
    print('\u2500' * 72)
    for mac, reason in sorted(fps.items()):
        ip = mac_to_ip.get(mac.lower(), '\u2014')
        print(f"{mac:<20}  {ip:<16}  {reason}")
    print()
    print(f"{len(fps)} registered. Remove with: beaconbutty-fp.sh remove <ip|mac>")
PYEOF
        ;;

    add)
        if [[ $# -lt 3 ]]; then
            echo "Error: 'add' requires <ip|mac> and \"<reason>\""
            usage
        fi
        ADDR="$2"
        REASON="$3"
        if [[ ${#REASON} -gt 50 ]]; then
            echo "Error: reason must be 50 characters or fewer (got ${#REASON})."
            echo "  \"${REASON}\""
            exit 1
        fi
        python3 - "$FP_FILE" "$LEASES_FILE" "$ADDR" "$REASON" <<'PYEOF'
import json, sys, os, re

fp_file     = sys.argv[1]
leases_file = sys.argv[2]
addr        = sys.argv[3].lower()
reason      = sys.argv[4]

MAC_RE = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')

def leases_lookup(key, field_ip=True):
    """Look up MAC for an IP (field_ip=True) or IP for a MAC (field_ip=False)."""
    src_idx, dst_idx = (2, 1) if field_ip else (1, 2)
    try:
        with open(leases_file) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[src_idx].lower() == key:
                    return parts[dst_idx].lower()
    except FileNotFoundError:
        pass
    return None

def arp_mac_for_ip(ip):
    try:
        with open('/proc/net/arp') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3].lower()
                    if MAC_RE.match(mac) and mac != '00:00:00:00:00:00':
                        return mac
    except Exception:
        pass
    return None

if MAC_RE.match(addr):
    mac = addr
    resolved_ip = leases_lookup(mac, field_ip=False)
else:
    mac = leases_lookup(addr) or arp_mac_for_ip(addr)
    if not mac:
        print(f"Error: could not resolve {addr} to a MAC address.")
        print("  Check dnsmasq leases or ARP table, or specify the MAC directly.")
        sys.exit(1)
    print(f"Resolved {addr} \u2192 {mac}")
    resolved_ip = addr

try:
    with open(fp_file) as f:
        fps = json.load(f)
except FileNotFoundError:
    fps = {}

already = mac in fps
fps[mac] = reason

os.makedirs(os.path.dirname(fp_file), exist_ok=True)
with open(fp_file, 'w') as f:
    json.dump(fps, f, indent=2, sort_keys=True)

label = mac + (f"  (current IP: {resolved_ip})" if resolved_ip else "")
verb  = "Updated" if already else "Added  "
print(f"{verb}: {label}  \u2192  {reason}")
print(f"Run beaconbutty-summary.sh to see the updated report.")
PYEOF
        ;;

    remove)
        if [[ $# -lt 2 ]]; then
            echo "Error: 'remove' requires <ip|mac>"
            usage
        fi
        ADDR="$2"
        python3 - "$FP_FILE" "$LEASES_FILE" "$ADDR" <<'PYEOF'
import json, sys, re

fp_file     = sys.argv[1]
leases_file = sys.argv[2]
addr        = sys.argv[3].lower()

MAC_RE = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')

def leases_mac_for_ip(ip):
    try:
        with open(leases_file) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[2] == ip:
                    return parts[1].lower()
    except FileNotFoundError:
        pass
    return None

def arp_mac_for_ip(ip):
    try:
        with open('/proc/net/arp') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3].lower()
                    if MAC_RE.match(mac) and mac != '00:00:00:00:00:00':
                        return mac
    except Exception:
        pass
    return None

if MAC_RE.match(addr):
    mac = addr
else:
    mac = leases_mac_for_ip(addr) or arp_mac_for_ip(addr)
    if not mac:
        print(f"Error: could not resolve {addr} to a MAC address.")
        print("  Specify the MAC directly: beaconbutty-fp.sh remove <mac>")
        sys.exit(1)
    print(f"Resolved {addr} \u2192 {mac}")

try:
    with open(fp_file) as f:
        fps = json.load(f)
except FileNotFoundError:
    fps = {}

if mac not in fps:
    print(f"Not found: {mac}  (not registered as a false positive)")
    sys.exit(1)

reason = fps.pop(mac)
with open(fp_file, 'w') as f:
    json.dump(fps, f, indent=2, sort_keys=True)

print(f"Removed: {mac}  (was: {reason})")
print(f"Run beaconbutty-summary.sh to see the updated report.")
PYEOF
        ;;

    migrate)
        python3 - "$FP_FILE" "$LEASES_FILE" <<'PYEOF'
import json, sys, os, re

fp_file     = sys.argv[1]
leases_file = sys.argv[2]

MAC_RE = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')

try:
    with open(fp_file) as f:
        fps = json.load(f)
except FileNotFoundError:
    print("No false-positives.conf found.")
    sys.exit(0)

if all(MAC_RE.match(k) for k in fps):
    print("Already MAC-keyed — nothing to migrate.")
    sys.exit(0)

# Build IP → MAC from leases and ARP table
ip_to_mac = {}
try:
    with open(leases_file) as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3:
                ip_to_mac[parts[2]] = parts[1].lower()
except FileNotFoundError:
    pass

try:
    with open('/proc/net/arp') as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 4:
                ip, mac = parts[0], parts[3].lower()
                if MAC_RE.match(mac) and mac != '00:00:00:00:00:00':
                    ip_to_mac.setdefault(ip, mac)
except Exception:
    pass

new_fps = {}
skipped = []
for key, reason in fps.items():
    if MAC_RE.match(key):
        new_fps[key] = reason
        print(f"  {key}  (already MAC)")
    elif key in ip_to_mac:
        mac = ip_to_mac[key]
        print(f"  {key:<16}  \u2192  {mac}  ({reason})")
        new_fps[mac] = reason
    else:
        print(f"  {key:<16}  \u2192  SKIPPED (no MAC found)  ({reason})")
        skipped.append((key, reason))

with open(fp_file, 'w') as f:
    json.dump(new_fps, f, indent=2, sort_keys=True)

print(f"\nMigrated {len(new_fps)} entr{'y' if len(new_fps) == 1 else 'ies'}.")
if skipped:
    print(f"Could not resolve {len(skipped)} IP(s) — add them manually:")
    for ip, reason in skipped:
        print(f"  beaconbutty-fp.sh add <mac-for-{ip}> \"{reason}\"")
PYEOF
        ;;

    *)
        echo "Unknown command: $CMD"
        usage
        ;;

esac
