#!/usr/bin/env bash
set -euo pipefail

# fp.sh — BeaconButty false positive registry manager
#
# Deploys to: /usr/local/bin/beaconbutty-fp.sh
#
# Usage:
#   beaconbutty-fp.sh list
#   beaconbutty-fp.sh add <ip|mac> "<reason>"          (device FP)
#   beaconbutty-fp.sh remove <ip|mac>
#   beaconbutty-fp.sh add-domain <pattern> "<reason>"  (e.g. "*.apple.com")
#   beaconbutty-fp.sh remove-domain <pattern>
#   beaconbutty-fp.sh add-protocol <svc> "<reason>"    (e.g. "123:udp:ntp")
#   beaconbutty-fp.sh remove-protocol <svc>
#   beaconbutty-fp.sh add-org <pattern> "<reason>" [--device <ip|mac>[,<ip|mac>]]
#   beaconbutty-fp.sh remove-org <pattern>
#   beaconbutty-fp.sh migrate                          (convert old IP-keyed conf to MAC-keyed)
#
# Config is stored in /var/lib/beaconbutty/false-positives.conf as JSON v2:
#   { "version": 2, "devices": {mac: reason}, "domains": {pattern: reason},
#                   "protocols": {svc: reason}, "orgs": {pattern: <org-value>} }
# v1 files (flat MAC dict) are auto-detected and treated as devices-only.
#
# An org value is either a bare reason string (suppressed LAN-wide, the
# original v2 shape) or {"reason": str, "devices": [mac, ...]} to suppress the
# ASN only for those devices. Device scoping is what keeps "Chinese CDN traffic
# from Xin's phone is baseline" from also blinding us to the same ASN reaching
# a server or an IoT device that has no business talking to it.

FP_FILE="/var/lib/beaconbutty/false-positives.conf"
LEASES_FILE="/var/lib/misc/dnsmasq.leases"

usage() {
    echo "Usage:"
    echo "  beaconbutty-fp.sh list"
    echo "  beaconbutty-fp.sh add <ip|mac> \"<reason>\"          (device — survives DHCP)"
    echo "  beaconbutty-fp.sh remove <ip|mac>"
    echo "  beaconbutty-fp.sh add-domain <pattern> \"<reason>\"  (e.g. '*.apple.com')"
    echo "  beaconbutty-fp.sh remove-domain <pattern>"
    echo "  beaconbutty-fp.sh add-protocol <svc> \"<reason>\"    (e.g. '123:udp:ntp')"
    echo "  beaconbutty-fp.sh remove-protocol <svc>"
    echo "  beaconbutty-fp.sh add-org <pattern> \"<reason>\"     (e.g. '*Tencent*' — GeoIP ASN owner)"
    echo "      [--device <ip|mac>[,<ip|mac>]]                 (scope to devices; omit for LAN-wide)"
    echo "  beaconbutty-fp.sh remove-org <pattern>"
    echo "  beaconbutty-fp.sh migrate                          (convert old IP-keyed conf)"
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

def load_conf(fp_file):
    try:
        with open(fp_file) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"version": 2, "devices": {}, "domains": {}, "protocols": {}, "orgs": {}}
    if "version" not in data:
        return {"version": 2, "devices": data, "domains": {}, "protocols": {}, "orgs": {}}
    data.setdefault("orgs", {})
    return data

conf = load_conf(fp_file)
devices   = conf.get("devices", {})
domains   = conf.get("domains", {})
protocols = conf.get("protocols", {})
orgs      = conf.get("orgs", {})

mac_to_ip = {}
try:
    with open(leases_file) as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3:
                mac_to_ip[parts[1].lower()] = parts[2]
except FileNotFoundError:
    pass

total = len(devices) + len(domains) + len(protocols) + len(orgs)
if total == 0:
    print("No false positives registered.")
    print("Add one with: beaconbutty-fp.sh add <ip|mac> \"<reason>\"")
else:
    if devices:
        print(f"DEVICES  ({len(devices)} registered — suppresses all beacon traffic from device)")
        print(f"  {'MAC Address':<20}  {'Current IP':<16}  Reason")
        print('  ' + '\u2500' * 68)
        for mac, reason in sorted(devices.items()):
            ip = mac_to_ip.get(mac.lower(), '\u2014')
            print(f"  {mac:<20}  {ip:<16}  {reason}")
        print()

    if domains:
        print(f"DOMAINS  ({len(domains)} registered — suppresses beacons to matching destinations)")
        print(f"  {'Pattern':<40}  Reason")
        print('  ' + '\u2500' * 68)
        for pat, reason in sorted(domains.items()):
            print(f"  {pat:<40}  {reason}")
        print()

    if protocols:
        print(f"PROTOCOLS  ({len(protocols)} registered — suppresses beacons on matching service)")
        print(f"  {'Service':<30}  Reason")
        print('  ' + '\u2500' * 68)
        for svc, reason in sorted(protocols.items()):
            print(f"  {svc:<30}  {reason}")
        print()

    if orgs:
        print(f"ORGANISATIONS  ({len(orgs)} registered — suppresses beacons whose GeoIP ASN owner matches)")
        print(f"  {'Pattern':<30}  Reason")
        print('  ' + '─' * 68)
        for pat, val in sorted(orgs.items()):
            # v2 org values are either a bare reason (LAN-wide) or
            # {"reason", "devices"} scoped to specific MACs. Scope goes on its
            # own indented line — a device list does not fit in a column.
            if isinstance(val, dict):
                reason = val.get("reason", "")
                macs   = sorted(m.lower() for m in (val.get("devices") or []))
            else:
                reason, macs = val, []
            print(f"  {pat:<30}  {reason}")
            if macs:
                for m in macs:
                    ip = mac_to_ip.get(m)
                    print(f"  {'':<30}    ↳ {m}{'  ' + ip if ip else ''}")
            else:
                print(f"  {'':<30}    ↳ LAN-wide")
        print()

    print(f"{total} total. Remove with: beaconbutty-fp.sh remove / remove-domain / remove-protocol / remove-org")
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

def load_conf(fp_file):
    try:
        with open(fp_file) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"version": 2, "devices": {}, "domains": {}, "protocols": {}, "orgs": {}}
    if "version" not in data:
        return {"version": 2, "devices": data, "domains": {}, "protocols": {}, "orgs": {}}
    data.setdefault("orgs", {})
    return data

def save_conf(fp_file, conf):
    # Atomic: a reader catching a truncated registry mid-write falls back to
    # "no FPs" and resurfaces every suppressed finding for that render.
    os.makedirs(os.path.dirname(fp_file), exist_ok=True)
    tmp = fp_file + ".tmp"
    with open(tmp, 'w') as f:
        json.dump(conf, f, indent=2, sort_keys=True)
    os.replace(tmp, fp_file)

def leases_lookup(key, field_ip=True):
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

conf = load_conf(fp_file)
already = mac in conf["devices"]
conf["devices"][mac] = reason
save_conf(fp_file, conf)

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
import json, sys, os, re

fp_file     = sys.argv[1]
leases_file = sys.argv[2]
addr        = sys.argv[3].lower()

MAC_RE = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')

def load_conf(fp_file):
    try:
        with open(fp_file) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"version": 2, "devices": {}, "domains": {}, "protocols": {}, "orgs": {}}
    if "version" not in data:
        return {"version": 2, "devices": data, "domains": {}, "protocols": {}, "orgs": {}}
    data.setdefault("orgs", {})
    return data

def save_conf(fp_file, conf):
    # Atomic: a reader catching a truncated registry mid-write falls back to
    # "no FPs" and resurfaces every suppressed finding for that render.
    os.makedirs(os.path.dirname(fp_file), exist_ok=True)
    tmp = fp_file + ".tmp"
    with open(tmp, 'w') as f:
        json.dump(conf, f, indent=2, sort_keys=True)
    os.replace(tmp, fp_file)

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

conf = load_conf(fp_file)
if mac not in conf["devices"]:
    print(f"Not found: {mac}  (not registered as a device false positive)")
    sys.exit(1)

reason = conf["devices"].pop(mac)
save_conf(fp_file, conf)
print(f"Removed: {mac}  (was: {reason})")
print(f"Run beaconbutty-summary.sh to see the updated report.")
PYEOF
        ;;

    add-domain)
        if [[ $# -lt 3 ]]; then
            echo "Error: 'add-domain' requires <pattern> and \"<reason>\""
            echo "  Example: beaconbutty-fp.sh add-domain '*.apple.com' 'Apple CDN'"
            exit 1
        fi
        PATTERN="$2"
        REASON="$3"
        if [[ ${#REASON} -gt 50 ]]; then
            echo "Error: reason must be 50 characters or fewer (got ${#REASON})."
            exit 1
        fi
        python3 - "$FP_FILE" "$PATTERN" "$REASON" <<'PYEOF'
import json, sys, os

fp_file = sys.argv[1]
pattern = sys.argv[2]
reason  = sys.argv[3]

def load_conf(fp_file):
    try:
        with open(fp_file) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"version": 2, "devices": {}, "domains": {}, "protocols": {}, "orgs": {}}
    if "version" not in data:
        return {"version": 2, "devices": data, "domains": {}, "protocols": {}, "orgs": {}}
    data.setdefault("orgs", {})
    return data

def save_conf(fp_file, conf):
    # Atomic: a reader catching a truncated registry mid-write falls back to
    # "no FPs" and resurfaces every suppressed finding for that render.
    os.makedirs(os.path.dirname(fp_file), exist_ok=True)
    tmp = fp_file + ".tmp"
    with open(tmp, 'w') as f:
        json.dump(conf, f, indent=2, sort_keys=True)
    os.replace(tmp, fp_file)

conf = load_conf(fp_file)
already = pattern in conf["domains"]
conf["domains"][pattern] = reason
save_conf(fp_file, conf)

verb = "Updated" if already else "Added  "
print(f"{verb}: {pattern}  \u2192  {reason}")
print(f"Run beaconbutty-summary.sh to see the updated report.")
PYEOF
        ;;

    remove-domain)
        if [[ $# -lt 2 ]]; then
            echo "Error: 'remove-domain' requires <pattern>"
            exit 1
        fi
        PATTERN="$2"
        python3 - "$FP_FILE" "$PATTERN" <<'PYEOF'
import json, sys, os

fp_file = sys.argv[1]
pattern = sys.argv[2]

def load_conf(fp_file):
    try:
        with open(fp_file) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"version": 2, "devices": {}, "domains": {}, "protocols": {}, "orgs": {}}
    if "version" not in data:
        return {"version": 2, "devices": data, "domains": {}, "protocols": {}, "orgs": {}}
    data.setdefault("orgs", {})
    return data

def save_conf(fp_file, conf):
    # Atomic: a reader catching a truncated registry mid-write falls back to
    # "no FPs" and resurfaces every suppressed finding for that render.
    os.makedirs(os.path.dirname(fp_file), exist_ok=True)
    tmp = fp_file + ".tmp"
    with open(tmp, 'w') as f:
        json.dump(conf, f, indent=2, sort_keys=True)
    os.replace(tmp, fp_file)

conf = load_conf(fp_file)
if pattern not in conf["domains"]:
    print(f"Not found: {pattern}  (not registered as a domain false positive)")
    sys.exit(1)

reason = conf["domains"].pop(pattern)
save_conf(fp_file, conf)
print(f"Removed: {pattern}  (was: {reason})")
print(f"Run beaconbutty-summary.sh to see the updated report.")
PYEOF
        ;;

    add-protocol)
        if [[ $# -lt 3 ]]; then
            echo "Error: 'add-protocol' requires <service> and \"<reason>\""
            echo "  Example: beaconbutty-fp.sh add-protocol '123:udp:ntp' 'NTP time sync'"
            exit 1
        fi
        SVC="$2"
        REASON="$3"
        if [[ ${#REASON} -gt 50 ]]; then
            echo "Error: reason must be 50 characters or fewer (got ${#REASON})."
            exit 1
        fi
        python3 - "$FP_FILE" "$SVC" "$REASON" <<'PYEOF'
import json, sys, os

fp_file = sys.argv[1]
svc     = sys.argv[2]
reason  = sys.argv[3]

def load_conf(fp_file):
    try:
        with open(fp_file) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"version": 2, "devices": {}, "domains": {}, "protocols": {}, "orgs": {}}
    if "version" not in data:
        return {"version": 2, "devices": data, "domains": {}, "protocols": {}, "orgs": {}}
    data.setdefault("orgs", {})
    return data

def save_conf(fp_file, conf):
    # Atomic: a reader catching a truncated registry mid-write falls back to
    # "no FPs" and resurfaces every suppressed finding for that render.
    os.makedirs(os.path.dirname(fp_file), exist_ok=True)
    tmp = fp_file + ".tmp"
    with open(tmp, 'w') as f:
        json.dump(conf, f, indent=2, sort_keys=True)
    os.replace(tmp, fp_file)

conf = load_conf(fp_file)
already = svc in conf["protocols"]
conf["protocols"][svc] = reason
save_conf(fp_file, conf)

verb = "Updated" if already else "Added  "
print(f"{verb}: {svc}  \u2192  {reason}")
print(f"Run beaconbutty-summary.sh to see the updated report.")
PYEOF
        ;;

    remove-protocol)
        if [[ $# -lt 2 ]]; then
            echo "Error: 'remove-protocol' requires <service>"
            exit 1
        fi
        SVC="$2"
        python3 - "$FP_FILE" "$SVC" <<'PYEOF'
import json, sys, os

fp_file = sys.argv[1]
svc     = sys.argv[2]

def load_conf(fp_file):
    try:
        with open(fp_file) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"version": 2, "devices": {}, "domains": {}, "protocols": {}, "orgs": {}}
    if "version" not in data:
        return {"version": 2, "devices": data, "domains": {}, "protocols": {}, "orgs": {}}
    data.setdefault("orgs", {})
    return data

def save_conf(fp_file, conf):
    # Atomic: a reader catching a truncated registry mid-write falls back to
    # "no FPs" and resurfaces every suppressed finding for that render.
    os.makedirs(os.path.dirname(fp_file), exist_ok=True)
    tmp = fp_file + ".tmp"
    with open(tmp, 'w') as f:
        json.dump(conf, f, indent=2, sort_keys=True)
    os.replace(tmp, fp_file)

conf = load_conf(fp_file)
if svc not in conf["protocols"]:
    print(f"Not found: {svc}  (not registered as a protocol false positive)")
    sys.exit(1)

reason = conf["protocols"].pop(svc)
save_conf(fp_file, conf)
print(f"Removed: {svc}  (was: {reason})")
print(f"Run beaconbutty-summary.sh to see the updated report.")
PYEOF
        ;;

    add-org)
        if [[ $# -lt 3 ]]; then
            echo "Error: 'add-org' requires <pattern> and \"<reason>\""
            echo "  Example: beaconbutty-fp.sh add-org '*Tencent*' 'Tencent Cloud'"
            exit 1
        fi
        PATTERN="$2"
        REASON="$3"
        DEVICES=""
        shift 3
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --device)
                    if [[ $# -lt 2 ]]; then
                        echo "Error: '--device' requires <ip|mac>[,<ip|mac>]"
                        exit 1
                    fi
                    DEVICES="$2"
                    shift 2
                    ;;
                --global)
                    DEVICES=""
                    shift
                    ;;
                *)
                    echo "Error: unknown option '$1' for add-org"
                    exit 1
                    ;;
            esac
        done
        if [[ ${#REASON} -gt 50 ]]; then
            echo "Error: reason must be 50 characters or fewer (got ${#REASON})."
            exit 1
        fi
        python3 - "$FP_FILE" "$LEASES_FILE" "$PATTERN" "$REASON" "$DEVICES" <<'PYEOF'
import json, sys, os, re

fp_file     = sys.argv[1]
leases_file = sys.argv[2]
pattern     = sys.argv[3]
reason      = sys.argv[4]
device_arg  = sys.argv[5]

MAC_RE = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')

def load_conf(fp_file):
    try:
        with open(fp_file) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"version": 2, "devices": {}, "domains": {}, "protocols": {}, "orgs": {}}
    if "version" not in data:
        return {"version": 2, "devices": data, "domains": {}, "protocols": {}, "orgs": {}}
    data.setdefault("orgs", {})
    return data

def save_conf(fp_file, conf):
    # Atomic: a reader catching a truncated registry mid-write falls back to
    # "no FPs" and resurfaces every suppressed finding for that render.
    os.makedirs(os.path.dirname(fp_file), exist_ok=True)
    tmp = fp_file + ".tmp"
    with open(tmp, 'w') as f:
        json.dump(conf, f, indent=2, sort_keys=True)
    os.replace(tmp, fp_file)

def leases_lookup_mac(ip):
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

new_macs = []
for token in (t.strip().lower() for t in device_arg.split(',') if t.strip()):
    if MAC_RE.match(token):
        new_macs.append(token)
        continue
    mac = leases_lookup_mac(token) or arp_mac_for_ip(token)
    if not mac:
        print(f"Error: could not resolve {token} to a MAC address.")
        print("  Check dnsmasq leases or ARP table, or specify the MAC directly.")
        sys.exit(1)
    print(f"Resolved {token} → {mac}")
    new_macs.append(mac)

conf = load_conf(fp_file)
prev = conf["orgs"].get(pattern)
already = pattern in conf["orgs"]

# Union with any existing scope so repeat adds accumulate devices rather than
# silently narrowing the entry to whichever device was named last.
prev_macs = []
if isinstance(prev, dict):
    prev_macs = [m.lower() for m in (prev.get("devices") or [])]

if new_macs:
    if already and not prev_macs:
        print(f"Note: {pattern} was LAN-wide; narrowing it to the named device(s).")
    macs = sorted(set(prev_macs) | set(new_macs))
    conf["orgs"][pattern] = {"reason": reason, "devices": macs}
    scope = ", ".join(macs)
else:
    if prev_macs:
        print(f"Note: {pattern} was scoped to {len(prev_macs)} device(s); "
              f"widening it to the whole LAN.")
    conf["orgs"][pattern] = reason
    scope = "LAN-wide"

save_conf(fp_file, conf)

verb = "Updated" if already else "Added  "
print(f"{verb}: {pattern}  [{scope}]  →  {reason}")
print(f"Refresh /beacons/slow to see the updated hunting surface.")
PYEOF
        ;;

    remove-org)
        if [[ $# -lt 2 ]]; then
            echo "Error: 'remove-org' requires <pattern>"
            exit 1
        fi
        PATTERN="$2"
        python3 - "$FP_FILE" "$PATTERN" <<'PYEOF'
import json, sys, os

fp_file = sys.argv[1]
pattern = sys.argv[2]

def load_conf(fp_file):
    try:
        with open(fp_file) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"version": 2, "devices": {}, "domains": {}, "protocols": {}, "orgs": {}}
    if "version" not in data:
        return {"version": 2, "devices": data, "domains": {}, "protocols": {}, "orgs": {}}
    data.setdefault("orgs", {})
    return data

def save_conf(fp_file, conf):
    # Atomic: a reader catching a truncated registry mid-write falls back to
    # "no FPs" and resurfaces every suppressed finding for that render.
    os.makedirs(os.path.dirname(fp_file), exist_ok=True)
    tmp = fp_file + ".tmp"
    with open(tmp, 'w') as f:
        json.dump(conf, f, indent=2, sort_keys=True)
    os.replace(tmp, fp_file)

conf = load_conf(fp_file)
if pattern not in conf["orgs"]:
    print(f"Not found: {pattern}  (not registered as an organisation false positive)")
    sys.exit(1)

val = conf["orgs"].pop(pattern)
save_conf(fp_file, conf)
if isinstance(val, dict):
    macs = ", ".join(sorted(m.lower() for m in (val.get("devices") or []))) or "LAN-wide"
    was  = f"{val.get('reason', '')}  [{macs}]"
else:
    was  = f"{val}  [LAN-wide]"
print(f"Removed: {pattern}  (was: {was})")
print(f"Refresh /beacons/slow to see the updated hunting surface.")
PYEOF
        ;;

    migrate)
        python3 - "$FP_FILE" "$LEASES_FILE" <<'PYEOF'
import json, sys, os, re

fp_file     = sys.argv[1]
leases_file = sys.argv[2]

MAC_RE = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')

def load_conf(fp_file):
    try:
        with open(fp_file) as f:
            data = json.load(f)
    except FileNotFoundError:
        return None
    if "version" not in data:
        return {"version": 2, "devices": data, "domains": {}, "protocols": {}, "orgs": {}}
    data.setdefault("orgs", {})
    return data

def save_conf(fp_file, conf):
    # Atomic: a reader catching a truncated registry mid-write falls back to
    # "no FPs" and resurfaces every suppressed finding for that render.
    os.makedirs(os.path.dirname(fp_file), exist_ok=True)
    tmp = fp_file + ".tmp"
    with open(tmp, 'w') as f:
        json.dump(conf, f, indent=2, sort_keys=True)
    os.replace(tmp, fp_file)

# Read raw to detect format before normalising
try:
    with open(fp_file) as f:
        raw = json.load(f)
except FileNotFoundError:
    print("No false-positives.conf found.")
    sys.exit(0)

if raw.get("version") == 2:
    print("Already v2 format — nothing to migrate.")
    sys.exit(0)

# v1: flat MAC dict
conf = {"version": 2, "devices": raw, "domains": {}, "protocols": {}, "orgs": {}}
fps  = conf["devices"]

if all(MAC_RE.match(k) for k in fps):
    conf["version"] = 2
    save_conf(fp_file, conf)
    print("Upgraded to v2 format (devices were already MAC-keyed).")
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

new_devices = {}
skipped = []
for key, reason in fps.items():
    if MAC_RE.match(key):
        new_devices[key] = reason
        print(f"  {key}  (already MAC)")
    elif key in ip_to_mac:
        mac = ip_to_mac[key]
        print(f"  {key:<16}  \u2192  {mac}  ({reason})")
        new_devices[mac] = reason
    else:
        print(f"  {key:<16}  \u2192  SKIPPED (no MAC found)  ({reason})")
        skipped.append((key, reason))

conf["devices"] = new_devices
save_conf(fp_file, conf)

print(f"\nMigrated {len(new_devices)} entr{'y' if len(new_devices) == 1 else 'ies'}.")
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
