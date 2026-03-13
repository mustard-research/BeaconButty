#!/usr/bin/env bash
set -euo pipefail

# assets.sh — build a LAN asset inventory for beaconbutty-summary.sh.
#
# Data sources (applied in order, each enriches rather than replaces):
#
#   1. Kernel ARP table (/proc/net/arp)
#        Every device the Pi has forwarded packets for appears here,
#        regardless of whether it responds to nmap probes.
#        Gives: IP → MAC
#
#   2. nmap MAC prefix database (/usr/share/nmap/nmap-mac-prefixes)
#        Offline OUI lookup — no network round-trip needed.
#        Gives: MAC prefix → vendor name
#
#   3. Zeek DHCP logs
#        Self-reported hostnames and vendor class IDs.
#        Gives: IP → hostname
#
#   4. nmap (active scan, -Pn skips host-discovery so sleeping devices
#        are still scanned if they're in the ARP table)
#        Gives: open ports, OS fingerprint, and confirms MAC for
#        devices that are awake.
#
# Requires: nmap (apt install nmap), run as root.
#
# Environment:
#   CAPTURE_IFACE   LAN interface (default: eth1)
#   LAN_SUBNET      Override scan subnet, e.g. 192.168.1.0/24
#   ZEEK_LOG_DIR    Zeek log root (default: /opt/zeek/logs)

CACHE_DIR="/var/lib/beaconbutty"
SCAN_GREP="${CACHE_DIR}/scan.gnmap"
HOSTS_FILE="${CACHE_DIR}/hosts.txt"
ASSETS_JSON="${CACHE_DIR}/assets.json"
LOGFILE="/var/log/beaconbutty/assets.log"
ZEEK_LOG_DIR="${ZEEK_LOG_DIR:-/opt/zeek/logs}"

mkdir -p "$CACHE_DIR" /var/log/beaconbutty
exec >> "$LOGFILE" 2>&1

echo ""
echo "=== beaconbutty-assets started: $(date --iso-8601=seconds) ==="

LAN_IFACE="${CAPTURE_IFACE:-eth1}"
if [[ -z "${LAN_SUBNET:-}" ]]; then
    LAN_SUBNET=$(ip -4 addr show "$LAN_IFACE" 2>/dev/null \
        | awk '/inet / {
            split($2, a, "/");
            split(a[1], o, ".");
            printf "%s.%s.%s.0/%s\n", o[1], o[2], o[3], a[2];
            exit
          }')
fi
LAN_SUBNET="${LAN_SUBNET:-192.168.50.0/24}"

# ── Step 1: seed from ARP table + OUI database + Zeek DHCP ───────────────────
echo "Reading ARP table, OUI database, and Zeek logs..."
python3 - "$LAN_IFACE" "$ZEEK_LOG_DIR" "$ASSETS_JSON" <<'PYEOF'
import json, os, re, sys, glob
from datetime import datetime

iface     = sys.argv[1]
zeek_dir  = sys.argv[2]
out_file  = sys.argv[3]
now_str   = datetime.now().isoformat(timespec='seconds')

try:
    with open(out_file) as f:
        cache = json.load(f)
except Exception:
    cache = {}

def blank():
    return {'hostname': '', 'os': '', 'mac': '', 'mac_vendor': '',
            'open_ports': [], 'last_seen': now_str, 'source': ''}

def get(ip):
    if ip not in cache:
        cache[ip] = blank()
    return cache[ip]

# ── Load nmap OUI vendor database ─────────────────────────────────────────────
oui = {}
for oui_path in ['/usr/share/nmap/nmap-mac-prefixes',
                 '/usr/share/ieee-data/oui.txt']:
    if not os.path.exists(oui_path):
        continue
    with open(oui_path, errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                oui[parts[0].upper().replace('-', '').replace(':', '')] = parts[1]
    break
print(f"  OUI entries loaded: {len(oui)}")

def vendor(mac):
    if not mac:
        return ''
    prefix = mac.upper().replace(':', '').replace('-', '')[:6]
    return oui.get(prefix, '')

# ── Read dnsmasq DHCP lease file ─────────────────────────────────────────────
# Format: expiry  mac  ip  hostname  client-id
# This covers sleeping devices that aren't in the ARP cache right now.
LEASE_PATHS = [
    '/var/lib/misc/dnsmasq.leases',
    '/var/lib/dnsmasq/dnsmasq.leases',
    '/tmp/dnsmasq.leases',
    '/var/run/dnsmasq/dnsmasq.leases',
]
lease_count = 0
for lpath in LEASE_PATHS:
    if not os.path.exists(lpath):
        continue
    print(f"  Reading {lpath}...")
    with open(lpath) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 4:
                continue
            mac      = parts[1]
            ip       = parts[2]
            hostname = parts[3] if parts[3] != '*' else ''
            if not re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                continue
            h = get(ip)
            if not h['mac']:
                h['mac'] = mac
                h['source'] = 'dnsmasq'
            if not h['mac_vendor']:
                h['mac_vendor'] = vendor(mac)
            if hostname and not h['hostname']:
                h['hostname'] = hostname
            lease_count += 1
    break
if lease_count == 0:
    print("  No dnsmasq lease file found — will rely on ARP table.")
else:
    print(f"  dnsmasq leases: {lease_count}  →  {len(cache)} IPs")

# ── Read kernel ARP table ─────────────────────────────────────────────────────
arp_count = 0
try:
    with open('/proc/net/arp') as f:
        next(f)   # skip header
        for line in f:
            parts = line.split()
            if len(parts) < 6:
                continue
            ip, hw_type, flags, mac, mask, dev = parts[:6]
            # flags 0x0 = incomplete, skip
            if flags == '0x0' or mac == '00:00:00:00:00:00':
                continue
            # Only keep entries for our LAN interface
            if dev != iface:
                continue
            if not re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                continue
            h = get(ip)
            if not h['mac']:
                h['mac'] = mac
                h['source'] = 'arp'
            if not h['mac_vendor']:
                h['mac_vendor'] = vendor(mac)
            arp_count += 1
except Exception as e:
    print(f"  ARP table read failed: {e}")

print(f"  ARP entries: {arp_count}  →  {len(cache)} IPs seeded")

# ── Read Zeek DHCP logs for hostnames ─────────────────────────────────────────
def zeek_rows(pattern):
    for path in sorted(glob.glob(pattern)):
        fields = []
        try:
            with open(path, errors='replace') as f:
                for line in f:
                    line = line.rstrip('\n')
                    if line.startswith('#fields'):
                        fields = line.split('\t')[1:]
                    elif line.startswith('#'):
                        continue
                    elif fields:
                        yield dict(zip(fields, line.split('\t')))
        except Exception:
            continue

dhcp_count = 0
for pattern in [f'{zeek_dir}/current/dhcp*.log',
                f'{zeek_dir}/*/dhcp*.log']:
    for row in zeek_rows(pattern):
        ip       = row.get('assigned_ip', '-')
        mac      = row.get('mac', '-')
        hostname = row.get('host_name', '-')
        if not re.match(r'\d+\.\d+\.\d+\.\d+', ip):
            continue
        h = get(ip)
        if mac and mac not in ('-', '') and not h['mac']:
            h['mac'] = mac
            if not h['mac_vendor']:
                h['mac_vendor'] = vendor(mac)
            h['source'] = 'zeek/dhcp'
        if hostname and hostname not in ('-', '') and not h['hostname']:
            h['hostname'] = hostname
        dhcp_count += 1

print(f"  DHCP rows processed: {dhcp_count}  →  {len(cache)} IPs total")

with open(out_file, 'w') as f:
    json.dump(cache, f, indent=2)
PYEOF

# ── Step 2: write host list for nmap ─────────────────────────────────────────
# Use IPs already known from ARP/DHCP plus a full subnet sweep.
# -Pn skips host-discovery ping so sleeping devices aren't skipped.
python3 -c "
import json
d = json.load(open('$ASSETS_JSON'))
ips = sorted(d.keys(), key=lambda x: tuple(int(p) for p in x.split('.')))
open('$HOSTS_FILE', 'w').write('\n'.join(ips) + '\n')
print(f'  {len(ips)} IPs queued for nmap scan.')
"

# Append the full subnet so nmap can discover anything ARP missed
echo "$LAN_SUBNET" >> "$HOSTS_FILE"

# ── Step 3: nmap scan ─────────────────────────────────────────────────────────
echo "Running nmap on known hosts + $LAN_SUBNET..."
nmap -O --osscan-guess \
     -sV --version-light \
     -p 22,80,443,445,3389,5900,8080,8443 \
     -T4 --host-timeout 20s \
     -Pn \
     -iL "$HOSTS_FILE" \
     -oG "$SCAN_GREP" 2>/dev/null

echo "nmap scan complete."

# ── Step 4: merge nmap results into cache ─────────────────────────────────────
python3 - "$SCAN_GREP" "$ASSETS_JSON" <<'PYEOF'
import json, re, sys
from datetime import datetime

scan_file = sys.argv[1]
out_file  = sys.argv[2]
now_str   = datetime.now().isoformat(timespec='seconds')

with open(out_file) as f:
    cache = json.load(f)

nmap_count = 0
with open(scan_file) as f:
    for line in f:
        line = line.strip()
        if not line.startswith('Host:'):
            continue
        ip_m = re.match(r'Host:\s+(\S+)\s+\(([^)]*)\)', line)
        if not ip_m:
            continue
        ip       = ip_m.group(1)
        hostname = ip_m.group(2)

        if ip not in cache:
            cache[ip] = {'hostname': '', 'os': '', 'mac': '', 'mac_vendor': '',
                         'open_ports': [], 'last_seen': now_str, 'source': 'nmap'}
        h = cache[ip]

        if hostname and not h['hostname']:
            h['hostname'] = hostname

        mac_m = re.search(r'MAC:\s+([0-9A-Fa-f:]{17})\s+\(([^)]+)\)', line)
        if mac_m:
            h['mac']        = mac_m.group(1)
            h['mac_vendor'] = mac_m.group(2)
            h['source']     = 'nmap'

        os_m = re.search(r'\tOS:\s+([^\t]+)', line)
        if os_m and not h['os']:
            h['os'] = os_m.group(1).split(';')[0].strip()[:60]

        ports_m = re.search(r'\tPorts:\s+([^\t]+)', line)
        if ports_m:
            for entry in ports_m.group(1).split(', '):
                parts = entry.split('/')
                if len(parts) >= 2 and parts[1] == 'open':
                    num   = parts[0]
                    proto = parts[2] if len(parts) > 2 else ''
                    svc   = parts[4] if len(parts) > 4 else ''
                    label = f'{num}/{proto}:{svc}' if svc else f'{num}/{proto}'
                    if label not in h['open_ports']:
                        h['open_ports'].append(label)

        h['last_seen'] = now_str
        nmap_count += 1

with open(out_file, 'w') as f:
    json.dump(cache, f, indent=2)

print(f"  nmap enriched {nmap_count} records.")
print(f"  Total hosts in cache: {len(cache)}")
PYEOF

echo "=== done: $(date --iso-8601=seconds) ==="
