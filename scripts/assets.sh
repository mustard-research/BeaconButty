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
#   ZEEK_LOG_DIR    Zeek log root (default: /var/log/zeek)

CACHE_DIR="/var/lib/beaconbutty"
SCAN_GREP="${CACHE_DIR}/scan.gnmap"
HOSTS_FILE="${CACHE_DIR}/hosts.txt"
ASSETS_JSON="${CACHE_DIR}/assets.json"
LOGFILE="/var/log/beaconbutty/assets.log"
ALERT_BIN="${ALERT_BIN:-beaconbutty-alert.sh}"
ZEEK_LOG_DIR="${ZEEK_LOG_DIR:-/var/log/zeek}"

mkdir -p "$CACHE_DIR" /var/log/beaconbutty

# Private per-run temp for the new-device list. Was a fixed, world-guessable
# /tmp path: concurrent runs interleaved on it, and a local user could
# pre-plant a symlink that root would follow on write.
NEW_DEVICES_TMP=$(mktemp "${CACHE_DIR}/.new-devices.XXXXXX.json")
trap 'rm -f "$NEW_DEVICES_TMP"' EXIT
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
python3 - "$LAN_IFACE" "$ZEEK_LOG_DIR" "$ASSETS_JSON" "$NEW_DEVICES_TMP" <<'PYEOF'
import gzip, json, os, re, sys, glob
from datetime import datetime, date as _date

iface         = sys.argv[1]
zeek_dir      = sys.argv[2]
out_file      = sys.argv[3]
new_dev_file  = sys.argv[4]
now_str   = datetime.now().isoformat(timespec='seconds')

# ── Load old cache, indexed by MAC for hostname/OS/ports carry-forward ────────
# We do NOT carry IPs forward — we rebuild from current sources only.
# This prevents stale entries accumulating when a device changes IP.
try:
    with open(out_file) as f:
        old_cache = json.load(f)
except Exception:
    old_cache = {}

old_by_mac = {}  # mac → entry, for carrying metadata across IP changes
for ip, entry in old_cache.items():
    mac = entry.get('mac', '')
    if mac and mac not in old_by_mac:
        old_by_mac[mac] = entry

cache = {}  # fresh — only IPs seen in current ARP/dnsmasq will be written

def blank():
    return {'hostname': '', 'os': '', 'mac': '', 'mac_vendor': '',
            'open_ports': [], 'last_seen': now_str, 'source': ''}

def get(ip):
    if ip not in cache:
        cache[ip] = blank()
    return cache[ip]

def carry_forward(ip, mac, h):
    """Fill empty fields from old cache — called once after all live sources run.
    Live sources (dnsmasq, Zeek DHCP, HTTP UA, OSINT) always take priority;
    this only fills fields that are still empty after them."""
    old = old_by_mac.get(mac) or old_cache.get(ip)
    if not old:
        return
    if not h['hostname'] and old.get('hostname'):
        h['hostname'] = old['hostname']
    if not h['os'] and old.get('os'):
        h['os'] = old['os']
    if not h['open_ports'] and old.get('open_ports'):
        h['open_ports'] = old['open_ports']

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
# Supplement with prefixes missing from the nmap database (e.g. Pi 5 MACs)
OUI_LOCAL = {
    '9C69D3': 'Raspberry Pi Trading Ltd',   # Pi 5 ethernet
    '88A29E': 'Raspberry Pi Trading Ltd',   # Pi 5 wireless
    'D83ADD': 'Raspberry Pi Trading Ltd',   # Pi 4B (some batches)
    'DCA632': 'Raspberry Pi Trading Ltd',   # Pi 3B+/4
    'E45F01': 'Raspberry Pi Trading Ltd',   # Pi 4
    'B827EB': 'Raspberry Pi Foundation',    # Pi 1/2/3
    '2CCF67': 'Raspberry Pi Trading Ltd',   # Pi Zero 2 W
}
for prefix, name in OUI_LOCAL.items():
    if prefix not in oui:
        oui[prefix] = name
print(f"  OUI entries loaded: {len(oui)}  (+{len(OUI_LOCAL)} local supplements)")

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

# ── Seed the Pi's own LAN IP with its interface MAC ───────────────────────────
# The gateway never appears in its own ARP table, so we read it directly.
import subprocess as _sp
try:
    _link = _sp.run(['ip', 'link', 'show', iface], capture_output=True, text=True).stdout
    _mac_m = re.search(r'link/ether ([0-9a-f:]{17})', _link)
    _addr = _sp.run(['ip', '-4', 'addr', 'show', iface], capture_output=True, text=True).stdout
    _ip_m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', _addr)
    if _mac_m and _ip_m:
        _gw_ip  = _ip_m.group(1)
        _gw_mac = _mac_m.group(1)
        h = get(_gw_ip)
        if not h['mac']:
            h['mac']        = _gw_mac
            h['mac_vendor'] = vendor(_gw_mac)
            h['source']     = 'self'
            print(f"  Gateway {_gw_ip} seeded with own MAC {_gw_mac} ({h['mac_vendor'] or 'unknown vendor'})")
except Exception as _e:
    print(f"  Gateway MAC seed failed: {_e}")

# ── Read Zeek DHCP logs for hostnames ─────────────────────────────────────────
def zeek_rows(pattern):
    """Yield row dicts from plain or gzipped Zeek TSV log files."""
    for path in sorted(glob.glob(pattern)):
        fields = []
        try:
            opener = gzip.open if path.endswith('.gz') else open
            with opener(path, 'rt', errors='replace') as f:
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

from datetime import timedelta
today_dir     = f"{zeek_dir}/{_date.today().isoformat()}"
yesterday_dir = f"{zeek_dir}/{(_date.today() - timedelta(days=1)).isoformat()}"

dhcp_count = 0
for pattern in [f'{zeek_dir}/current/dhcp*.log',
                f'{today_dir}/dhcp*.log.gz',
                f'{yesterday_dir}/dhcp*.log.gz',
                f'{today_dir}/dhcp*.log',
                f'{yesterday_dir}/dhcp*.log']:
    for row in zeek_rows(pattern):
        ip       = row.get('assigned_addr', row.get('assigned_ip', '-'))
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

# ── Read Zeek HTTP logs for OS fingerprinting via User-Agent ──────────────────
def ua_to_os(ua):
    """Extract a clean OS name from a User-Agent string. Returns '' if unclear."""
    # iPadOS (must come before generic Mac OS X match)
    m = re.search(r'\(iPad[^)]*CPU.*?OS (\d+)[._](\d+)', ua)
    if m: return f"iPadOS {m.group(1)}.{m.group(2)}"
    # iPhone iOS
    m = re.search(r'\(iPhone[^)]*CPU.*?OS (\d+)[._](\d+)', ua)
    if m: return f"iOS {m.group(1)}.{m.group(2)}"
    # iPod iOS
    m = re.search(r'\(iPod[^)]*CPU.*?OS (\d+)[._](\d+)', ua)
    if m: return f"iOS {m.group(1)}.{m.group(2)} (iPod)"
    # Android (catches Dalvik/... Linux; U; Android N; too)
    m = re.search(r'Android (\d+)', ua)
    if m: return f"Android {m.group(1)}"
    # macOS
    m = re.search(r'Mac OS X (\d+)[._](\d+)', ua)
    if m: return f"macOS {m.group(1)}.{m.group(2)}"
    # Apple system daemons — macOS or iOS but can't distinguish
    if re.search(r'com\.apple\.|Darwin/', ua):
        return "macOS/iOS"
    # Windows
    m = re.search(r'Windows NT (\d+)\.(\d+)', ua)
    if m:
        names = {'10.0': 'Windows 10/11', '6.3': 'Windows 8.1', '6.2': 'Windows 8',
                 '6.1': 'Windows 7', '6.0': 'Windows Vista', '5.1': 'Windows XP'}
        return names.get(f"{m.group(1)}.{m.group(2)}", f"Windows NT {m.group(1)}.{m.group(2)}")
    # Linux desktop (X11)
    if re.search(r'\(X11.*?Linux|Linux.*?x86_64|Linux.*?aarch64', ua):
        return "Linux"
    # Chrome OS
    if 'CrOS' in ua: return "Chrome OS"
    # Sonos
    if 'Sonos/' in ua: return "Sonos"
    return ''

ua_votes = {}  # ip → {os_str: count}
for pattern in [f'{today_dir}/http.*.log.gz', f'{zeek_dir}/current/http.log']:
    for row in zeek_rows(pattern):
        ip = row.get('id.orig_h', '-')
        ua = row.get('user_agent', '-')
        if ip in ('-', '') or ua in ('-', ''):
            continue
        os_str = ua_to_os(ua)
        if os_str:
            ua_votes.setdefault(ip, {})
            ua_votes[ip][os_str] = ua_votes[ip].get(os_str, 0) + 1

ua_assigned = 0
for ip, votes in ua_votes.items():
    best = max(votes, key=votes.get)
    h = cache.get(ip)
    if h and not h.get('os'):
        h['os'] = best
        ua_assigned += 1
print(f"  HTTP UA OS detection: {len(ua_votes)} IPs seen, {ua_assigned} OS values assigned")

# ── OSINT static lookup: vendor + hostname → OS ───────────────────────────────
# High-confidence entries override existing OS values (correct nmap misidentifications).
# Medium-confidence entries only fill blanks.
# Skip override if existing OS already starts with the same family (preserves version detail).
def osint_os(vendor, hostname):
    """Return (os_str, high_confidence) from static device knowledge base."""
    v = (vendor or '').lower()
    h = (hostname or '').lower()
    # ── High confidence: hostname patterns ──────────────────────────────────
    if re.match(r'ipad', h):                                    return 'iPadOS', True
    if re.match(r'iphone', h) or 'iphone' in h:                return 'iOS', True
    if re.match(r'(laptop|desktop|pc)-[a-z0-9]', h):           return 'Windows 10/11', True
    if re.match(r'awair-elem', h):                              return 'FreeRTOS (Awair)', True
    if re.match(r'echoshow-', h):                               return 'Fire OS (Echo Show)', True
    if re.match(r'echo-[0-9a-f]', h):                          return 'Fire OS (Echo)', True
    if re.match(r'sonoszp|sonosp', h):                          return 'Sonos OS (Linux)', True
    if re.match(r'appletv', h):                                 return 'tvOS', True
    if re.match(r'sm-[a-z0-9]', h):                            return 'Android (Samsung)', True
    if re.search(r'-s\d{2}-ultra|-s\d{2}-plus|-s\d{2}-fe', h): return 'Android (Samsung)', True
    # ── High confidence: MAC vendor ─────────────────────────────────────────
    if 'sonos' in v:                                            return 'Sonos OS (Linux)', True
    if 'peloton interactive' in v:                              return 'Android (Peloton AOSP)', True
    if 'nest labs' in v:                                        return 'Embedded Linux (Nest)', True
    if 'espressif' in v:                                        return 'Embedded (ESP32/ESP8266)', True
    if 'raspberry pi' in v:                                     return 'Linux (Raspberry Pi OS)', True
    # ── Medium confidence: fill blanks only ─────────────────────────────────
    if 'philips lighting' in v:                                 return 'Embedded Linux (Hue Bridge)', False
    if 'amazon technologies' in v:
        label = 'Fire OS (Echo Show)' if 'echoshow' in h else 'Fire OS (Amazon)'
        return label, False
    if 'apple' in v:
        if any(x in h for x in ('-mb', '-air', '-pro', 'macbook', 'imac', 'mac-mini', 'mac-pro')):
            return 'macOS', False
    if h == 'mac':                                              return 'macOS', False
    return '', False

osint_count = 0
for ip, h in cache.items():
    os_str, high = osint_os(h.get('mac_vendor', ''), h.get('hostname', ''))
    if not os_str:
        continue
    current = h.get('os', '')
    # Never downgrade: skip if existing OS already starts with same family
    if current and current.lower().startswith(os_str.lower()):
        continue
    if high or not current:
        h['os'] = os_str
        osint_count += 1
print(f"  OSINT OS lookup: {osint_count} OS values set/corrected")

# ── Deferred carry-forward: fill gaps from old cache after all live sources ───
# Only fields still empty at this point get filled — live sources always win.
cf_count = 0
for ip, h in cache.items():
    mac = h.get('mac', '')
    before = (h['hostname'], h['os'], bool(h['open_ports']))
    carry_forward(ip, mac, h)
    if (h['hostname'], h['os'], bool(h['open_ports'])) != before:
        cf_count += 1
print(f"  Carry-forward from old cache: {cf_count} entries enriched")

pruned = len(old_cache) - len(cache)
if pruned > 0:
    print(f"  Pruned {pruned} stale IP(s) not seen in current ARP/DHCP sources")

# ── Dedup: if same MAC appears at multiple IPs, keep the dnsmasq entry ────────
# This handles mid-lease transitions where ARP and dnsmasq momentarily
# disagree on which IP a device holds.
mac_to_ips = {}
for ip, h in cache.items():
    mac = h.get('mac', '')
    if mac:
        mac_to_ips.setdefault(mac, []).append(ip)
for mac, ips in mac_to_ips.items():
    if len(ips) <= 1:
        continue
    # Prefer dnsmasq/zeek sources over arp-only
    preferred = sorted(ips, key=lambda i: (0 if cache[i]['source'] in ('dnsmasq', 'zeek/dhcp') else 1))
    for ip in preferred[1:]:
        del cache[ip]
    print(f"  Deduped MAC {mac}: kept {preferred[0]}, dropped {preferred[1:]}")

# ── Detect new devices ───────────────────────────────────────────────────────
# A MAC is "new" only if we have never seen it on this LAN before.
# Baseline = union of:
#   - known-macs.json   (persistent ever-seen set; grows each run)
#   - old_by_mac        (previous run's cache — seeds known-macs.json on upgrade)
#   - FP device list    (MACs the user has explicitly declared known)
# This stops sporadic devices (scales, bikes) from re-alerting every time their
# DHCP lease expires and they reappear.
KNOWN_MACS_FILE = os.path.join(os.path.dirname(out_file), 'known-macs.json')
known_macs = set()
try:
    with open(KNOWN_MACS_FILE) as f:
        known_macs = {m.lower() for m in json.load(f) if m}
except Exception:
    pass
known_macs.update(m.lower() for m in old_by_mac if m)

fp_macs = set()
try:
    with open(os.path.join(os.path.dirname(out_file), 'false-positives.conf')) as f:
        fp = json.load(f)
    fp_macs = {m.lower() for m in (fp.get('devices') or {}) if m}
except Exception:
    pass

new_devices = []
if known_macs:   # suppress all alerts on very first run (no baseline)
    for ip, h in cache.items():
        mac = (h.get('mac') or '').lower()
        if not mac:
            continue
        if mac in known_macs or mac in fp_macs:
            continue
        new_devices.append({
            'ip': ip,
            'mac': h['mac'],
            'vendor': h.get('mac_vendor', 'unknown vendor'),
            'hostname': h.get('hostname', ''),
        })
        print(f"  NEW device: {ip}  MAC {h['mac']}  ({h.get('mac_vendor','?')})")

# Persist every MAC seen this run so next run can recognise it
current_macs = {(h.get('mac') or '').lower() for h in cache.values() if h.get('mac')}
current_macs.discard('')
known_macs.update(current_macs)
# Atomic writes throughout: summarize.sh and the webapp read these files
# constantly; a torn read silently degrades to {} (and a truncated
# known-macs file would re-alert every sleeping device as "new").
try:
    with open(KNOWN_MACS_FILE + '.tmp', 'w') as f:
        json.dump(sorted(known_macs), f, indent=2)
    os.replace(KNOWN_MACS_FILE + '.tmp', KNOWN_MACS_FILE)
except Exception as e:
    print(f"  Warning: could not write {KNOWN_MACS_FILE}: {e}")

with open(new_dev_file + '.tmp', 'w') as f:
    json.dump(new_devices, f)
os.replace(new_dev_file + '.tmp', new_dev_file)

with open(out_file + '.tmp', 'w') as f:
    json.dump(cache, f, indent=2)
os.replace(out_file + '.tmp', out_file)
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
nmap -O \
     -sV --version-light \
     -p 22,80,443,445,3389,5900,8080,8443 \
     -T4 --host-timeout 20s \
     -Pn \
     -iL "$HOSTS_FILE" \
     -oG "$SCAN_GREP" 2>/dev/null

echo "nmap scan complete."

# ── Step 4: merge nmap results into cache ─────────────────────────────────────
python3 - "$SCAN_GREP" "$ASSETS_JSON" <<'PYEOF'
import json, os, re, sys
from datetime import datetime, timedelta

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
            os_str = os_m.group(1).split(';')[0].strip()[:60]
            # Reject multi-guess strings — nmap uses '|' to separate uncertain candidates
            if '|' not in os_str:
                h['os'] = os_str

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

with open(out_file + '.tmp', 'w') as f:
    json.dump(cache, f, indent=2)
os.replace(out_file + '.tmp', out_file)

print(f"  nmap enriched {nmap_count} records.")
print(f"  Total hosts in cache: {len(cache)}")

# ── Update rolling 14-day asset history ───────────────────────────────────────
# Records every IP+MAC ever resolved, with first_seen/last_seen dates.  The
# /assets webapp page renders entries from this file that are NOT in the live
# cache as dimmed "ghost" rows so the multi-day Slow-Cadence view stays
# coherent with Assets when a laptop disappears mid-window.
HISTORY_FILE = os.path.join(os.path.dirname(out_file), 'assets-history.json')
HISTORY_DAYS = 14
today_iso    = datetime.now().date().isoformat()

history = {}
try:
    with open(HISTORY_FILE) as f:
        history = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    pass

# Fold today's live cache into history.  Live data wins on every field, but
# preserve first_seen across runs.
for ip, h in cache.items():
    prev = history.get(ip, {})
    history[ip] = {
        'mac':         h.get('mac', ''),
        'mac_vendor':  h.get('mac_vendor', ''),
        'hostname':    h.get('hostname', ''),
        'os':          h.get('os', ''),
        'open_ports':  list(h.get('open_ports', [])),
        'first_seen':  prev.get('first_seen', today_iso),
        'last_seen':   today_iso,
    }

# Prune entries whose last_seen is older than HISTORY_DAYS.
cutoff = (datetime.now().date() - timedelta(days=HISTORY_DAYS)).isoformat()
pruned = [ip for ip, h in history.items() if h.get('last_seen', '') < cutoff]
for ip in pruned:
    del history[ip]

tmp_history = HISTORY_FILE + '.tmp'
with open(tmp_history, 'w') as f:
    json.dump(history, f, indent=2, sort_keys=True)
os.replace(tmp_history, HISTORY_FILE)
print(f"  Asset history: {len(history)} entries (pruned {len(pruned)} >{HISTORY_DAYS}d).")
PYEOF

# ── Alert on new devices ─────────────────────────────────────────────────────
# Gate: a MAC with the locally-administered bit set (LAA, bit 0x02 of the
# first byte) is almost certainly an OS-generated randomised MAC — iOS,
# macOS, Android, and Windows all rotate their MAC for privacy. These
# rotate naturally over time and would page repeatedly without ever
# representing a "new" device. Demote them to hunt-only (visible on
# /assets, not Slack-paged). Globally-assigned MACs from real OUIs
# continue to alert as before.
if command -v "$ALERT_BIN" &>/dev/null && [[ -s "$NEW_DEVICES_TMP" ]]; then
    python3 -c "
import json, subprocess, os
from datetime import datetime, timezone

STATS = '/var/lib/beaconbutty/reports/alert-gate-stats.json'

def is_laa(mac):
    \"\"\"Locally-administered MAC: bit 0x02 of the first octet is set.\"\"\"
    try:
        return bool(int(mac.split(':')[0], 16) & 0x02)
    except (ValueError, IndexError, AttributeError):
        return False

devs = json.load(open('$NEW_DEVICES_TMP'))
fired = 0
gated_random = 0
for d in devs:
    if is_laa(d.get('mac', '')):
        gated_random += 1
        print(f\"  gated (randomised MAC): {d['ip']} {d['mac']}\")
        continue
    vendor   = d.get('vendor') or 'unknown vendor'
    hostname = d.get('hostname') or ''
    host_str = f' ({hostname})' if hostname else ''
    detail   = f\"MAC {d['mac']} — {vendor}{host_str}\"
    subprocess.run(['$ALERT_BIN', 'new_device', 'medium', d['ip'], detail])
    fired += 1

# Stats for /health Alert Gate panel.
try:
    data = json.load(open(STATS)) if os.path.exists(STATS) else {}
except json.JSONDecodeError:
    data = {}
data['new_device'] = {
    'ts':    datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    'fired': fired,
    'gated': {'mac_randomised': gated_random},
}
os.makedirs(os.path.dirname(STATS), exist_ok=True)
tmp = STATS + '.tmp'
with open(tmp, 'w') as f:
    json.dump(data, f, indent=2)
os.replace(tmp, STATS)
" 2>/dev/null || true
fi
rm -f "$NEW_DEVICES_TMP"

echo "=== done: $(date --iso-8601=seconds) ==="
