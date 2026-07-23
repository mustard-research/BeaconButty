#!/usr/bin/env bash
set -euo pipefail

# summarize.sh — parse the day's beacon report and print visual summary tables.
#
# Usage:
#   beaconbutty-summary.sh                  # uses today's report (runs it first if needed)
#   beaconbutty-summary.sh /path/to/report  # summarises a specific report file
#
# Set BEACON_THRESHOLD=0.90 to raise the score cutoff for the top-beacons table.

REPORT_DIR="/var/lib/beaconbutty/reports"
LEASES_FILE="/var/lib/misc/dnsmasq.leases"
TODAY=$(date +%Y%m%d)
THRESHOLD="${BEACON_THRESHOLD:-0.80}"

if [[ $# -ge 1 ]]; then
    REPORT_FILE="$1"
elif [[ -f "${REPORT_DIR}/beacon-report-${TODAY}.txt" ]]; then
    REPORT_FILE="${REPORT_DIR}/beacon-report-${TODAY}.txt"
else
    echo "No report for today — running beacon-report.sh first..."
    beacon-report.sh >/dev/null
    echo ""
    REPORT_FILE="${REPORT_DIR}/beacon-report-${TODAY}.txt"
fi

[[ -f "$REPORT_FILE" ]] || { echo "Report not found: $REPORT_FILE"; exit 1; }

SEND_ALERTS="${SEND_ALERTS:-0}"

python3 - "$REPORT_FILE" "$THRESHOLD" "$LEASES_FILE" "$SEND_ALERTS" <<'PYEOF'
import csv, json, re, sys, os, ipaddress, fnmatch
from collections import defaultdict
from datetime import datetime

# MaxMind ASN + City lookup (same databases as webapp)
_asn_reader  = None
_city_reader = None
try:
    import geoip2.database
    _asn_reader  = geoip2.database.Reader('/var/lib/GeoIP/GeoLite2-ASN.mmdb')
    _city_reader = geoip2.database.Reader('/var/lib/GeoIP/GeoLite2-City.mmdb')
except Exception:
    pass

_SAFE_ORGS = {'Apple Inc.', 'Microsoft Corporation', 'Google LLC', 'Cloudflare, Inc.', 'NetActuate, Inc'}

def _is_safe_org_ip(ip):
    if not _asn_reader or not ip:
        return False
    try:
        return _asn_reader.asn(ip).autonomous_system_organization in _SAFE_ORGS
    except Exception:
        return False

_IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

def annotate_dest(d):
    """Append (org, city, country) for bare IP destinations."""
    if not _IP_RE.match(d):
        return d
    parts = []
    try:
        if _asn_reader:
            org = _asn_reader.asn(d).autonomous_system_organization
            if org:
                parts.append(org)
    except Exception:
        pass
    try:
        if _city_reader:
            r = _city_reader.city(d)
            if r.city.name:
                parts.append(r.city.name)
            if r.country.iso_code:
                parts.append(r.country.iso_code)
    except Exception:
        pass
    return f"{d} ({', '.join(parts)})" if parts else d

report_file  = sys.argv[1]
threshold    = float(sys.argv[2])
leases_file  = sys.argv[3]
send_alerts  = sys.argv[4] == "1"

# ── Parse all CSV rows from report ───────────────────────────────────────────
csv_lines = []
with open(report_file) as f:
    in_csv = False
    for raw in f:
        line = raw.rstrip('\n')
        if line.startswith('Severity,'):
            in_csv = True
            if not csv_lines:
                csv_lines.append(line)
        elif in_csv:
            if not line.strip() or line[0] in '└╔╚┌─':
                in_csv = False
            elif not line.startswith('Severity,'):
                csv_lines.append(line)

if not csv_lines:
    print("No CSV data found in report.")
    sys.exit(0)

reader = csv.reader(csv_lines)
header = next(reader)
COL    = {name.strip(): i for i, name in enumerate(header)}
rows   = [r for r in reader if len(r) >= len(header) - 1]

# RITA emits some FQDNs in DNS root-anchored form ("foo.com."); normalise so
# FP patterns, the hyperscaler-suffix gate and (src,dst,fqdn) dedup all match.
for r in rows:
    r[COL['FQDN']] = r[COL['FQDN']].rstrip('.')

# Each report file bundles the last 3 RITA daily databases, so a persistent
# beacon appears once per day. Collapse to one row per distinct
# (src, dst, fqdn) — highest score wins, the later (more recent) day breaks
# ties — so every count below reflects distinct beacons, not beacon-days.
def _bscore(r):
    try:    return float(r[COL['Beacon Score']])
    except: return 0.0
_deduped = {}
for r in rows:
    k = (r[COL['Source IP']].strip(),
         r[COL['Destination IP']].strip(),
         r[COL['FQDN']].strip())
    if k not in _deduped or _bscore(r) >= _bscore(_deduped[k]):
        _deduped[k] = r
rows = list(_deduped.values())

# ── Load asset cache ──────────────────────────────────────────────────────────
ASSETS_FILE = '/var/lib/beaconbutty/assets.json'
try:
    with open(ASSETS_FILE) as f:
        assets = json.load(f)
    asset_ts = os.path.getmtime(ASSETS_FILE)
    asset_age_min = int((datetime.now().timestamp() - asset_ts) / 60)
except Exception:
    assets = {}
    asset_age_min = None

# ── Load false positives and resolve to current IPs ───────────────────────────
FP_FILE = '/var/lib/beaconbutty/false-positives.conf'
try:
    with open(FP_FILE) as f:
        fp_raw = json.load(f)
except Exception:
    fp_raw = {}

# Support v2 format {version, devices, domains, protocols} and v1 (flat MAC dict)
if isinstance(fp_raw, dict) and fp_raw.get('version') == 2:
    fp_by_mac  = fp_raw.get('devices', {})
    fp_domains = fp_raw.get('domains', {})    # pattern → reason
    fp_protos  = fp_raw.get('protocols', {})  # svc → reason
else:
    fp_by_mac  = fp_raw
    fp_domains = {}
    fp_protos  = {}

mac_to_ip  = {}
ip_to_host = {}
try:
    with open(leases_file) as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3:
                mac_to_ip[parts[1].lower()] = parts[2]
            if len(parts) >= 4 and parts[3] != '*':
                ip_to_host[parts[2]] = parts[3]
except Exception:
    pass

# Manual name overrides — same semantics as the webapp's ip_label():
# device-names.json wins over the DHCP hostname (the summary previously
# ignored the override file entirely, so the two surfaces disagreed).
name_overrides = {}
try:
    with open('/var/lib/beaconbutty/device-names.json') as f:
        name_overrides = {k: v for k, v in json.load(f).items()
                          if isinstance(v, str) and v}
except Exception:
    pass

def ip_label(ip):
    h = name_overrides.get(ip) or ip_to_host.get(ip, '')
    return f"{ip} ({h})" if h else ip

# ── MAC→IP history from Zeek DHCP logs ───────────────────────────────────────
# Beacon report rows carry the LAN IP that was assigned at Zeek-capture time.
# A device can change IP between capture and report rendering (lease renewal),
# so matching FP MACs to the *current* dnsmasq lease alone misses rows that
# still reference the MAC's previous IP. Walk the last 14 days of Zeek DHCP
# logs (RITA retention window) so every IP each MAC has held is covered.
import gzip, glob
ZEEK_LOG_DIR = '/var/log/zeek'
mac_ips_hist = defaultdict(set)   # mac → {ip, ip, ...}
_dhcp_patterns = sorted(glob.glob(f'{ZEEK_LOG_DIR}/2*'))[-14:]
_dhcp_patterns.append(f'{ZEEK_LOG_DIR}/current')
for day_dir in _dhcp_patterns:
    for logp in glob.glob(f'{day_dir}/dhcp*.log*'):
        try:
            opener = gzip.open if logp.endswith('.gz') else open
            with opener(logp, 'rt', errors='replace') as f:
                fields = []
                for line in f:
                    line = line.rstrip('\n')
                    if line.startswith('#fields'):
                        fields = line.split('\t')[1:]
                    elif line.startswith('#') or not fields:
                        continue
                    else:
                        row = dict(zip(fields, line.split('\t')))
                        mac = (row.get('mac') or '').lower()
                        ip  = row.get('assigned_addr') or row.get('assigned_ip') or ''
                        if mac and ip and mac != '-' and ip != '-':
                            mac_ips_hist[mac].add(ip)
        except Exception:
            continue
# Merge current dnsmasq view so an FP MAC is always resolved even if Zeek
# never recorded a DHCP handshake for it (e.g. static ARP entry).
for mac, ip in mac_to_ip.items():
    mac_ips_hist[mac].add(ip)

# Build IP-keyed view for device suppression
false_positives = {}   # ip → reason  (for suppression)
fp_mac_display  = []   # (mac, current_ip, reason)  (for display table)
for mac, reason in fp_by_mac.items():
    mac_l  = mac.lower()
    cur_ip = mac_to_ip.get(mac_l)
    fp_mac_display.append((mac, cur_ip or '\u2014', reason))
    for hist_ip in mac_ips_hist.get(mac_l, ()):
        false_positives[hist_ip] = reason

if not rows:
    print("No findings in report.")
    sys.exit(0)

# Count suppressed findings per FP IP, then remove them from all analysis
fp_suppressed = defaultdict(int)
for r in rows:
    if r[COL['Source IP']].strip() in false_positives:
        fp_suppressed[r[COL['Source IP']].strip()] += 1
rows = [r for r in rows if r[COL['Source IP']].strip() not in false_positives]

# Domain and protocol suppression (row-level, independent of source device)
def _domain_suppressed(fqdn, dst):
    if not fp_domains:
        return False
    target = fqdn if fqdn else dst
    for pat in fp_domains:
        if fnmatch.fnmatch(target, pat):
            return True
        if pat.startswith("*.") and target == pat[2:]:
            return True
    return False

def _proto_suppressed(svc):
    # RITA bundles services into one field ("80:tcp:http,3478:udp:"); FPs are
    # registered per single component ("3478:udp"), so test each comma-separated
    # component rather than prefix-matching the whole string.
    if not fp_protos:
        return False
    for comp in (svc or '').strip().split(','):
        comp = comp.strip()
        if comp and any(comp == pat or comp.startswith(pat + ':') for pat in fp_protos):
            return True
    return False

fp_domain_count = 0
fp_proto_count  = 0
filtered_rows   = []
for r in rows:
    fqdn = r[COL['FQDN']].strip()
    dst  = r[COL['Destination IP']].strip()
    svc  = r[COL['Port:Proto:Service']].strip()
    if _domain_suppressed(fqdn, dst):
        fp_domain_count += 1
    elif _proto_suppressed(svc):
        fp_proto_count += 1
    else:
        filtered_rows.append(r)
rows = filtered_rows

# Drop rows with non-IPv4 source IPs (e.g. '::' from RITA's IPv6 artefacts)
def is_ipv4(s):
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False
rows = [r for r in rows if is_ipv4(r[COL['Source IP']].strip())]

# ── Field accessors ───────────────────────────────────────────────────────────
def dest(row):
    fqdn = row[COL['FQDN']].strip()
    ip   = row[COL['Destination IP']].strip()
    raw  = fqdn if fqdn else ip
    return annotate_dest(raw)

def score(row):
    try:    return float(row[COL['Beacon Score']])
    except: return 0.0

def conns(row):
    try:    return int(row[COL['Connection Count']])
    except: return 0

def svc(row):
    s = row[COL['Port:Proto:Service']].strip()
    return s[:24] if len(s) > 24 else s

def bytes_mb(row):
    try:    return int(row[COL['Total Bytes']]) / 1e6
    except: return 0.0

def trunc(s, n):
    return s[:n - 1] + '\u2026' if len(s) > n else s

def ip_sort(ip):
    try:    return tuple(int(x) for x in ip.split('.'))
    except: return (0,) * 4

# ── Alert gate (lonely + non-hyperscaler) ────────────────────────────────────
# Same philosophy as scripts/slow-cadence.py: only Slack-page when the
# finding is the sole LAN talker AND on a non-hyperscaler ASN. Everything
# else stays on the dashboard for hunting. The two scripts maintain
# duplicate copies of HYPERSCALER_TOKENS — keep them in sync.
HYPERSCALER_TOKENS = (
    'amazon', 'cloudflare', 'google', 'microsoft', 'apple', 'akamai',
    'fastly', 'netflix', 'facebook', 'meta platforms', 'meta-llc',
    'twitter', 'github', 'salesforce', 'adobe', 'oracle',
    'linode', 'digitalocean', 'stackpath', 'bunny.net', 'cdn77',
    'keycdn', 'alibaba', 'tencent', 'byteplus', 'bytedance',
    'ovh', 'hetzner', 'leaseweb', 'limelight', 'edgio', 'cloudfront',
    'verizon', 'at&t', 'comcast', 'level 3', 'lumen', 'centurylink',
    'incapsula', 'imperva', 'sucuri',
)

def is_hyperscaler(org):
    if not org: return False
    low = org.lower()
    return any(t in low for t in HYPERSCALER_TOKENS)

# FQDN suffixes for the same hyperscaler set. Used when RITA's row has no
# usable Destination IP (it represents FQDN-keyed beacons as "::"), so the
# ASN lookup returns empty. Suffix match treats `live.net` as covering
# `docs.live.net`, `eas.outlook.com`, etc. Keep aligned with the ASN-side
# token list — a domain owned by a hyperscaler should be classified the
# same way regardless of which signal carried it.
HYPERSCALER_FQDN_SUFFIXES = (
    # Microsoft family
    'microsoft.com', 'live.com', 'live.net', 'office.com', 'office.net',
    'microsoftonline.com', 'sharepoint.com', 'outlook.com', 'msn.com',
    'azure.com', 'azureedge.net', 'windows.com', 'windowsupdate.com',
    'msftconnecttest.com', 'msecnd.net', 'cloud.microsoft',
    'svc.static.microsoft', 'public.onecdn.static.microsoft',
    'aka.ms', 'appcenter.ms', 'microsoftpersonalcontent.com',
    # Google
    'google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com',
    'googlevideo.com', 'youtube.com', 'doubleclick.net',
    # Apple
    'apple.com', 'icloud.com', 'icloud-content.com', 'mzstatic.com',
    'aaplimg.com', 'cdn-apple.com',
    # Cloudflare
    'cloudflare.com', 'cloudflare-dns.com', 'cloudflareinsights.com',
    # Amazon
    'amazon.com', 'amazonaws.com', 'amazonvideo.com', 'cloudfront.net',
    # Akamai / Fastly
    'akamai.net', 'akamaiedge.net', 'akamaihd.net', 'edgekey.net',
    'fastly.net', 'fastly-edge.com',
)

def is_hyperscaler_fqdn(fqdn):
    if not fqdn: return False
    f = fqdn.lower().strip()
    return any(f == s or f.endswith('.' + s) for s in HYPERSCALER_FQDN_SUFFIXES)

def asn_org_for(ip):
    if not _asn_reader or not ip: return ''
    try:    return _asn_reader.asn(ip).autonomous_system_organization or ''
    except Exception: return ''

def port_from(row):
    """Extract numeric dst port from "443:tcp:ssl" style column."""
    try:    return int(row[COL['Port:Proto:Service']].split(':')[0])
    except Exception: return 0

def get_lan_talkers_map():
    """Per (dst_ip, dst_port), distinct LAN srcs over the 14-day window.
    Filtering by candidate dsts is left to Python — a 14× IN-list
    overruns max_query_size (slow-cadence learned the same lesson)."""
    import subprocess
    CH = '/usr/bin/clickhouse-client'
    try:
        dbs_out = subprocess.run(
            [CH, '-q', 'SHOW DATABASES'], capture_output=True, text=True,
            timeout=30, check=True).stdout
        dbs = sorted(d for d in dbs_out.splitlines()
                     if d.startswith('beaconbutty_2'))[-14:]
        if not dbs: return {}
        union = ' UNION ALL '.join(
            f"""SELECT IPv6NumToString(dst) AS dst_str, dst_port, src
                FROM {db}.conn
                WHERE dst_local = false AND src_local = true
                  AND proto IN ('tcp', 'udp')
                  AND service NOT IN ('dns', 'ntp')""" for db in dbs)
        sql = (f"SELECT dst_str AS dst, dst_port, uniqExact(src) AS talkers "
               f"FROM ({union}) GROUP BY dst_str, dst_port "
               f"FORMAT JSONEachRow")
        out = subprocess.run([CH], input=sql, capture_output=True, text=True,
                             timeout=300, check=True).stdout
    except Exception as e:
        # None (not {}) — an empty map would make every destination look
        # "lonely" and a ClickHouse outage would fire the full ungated
        # alert set. The gate treats None as "unknown → don't page".
        print(f'lan_talkers query failed: {e}', file=sys.stderr)
        return None
    result = {}
    for line in out.splitlines():
        if not line.strip(): continue
        row = json.loads(line)
        ip = row['dst'].replace('::ffff:', '')
        result[(ip, int(row['dst_port']))] = row['talkers']
    return result

GATE_STATS_FILE = '/var/lib/beaconbutty/reports/alert-gate-stats.json'

def write_gate_stats(component, fired, gated):
    """Atomic update of the per-component subkey in the shared stats file."""
    from datetime import datetime, timezone
    try:
        with open(GATE_STATS_FILE) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}
    data[component] = {
        'ts':    datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        'fired': fired,
        'gated': gated,
    }
    tmp = GATE_STATS_FILE + '.tmp'
    os.makedirs(os.path.dirname(GATE_STATS_FILE), exist_ok=True)
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, GATE_STATS_FILE)

def parse_hours(s):
    s = s.strip().lower()
    m = re.match(r'(\d+)\s+hours?\s+ago', s)
    if m: return float(m.group(1))
    m = re.match(r'(\d+)\s+minutes?\s+ago', s)
    if m: return float(m.group(1)) / 60
    return None

# ── Box-drawing table renderer ────────────────────────────────────────────────
def table(headers, data_rows, aligns=None):
    # data_rows may contain None as a group-separator sentinel
    real_rows = [[str(c) for c in r] for r in data_rows if r is not None]
    if not real_rows:
        return '  (none)'
    aligns = aligns or ['<'] * len(headers)
    widths = [
        max(len(h), max((len(r[i]) for r in real_rows), default=0))
        for i, h in enumerate(headers)
    ]

    def bar(l, m, r):
        return l + m.join('\u2500' * (w + 2) for w in widths) + r

    def row_str(cells):
        return '\u2502' + '\u2502'.join(
            f' {c:>{w}} ' if a == '>' else f' {c:<{w}} '
            for c, w, a in zip(cells, widths, aligns)
        ) + '\u2502'

    lines = [bar('\u250c', '\u252c', '\u2510'), row_str(headers), bar('\u251c', '\u253c', '\u2524')]
    for r in data_rows:
        if r is None:
            lines.append(bar('\u251c', '\u253c', '\u2524'))
        else:
            lines.append(row_str([str(c) for c in r]))
    lines.append(bar('\u2514', '\u2534', '\u2518'))
    return '\n'.join(lines)

# ── Intelligence patterns ─────────────────────────────────────────────────────
BENIGN_PATS = [
    (r'microsoft|aka\.ms|msecnd\.net|msftconnecttest|appcenter\.ms|microsoftpersonalcontent\.com', 'Microsoft'),
    (r'office365|sharepoint\.com|onedrive|outlook\.com', 'Microsoft 365'),
    (r'trouter|asyncgw|flightproxy|teams\.', 'Microsoft Teams'),
    (r'\.apple\.com$|icloud\.com|tether\.edge\.apple|\.apple$|smoot\.apple|mzstatic\.com|aaplimg\.com', 'Apple'),
    (r'ubuntu\.com', 'Ubuntu'),
    (r'mozilla\.(com|org|net)', 'Mozilla'),
    (r'google(apis)?\.com|googleapis\.com|\.goog$|safebrowsing|dns\.google', 'Google'),
    (r'^1\.1\.1\.1$|one\.one\.one\.one|cloudflare(-dns)?\.com', 'Cloudflare DNS'),
    (r'^8\.8\.[48]\.8$', 'Google DNS'),
    (r'nest\.com', 'Google Nest'),
    (r'amazonalexa\.com', 'Amazon Alexa'),
    (r'amazon\.(com|co\.uk)|amazonaws\.com|amazonvideo\.com|thumbnails-photos\.amazon', 'Amazon'),
    (r'garmin\.com', 'Garmin'),
    (r'fing\.(io|com)', 'Fing'),
    (r'svc\.ui\.com|ubnt\.com', 'Ubiquiti'),
    (r'newrelic\.com', 'New Relic'),
    (r'optimizely\.com', 'Optimizely'),
    (r'tailscale\.com', 'Tailscale'),
    (r'signal\.org', 'Signal'),
    (r'anthropic\.com', 'Anthropic'),
    (r'cloudfront|azureedge\.net|fastly-edge', 'CDN'),
    (r'duckduckgo\.com', 'DuckDuckGo'),
    (r'monknow\.com', 'Monknow'),
    (r'netflix\.com', 'Netflix'),
    (r'connectivity-check', 'Ubuntu connectivity'),
    (r'pgdiscovery\.com', 'pgdiscovery'),
]

TOR_NETS = [ipaddress.ip_network(c) for c in [
    '162.247.241.0/24', '162.247.72.0/24', '199.87.154.0/24',
    '176.10.104.0/24',  '185.220.101.0/24',
]]

BENIGN_NETS = [
    ('17.0.0.0/8',     'Apple'),
    ('20.0.0.0/8',     'Microsoft Azure'),
    ('40.0.0.0/8',     'Microsoft Azure'),
    ('52.0.0.0/8',     'AWS/Microsoft'),
    ('54.0.0.0/8',     'AWS'),
    ('35.0.0.0/8',     'Google Cloud'),
    ('34.0.0.0/8',     'Google Cloud'),
]
BENIGN_NET_OBJS = [(ipaddress.ip_network(c), label) for c, label in BENIGN_NETS]

def is_benign_ip(ip):
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
        for net, label in BENIGN_NET_OBJS:
            if addr in net:
                return label
    except ValueError:
        pass
    return None

CHINESE_TECH = [
    (r'baidu\.com',     'Baidu'),
    (r'tuisong\.',      'Baidu Push'),
    (r'snssdk\.com',    'TikTok/ByteDance'),
    (r'aweme\.',        'TikTok/ByteDance'),
    (r'bytedance\.com', 'ByteDance'),
    (r'toutiao\.com',   'ByteDance/Toutiao'),
    (r'qq\.com',        'Tencent'),
    (r'wechat\.com',    'WeChat'),
    (r'alibaba\.com',   'Alibaba'),
    (r'aliyun\.com',    'Alibaba Cloud'),
]

DEVICE_PRINTS = [
    (['tailscale.com', 'anthropic.com'],                              'The Pi'),
    (['svc.ui.com', 'ubnt.com'],                                      'Ubiquiti UniFi'),
    (['logsink.devices.nest.com', 'weather.nest.com'],                'Nest device'),
    (['amazonalexa.com'],                                             'Alexa device'),
    (['thumbnails-photos.amazon'],                                    'Amazon device'),
    (['connectivity-check.ubuntu.com'],                               'Ubuntu machine'),
    (['garmin.com'],                                                  'Garmin device'),
    (['fing.io', 'fing.com'],                                        'Fing network scanner'),
    (['endpoint.security.microsoft', 'trouter.teams.microsoft.com'], 'Windows/Mac + Office 365'),
    (['icloud.com', 'mask.icloud.com', 'tether.edge.apple',
      'xp.apple.com', 'smoot.apple.com'],                            'Apple device'),
    (['newrelic.com'],                                                'Device with New Relic agent'),
    (['signal.org'],                                                  'Device with Signal'),
]

def is_benign(d):
    for pat, vendor in BENIGN_PATS:
        if re.search(pat, d, re.I):
            return vendor
    return None

def is_tor(ip):
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in TOR_NETS)
    except ValueError:
        return False

def is_chinese(d):
    for pat, vendor in CHINESE_TECH:
        if re.search(pat, d, re.I):
            return vendor
    return None

def flag_row(row):
    """Return (flag_type, message) or (None, None) if not suspicious."""
    d      = dest(row)
    raw_ip = row[COL['Destination IP']].strip()
    s      = score(row)
    p      = svc(row).lower()
    c      = conns(row)
    fs     = row[COL['First Seen']]

    if is_tor(raw_ip):
        mb = bytes_mb(row)
        return 'tor', f'Tor Project IP ({c} conns, {mb:.1f}\u202fMB)'

    cn = is_chinese(d)
    if cn:
        return 'chinese', cn

    if 'icmp' in p and s >= 0.90:
        hrs = parse_hours(fs)
        if hrs and c > 0:
            interval = hrs * 60 / c
            return 'icmp', f'ICMP beacon: {c} pings, ~1 every {interval:.1f}\u202fmin'
        return 'icmp', f'ICMP beacon: {c} pings'

    if '53:udp:dns' in p and c >= 200 and s >= 0.90:
        hrs = parse_hours(fs)
        if hrs and hrs > 0:
            rate = c / hrs
            return 'dns', f'Excessive DNS: {c} queries, ~{rate:.0f}/hr \u2192 {d}'
        return 'dns', f'Excessive DNS: {c} queries \u2192 {d}'

    if s >= 0.97 and not row[COL['FQDN']].strip() \
            and not is_benign(raw_ip) and not is_benign_ip(raw_ip):
        return 'unknown', f'Score {s:.3f} beacon to unnamed IP (no FQDN)'

    return None, None

def fingerprint(dests_list):
    for keywords, label in DEVICE_PRINTS:
        if any(any(kw in d for d in dests_list) for kw in keywords):
            return label
    return None

# ── Extract display date from filename ───────────────────────────────────────
fname = os.path.basename(report_file)
try:
    d = fname.replace('beacon-report-', '').split('.')[0]
    display_date = f'{d[:4]}-{d[4:6]}-{d[6:8]}'
except Exception:
    display_date = '(unknown date)'

# ═════════════════════════════════════════════════════════════════════════════
print()
inner = f'  BeaconButty Summary  \u2500  {display_date}'
print('\u2554' + '\u2550' * 54 + '\u2557')
print(f'\u2551{inner:<54}\u2551')
print('\u255a' + '\u2550' * 54 + '\u255d')
print()

# ── 1. False positives ───────────────────────────────────────────────────────
has_fp = fp_mac_display or fp_domains or fp_protos
if has_fp:
    dev_sup = sum(fp_suppressed.values())
    total_sup = dev_sup + fp_domain_count + fp_proto_count
    total_rules = len(fp_mac_display) + len(fp_domains) + len(fp_protos)
    print(f'FALSE POSITIVES  ({total_rules} registered \u2014 {total_sup} findings suppressed)')
    if fp_mac_display:
        print('  Devices:')
        fp_data = []
        for mac, cur_ip, reason in sorted(fp_mac_display, key=lambda x: ip_sort(x[1])):
            sup = sum(fp_suppressed.get(ip, 0) for ip in mac_ips_hist.get(mac.lower(), ()))
            fp_data.append([mac, cur_ip, trunc(reason, 38), sup if sup else '\u2014'])
        print(table(
            ['MAC Address', 'Current IP', 'Reason', 'Suppressed'],
            fp_data,
            ['<', '<', '<', '>']
        ))
    if fp_domains:
        print(f'  Domains  ({fp_domain_count} suppressed):')
        dom_data = [[pat, trunc(reason, 50)] for pat, reason in sorted(fp_domains.items())]
        print(table(['Pattern', 'Reason'], dom_data, ['<', '<']))
    if fp_protos:
        print(f'  Protocols  ({fp_proto_count} suppressed):')
        proto_data = [[svc, trunc(reason, 50)] for svc, reason in sorted(fp_protos.items())]
        print(table(['Service', 'Reason'], proto_data, ['<', '<']))
    print()

# ── 2. Likely benign ─────────────────────────────────────────────────────────
ip_all_dests = defaultdict(list)
for r in rows:
    ip = r[COL['Source IP']].strip()
    d  = dest(r)
    if d and d not in ip_all_dests[ip]:
        ip_all_dests[ip].append(d)

benign_map = {}
for ip, dests_list in ip_all_dests.items():
    label = fingerprint(dests_list)
    if not label:
        continue
    evidence = []
    for d in dests_list:
        vendor = is_benign(d)
        if vendor and len(evidence) < 3:
            evidence.append(d)
    benign_map[ip] = {'label': label, 'evidence': evidence}

benign_rows = [
    [ip_label(ip), benign_map[ip]['label'], trunc(', '.join(benign_map[ip]['evidence']), 52)]
    for ip in sorted(benign_map, key=ip_sort)
]

print(f'LIKELY BENIGN  ({len(benign_rows)} recognised device{"s" if len(benign_rows) != 1 else ""})')
if benign_rows:
    print(table(
        ['Source IP', 'Likely Device', 'Evidence'],
        benign_rows,
        ['<', '<', '<']
    ))
else:
    print('  No devices recognised.')
print()

# ── Filter benign-destination rows before hotlist/scoring sections ────────────
# Mirror the webapp: remove rows whose destination matches a known-safe vendor.
def is_safe_dest_row(row):
    d      = dest(row)
    raw_ip = row[COL['Destination IP']].strip()
    return bool(is_benign(d)) or bool(is_benign_ip(raw_ip)) or _is_safe_org_ip(raw_ip)

# Capture threat-intel rows BEFORE the benign filter: a TI hit is
# high-confidence on its own, and real C2 is routinely hosted inside the
# blanket vendor /8s (EC2/Azure/GCP), so those must not suppress it. Explicit
# user-curated suppressions (domain safe list, org FPs) still apply.
ti_rows = [r for r in rows
           if r[COL['Threat Intel']].strip().lower() == 'true'
           and not is_benign(dest(r))
           and not _is_safe_org_ip(r[COL['Destination IP']].strip())]

rows = [r for r in rows if not is_safe_dest_row(r)]

# ── 3. Severity breakdown ────────────────────────────────────────────────────
sev_counts = defaultdict(int)
for r in rows:
    sev_counts[r[COL['Severity']].strip()] += 1

print('SEVERITY BREAKDOWN')
sev_data = [(s, sev_counts[s]) for s in ('Critical', 'High', 'Medium', 'Low', 'None') if sev_counts[s]]
sev_data.append(('Total', sum(c for _, c in sev_data)))
print(table(['Severity', 'Count'], sev_data, ['<', '>']))
print()

# ── 4. Device hotlist ────────────────────────────────────────────────────────
print('DEVICE HOTLIST')
dev = defaultdict(lambda: {'H': 0, 'M': 0, 'total': 0, 'max': 0.0, 'top': ''})
for r in rows:
    ip  = r[COL['Source IP']].strip()
    s   = score(r)
    sev = r[COL['Severity']].strip()
    d   = dev[ip]
    d['total'] += 1
    if   sev in ('Critical', 'High'): d['H'] += 1
    elif sev == 'Medium':             d['M'] += 1
    if s > d['max']:
        d['max'] = s
        d['top'] = dest(r)

sorted_devs = sorted(dev.items(), key=lambda x: (-x[1]['H'], -x[1]['max']))
dev_data = [
    [ip_label(ip), d['H'], d['M'], d['total'], f"{d['max']:.3f}", trunc(d['top'], 36)]
    for ip, d in sorted_devs
]
print(table(
    ['Source IP', 'High', 'Med', 'Total', 'Max Score', 'Top Destination'],
    dev_data,
    ['<', '>', '>', '>', '>', '<']
))
print()

# ── 5. Top beacons ───────────────────────────────────────────────────────────
top = sorted([r for r in rows if score(r) >= threshold], key=score, reverse=True)
print(f'TOP BEACONS  (score \u2265 {threshold:.2f},  {len(top)} findings across {len({r[COL["Source IP"]].strip() for r in top})} IPs)')
if top:
    ip_groups = defaultdict(list)
    for r in top:
        ip_groups[r[COL['Source IP']].strip()].append(r)
    sorted_ips = sorted(ip_groups, key=lambda ip: -max(score(r) for r in ip_groups[ip]))

    tdata = []
    total_rows = 0
    for i, ip in enumerate(sorted_ips):
        if total_rows >= 30:
            break
        if i > 0:
            tdata.append(None)
        first = True
        for r in sorted(ip_groups[ip], key=score, reverse=True):
            if total_rows >= 30:
                break
            tdata.append([
                ip_label(ip) if first else '',
                trunc(dest(r), 42),
                f'{score(r):.3f}',
                conns(r),
                svc(r),
            ])
            first = False
            total_rows += 1
    print(table(
        ['Source IP', 'Destination', 'Score', 'Conn', 'Service'],
        tdata,
        ['<', '<', '>', '>', '<']
    ))
else:
    print(f'  No findings with score \u2265 {threshold:.2f}')
print()

# ── 6. Alerts (threat intel / strobes) ───────────────────────────────────────
threat  = ti_rows  # pre-benign-filter capture — see comment above the filter
strobes = [r for r in rows if r[COL['Strobe']].strip().lower()        == 'true']

print('ALERTS')
if not threat and not strobes:
    print('  No threat intel hits or strobes detected.')
else:
    if threat:
        print(f'  \u26a0  THREAT INTEL  ({len(threat)} hits)')
        for r in threat:
            print(f'     {ip_label(r[COL["Source IP"]].strip()):<30}  \u2192  {trunc(dest(r), 50)}')
    if strobes:
        print(f'  \u26a0  STROBES  ({len(strobes)})')
        for r in strobes:
            print(f'     {ip_label(r[COL["Source IP"]].strip()):<30}  \u2192  {trunc(dest(r), 50)}  ({conns(r)} conns)')
print()

# ── 7. Investigate ───────────────────────────────────────────────────────────
grouped = {}
for r in rows:
    ft, msg = flag_row(r)
    if not ft:
        continue
    ip  = r[COL['Source IP']].strip()
    key = (ip, ft)
    if key not in grouped:
        grouped[key] = {'best': r, 'msgs': [msg], 'dests': [dest(r)]}
    else:
        g = grouped[key]
        if score(r) > score(g['best']):
            g['best'] = r
        if msg not in g['msgs']:
            g['msgs'].append(msg)
        d = dest(r)
        if d not in g['dests']:
            g['dests'].append(d)

inv_rows = []
for (ip, ft), g in sorted(grouped.items(), key=lambda x: -score(x[1]['best'])):
    s = score(g['best'])

    dests_list = g['dests'][:3]
    if len(g['dests']) > 3:
        dests_list = g['dests'][:2] + [f'+{len(g["dests"]) - 2} more']
    dest_str = ', '.join(dests_list)

    if ft == 'chinese':
        vendors = sorted(set(g['msgs']))
        total_c = sum(conns(r) for r in rows
                      if r[COL['Source IP']].strip() == ip and is_chinese(dest(r)))
        flag_str = ' + '.join(vendors) + f' telemetry ({total_c} conns)'
    elif ft == 'dns':
        flag_str = g['msgs'][0] if len(g['msgs']) == 1 else \
                   f"Excessive DNS: {sum(conns(r) for r in rows if r[COL['Source IP']].strip() == ip and '53:udp:dns' in svc(r).lower())} total queries"
    else:
        flag_str = g['msgs'][0]

    inv_rows.append([ip_label(ip), trunc(dest_str, 40), f'{s:.3f}', trunc(flag_str, 48)])

print(f'INVESTIGATE  ({len(inv_rows)} item{"s" if len(inv_rows) != 1 else ""})')
if inv_rows:
    print(table(
        ['Source IP', 'Destination', 'Score', 'Flag'],
        inv_rows,
        ['<', '<', '>', '<']
    ))
else:
    print('  Nothing flagged as suspicious.')

# ── Asset info for investigated IPs ──────────────────────────────────────────
if inv_rows and assets:
    seen_ips = set()
    inv_ips  = []
    for r in inv_rows:
        if r[0] not in seen_ips:
            inv_ips.append(r[0])
            seen_ips.add(r[0])
    asset_data = []
    for ip in inv_ips:
        a = assets.get(ip, {})
        hostname   = a.get('hostname', '') or '\u2013'
        os_str     = a.get('os', '')
        if os_str:
            os_str = re.sub(r'Linux \d+\.\d+ - \d+\.\d+', lambda m: m.group(0).split(' - ')[0], os_str)
            os_str = trunc(os_str, 30)
        else:
            os_str = '\u2013'
        mac_vendor = a.get('mac_vendor', '') or '\u2013'
        ports_list = a.get('open_ports', [])
        ports_str  = ', '.join(ports_list[:4]) or '\u2013'
        if len(ports_list) > 4:
            ports_str += f' +{len(ports_list) - 4}'
        asset_data.append([ip, trunc(hostname, 26), os_str, mac_vendor, trunc(ports_str, 30)])

    if asset_data:
        print()
        if asset_age_min is not None:
            hrs, mins = divmod(asset_age_min, 60)
            age_str = (f'{hrs}h {mins}m' if hrs else f'{mins}m') + ' ago'
            print(f'  Asset cache: {age_str}  (run: sudo beaconbutty-assets.sh to refresh)')
        else:
            print('  Asset cache: not found  (run: sudo beaconbutty-assets.sh)')
        print()
        print(table(
            ['Source IP', 'Hostname', 'OS', 'MAC Vendor', 'Open Ports'],
            asset_data,
            ['<', '<', '<', '<', '<']
        ))
elif inv_rows:
    print()
    print('  No asset cache — run: sudo beaconbutty-assets.sh')
print()

# ── Alerts ───────────────────────────────────────────────────────────────────
if send_alerts:
    import subprocess, shutil
    alert_bin = shutil.which('beaconbutty-alert.sh')
    if alert_bin:
        def _alert(atype, severity, device, detail):
            subprocess.run([alert_bin, atype, severity, device, detail],
                           capture_output=True)

        # Pre-compute the lan-talkers map once for the gate decisions.
        lan_talkers_map = get_lan_talkers_map()

        # FQDN-keyed rows (dst "::") can never hit the IP-keyed talkers map,
        # so count LAN talkers per FQDN from the report itself for those.
        fqdn_talkers = defaultdict(set)
        for _r in rows:
            _fq = _r[COL['FQDN']].strip()
            if _fq:
                fqdn_talkers[_fq].add(_r[COL['Source IP']].strip())

        def gate(dst_ip, dst_port, fqdn=''):
            """Return (fire, reason). reason in {'hyperscaler','shared_lan',
            'talkers_unknown',''}.

            RITA represents FQDN-keyed beacons with Destination IP = "::",
            which gives no useful ASN. When the IP is unusable, fall back
            to a suffix match on the FQDN — `docs.live.net` is Microsoft
            even when the report doesn't tell us which IP was actually hit."""
            org = asn_org_for(dst_ip) if dst_ip and dst_ip != '::' else ''
            if is_hyperscaler(org) or is_hyperscaler_fqdn(fqdn):
                return False, 'hyperscaler'
            if lan_talkers_map is None:
                return False, 'talkers_unknown'
            if dst_ip and dst_ip != '::':
                if lan_talkers_map.get((dst_ip, int(dst_port)), 1) > 1:
                    return False, 'shared_lan'
            elif len(fqdn_talkers.get(fqdn, ())) > 1:
                return False, 'shared_lan'
            return True, ''

        fired = {'high_score_beacon': 0, 'persistent_beacon': 0,
                 'threat_intel_hit':  0, 'tor_contact':       0}
        gated = {'high_score_beacon': {'hyperscaler': 0, 'shared_lan': 0,
                                       'talkers_unknown': 0},
                 'persistent_beacon': {'hyperscaler': 0, 'shared_lan': 0,
                                       'talkers_unknown': 0}}

        # high_score_beacon — RITA score 1.0; gated by lonely + non-hyperscaler.
        # Score 1.0 alone catches a lot of long-running CDN flows; the gate
        # keeps the alert meaningful.
        for r in rows:
            s = score(r)
            if s >= 1.0:
                src = r[COL['Source IP']].strip()
                dst_ip = r[COL['Destination IP']].strip()
                fqdn   = r[COL['FQDN']].strip()
                dst    = dest(r)
                fire, reason = gate(dst_ip, port_from(r), fqdn)
                if fire:
                    # No live numbers in alert details \u2014 Lambda dedup keys on
                    # (type, device, detail) and a varying score/count makes
                    # the same logical finding page again and again.
                    _alert('high_score_beacon', 'high', src,
                           f"Score-1.0 beacon \u2192 {dst[:80]}")
                    fired['high_score_beacon'] += 1
                else:
                    gated['high_score_beacon'][reason] += 1

        # persistent_beacon — strobes; same gate, same reasoning.
        for r in strobes:
            src = r[COL['Source IP']].strip()
            dst_ip = r[COL['Destination IP']].strip()
            fqdn   = r[COL['FQDN']].strip()
            dst    = dest(r)
            fire, reason = gate(dst_ip, port_from(r), fqdn)
            if fire:
                _alert('persistent_beacon', 'high', src,
                       f"Strobe \u2192 {dst[:80]}")
                fired['persistent_beacon'] += 1
            else:
                gated['persistent_beacon'][reason] += 1

        # threat_intel_hit — exact JA4 / known-bad match. No gate: a hit
        # here is high-confidence on its own.
        for r in threat:
            src = r[COL['Source IP']].strip()
            dst = dest(r)
            _alert('threat_intel_hit', 'high', src,
                   f"Threat intel hit \u2192 {dst[:80]}")
            fired['threat_intel_hit'] += 1

        # tor_contact — Tor egress from a LAN device. No gate. Detail names
        # the destination, not the flag message (whose conn/MB counts change
        # run to run and defeat Lambda dedup).
        for (ip, ft), g in grouped.items():
            if ft == 'tor':
                _alert('tor_contact', 'high', ip,
                       f"Tor exit contact → {g['dests'][0][:80]}")
                fired['tor_contact'] += 1

        write_gate_stats('daily_summary', fired, gated)

# ── Footer: daily operations ──────────────────────────────────────────────────
print('\u2500' * 56)
print('  Health:     beaconbutty-health.sh')
print('  Morning:    sudo beaconbutty-morning.sh')
print('  Assets:     sudo beaconbutty-assets.sh')
print('  False +ve:  beaconbutty-fp.sh list')
print('              beaconbutty-fp.sh add <ip|mac> "<reason up to 50 chars>"')
print('              beaconbutty-fp.sh remove <ip|mac>')
print()
PYEOF
