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

python3 - "$REPORT_FILE" "$THRESHOLD" <<'PYEOF'
import csv, json, re, sys, os, ipaddress
from collections import defaultdict
from datetime import datetime

report_file = sys.argv[1]
threshold   = float(sys.argv[2])

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

# ── Load false positives ──────────────────────────────────────────────────────
FP_FILE = '/var/lib/beaconbutty/false-positives.conf'
try:
    with open(FP_FILE) as f:
        false_positives = json.load(f)
except Exception:
    false_positives = {}

if not rows:
    print("No findings in report.")
    sys.exit(0)

# Count suppressed findings per FP IP, then remove them from all analysis
fp_suppressed = defaultdict(int)
for r in rows:
    if r[COL['Source IP']].strip() in false_positives:
        fp_suppressed[r[COL['Source IP']].strip()] += 1
rows = [r for r in rows if r[COL['Source IP']].strip() not in false_positives]

# ── Field accessors ───────────────────────────────────────────────────────────
def dest(row):
    fqdn = row[COL['FQDN']].strip()
    ip   = row[COL['Destination IP']].strip()
    return fqdn if fqdn else ip

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
    (r'microsoft', 'Microsoft'),
    (r'office365|sharepoint|onedrive', 'Microsoft 365'),
    (r'trouter|asyncgw|flightproxy|teams\.', 'Microsoft Teams'),
    (r'\.apple\.com$|icloud\.com|tether\.edge\.apple|\.apple$|smoot\.apple', 'Apple'),
    (r'ubuntu\.com', 'Ubuntu'),
    (r'mozilla\.(com|org|net)', 'Mozilla'),
    (r'google(apis)?\.com|googleapis\.com|\.goog$|safebrowsing', 'Google'),
    (r'^1\.1\.1\.1$|one\.one\.one\.one', 'Cloudflare DNS'),
    (r'^8\.8\.[48]\.8$|dns\.google', 'Google DNS'),
    (r'nest\.com', 'Google Nest'),
    (r'amazonalexa\.com', 'Amazon Alexa'),
    (r'amazon\.co\.uk|thumbnails-photos\.amazon', 'Amazon'),
    (r'garmin\.com', 'Garmin'),
    (r'fing\.(io|com)', 'Fing'),
    (r'svc\.ui\.com|ubnt\.com', 'Ubiquiti'),
    (r'newrelic\.com', 'New Relic'),
    (r'optimizely\.com', 'Optimizely'),
    (r'tailscale\.com', 'Tailscale'),
    (r'signal\.org', 'Signal'),
    (r'anthropic\.com', 'Anthropic'),
    (r'cloudfront|azureedge|fastly-edge', 'CDN'),
    (r'duckduckgo\.com', 'DuckDuckGo'),
    (r'monknow\.com', 'Monknow'),
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
if false_positives:
    total_sup = sum(fp_suppressed.values())
    print(f'FALSE POSITIVES  ({len(false_positives)} registered \u2014 {total_sup} findings suppressed)')
    fp_data = []
    for ip in sorted(false_positives, key=ip_sort):
        sup = fp_suppressed.get(ip, 0)
        fp_data.append([ip, trunc(false_positives[ip], 50), sup if sup else '\u2014'])
    print(table(
        ['Source IP', 'Reason', 'Suppressed'],
        fp_data,
        ['<', '<', '>']
    ))
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
    [ip, benign_map[ip]['label'], trunc(', '.join(benign_map[ip]['evidence']), 52)]
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

# ── 3. Severity breakdown ────────────────────────────────────────────────────
sev_counts = defaultdict(int)
for r in rows:
    sev_counts[r[COL['Severity']].strip()] += 1

print('SEVERITY BREAKDOWN')
sev_data = [(s, sev_counts[s]) for s in ('High', 'Medium', 'Low', 'None') if sev_counts[s]]
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
    if   sev == 'High':   d['H'] += 1
    elif sev == 'Medium': d['M'] += 1
    if s > d['max']:
        d['max'] = s
        d['top'] = dest(r)

sorted_devs = sorted(dev.items(), key=lambda x: (-x[1]['H'], -x[1]['max']))
dev_data = [
    [ip, d['H'], d['M'], d['total'], f"{d['max']:.3f}", trunc(d['top'], 36)]
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
                ip if first else '',
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
threat  = [r for r in rows if r[COL['Threat Intel']].strip().lower() == 'true']
strobes = [r for r in rows if r[COL['Strobe']].strip().lower()        == 'true']

print('ALERTS')
if not threat and not strobes:
    print('  No threat intel hits or strobes detected.')
else:
    if threat:
        print(f'  \u26a0  THREAT INTEL  ({len(threat)} hits)')
        for r in threat:
            print(f'     {r[COL["Source IP"]].strip():<16}  \u2192  {trunc(dest(r), 50)}')
    if strobes:
        print(f'  \u26a0  STROBES  ({len(strobes)})')
        for r in strobes:
            print(f'     {r[COL["Source IP"]].strip():<16}  \u2192  {trunc(dest(r), 50)}  ({conns(r)} conns)')
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

    inv_rows.append([ip, trunc(dest_str, 40), f'{s:.3f}', trunc(flag_str, 48)])

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

# ── Footer: daily operations ──────────────────────────────────────────────────
print('\u2500' * 56)
print('  Health:     beaconbutty-health.sh')
print('  Morning:    sudo beaconbutty-morning.sh')
print('  Assets:     sudo beaconbutty-assets.sh')
print('  False +ve:  beaconbutty-fp.sh list')
print('              beaconbutty-fp.sh add <ip> "<reason up to 50 chars>"')
print('              beaconbutty-fp.sh remove <ip>')
print()
PYEOF
