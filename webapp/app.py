#!/usr/bin/env python3
"""BeaconButty web UI — Flask app on port 8080."""

import csv
from collections import Counter
from datetime import datetime
import fnmatch
import gzip
import ipaddress
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import psutil
from datetime import datetime, date, timedelta
from glob import glob
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file

app = Flask(__name__)

# Simple TTL cache for the Suricata page (heavy I/O: eve.json + fast.log + Zeek gz)
_suricata_cache: dict = {"ts": 0.0, "payload": None}
_SURICATA_CACHE_TTL = 900  # seconds (15 min)

# ── Site-local overrides ───────────────────────────────────────────────────────
def _load_local_env(path: str = "/etc/beaconbutty/local.env") -> None:
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

_load_local_env()
BB_HOST         = os.environ.get("BB_HOST", "beaconbutty.local")
BB_TLS_CERT_DIR = os.environ.get("BB_TLS_CERT_DIR", "/etc/letsencrypt/live")
TLS_FULLCHAIN   = f"{BB_TLS_CERT_DIR}/{BB_HOST}/fullchain.pem"
TLS_PRIVKEY     = f"{BB_TLS_CERT_DIR}/{BB_HOST}/privkey.pem"

# ── Paths ──────────────────────────────────────────────────────────────────────
WATCHDOG_DATA_DIR   = Path("/var/lib/beaconbutty/watchdog/data")
HEALTH_STATUS_FILE  = Path("/var/lib/beaconbutty/watchdog/health-status.json")
REPORTS_DIR         = Path("/var/lib/beaconbutty/reports")
BACKUP_DIR          = Path("/var/lib/beaconbutty/backups")
BACKUP_SCRIPT       = Path("/usr/local/bin/beaconbutty-backup.sh")
ARCHIVE_SCRIPT      = Path("/home/dm/BeaconButty/scripts/backup-archive.sh")
ASSETS_FILE         = Path("/var/lib/beaconbutty/assets.json")
FP_CONF             = Path("/var/lib/beaconbutty/false-positives.conf")
LEASES_FILE         = Path("/var/lib/misc/dnsmasq.leases")
EVE_JSON            = Path("/var/log/suricata/eve.json")
FAST_LOG            = Path("/var/log/suricata/fast.log")
ZEEK_LOG_DIR        = Path("/var/log/zeek")
FP_SCRIPT           = Path("/usr/local/bin/beaconbutty-fp.sh")
LOCAL_RULES         = Path("/var/lib/suricata/rules/local.rules")
ET_RULES            = Path("/var/lib/suricata/rules/suricata.rules")
DOMAIN_WATCH_CONFIG = Path("/var/lib/beaconbutty/domain-watch.json")
JA4_HISTORY_FILE    = Path("/var/lib/beaconbutty/device-ja4-history.json")
JA4DB_FILE          = Path("/var/lib/beaconbutty/ja4db.csv")
# A historical JA4 fingerprint stops contributing to the device's THREAT
# marker once `last_seen` is older than this many days. Today's live
# fingerprints are always counted regardless.
JA4_THREAT_FADE_DAYS = 14
PCAP_ROOT           = Path("/var/lib/beaconbutty/pcaps")
PCAP_SNAPSHOT_DIR   = PCAP_ROOT / "snapshots"

# ── Validation patterns ────────────────────────────────────────────────────────
_MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$')
_IP_RE  = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

# ── Beacon CSV columns ─────────────────────────────────────────────────────────
BEACON_COLS = [
    "Severity", "Source IP", "Destination IP", "FQDN", "Beacon Score",
    "Strobe", "Total Duration", "Long Connection Score", "Subdomains",
    "C2 Over DNS Score", "Threat Intel", "Prevalence", "First Seen",
    "Missing Host Header", "Connection Count", "Total Bytes",
    "Port:Proto:Service", "Modifiers",
]
COL = {name: i for i, name in enumerate(BEACON_COLS)}

# ── GeoIP ─────────────────────────────────────────────────────────────────────

_GEOIP_ASN  = None
_GEOIP_CITY = None
try:
    import geoip2.database as _geoip2_db
    _GEOIP_ASN  = _geoip2_db.Reader('/var/lib/GeoIP/GeoLite2-ASN.mmdb')
    _GEOIP_CITY = _geoip2_db.Reader('/var/lib/GeoIP/GeoLite2-City.mmdb')
except Exception:
    pass


def _geoip_info(ip):
    """Return (country_code, city, asn_org) for an IP — any field may be None."""
    cc = city = org = None
    try:
        if _GEOIP_CITY:
            r = _GEOIP_CITY.city(ip)
            cc   = r.country.iso_code or None
            city = r.city.name or None
    except Exception:
        pass
    try:
        if _GEOIP_ASN:
            r = _GEOIP_ASN.asn(ip)
            org = r.autonomous_system_organization or None
    except Exception:
        pass
    return cc, city, org


_SAFE_ORGS = {
    "Apple Inc.",
    "Microsoft Corporation",
    "Google LLC",
    "NetActuate, Inc",
    "Cloudflare, Inc.",
}

_SAFE_DOMAIN_SUFFIXES = (
    # Microsoft
    "microsoft.com", "windows.com", "windowsupdate.com", "live.com",
    "office.com", "microsoftonline.com", "azure.com", "bing.com",
    "msn.com", "msftconnecttest.com", "msecnd.net",
    # Google
    "google.com", "googleapis.com", "gstatic.com",
    "googleusercontent.com", "googlevideo.com", "youtube.com",
    # Apple
    "apple.com", "icloud.com", "mzstatic.com", "aaplimg.com", "apple",
    # Cloudflare DNS
    "one.one.one.one", "cloudflare.com", "cloudflare-dns.com", "cloudflareinsights.com",
    "google-analytics.com", "samsungelectronics.com",
    # Google DNS (dns.google TLD)
    "dns.google",
    # Signal
    "signal.org",
    # Fing network scanner
    "fing.io", "fing.com",
    # Microsoft SharePoint
    "sharepoint.com",
    # Netflix
    "netflix.com",
    # Monknow (browser extension)
    "monknow.com",
    # Amazon
    "amazon.com", "amazonaws.com", "amazonvideo.com",
    # Microsoft App Center / short links
    "appcenter.ms", "aka.ms", "outlook.com", "microsoftpersonalcontent.com", "azureedge.net",
)

def _is_safe_org(ip):
    """Return True if the IP belongs to a known safe org."""
    try:
        if _GEOIP_ASN:
            org = _GEOIP_ASN.asn(ip).autonomous_system_organization
            return org in _SAFE_ORGS
    except Exception:
        pass
    return False

def _is_safe_dest(dst, fqdn):
    """Return True if destination is known-safe (Apple/Microsoft/Google/Cloudflare)."""
    # Check FQDN against known domain suffixes
    name = (fqdn or "").lower().strip()
    if name and any(name == s or name.endswith("." + s) for s in _SAFE_DOMAIN_SUFFIXES):
        return True
    # Check bare IP against ASN
    ip = (dst or "").strip()
    if _IP_RE.match(ip) and _is_safe_org(ip):
        return True
    return False


def _annotate_dest(dest):
    """Append geo/org info if dest is a bare IP address."""
    if dest and _IP_RE.match(dest.strip()):
        cc, city, org = _geoip_info(dest.strip())
        parts = []
        if org:
            parts.append(org)
        if city:
            parts.append(city)
        if cc:
            parts.append(cc)
        if parts:
            return f"{dest} ({', '.join(parts)})"
    return dest


# ── Beacon intelligence patterns ───────────────────────────────────────────────

_CHINESE_TECH = [
    (re.compile(r'baidu\.com',     re.I), 'Baidu'),
    (re.compile(r'tuisong\.',      re.I), 'Baidu Push'),
    (re.compile(r'snssdk\.com',    re.I), 'TikTok/ByteDance'),
    (re.compile(r'aweme\.',        re.I), 'TikTok/ByteDance'),
    (re.compile(r'bytedance\.com', re.I), 'ByteDance'),
    (re.compile(r'toutiao\.com',   re.I), 'ByteDance/Toutiao'),
    (re.compile(r'qq\.com',        re.I), 'Tencent'),
    (re.compile(r'wechat\.com',    re.I), 'WeChat'),
    (re.compile(r'alibaba\.com',   re.I), 'Alibaba'),
    (re.compile(r'aliyun\.com',    re.I), 'Alibaba Cloud'),
]

_TOR_NETS = [ipaddress.ip_network(c) for c in [
    '162.247.241.0/24', '162.247.72.0/24', '199.87.154.0/24',
    '176.10.104.0/24',  '185.220.101.0/24',
]]

_BENIGN_NETS = [(ipaddress.ip_network(c), lbl) for c, lbl in [
    ('17.0.0.0/8',  'Apple'),
    ('20.0.0.0/8',  'Microsoft Azure'),
    ('40.0.0.0/8',  'Microsoft Azure'),
    ('52.0.0.0/8',  'AWS/Microsoft'),
    ('54.0.0.0/8',  'AWS'),
    ('35.0.0.0/8',  'Google Cloud'),
    ('34.0.0.0/8',  'Google Cloud'),
]]


def _is_chinese(dest):
    for pat, vendor in _CHINESE_TECH:
        if pat.search(dest):
            return vendor
    return None


def _is_tor(ip):
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _TOR_NETS)
    except ValueError:
        return False


def _is_benign_net(ip):
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
        for net, label in _BENIGN_NETS:
            if addr in net:
                return label
    except ValueError:
        pass
    return None


def _parse_hours(s):
    s = (s or "").strip().lower()
    m = re.match(r'(\d+)\s+hours?\s+ago', s)
    if m:
        return float(m.group(1))
    m = re.match(r'(\d+)\s+minutes?\s+ago', s)
    if m:
        return float(m.group(1)) / 60
    return None


def _flag_row(row):
    """Return (flag_type, message) or (None, None) if not suspicious."""
    fqdn       = row[COL["FQDN"]]
    dst_ip     = row[COL["Destination IP"]]
    dest       = fqdn if fqdn else dst_ip
    first_seen = row[COL["First Seen"]] if len(row) > COL["First Seen"] else ""
    svc_str    = row[COL["Port:Proto:Service"]].lower() if len(row) > COL["Port:Proto:Service"] else ""

    try:
        score = float(row[COL["Beacon Score"]])
    except (ValueError, IndexError):
        score = 0.0
    try:
        conns = int(row[COL["Connection Count"]])
    except (ValueError, IndexError):
        conns = 0

    if _is_tor(dst_ip):
        try:
            mb = int(row[COL["Total Bytes"]]) / 1e6
        except (ValueError, IndexError):
            mb = 0.0
        return "tor", f"Tor Project IP ({conns} conns, {mb:.1f} MB)"

    cn = _is_chinese(dest)
    if cn:
        return "chinese", cn

    if "icmp" in svc_str and score >= 0.90:
        hrs = _parse_hours(first_seen)
        if hrs and conns > 0:
            interval = hrs * 60 / conns
            return "icmp", f"ICMP beacon: {conns} pings, ~1 every {interval:.1f} min"
        return "icmp", f"ICMP beacon: {conns} pings"

    if "53:udp:dns" in svc_str and conns >= 200 and score >= 0.90:
        hrs = _parse_hours(first_seen)
        if hrs and hrs > 0:
            rate = conns / hrs
            return "dns", f"Excessive DNS: {conns} queries, ~{rate:.0f}/hr \u2192 {dest}"
        return "dns", f"Excessive DNS: {conns} queries \u2192 {dest}"

    if score >= 0.97 and not fqdn and not _is_benign_net(dst_ip):
        return "unknown", f"Score {score:.3f} beacon to unnamed IP (no FQDN)"

    return None, None


# ── Helpers ────────────────────────────────────────────────────────────────────

def load_leases():
    """Return (mac_to_ip, ip_to_host) dicts parsed from dnsmasq.leases."""
    mac_to_ip  = {}
    ip_to_host = {}
    try:
        with open(LEASES_FILE) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 4:
                    continue
                # format: timestamp mac ip hostname clientid
                mac, ip, host = parts[1], parts[2], parts[3]
                mac = mac.lower()
                mac_to_ip[mac]  = ip
                if host and host != "*":
                    ip_to_host[ip] = host
    except FileNotFoundError:
        pass
    return mac_to_ip, ip_to_host


_DEVICE_NAMES_FILE  = Path("/var/lib/beaconbutty/device-names.json")
_device_names_cache = {"data": {}, "mtime": 0}

_IP_INTEL_FILE  = Path("/var/lib/beaconbutty/ip-intel-cache.json")
_ip_intel_cache = {"data": {}, "mtime": 0}


def load_ip_intel():
    """External threat-intel cache (Shodan InternetDB + AbuseIPDB) keyed by
    public IPv4. Refreshed daily by beaconbutty-ip-intel.service — this side
    is read-only. Reloaded on mtime change so the timer's writes go live
    without webapp restart."""
    try:
        st = _IP_INTEL_FILE.stat()
    except FileNotFoundError:
        if _ip_intel_cache["mtime"]:
            _ip_intel_cache["data"]  = {}
            _ip_intel_cache["mtime"] = 0
        return _ip_intel_cache["data"]
    if st.st_mtime != _ip_intel_cache["mtime"]:
        try:
            data = json.loads(_IP_INTEL_FILE.read_text())
            if not isinstance(data, dict):
                data = {}
        except (json.JSONDecodeError, OSError):
            data = {}
        _ip_intel_cache["data"]  = data
        _ip_intel_cache["mtime"] = st.st_mtime
    return _ip_intel_cache["data"]


def ip_intel(ip):
    """Return the threat-intel record for an IP, or {} if not cached."""
    return load_ip_intel().get(ip, {})


def load_device_names():
    """Manual `{ip: friendly_name}` overrides. Takes precedence over dnsmasq
    leases and assets.json in `ip_label()`. File is hand-edited (or edited via
    any future webapp endpoint) and reloaded on mtime change — no restart
    needed after editing."""
    try:
        st = _DEVICE_NAMES_FILE.stat()
    except FileNotFoundError:
        if _device_names_cache["mtime"]:
            _device_names_cache["data"]  = {}
            _device_names_cache["mtime"] = 0
        return _device_names_cache["data"]
    if st.st_mtime != _device_names_cache["mtime"]:
        try:
            data = json.loads(_DEVICE_NAMES_FILE.read_text())
            if not isinstance(data, dict):
                data = {}
        except (json.JSONDecodeError, OSError):
            data = {}
        _device_names_cache["data"]  = data
        _device_names_cache["mtime"] = st.st_mtime
    return _device_names_cache["data"]


def ip_label(ip, ip_to_host, assets=None):
    """Return 'ip (name)' or just 'ip'. Precedence:
       1. /var/lib/beaconbutty/device-names.json manual override
       2. dnsmasq DHCP hostname
       3. assets.json hostname / mac_vendor"""
    manual = load_device_names().get(ip)
    if manual:
        return f"{ip} ({manual})"
    host = ip_to_host.get(ip)
    if host:
        return f"{ip} ({host})"
    if assets:
        a = assets.get(ip, {})
        h = a.get("hostname") or a.get("mac_vendor")
        if h:
            return f"{ip} ({h})"
    return ip


def load_fp_all():
    """Return full FP config: {version, devices, domains, protocols, orgs}.

    `orgs` is fnmatch-against-GeoIP-ASN — the only handle the slow detector
    has on a destination with no SNI/Host/DNS."""
    try:
        with open(FP_CONF) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"version": 2, "devices": {}, "domains": {}, "protocols": {}, "orgs": {}}
    if "version" not in data:
        # v1 — flat MAC dict
        return {"version": 2, "devices": {k.lower(): v for k, v in data.items()},
                "domains": {}, "protocols": {}, "orgs": {}}
    return {
        "version":   data.get("version", 2),
        "devices":   {k.lower(): v for k, v in data.get("devices", {}).items()},
        "domains":   data.get("domains", {}),
        "protocols": data.get("protocols", {}),
        "orgs":      data.get("orgs", {}),
    }

def load_fps():
    """Return {mac: reason} — devices only. Backward-compat shim."""
    return load_fp_all()["devices"]


def _fp_domain_match(q, patterns):
    """True if q matches any FP domain pattern. A pattern like "*.foo.com"
    also matches the bare apex "foo.com" (fnmatch otherwise requires the dot)."""
    if not q or not patterns:
        return False
    for pat in patterns:
        if fnmatch.fnmatch(q, pat):
            return True
        if pat.startswith("*.") and q == pat[2:]:
            return True
    return False


def _fp_service_match(svc, fp_protocols):
    """Match a RITA service field against registered protocol FPs.

    RITA can bundle several services into one field, e.g.
    "80:tcp:http,3478:udp:". Protocol FPs are registered per single
    component ("3478:udp"), so each comma-separated component is tested
    independently — a whole-string prefix match misses STUN whenever it is
    not the first service listed. Returns (pattern, reason) on the first
    hit, else (None, None)."""
    for comp in (svc or "").strip().split(","):
        comp = comp.strip()
        if not comp:
            continue
        for pat, reason in fp_protocols.items():
            if comp == pat or comp.startswith(pat + ":"):
                return pat, reason
    return None, None


def get_wan_ip():
    """Parse WAN IP from 'ip addr show eth0'."""
    try:
        out = subprocess.run(
            ["ip", "addr", "show", "eth0"],
            capture_output=True, text=True, timeout=5
        ).stdout
        m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', out)
        return m.group(1) if m else "unknown"
    except Exception:
        return "unknown"


def get_system_stats():
    """Return system stats dict using /proc and /sys directly."""
    stats = {}

    # Temperature
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            stats["temp_c"] = round(int(f.read().strip()) / 1000, 1)
    except Exception:
        stats["temp_c"] = None

    # Pi active cooler (PWM fan) — firmware-controlled; cur_state > 0 means spinning
    try:
        with open("/sys/class/thermal/cooling_device0/cur_state") as f:
            stats["pi_fan_on"] = int(f.read().strip()) > 0
    except Exception:
        stats["pi_fan_on"] = None

    # Pironman case fan — bb-watchdog writes "on"/"off" to this file
    try:
        with open("/var/lib/beaconbutty/watchdog/fan-state") as f:
            stats["pironman_fan_on"] = f.read().strip().lower() == "on"
    except Exception:
        stats["pironman_fan_on"] = None

    # Manual-override flag (set by /api/pironman-fan; bb-watchdog honours it)
    stats["pironman_fan_manual"] = False
    try:
        ov = json.loads(Path("/var/lib/beaconbutty/watchdog/fan-override.json").read_text())
        if datetime.fromisoformat(ov["expires"]) > datetime.now():
            stats["pironman_fan_manual"] = True
    except Exception:
        pass

    # CPU — psutil with 0.5s interval for accurate reading
    stats["cpu_pct"] = psutil.cpu_percent(interval=0.5)

    # Memory
    mem = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":")
                mem[k.strip()] = int(v.split()[0])  # kB
        total_kb = mem.get("MemTotal", 1)
        avail_kb = mem.get("MemAvailable", 0)
        used_kb  = total_kb - avail_kb
        stats["mem_total_mb"] = round(total_kb / 1024, 0)
        stats["mem_used_mb"]  = round(used_kb  / 1024, 0)
        stats["mem_pct"]      = round(used_kb / total_kb * 100, 1) if total_kb else 0
    except Exception:
        stats["mem_total_mb"] = stats["mem_used_mb"] = stats["mem_pct"] = None

    # Disk (root fs)
    try:
        st = os.statvfs("/")
        total_b = st.f_frsize * st.f_blocks
        free_b  = st.f_frsize * st.f_bavail
        used_b  = total_b - free_b
        stats["disk_pct"]     = round(used_b  / total_b * 100, 1) if total_b else 0
        stats["disk_free_gb"] = round(free_b / 1024**3, 2)
    except Exception:
        stats["disk_pct"] = stats["disk_free_gb"] = None

    # log2ram (tmpfs mounted on /var/log) — sync to NVMe happens daily at 23:55
    try:
        st = os.statvfs("/var/log")
        total_b = st.f_frsize * st.f_blocks
        free_b  = st.f_frsize * st.f_bavail
        used_b  = total_b - free_b
        stats["log2ram_total_mb"] = round(total_b / 1024**2, 0)
        stats["log2ram_used_mb"]  = round(used_b  / 1024**2, 0)
        stats["log2ram_pct"]      = round(used_b / total_b * 100, 1) if total_b else 0
    except Exception:
        stats["log2ram_total_mb"] = stats["log2ram_used_mb"] = stats["log2ram_pct"] = None

    # Uptime
    try:
        with open("/proc/uptime") as f:
            secs = float(f.read().split()[0])
        d, rem = divmod(int(secs), 86400)
        h, rem = divmod(rem, 3600)
        m = rem // 60
        if d:
            stats["uptime"] = f"{d}d {h}h {m}m"
        elif h:
            stats["uptime"] = f"{h}h {m}m"
        else:
            stats["uptime"] = f"{m}m"
    except Exception:
        stats["uptime"] = "?"

    return stats


def parse_beacon_report(path):
    """
    Parse a beacon report file.
    Returns (COL, rows_by_date) where rows_by_date is
    {date_str: [row_list, ...]} — row_list is indexed by COL.
    """
    rows_by_date = {}
    current_date = None
    try:
        with open(path) as f:
            for line in f:
                line = line.rstrip()
                # Section header: ┌─ YYYY-MM-DD
                m = re.match(r'[┌│└─\s]*(\d{4}-\d{2}-\d{2})', line)
                if m and "─" in line or line.lstrip().startswith("┌"):
                    m2 = re.search(r'(\d{4}-\d{2}-\d{2})', line)
                    if m2:
                        current_date = m2.group(1)
                        rows_by_date.setdefault(current_date, [])
                    continue
                # CSV data rows start with Severity value
                if current_date and line and line.split(",")[0].strip() in (
                    "High", "Medium", "Low", "None", "Critical"
                ):
                    parts = [p.strip() for p in next(csv.reader([line]))]
                    # Pad/truncate to expected column count
                    while len(parts) < len(BEACON_COLS):
                        parts.append("")
                    # RITA emits some FQDNs in DNS root-anchored form
                    # ("foo.com."); normalise so FP patterns, safe-list
                    # suffix checks and (src,dst,fqdn) dedup all match.
                    parts[COL["FQDN"]] = parts[COL["FQDN"]].rstrip(".")
                    rows_by_date[current_date].append(parts)
    except FileNotFoundError:
        pass
    return COL, rows_by_date


def get_beacon_data(report_file, mac_to_ip, ip_to_host, assets=None):
    """
    Parse all beacon data from report_file (aggregates all dates in the file).
    top_beacons is limited to the most recent 3 dates in the file.
    Returns dict with: sev_counts, total, suppressed, fp_count, date_range,
    devices, top_beacons, investigate.
    """
    _, rows_by_date = parse_beacon_report(report_file)
    dates = sorted(rows_by_date.keys())
    recent_sorted = sorted(dates[-3:])
    recent_dates = set(recent_sorted)
    date_range = f"{dates[0]} to {dates[-1]}" if len(dates) > 1 else (dates[0] if dates else "")
    top_beacons_range = f"{recent_sorted[0]} to {recent_sorted[-1]}" if len(recent_sorted) > 1 else (recent_sorted[0] if recent_sorted else "")

    # Build suppression maps from FPs
    fp_all = load_fp_all()
    fp_ip_reason = {}
    for mac, reason in fp_all["devices"].items():
        ip = mac_to_ip.get(mac)
        if ip:
            fp_ip_reason[ip] = reason
    fp_domains   = fp_all["domains"]    # pattern → reason
    fp_protocols = fp_all["protocols"]  # svc → reason

    def _fp_domain_hit(fqdn, dst, enrich_name=""):
        # FQDN if RITA had one, the literal dst as fallback, AND the
        # Zeek-recovered enrichment name when present. Without the third
        # target, an FP like "*.knock.app" never suppresses the bare AWS
        # IPs that map to it (RITA only joins same-day DNS).
        targets = [t for t in
                   (fqdn.strip(), dst.strip(), (enrich_name or "").strip())
                   if t]
        for pat, reason in fp_domains.items():
            for target in targets:
                if fnmatch.fnmatch(target, pat):
                    return pat, reason
                if pat.startswith("*.") and target == pat[2:]:
                    return pat, reason
        return None, None

    def _fp_proto_hit(svc):
        return _fp_service_match(svc, fp_protocols)

    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
    suppressed = 0
    suppressed_groups_map = {}  # (rule_type, rule) → {rule_type, rule, reason, rows}
    devices_map = {}  # ip → {label, high, med, total, max_score, top_dests}
    top_beacons_map = {}  # (src, fqdn-or-dst) → entry; dedups a beacon seen on multiple days
    inv_grouped  = {}  # (src, flag_type) → {score, msgs, dests, rows}

    # Pre-pass: collect every (src, dst) pair that's a bare IP and not
    # already FP'd by source MAC. The Zeek-recovered FQDN for each pair
    # then participates in the FP-domain check below so an FP like
    # "*.knock.app" can suppress the bare AWS IPs that map to it.
    prelim_pairs = set()
    for date_rows in rows_by_date.values():
        for row in date_rows:
            src_p  = row[COL["Source IP"]].strip()
            dst_p  = row[COL["Destination IP"]].strip()
            fqdn_p = row[COL["FQDN"]].strip()
            if (not _IP_RE.match(src_p) or src_p in fp_ip_reason
                    or fqdn_p or not _IP_RE.match(dst_p)):
                continue
            prelim_pairs.add((src_p, dst_p))
    emap = enrich_ips_batch(prelim_pairs, days=14) if prelim_pairs else {}

    def _record_suppression(rule_type, rule, reason, src_label, dest_str, score_f, svc_str, sev_str):
        key = (rule_type, rule)
        g = suppressed_groups_map.setdefault(key, {
            "rule_type": rule_type, "rule": rule, "reason": reason, "rows": []
        })
        g["rows"].append({
            "label": src_label, "dest": dest_str, "score": score_f,
            "svc": svc_str, "severity": sev_str,
        })

    # Each report file bundles the last 3 RITA daily databases, so a beacon
    # that persists appears once per day. Collapse to one row per distinct
    # (src, dst, fqdn) before aggregating — highest score wins, the most
    # recent day breaks ties — so every count below reflects distinct
    # beacons rather than beacon-days.
    deduped = {}  # (src, dst, fqdn) → [row, is_recent, score]
    for date_str in sorted(rows_by_date):  # oldest first → later day wins ties
        date_recent = date_str in recent_dates
        for row in rows_by_date[date_str]:
            key = (row[COL["Source IP"]].strip(),
                   row[COL["Destination IP"]].strip(),
                   row[COL["FQDN"]].strip())
            try:
                sc = float(row[COL["Beacon Score"]])
            except (ValueError, IndexError):
                sc = 0.0
            prev = deduped.get(key)
            if prev is None:
                deduped[key] = [row, date_recent, sc]
            else:
                if sc >= prev[2]:
                    prev[0] = row
                prev[1] = prev[1] or date_recent
                prev[2] = max(prev[2], sc)

    for row, is_recent, _row_score in deduped.values():
        sev = row[COL["Severity"]]
        src = row[COL["Source IP"]]
        dst = row[COL["Destination IP"]]
        fqdn = row[COL["FQDN"]]
        svc  = row[COL["Port:Proto:Service"]] if len(row) > COL["Port:Proto:Service"] else ""
        dest = _annotate_dest(fqdn if fqdn else dst)

        # Skip non-IPv4 source IPs
        if not _IP_RE.match(src.strip()):
            continue

        # Skip beacons to Apple, Microsoft, Google, Cloudflare
        if _is_safe_dest(dst, fqdn):
            continue

        try:
            row_score = float(row[COL["Beacon Score"]])
        except (ValueError, IndexError):
            row_score = 0.0
        row_label = ip_label(src, ip_to_host, assets)

        # Suppress FP IPs
        if src in fp_ip_reason:
            suppressed += 1
            _record_suppression("device", row_label, fp_ip_reason[src],
                                row_label, dest, row_score, svc, sev)
            continue

        # Suppress FP domains and protocols (enrichment-aware so an FP like
        # "*.knock.app" suppresses bare AWS IPs whose Zeek-recovered FQDN
        # matches).
        e_name = (emap.get((src.strip(), dst.strip())) or {}).get("name", "")
        dom_pat, dom_reason = _fp_domain_hit(fqdn, dst, e_name)
        if dom_pat:
            suppressed += 1
            _record_suppression("domain", dom_pat, dom_reason,
                                row_label, dest, row_score, svc, sev)
            continue
        proto_pat, proto_reason = _fp_proto_hit(svc)
        if proto_pat:
            suppressed += 1
            _record_suppression("protocol", proto_pat, proto_reason,
                                row_label, dest, row_score, svc, sev)
            continue

        score = row_score

        # Skip rows with no beacon score — these are long-connection or other
        # RITA detections, not actual beacons, and would show as score 0.000
        if score == 0.0:
            continue

        sev_counts[sev] = sev_counts.get(sev, 0) + 1

        try:
            conns = int(row[COL["Connection Count"]])
        except (ValueError, IndexError):
            conns = 0

        label = row_label

        if src not in devices_map:
            devices_map[src] = {
                "ip": src,
                "label": label,
                "high": 0,
                "med": 0,
                "low": 0,
                "total": 0,
                "max_score": 0.0,
                "top_dests": [],   # list of (score, dest), top 3 by score
                "high_beacons": [], # High severity rows
                "med_beacons":  [], # Medium severity rows
                "low_beacons":  [], # Low severity rows
                "all_beacons":  [], # every surviving row (every severity)
            }
        d = devices_map[src]
        d["total"] += 1
        # GeoIP ASN org gives the cheapest "who owns this destination"
        # answer — used to pre-fill the FP reason field when the user
        # clicks the destination IP.
        _, _, _dst_org = _geoip_info(dst.strip())
        beacon_entry = {"dest": dest, "score": score, "conns": conns, "svc": svc,
                        "fqdn": fqdn.strip(), "raw_dst": dst.strip(), "severity": sev,
                        "dst_org": _dst_org or ""}
        d["all_beacons"].append(beacon_entry)
        # RITA emits "Critical" above High — fold it into the High rollup so
        # those rows appear in the hotlist counts and drill-downs.
        if sev in ("Critical", "High"):
            d["high"] += 1
            d["high_beacons"].append(beacon_entry)
        elif sev == "Medium":
            d["med"] += 1
            d["med_beacons"].append(beacon_entry)
        elif sev == "Low":
            d["low"] += 1
            d["low_beacons"].append(beacon_entry)
        if score > d["max_score"]:
            d["max_score"] = score
        # Maintain top-3 destinations by score (deduped by dest)
        existing = {td[1]: i for i, td in enumerate(d["top_dests"])}
        if dest in existing:
            idx = existing[dest]
            if score > d["top_dests"][idx][0]:
                d["top_dests"][idx] = (score, dest)
        else:
            d["top_dests"].append((score, dest))
        d["top_dests"].sort(key=lambda x: -x[0])
        d["top_dests"] = d["top_dests"][:3]

        if score >= 0.80 and is_recent:
            # Each daily section of the report yields its own row, so the same
            # beacon seen across multiple days would appear multiple times.
            # Keep one entry per (src, destination), preferring the highest
            # score and — on ties — the most recent day (dates iterate oldest
            # first, so >= lets the later day win).
            tb_key = (src, fqdn.strip() or dst.strip())
            existing = top_beacons_map.get(tb_key)
            if existing is None or score >= existing["score"]:
                top_beacons_map[tb_key] = {
                    "ip":       src,
                    "label":    label,
                    "dest":     dest,
                    "raw_dst":  dst.strip(),
                    "fqdn":     fqdn.strip(),
                    "score":    score,
                    "conns":    conns,
                    "svc":      svc,
                    "severity": sev,
                }

        # Investigate flagging
        ft, msg = _flag_row(row)
        if ft:
            key = (src, ft)
            if key not in inv_grouped:
                inv_grouped[key] = {"score": score, "msgs": [msg], "dests": [dest], "rows": [row]}
            else:
                g = inv_grouped[key]
                if score > g["score"]:
                    g["score"] = score
                if msg not in g["msgs"]:
                    g["msgs"].append(msg)
                if dest not in g["dests"]:
                    g["dests"].append(dest)
                g["rows"].append(row)

    top_beacons = list(top_beacons_map.values())

    # Attach the enrichment data (already computed up-front in `emap` so
    # the FP-domain check could see it) onto every visible beacon entry.
    def _attach_enrich(entry, src_ip):
        rd = (entry.get("raw_dst") or "").strip()
        e = emap.get((src_ip, rd)) if rd else None
        entry["enrich_name"]      = (e or {}).get("name", "")
        entry["enrich_source"]    = (e or {}).get("source", "")
        entry["enrich_when_days"] = (e or {}).get("when_days")
        entry["intel"]            = (e or {}).get("intel") or ip_intel(rd)
    for d in devices_map.values():
        for b in d["all_beacons"]:
            _attach_enrich(b, d["ip"])
        # high/med/low_beacons are references to the same dicts — no rework needed
    for tb in top_beacons:
        _attach_enrich(tb, tb["ip"])

    for d in devices_map.values():
        d["high_beacons"].sort(key=lambda x: -x["score"])
        d["med_beacons"].sort(key=lambda x: -x["score"])
        d["low_beacons"].sort(key=lambda x: -x["score"])
        d["all_beacons"].sort(key=lambda x: -x["score"])

    devices = sorted(
        devices_map.values(),
        key=lambda x: -x["max_score"]
    )
    top_beacons.sort(key=lambda x: -x["score"])

    # Pre-pass: enrich every bare-IP dst across all investigate groups in
    # one batch so the per-row template can show "→ api.knock.app" beneath
    # bare IPs. The bandwidth helper deduplicates dsts internally.
    inv_dst_pairs = set()
    for (src, _ft), g in inv_grouped.items():
        for r in g["rows"]:
            d = r[COL["Destination IP"]].strip()
            if d and _IP_RE.match(d):
                inv_dst_pairs.add((src, d))
    inv_emap = enrich_ips_batch(inv_dst_pairs, days=14) if inv_dst_pairs else {}

    # Build investigate list
    investigate = []
    for (src, ft), g in sorted(inv_grouped.items(), key=lambda x: -x[1]["score"]):
        lbl = ip_label(src, ip_to_host, assets)
        dests_list = g["dests"][:3]
        if len(g["dests"]) > 3:
            dests_list = g["dests"][:2] + [f'+{len(g["dests"]) - 2} more']
        # Enriched dest rows: raw label + optional Zeek-recovered FQDN.
        # Walk the original full dests list so each bare IP gets its own
        # enrichment line (the join-into-one-string was display-only).
        dest_entries = []
        for d_label in dests_list:
            entry = {"raw": d_label, "enrich": "", "source": ""}
            # d_label might be the FQDN (no enrichment needed) or a bare IP
            # (enrichment lookup). Match against the rows for this group.
            if _IP_RE.match(d_label):
                e = inv_emap.get((src, d_label)) or {}
                if e.get("name"):
                    entry["enrich"] = e["name"]
                    entry["source"] = e["source"]
            dest_entries.append(entry)

        if ft == "chinese":
            vendors = sorted(set(g["msgs"]))
            cn_conns = 0
            for r in g["rows"]:
                d = r[COL["FQDN"]] or r[COL["Destination IP"]]
                if _is_chinese(d):
                    try:
                        cn_conns += int(r[COL["Connection Count"]])
                    except (ValueError, IndexError):
                        pass
            flag_str = " + ".join(vendors) + f" telemetry ({cn_conns} conns)"
        elif ft == "dns" and len(g["msgs"]) > 1:
            dns_conns = 0
            for r in g["rows"]:
                svc_str = r[COL["Port:Proto:Service"]].lower() if len(r) > COL["Port:Proto:Service"] else ""
                if "53:udp:dns" in svc_str:
                    try:
                        dns_conns += int(r[COL["Connection Count"]])
                    except (ValueError, IndexError):
                        pass
            flag_str = f"Excessive DNS: {dns_conns} total queries"
        else:
            flag_str = g["msgs"][0]

        # JA4 enrichment: most-common TLS client fingerprint observed from this
        # source across the destination IPs in this investigate group, looked
        # up against today + yesterday's ssl.log.
        dst_ips = {r[COL["Destination IP"]].strip() for r in g["rows"]}
        dst_ips.discard("")
        ja4_hash, ja4_count = _ja4_modal_for_src_and_dsts(src, dst_ips, lookback_days=2)
        ja4_label, ja4_src, ja4_threat = classify_ja4(ja4_hash)

        investigate.append({
            "label":        lbl,
            "ip":           src,
            "dest":         ", ".join(dests_list),
            "dest_entries": dest_entries,
            "score":        g["score"],
            "flag_type":    ft,
            "flag_str":     flag_str,
            "ja4":          ja4_hash,
            "ja4_count":    ja4_count,
            "ja4_label":    ja4_label,
            "ja4_src":      ja4_src,
            "ja4_threat":   ja4_threat,
        })

    total = sum(sev_counts.values())
    fp_count = (len(fp_all["devices"]) + len(fp_all["domains"])
                + len(fp_all["protocols"]) + len(fp_all["orgs"]))

    # Build suppressed groups, sort rows within each by score desc, groups by row count desc
    suppressed_groups = []
    for g in suppressed_groups_map.values():
        g["rows"].sort(key=lambda r: -r["score"])
        suppressed_groups.append(g)
    suppressed_groups.sort(key=lambda g: -len(g["rows"]))

    return {
        "sev_counts":  sev_counts,
        "total":       total,
        "suppressed":  suppressed,
        "fp_count":    fp_count,
        "date_range":        date_range,
        "top_beacons_range": top_beacons_range,
        "devices":           devices,
        "top_beacons":       top_beacons,
        "investigate":       investigate,
        "suppressed_groups": suppressed_groups,
    }


def list_report_dates():
    """Return list of (latest_date_str, filepath) — one entry per report file, newest first."""
    results = []
    for path in sorted(REPORTS_DIR.glob("beacon-report-*.txt"), reverse=True):
        _, rows_by_date = parse_beacon_report(path)
        if rows_by_date:
            latest_date = max(rows_by_date.keys())
            results.append((latest_date, str(path)))
    return results


def _parse_fast_log_line(line):
    """
    Parse one Suricata fast.log line.
    Returns dict or None.
    Format: [x2] MM/DD/YYYY-HH:MM:SS.uuuuuu  [**] [sid] RULE [**]
            [Classification: X] [Priority: N] {PROTO} src:sport -> dst:dport
    """
    line = line.strip()
    # Strip optional [xN] prefix
    line = re.sub(r'^\[\s*x\d+\]\s*', '', line)

    m = re.match(
        r'(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)'   # timestamp
        r'\s+\[\*\*\]\s+\[([^\]]+)\]\s+'                  # [sid]
        r'(.+?)\s+\[\*\*\]'                                # rule name
        r'(?:\s+\[Classification:\s*([^\]]*)\])?'          # classification
        r'\s+\[Priority:\s*(\d+)\]'                        # priority
        r'\s+\{(\w+)\}'                                    # proto
        r'\s+(\S+)\s+->\s+(\S+)',                          # src -> dst
        line
    )
    if not m:
        return None

    ts_str, sid, rule, classification, priority, proto, src_full, dst_full = m.groups()

    def split_addr(s):
        # handle IPv6 [addr]:port or addr:port
        mp = re.match(r'\[([^\]]+)\]:(\d+)$', s)
        if mp:
            return mp.group(1), int(mp.group(2))
        parts = s.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0], int(parts[1])
        return s, None

    src_ip, src_port = split_addr(src_full)
    dst_ip, dst_port = split_addr(dst_full)

    try:
        ts = datetime.strptime(ts_str, "%m/%d/%Y-%H:%M:%S.%f")
    except ValueError:
        ts = None

    return {
        "ts":             ts,
        "ts_str":         ts_str,
        "sid":            sid,
        "rule":           rule.strip(),
        "classification": (classification or "").strip(),
        "priority":       int(priority),
        "proto":          proto,
        "src_ip":         src_ip,
        "src_port":       src_port,
        "dst_ip":         dst_ip,
        "dst_port":       dst_port,
    }


LAN_NET = re.compile(r'^192\.168\.50\.\d+$')


def _is_lan(ip):
    return bool(LAN_NET.match(ip or ""))


def parse_fast_log(days=1):
    """
    Parse Suricata fast.log entries from the last `days` days (including today).
    Reads the current fast.log plus rotated .gz files (fast.log.1.gz etc.).
    Returns list of parsed alert dicts, newest entries last.
    """
    cutoff = (date.today() - timedelta(days=days - 1))
    alerts = []

    # Collect files to read: current log + rotated gz files, oldest first
    # Rotated archives land in /var/lib/suricata/archive/ via logrotate lastaction
    archive_dir = Path("/var/lib/suricata/archive")
    log_files = []
    i = days  # only look back as many rotated files as we need
    while i >= 1:
        gz = archive_dir / f"{FAST_LOG.name}.{i}.gz"
        if gz.exists():
            log_files.append(gz)
        i -= 1
    log_files.append(FAST_LOG)  # current file last (chronological order)

    for path in log_files:
        try:
            opener = gzip.open if str(path).endswith(".gz") else open
            with opener(path, "rt", errors="replace") as f:
                for line in f:
                    parsed = _parse_fast_log_line(line)
                    if parsed and parsed["ts"] and parsed["ts"].date() >= cutoff:
                        alerts.append(parsed)
        except (FileNotFoundError, OSError):
            pass
    return alerts


def parse_fast_log_today():
    """Parse today's Suricata fast.log entries. Thin wrapper around parse_fast_log."""
    today = date.today()
    return [a for a in parse_fast_log(days=1) if a["ts"].date() == today]


# Infrastructure-noise rules: Suricata's own stream-reassembly and QUIC-decrypt
# complaints. Firing volume is dictated by traffic shape, not threats; they
# drown out anything meaningful. Suppressed across every UI surface on the
# Suricata page (tile, Top Signatures, trend, hourly timeline, categories).
_INFRA_NOISE_PREFIXES = ("SURICATA STREAM", "SURICATA QUIC")


def _is_infra_noise(rule):
    return rule.startswith(_INFRA_NOISE_PREFIXES) if rule else False


def filter_infra_noise(alerts):
    return [a for a in alerts if not _is_infra_noise(a.get("rule", ""))]


def build_suricata_data(ip_to_host, alerts=None):
    """
    Build suricata page data from fast.log.
    Returns: sig_list, lan_rows, unresolved, total_alerts
    Pass pre-parsed today's alerts to avoid re-reading the file.
    """
    if alerts is None:
        alerts = parse_fast_log_today()

    # Drop SURICATA STREAM/QUIC infrastructure noise (see _is_infra_noise).
    alerts = filter_infra_noise(alerts)

    # FP filtering — drop alerts whose LAN side is an FP'd device so both the
    # signature summary and the LAN rows match what the user expects to see.
    fp_all = load_fp_all()
    mac_to_ip, _ = load_leases()
    fp_ips = _fp_device_ips(fp_all["devices"], mac_to_ip)
    alerts = [a for a in alerts if a["src_ip"] not in fp_ips and a["dst_ip"] not in fp_ips]
    total_alerts = len(alerts)

    # Signature summary
    sig_map = {}  # rule → {count, priority, srcs, last_ts}
    for a in alerts:
        r = a["rule"]
        if r not in sig_map:
            sig_map[r] = {"count": 0, "priority": a["priority"],
                          "srcs": set(), "last_ts": None}
        sig_map[r]["count"] += 1
        sig_map[r]["srcs"].add(a["src_ip"])
        if sig_map[r]["last_ts"] is None or (a["ts"] and a["ts"] > sig_map[r]["last_ts"]):
            sig_map[r]["last_ts"] = a["ts"]

    sig_list = sorted(
        [{"rule": r, "count": v["count"], "priority": v["priority"],
          "unique_srcs": len(v["srcs"]),
          "last_seen": v["last_ts"].strftime("%H:%M:%S") if v["last_ts"] else ""}
         for r, v in sig_map.items()],
        key=lambda x: (x["priority"], -x["count"])
    )

    # Zeek conn.log trace — find external IPs from alerts, look for LAN originator
    ext_ips = set()
    for a in alerts:
        if not _is_lan(a["src_ip"]) and a["src_ip"] not in ("", "unknown"):
            ext_ips.add(a["src_ip"])
        if not _is_lan(a["dst_ip"]) and a["dst_ip"] not in ("", "unknown"):
            ext_ips.add(a["dst_ip"])

    # Map ext_ip → set of LAN IPs from Zeek
    ext_to_lan = {}
    today_str = date.today().strftime("%Y-%m-%d")
    zeek_day_dir = ZEEK_LOG_DIR / today_str
    try:
        zeek_accessible = zeek_day_dir.is_dir()
    except PermissionError:
        zeek_accessible = False
    if zeek_accessible and ext_ips:
        for gz_path in sorted(zeek_day_dir.glob("conn.*.log.gz")):
            try:
                with gzip.open(gz_path, "rt") as f:
                    for line in f:
                        if line.startswith("#"):
                            continue
                        parts = line.split("\t")
                        if len(parts) < 6:
                            continue
                        orig_h = parts[2]
                        resp_h = parts[4]
                        # Check if conn involves an ext_ip
                        if orig_h in ext_ips and _is_lan(resp_h):
                            ext_to_lan.setdefault(orig_h, set()).add(resp_h)
                        elif resp_h in ext_ips and _is_lan(orig_h):
                            ext_to_lan.setdefault(resp_h, set()).add(orig_h)
            except Exception:
                continue

    # Build LAN → alerts list
    lan_alerts = {}   # lan_ip → [{ext_ip, rule, priority}]
    unresolved = []

    for a in alerts:
        src_lan = _is_lan(a["src_ip"])
        dst_lan = _is_lan(a["dst_ip"])

        if src_lan:
            lan_ip = a["src_ip"]
            ext_ip = a["dst_ip"]
        elif dst_lan:
            lan_ip = a["dst_ip"]
            ext_ip = a["src_ip"]
        else:
            # Neither side is LAN — check Zeek trace
            ext_candidates = []
            for ip in (a["src_ip"], a["dst_ip"]):
                if ip in ext_to_lan:
                    for lan_ip in ext_to_lan[ip]:
                        ext_candidates.append((lan_ip, ip))
            if ext_candidates:
                for lan_ip, ext_ip in ext_candidates:
                    if lan_ip in fp_ips:
                        continue
                    lan_alerts.setdefault(lan_ip, []).append({
                        "ext_ip":   ext_ip,
                        "rule":     a["rule"],
                        "priority": a["priority"],
                    })
            else:
                unresolved.append({
                    "src_ip":  a["src_ip"],
                    "dst_ip":  a["dst_ip"],
                    "rule":    a["rule"],
                    "priority": a["priority"],
                })
            continue

        lan_alerts.setdefault(lan_ip, []).append({
            "ext_ip":   ext_ip,
            "rule":     a["rule"],
            "priority": a["priority"],
        })

    lan_rows = []
    for lan_ip in sorted(lan_alerts.keys()):
        # Deduplicate alerts by (ext_ip, rule), keeping count
        deduped = {}
        for a in lan_alerts[lan_ip]:
            key = (a["ext_ip"], a["rule"])
            if key not in deduped:
                deduped[key] = {"ext_ip": a["ext_ip"], "rule": a["rule"],
                                "priority": a["priority"], "count": 0}
            deduped[key]["count"] += 1
        lan_rows.append({
            "lan_ip":    lan_ip,
            "lan_label": ip_label(lan_ip, ip_to_host),
            "alerts":    sorted(deduped.values(), key=lambda x: (x["priority"], -x["count"])),
        })

    # Enrich every (lan_ip, ext_ip) pair across all surfaces in one batch so
    # the operator can see "→ api.knock.app" beneath bare AWS IPs that
    # Suricata flagged. Same shape as /beacons and /network.
    suri_pairs = set()
    for row in lan_rows:
        for a in row["alerts"]:
            ext = (a.get("ext_ip") or "").strip()
            if ext and _IP_RE.match(ext):
                suri_pairs.add((row["lan_ip"], ext))
    for u in unresolved:
        for side in ("src_ip", "dst_ip"):
            ip = (u.get(side) or "").strip()
            if ip and _IP_RE.match(ip) and not _is_lan(ip):
                # Pair with the LAN-side IP if known, else a sentinel src
                # (enrichment is keyed on dst only so the src is just an
                # arbitrary tag for the lookup).
                other = u.get("dst_ip" if side == "src_ip" else "src_ip", "")
                suri_pairs.add((other or "0.0.0.0", ip))
    suri_emap = enrich_ips_batch(suri_pairs, days=14) if suri_pairs else {}
    for row in lan_rows:
        for a in row["alerts"]:
            ext = (a.get("ext_ip") or "").strip()
            e = suri_emap.get((row["lan_ip"], ext)) if ext else None
            a["ext_enrich"]  = (e or {}).get("name", "")
            a["ext_source"]  = (e or {}).get("source", "")
            a["ext_intel"]   = (e or {}).get("intel") or (ip_intel(ext) if ext else {})
    for u in unresolved:
        for side in ("src", "dst"):
            ip = (u.get(f"{side}_ip") or "").strip()
            other = u.get(f"{'dst' if side == 'src' else 'src'}_ip", "")
            e = (suri_emap.get((other or "0.0.0.0", ip))
                 if ip and not _is_lan(ip) else None)
            u[f"{side}_enrich"] = (e or {}).get("name", "")
            u[f"{side}_source"] = (e or {}).get("source", "")
            u[f"{side}_intel"]  = (
                (e or {}).get("intel")
                or (ip_intel(ip) if ip and not _is_lan(ip) else {})
            )

    return sig_list, lan_rows, unresolved, total_alerts


def count_alerts_by_priority():
    """Count today's Suricata alerts by priority using fast.log.

    Applies the same FP-device suppression as build_suricata_data so the
    dashboard tile agrees with the /suricata page — an FP'd device tripping
    a rule must not show a count the page then can't explain."""
    alerts = filter_infra_noise(parse_fast_log_today())
    fp_all = load_fp_all()
    mac_to_ip, _ = load_leases()
    fp_ips = _fp_device_ips(fp_all["devices"], mac_to_ip)
    counts = {1: 0, 2: 0, 3: 0, 4: 0}
    for a in alerts:
        if a.get("src_ip") in fp_ips or a.get("dst_ip") in fp_ips:
            continue
        p = a.get("priority", 4)
        counts[p] = counts.get(p, 0) + 1
    return counts


def count_beacon_findings_today():
    """Count unique source IPs on the Device Hotlist. Must mirror get_beacon_data's
    filter set exactly: safe-dest, FP device/domain/protocol (incl. Zeek-recovered
    FQDN), and score==0 skip. Drift between this counter and get_beacon_data
    surfaces as the dashboard tile disagreeing with the Hotlist itself."""
    mac_to_ip, _ = load_leases()
    fp_all       = load_fp_all()
    fp_ips       = _fp_device_ips(fp_all["devices"], mac_to_ip)
    fp_domains   = fp_all["domains"]
    fp_protocols = fp_all["protocols"]

    def _fp_proto_hit(svc):
        return _fp_service_match(svc, fp_protocols)[0] is not None

    for path in sorted(REPORTS_DIR.glob("beacon-report-*.txt"), reverse=True):
        _, rows_by_date = parse_beacon_report(path)
        if not rows_by_date:
            continue
        # Pre-pass — same shape as get_beacon_data: enrich every bare-IP
        # candidate so the FP-domain check below can match against the
        # Zeek-recovered FQDN. Without this, an FP like "*.knock.app"
        # never suppresses the bare AWS IPs and the tile over-counts.
        prelim_pairs = set()
        for row in (r for date_rows in rows_by_date.values() for r in date_rows):
            src_p  = row[COL["Source IP"]].strip()
            dst_p  = row[COL["Destination IP"]].strip()
            fqdn_p = row[COL["FQDN"]].strip()
            if (not _IP_RE.match(src_p) or src_p in fp_ips
                    or fqdn_p or not _IP_RE.match(dst_p)):
                continue
            prelim_pairs.add((src_p, dst_p))
        emap = enrich_ips_batch(prelim_pairs, days=14) if prelim_pairs else {}

        ips = set()
        for row in (r for date_rows in rows_by_date.values() for r in date_rows):
            src  = row[COL["Source IP"]].strip()
            dst  = row[COL["Destination IP"]].strip()
            fqdn = row[COL["FQDN"]].strip()
            svc  = row[COL["Port:Proto:Service"]] if len(row) > COL["Port:Proto:Service"] else ""
            if not _IP_RE.match(src) or src in fp_ips:
                continue
            if _is_safe_dest(dst, fqdn):
                continue
            e_name = (emap.get((src, dst)) or {}).get("name", "")
            candidates = [t for t in (fqdn, dst, e_name) if t]
            if (any(_fp_domain_match(t, fp_domains) for t in candidates)
                    or _fp_proto_hit(svc)):
                continue
            try:
                score = float(row[COL["Beacon Score"]])
            except (ValueError, IndexError):
                score = 0.0
            if score == 0.0:
                continue
            ips.add(src)
        return len(ips)
    return 0


def load_health():
    """Load health-status.json, return dict or {}."""
    try:
        with open(HEALTH_STATUS_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


# ── Temperature data ────────────────────────────────────────────────────────────

def load_watchdog_day(day_str):
    """Load a single day's watchdog JSON file. Returns list of records."""
    path = WATCHDOG_DATA_DIR / f"{day_str}.json"
    try:
        with open(path) as f:
            data = json.load(f)
        # Format: {"date": "...", "records": [...]}
        return data.get("records", data) if isinstance(data, dict) else data
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def get_system_data(days=1):
    """
    Load system telemetry (temp + CPU + memory + fans) for the last N days.
    If days > 2: aggregate hourly, taking max of temp_c/cpu_pct/mem_pct per
    hour (fan flags OR'd per hour); top_cpu/top_mem come from the record at
    the hour's CPU/memory peak, so the tooltip explains the peak it shows.
    Returns list of {time, temp_c, cpu_pct, mem_pct, top_cpu, top_mem,
    rpi_fan, pironman_fan}.
    """
    records = []
    for i in range(days - 1, -1, -1):
        day = (date.today() - timedelta(days=i)).strftime("%Y-%m-%d")
        records.extend(load_watchdog_day(day))

    if not records:
        return []

    if days > 2:
        hourly = {}
        for rec in records:
            t = rec.get("time", "")
            hour_key = t[:13] + ":00" if len(t) >= 13 else t
            h = hourly.setdefault(hour_key, {
                "temps": [], "cpus": [], "mems": [],
                "rpi_fan": False, "pironman_fan": False,
            })
            temp = rec.get("temp_c")
            if temp is not None:
                h["temps"].append(temp)
            cpu = rec.get("cpu_pct")
            if cpu is not None:
                h["cpus"].append(cpu)
                if rec.get("top_cpu") and cpu >= h.get("_cpu_peak", -1):
                    h["_cpu_peak"] = cpu
                    h["top_cpu"] = rec["top_cpu"]
            mem = rec.get("mem_pct")
            if mem is not None:
                h["mems"].append(mem)
                if rec.get("top_mem") and mem >= h.get("_mem_peak", -1):
                    h["_mem_peak"] = mem
                    h["top_mem"] = rec["top_mem"]
            if rec.get("rpi_fan"):
                h["rpi_fan"] = True
            if rec.get("pironman_fan"):
                h["pironman_fan"] = True

        result = []
        for hour_key in sorted(hourly.keys()):
            h = hourly[hour_key]
            result.append({
                "time":         hour_key,
                "temp_c":       round(max(h["temps"]), 1) if h["temps"] else None,
                "cpu_pct":      round(max(h["cpus"]), 1) if h["cpus"] else None,
                "mem_pct":      round(max(h["mems"]), 1) if h["mems"] else None,
                "top_cpu":      h.get("top_cpu"),
                "top_mem":      h.get("top_mem"),
                "rpi_fan":      h["rpi_fan"],
                "pironman_fan": h["pironman_fan"],
            })
        return result
    else:
        return [
            {
                "time":         r.get("time", ""),
                "temp_c":       r.get("temp_c"),
                "cpu_pct":      r.get("cpu_pct"),
                "mem_pct":      r.get("mem_pct"),
                "top_cpu":      r.get("top_cpu"),
                "top_mem":      r.get("top_mem"),
                "rpi_fan":      bool(r.get("rpi_fan")),
                "pironman_fan": bool(r.get("pironman_fan")),
            }
            for r in records
        ]


# ── Bandwidth (RITA ClickHouse-backed) ────────────────────────────────────────
#
# Sources: the per-day databases RITA imports hourly, named
# `beaconbutty_YYYYMMDD`. Each has a `conn` table with src/dst IPv6 columns
# (IPv4 encoded as ::ffff:a.b.c.d), src_local/dst_local flags, and byte
# counters. We use src_ip_bytes/dst_ip_bytes (real IP-layer bytes observed
# on the wire), NOT src_bytes/dst_bytes — Zeek's payload estimator can
# inflate to ~20 GiB on a TCP-sequence-wrap artifact, producing phantom
# spikes for connections that only moved a few KB. We filter
# src_local=1 AND dst_local=0 to restrict to WAN-bound flows per LAN device.
#
# One clickhouse-client subprocess per section (summary / timeseries /
# talkers / destinations). UNION ALL across daily DBs for multi-day windows.

BW_CH_BIN = "/usr/bin/clickhouse-client"


def _bw_ch_dbs_for_window(days: int):
    """Return list of existing beaconbutty_YYYYMMDD DB names that could hold
    data inside the last `days` calendar days (today inclusive)."""
    available = set()
    try:
        out = subprocess.run(
            [BW_CH_BIN, "--query", "SHOW DATABASES"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0:
            available = {line.strip() for line in out.stdout.splitlines()
                         if line.strip().startswith("beaconbutty_")}
    except Exception:
        return []
    dbs = []
    for i in range(days):
        d = (date.today() - timedelta(days=i)).strftime("%Y%m%d")
        name = f"beaconbutty_{d}"
        if name in available:
            dbs.append(name)
    return sorted(dbs)  # oldest first — ORDER BY ts works across UNION ALL


def _bw_run(sql: str):
    """Run clickhouse-client with FORMAT JSONEachRow, return list of dicts.
    Returns [] on error (logged) — callers should handle empty results."""
    try:
        out = subprocess.run(
            [BW_CH_BIN, "--query", sql + " FORMAT JSONEachRow"],
            capture_output=True, text=True, timeout=15,
        )
    except subprocess.TimeoutExpired:
        app.logger.warning("bandwidth CH query timed out")
        return []
    if out.returncode != 0:
        app.logger.warning("bandwidth CH query failed: %s", out.stderr[:400])
        return []
    rows = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows


def _bw_strip_v4(ipv6_str):
    """Turn ::ffff:192.168.50.1 → 192.168.50.1. Leave real IPv6 untouched."""
    if ipv6_str and ipv6_str.startswith("::ffff:"):
        return ipv6_str[7:]
    return ipv6_str or ""


# ── IP enrichment (for "who is this AWS IP?" cases) ────────────────────────
# RITA's daily report only joins against the same-day dns_history table, so
# any beacon whose dst was last resolved on a prior day shows up as a bare
# IP. Zeek captures the answer in its dns log and the SNI in ssl.log; this
# helper pulls those across the recent window so the dashboard can show
# "3.146.81.149 → api.knock.app (DNS, 2d ago)".
#
# Lookups are keyed on dst only — the identity of an IP is the same
# regardless of which LAN device is talking to it. This catches the case
# where one device confirms an SNI for a STUN/derp/CDN IP that a different
# device only sees as an IP literal (Zeek's DNS lookup happened earlier
# on a different src). The narrow case where two LAN devices use the same
# shared CDN IP for genuinely different services is rare; if it bites, the
# operator can override with a per-IP FP.
#
# Priority: SNI > DNS history > TLS server cert Subject > HTTP host header.

_IP_ENRICH_CACHE: dict = {}     # dst → {'name', 'source', 'when_days', 'ts'}
_IP_ENRICH_TTL   = 600          # 10 min — IP→FQDN doesn't change often


def _x509_cn(subject: str) -> str:
    """Extract CN= from an X509 Subject DN; fall back to full string."""
    if not subject:
        return ""
    for part in subject.split(","):
        p = part.strip()
        if p.upper().startswith("CN="):
            return p[3:].strip()
    return subject


def enrich_ips_batch(pairs, days: int = 7) -> dict:
    """Identify dst IPs from Zeek logs across the last `days` daily DBs.

    `pairs` is a collection of (src_ip, dst_ip) tuples — the src component
    is preserved in the return key for caller convenience but not used in
    the lookup itself (see module comment). Returns
    `{(src, dst): {'name', 'source', 'when_days'}}` where `source` is one
    of "SNI", "DNS", "cert", "HTTP", "" (unknown), and `when_days` is
    approximate days since the most recent observation."""
    pairs = {p for p in pairs if p[0] and p[1]}
    if not pairs:
        return {}

    now = time.time()
    dst_set: set = set()
    by_dst: dict = {}        # dst → entry (resolved here or from cache)
    for src, dst in pairs:
        if dst in by_dst:
            continue
        c = _IP_ENRICH_CACHE.get(dst)
        if c and now - c["ts"] < _IP_ENRICH_TTL:
            by_dst[dst] = {k: c[k] for k in ("name", "source", "when_days")}
        else:
            dst_set.add(dst)

    if dst_set:
        dbs = _bw_ch_dbs_for_window(days)
        if not dbs:
            for d in dst_set:
                by_dst[d] = {"name": "", "source": "", "when_days": None}
        else:
            in_dst_v6  = ",".join(f"'::ffff:{d}'" for d in dst_set)
            in_dst_str = ",".join(f"'{d}'" for d in dst_set)
            best: dict = {d: None for d in dst_set}

            def _consider(dst, name, source, ts):
                if dst not in dst_set or not name:
                    return
                # IP-literal "names" aren't enrichment (some clients send
                # the IP as SNI; PTR-style queries can return numerics).
                if _IP_RE.match(name) or name == dst:
                    return
                if best.get(dst) is None:
                    best[dst] = {"name": name, "source": source, "ts": ts}

            # 1. TLS SNI from ssl.log — most authoritative.
            union = " UNION ALL ".join(
                f"""SELECT IPv6NumToString(dst) AS d, server_name AS name, ts
                    FROM {db}.ssl
                    WHERE server_name != ''
                      AND IPv6NumToString(dst) IN ({in_dst_v6})"""
                for db in dbs
            )
            sql = (f"SELECT d, argMax(name, ts) AS name, max(ts) AS ts_max "
                   f"FROM ({union}) GROUP BY d")
            for r in _bw_run(sql):
                _consider(_bw_strip_v4(r["d"]),
                          r.get("name", ""), "SNI", r.get("ts_max"))

            # 2. DNS history — any LAN-side query that resolved to dst.
            todo_left = {d for d in dst_set if best[d] is None}
            if todo_left:
                in_left = ",".join(f"'{d}'" for d in todo_left)
                union = " UNION ALL ".join(
                    f"""SELECT query AS name, ts, answers
                        FROM {db}.dns
                        WHERE length(answers) > 0
                          AND arrayExists(a -> a IN ({in_left}), answers)"""
                    for db in dbs
                )
                sql = (f"SELECT d, argMax(name, ts) AS name, max(ts) AS ts_max "
                       f"FROM (SELECT name, ts, arrayJoin(answers) AS d "
                       f"      FROM ({union})) "
                       f"WHERE d IN ({in_left}) GROUP BY d")
                for r in _bw_run(sql):
                    _consider(r["d"], r.get("name", ""), "DNS",
                              r.get("ts_max"))

            # 3. TLS server cert Subject (CN) — for SNI-less / ESNI flows.
            todo_left = {d for d in dst_set if best[d] is None}
            if todo_left:
                in_left_v6 = ",".join(f"'::ffff:{d}'" for d in todo_left)
                union = " UNION ALL ".join(
                    f"""SELECT IPv6NumToString(dst) AS d,
                               server_subject AS name, ts FROM {db}.ssl
                        WHERE server_subject != ''
                          AND IPv6NumToString(dst) IN ({in_left_v6})"""
                    for db in dbs
                )
                sql = (f"SELECT d, argMax(name, ts) AS name, max(ts) AS ts_max "
                       f"FROM ({union}) GROUP BY d")
                for r in _bw_run(sql):
                    _consider(_bw_strip_v4(r["d"]),
                              _x509_cn(r.get("name", "")), "cert",
                              r.get("ts_max"))

            # 4. HTTP Host header — for plain HTTP flows.
            todo_left = {d for d in dst_set if best[d] is None}
            if todo_left:
                in_left_v6 = ",".join(f"'::ffff:{d}'" for d in todo_left)
                union = " UNION ALL ".join(
                    f"""SELECT IPv6NumToString(dst) AS d, host AS name, ts
                        FROM {db}.http
                        WHERE host != ''
                          AND IPv6NumToString(dst) IN ({in_left_v6})"""
                    for db in dbs
                )
                sql = (f"SELECT d, argMax(name, ts) AS name, max(ts) AS ts_max "
                       f"FROM ({union}) GROUP BY d")
                for r in _bw_run(sql):
                    _consider(_bw_strip_v4(r["d"]),
                              r.get("name", ""), "HTTP", r.get("ts_max"))

            today_dt = date.today()
            for d in dst_set:
                b = best[d]
                if b:
                    try:
                        seen = datetime.strptime(b["ts"][:10],
                                                 "%Y-%m-%d").date()
                        when_days = (today_dt - seen).days
                    except Exception:
                        when_days = None
                    entry = {"name": b["name"], "source": b["source"],
                             "when_days": when_days}
                else:
                    entry = {"name": "", "source": "", "when_days": None}
                by_dst[d] = entry
                _IP_ENRICH_CACHE[d] = {**entry, "ts": now}

    # Evict expired entries occasionally — TTL is otherwise only checked on
    # read, so every external IP ever seen accumulates for the process
    # lifetime (the one unbounded structure in the app).
    if len(_IP_ENRICH_CACHE) > 5000:
        cutoff = now - _IP_ENRICH_TTL
        for k in [k for k, v in _IP_ENRICH_CACHE.items()
                  if v.get("ts", 0) < cutoff]:
            del _IP_ENRICH_CACHE[k]

    # Attach external threat-intel from the local cache (refreshed daily by
    # beaconbutty-ip-intel.service). Adds an `intel` sub-dict on each entry;
    # callers that don't care can ignore it.
    intel = load_ip_intel()
    for dst, entry in by_dst.items():
        e = intel.get(dst)
        if e:
            entry["intel"] = {
                "shodan":    e.get("shodan", {}),
                "abuseipdb": e.get("abuseipdb", {}),
                "spamhaus":  e.get("spamhaus", {}),
                "tor":       e.get("tor", {}),
                "ts":        e.get("ts"),
            }

    # Fan out the per-dst result to every (src, dst) pair the caller asked
    # for. This is also where we satisfy any cache hits collected up top.
    return {(src, dst): by_dst[dst] for src, dst in pairs if dst in by_dst}


def _bw_window_start(days: int):
    """UTC datetime at the start of the window (days full calendar days back)."""
    start = datetime.combine(date.today() - timedelta(days=days - 1), datetime.min.time())
    return start.strftime("%Y-%m-%d %H:%M:%S")


def _bw_union_from(dbs):
    """Build a `(SELECT ... FROM db1.conn UNION ALL ... FROM dbN.conn)` subquery
    body — caller wraps with outer SELECT. Only projects the fields we need."""
    parts = []
    for db in dbs:
        parts.append(
            f"SELECT ts, src, dst, src_ip_bytes, dst_ip_bytes, src_local, dst_local "
            f"FROM {db}.conn "
            f"WHERE src_local = 1 AND dst_local = 0"
        )
    return "(" + " UNION ALL ".join(parts) + ")"


def get_bandwidth_data(days=1, top_n=8, dest_limit=20):
    """Return {summary, timeseries, talkers, destinations} for the last N days."""
    days = max(1, min(days, 30))
    dbs = _bw_ch_dbs_for_window(days)
    empty = {
        "summary": {"total_bytes": 0, "up_bytes": 0, "down_bytes": 0,
                    "device_count": 0, "peak_hour": None, "peak_hour_bytes": 0,
                    "top_device_ip": None, "top_device_label": None,
                    "top_device_bytes": 0, "window_days": days},
        "timeseries": [],
        "series_order": [],
        "series_labels": {},   # keep the shape identical to the full payload
        "talkers": [],
        "destinations": [],
    }
    if not dbs:
        return empty
    union = _bw_union_from(dbs)
    window_start = _bw_window_start(days)
    where_ts = f"ts >= toDateTime('{window_start}')"

    # ── Asset label map (lazy load once per call) ────────────────────────
    _, ip_to_host = load_leases()
    try:
        with open(ASSETS_FILE) as f:
            assets = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        assets = {}
    def label(ip):
        return ip_label(ip, ip_to_host, assets)

    # ── Talkers (per LAN device totals) ──────────────────────────────────
    talker_rows = _bw_run(
        f"SELECT IPv6NumToString(src) AS src_ip, "
        f"sum(src_ip_bytes) AS up_bytes, sum(dst_ip_bytes) AS down_bytes, "
        f"sum(src_ip_bytes + dst_ip_bytes) AS total_bytes, count() AS flows, "
        f"uniqExact(dst) AS external_dests, "
        f"toUnixTimestamp(max(ts)) AS last_active "
        f"FROM {union} WHERE {where_ts} GROUP BY src ORDER BY total_bytes DESC"
    )
    talkers = []
    for r in talker_rows:
        ip = _bw_strip_v4(r.get("src_ip"))
        talkers.append({
            "ip":            ip,
            "label":         label(ip),
            "up_bytes":      int(r.get("up_bytes") or 0),
            "down_bytes":    int(r.get("down_bytes") or 0),
            "total_bytes":   int(r.get("total_bytes") or 0),
            "flows":         int(r.get("flows") or 0),
            "external_dests": int(r.get("external_dests") or 0),
            "last_active":   int(r.get("last_active") or 0),
        })

    total_all = sum(t["total_bytes"] for t in talkers)
    up_all    = sum(t["up_bytes"]    for t in talkers)
    down_all  = sum(t["down_bytes"]  for t in talkers)

    # ── Timeseries (per-hour, pivoted to top-N devices + Other) ──────────
    top_ips = [t["ip"] for t in talkers[:top_n]]
    ts_rows = _bw_run(
        f"SELECT toUnixTimestamp(toStartOfHour(ts)) AS hour, "
        f"IPv6NumToString(src) AS src_ip, "
        f"sum(src_ip_bytes + dst_ip_bytes) AS bytes "
        f"FROM {union} WHERE {where_ts} "
        f"GROUP BY hour, src ORDER BY hour ASC"
    )
    # Pivot into {hour_iso: {ip_or_other: bytes}}
    series_order = top_ips + (["__other__"] if len(talkers) > top_n else [])
    hour_map = {}
    for r in ts_rows:
        ip = _bw_strip_v4(r.get("src_ip"))
        hour = int(r.get("hour") or 0)
        bytes_ = int(r.get("bytes") or 0)
        bucket = ip if ip in top_ips else "__other__"
        row = hour_map.setdefault(hour, {k: 0 for k in series_order})
        row[bucket] = row.get(bucket, 0) + bytes_
    timeseries = []
    for hour in sorted(hour_map.keys()):
        rec = {"time": datetime.fromtimestamp(hour).isoformat(timespec="seconds")}
        rec.update(hour_map[hour])
        timeseries.append(rec)

    # Build label map for series (used by client legend)
    series_labels = {ip: label(ip) for ip in top_ips}
    if "__other__" in series_order:
        series_labels["__other__"] = f"Other ({len(talkers) - top_n})"

    # Peak hour (overall)
    peak_hour = peak_hour_bytes = None
    for rec in timeseries:
        h_total = sum(v for k, v in rec.items() if k != "time")
        if peak_hour is None or h_total > peak_hour_bytes:
            peak_hour = rec["time"]
            peak_hour_bytes = h_total

    # ── Top destinations (external IPs, with GeoIP org) ──────────────────
    dest_rows = _bw_run(
        f"SELECT IPv6NumToString(dst) AS dst_ip, "
        f"sum(src_ip_bytes + dst_ip_bytes) AS total_bytes, "
        f"count() AS flows, uniqExact(src) AS distinct_sources "
        f"FROM {union} WHERE {where_ts} "
        f"GROUP BY dst ORDER BY total_bytes DESC LIMIT {int(dest_limit)}"
    )
    destinations = []
    for r in dest_rows:
        ip = _bw_strip_v4(r.get("dst_ip"))
        cc, city, org = _geoip_info(ip)
        destinations.append({
            "ip":               ip,
            "org":              org,
            "country":          cc,
            "city":             city,
            "total_bytes":      int(r.get("total_bytes") or 0),
            "flows":            int(r.get("flows") or 0),
            "distinct_sources": int(r.get("distinct_sources") or 0),
        })

    top_device = talkers[0] if talkers else None

    return {
        "summary": {
            "total_bytes":      total_all,
            "up_bytes":         up_all,
            "down_bytes":       down_all,
            "device_count":     len(talkers),
            "peak_hour":        peak_hour,
            "peak_hour_bytes":  peak_hour_bytes or 0,
            "top_device_ip":    top_device["ip"]    if top_device else None,
            "top_device_label": top_device["label"] if top_device else None,
            "top_device_bytes": top_device["total_bytes"] if top_device else 0,
            "window_days":      days,
        },
        "timeseries":    timeseries,
        "series_order":  series_order,
        "series_labels": series_labels,
        "talkers":       talkers,
        "destinations":  destinations,
    }


def get_bandwidth_device_destinations(src_ip, days=1, direction="down", limit=10):
    """Top external destinations for a single LAN device, ordered by bytes
    in the requested direction (up = bytes the device sent; down = bytes it
    received). Returns [{ip, org, country, city, up_bytes, down_bytes,
    total_bytes, flows}, …]."""
    days = max(1, min(days, 30))
    direction = "up" if str(direction).lower() == "up" else "down"
    dbs = _bw_ch_dbs_for_window(days)
    if not dbs or not src_ip:
        return []
    union = _bw_union_from(dbs)
    window_start = _bw_window_start(days)
    order_col = "up_bytes" if direction == "up" else "down_bytes"
    # IPv6StringToNum encodes IPv4 as ::ffff:a.b.c.d to match the conn.src column.
    rows = _bw_run(
        f"SELECT IPv6NumToString(dst) AS dst_ip, "
        f"sum(src_ip_bytes) AS up_bytes, sum(dst_ip_bytes) AS down_bytes, "
        f"sum(src_ip_bytes + dst_ip_bytes) AS total_bytes, count() AS flows "
        f"FROM {union} "
        f"WHERE ts >= toDateTime('{window_start}') "
        f"AND src = toIPv6('::ffff:{src_ip}') "
        f"GROUP BY dst ORDER BY {order_col} DESC LIMIT {int(limit)}"
    )
    out = []
    for r in rows:
        ip = _bw_strip_v4(r.get("dst_ip"))
        cc, city, org = _geoip_info(ip)
        out.append({
            "ip":           ip,
            "org":          org,
            "country":      cc,
            "city":         city,
            "up_bytes":     int(r.get("up_bytes")    or 0),
            "down_bytes":   int(r.get("down_bytes")  or 0),
            "total_bytes":  int(r.get("total_bytes") or 0),
            "flows":        int(r.get("flows")       or 0),
        })
    return out


# ── Network intelligence (Zeek-based) ─────────────────────────────────────────

_NIGHT_HOURS        = frozenset(range(1, 6))   # 01:00–05:59 local time
_NXDOMAIN_MIN_Q     = 30                        # min queries before flagging rate
_NXDOMAIN_THRESHOLD = 0.25                      # 25 % NXDOMAIN rate
_ENTROPY_THRESHOLD  = 3.5                       # bits/char — DGA suspicion
_EXFIL_THRESHOLD_MB = 10.0                      # MB/day minimum for exfil table
_NETWORK_CACHE      = {"data": None, "ts": 0}
_NETWORK_CACHE_TTL  = 300                       # seconds
_NETWORK_BUILD_LOCK = threading.Lock()          # single-flight: one rebuild at a time
_NETWORK_REBUILD_REQUEST = threading.Event()    # set() wakes the warmer for an out-of-band rebuild (e.g. after an FP edit)


def _invalidate_network_cache():
    """Request a fresh network-intel rebuild without blocking the next reader.

    An FP edit changes what /network and the dashboard tile should show, but
    the rebuild scans ~17s of Zeek logs. Rather than null the cache (which
    forced the next dashboard load to pay that cost synchronously — a multi-
    second spinner), we wake the background warmer: it rebuilds off to the side
    and swaps the fresh, FP-filtered result in atomically. Readers keep getting
    the previous (one-edit-stale) data until then, so nothing ever blocks."""
    _NETWORK_REBUILD_REQUEST.set()


def _write_json_atomic(path, obj, **dump_kwargs):
    """tmp + os.replace so a crash mid-write never leaves a truncated file
    for the next reader to silently fall back to defaults on."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(obj, **dump_kwargs))
    tmp.replace(p)


_ASSETS_HISTORY_IPS_CACHE = {"mtime": 0.0, "mac_to_ips": {}}


def _history_mac_to_ips():
    """mac → {IPs seen in the last 14 days} from assets-history.json,
    mtime-cached. Lets FP suppression keep covering a device after it
    renumbers or goes offline (current dnsmasq leases alone lose it)."""
    try:
        mtime = ASSETS_HISTORY_FILE.stat().st_mtime
    except OSError:
        return {}
    if mtime != _ASSETS_HISTORY_IPS_CACHE["mtime"]:
        m2i: dict = {}
        try:
            with open(ASSETS_HISTORY_FILE) as f:
                for hist_ip, info in json.load(f).items():
                    mac = (info.get("mac") or "").lower()
                    if mac:
                        m2i.setdefault(mac, set()).add(hist_ip)
        except (OSError, json.JSONDecodeError):
            m2i = {}
        _ASSETS_HISTORY_IPS_CACHE["mtime"] = mtime
        _ASSETS_HISTORY_IPS_CACHE["mac_to_ips"] = m2i
    return _ASSETS_HISTORY_IPS_CACHE["mac_to_ips"]


def _fp_device_ips(fp_devices, mac_to_ip):
    """All IPs — current lease plus 14-day history — for FP'd device MACs.
    The single source for every fp_ips derivation (14 sites used to inline
    the lease-only set comprehension and drift independently)."""
    hist = _history_mac_to_ips()
    ips = set()
    for mac in fp_devices:
        mac = mac.lower()
        if mac in mac_to_ip:
            ips.add(mac_to_ip[mac])
        ips.update(hist.get(mac, ()))
    return ips


def _run_fp_script(*args):
    """Run fp.sh, surfacing failures instead of reporting success on a
    failed registry write. On success, bust every cache FP state feeds."""
    try:
        r = subprocess.run([str(FP_SCRIPT), *args],
                           capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        app.logger.error("fp.sh %s: timed out", " ".join(args))
        return False, "fp.sh timed out"
    if r.returncode != 0:
        lines = (r.stderr or r.stdout or "").strip().splitlines()
        msg = lines[-1] if lines else f"fp.sh exited {r.returncode}"
        app.logger.error("fp.sh %s failed rc=%s: %s",
                         " ".join(args), r.returncode, msg)
        return False, msg
    _invalidate_network_cache()
    _suricata_cache["ts"] = 0  # the /suricata page cache must not outlive an FP edit
    return True, ""


def _domain_entropy(query):
    """Shannon entropy of the registered domain label (SLD only).
    Uses only the second-level label so subdomains don't inflate entropy.
    Returns 0 for short or malformed strings."""
    if not query or query == "-":
        return 0.0
    parts = query.rstrip(".").lower().split(".")
    if len(parts) < 2:
        return 0.0
    # Use the second-level domain label only (e.g. "xn--abc123" from "sub.xn--abc123.com")
    s = parts[-2]
    if len(s) < 8:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _zeek_day_dirs(n_days=1):
    """Return list of existing Zeek daily log dirs for the last n_days days.

    For today (i=0), always also include `current/` if present — that holds the
    live tail that hasn't been rotated into today's dated dir yet. Without this,
    consumers run on stale data immediately after a Zeek restart (when rotated
    archives in the dated dir predate any new feature, e.g. JA4 fields).
    """
    dirs = []
    for i in range(n_days):
        p = ZEEK_LOG_DIR / (date.today() - timedelta(days=i)).strftime("%Y-%m-%d")
        if p.is_dir():
            dirs.append(p)
        if i == 0:
            cur = ZEEK_LOG_DIR / "current"
            if cur.is_dir() and cur not in dirs:
                dirs.append(cur)
    return dirs


def _read_zeek_logs(day_dirs, log_prefix):
    """Yield row dicts from rotated Zeek logs matching log_prefix in day_dirs."""
    for day_dir in day_dirs:
        for pattern in (f"{log_prefix}.*.log.gz", f"{log_prefix}.*.log", f"{log_prefix}.log"):
            for path in sorted(day_dir.glob(pattern)):
                try:
                    opener = gzip.open if str(path).endswith(".gz") else open
                    with opener(path, "rt", errors="replace") as f:
                        fields = None
                        for line in f:
                            line = line.rstrip("\n")
                            if line.startswith("#fields\t"):
                                fields = line.split("\t")[1:]
                            elif line.startswith("#") or not line:
                                continue
                            elif fields:
                                parts = line.split("\t")
                                if len(parts) >= len(fields):
                                    yield dict(zip(fields, parts))
                except Exception:
                    continue


# ── JA4 fingerprints ──────────────────────────────────────────────────────────
#
# The Foxio zeek/ja4 package extends ssl.log with `ja4` (TLS client hash) and
# `ja4s` (server response). Both pages — Beacon Investigate and Network Intel —
# read these via the helpers below; the index is rebuilt only when an ssl.log
# file mtime changes, so consecutive page loads are cheap.

_JA4_CACHE = {"key": None, "pair_idx": {}}  # (src,dst) -> Counter[ja4]


def _ja4_index(lookback_days=1):
    """Build/return the cached (src,dst)→Counter[ja4] index."""
    day_dirs = _zeek_day_dirs(lookback_days)
    paths = []
    for d in day_dirs:
        paths.extend(d.glob("ssl.*.log.gz"))
        paths.extend(d.glob("ssl.*.log"))
        p = d / "ssl.log"
        if p.exists():
            paths.append(p)
    try:
        key = tuple(sorted((str(p), p.stat().st_mtime, p.stat().st_size)
                           for p in paths))
    except OSError:
        key = None
    if _JA4_CACHE["key"] == key and key is not None:
        return _JA4_CACHE["pair_idx"]

    pair_idx = {}
    for row in _read_zeek_logs(day_dirs, "ssl"):
        ja4 = (row.get("ja4") or "").strip()
        if not ja4 or ja4 == "-":
            continue
        src = row.get("id.orig_h", "")
        dst = row.get("id.resp_h", "")
        if not src or not dst:
            continue
        pair_idx.setdefault((src, dst), Counter())[ja4] += 1

    _JA4_CACHE["key"] = key
    _JA4_CACHE["pair_idx"] = pair_idx
    return pair_idx


def _ja4_modal_for_src_and_dsts(src, dst_ips, lookback_days=1):
    """
    Return (modal_ja4_hash, total_count) for `src` across the given dst IPs.
    Picks the most-common JA4 across all (src, dst) pairs; ties broken by total
    observation count.
    """
    idx = _ja4_index(lookback_days)
    combined = Counter()
    for dst in dst_ips:
        c = idx.get((src, dst))
        if c:
            combined.update(c)
    if not combined:
        return ("", 0)
    h, n = combined.most_common(1)[0]
    return (h, n)


# ── JA4 history (persistent across log2ram retention) ─────────────────────────

_JA4_HISTORY_CACHE = {"mtime": 0.0, "data": {}}


def load_ja4_history():
    """Load /var/lib/beaconbutty/device-ja4-history.json with mtime cache.

    Schema: {ip: {first_seen, last_seen, fingerprints: {ja4: {first_seen,
    last_seen, count}}}}. Written by beaconbutty-ja4-history-update.py
    (daily timer + manual backfill).
    """
    try:
        st = JA4_HISTORY_FILE.stat()
    except OSError:
        return {}
    if _JA4_HISTORY_CACHE["mtime"] == st.st_mtime:
        return _JA4_HISTORY_CACHE["data"]
    try:
        data = json.loads(JA4_HISTORY_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        data = {}
    _JA4_HISTORY_CACHE["mtime"] = st.st_mtime
    _JA4_HISTORY_CACHE["data"] = data
    return data


# ── JA4 → client/OS classifier ─────────────────────────────────────────────────
#
# Two-layer classification:
#   1. ja4db exact match (FoxIO's ja4plus-mapping.csv) — high confidence.
#   2. Cipher-hash agreement across ja4db rows — coarse "family" inference.
#   3. Envelope heuristic on the first JA4 segment — generic fallback.
#
# Returns (label, source) where source ∈ {"ja4db", "ja4db-cipher",
# "heuristic", "unknown"} so the UI can show provenance.

_JA4DB_CACHE = {"mtime": 0.0, "exact": {}, "by_cipher": {}}


def load_ja4db():
    """Parse /var/lib/beaconbutty/ja4db.csv (FoxIO ja4plus-mapping format).

    Returns {"exact": {ja4: label}, "by_cipher": {cipher_hash: label}}.
    `by_cipher` is only populated for cipher hashes whose ja4db rows all
    agree on a single label — otherwise the hash is ambiguous and skipped.
    """
    try:
        st = JA4DB_FILE.stat()
    except OSError:
        return {"exact": {}, "by_cipher": {}}
    if _JA4DB_CACHE["mtime"] == st.st_mtime:
        return {"exact": _JA4DB_CACHE["exact"],
                "by_cipher": _JA4DB_CACHE["by_cipher"]}

    exact = {}
    cipher_to_labels = {}
    try:
        with open(JA4DB_FILE, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ja4 = (row.get("ja4") or "").strip()
                if not ja4 or "_" not in ja4:
                    continue
                # Compose a label like "Chromium Browser" / "Safari"
                # / "Python (urllib3)" depending on which fields are set.
                app = (row.get("Application") or "").strip()
                lib = (row.get("Library") or "").strip()
                osn = (row.get("OS") or "").strip()
                parts = [p for p in (app, lib) if p]
                if osn:
                    parts.append(f"on {osn}")
                label = " / ".join(parts) or "Known JA4"
                exact[ja4] = label
                try:
                    _, cipher_h, _ = ja4.split("_", 2)
                except ValueError:
                    continue
                cipher_to_labels.setdefault(cipher_h, set()).add(label)
    except OSError:
        pass

    by_cipher = {h: next(iter(s)) for h, s in cipher_to_labels.items() if len(s) == 1}

    _JA4DB_CACHE["mtime"] = st.st_mtime
    _JA4DB_CACHE["exact"] = exact
    _JA4DB_CACHE["by_cipher"] = by_cipher
    return {"exact": exact, "by_cipher": by_cipher}


def _ja4_envelope_heuristic(ja4):
    """Classify by the first segment shape only. Last-resort fallback."""
    try:
        env, _, _ = ja4.split("_", 2)
    except ValueError:
        return ""
    if not env:
        return ""
    proto = env[0]
    if len(env) >= 3 and env[1:3] == "12" and env.endswith("00"):
        return "TLS 1.2 / no-ALPN (IoT-likely)"
    if proto == "q":
        return "QUIC client (Chrome / Apple-family)"
    if env.endswith("h1") and len(env) >= 3 and env[1:3] == "13":
        return "TLS 1.3 / h1 client (system service or app)"
    if env.endswith("h2") and len(env) >= 3 and env[1:3] == "13":
        return "TLS 1.3 / h2 client"
    if env.endswith("h3"):
        return "HTTP/3 client"
    if proto == "t":
        return "TLS client"
    return ""


_JA4_THREAT_NEEDLES = (
    "cobalt strike",
    "sliver",
    "havoc",
    "qakbot",
    "pikabot",
    "darkgate",
    "icedid",
    "lumma",
    "ngrok",     # Not malware per se but a common reverse-tunnel for C2
                 # operators; flag and let user FP-suppress if legitimate.
    "mythic",
    "brute ratel",
)

# A JA4 fingerprint whose ja4db Library field is a generic language runtime
# is just that runtime's stock TLS Client Hello — shared by EVERY program
# built with it. ja4db may still name one known malware user (e.g. the hash
# labelled "Sliver Agent / GoLang" — Sliver is written in Go), but the
# fingerprint cannot distinguish it from ordinary Go software (Docker,
# kubectl, Tailscale, restic, …). Like a cipher-family hit, it is far too
# broad to flag — so a threat-named label is downgraded to informational
# when a generic runtime is also present.
_JA4_GENERIC_RUNTIMES = ("golang",)


def _ja4_label_is_threat(label: str) -> bool:
    if not label:
        return False
    low = label.lower()
    if not any(needle in low for needle in _JA4_THREAT_NEEDLES):
        return False
    if any(rt in low for rt in _JA4_GENERIC_RUNTIMES):
        return False
    return True


def classify_ja4(ja4):
    """Return (label, source, is_threat). Empty label when nothing matches."""
    if not ja4:
        return ("", "unknown", False)
    db = load_ja4db()
    lab = db["exact"].get(ja4)
    if lab:
        return (lab, "ja4db", _ja4_label_is_threat(lab))
    try:
        _, cipher_h, _ = ja4.split("_", 2)
        lab = db["by_cipher"].get(cipher_h)
        if lab:
            return (f"{lab} (cipher-family)", "ja4db-cipher",
                    _ja4_label_is_threat(lab))
    except ValueError:
        pass
    h = _ja4_envelope_heuristic(ja4)
    if h:
        return (h, "heuristic", False)
    return ("Unknown TLS client", "unknown", False)


def ja4_known_set_for_ip(src_ip):
    """
    Return the set of JA4 hashes "known" for `src_ip` — i.e. observed on a
    day strictly before today. Fingerprints whose `first_seen == today` are
    excluded so a manual same-day backfill (or an off-cycle cron run) can't
    mask the new-today signal.
    """
    today_iso = date.today().isoformat()
    dev = load_ja4_history().get(src_ip) or {}
    fps = dev.get("fingerprints") or {}
    return {ja4 for ja4, info in fps.items()
            if info.get("first_seen", today_iso) < today_iso}


def ja4_summary_for_ip(src_ip):
    """
    Combine today's live JA4 data with the persistent history for one IP.
    Returns:
        {
            "n_total":     distinct fingerprints ever seen,
            "n_today":     distinct fingerprints in today's live data,
            "n_new_today": distinct fingerprints today that are not "known"
                           (where known = first_seen < today),
            "modal":       modal JA4 hash (history + today combined),
            "modal_count": observation count for modal,
            "first_seen":  first-seen date for the device (or "" if none),
        }
    Empty fields when there's no JA4 data at all.
    """
    history = load_ja4_history()
    dev_hist = history.get(src_ip) or {}
    hist_fps = dev_hist.get("fingerprints") or {}

    # If this device's MAC is on the FP list, suppress threat flags
    # entirely — keeps /assets consistent with the threat-matches card
    # and Slack alerts, both of which already FP-filter.
    fp_all = load_fp_all()
    mac_to_ip, _ = load_leases()
    fp_ips = _fp_device_ips(fp_all["devices"], mac_to_ip)
    device_is_fp = src_ip in fp_ips

    pair_idx = _ja4_index(lookback_days=1)
    today_fps = Counter()
    for (s, _d), c in pair_idx.items():
        if s == src_ip:
            today_fps.update(c)

    if not hist_fps and not today_fps:
        return {"n_total": 0, "n_today": 0, "n_new_today": 0,
                "modal": "", "modal_count": 0, "first_seen": ""}

    combined = Counter()
    for ja4, info in hist_fps.items():
        combined[ja4] += info.get("count", 0)
    combined.update(today_fps)

    known = ja4_known_set_for_ip(src_ip)
    n_new_today = sum(1 for ja4 in today_fps if ja4 not in known)
    modal_hash, modal_count = ("", 0)
    if combined:
        modal_hash, modal_count = combined.most_common(1)[0]

    # Threat flags fade after JA4_THREAT_FADE_DAYS so a device that hit a
    # bad fingerprint once 3 weeks ago doesn't carry a permanent badge.
    fade_cutoff = (date.today() - timedelta(days=JA4_THREAT_FADE_DAYS)).isoformat()

    def _is_fresh(ja4: str) -> bool:
        if ja4 in today_fps:
            return True
        info = hist_fps.get(ja4) or {}
        return (info.get("last_seen") or "") >= fade_cutoff

    label, source, is_threat = classify_ja4(modal_hash)
    # Exact-match only (cipher-family is informational), fresh, and not FP'd.
    is_threat = (is_threat and source == "ja4db"
                 and _is_fresh(modal_hash) and not device_is_fp)

    # Also check whether ANY fingerprint observed (today + history) for this
    # device matches a threat family — surfaces malware even if it's not the
    # device's modal hash. Exact-match only, recent only, not FP'd.
    any_threat = False
    threat_hashes = []
    threat_details = []
    if not device_is_fp:
        for ja4 in combined:
            lab, src, t = classify_ja4(ja4)
            if t and src == "ja4db" and _is_fresh(ja4):
                any_threat = True
                threat_hashes.append(ja4)
                last_seen = (today_fps and ja4 in today_fps and date.today().isoformat()) \
                            or (hist_fps.get(ja4) or {}).get("last_seen", "")
                threat_details.append({
                    "ja4":       ja4,
                    "label":     lab,
                    "last_seen": last_seen,
                })

    return {
        "n_total":        len(combined),
        "n_today":        len(today_fps),
        "n_new_today":    n_new_today,
        "modal":          modal_hash,
        "modal_count":    modal_count,
        "first_seen":     dev_hist.get("first_seen", ""),
        "client_label":   label,
        "client_src":     source,
        "client_threat":  is_threat,
        "any_threat":     any_threat,
        "threat_hashes":  threat_hashes,
        "threat_details": threat_details,
    }


# ── Domain activity flagger ────────────────────────────────────────────────────

DOMAIN_WATCH_MAX = 3


def load_domain_watch_config():
    """Return {"domains": [...]} (max DOMAIN_WATCH_MAX, lowercased, deduped).

    Backward-compatible: if the file uses the old singleton schema
    {"domain": "x"}, treat as ["x"] and ignore on empty.
    """
    try:
        cfg = json.loads(DOMAIN_WATCH_CONFIG.read_text())
    except Exception:
        return {"domains": []}

    raw = cfg.get("domains")
    if raw is None:
        legacy = (cfg.get("domain") or "").strip()
        raw = [legacy] if legacy else []

    cleaned = []
    seen = set()
    for d in raw:
        if not isinstance(d, str):
            continue
        d = d.strip().lower()
        if not d or d in seen:
            continue
        seen.add(d)
        cleaned.append(d)
        if len(cleaned) >= DOMAIN_WATCH_MAX:
            break
    return {"domains": cleaned}


def save_domain_watch_config(domains):
    """Persist a sanitised list. Accepts a list or a single string for callers
    that haven't migrated yet."""
    if isinstance(domains, str):
        domains = [domains] if domains.strip() else []
    DOMAIN_WATCH_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    cleaned = []
    seen = set()
    for d in domains or []:
        if not isinstance(d, str):
            continue
        d = d.strip().lower()
        if not d or d in seen:
            continue
        seen.add(d)
        cleaned.append(d)
        if len(cleaned) >= DOMAIN_WATCH_MAX:
            break
    # Atomic write: bb-pcap-watch polls this file by mtime, and a torn read
    # parses as "no watches" — its reconcile would then delete every active
    # capture ring.
    tmp = DOMAIN_WATCH_CONFIG.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"domains": cleaned}, indent=2))
    tmp.replace(DOMAIN_WATCH_CONFIG)
    return cleaned


def _scan_domain_activity(domain, lookback_seconds=6 * 3600):
    """
    Scan Zeek ssl.log (SNI) and dns.log (query) for events matching `domain`
    (case-insensitive substring). Bucket events by UTC minute.

    Returns (buckets, window_start, window_end).

    Each bucket:
        {
            "ts": <minute-epoch>,
            "count": <unique (second, src, source_type) events in the minute>,
            "sources": [[ip, count], ...]      # sorted desc by count
            "paired":  [hostname, ...]         # other domains resolved
                                                 # by same src within +/-1s
        }
    """
    domain_l = (domain or "").lower().strip()
    if not domain_l:
        return [], 0, int(time.time())

    now = int(time.time())
    since = now - lookback_seconds

    dirs = []
    today_dir = ZEEK_LOG_DIR / date.today().strftime("%Y-%m-%d")
    if today_dir.is_dir():
        dirs.append(today_dir)
    cur = ZEEK_LOG_DIR / "current"
    if cur.is_dir():
        dirs.append(cur)

    def rows(prefix):
        for d in dirs:
            for pattern in (f"{prefix}.*.log.gz", f"{prefix}.log"):
                for path in sorted(d.glob(pattern)):
                    try:
                        opener = gzip.open if str(path).endswith(".gz") else open
                        with opener(path, "rt", errors="replace") as f:
                            fields = None
                            for line in f:
                                if line.startswith("#fields\t"):
                                    fields = line.rstrip("\n").split("\t")[1:]
                                    continue
                                if line.startswith("#") or not line.strip():
                                    continue
                                if not fields:
                                    continue
                                parts = line.rstrip("\n").split("\t")
                                if len(parts) >= len(fields):
                                    yield dict(zip(fields, parts))
                    except Exception:
                        continue

    events = set()            # (second_ts, src_ip, source_type)
    dns_by_src = {}           # src_ip -> list of (second_ts, query_lower, query_raw)

    for row in rows("ssl"):
        try:
            ts = float(row.get("ts", "0"))
        except (TypeError, ValueError):
            continue
        if ts < since:
            continue
        sni = (row.get("server_name") or "").lower()
        if sni and domain_l in sni:
            events.add((int(ts), row.get("id.orig_h", ""), "ssl"))

    for row in rows("dns"):
        try:
            ts = float(row.get("ts", "0"))
        except (TypeError, ValueError):
            continue
        if ts < since:
            continue
        q_raw = row.get("query") or ""
        q = q_raw.lower()
        src = row.get("id.orig_h", "")
        if not q or not src:
            continue
        dns_by_src.setdefault(src, []).append((int(ts), q, q_raw))
        if domain_l in q:
            events.add((int(ts), src, "dns"))

    buckets = {}
    for t, ip, _src_type in events:
        minute = (t // 60) * 60
        b = buckets.setdefault(minute, {"count": 0, "sources": {}, "paired": {}})
        b["count"] += 1
        b["sources"][ip] = b["sources"].get(ip, 0) + 1

    # Paired-domain hints: for each event, collect unique hostnames resolved by
    # the same source within +/-1s; increment each bucket's per-hostname counter
    # so users can distinguish causation (high count) from noise (count of 1).
    for t, ip, _src_type in events:
        minute = (t // 60) * 60
        nearby = dns_by_src.get(ip, ())
        event_hosts = set()
        for qt, q, q_raw in nearby:
            if abs(qt - t) <= 1 and domain_l not in q:
                event_hosts.add(q_raw)
        b_paired = buckets[minute]["paired"]
        for host in event_hosts:
            b_paired[host] = b_paired.get(host, 0) + 1

    result = []
    PAIRED_CAP = 8
    for minute in sorted(buckets.keys(), reverse=True):
        b = buckets[minute]
        paired_sorted = sorted(
            b["paired"].items(), key=lambda x: (-x[1], x[0])
        )[:PAIRED_CAP]
        result.append({
            "ts": minute,
            "count": b["count"],
            "sources": sorted(b["sources"].items(), key=lambda x: (-x[1], x[0])),
            "paired": paired_sorted,
        })
    return result, since, now


def build_ja4_threat_matches(ip_to_host, assets=None):
    """Find LAN devices whose JA4 hashes today match a known threat family
    in the FoxIO ja4plus-mapping.csv (Cobalt Strike, Sliver, Havoc, Qakbot,
    Pikabot, Darkgate, IcedID, Lumma, ngrok, Mythic, Brute Ratel).

    Exact-hash matches only. Cipher-family hits are excluded — that path
    is too broad to surface here (legitimate clients commonly share cipher
    lists with malware families). Cipher-family classification is still
    visible per-fingerprint in the JA4 Inventory card.
    """
    fp_all = load_fp_all()
    mac_to_ip, _ = load_leases()
    fp_ips = _fp_device_ips(fp_all["devices"], mac_to_ip)

    pair_idx = _ja4_index(lookback_days=1)
    by_src: dict[str, Counter] = {}
    for (src, dst), c in pair_idx.items():
        if not _is_lan(src) or _is_lan(dst):
            continue
        if src in fp_ips:
            continue
        by_src.setdefault(src, Counter()).update(c)

    rows = []
    for src, c in by_src.items():
        for ja4, count in c.items():
            label, source, is_threat = classify_ja4(ja4)
            if not is_threat or source != "ja4db":
                continue
            rows.append({
                "ip":     src,
                "label":  ip_label(src, ip_to_host, assets or {}),
                "ja4":    ja4,
                "match":  label,
                "source": source,
                "count":  count,
            })
    rows.sort(key=lambda r: -r["count"])
    return rows


def build_l2_anomalies(ip_to_host, assets=None):
    """
    L2 anomaly detector reading Zeek arp.log (created by site/arp-log.zeek).
    Flags three classes:

    1. **gateway_impersonation** — any MAC other than the Pi's announcing
       192.168.50.1. Critical: this is router takeover.
    2. **mac_change** — an IP previously associated with one MAC announces
       under a different one. Suspicious unless it's a known randomised-MAC
       device (iPhone, etc.). FP MACs are excluded by default.
    3. **bad_arp** — Zeek's bad_arp event (malformed packet).

    Lookback: today only. Scans both reply and request rows; the *sender*
    fields (src_mac/src_ip) are the announcement.
    """
    fp_all = load_fp_all()
    mac_to_ip, _ = load_leases()
    fp_macs = {mac.lower() for mac in fp_all["devices"]}

    # All of bb0's own NIC MACs (eth0, eth1, wlan0, …). Used to skip
    # self-on-self flux (multiple bb0 interfaces on the same broadcast
    # domain replying for each other's IPs) and to identify rogue gateway
    # claimants.
    bb0_macs: set[str] = set()
    try:
        for iface_dir in os.listdir("/sys/class/net"):
            try:
                with open(f"/sys/class/net/{iface_dir}/address") as f:
                    m = f.read().strip().lower()
                    if m and m != "00:00:00:00:00:00":
                        bb0_macs.add(m)
            except OSError:
                continue
    except OSError:
        pass
    GATEWAY_IP = "192.168.50.1"

    # ip → set of distinct macs seen today
    ip_to_macs = {}
    # ip → list of (ts, mac) sorted by ts; for change detection
    ip_macs_ts = {}
    bad_events = []

    for row in _read_zeek_logs(_zeek_day_dirs(1), "arp"):
        op  = row.get("operation", "")
        mac = (row.get("src_mac") or "").lower()
        ip  = (row.get("src_ip") or "").strip()
        ts  = row.get("ts", "")

        if op == "bad":
            bad_events.append({
                "ts":   ts,
                "mac":  mac,
                "ip":   ip,
                "info": row.get("info", ""),
            })
            continue
        if not mac or not ip or ip == "-" or not _is_lan(ip):
            continue

        ip_to_macs.setdefault(ip, set()).add(mac)
        ip_macs_ts.setdefault(ip, []).append((ts, mac))

    anomalies = []

    # 1. Gateway impersonation
    gw_macs = ip_to_macs.get(GATEWAY_IP, set())
    rogues  = gw_macs - bb0_macs
    for rogue_mac in sorted(rogues):
        anomalies.append({
            "kind":     "gateway_impersonation",
            "severity": "critical",
            "ip":       GATEWAY_IP,
            "mac":      rogue_mac,
            "label":    ip_label(GATEWAY_IP, ip_to_host, assets or {}),
            "detail":   f"MAC {rogue_mac} announced as gateway {GATEWAY_IP}",
        })

    # 2. MAC changes (>1 distinct MAC for a non-gateway IP)
    for ip, macs in ip_to_macs.items():
        if ip == GATEWAY_IP:
            continue
        if len(macs) < 2:
            continue
        # Suppress when every claiming MAC is one of bb0's own interfaces —
        # that's ARP flux from the Pi being multi-homed on its own LAN, not
        # a real conflict.
        if macs.issubset(bb0_macs):
            continue
        # Suppress when the device is in the FP list (randomised-MAC iPhone,
        # etc.). Match by any MAC the IP has used today.
        if macs & fp_macs:
            continue
        anomalies.append({
            "kind":     "mac_change",
            "severity": "warning",
            "ip":       ip,
            "mac":      ", ".join(sorted(macs)),
            "label":    ip_label(ip, ip_to_host, assets or {}),
            "detail":   f"{len(macs)} distinct MACs claiming {ip} today",
        })

    # 3. Malformed ARP packets — most-recent first, capped.
    for ev in bad_events[-20:]:
        anomalies.append({
            "kind":     "bad_arp",
            "severity": "info",
            "ip":       ev["ip"],
            "mac":      ev["mac"],
            "label":    ip_label(ev["ip"], ip_to_host, assets or {}) if ev["ip"] else "",
            "detail":   ev["info"] or "malformed ARP",
        })

    sev_order = {"critical": 0, "warning": 1, "info": 2}
    anomalies.sort(key=lambda a: (sev_order.get(a["severity"], 9), a["ip"]))
    return anomalies


def build_ja4_inventory(ip_to_host, assets=None):
    """
    Per-LAN-device JA4 client fingerprint inventory for the past day.
    Returns a list of rows sorted by distinct-fingerprint count (descending),
    each row:
        {
            "ip", "label",
            "n_unique":   distinct JA4 count,
            "n_total":    TLS connections observed,
            "top":        [(hash, count), ...]  # up to 3
            "more":       extra distinct hashes beyond the top 3,
            "outlier":    True if exactly 1 distinct fingerprint
                          (single-app device — could be IoT or a dedicated
                          beacon),
        }
    """
    fp_all = load_fp_all()
    mac_to_ip, _ = load_leases()
    fp_ips = _fp_device_ips(fp_all["devices"], mac_to_ip)

    pair_idx = _ja4_index(lookback_days=1)
    by_src = {}
    for (src, dst), c in pair_idx.items():
        if not _is_lan(src) or _is_lan(dst):
            continue
        if src in fp_ips:
            continue
        by_src.setdefault(src, Counter()).update(c)

    rows = []
    for src, c in by_src.items():
        known = ja4_known_set_for_ip(src)
        top_hashes = c.most_common(3)
        # Annotate each top entry with new-today, classifier, threat flags.
        # Threat flag is exact-match only — cipher-family is informational
        # (the cli_label still shows it as e.g. "IcedID (cipher-family)" so
        # an operator hovering can still see the classification, but it
        # doesn't paint the hash red or stamp the row THREAT).
        top = []
        for h, n in top_hashes:
            cli_label, cli_src, raw_threat = classify_ja4(h)
            threat = raw_threat and cli_src == "ja4db"
            top.append((h, n, h not in known, cli_label, cli_src, threat))
        # Threat detection scans ALL fingerprints today, not just top 3 — a
        # rare malware hash could be outside the top. Exact-match only.
        # threat_details carries the matched family + conn count per hash so
        # the THREAT badge can explain *why* the device is flagged (the bad
        # hash is often outside the top 3, where the inline row gives no clue).
        threat_details = []
        for h, n in c.most_common():
            cli_label, cli_src, raw_threat = classify_ja4(h)
            if raw_threat and cli_src == "ja4db":
                threat_details.append({"ja4": h, "label": cli_label, "count": n})
        any_threat_here = bool(threat_details)
        n_unique = len(c)
        n_total = sum(c.values())
        n_new_today = sum(1 for h in c if h not in known)
        rows.append({
            "ip":            src,
            "label":         ip_label(src, ip_to_host, assets or {}),
            "n_unique":      n_unique,
            "n_total":       n_total,
            "n_new_today":   n_new_today,
            "top":           top,
            "more":          max(0, n_unique - len(top)),
            "outlier":       n_unique == 1 and n_total >= 5,
            "threat":        any_threat_here,
            "threat_details": threat_details,
        })

    # Sort: devices with new-today fingerprints first, then by distinct count.
    rows.sort(key=lambda r: (-r["n_new_today"], -r["n_unique"], -r["n_total"]))
    return rows


def build_tls_anomalies(ip_to_host, assets=None):
    """
    Scan ssl.log for TLS anomalies from LAN→WAN connections:
    no SNI, self-signed cert, expired cert.
    Destinations are grouped by ASN organisation to reduce noise.
    """
    fp_all = load_fp_all()
    mac_to_ip, _ = load_leases()
    fp_ips     = _fp_device_ips(fp_all["devices"], mac_to_ip)
    fp_domains = fp_all["domains"]

    # (src, dst_ip, issue) → count
    raw = {}
    for row in _read_zeek_logs(_zeek_day_dirs(1), "ssl"):
        src   = row.get("id.orig_h", "-")
        dst   = row.get("id.resp_h", "-")
        sni   = row.get("server_name", "-")
        val   = row.get("validation_status", "-")
        estab = row.get("established", "-")

        if not _is_lan(src) or _is_lan(dst):
            continue
        if src in fp_ips:
            continue
        if estab not in ("T", "true", "1"):
            continue
        # Suppress destinations the operator has FP'd. fp_domains uses fnmatch,
        # so literal IPs and wildcards like "1.2.3.*" both work. SNI is also
        # checked when present so a domain FP suppresses cert-anomaly rows.
        if _fp_domain_match(dst, fp_domains):
            continue
        if sni and sni != "-" and _fp_domain_match(sni, fp_domains):
            continue

        issues = []
        sni_missing = not sni or sni == "-"
        if sni_missing and not _is_safe_org(dst):
            issues.append("no-sni")
        if val and "self signed" in val.lower():
            issues.append("self-signed")
        if val and "expired" in val.lower():
            issues.append("expired")

        for issue in issues:
            key = (src, dst, issue)
            raw[key] = raw.get(key, 0) + 1

    order = {"expired": 0, "self-signed": 1, "no-sni": 2}

    def _org(ip):
        try:
            if _GEOIP_ASN:
                return _GEOIP_ASN.asn(ip).autonomous_system_organization or "Unknown"
        except Exception:
            pass
        return "Unknown"

    # Group by (src, org, issue) → {ips: {ip: count}, total}
    by_src_org = {}  # src → {(org, issue): {ip: count}}
    for (src, dst, issue), cnt in raw.items():
        org = _org(dst)
        by_src_org.setdefault(src, {})
        key = (org, issue)
        by_src_org[src].setdefault(key, {})
        by_src_org[src][key][dst] = by_src_org[src][key].get(dst, 0) + cnt

    # Build per-source entity list
    by_src = {}
    for src, org_map in by_src_org.items():
        entities = []
        for (org, issue), ip_counts in org_map.items():
            total = sum(ip_counts.values())
            ips = sorted(ip_counts.keys(), key=lambda ip: -ip_counts[ip])
            entities.append({
                "org":   org,
                "issue": issue,
                "ips":   ips,
                "count": total,
            })
        entities.sort(key=lambda e: (order.get(e["issue"], 9), -e["count"]))
        by_src[src] = entities

    def src_sort_key(src):
        ents = by_src[src]
        worst = min(order.get(e["issue"], 9) for e in ents)
        total = sum(e["count"] for e in ents)
        return (worst, -total)

    results = [
        {
            "src_ip":    src,
            "src_label": ip_label(src, ip_to_host, assets),
            "entities":  by_src[src],
        }
        for src in sorted(by_src, key=src_sort_key)
    ]
    return results[:50]


def build_exfil_candidates(ip_to_host, assets=None):
    """
    Scan conn.log for LAN→WAN outbound byte totals (≥ threshold).
    Skips known-safe ASN destinations and FP devices.
    """
    fp_all = load_fp_all()
    mac_to_ip, _ = load_leases()
    fp_ips = _fp_device_ips(fp_all["devices"], mac_to_ip)

    # Use orig_ip_bytes (real IP-layer bytes Zeek observed) rather than
    # orig_bytes (payload estimator that can inflate on TCP-sequence-wrap
    # artifacts — see Bandwidth page).
    src_bytes = {}
    src_conns = {}
    src_top   = {}  # ip → (bytes, dst_ip)

    for row in _read_zeek_logs(_zeek_day_dirs(1), "conn"):
        src = row.get("id.orig_h", "-")
        dst = row.get("id.resp_h", "-")
        ob  = row.get("orig_ip_bytes", "-")

        if not _is_lan(src) or _is_lan(dst):
            continue
        if src in fp_ips:
            continue
        if _is_safe_org(dst):
            continue
        try:
            b = int(ob)
        except (ValueError, TypeError):
            continue
        if b <= 0:
            continue

        src_bytes[src] = src_bytes.get(src, 0) + b
        src_conns[src] = src_conns.get(src, 0) + 1
        if b > src_top.get(src, (0, ""))[0]:
            src_top[src] = (b, dst)

    threshold_b = int(_EXFIL_THRESHOLD_MB * 1_000_000)
    results = []
    for src, total in sorted(src_bytes.items(), key=lambda x: -x[1]):
        if total < threshold_b:
            continue
        top_dst = src_top.get(src, (0, ""))[1]
        results.append({
            "src_ip":    src,
            "src_label": ip_label(src, ip_to_host, assets),
            "total_mb":  round(total / 1_000_000, 1),
            "conns":     src_conns.get(src, 0),
            "top_dst":   _annotate_dest(top_dst) if top_dst else "—",
        })
    return results[:20]


def build_night_activity(ip_to_host, assets=None):
    """
    Scan conn.log for LAN→WAN connections during 01:00–05:59 local time.
    """
    fp_all = load_fp_all()
    mac_to_ip, _ = load_leases()
    fp_ips = _fp_device_ips(fp_all["devices"], mac_to_ip)

    # See build_exfil_candidates — ip_bytes, not payload bytes.
    src_conns = {}
    src_bytes = {}
    src_dsts  = {}

    for row in _read_zeek_logs(_zeek_day_dirs(1), "conn"):
        src = row.get("id.orig_h", "-")
        dst = row.get("id.resp_h", "-")
        ts  = row.get("ts", "-")
        ob  = row.get("orig_ip_bytes", "-")

        if not _is_lan(src) or _is_lan(dst):
            continue
        if src in fp_ips:
            continue
        try:
            dt = datetime.fromtimestamp(float(ts))
        except (ValueError, TypeError):
            continue
        if dt.hour not in _NIGHT_HOURS:
            continue
        try:
            b = max(0, int(ob))
        except (ValueError, TypeError):
            b = 0

        src_conns[src] = src_conns.get(src, 0) + 1
        src_bytes[src] = src_bytes.get(src, 0) + b
        src_dsts.setdefault(src, set()).add(dst)

    results = [
        {
            "src_ip":      src,
            "src_label":   ip_label(src, ip_to_host, assets),
            "conns":       src_conns[src],
            "mb":          round(src_bytes.get(src, 0) / 1_000_000, 1),
            "unique_dsts": len(src_dsts.get(src, set())),
        }
        for src in sorted(src_conns, key=lambda x: -src_conns[x])
        if src_conns[src] >= 5
    ]
    return results[:20]


def build_dns_anomalies(ip_to_host, assets=None):
    """
    Scan dns.log for high NXDOMAIN rates and high-entropy (DGA-like) queries.
    """
    fp_all = load_fp_all()
    mac_to_ip, _ = load_leases()
    fp_ips = _fp_device_ips(fp_all["devices"], mac_to_ip)
    fp_domains = fp_all["domains"]  # pattern → reason

    def _fp_domain_match_q(q):
        return _fp_domain_match(q, fp_domains)

    src_total    = {}
    src_nxdomain = {}
    src_entropy  = {}  # src → [(query, entropy)]

    for row in _read_zeek_logs(_zeek_day_dirs(1), "dns"):
        src   = row.get("id.orig_h", "-")
        query = row.get("query", "-")
        rcode = row.get("rcode_name", "-")
        qtype = row.get("qtype_name", "-")

        if not _is_lan(src):
            continue
        if src in fp_ips:
            continue
        if not query or query == "-":
            continue
        if query.endswith(".in-addr.arpa") or query.endswith(".ip6.arpa"):
            continue
        if query.endswith(".local") or query.endswith(".internal") or query.endswith(".lan"):
            continue

        src_total[src] = src_total.get(src, 0) + 1
        if rcode and rcode.upper() == "NXDOMAIN":
            src_nxdomain[src] = src_nxdomain.get(src, 0) + 1

        # Entropy check — forward lookups only, skip known-safe domains
        # and anything matching an FP domain pattern (e.g. *.cloudfront.net)
        if qtype in ("A", "AAAA") and not _is_safe_dest(None, query) \
                and not _fp_domain_match_q(query):
            ent = _domain_entropy(query)
            if ent >= _ENTROPY_THRESHOLD:
                lst = src_entropy.setdefault(src, [])
                entry = (query, round(ent, 2))
                if len(lst) < 5 and entry not in lst:
                    lst.append(entry)

    results = []
    seen = set()
    for src, total in sorted(src_total.items(), key=lambda x: -x[1]):
        if total < _NXDOMAIN_MIN_Q:
            continue
        nxd  = src_nxdomain.get(src, 0)
        rate = nxd / total
        has_entropy = src in src_entropy
        if rate >= _NXDOMAIN_THRESHOLD or has_entropy:
            seen.add(src)
            if rate >= _NXDOMAIN_THRESHOLD and has_entropy:
                flag = "both"
            elif rate >= _NXDOMAIN_THRESHOLD:
                flag = "nxdomain"
            else:
                flag = "entropy"
            results.append({
                "src_ip":       src,
                "src_label":    ip_label(src, ip_to_host, assets),
                "total":        total,
                "nxdomain":     nxd,
                "nxdomain_pct": round(rate * 100, 1),
                "flag":         flag,
                "examples":     src_entropy.get(src, []),
            })

    # Entropy-only sources that didn't reach min query count
    for src, examples in src_entropy.items():
        if src not in seen:
            total = src_total.get(src, 0)
            nxd   = src_nxdomain.get(src, 0)
            results.append({
                "src_ip":       src,
                "src_label":    ip_label(src, ip_to_host, assets),
                "total":        total,
                "nxdomain":     nxd,
                "nxdomain_pct": round(nxd / total * 100, 1) if total else 0,
                "flag":         "entropy",
                "examples":     examples,
            })

    results.sort(key=lambda x: (-x["nxdomain_pct"], -x["total"]))
    return results[:20]


def build_weird_events(ip_to_host, assets=None):
    """
    Scan weird.log for protocol anomalies. Groups by name, shows LAN sources.
    """
    fp_all = load_fp_all()
    mac_to_ip, _ = load_leases()
    fp_ips = _fp_device_ips(fp_all["devices"], mac_to_ip)

    agg = {}  # name → {count, lan_srcs: set, addl: str}

    for row in _read_zeek_logs(_zeek_day_dirs(1), "weird"):
        src  = row.get("id.orig_h", "-")
        name = row.get("name", "-")
        addl = row.get("addl", "")

        if not name or name == "-":
            continue

        if name not in agg:
            agg[name] = {"count": 0, "lan_srcs": set(), "addl": addl or ""}
        agg[name]["count"] += 1
        if src and src != "-" and _is_lan(src) and src not in fp_ips:
            agg[name]["lan_srcs"].add(src)

    results = [
        {
            "name":      name,
            "count":     v["count"],
            "src_count": len(v["lan_srcs"]),
            "srcs":      ", ".join(
                ip_label(ip, ip_to_host, assets) for ip in sorted(v["lan_srcs"])[:3]
            ) or "—",
            "addl":      (v["addl"] or "—")[:60],
        }
        for name, v in sorted(agg.items(), key=lambda x: -x[1]["count"])
    ]
    return results[:30]


def build_beacon_persistence(ip_to_host, assets=None):
    """
    Find (src, dest) beacon pairs appearing across 3+ report files (up to 14 days).
    """
    pair_dates = {}  # (src, dest_key) → set of date strings
    pair_score = {}  # (src, dest_key) → max score
    pair_dst   = {}  # (src, dest_key) → most recent dst IP (for GeoIP lookup)

    for path in sorted(REPORTS_DIR.glob("beacon-report-*.txt"), reverse=True)[:14]:
        _, rows_by_date = parse_beacon_report(path)
        for day_str, rows in rows_by_date.items():
            for row in rows:
                src      = row[COL["Source IP"]].strip()
                dst      = row[COL["Destination IP"]].strip()
                fqdn     = row[COL["FQDN"]].strip()
                dest_key = fqdn if fqdn else dst
                if not _IP_RE.match(src) or _is_safe_dest(dst, fqdn):
                    continue
                try:
                    sc = float(row[COL["Beacon Score"]])
                except (ValueError, IndexError):
                    sc = 0.0
                key = (src, dest_key)
                pair_dates.setdefault(key, set()).add(day_str)
                if sc > pair_score.get(key, 0.0):
                    pair_score[key] = sc
                pair_dst[key] = dst   # keep last IP we saw for this pair

    fp_all = load_fp_all()
    mt2i, _ = load_leases()
    fp_ips     = _fp_device_ips(fp_all["devices"], mt2i)
    fp_domains = fp_all["domains"]

    results = []
    for (src, dest_key), dates in pair_dates.items():
        if len(dates) < 3 or src in fp_ips or _fp_domain_match(dest_key, fp_domains):
            continue
        # GeoIP ASN org for FP-modal reason pre-fill — based on the IP form
        # of dest_key when it's an IP, else on the most recent IP we saw
        # for this pair.
        ip_for_lookup = dest_key if _IP_RE.match(dest_key) else pair_dst.get((src, dest_key), "")
        _, _, _dst_org = _geoip_info(ip_for_lookup) if ip_for_lookup else (None, None, None)
        results.append({
            "src_ip":      src,
            "src_label":   ip_label(src, ip_to_host, assets),
            "dest":        _annotate_dest(dest_key) if _IP_RE.match(dest_key) else dest_key,
            "dest_key":    dest_key,
            "dst_org":     _dst_org or "",
            "days":        len(dates),
            "latest_date": max(dates),
            "score":       pair_score.get((src, dest_key), 0.0),
        })
    results.sort(key=lambda x: (-x["days"], -x["score"]))
    return results[:30]


def build_new_beacons(ip_to_host, assets=None):
    """
    Find beacon (src, dest) pairs in the most recent report not seen in the previous 7.
    """
    report_files = sorted(REPORTS_DIR.glob("beacon-report-*.txt"), reverse=True)
    if not report_files:
        return []

    _, rows_by_date = parse_beacon_report(report_files[0])
    current_pairs  = {}  # key → row
    current_scores = {}  # key → score

    for rows in rows_by_date.values():
        for row in rows:
            src      = row[COL["Source IP"]].strip()
            dst      = row[COL["Destination IP"]].strip()
            fqdn     = row[COL["FQDN"]].strip()
            dest_key = fqdn if fqdn else dst
            if not _IP_RE.match(src) or _is_safe_dest(dst, fqdn):
                continue
            try:
                sc = float(row[COL["Beacon Score"]])
            except (ValueError, IndexError):
                sc = 0.0
            key = (src, dest_key)
            if key not in current_pairs or sc > current_scores.get(key, 0.0):
                current_pairs[key]  = row
                current_scores[key] = sc

    historical = set()
    for path in report_files[1:8]:
        _, rows_by_date = parse_beacon_report(path)
        for rows in rows_by_date.values():
            for row in rows:
                src  = row[COL["Source IP"]].strip()
                dst  = row[COL["Destination IP"]].strip()
                fqdn = row[COL["FQDN"]].strip()
                historical.add((src, fqdn if fqdn else dst))

    fp_all = load_fp_all()
    mt2i, _ = load_leases()
    fp_ips       = _fp_device_ips(fp_all["devices"], mt2i)
    fp_domains   = fp_all["domains"]
    fp_protocols = fp_all["protocols"]

    def _fp_proto_match(svc):
        return _fp_service_match(svc, fp_protocols)[0] is not None

    # Pre-pass: enrich every bare-IP candidate (not already FP'd by IP)
    # so the FP-domain check below can match against the Zeek-recovered
    # FQDN. Without this, "*.knock.app" never suppresses bare AWS IPs.
    prelim_pairs = set()
    for (src, dest_key), row in current_pairs.items():
        if src in fp_ips or (src, dest_key) in historical:
            continue
        row_dst  = row[COL["Destination IP"]].strip()
        row_fqdn = row[COL["FQDN"]].strip()
        if not row_fqdn and row_dst and _IP_RE.match(row_dst):
            prelim_pairs.add((src, row_dst))
    emap = enrich_ips_batch(prelim_pairs, days=14) if prelim_pairs else {}

    results = []
    for (src, dest_key), row in current_pairs.items():
        if src in fp_ips or (src, dest_key) in historical:
            continue
        row_fqdn = row[COL["FQDN"]].strip()
        row_dst  = row[COL["Destination IP"]].strip()
        svc = row[COL["Port:Proto:Service"]] if len(row) > COL["Port:Proto:Service"] else ""
        # Enrichment-aware FP-domain check — also tries the Zeek-recovered
        # FQDN so "*.knock.app" suppresses bare AWS IPs that map to it.
        e_name = (emap.get((src, row_dst)) or {}).get("name", "")
        candidates = [t for t in (row_fqdn, row_dst, e_name) if t]
        if any(_fp_domain_match(t, fp_domains) for t in candidates) \
                or _fp_proto_match(svc):
            continue
        sc  = current_scores.get((src, dest_key), 0.0)
        fs  = row[COL["First Seen"]]         if len(row) > COL["First Seen"]          else ""
        # GeoIP ASN org of the destination IP for FP-modal reason pre-fill.
        _, _, _dst_org = _geoip_info(row_dst) if row_dst else (None, None, None)
        results.append({
            "src_ip":     src,
            "src_label":  ip_label(src, ip_to_host, assets),
            "dest":       _annotate_dest(dest_key) if _IP_RE.match(dest_key) else dest_key,
            "dest_key":   dest_key,
            "dst_org":    _dst_org or "",
            "score":      sc,
            "svc":        svc,
            "first_seen": fs,
            "severity":   row[COL["Severity"]],
        })
    sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    def _row_key(r):
        return (sev_rank.get(r["severity"], 0), r["score"])
    # Group by source IP; group order = best row in group; rows within group sorted same way.
    group_best = {}
    for r in results:
        k = _row_key(r)
        if r["src_ip"] not in group_best or k > group_best[r["src_ip"]]:
            group_best[r["src_ip"]] = k
    results.sort(key=lambda r: (
        -group_best[r["src_ip"]][0], -group_best[r["src_ip"]][1], r["src_ip"],
        -sev_rank.get(r["severity"], 0), -r["score"],
    ))
    results = results[:30]

    # Enrich bare-IP rows with Zeek-side identity (SNI / DNS / cert / HTTP).
    # RITA only joins same-day dns_history, so any beacon whose dst was last
    # resolved on a prior day shows here as a bare AWS/Azure IP. The batch
    # lookup runs once across all visible IP-only rows.
    enrich_targets = []
    for r in results:
        if _IP_RE.match(r["dest_key"]) and r["src_ip"]:
            enrich_targets.append((r["src_ip"], r["dest_key"]))
    if enrich_targets:
        emap = enrich_ips_batch(enrich_targets, days=7)
        for r in results:
            e = emap.get((r["src_ip"], r["dest_key"]))
            if e is None:
                e = {"name": "", "source": "", "when_days": None,
                     "intel": ip_intel(r["dest_key"]) or None}
            elif "intel" not in e:
                e["intel"] = ip_intel(r["dest_key"]) or None
            r["dest_enrich"] = e
    else:
        for r in results:
            r.setdefault("dest_enrich",
                         {"name": "", "source": "", "when_days": None})

    # Annotate groups so the template can rowspan the source-device cell.
    group_size = {}
    for r in results:
        group_size[r["src_ip"]] = group_size.get(r["src_ip"], 0) + 1
    seen = set()
    for r in results:
        first = r["src_ip"] not in seen
        r["group_first"] = first
        r["group_size"]  = group_size[r["src_ip"]] if first else 0
        seen.add(r["src_ip"])
    return results


def _compute_network_intel(ip_to_host, assets=None):
    """Run every network-intel builder. Uncached — see build_network_intel."""
    return {
        "tls_anomalies": build_tls_anomalies(ip_to_host, assets),
        "exfil":         build_exfil_candidates(ip_to_host, assets),
        "night":         build_night_activity(ip_to_host, assets),
        "dns_anomalies": build_dns_anomalies(ip_to_host, assets),
        "weird":         build_weird_events(ip_to_host, assets),
        "persistence":   build_beacon_persistence(ip_to_host, assets),
        "new_beacons":   build_new_beacons(ip_to_host, assets),
        "ja4_inventory": build_ja4_inventory(ip_to_host, assets),
        "ja4_threats":   build_ja4_threat_matches(ip_to_host, assets),
        "l2_anomalies":  build_l2_anomalies(ip_to_host, assets),
    }


def build_network_intel(ip_to_host, assets=None):
    """Return all network intelligence, cached for 5 minutes.

    The full rebuild scans ~17s of Zeek logs. A background thread
    (_network_cache_warmer) refreshes this cache just inside the TTL so
    requests almost always hit the fast path. The cold rebuild below is
    only the fallback for the first request after a restart, or after an
    FP edit invalidated the cache.

    _NETWORK_BUILD_LOCK makes the rebuild single-flight: if the warmer (or
    another request) is already building, a cold request waits for that
    build and then finds the cache fresh — rather than starting a second
    concurrent rebuild that contends for CPU and doubles both their times."""
    now_ts = time.time()
    if _NETWORK_CACHE["data"] and now_ts - _NETWORK_CACHE["ts"] < _NETWORK_CACHE_TTL:
        return _NETWORK_CACHE["data"]
    with _NETWORK_BUILD_LOCK:
        # Re-check: another thread may have rebuilt while we waited for the lock.
        now_ts = time.time()
        if _NETWORK_CACHE["data"] and now_ts - _NETWORK_CACHE["ts"] < _NETWORK_CACHE_TTL:
            return _NETWORK_CACHE["data"]
        data = _compute_network_intel(ip_to_host, assets)
        _NETWORK_CACHE["data"] = data
        _NETWORK_CACHE["ts"]   = now_ts
        return data


def _network_cache_warmer():
    """Keep _NETWORK_CACHE warm so /network never pays the ~17s cold rebuild.

    Rebuilds off to the side and swaps the finished dict in atomically, so
    requests during the rebuild still see the previous (still-valid) cache.
    Runs once immediately on startup, then every TTL-minus-margin seconds, or
    sooner when _invalidate_network_cache() signals an out-of-band rebuild
    (e.g. after an FP edit). Clearing the request before each rebuild means an
    edit that lands mid-rebuild re-sets it and is picked up by a follow-up."""
    interval = max(60, _NETWORK_CACHE_TTL - 60)
    while True:
        _NETWORK_REBUILD_REQUEST.clear()
        try:
            _, ip_to_host = load_leases()
            assets = {}
            try:
                with open(ASSETS_FILE) as f:
                    assets = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            with _NETWORK_BUILD_LOCK:
                data = _compute_network_intel(ip_to_host, assets)
                _NETWORK_CACHE["data"] = data
                _NETWORK_CACHE["ts"]   = time.time()
        except Exception:
            # Log it — a persistently-failing warmer otherwise leaves zero
            # journal evidence until the cache TTL-expires and a request
            # pays the cold rebuild (and surfaces the error as a 500).
            app.logger.exception("network cache warmer rebuild failed")
        _NETWORK_REBUILD_REQUEST.wait(timeout=interval)


def network_alert_summary():
    """Return per-category dashboard counts, warming the cache if cold.
    Dashboard calls this so the tile is always populated — trade-off is that
    the first dashboard load after a restart / FP edit runs the full
    build_network_intel (a few seconds of Zeek log scanning).

    JA4 count is exact-match only — cipher-family hits are visible on
    /network but excluded here to match the Slack-alert policy."""
    if not _NETWORK_CACHE.get("data"):
        mac_to_ip, ip_to_host = load_leases()
        try:
            with open(ASSETS_FILE) as f:
                assets = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            assets = {}
        build_network_intel(ip_to_host, assets)
    d = _NETWORK_CACHE.get("data") or {}
    counts = {
        "tls":         len(d.get("tls_anomalies", [])),
        "dns":         len(d.get("dns_anomalies", [])),
        "new_beacons": len(d.get("new_beacons",   [])),
        "ja4":         sum(1 for r in d.get("ja4_threats", [])
                           if r.get("source") == "ja4db"),
        "l2":          sum(1 for a in d.get("l2_anomalies", [])
                           if a.get("severity") == "critical"),
    }
    counts["total"] = sum(counts.values())
    return counts


# ── Suricata intelligence (extras) ────────────────────────────────────────────

def _eve_find_today_offset(f, today_str):
    """
    Binary-search eve.json (opened in binary mode) for the byte offset where
    today's entries begin.  Lines start: {"timestamp":"YYYY-MM-DD...
    """
    today_b = today_str.encode()
    f.seek(0, 2)
    hi = f.tell()
    lo = 0
    while hi - lo > 65536:
        mid = (lo + hi) // 2
        f.seek(mid)
        f.readline()          # discard partial line
        line = f.readline()
        if not line:
            hi = mid
            continue
        idx = line.find(b'"timestamp":"')
        if idx >= 0 and len(line) > idx + 23:
            if line[idx + 13: idx + 23] >= today_b:
                hi = mid
            else:
                lo = mid
        else:
            lo = mid
    return lo


def parse_eve_json_today():
    """Parse today's eve.json alert events. Binary-searches to today's start."""
    today = date.today().isoformat()
    events = []
    try:
        with open(EVE_JSON, "rb") as fb:
            offset = _eve_find_today_offset(fb, today)
            fb.seek(offset)
            fb.readline()  # skip any partial line at the boundary
            for raw in fb:
                try:
                    ev = json.loads(raw)
                except (json.JSONDecodeError, ValueError):
                    continue
                if ev.get("event_type") != "alert":
                    continue
                if not ev.get("timestamp", "").startswith(today):
                    continue
                events.append(ev)
    except FileNotFoundError:
        pass
    return events


def _suricata_category(rule_name):
    """Extract 'PREFIX CATEGORY' prefix from a Suricata rule name."""
    parts = rule_name.split()
    return " ".join(parts[:2]) if len(parts) >= 2 else rule_name


def build_suricata_extras(ip_to_host, today_alerts=None, week_alerts=None, eve_events=None):
    """
    Build additional Suricata intelligence sections:
    - Category breakdown
    - Hourly alert timeline
    - 7-day alert trend
    - External repeat offenders
    - Eve.json enrichment (HTTP/DNS/TLS context per rule)
    - Beacon cross-correlation
    Pass pre-parsed alerts/eve_events to avoid re-reading files.
    """
    if week_alerts is None:
        week_alerts = parse_fast_log(days=7)
    week_alerts = filter_infra_noise(week_alerts)
    today = date.today()
    if today_alerts is None:
        today_alerts = [a for a in week_alerts if a["ts"].date() == today]
    else:
        today_alerts = filter_infra_noise(today_alerts)
    if eve_events is None:
        eve_events = parse_eve_json_today()
    alerts = today_alerts

    # ── Category breakdown ────────────────────────────────────────────────────
    cat_counts = {}
    for a in alerts:
        cat = _suricata_category(a["rule"])
        cat_counts[cat] = cat_counts.get(cat, 0) + 1
    category_breakdown = sorted(
        [{"cat": k, "count": v} for k, v in cat_counts.items()],
        key=lambda x: -x["count"]
    )[:20]

    # ── Hourly timeline ───────────────────────────────────────────────────────
    hourly = {}
    for a in alerts:
        if a.get("ts"):
            h = a["ts"].hour
            hourly[h] = hourly.get(h, 0) + 1
    hourly_data = [{"hour": h, "count": hourly.get(h, 0)} for h in range(24)]

    # ── 7-day alert trend (from pre-parsed week_alerts) ───────────────────────
    # A day has source coverage if it's today (live fast.log) or at least one
    # parsed alert has that date. Archive mtimes are unreliable — rotation
    # runs near midnight so fast.log.1.gz rotated at 00:40 contains yesterday's
    # data, and rotations occasionally skip days entirely.
    trend_raw = {}
    trend_details = {}  # date iso → list of {time, priority, rule, src, dst}
    covered_dates = {today}
    for a in week_alerts:
        if not a.get("ts"):
            continue
        d = a["ts"].date()
        ds = d.isoformat()
        trend_raw[ds] = trend_raw.get(ds, 0) + 1
        covered_dates.add(d)
        trend_details.setdefault(ds, []).append({
            "time":     a["ts"].strftime("%H:%M:%S"),
            "priority": a.get("priority", 4),
            "rule":     a.get("rule", ""),
            "src":      ip_label(a.get("src_ip", ""), ip_to_host),
            "dst":      _annotate_dest(a.get("dst_ip", "")) if a.get("dst_ip") else "",
        })
    # Sort each day's list by time (newest first) for the popup
    for ds in trend_details:
        trend_details[ds].sort(key=lambda x: x["time"], reverse=True)
    trend_data = []
    for i in range(7):
        d  = today - timedelta(days=i)
        ds = d.isoformat()
        trend_data.append({
            "date":    ds,
            "count":   trend_raw.get(ds, 0),
            "no_data": d not in covered_dates,
        })

    # ── External repeat offenders ─────────────────────────────────────────────
    ext_rules = {}  # ext_ip → set of rule names
    for a in alerts:
        for ip in (a["src_ip"], a["dst_ip"]):
            if ip and not _is_lan(ip) and ip not in ("", "unknown"):
                ext_rules.setdefault(ip, set()).add(a["rule"])
    offenders = [
        {
            "ip":         ip,
            "ip_display": _annotate_dest(ip),
            "rule_count": len(rules),
            "rules":      sorted(rules)[:3],
        }
        for ip, rules in sorted(ext_rules.items(), key=lambda x: -len(x[1]))
        if len(rules) >= 2
    ][:20]

    # ── Eve.json enrichment ───────────────────────────────────────────────────
    eve_enriched = {}  # rule_name → {http, dns_query, tls_sni}
    try:
        for ev in eve_events:
            rule = ev.get("alert", {}).get("signature", "")
            if not rule:
                continue
            if rule not in eve_enriched:
                eve_enriched[rule] = {"http": None, "dns_query": None, "tls_sni": None}
            rec = eve_enriched[rule]
            if "http" in ev and rec["http"] is None:
                h = ev["http"]
                rec["http"] = {
                    "hostname":   h.get("hostname", ""),
                    "url":        h.get("url", ""),
                    "user_agent": h.get("http_user_agent", ""),
                    "method":     h.get("http_method", ""),
                }
            if "dns" in ev and rec["dns_query"] is None:
                rec["dns_query"] = ev["dns"].get("rrname", "")
            if "tls" in ev and rec["tls_sni"] is None:
                rec["tls_sni"] = ev["tls"].get("sni", "")
    except Exception:
        pass

    # ── Beacon cross-correlation ──────────────────────────────────────────────
    alert_lan_ips = set()
    for a in alerts:
        if _is_lan(a["src_ip"]):
            alert_lan_ips.add(a["src_ip"])

    fps    = load_fps()
    mt2i, _ = load_leases()
    fp_ips = _fp_device_ips(fps, mt2i)

    beacon_ips = set()
    for path in sorted(REPORTS_DIR.glob("beacon-report-*.txt"), reverse=True)[:1]:
        _, rows_by_date = parse_beacon_report(path)
        for rows in rows_by_date.values():
            for row in rows:
                src = row[COL["Source IP"]].strip()
                if _IP_RE.match(src) and src not in fp_ips:
                    beacon_ips.add(src)

    cross_ref = [
        {"ip": ip, "label": ip_label(ip, ip_to_host)}
        for ip in sorted(beacon_ips & alert_lan_ips)
    ]

    return {
        "category_breakdown": category_breakdown,
        "hourly_data":        hourly_data,
        "trend_data":         trend_data,
        "trend_details":      trend_details,
        "offenders":          offenders,
        "eve_enriched":       eve_enriched,
        "cross_ref":          cross_ref,
    }


# ── Routes ──────────────────────────────────────────────────────────────────────

def get_network_ips():
    """Return (ethernet_ip, tailscale_ip) strings, or None if not found."""
    eth_ip = None
    ts_ip = None
    try:
        addrs = psutil.net_if_addrs()
        for iface in ("eth1", "eth0"):
            if iface in addrs:
                for addr in addrs[iface]:
                    if addr.family == 2:  # AF_INET
                        eth_ip = addr.address
                        break
            if eth_ip:
                break
        for iface, addr_list in addrs.items():
            if iface.startswith("tailscale") or iface == "ts0":
                for addr in addr_list:
                    if addr.family == 2:
                        ts_ip = addr.address
                        break
    except Exception:
        pass
    return eth_ip, ts_ip


@app.route("/")
def dashboard():
    stats  = get_system_stats()
    health = load_health()
    beacon_count    = count_beacon_findings_today()
    suricata_counts = count_alerts_by_priority()
    network         = network_alert_summary()
    slow            = slow_beacon_summary()
    pcap_active     = len(load_domain_watch_config()["domains"])
    now = datetime.now().strftime("%A %-d %B %Y, %H:%M")
    eth_ip, ts_ip = get_network_ips()
    return render_template(
        "dashboard.html",
        stats=stats,
        health=health,
        beacon_count=beacon_count,
        suricata_counts=suricata_counts,
        network=network,
        slow=slow,
        pcap_active=pcap_active,
        now=now,
        eth_ip=eth_ip,
        ts_ip=ts_ip,
    )


@app.route("/system")
def system():
    return render_template("system.html")


@app.route("/temperature")
def temperature_legacy():
    return redirect(url_for("system"), code=301)


@app.route("/bandwidth")
def bandwidth():
    return render_template("bandwidth.html")


def _group_dates_by_week(date_list):
    """Group [(date_str, filepath)] by ISO week, newest week first.
    Returns [{"label": str, "is_current": bool, "dates": [(date_str, fp), ...]}, ...]
    """
    from datetime import timedelta
    today = date.today()
    current_week_start = today - timedelta(days=today.weekday())

    groups: dict = {}
    for ds, fp in date_list:
        try:
            d = date.fromisoformat(ds)
        except ValueError:
            # A corrupt report header can yield an impossible date — one bad
            # file must not 500 the whole /beacons page.
            continue
        week_start = d - timedelta(days=d.weekday())
        groups.setdefault(week_start, []).append((ds, fp))

    result = []
    for week_start in sorted(groups.keys(), reverse=True):
        is_current = (week_start == current_week_start)
        if is_current:
            label = "This week"
        else:
            week_end = week_start + timedelta(days=6)
            if week_start.month == week_end.month:
                label = f"{week_start.day}–{week_end.day} {week_end.strftime('%b')}"
            else:
                label = f"{week_start.day} {week_start.strftime('%b')} – {week_end.day} {week_end.strftime('%b')}"
        result.append({"label": label, "is_current": is_current, "dates": groups[week_start]})
    return result


@app.route("/beacons")
def beacons():
    mac_to_ip, ip_to_host = load_leases()
    date_list = list_report_dates()  # [(date_str, filepath), ...]

    selected_date = request.args.get("date")
    if not selected_date and date_list:
        selected_date, _ = date_list[0]

    # Load asset cache for label enrichment
    assets = {}
    try:
        with open(ASSETS_FILE) as f:
            assets = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    # Find the file for the selected date
    beacon_data = None
    selected_file = None
    for ds, fp in date_list:
        if ds == selected_date:
            selected_file = fp
            break

    if selected_file:
        beacon_data = get_beacon_data(selected_file, mac_to_ip, ip_to_host, assets)

    today = date.today().strftime("%Y-%m-%d")
    top_beacons_label = (
        "last 3 days"
        if selected_date == today
        else (beacon_data["top_beacons_range"] if beacon_data else "")
    )

    return render_template(
        "beacons.html",
        date_groups=_group_dates_by_week(date_list),
        date_list=date_list,
        selected_date=selected_date,
        beacon_data=beacon_data,
        top_beacons_label=top_beacons_label,
    )


SLOW_CADENCE_REPORT = "/var/lib/beaconbutty/reports/slow-cadence.json"


def _load_slow_cadence_filtered():
    """Load the slow-cadence report and apply the FP filter at render time.
    Returns (filtered_candidates, payload_meta).  Shared by /beacons/slow
    and the dashboard tile so the two surfaces can't drift on counts.

    Re-applying the FP filter here (rather than relying on the detector's
    own pass) means a freshly-added FP pattern takes effect on the next
    page load instead of waiting for the next detector run."""
    payload = {"candidates": [], "generated_at": "", "window_days": 0,
               "thresholds": {}}
    try:
        with open(SLOW_CADENCE_REPORT) as f:
            payload = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    mac_to_ip, _ = load_leases()
    ip_to_mac    = {ip: mac for mac, ip in mac_to_ip.items()}
    fp_all       = load_fp_all()
    fp_doms      = list(fp_all.get("domains", {}).keys())
    fp_orgs      = list(fp_all.get("orgs", {}).keys())
    fp_macs      = {m.lower() for m in fp_all.get("devices", {}).keys()}

    filtered = []
    for c in payload["candidates"]:
        c["src"] = c["src"].replace("::ffff:", "")
        c["dst"] = c["dst"].replace("::ffff:", "")
        if _fp_domain_match(c.get("sni", ""), fp_doms):
            continue
        if _fp_domain_match(c["dst"], fp_doms):
            continue
        # HTTP-side FP: any Host header observed on this dst being FP'd is
        # enough — shared CDN IPs serve many hosts and one match is a
        # strong "this dst is benign" signal.
        if any(_fp_domain_match(h, fp_doms)
               for h in c.get("http_hosts", []) or []):
            continue
        # Org FP — fnmatch against GeoIP ASN owner; the only handle for
        # rows with no SNI, no HTTP Host, no DNS resolution.
        if _fp_domain_match(c.get("dst_org", ""), fp_orgs):
            continue
        src_mac = ip_to_mac.get(c["src"], "").lower()
        if src_mac and src_mac in fp_macs:
            continue
        filtered.append(c)
    return filtered, payload


def slow_beacon_summary():
    """Counts for the dashboard tile.  `eligible` is the would-Slack count
    (sole LAN talker AND non-hyperscaler dst); `total` is the broader
    hunt surface that survives FPs."""
    filtered, _ = _load_slow_cadence_filtered()
    eligible = sum(1 for c in filtered if c.get("alert_eligible"))
    return {"total": len(filtered), "eligible": eligible}


@app.route("/beacons/slow")
def beacons_slow():
    """Multi-day low-rate beacon candidates — fills RITA's sleep-cycle blind
    spot. Reads the JSON written by scripts/slow-cadence.py."""
    _, ip_to_host = load_leases()
    assets = {}
    try:
        with open(ASSETS_FILE) as f:
            assets = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    filtered, payload = _load_slow_cadence_filtered()

    for c in filtered:
        c["src_label"] = ip_label(c["src"], ip_to_host, assets)
        # GeoIP enrichment now comes from the detector (it has both DBs and
        # also computes the alert-eligibility flag). Fall back to live
        # lookup only for older JSON payloads that pre-date the change.
        if "dst_org" not in c or "dst_cc" not in c:
            cc, _city, org = _geoip_info(c["dst"])
            c["dst_org"] = org or ""
            c["dst_cc"]  = cc  or ""
        c["intel"] = ip_intel(c["dst"]) or None

    # Group by source. Sort groups so the ones with alert-eligible rows
    # come first (those are the "real" findings worth eyeballing); within
    # that, biggest groups first so high-impact FP-src buttons surface.
    # Inside each group, alert-eligible rows float to the top, then the
    # detector's suspicion order takes over.
    from collections import defaultdict
    by_src = defaultdict(list)
    for c in filtered:
        by_src[c["src"]].append(c)

    groups = []
    for src, rows in by_src.items():
        eligible = sum(1 for r in rows if r.get("alert_eligible"))
        rows.sort(key=lambda r: (
            0 if r.get("alert_eligible") else 1,
            -r["days_seen"],
            r["interval_cv"] if r["interval_cv"] is not None else 99,
        ))
        groups.append({
            "src":            src,
            "src_label":      rows[0]["src_label"],
            "count":          len(rows),
            # Distinct destination IPs — a row is per (dst, dst_port), so one
            # dst hit on several ports inflates `count`; the badge needs this.
            "dst_count":      len({r["dst"] for r in rows}),
            "eligible_count": eligible,
            "rows":           rows,
        })
    groups.sort(key=lambda g: (-g["eligible_count"], -g["count"], g["src"]))

    payload["candidates"]     = filtered
    payload["groups"]         = groups
    payload["eligible_total"] = sum(g["eligible_count"] for g in groups)

    return render_template("slow_beacons.html", payload=payload)


@app.route("/suricata")
def suricata():
    now = time.time()
    if _suricata_cache["payload"] and now - _suricata_cache["ts"] < _SURICATA_CACHE_TTL:
        return _suricata_cache["payload"]

    _, ip_to_host = load_leases()
    week_alerts  = parse_fast_log(days=7)
    today        = date.today()
    today_alerts = [a for a in week_alerts if a["ts"].date() == today]
    eve_events   = parse_eve_json_today()
    sig_list, lan_rows, unresolved, total_alerts = build_suricata_data(ip_to_host, alerts=today_alerts)
    extras = build_suricata_extras(ip_to_host, today_alerts=today_alerts, week_alerts=week_alerts, eve_events=eve_events)
    rendered = render_template(
        "suricata.html",
        sig_list=sig_list,
        lan_rows=lan_rows,
        unresolved=unresolved,
        total_alerts=total_alerts,
        extras=extras,
    )
    _suricata_cache["ts"] = now
    _suricata_cache["payload"] = rendered
    return rendered


@app.route("/suricata/rules")
def suricata_rules():
    return render_template("rules.html",
                           local_rules=_parse_local_rules(),
                           et_stats=_et_ruleset_stats())


@app.route("/suricata/rules/add", methods=["POST"])
def suricata_rules_add():
    rule = request.form.get("rule", "").strip()
    if rule:
        msg, ok = _local_rules_add(rule)
        return jsonify({"ok": ok, "msg": msg})
    return jsonify({"ok": False, "msg": "No rule provided"})


@app.route("/suricata/rules/toggle", methods=["POST"])
def suricata_rules_toggle():
    sid = request.form.get("sid", "").strip()
    if sid:
        msg, ok = _local_rules_toggle(sid)
        return jsonify({"ok": ok, "msg": msg})
    return jsonify({"ok": False, "msg": "No SID provided"})


@app.route("/suricata/rules/delete", methods=["POST"])
def suricata_rules_delete():
    sid = request.form.get("sid", "").strip()
    if sid:
        msg, ok = _local_rules_delete(sid)
        return jsonify({"ok": ok, "msg": msg})
    return jsonify({"ok": False, "msg": "No SID provided"})


@app.route("/suricata/rules/search")
def suricata_rules_search():
    q = request.args.get("q", "").strip().lower()
    if not q or len(q) < 3:
        return jsonify([])
    results = []
    try:
        with open(ET_RULES) as f:
            for line in f:
                if q in line.lower():
                    results.append(line.rstrip())
                    if len(results) >= 50:
                        break
    except OSError:
        pass
    return jsonify(results)


@app.route("/suricata/rules/update", methods=["POST"])
def suricata_rules_update():
    sid     = request.form.get("sid", "").strip()
    new_rule = request.form.get("rule", "").strip()
    if sid and new_rule:
        msg, ok = _local_rules_update(sid, new_rule)
        return jsonify({"ok": ok, "msg": msg})
    return jsonify({"ok": False, "msg": "Missing sid or rule"})


def _parse_local_rules():
    """Return list of dicts: {sid, enabled, action, msg, classtype, raw}."""
    rules = []
    try:
        text = LOCAL_RULES.read_text()
    except OSError:
        return rules
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            # Could be a disabled rule: #alert ...
            candidate = stripped.lstrip("#").strip()
            if candidate.startswith(("alert ", "drop ", "pass ", "reject ")):
                rules.append(_parse_rule_line(candidate, enabled=False, raw=line))
            continue
        if stripped.split()[0] in ("alert", "drop", "pass", "reject"):
            rules.append(_parse_rule_line(stripped, enabled=True, raw=line))
    return rules


def _parse_rule_line(text, enabled, raw):
    sid_m   = re.search(r'\bsid\s*:\s*(\d+)', text)
    msg_m   = re.search(r'\bmsg\s*:\s*"([^"]*)"', text)
    cls_m   = re.search(r'\bclasstype\s*:\s*(\S+?)\s*[;)]', text)
    action  = text.split()[0] if text else "alert"
    return {
        "sid":       sid_m.group(1) if sid_m else "?",
        "enabled":   enabled,
        "action":    action,
        "msg":       msg_m.group(1) if msg_m else text[:80],
        "classtype": cls_m.group(1).rstrip(";") if cls_m else "",
        "raw":       text.strip(),
    }


def _next_local_sid():
    """Return one above the highest sid: found in local.rules."""
    max_sid = 1000029
    try:
        for m in re.finditer(r'\bsid\s*:\s*(\d+)', LOCAL_RULES.read_text()):
            max_sid = max(max_sid, int(m.group(1)))
    except OSError:
        pass
    return max_sid + 1


def _local_rules_add(rule):
    """Append a rule to local.rules and reload Suricata. Returns (msg, ok)."""
    # Basic sanity: must have sid: or we assign one
    if "sid:" not in rule and "sid :" not in rule:
        sid = _next_local_sid()
        # Insert before the closing ) if it ends with );
        if rule.rstrip().endswith(";)"):
            rule = rule.rstrip()[:-2] + f" sid:{sid}; rev:1;)"
        else:
            rule = rule.rstrip().rstrip(")").rstrip() + f" sid:{sid}; rev:1;)"
    try:
        with open(LOCAL_RULES, "a") as f:
            f.write("\n" + rule + "\n")
    except OSError as e:
        return str(e), False
    return _reload_suricata_rules()


def _local_rules_toggle(sid):
    """Comment out or uncomment the rule with the given SID."""
    try:
        lines = LOCAL_RULES.read_text().splitlines(keepends=True)
    except OSError as e:
        return str(e), False

    new_lines = []
    found = False
    sid_pat = re.compile(r'\bsid\s*:\s*' + re.escape(sid) + r'\b')
    for line in lines:
        core = line.strip().lstrip("#").strip()
        if sid_pat.search(core):
            found = True
            if line.strip().startswith("#"):
                new_lines.append(core + "\n")   # enable: remove leading #
            else:
                new_lines.append("#" + line)     # disable: add leading #
        else:
            new_lines.append(line)

    if not found:
        return f"SID {sid} not found", False
    LOCAL_RULES.write_text("".join(new_lines))
    return _reload_suricata_rules()


def _local_rules_delete(sid):
    """Remove the rule with the given SID entirely."""
    try:
        lines = LOCAL_RULES.read_text().splitlines(keepends=True)
    except OSError as e:
        return str(e), False

    sid_pat = re.compile(r'\bsid\s*:\s*' + re.escape(sid) + r'\b')
    new_lines = [l for l in lines if not sid_pat.search(l.lstrip("#").strip())]
    if len(new_lines) == len(lines):
        return f"SID {sid} not found", False
    LOCAL_RULES.write_text("".join(new_lines))
    return _reload_suricata_rules()


def _local_rules_update(sid, new_rule):
    """Replace the line containing the given SID with new_rule."""
    try:
        lines = LOCAL_RULES.read_text().splitlines(keepends=True)
    except OSError as e:
        return str(e), False

    sid_pat = re.compile(r'\bsid\s*:\s*' + re.escape(sid) + r'\b')
    new_lines = []
    found = False
    for line in lines:
        if sid_pat.search(line.lstrip("#").strip()):
            found = True
            new_lines.append(new_rule.rstrip() + "\n")
        else:
            new_lines.append(line)

    if not found:
        return f"SID {sid} not found", False
    LOCAL_RULES.write_text("".join(new_lines))
    return _reload_suricata_rules()


def _reload_suricata_rules():
    """Signal Suricata to reload rules. Returns (msg, ok)."""
    try:
        r = subprocess.run(
            ["sudo", "/usr/bin/suricatasc", "-c", "reload-rules"],
            capture_output=True, text=True, timeout=15
        )
        if r.returncode == 0 and '"return": "OK"' in r.stdout:
            return "Rules saved and reloaded.", True
        err = (r.stdout + r.stderr).strip()
        return f"Saved but reload failed: {err}", False
    except Exception as e:
        return f"Saved but reload failed: {e}", False


def _et_ruleset_stats():
    """Return dict with count, size_mb, modified for the ET ruleset."""
    try:
        stat = ET_RULES.stat()
        count = sum(
            1 for line in ET_RULES.open()
            if line.strip() and not line.startswith("#")
        )
        return {
            "count":    count,
            "size_mb":  round(stat.st_size / 1024 / 1024, 1),
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
        }
    except OSError:
        return {"count": 0, "size_mb": 0, "modified": "unknown"}


@app.route("/network")
def network():
    _, ip_to_host = load_leases()
    assets = {}
    try:
        with open(ASSETS_FILE) as f:
            assets = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    intel = build_network_intel(ip_to_host, assets)
    return render_template("network.html", intel=intel)


ASSETS_HISTORY_FILE = Path("/var/lib/beaconbutty/assets-history.json")


@app.route("/assets")
def assets():
    data = {}
    try:
        with open(ASSETS_FILE) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    # Apply manual hostname overrides — for devices assets.sh cannot identify
    # (no DHCP hostname, locally-administered MAC, etc.) the user curates a
    # name in /var/lib/beaconbutty/device-names.json. Fills the gap
    # non-destructively: real hostnames from dnsmasq still win.
    overrides = load_device_names()
    for ip, info in data.items():
        if not info.get("hostname") and ip in overrides:
            info["hostname"]        = overrides[ip]
            info["hostname_source"] = "manual"
        info["ghost"] = False

    # Merge in "ghost" entries — devices seen in the last 14 days that aren't
    # currently live. Keeps Assets coherent with the multi-day Slow-Cadence
    # view: a laptop that disappeared mid-window is still findable here.
    try:
        with open(ASSETS_HISTORY_FILE) as f:
            history = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        history = {}
    for ip, info in history.items():
        if ip in data:
            continue
        last = info.get("last_seen", "")
        if not last:
            continue
        try:
            d = date.fromisoformat(last)
            days_ago = (date.today() - d).days
        except ValueError:
            continue
        # days_ago == 0 is a valid ghost: present at the morning assets run
        # but gone from the live set now (the `ip in data` check above
        # already excluded currently-live devices).
        if days_ago < 0 or days_ago > 14:
            continue
        ghost = dict(info)
        ghost["ghost"]       = True
        ghost["days_ago"]    = days_ago
        if not ghost.get("hostname") and ip in overrides:
            ghost["hostname"]        = overrides[ip]
            ghost["hostname_source"] = "manual"
        data[ip] = ghost

    def _ip_sort_key(ip):
        try:
            return tuple(int(x) for x in ip.split("."))
        except Exception:
            return (999, 999, 999, 999)

    sorted_assets = sorted(data.items(), key=lambda kv: _ip_sort_key(kv[0]))
    fp_macs = set(load_fps().keys())  # set of registered FP MAC addresses

    # Attach a JA4 summary to each row — pulled from the persistent history
    # file plus today's live ssl.log. Empty for devices with no TLS observed.
    ja4_summaries = {ip: ja4_summary_for_ip(ip) for ip, _ in sorted_assets}

    return render_template(
        "assets.html",
        assets=sorted_assets,
        fp_macs=fp_macs,
        ja4_summaries=ja4_summaries,
        ja4_threat_fade_days=JA4_THREAT_FADE_DAYS,
    )


@app.route("/fps")
def fps():
    mac_to_ip, ip_to_host = load_leases()
    fp_all = load_fp_all()
    device_rows = []
    for mac, reason in sorted(fp_all["devices"].items()):
        ip = mac_to_ip.get(mac, "")
        device_rows.append({
            "mac":    mac,
            "ip":     ip,
            "label":  ip_label(ip, ip_to_host) if ip else "",
            "reason": reason,
        })
    domain_rows   = [{"pattern": p, "reason": r} for p, r in sorted(fp_all["domains"].items())]
    protocol_rows = [{"svc": s, "reason": r} for s, r in sorted(fp_all["protocols"].items())]
    org_rows      = [{"pattern": p, "reason": r} for p, r in sorted(fp_all["orgs"].items())]
    return render_template("fps.html",
                           rows=device_rows,
                           domain_rows=domain_rows,
                           protocol_rows=protocol_rows,
                           org_rows=org_rows)


@app.route("/fps/add", methods=["POST"])
def fps_add():
    addr   = request.form.get("addr", "").strip()
    reason = request.form.get("reason", "").strip()
    nxt    = request.form.get("next", "").strip()

    if not addr or not reason:
        return redirect(url_for("fps"))
    if len(reason) > 50:
        reason = reason[:50]
    if not (_MAC_RE.match(addr) or _IP_RE.match(addr)):
        return redirect(url_for("fps"))

    _run_fp_script("add", addr, reason)
    if nxt.startswith("/") and not nxt.startswith("//"):
        return redirect(nxt)
    return redirect(url_for("fps"))


@app.route("/fps/remove", methods=["POST"])
def fps_remove():
    mac = request.form.get("mac", "").strip()
    if _MAC_RE.match(mac):
        _run_fp_script("remove", mac)
    return redirect(url_for("fps"))


@app.route("/fps/add-domain", methods=["POST"])
def fps_add_domain():
    pattern = request.form.get("pattern", "").strip()
    reason  = request.form.get("reason", "").strip()
    nxt     = request.form.get("next", "").strip()
    if pattern and reason:
        if len(reason) > 50:
            reason = reason[:50]
        _run_fp_script("add-domain", pattern, reason)
    # Only honour same-origin paths to prevent open-redirect.
    if nxt.startswith("/") and not nxt.startswith("//"):
        return redirect(nxt)
    return redirect(url_for("fps"))


@app.route("/fps/remove-domain", methods=["POST"])
def fps_remove_domain():
    pattern = request.form.get("pattern", "").strip()
    if pattern:
        _run_fp_script("remove-domain", pattern)
    return redirect(url_for("fps"))


@app.route("/fps/add-protocol", methods=["POST"])
def fps_add_protocol():
    svc    = request.form.get("svc", "").strip()
    reason = request.form.get("reason", "").strip()
    if svc and reason:
        if len(reason) > 50:
            reason = reason[:50]
        _run_fp_script("add-protocol", svc, reason)
    return redirect(url_for("fps"))


@app.route("/fps/remove-protocol", methods=["POST"])
def fps_remove_protocol():
    svc = request.form.get("svc", "").strip()
    if svc:
        _run_fp_script("remove-protocol", svc)
    return redirect(url_for("fps"))


@app.route("/fps/add-org", methods=["POST"])
def fps_add_org():
    """Add an org-level FP — fnmatch against GeoIP ASN owner."""
    pattern = request.form.get("pattern", "").strip()
    reason  = request.form.get("reason", "").strip()
    nxt     = request.form.get("next", "").strip()
    if pattern and reason:
        if len(reason) > 50:
            reason = reason[:50]
        _run_fp_script("add-org", pattern, reason)
    if nxt.startswith("/") and not nxt.startswith("//"):
        return redirect(nxt)
    return redirect(url_for("fps"))


@app.route("/fps/remove-org", methods=["POST"])
def fps_remove_org():
    pattern = request.form.get("pattern", "").strip()
    if pattern:
        _run_fp_script("remove-org", pattern)
    return redirect(url_for("fps"))


# ── API routes ──────────────────────────────────────────────────────────────────

def get_cert_info():
    """Read TLS cert and return subject, issue date, expiry date, days remaining."""
    try:
        with open(TLS_FULLCHAIN, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        now = datetime.now(cert.not_valid_after_utc.tzinfo)
        days_remaining = (cert.not_valid_after_utc - now).days
        return {
            "subject":        cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
            "issued":         cert.not_valid_before_utc.strftime("%Y-%m-%d"),
            "expires":        cert.not_valid_after_utc.strftime("%Y-%m-%d"),
            "days_remaining": days_remaining,
        }
    except Exception as e:
        return {"error": str(e)}


@app.route("/health")
def health():
    import subprocess
    report = None
    error = None
    try:
        result = subprocess.run(
            ["sudo", "/usr/local/bin/beaconbutty-health.sh", "--json"],
            capture_output=True, text=True, timeout=30
        )
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            error = (result.stderr or result.stdout or "empty output").strip()

        if report is not None:
            failures = [c['message'] for s in report['sections']
                        for c in s['checks'] if c['status'] == 'fail']
            warnings = [c['message'] for s in report['sections']
                        for c in s['checks'] if c['status'] == 'warn']
            has_issues = result.returncode != 0 or bool(failures)
            status = {
                'last_check': datetime.now().isoformat(timespec='seconds'),
                'exit_code':  result.returncode,
                'status':     'issues' if has_issues else 'ok',
                'failures':   failures,
                'warnings':   warnings,
                'led_alert':  has_issues,
            }
            try:
                _write_json_atomic(HEALTH_STATUS_FILE, status, indent=2)
            except Exception:
                pass
    except Exception as e:
        error = f"Error running health check: {e}"
    gate_stats = None
    try:
        with open("/var/lib/beaconbutty/reports/alert-gate-stats.json") as f:
            gate_stats = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return render_template("health.html", report=report, error=error,
                           alert_config=load_alert_config(),
                           cert=get_cert_info(),
                           gate_stats=gate_stats,
                           teams_detector_config=load_teams_detector_config(),
                           teams_detector_report=load_teams_detector_report())


ALERT_CONFIG_PATH = "/var/lib/beaconbutty/alert-config.json"

ALERT_TYPES = [
    "service_down",
    "disk_critical",
    "high_score_beacon",
    "persistent_beacon",
    "threat_intel_hit",
    "tor_contact",
    "suricata_p1_lan",
    "suricata_p1_repeated",
    "new_device",
    "slow_cadence_digest",
    "slow_cadence_beacon",
    "gateway_impersonation",
    "config_invalid",
    "config_stray_files",
    "health_check_fail",
    "sustained_high_cpu",
    "teams_relay_anomaly",
]

def load_alert_config():
    try:
        with open(ALERT_CONFIG_PATH) as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}
    enabled = cfg.get("enabled", {})
    # Default: all types enabled
    return {t: enabled.get(t, True) for t in ALERT_TYPES}


def save_alert_config(enabled):
    _write_json_atomic(ALERT_CONFIG_PATH, {"enabled": enabled}, indent=2)


@app.route("/api/alert-config", methods=["GET"])
def api_alert_config_get():
    return {"enabled": load_alert_config()}


@app.route("/api/alert-config", methods=["POST"])
def api_alert_config_set():
    data = request.get_json(force=True) or {}
    alert_type = data.get("type")
    enabled_val = data.get("enabled")
    if alert_type not in ALERT_TYPES or not isinstance(enabled_val, bool):
        return {"ok": False, "message": "Invalid request"}, 400
    cfg = load_alert_config()
    cfg[alert_type] = enabled_val
    save_alert_config(cfg)
    return {"ok": True}


# ── Teams-relay detector config ───────────────────────────────────────────────
TEAMS_DETECTOR_CONFIG_PATH = "/var/lib/beaconbutty/teams-detector-config.json"
TEAMS_DETECTOR_REPORT_PATH = "/var/lib/beaconbutty/reports/teams-relay.json"
TEAMS_DETECTOR_DEFAULTS = {
    "enabled":               True,
    "max_duration_hours":    2.0,
    "min_kbps":              30.0,
    "min_flow_seconds":      300,
    "max_alerts_per_device": 5,
}

def load_teams_detector_config():
    try:
        with open(TEAMS_DETECTOR_CONFIG_PATH) as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}
    out = dict(TEAMS_DETECTOR_DEFAULTS)
    for k in out:
        if k in cfg:
            out[k] = cfg[k]
    return out


def save_teams_detector_config(cfg):
    out = dict(TEAMS_DETECTOR_DEFAULTS)
    out.update({k: v for k, v in cfg.items() if k in TEAMS_DETECTOR_DEFAULTS})
    _write_json_atomic(TEAMS_DETECTOR_CONFIG_PATH, out, indent=2)


def load_teams_detector_report():
    try:
        with open(TEAMS_DETECTOR_REPORT_PATH) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


@app.route("/api/teams-detector/config", methods=["GET"])
def api_teams_detector_config_get():
    return {"config": load_teams_detector_config(),
            "report": load_teams_detector_report()}


@app.route("/api/teams-detector/config", methods=["POST"])
def api_teams_detector_config_set():
    data = request.get_json(force=True) or {}
    cfg = load_teams_detector_config()
    # Type coercion + range guards keep webapp errors local rather than
    # corrupting the JSON file the detector reads.
    try:
        if "enabled" in data:
            cfg["enabled"] = bool(data["enabled"])
        if "max_duration_hours" in data:
            v = float(data["max_duration_hours"])
            if not (0.1 <= v <= 24.0):
                return {"ok": False, "message": "max_duration_hours must be 0.1–24.0"}, 400
            cfg["max_duration_hours"] = v
        if "min_kbps" in data:
            v = float(data["min_kbps"])
            if not (0.0 <= v <= 10000.0):
                return {"ok": False, "message": "min_kbps must be 0–10000"}, 400
            cfg["min_kbps"] = v
        if "min_flow_seconds" in data:
            v = int(data["min_flow_seconds"])
            if not (1 <= v <= 3600):
                return {"ok": False, "message": "min_flow_seconds must be 1–3600"}, 400
            cfg["min_flow_seconds"] = v
    except (TypeError, ValueError) as e:
        return {"ok": False, "message": f"Invalid value: {e}"}, 400
    save_teams_detector_config(cfg)
    return {"ok": True, "config": cfg}


@app.route("/api/alert-test", methods=["POST"])
def api_alert_test():
    import subprocess, uuid
    from datetime import datetime, timezone
    # Include timestamp + random token so the fingerprint is always unique
    # and the Lambda dedup window never suppresses it.
    token = uuid.uuid4().hex[:8]
    ts    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    detail = f"Manual test from webapp — {ts} [{token}]"
    try:
        result = subprocess.run(
            ["/usr/local/bin/beaconbutty-alert.sh",
             "service_down", "low", "bb0", detail],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            return {"ok": True, "message": result.stdout.strip()}
        else:
            return {"ok": False, "message": result.stderr.strip() or result.stdout.strip()}, 500
    except Exception as e:
        return {"ok": False, "message": str(e)}, 500


SLACK_CONFIG_PATH = "/var/lib/beaconbutty/slack-config.json"

@app.route("/api/slack-message-count", methods=["GET"])
def api_slack_message_count():
    try:
        with open(SLACK_CONFIG_PATH) as f:
            cfg = json.load(f)
        token   = cfg["token"]
        channel = cfg["channel"]
    except Exception as e:
        return {"ok": False, "message": f"Could not read Slack config: {e}"}, 500
    try:
        from slack_cleaner2 import SlackCleaner, match
        # slack_cleaner2 exposes no timeout — bound its sockets or a
        # black-holed slack.com parks this request thread forever.
        import socket
        _old_to = socket.getdefaulttimeout()
        socket.setdefaulttimeout(30)
        try:
            s = SlackCleaner(token)
            count = sum(1 for _ in s.msgs(filter(match(channel), s.channels)))
        finally:
            socket.setdefaulttimeout(_old_to)
        return {"ok": True, "count": count, "has_more": False, "channel": channel}
    except Exception as e:
        return {"ok": False, "message": str(e)}, 500


@app.route("/api/slack-clear-channel", methods=["POST"])
def api_slack_clear_channel():
    try:
        with open(SLACK_CONFIG_PATH) as f:
            cfg = json.load(f)
        token   = cfg["token"]
        channel = cfg["channel"]
    except Exception as e:
        return {"ok": False, "message": f"Could not read Slack config: {e}"}, 500
    try:
        from slack_cleaner2 import SlackCleaner, match
        import socket
        _old_to = socket.getdefaulttimeout()
        socket.setdefaulttimeout(30)
        try:
            s = SlackCleaner(token)
            deleted = 0
            for msg in s.msgs(filter(match(channel), s.channels)):
                msg.delete()
                deleted += 1
        finally:
            socket.setdefaulttimeout(_old_to)
        return {"ok": True, "message": f"Deleted {deleted} message{'s' if deleted != 1 else ''} from #{channel}"}
    except Exception as e:
        return {"ok": False, "message": str(e)}, 500


@app.route("/api/domain-watch/config", methods=["GET"])
def api_domain_watch_config_get():
    return load_domain_watch_config()


@app.route("/api/domain-watch/config", methods=["POST"])
def api_domain_watch_config_set():
    """Set the full list. Body: {"domains": [...]}."""
    data = request.get_json(silent=True) or {}
    domains = data.get("domains")
    if domains is None and "domain" in data:
        # Legacy single-domain caller — accept and migrate.
        d = (data.get("domain") or "").strip()
        domains = [d] if d else []
    if not isinstance(domains, list):
        return {"ok": False, "message": "Expected 'domains' array"}, 400
    for d in domains:
        if not isinstance(d, str) or len(d) > 253:
            return {"ok": False, "message": "Bad domain entry"}, 400
    try:
        cleaned = save_domain_watch_config(domains)
    except Exception as e:
        return {"ok": False, "message": str(e)}, 500
    return {"ok": True, "domains": cleaned}


@app.route("/api/domain-watch/data", methods=["GET"])
def api_domain_watch_data():
    """Return per-domain activity buckets. Caller can request a specific
    domain via ?domain=… (used by the Health-page card to show one card per
    watched domain). Without the query, returns the first domain (back-compat
    with older clients)."""
    cfg = load_domain_watch_config()
    domains = cfg["domains"]
    requested = (request.args.get("domain") or "").strip().lower()
    if requested and requested not in domains:
        # Allow ad-hoc lookup of a domain not in the current watch set —
        # useful when investigating without committing to capture.
        domains = [requested]
    elif requested:
        domains = [requested]
    if not domains:
        now = int(time.time())
        return {"ok": True, "domain": "", "buckets": [],
                "window_start": now - 6 * 3600, "window_end": now}

    domain = domains[0]
    try:
        buckets, start, end = _scan_domain_activity(domain)
    except Exception as e:
        return {"ok": False, "message": str(e)}, 500
    return {"ok": True, "domain": domain, "buckets": buckets,
            "window_start": start, "window_end": end}


# ── Triggered PCAP capture API ────────────────────────────────────────────────
#
# The bb-pcap-watch daemon owns the actual capture; this is just the UI side.
# Add/remove a domain by mutating domain-watch.json (the daemon polls mtime).
# Snapshot/clear/view are pure filesystem ops on /var/lib/beaconbutty/pcaps/.

PCAP_DOMAIN_RE = re.compile(r"^[a-z0-9.-]{1,253}$")


def _pcap_sanitise(domain: str) -> str:
    return re.sub(r"[^a-z0-9.-]", "_", domain.lower())[:120]


def _pcap_dir_for(domain: str) -> Path:
    return PCAP_ROOT / _pcap_sanitise(domain)


def _pcap_files_for(domain: str) -> list[Path]:
    d = _pcap_dir_for(domain)
    if not d.is_dir():
        return []
    return sorted(d.glob("*.pcap"))


def _pcap_capture_status(domain: str) -> dict:
    files = _pcap_files_for(domain)
    if not files:
        return {"files": 0, "bytes": 0, "oldest_ts": 0, "newest_ts": 0}
    sizes = []
    oldest = newest = 0.0
    for f in files:
        try:
            st = f.stat()
        except OSError:
            continue
        sizes.append(st.st_size)
        if oldest == 0 or st.st_mtime < oldest:
            oldest = st.st_mtime
        if st.st_mtime > newest:
            newest = st.st_mtime
    return {
        "files":     len(sizes),
        "bytes":     sum(sizes),
        "oldest_ts": int(oldest),
        "newest_ts": int(newest),
    }


def _pcap_snapshots() -> list[dict]:
    if not PCAP_SNAPSHOT_DIR.is_dir():
        return []
    out = []
    for f in sorted(PCAP_SNAPSHOT_DIR.glob("*.pcap.gz"), reverse=True):
        try:
            st = f.stat()
        except OSError:
            continue
        out.append({
            "name":  f.name,
            "bytes": st.st_size,
            "ts":    int(st.st_mtime),
        })
    return out


@app.route("/api/pcap/state", methods=["GET"])
def api_pcap_state():
    cfg = load_domain_watch_config()
    domains = cfg["domains"]
    captures = {d: _pcap_capture_status(d) for d in domains}
    return {
        "ok":           True,
        "domains":      domains,
        "max_domains":  DOMAIN_WATCH_MAX,
        "captures":     captures,
        "snapshots":    _pcap_snapshots(),
    }


@app.route("/api/pcap/watch", methods=["POST"])
def api_pcap_watch():
    """Add a domain to the watch list. Idempotent. Daemon picks up via
    mtime poll. The daemon itself wipes any leftover PCAP dir on add, so
    the user always gets a clean ring on (re-)watch."""
    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip().lower()
    if not domain or not PCAP_DOMAIN_RE.match(domain):
        return {"ok": False, "message": "Invalid domain"}, 400
    domains = load_domain_watch_config()["domains"]
    if domain in domains:
        return {"ok": True, "domains": domains}
    if len(domains) >= DOMAIN_WATCH_MAX:
        return {"ok": False, "message":
                f"Max {DOMAIN_WATCH_MAX} domains already watched"}, 400
    domains.append(domain)
    cleaned = save_domain_watch_config(domains)
    return {"ok": True, "domains": cleaned}


@app.route("/api/pcap/unwatch", methods=["POST"])
def api_pcap_unwatch():
    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip().lower()
    domains = [d for d in load_domain_watch_config()["domains"] if d != domain]
    cleaned = save_domain_watch_config(domains)
    return {"ok": True, "domains": cleaned}


@app.route("/api/pcap/snapshot", methods=["POST"])
def api_pcap_snapshot():
    """Concat the current rolling ring for `domain` into one gzipped pcap
    under pcaps/snapshots/. Survives Stop / Clear."""
    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip().lower()
    if not PCAP_DOMAIN_RE.match(domain):
        return {"ok": False, "message": "Invalid domain"}, 400
    files = _pcap_files_for(domain)
    if not files:
        return {"ok": False, "message": "No PCAP data to snapshot"}, 404
    PCAP_SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    name = f"{_pcap_sanitise(domain)}-{datetime.now().strftime('%Y%m%dT%H%M%S')}.pcap.gz"
    out_path = PCAP_SNAPSHOT_DIR / name
    # Unique per request — a pid-keyed name is identical for every thread of
    # this single Flask process, so concurrent snapshots would clobber and
    # unlink each other's merge output.
    fd, tmp_name = tempfile.mkstemp(prefix="bb-pcap-snap-", suffix=".pcap")
    os.close(fd)
    merged = Path(tmp_name)
    try:
        r = subprocess.run(
            ["mergecap", "-w", str(merged), *[str(f) for f in files]],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            return {"ok": False, "message": f"mergecap failed: {r.stderr.strip()}"}, 500
        with merged.open("rb") as fin, gzip.open(out_path, "wb") as fout:
            shutil.copyfileobj(fin, fout)
    finally:
        merged.unlink(missing_ok=True)
    return {"ok": True, "name": name, "bytes": out_path.stat().st_size}


@app.route("/pcap/snapshot-download", methods=["GET"])
def pcap_snapshot_download():
    name = (request.args.get("name") or "").strip()
    if not name or "/" in name or not name.endswith(".pcap.gz"):
        return ("Invalid snapshot name", 400)
    target = PCAP_SNAPSHOT_DIR / name
    if not target.is_file():
        return ("Not found", 404)
    return send_file(
        str(target),
        mimetype="application/gzip",
        as_attachment=True,
        download_name=name,
    )


@app.route("/api/pcap/snapshot-delete", methods=["POST"])
def api_pcap_snapshot_delete():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name or "/" in name or not name.endswith(".pcap.gz"):
        return {"ok": False, "message": "Invalid snapshot name"}, 400
    target = PCAP_SNAPSHOT_DIR / name
    if not target.is_file():
        return {"ok": False, "message": "Not found"}, 404
    target.unlink()
    return {"ok": True}


@app.route("/api/pcap/clear-all", methods=["POST"])
def api_pcap_clear_all():
    """Stop ALL captures and delete the rolling pcaps. Snapshots untouched.
    Implemented by emptying the watch list (the daemon does the actual
    cleanup as it reconciles)."""
    save_domain_watch_config([])
    return {"ok": True}


@app.route("/api/pcap/view", methods=["GET"])
def api_pcap_view():
    """View modes: conv | packets | decode | download.

    For conv/packets/decode, returns text/plain.
    For download, streams the merged .pcap file.
    """
    domain = (request.args.get("domain") or "").strip().lower()
    mode   = (request.args.get("mode")   or "conv").strip().lower()
    frame  = (request.args.get("frame")  or "1").strip()
    if not PCAP_DOMAIN_RE.match(domain):
        return ("Invalid domain", 400)
    if mode not in ("conv", "packets", "decode", "download"):
        return ("Invalid mode", 400)
    files = _pcap_files_for(domain)
    if not files:
        return ("No PCAP data yet for this domain.\n", 200,
                {"Content-Type": "text/plain; charset=utf-8"})

    fd, tmp_name = tempfile.mkstemp(prefix="bb-pcap-view-", suffix=".pcap")
    os.close(fd)
    merged = Path(tmp_name)
    try:
        r = subprocess.run(
            ["mergecap", "-w", str(merged), *[str(f) for f in files]],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode != 0:
            return (f"mergecap failed: {r.stderr.strip()}", 500)

        if mode == "download":
            resp = send_file(
                str(merged),
                mimetype="application/vnd.tcpdump.pcap",
                as_attachment=True,
                download_name=f"{_pcap_sanitise(domain)}.pcap",
            )
            # /tmp is RAM-backed tmpfs — deleting after the response streams
            # (not never) is what stops merged rings accumulating in memory.
            resp.call_on_close(lambda: merged.unlink(missing_ok=True))
            return resp

        if mode == "conv":
            cmd = ["tshark", "-r", str(merged),
                   "-q", "-z", "conv,tcp", "-z", "conv,udp"]
        elif mode == "packets":
            cmd = ["tshark", "-r", str(merged), "-c", "500"]
        else:  # decode
            try:
                fr = max(1, int(frame))
            except ValueError:
                fr = 1
            cmd = ["tshark", "-r", str(merged), "-V",
                   "-Y", f"frame.number=={fr}", "-c", "1"]

        rr = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        body = rr.stdout
        if rr.returncode != 0:
            body += "\n--- stderr ---\n" + (rr.stderr or "")
        return (body, 200, {"Content-Type": "text/plain; charset=utf-8"})
    finally:
        # download mode cleans up via call_on_close after streaming.
        if mode != "download":
            merged.unlink(missing_ok=True)


_DISPLAY_OFF_FLAG = Path("/var/lib/beaconbutty/display-off")


@app.route("/api/display", methods=["GET"])
def api_display_get():
    try:
        active = _DISPLAY_OFF_FLAG.read_text().strip() != "1"
    except Exception:
        active = True
    return {"active": active}


@app.route("/api/display", methods=["POST"])
def api_display_set():
    data = request.get_json(silent=True) or {}
    enable = bool(data.get("enable"))
    try:
        _DISPLAY_OFF_FLAG.write_text("0" if enable else "1")
        return {"ok": True, "active": enable}
    except Exception as e:
        return {"ok": False, "message": str(e)}, 500


_FAN_STATE_FILE    = Path("/var/lib/beaconbutty/watchdog/fan-state")
_FAN_OVERRIDE_FILE = Path("/var/lib/beaconbutty/watchdog/fan-override.json")
_FAN_OVERRIDE_TTL_MIN = 10
# Mirror of bb-watchdog's hysteresis; used on override-clear to decide the
# correct fan-state immediately, so the UI doesn't show a stale ON for up to
# one watchdog tick (60s).
_FAN_ON_TEMP  = 60.0
_FAN_OFF_TEMP = 55.0


def _pironman_reapply_auto():
    """On override clear, replicate bb-watchdog's hysteresis against the
    current CPU temp so fan-state flips immediately if it should."""
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            temp_c = int(f.read().strip()) / 1000.0
        try:
            current_on = _FAN_STATE_FILE.read_text().strip().lower() == "on"
        except Exception:
            current_on = False
        if not current_on and temp_c >= _FAN_ON_TEMP:
            _FAN_STATE_FILE.write_text("on")
        elif current_on and temp_c <= _FAN_OFF_TEMP:
            _FAN_STATE_FILE.write_text("off")
        # inside the hysteresis band: leave the current state alone
    except Exception:
        pass


@app.route("/api/pironman-fan", methods=["POST"])
def api_pironman_fan():
    """Manage the Pironman fan manual override.
    Body `{"state": "on"|"off"}` forces the fan for 10 minutes; `{"clear": true}`
    removes any active override so bb-watchdog resumes temperature-based control
    on its next tick."""
    data = request.get_json(silent=True) or {}
    if data.get("clear"):
        try:
            _FAN_OVERRIDE_FILE.unlink(missing_ok=True)
            _pironman_reapply_auto()
            return {"ok": True, "cleared": True}
        except Exception as e:
            return {"ok": False, "message": str(e)}, 500
    state = (data.get("state") or "").strip().lower()
    if state not in ("on", "off"):
        return {"ok": False, "message": "state must be 'on' or 'off', or send {clear: true}"}, 400
    expires = datetime.now() + timedelta(minutes=_FAN_OVERRIDE_TTL_MIN)
    try:
        _write_json_atomic(_FAN_OVERRIDE_FILE, {
            "state":   state,
            "expires": expires.isoformat(timespec="seconds"),
        })
        # Apply immediately so bb0-display flips GPIO within 0.5s; bb-watchdog
        # will re-assert on its next 60s tick and keep it until expiry.
        _FAN_STATE_FILE.write_text(state)
        return {"ok": True, "state": state, "expires": expires.isoformat(timespec="seconds")}
    except Exception as e:
        return {"ok": False, "message": str(e)}, 500


@app.route("/api/system")
def api_system():
    try:
        days = int(request.args.get("days", 1))
    except ValueError:
        days = 1
    days = max(1, min(days, 30))
    data = get_system_data(days)
    return jsonify(data)


# ── Memory consumers (current snapshot for the /system page) ─────────────────
#
# Friendly names + expected-RSS ceilings (MiB) for the processes we expect to
# dominate on bb0. Group RSS above the ceiling flags the row "high"; anything
# not listed shares a generic ceiling. Ceilings sit ~30% above the observed
# steady state (2026-07-12) so normal drift doesn't nag.
_MEM_KNOWN = [
    (re.compile(r"clickhouse-server"),          "ClickHouse",     3600),
    (re.compile(r"/usr/bin/suricata"),          "Suricata",       2000),
    (re.compile(r"/opt/zeek/bin/zeek"),         "Zeek",            800),
    (re.compile(r"webapp/app\.py"),             "Webapp (Flask)",  600),
    (re.compile(r"chroma-mcp|claude-mem"),      "claude-mem",      600),
    (re.compile(r"(^|/)claude( |$)"),           "Claude Code",    2000),
    (re.compile(r"tailscaled"),                 "Tailscale",       300),
    (re.compile(r"bb-watchdog|bb0-display"),    "Pi monitoring",   250),
    (re.compile(r"syncthing"),                  "Syncthing",       300),
    (re.compile(r"dnsmasq"),                    "dnsmasq",         100),
]
_MEM_GENERIC_CEILING_MB = 500
_MEM_LIST_FLOOR_MB      = 50   # hide the long tail of tiny processes


@app.route("/api/memory-consumers")
def api_memory_consumers():
    info = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, _, rest = line.partition(":")
            info[key] = int(rest.split()[0])   # kB
    except Exception:
        pass
    total_kb = info.get("MemTotal", 0)
    avail_kb = info.get("MemAvailable", 0)
    swap_used_kb = max(info.get("SwapTotal", 0) - info.get("SwapFree", 0), 0)

    # Per-process RSS grouped under friendly names. Unknown interpreters
    # (python3/bun/node scripts) group by script basename, not the binary.
    groups = {}
    try:
        out = subprocess.run(
            ["ps", "-eo", "rss=,args="],
            capture_output=True, text=True, timeout=10,
        )
        for line in out.stdout.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) != 2 or not parts[0].isdigit():
                continue
            rss_kb, args_str = int(parts[0]), parts[1]
            name, ceiling = None, _MEM_GENERIC_CEILING_MB
            for rx, label, ceil in _MEM_KNOWN:
                if rx.search(args_str):
                    name, ceiling = label, ceil
                    break
            if name is None:
                toks = args_str.split()
                exe = os.path.basename(toks[0])
                if exe.startswith(("python", "node", "bun", "bash", "sh", "perl")):
                    for t in toks[1:]:
                        if not t.startswith("-"):
                            exe = os.path.basename(t)
                            break
                name = exe
            g = groups.setdefault(name, {"rss_kb": 0, "ceiling_mb": ceiling, "procs": 0})
            g["rss_kb"] += rss_kb
            g["procs"] += 1
    except Exception:
        pass

    consumers = []
    for name, g in groups.items():
        rss_mb = g["rss_kb"] / 1024
        if rss_mb < _MEM_LIST_FLOOR_MB:
            continue
        consumers.append({
            "name":       name,
            "rss_mb":     round(rss_mb),
            "pct":        round(100 * g["rss_kb"] / total_kb, 1) if total_kb else None,
            "procs":      g["procs"],
            "status":     "high" if rss_mb > g["ceiling_mb"] else "ok",
            "ceiling_mb": g["ceiling_mb"],
        })
    consumers.sort(key=lambda c: -c["rss_mb"])

    # "Used" = total - MemAvailable, matching the graph's mem_pct definition
    # (reclaimable buff/cache doesn't count as used).
    avail_gb = avail_kb / 1048576
    overall = "ok" if avail_gb >= 1.0 else ("warn" if avail_gb >= 0.5 else "high")
    return jsonify({
        "total_mb":     round(total_kb / 1024),
        "used_mb":      round(max(total_kb - avail_kb, 0) / 1024),
        "available_mb": round(avail_kb / 1024),
        "swap_used_mb": round(swap_used_kb / 1024),
        "status":       overall,
        "consumers":    consumers[:12],
    })


@app.route("/api/temperature")
def api_temperature_legacy():
    return redirect(url_for("api_system", **request.args.to_dict()), code=301)


@app.route("/api/bandwidth")
def api_bandwidth():
    try:
        days = int(request.args.get("days", 1))
    except ValueError:
        days = 1
    days = max(1, min(days, 30))
    return jsonify(get_bandwidth_data(days))


@app.route("/api/bandwidth/device-destinations")
def api_bandwidth_device_destinations():
    src_ip = (request.args.get("ip") or "").strip()
    # Cheap sanity check — keep arbitrary input out of the SQL.
    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", src_ip):
        return jsonify([])
    direction = request.args.get("direction", "down")
    try:
        days = int(request.args.get("days", 1))
    except ValueError:
        days = 1
    days = max(1, min(days, 30))
    return jsonify(get_bandwidth_device_destinations(src_ip, days, direction))


@app.route("/api/stats")
def api_stats():
    stats = get_system_stats()
    return jsonify(stats)


# ── Backup ──────────────────────────────────────────────────────────────────────

def _list_backups():
    """Return sorted list of config snapshot dicts (newest first)."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    entries = []
    for p in sorted(BACKUP_DIR.glob("config-*.tar.gz"), reverse=True):
        stat = p.stat()
        size_mb = stat.st_size / (1024 * 1024)
        size_str = f"{size_mb:.1f} MB" if size_mb >= 1 else f"{stat.st_size // 1024} KB"
        mtime_str = datetime.fromtimestamp(stat.st_mtime).strftime("%H:%M")
        ds = p.name.replace("config-", "").replace(".tar.gz", "")
        entries.append({"filename": p.name, "date": ds, "size": size_str, "mtime": mtime_str})
    return entries


def _group_backups_by_week(entries):
    """Group backup entries by ISO week, newest first.
    Returns [{"label": str, "is_current": bool, "items": [entry, ...]}, ...]
    """
    from datetime import timedelta
    today = date.today()
    current_week_start = today - timedelta(days=today.weekday())
    groups: dict = {}
    for e in entries:
        try:
            d = date.fromisoformat(e["date"])
        except ValueError:
            continue
        week_start = d - timedelta(days=d.weekday())
        groups.setdefault(week_start, []).append(e)
    result = []
    for week_start in sorted(groups.keys(), reverse=True):
        is_current = (week_start == current_week_start)
        if is_current:
            label = "This week"
        else:
            week_end = week_start + timedelta(days=6)
            if week_start.month == week_end.month:
                label = f"{week_start.day}–{week_end.day} {week_end.strftime('%b')}"
            else:
                label = f"{week_start.day} {week_start.strftime('%b')} – {week_end.day} {week_end.strftime('%b')}"
        result.append({"label": label, "is_current": is_current, "entries": groups[week_start]})
    return result


def _list_archives():
    """Return sorted list of full-archive dicts (newest first)."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    entries = []
    for p in sorted(BACKUP_DIR.glob("archive-*.tar.gz"), reverse=True):
        stat = p.stat()
        size_gb = stat.st_size / (1024 ** 3)
        if size_gb >= 1:
            size_str = f"{size_gb:.1f} GB"
        else:
            size_str = f"{stat.st_size / (1024 * 1024):.0f} MB"
        mtime_str = datetime.fromtimestamp(stat.st_mtime).strftime("%H:%M")
        entries.append({"filename": p.name, "size": size_str, "mtime": mtime_str})
    return entries


def _detect_usb_drives():
    """Return list of removable/USB block devices suitable for rpi-clone."""
    try:
        result = subprocess.run(
            ["lsblk", "-Jo", "name,type,rm,tran,size,mountpoint,label"],
            capture_output=True, text=True, timeout=5
        )
        data = json.loads(result.stdout)
    except Exception:
        return []

    drives = []
    for dev in data.get("blockdevices", []):
        if dev.get("type") != "disk":
            continue
        # Accept drives that are flagged removable OR connected via USB transport
        if not dev.get("rm") and dev.get("tran") != "usb":
            continue
        # Skip the system NVMe
        if dev["name"].startswith("nvme"):
            continue
        mountpoints = []
        for child in dev.get("children", []):
            mp = child.get("mountpoint")
            if mp:
                mountpoints.append(mp)
        drives.append({
            "name":        dev["name"],
            "path":        f"/dev/{dev['name']}",
            "size":        dev.get("size", "?"),
            "label":       dev.get("label") or "",
            "mountpoints": mountpoints,
        })
    return drives


def _rpi_clone_available():
    """Check if rpi-clone is installed."""
    for p in ("/usr/local/bin/rpi-clone", "/usr/bin/rpi-clone"):
        if Path(p).exists():
            return p
    return None


# Background rpi-clone job state
_clone_job: dict = {"running": False, "device": None, "lines": [], "rc": None, "started": None}
_clone_lock = threading.Lock()


def _clone_worker(device_path):
    with _clone_lock:
        _clone_job["lines"] = []
        _clone_job["running"] = True
        _clone_job["started"] = datetime.now().strftime("%H:%M:%S")
        _clone_job["rc"] = None

    rpi_clone = _rpi_clone_available()
    try:
        proc = subprocess.Popen(
            ["sudo", rpi_clone, "-U", device_path],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )
        for line in proc.stdout:
            with _clone_lock:
                _clone_job["lines"].append(line.rstrip())
        proc.wait()
        with _clone_lock:
            _clone_job["rc"] = proc.returncode
    except Exception as e:
        with _clone_lock:
            _clone_job["lines"].append(f"Error: {e}")
            _clone_job["rc"] = -1
    finally:
        with _clone_lock:
            _clone_job["running"] = False


@app.route("/backup")
def backup():
    backups     = _list_backups()
    archives    = _list_archives()
    usb_drives  = _detect_usb_drives()
    rpi_clone   = _rpi_clone_available()
    with _clone_lock:
        clone_state = dict(_clone_job)
    with _archive_lock:
        archive_state = dict(_archive_job)
    return render_template(
        "backup.html",
        backups=backups,
        backup_groups=_group_backups_by_week(backups),
        archives=archives,
        usb_drives=usb_drives,
        rpi_clone=rpi_clone,
        clone_state=clone_state,
        archive_state=archive_state,
    )


@app.route("/backup/download/<filename>")
def backup_download(filename):
    if not re.match(r'^config-\d{4}-\d{2}-\d{2}\.tar\.gz$', filename):
        return "Not found", 404
    path = BACKUP_DIR / filename
    if not path.exists():
        return "Not found", 404
    return send_file(path, as_attachment=True)


@app.route("/backup/config/run", methods=["POST"])
def backup_config_run():
    """Trigger the config backup via systemd so pollBackupStatus can track it."""
    if not BACKUP_SCRIPT.exists():
        return jsonify({"error": "Backup script not deployed"}), 500
    try:
        subprocess.run(
            ["sudo", "systemctl", "start", "beaconbutty-backup.service"],
            check=True, capture_output=True, timeout=10
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True})


@app.route("/backup/config/status")
def backup_config_status():
    """Return status of the beaconbutty-backup systemd service."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "beaconbutty-backup.service"],
            capture_output=True, text=True, timeout=3
        )
        active = result.stdout.strip()
        result2 = subprocess.run(
            ["journalctl", "-u", "beaconbutty-backup.service", "-n", "20", "--no-pager", "--output=cat"],
            capture_output=True, text=True, timeout=5
        )
        log_lines = result2.stdout.strip().splitlines()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"active": active, "log": log_lines})


@app.route("/backup/clone/start", methods=["POST"])
def backup_clone_start():
    device = request.form.get("device", "")
    if not re.match(r'^[a-z]{2,8}\d?$', device):
        return jsonify({"error": "Invalid device name"}), 400
    if not _rpi_clone_available():
        return jsonify({"error": "rpi-clone not installed"}), 500
    with _clone_lock:
        if _clone_job["running"]:
            return jsonify({"error": "Clone already running"}), 409
        # Claim the slot here, not in the worker — two POSTs racing between
        # this check and the worker's first statement would both pass the
        # guard and run two rpi-clone jobs against the same disk.
        _clone_job["running"] = True
        _clone_job["device"] = device
    t = threading.Thread(target=_clone_worker, args=(f"/dev/{device}",), daemon=True)
    t.start()
    return jsonify({"ok": True})


@app.route("/backup/clone/status")
def backup_clone_status():
    with _clone_lock:
        return jsonify({
            "running": _clone_job["running"],
            "device":  _clone_job["device"],
            "lines":   _clone_job["lines"][-200:],
            "rc":      _clone_job["rc"],
            "started": _clone_job["started"],
        })


# ── Full archive (rootfs tarball) ───────────────────────────────────────────────
_archive_job: dict = {"running": False, "lines": [], "rc": None, "started": None}
_archive_lock = threading.Lock()


def _archive_worker():
    with _archive_lock:
        _archive_job["lines"] = []
        _archive_job["running"] = True
        _archive_job["started"] = datetime.now().strftime("%H:%M:%S")
        _archive_job["rc"] = None

    try:
        proc = subprocess.Popen(
            ["sudo", str(ARCHIVE_SCRIPT)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )
        for line in proc.stdout:
            with _archive_lock:
                _archive_job["lines"].append(line.rstrip())
        proc.wait()
        with _archive_lock:
            _archive_job["rc"] = proc.returncode
    except Exception as e:
        with _archive_lock:
            _archive_job["lines"].append(f"Error: {e}")
            _archive_job["rc"] = -1
    finally:
        with _archive_lock:
            _archive_job["running"] = False


@app.route("/backup/archive/run", methods=["POST"])
def backup_archive_run():
    if not ARCHIVE_SCRIPT.exists():
        return jsonify({"error": "Archive script not found"}), 500
    with _archive_lock:
        if _archive_job["running"]:
            return jsonify({"error": "Archive already running"}), 409
        # Claim the slot inside the lock (see backup_clone_start)
        _archive_job["running"] = True
    t = threading.Thread(target=_archive_worker, daemon=True)
    t.start()
    return jsonify({"ok": True})


@app.route("/backup/archive/status")
def backup_archive_status():
    with _archive_lock:
        return jsonify({
            "running": _archive_job["running"],
            "lines":   _archive_job["lines"][-200:],
            "rc":      _archive_job["rc"],
            "started": _archive_job["started"],
        })


@app.route("/backup/archive/download/<filename>")
def backup_archive_download(filename):
    if not re.match(r'^archive-\d{4}-\d{2}-\d{2}\.tar\.gz$', filename):
        return "Not found", 404
    path = BACKUP_DIR / filename
    if not path.exists():
        return "Not found", 404
    return send_file(path, as_attachment=True)


# ── Entry point ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ssl_context = (TLS_FULLCHAIN, TLS_PRIVKEY)
    threading.Thread(target=_network_cache_warmer, daemon=True,
                     name="network-cache-warmer").start()
    app.run(host="0.0.0.0", port=443, debug=False, ssl_context=ssl_context)
