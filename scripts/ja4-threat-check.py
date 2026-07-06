#!/usr/bin/env python3
"""
Scan today's Zeek ssl.log for JA4 fingerprints that match a known threat
family in FoxIO's ja4plus-mapping.csv. For each (LAN device, threat family)
hit on an EXACT ja4 match, fire one `threat_intel_hit` alert via
beaconbutty-alert.sh.

Cipher-family matches (where only the cipher portion of a JA4 maps to a
threat label) are intentionally NOT alerted — that path is too broad to
page on, since legitimate clients commonly share cipher lists with malware
families. Cipher-family matches still surface in the webapp classifier;
this script only fires Slack alerts on exact JA4 hits.

Devices whose MAC is in /var/lib/beaconbutty/false-positives.conf are
skipped entirely (looked up via dnsmasq.leases).

The detail string is stable per (device, threat label) so the Lambda's
(type, device, detail) dedup catches repeat firings — one page per
device-threat pair per day.

Run via beaconbutty-ja4-threat-check.timer (every 15 min).
"""

from __future__ import annotations

import csv
import gzip
import ipaddress
import json
import os
import subprocess
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path

ZEEK_LOG_DIR  = Path("/var/log/zeek")
JA4DB_FILE    = Path("/var/lib/beaconbutty/ja4db.csv")
ALERT_BIN     = Path("/usr/local/bin/beaconbutty-alert.sh")
FP_FILE       = Path("/var/lib/beaconbutty/false-positives.conf")
DHCP_LEASES   = Path("/var/lib/misc/dnsmasq.leases")

THREAT_NEEDLES = (
    "cobalt strike", "sliver", "havoc", "qakbot", "pikabot",
    "darkgate", "icedid", "lumma", "ngrok", "mythic", "brute ratel",
)

# A JA4 fingerprint whose ja4db Library is a generic language runtime is
# just that runtime's stock TLS Client Hello — shared by every program
# built with it. ja4db may name one known malware user (e.g. "Sliver Agent
# / GoLang") but the hash cannot distinguish it from ordinary Go software.
# Too broad to alert on — same rationale as the cipher-family exclusion.
GENERIC_RUNTIMES = ("golang",)

def _load_local_env(path: str = "/etc/beaconbutty/local.env") -> None:
    from pathlib import Path as _P
    p = _P(path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

_load_local_env()
LAN_NETS = [ipaddress.ip_network(os.environ.get("BB_LAN_SUBNET", "192.168.50.0/24"))]


def is_lan(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in LAN_NETS)


def label_is_threat(label: str) -> bool:
    if not label:
        return False
    low = label.lower()
    if not any(needle in low for needle in THREAT_NEEDLES):
        return False
    if any(rt in low for rt in GENERIC_RUNTIMES):
        return False
    return True


def load_ja4db():
    """Return {"exact": {ja4: label}} — only exact matches are alerted on."""
    exact: dict[str, str] = {}
    if not JA4DB_FILE.exists():
        return {"exact": exact}
    with JA4DB_FILE.open(newline="") as f:
        for row in csv.DictReader(f):
            ja4 = (row.get("ja4") or "").strip()
            if not ja4 or "_" not in ja4:
                continue
            app = (row.get("Application") or "").strip()
            lib = (row.get("Library") or "").strip()
            osn = (row.get("OS") or "").strip()
            parts = [p for p in (app, lib) if p]
            if osn:
                parts.append(f"on {osn}")
            label = " / ".join(parts) or "Known JA4"
            exact[ja4] = label
    return {"exact": exact}


def classify(ja4: str, db) -> tuple[str, bool]:
    """Return (label, is_threat) for EXACT ja4 matches only.

    Cipher-family matches are deliberately ignored here — they are too
    broad to alert on. The webapp's network-intel page still surfaces
    cipher-family matches separately."""
    if not ja4 or "_" not in ja4:
        return ("", False)
    lab = db["exact"].get(ja4)
    if lab:
        return (lab, label_is_threat(lab))
    return ("", False)


def fp_source_ips() -> set[str]:
    """LAN IPs whose MAC is on the FP devices list — drop these entirely."""
    try:
        with FP_FILE.open() as f:
            fp_macs = {m.lower() for m in json.load(f).get("devices", {}).keys()}
    except (FileNotFoundError, json.JSONDecodeError):
        return set()
    if not fp_macs:
        return set()
    ips: set[str] = set()
    try:
        with DHCP_LEASES.open() as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[1].lower() in fp_macs:
                    ips.add(parts[2])
    except FileNotFoundError:
        pass
    # Also cover IPs the MAC held earlier in the window — current leases
    # alone lose an FP'd device that renumbered or went offline.
    try:
        with open("/var/lib/beaconbutty/assets-history.json") as f:
            for hist_ip, info in json.load(f).items():
                if (info.get("mac") or "").lower() in fp_macs:
                    ips.add(hist_ip)
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return ips


def ssl_log_paths(target: date) -> list[Path]:
    paths: list[Path] = []
    day_dir = ZEEK_LOG_DIR / target.strftime("%Y-%m-%d")
    if day_dir.is_dir():
        paths.extend(sorted(day_dir.glob("ssl.*.log.gz")))
        paths.extend(sorted(day_dir.glob("ssl.*.log")))
    cur = ZEEK_LOG_DIR / "current" / "ssl.log"
    if cur.exists():
        paths.append(cur)
    return paths


def iter_ssl_rows(path: Path):
    opener = gzip.open if str(path).endswith(".gz") else open
    fields = None
    try:
        with opener(path, "rt", errors="replace") as f:
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
    except OSError:
        return


def main() -> int:
    if not ALERT_BIN.exists():
        print("beaconbutty-alert.sh not found — skipping", file=sys.stderr)
        return 0
    db = load_ja4db()
    fp_ips = fp_source_ips()

    # device_ip -> set(threat_label) — one alert per (device, label)
    hits: dict[str, set[str]] = defaultdict(set)
    today = date.today()
    for path in ssl_log_paths(today):
        for row in iter_ssl_rows(path):
            ja4 = (row.get("ja4") or "").strip()
            if not ja4 or ja4 == "-":
                continue
            src = (row.get("id.orig_h") or "").strip()
            if not is_lan(src) or src in fp_ips:
                continue
            label, is_threat = classify(ja4, db)
            if not is_threat:
                continue
            hits[src].add(label)

    if not hits:
        return 0

    for ip, labels in hits.items():
        for label in sorted(labels):
            detail = f"JA4 fingerprint match: {label}"
            print(f"firing alert: {ip} → {label}")
            subprocess.run(
                [str(ALERT_BIN), "threat_intel_hit", "high", ip, detail],
                check=False,
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
