#!/usr/bin/env python3
"""
seed-assets-history.py — one-shot bootstrap for assets-history.json.

Walks the last 14 days of Zeek dhcp.log archives plus the live spool to
populate the asset history file with IP/MAC pairs and a last_seen date
derived from the day each entry was observed.  Entries already present
in the live assets.json are preserved as-is.

Run once after deploying the assets-history feature.  Subsequent runs
of assets.sh will keep the file refreshed.
"""

from __future__ import annotations

import datetime as dt
import gzip
import json
import os
import re
import sys
from pathlib import Path

ASSETS_FILE  = Path("/var/lib/beaconbutty/assets.json")
HISTORY_FILE = Path("/var/lib/beaconbutty/assets-history.json")
ZEEK_LOGS    = Path("/var/log/zeek")
WINDOW_DAYS  = 14

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
# Derive LAN_PREFIX from BB_LAN_SUBNET (a CIDR like "192.168.50.0/24" → "192.168.50.")
_subnet = os.environ.get("BB_LAN_SUBNET", "192.168.50.0/24").split("/")[0]
LAN_PREFIX = ".".join(_subnet.split(".")[:3]) + "."
DAY_RE     = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def parse_dhcp(path: Path):
    """Yield (ip, mac, hostname) tuples from a Zeek dhcp.log[.gz]."""
    opener = gzip.open if path.suffix == ".gz" else open
    fields: list[str] | None = None
    try:
        with opener(path, "rt") as f:
            for line in f:
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                    fields[-1] = fields[-1].rstrip()
                    continue
                if line.startswith("#") or not line.strip():
                    continue
                if fields is None:
                    continue
                parts = line.rstrip("\n").split("\t")
                row = dict(zip(fields, parts))
                ip   = row.get("client_addr") or row.get("assigned_addr") or ""
                mac  = row.get("mac", "").lower()
                host = row.get("host_name", "")
                if host == "-":
                    host = ""
                if ip.startswith(LAN_PREFIX) and mac and mac != "-":
                    yield ip, mac, host
    except (OSError, EOFError):
        return


def main() -> int:
    today = dt.date.today()
    cutoff = today - dt.timedelta(days=WINDOW_DAYS)

    history: dict = {}
    if HISTORY_FILE.exists():
        try:
            history = json.loads(HISTORY_FILE.read_text())
        except json.JSONDecodeError:
            history = {}

    live: dict = {}
    if ASSETS_FILE.exists():
        live = json.loads(ASSETS_FILE.read_text())

    # Collect daily dhcp logs in chronological order so later days
    # naturally win on last_seen.
    day_dirs = sorted(
        d for d in ZEEK_LOGS.iterdir()
        if d.is_dir() and DAY_RE.match(d.name)
    )

    discovered = 0
    for day_dir in day_dirs:
        try:
            day = dt.date.fromisoformat(day_dir.name)
        except ValueError:
            continue
        if day < cutoff or day > today:
            continue
        day_iso = day.isoformat()
        for path in sorted(day_dir.glob("dhcp.*")):
            for ip, mac, host in parse_dhcp(path):
                prev = history.get(ip, {})
                history[ip] = {
                    "mac":         mac,
                    "mac_vendor":  prev.get("mac_vendor", ""),
                    "hostname":    host or prev.get("hostname", ""),
                    "os":          prev.get("os", ""),
                    "open_ports":  prev.get("open_ports", []),
                    "first_seen":  prev.get("first_seen", day_iso),
                    "last_seen":   max(prev.get("last_seen", day_iso), day_iso),
                }
                discovered += 1

    # Live assets always win — replay them last so today's MAC/vendor/etc.
    # take precedence over any stale dhcp.log row.
    today_iso = today.isoformat()
    for ip, info in live.items():
        prev = history.get(ip, {})
        history[ip] = {
            "mac":         info.get("mac", "") or prev.get("mac", ""),
            "mac_vendor":  info.get("mac_vendor", "") or prev.get("mac_vendor", ""),
            "hostname":    info.get("hostname", "") or prev.get("hostname", ""),
            "os":          info.get("os", "") or prev.get("os", ""),
            "open_ports":  info.get("open_ports", []) or prev.get("open_ports", []),
            "first_seen":  prev.get("first_seen", today_iso),
            "last_seen":   today_iso,
        }

    # Prune anything older than the window in case the file already had stale
    # entries from an earlier deploy.
    cutoff_iso = cutoff.isoformat()
    pruned = [ip for ip, info in history.items()
              if info.get("last_seen", "") < cutoff_iso]
    for ip in pruned:
        del history[ip]

    tmp = HISTORY_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(history, indent=2, sort_keys=True))
    os.replace(tmp, HISTORY_FILE)

    ghosts = [ip for ip in history if ip not in live]
    print(f"Walked {discovered} dhcp rows over {len(day_dirs)} day dirs.")
    print(f"History: {len(history)} entries, "
          f"{len(live)} live, {len(ghosts)} ghost.")
    for ip in sorted(ghosts, key=lambda x: tuple(int(p) for p in x.split('.'))):
        h = history[ip]
        days_ago = (today - dt.date.fromisoformat(h["last_seen"])).days
        print(f"  ghost  {ip:18}  {h.get('mac',''):17}  "
              f"{h.get('hostname','—')[:20]:20}  last={h['last_seen']} ({days_ago}d)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
