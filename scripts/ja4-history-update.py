#!/usr/bin/env python3
"""
Fold a day's worth of Zeek ssl.log JA4 fingerprints into a persistent
per-device history file on NVMe.

Usage:
    ja4-history-update.py            # process yesterday (UTC)
    ja4-history-update.py 2026-05-04 # process a specific date
    ja4-history-update.py today      # process today

Writes /var/lib/beaconbutty/device-ja4-history.json atomically.

Schema (top level):
    {
        "<src_ip>": {
            "first_seen": "YYYY-MM-DD",
            "last_seen":  "YYYY-MM-DD",
            "fingerprints": {
                "<ja4_hash>": {
                    "first_seen": "YYYY-MM-DD",
                    "last_seen":  "YYYY-MM-DD",
                    "count":      <int>          # total observations ever
                },
                ...
            }
        }
    }

The webapp consumes this file alongside today's live ssl.log to surface
"first-time-today" fingerprints (a fingerprint is new today iff today's
live JA4 index contains it but history does not, for the same source).
"""

from __future__ import annotations

import gzip
import ipaddress
import json
import os
import sys
from collections import defaultdict
from datetime import date, datetime, timedelta
from pathlib import Path

ZEEK_LOG_DIR = Path("/var/log/zeek")
HISTORY_FILE = Path("/var/lib/beaconbutty/device-ja4-history.json")

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


def parse_target_date(arg: str | None) -> date:
    if arg is None or arg == "yesterday":
        return date.today() - timedelta(days=1)
    if arg == "today":
        return date.today()
    return datetime.strptime(arg, "%Y-%m-%d").date()


def ssl_log_paths(target: date) -> list[Path]:
    """Return all ssl.log files relevant to `target`.

    For a past day this is just the dated dir's archives. For today we also
    include `current/ssl.log` (the live tail not yet rotated).
    """
    paths: list[Path] = []
    day_dir = ZEEK_LOG_DIR / target.strftime("%Y-%m-%d")
    if day_dir.is_dir():
        paths.extend(sorted(day_dir.glob("ssl.*.log.gz")))
        paths.extend(sorted(day_dir.glob("ssl.*.log")))
    if target == date.today():
        cur = ZEEK_LOG_DIR / "current" / "ssl.log"
        if cur.exists():
            paths.append(cur)
    return paths


def iter_ssl_rows(path: Path):
    """Yield dict rows from a Zeek TSV ssl.log, gzipped or not."""
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


def collect_pairs(target: date) -> dict[str, dict[str, int]]:
    """Return {src_ip: {ja4: count}} for one day, LAN-source only."""
    out: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for path in ssl_log_paths(target):
        for row in iter_ssl_rows(path):
            ja4 = (row.get("ja4") or "").strip()
            if not ja4 or ja4 == "-":
                continue
            src = row.get("id.orig_h", "")
            if not is_lan(src):
                continue
            out[src][ja4] += 1
    return out


def load_history() -> dict:
    try:
        return json.loads(HISTORY_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_history_atomic(data: dict) -> None:
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = HISTORY_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
    os.replace(tmp, HISTORY_FILE)


def fold(history: dict, day_pairs: dict[str, dict[str, int]], target: date) -> tuple[int, int]:
    """Merge `day_pairs` into `history`. Returns (new_devices, new_fingerprints)."""
    iso = target.isoformat()
    new_devices = 0
    new_fps = 0

    for src, ja4_counts in day_pairs.items():
        dev = history.get(src)
        if dev is None:
            history[src] = dev = {
                "first_seen": iso,
                "last_seen":  iso,
                "fingerprints": {},
            }
            new_devices += 1
        else:
            if iso < dev["first_seen"]:
                dev["first_seen"] = iso
            if iso > dev["last_seen"]:
                dev["last_seen"] = iso

        fps = dev["fingerprints"]
        for ja4, count in ja4_counts.items():
            fp = fps.get(ja4)
            if fp is None:
                fps[ja4] = {"first_seen": iso, "last_seen": iso, "count": count}
                new_fps += 1
            else:
                if iso < fp["first_seen"]:
                    fp["first_seen"] = iso
                if iso > fp["last_seen"]:
                    fp["last_seen"] = iso
                fp["count"] += count

    return new_devices, new_fps


def main(argv: list[str]) -> int:
    target = parse_target_date(argv[1] if len(argv) > 1 else None)
    print(f"[ja4-history] processing {target}", flush=True)

    day_pairs = collect_pairs(target)
    if not day_pairs:
        print("[ja4-history] no JA4 rows found — nothing to fold", flush=True)
        return 0

    history = load_history()
    new_devices, new_fps = fold(history, day_pairs, target)
    save_history_atomic(history)

    total_devices = len(history)
    total_fps = sum(len(d["fingerprints"]) for d in history.values())
    print(
        f"[ja4-history] folded {sum(len(c) for c in day_pairs.values())} "
        f"(ip, ja4) cells from {len(day_pairs)} sources; "
        f"+{new_devices} new device(s), +{new_fps} new fingerprint(s); "
        f"file now: {total_devices} devices, {total_fps} fingerprints.",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
