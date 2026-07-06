#!/usr/bin/env python3
"""
teams-cidr-refresh.py — pull the live Microsoft 365 Teams endpoint list
from endpoints.office.com and write it to
/var/lib/beaconbutty/teams-cidrs.json for consumption by teams-relay-check.py.

The Teams TURN relays live under the legacy 'Skype' service area in the
endpoint feed (the renamed-but-not-renamed product). We pick up every
Skype-area entry (ids 11, 12, 16, 17, 19, 27, 127 today) and union the
IPv4 CIDRs + URL patterns.

Run via beaconbutty-teams-cidr-refresh.timer (daily 03:30). If the fetch
fails, the existing /var/lib copy is left untouched. If neither exists,
the detector falls back to the repo's bundled /home/dm/BeaconButty/
config/teams-cidrs.json.

Usage:
    teams-cidr-refresh.py              # write live list to /var/lib
    teams-cidr-refresh.py --dry-run    # print the diff vs current file
"""

from __future__ import annotations

import datetime as dt
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ENDPOINT_URL = "https://endpoints.office.com/endpoints/worldwide"
OUT_PATH     = Path("/var/lib/beaconbutty/teams-cidrs.json")
TIMEOUT_SEC  = 15
USER_AGENT   = "BeaconButty/1.0 (teams-cidr-refresh; +https://github.com/mustard-research/BeaconButty)"


def _cidr_sort_key(c: str):
    """Numeric sort with a fallback: one malformed feed entry must not
    crash the whole refresh (the existing file would just go stale)."""
    try:
        return (0, tuple(int(p) for p in c.split("/")[0].split(".")))
    except ValueError:
        return (1, (c,))


def fetch_endpoints() -> list:
    qs   = f"?clientrequestid={uuid.uuid4()}"
    url  = ENDPOINT_URL + qs
    req  = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT_SEC) as r:
        return json.loads(r.read())


def extract_teams(entries: list) -> dict:
    cidrs_v4: set[str]  = set()
    sni_exact: set[str] = set()
    sni_suffix: set[str] = set()
    for e in entries:
        if e.get("serviceArea") != "Skype":
            continue
        for ip in e.get("ips", []) or []:
            if ":" not in ip:               # IPv4 only for now
                cidrs_v4.add(ip)
        for url in e.get("urls", []) or []:
            url = url.strip().lower()
            if not url:
                continue
            if url.startswith("*."):
                sni_suffix.add(url[1:])     # "*.teams.microsoft.com" -> ".teams.microsoft.com"
            else:
                sni_exact.add(url)
    return {
        "version": dt.date.today().isoformat(),
        "source":  "endpoints.office.com — Microsoft 365 Skype service area",
        "comment": "Refreshed by beaconbutty-teams-cidr-refresh.timer (daily).",
        "ipv4_cidrs":   sorted(cidrs_v4, key=_cidr_sort_key),
        "sni_suffixes": sorted(sni_suffix),
        "sni_exact":    sorted(sni_exact),
    }


def write_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".teams-cidrs.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, indent=2, sort_keys=False)
            f.write("\n")
        os.chmod(tmp, 0o644)   # mkstemp default is 0600; webapp runs as 'dm'
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    dry = "--dry-run" in sys.argv
    try:
        entries = fetch_endpoints()
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        print(f"teams-cidr-refresh: fetch failed ({e}); leaving existing file untouched", file=sys.stderr)
        return 1

    payload = extract_teams(entries)
    if not payload["ipv4_cidrs"]:
        print("teams-cidr-refresh: zero IPv4 CIDRs in fetched feed — bailing out so we don't blank the file", file=sys.stderr)
        return 2

    if dry:
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    write_atomic(OUT_PATH, payload)
    print(f"teams-cidr-refresh: wrote {OUT_PATH} — "
          f"{len(payload['ipv4_cidrs'])} cidrs, "
          f"{len(payload['sni_suffixes'])} suffix patterns, "
          f"{len(payload['sni_exact'])} exact hosts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
