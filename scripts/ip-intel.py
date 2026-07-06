#!/usr/bin/env python3
"""
Daily refresher of external IP threat-intel cache.

Sources (all free):
- Shodan InternetDB — no key, returns ports/hostnames/cpes/tags/vulns from
  Shodan's own crawl. https://internetdb.shodan.io/<ip>
- AbuseIPDB v2 /check — free tier 1000 lookups/day; returns abuse confidence
  score, country, ISP, report counts. Key in /var/lib/beaconbutty/threat-intel.json.
- Spamhaus DROP/EDROP — no key, bulk netblock list of high-confidence malicious
  CIDRs (drop.txt + drop_v6.txt). Hits are red — network-level signal.
- Tor exit nodes — no key, bulk list from the Tor Project (torbulkexitlist).
  Authoritative; supersedes Shodan's incomplete 'tor' tag coverage.

Targets: distinct external dst IPs from threat_mixtape (beacon hotlist source)
and from Suricata eve.json across the last LOOKBACK_DAYS. Private/loopback/
link-local etc. are filtered out — they don't have external intel.

Cache: /var/lib/beaconbutty/ip-intel-cache.json (atomic-replace writes).
Entries older than CACHE_TTL_DAYS are refreshed. Entries not seen for
GC_DAYS get evicted to keep the file small. Spamhaus/Tor results are
re-stamped on every run (free lookups against locally-cached lists).

Sidecar files (for debug / external consumers):
  /var/lib/beaconbutty/spamhaus-drop.json — {"cidrs": [["1.2.3.0/24", "SBL123"], ...]}
  /var/lib/beaconbutty/tor-exits.json     — {"ips": ["1.2.3.4", ...]}

The webapp reads ip-intel-cache.json directly via _load_ip_intel(); this script
only writes it. Safe to re-run any time.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

CONFIG_FILE = Path("/var/lib/beaconbutty/threat-intel.json")
CACHE_FILE = Path("/var/lib/beaconbutty/ip-intel-cache.json")
SPAMHAUS_FILE = Path("/var/lib/beaconbutty/spamhaus-drop.json")
TOR_FILE = Path("/var/lib/beaconbutty/tor-exits.json")
SURICATA_EVE = Path("/var/lib/suricata/log/eve.json")

SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_DROP_V6_URL = "https://www.spamhaus.org/drop/drop_v6.txt"
TOR_EXIT_URL = "https://check.torproject.org/torbulkexitlist"

CH_BIN = "clickhouse-client"
CACHE_TTL_DAYS = 30     # re-query after this many days (AbuseIPDB data is stable on this order)
LOOKBACK_DAYS = 7       # how far back to gather candidate IPs
GC_DAYS = 60            # evict entries not seen for this long
HTTP_TIMEOUT = 8
ABUSEIPDB_SLEEP = 0.4   # ~2.5 req/s
SHODAN_SLEEP = 0.2
MAX_PER_RUN = 800       # safety cap so we stay under AbuseIPDB free-tier 1000/day
USER_AGENT = "beaconbutty-ip-intel/1.0 (+https://github.com/mustard-research/BeaconButty)"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_minus(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_public_v4(ip: str) -> bool:
    try:
        a = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_multicast
                or a.is_link_local or a.is_reserved or a.is_unspecified)


def strip_v4mapped(s: str) -> str:
    return s[7:] if s.startswith("::ffff:") else s


def load_cache() -> dict:
    if not CACHE_FILE.exists():
        return {}
    try:
        return json.loads(CACHE_FILE.read_text())
    except Exception as e:
        print(f"WARN: cache parse failed ({e}); starting fresh", file=sys.stderr)
        return {}


def save_cache_atomic(d: dict) -> None:
    tmp = CACHE_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(d, indent=1, sort_keys=True))
    os.chmod(tmp, 0o644)
    os.replace(tmp, CACHE_FILE)


def ch_query(sql: str) -> list[dict]:
    try:
        out = subprocess.run(
            [CH_BIN, "--format=JSONEachRow", "--query", sql],
            capture_output=True, text=True, timeout=30,
        )
        if out.returncode != 0:
            return []
        return [json.loads(line) for line in out.stdout.splitlines() if line.strip()]
    except Exception as e:
        print(f"WARN: clickhouse query failed: {e}", file=sys.stderr)
        return []


def ch_available_dbs() -> set[str]:
    rows = ch_query("SHOW DATABASES")
    return {r.get("name", "") for r in rows}


def target_ips_ranked() -> list[str]:
    """
    Distinct public-v4 dst IPs from RITA beacons + Suricata alerts, ordered
    most-recent-first. Recency = most recent DB the IP appears in (today = 0,
    yesterday = 1, ...). Ties broken by total beacon row count across the
    lookback window. So if MAX_PER_RUN truncates, the freshest IPs still land.
    """
    # For each IP track (best_recency_i, max_count). Best recency = smallest i.
    best_i: dict[str, int] = {}
    max_c: dict[str, int] = {}
    avail = ch_available_dbs()
    today = datetime.now(timezone.utc).date()
    for i in range(LOOKBACK_DAYS):
        d = (today - timedelta(days=i)).strftime("%Y%m%d")
        name = f"beaconbutty_{d}"
        if name not in avail:
            continue
        rows = ch_query(
            f"SELECT IPv6NumToString(dst) AS d, count(*) AS c "
            f"FROM {name}.threat_mixtape "
            f"WHERE IPv6NumToString(dst) != '::' "
            f"GROUP BY d"
        )
        for r in rows:
            d_ip = strip_v4mapped(r.get("d", ""))
            if not is_public_v4(d_ip):
                continue
            c = int(r.get("c", 0))
            if d_ip not in best_i or i < best_i[d_ip]:
                best_i[d_ip] = i
            max_c[d_ip] = max(max_c.get(d_ip, 0), c)

    if SURICATA_EVE.exists():
        cutoff = (datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)).timestamp()
        try:
            with SURICATA_EVE.open() as f:
                for line in f:
                    if '"event_type":"alert"' not in line:
                        continue
                    try:
                        ev = json.loads(line)
                    except Exception:
                        continue
                    ts = ev.get("timestamp", "")
                    if ts:
                        try:
                            t = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
                            if t < cutoff:
                                continue
                        except Exception:
                            pass
                    d_ip = ev.get("dest_ip", "")
                    if not is_public_v4(d_ip):
                        continue
                    if d_ip not in best_i:
                        best_i[d_ip] = 0
                        max_c[d_ip] = 1
        except Exception as e:
            print(f"WARN: Suricata eve scan failed: {e}", file=sys.stderr)

    # Most-recent first; within a day, higher beacon-row count first.
    return sorted(best_i.keys(), key=lambda ip: (best_i[ip], -max_c[ip]))


def shodan_internetdb(ip: str) -> dict | None:
    """
    Returns the InternetDB record, or an empty-fields dict on 404 (no scan).
    Returns None only on transport error so caller can decide whether to retry.

    NB: Shodan returns 403 to the default Python urllib UA — must set a
    real User-Agent header. curl works because its default UA is allowed.
    """
    req = urllib.request.Request(
        f"https://internetdb.shodan.io/{ip}",
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            if r.status == 200:
                d = json.loads(r.read())
                return {k: d.get(k, []) for k in ("ports", "hostnames", "cpes", "tags", "vulns")}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"ports": [], "hostnames": [], "cpes": [], "tags": [], "vulns": []}
        print(f"WARN: Shodan HTTP {e.code} for {ip}", file=sys.stderr)
    except Exception as e:
        print(f"WARN: Shodan error for {ip}: {e}", file=sys.stderr)
    return None


def abuseipdb_check(ip: str, api_key: str) -> dict | None:
    if not api_key:
        return None
    url = "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode({
        "ipAddress": ip,
        "maxAgeInDays": "90",
    })
    req = urllib.request.Request(url, headers={
        "Key": api_key,
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            if r.status != 200:
                return None
            d = json.loads(r.read()).get("data", {}) or {}
            return {
                "score": int(d.get("abuseConfidenceScore", 0) or 0),
                "country": d.get("countryCode") or None,
                "usage_type": d.get("usageType") or None,
                "isp": d.get("isp") or None,
                "domain": d.get("domain") or None,
                "total_reports": int(d.get("totalReports", 0) or 0),
                "distinct_users": int(d.get("numDistinctUsers", 0) or 0),
                "last_reported": d.get("lastReportedAt") or None,
            }
    except urllib.error.HTTPError as e:
        # 429 = quota exceeded; 401 = bad key. Caller handles.
        print(f"WARN: AbuseIPDB {e.code} for {ip}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"WARN: AbuseIPDB error for {ip}: {e}", file=sys.stderr)
        return None


def _http_text(url: str) -> str | None:
    """GET a plain-text resource with our UA. Returns None on any failure."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            if r.status != 200:
                return None
            return r.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"WARN: fetch {url} failed: {e}", file=sys.stderr)
        return None


def fetch_spamhaus_drop() -> list[tuple]:
    """
    Returns [(ip_network, sbl_id), ...] across DROP v4 and DROP v6.
    Falls back to the on-disk sidecar if both fetches fail (don't lose
    coverage on transient network errors).
    """
    out: list[tuple] = []
    for url in (SPAMHAUS_DROP_URL, SPAMHAUS_DROP_V6_URL):
        body = _http_text(url)
        if not body:
            continue
        for raw in body.splitlines():
            line = raw.strip()
            if not line or line.startswith(";") or line.startswith("#"):
                continue
            # Format: "1.2.3.0/24 ; SBL12345"
            parts = [p.strip() for p in line.split(";", 1)]
            cidr = parts[0]
            sbl = parts[1] if len(parts) > 1 else ""
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            out.append((net, sbl))
    if out:
        try:
            SPAMHAUS_FILE.write_text(json.dumps(
                {"ts": utc_now(), "cidrs": [[str(n), s] for n, s in out]},
                indent=1,
            ))
            os.chmod(SPAMHAUS_FILE, 0o644)
        except Exception as e:
            print(f"WARN: spamhaus sidecar write failed: {e}", file=sys.stderr)
        return out
    # Fallback: load previous sidecar
    if SPAMHAUS_FILE.exists():
        try:
            data = json.loads(SPAMHAUS_FILE.read_text())
            for cidr, sbl in data.get("cidrs", []):
                try:
                    out.append((ipaddress.ip_network(cidr, strict=False), sbl))
                except ValueError:
                    continue
            print(f"WARN: spamhaus fetch failed; using cached sidecar "
                  f"({len(out)} CIDRs from {data.get('ts', '?')})", file=sys.stderr)
        except Exception as e:
            print(f"WARN: spamhaus sidecar read failed: {e}", file=sys.stderr)
    return out


def fetch_tor_exits() -> set[str]:
    """
    Returns the set of current Tor exit IPs. Falls back to the on-disk
    sidecar if the fetch fails.
    """
    body = _http_text(TOR_EXIT_URL)
    if body:
        ips: set[str] = set()
        for raw in body.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                ipaddress.ip_address(line)
            except ValueError:
                continue
            ips.add(line)
        if ips:
            try:
                TOR_FILE.write_text(json.dumps(
                    {"ts": utc_now(), "ips": sorted(ips)},
                    indent=1,
                ))
                os.chmod(TOR_FILE, 0o644)
            except Exception as e:
                print(f"WARN: tor sidecar write failed: {e}", file=sys.stderr)
            return ips
    if TOR_FILE.exists():
        try:
            data = json.loads(TOR_FILE.read_text())
            ips = set(data.get("ips", []))
            print(f"WARN: tor fetch failed; using cached sidecar "
                  f"({len(ips)} IPs from {data.get('ts', '?')})", file=sys.stderr)
            return ips
        except Exception as e:
            print(f"WARN: tor sidecar read failed: {e}", file=sys.stderr)
    return set()


def classify_threatlists(ip: str, drop_nets: list, tor_set: set) -> tuple[dict, dict]:
    """Returns (spamhaus_dict, tor_dict) for one IP. Always returns dicts
    (never None) so callers can unconditionally stamp the cache."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return {"drop": False, "sbl": None}, {"exit": False}
    sbl = None
    for net, sbl_id in drop_nets:
        if a.version == net.version and a in net:
            sbl = sbl_id or "DROP"
            break
    return ({"drop": sbl is not None, "sbl": sbl},
            {"exit": ip in tor_set})


def main() -> int:
    if not CONFIG_FILE.exists():
        print(f"ERROR: missing {CONFIG_FILE}", file=sys.stderr)
        return 1
    try:
        cfg = json.loads(CONFIG_FILE.read_text())
    except Exception as e:
        print(f"ERROR: cannot parse {CONFIG_FILE}: {e}", file=sys.stderr)
        return 1
    api_key = cfg.get("abuseipdb_api_key", "")
    if not api_key:
        print("WARN: no AbuseIPDB key — Shodan-only run", file=sys.stderr)

    cache = load_cache()
    now = utc_now()
    refresh_cutoff = utc_minus(CACHE_TTL_DAYS)

    drop_nets = fetch_spamhaus_drop()
    tor_set = fetch_tor_exits()
    print(f"  spamhaus drop: {len(drop_nets)} CIDRs · tor exits: {len(tor_set)} IPs")

    targets = target_ips_ranked()
    target_set = set(targets)
    # Keep the ranking order — most-recent / hottest IPs first.
    # "Stale" = entry missing OR older than TTL OR missing one of the two
    # source results (e.g., Shodan transient failure on a previous run).
    def _needs_refresh(ip: str) -> bool:
        c = cache.get(ip)
        if not c or c.get("ts", "") < refresh_cutoff:
            return True
        if "shodan" not in c or "abuseipdb" not in c:
            return True
        return False
    stale = [ip for ip in targets if _needs_refresh(ip)]
    capped = stale[:MAX_PER_RUN]
    print(f"[{now}] {len(targets)} target IPs, {len(stale)} stale, "
          f"processing {len(capped)} this run (cap={MAX_PER_RUN})")

    failures = 0
    for i, ip in enumerate(capped, 1):
        entry = cache.get(ip, {})
        refreshed_ok = True
        # Only refetch Shodan if we don't already have it or entry expired.
        shodan_stale = ("shodan" not in entry) or entry.get("ts", "") < refresh_cutoff
        if shodan_stale:
            sh = shodan_internetdb(ip)
            if sh is not None:
                entry["shodan"] = sh
            else:
                failures += 1
                refreshed_ok = False
            time.sleep(SHODAN_SLEEP)
        # Same for AbuseIPDB — don't burn quota re-checking what we already have.
        abuse_stale = ("abuseipdb" not in entry) or entry.get("ts", "") < refresh_cutoff
        if abuse_stale and api_key:
            ab = abuseipdb_check(ip, api_key)
            if ab is not None:
                entry["abuseipdb"] = ab
            else:
                refreshed_ok = False
            time.sleep(ABUSEIPDB_SLEEP)

        # Stamp fresh only when the refresh succeeded — bumping ts on a
        # failed refetch presents month-old intel as fresh for another
        # 30 days instead of retrying on the next run.
        if refreshed_ok:
            entry["ts"] = now
        cache[ip] = entry
        if i % 25 == 0:
            save_cache_atomic(cache)
            print(f"  ... checkpoint {i}/{len(stale)}")

    # Stamp every cached IP with current Spamhaus + Tor status. Cheap (local
    # set / CIDR check, no API call) so we re-run on every entry every time —
    # keeps the cache fresh against today's lists even for IPs we didn't
    # re-query against Shodan/AbuseIPDB this run.
    if drop_nets or tor_set:
        spamhaus_hits = 0
        tor_hits = 0
        for ip, entry in cache.items():
            sp, to = classify_threatlists(ip, drop_nets, tor_set)
            entry["spamhaus"] = sp
            entry["tor"] = to
            if sp["drop"]:
                spamhaus_hits += 1
            if to["exit"]:
                tor_hits += 1
        print(f"  spamhaus DROP hits in cache: {spamhaus_hits} · tor exit hits: {tor_hits}")

    # GC: drop entries we haven't seen for GC_DAYS AND aren't in current targets.
    gc_cutoff = utc_minus(GC_DAYS)
    drop = [ip for ip, e in cache.items()
            if e.get("ts", "") < gc_cutoff and ip not in target_set]
    for ip in drop:
        del cache[ip]
    if drop:
        print(f"  GC'd {len(drop)} stale entries")

    save_cache_atomic(cache)
    print(f"[{utc_now()}] cache has {len(cache)} IPs total, {failures} fetch failures")
    return 0


if __name__ == "__main__":
    sys.exit(main())
