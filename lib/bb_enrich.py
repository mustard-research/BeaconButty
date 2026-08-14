#!/usr/bin/env python3
"""bb_enrich — shared destination-IP → hostname enrichment.

RITA's daily report only joins against the same-day dns_history table, so any
beacon whose dst was last resolved on a prior day surfaces as a bare IP. The
name is nearly always recoverable from data already on this box; this module is
the single place that recovers it.

Before this existed the ladder lived in three places, none complete:

    webapp/app.py::enrich_ips_batch   SNI -> DNS -> cert CN -> HTTP Host
    scripts/slow-cadence.py           SNI, HTTP Host (own re-implementation)
    scripts/summarize.sh              nothing at all - GeoIP ASN only

which is why the 2026-08-14 report showed `185.125.190.100` as
"Canonical Group Limited" when both Zeek and the Shodan cache knew it was
`connectivity-check.ubuntu.com`.

Lookups are keyed on dst only - the identity of an IP is the same regardless of
which LAN device is talking to it. This catches the case where one device
confirms an SNI for a STUN/derp/CDN IP that a different device only ever sees as
an IP literal. The narrow case where two LAN devices share a CDN IP for
genuinely different services is rare; the operator can override with a per-IP FP.

The ladder, strongest evidence first:

    tier  source    where                             cost
    1     SNI       {db}.ssl.server_name              SQL
    2     DNS       {db}.dns.answers                  SQL
    3     cert      {db}.ssl.server_subject (CN=)     SQL
    4     HTTP      {db}.http.host                    SQL
    5     QUIC      Zeek quic.log                     file scan
    6     SAN       Zeek ssl.log + x509.log           file scan
    7     derp      tailscale debug derp-map          subprocess
    8     shodan    ip-intel-cache.json               file
    9     PTR       live reverse DNS                  network

Tiers 1-4 are cheap SQL and run first as a batch. Tiers 5-6 are equally
authoritative but are the only ones that scan files, so they run lazily - for
dsts still unresolved after the SQL tiers. In practice any dst with a parallel
TLS flow already resolved at tier 1, so the scan set is small. If QUIC-only
destinations ever become common enough to matter, promote tier 5 above tier 2
and scan eagerly; that is a measurement, not a guess.

Every tier names a HOST. The ASN owner's domain ("linode.com") is NOT a tier:
it is returned separately as `org_hint`, never in `name`. It briefly was a
ninth tier flagged `weak: True` in the shared `name` field, and two of the
three consumers remembered to check the flag - the webapp did not, and started
both displaying "linode.com" as though it were a hostname and feeding it to FP
matching, where 19 org domains match a registered "*.<domain>" pattern. A
separate field cannot be misused by omission. See org_hint_for.

Neither `quic` nor `x509` is imported into ClickHouse by RITA (verified: no
such tables, and `ip_to_hostname` exists but is empty in every daily DB), hence
the file tiers.
"""

from __future__ import annotations

import gzip
import ipaddress
import json
import os
import re
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta
from pathlib import Path

CH_BIN          = "/usr/bin/clickhouse-client"
ZEEK_LOG_DIR    = Path("/var/log/zeek")
IP_INTEL_FILE   = Path("/var/lib/beaconbutty/ip-intel-cache.json")
NAME_CACHE_FILE = Path("/var/lib/beaconbutty/ip-names-cache.json")

# On-disk cache TTL. The webapp keeps its own short in-process cache on top of
# this; the value here is what makes one-shot consumers (summarize.sh,
# slow-cadence.py) cheap, since they would otherwise redo tiers 5-8 every run.
NAME_CACHE_TTL = 6 * 3600

# Bump whenever a change to the ladder could produce a different name for the
# same IP. Entries stamped with an older version are ignored, so a fix takes
# effect on the next run instead of being masked by cached answers for a TTL.
CACHE_VERSION = 4

# Wall-clock ceiling for the whole PTR tier, and per-lookup. Reverse DNS is the
# only tier that touches the network, and it runs inside a page render.
PTR_TOTAL_TIMEOUT = 3.0
PTR_LOOKUP_TIMEOUT = 1.0

_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

#: Sources that name a host. Ordered by authority - index doubles as rank.
SOURCE_RANK = ("SNI", "DNS", "cert", "HTTP", "QUIC", "SAN", "derp",
               "shodan", "PTR")

#: Every source in SOURCE_RANK names a HOST. Organisation-level identifiers
#: (the ASN owner's domain) are deliberately not a tier — see org_hint_for.


# ── normalisation ────────────────────────────────────────────────────────────

def normalise_host(name, dst: str = "") -> str:
    """Canonicalise a candidate hostname, or return "" if it isn't one.

    Zeek and RITA disagree about root-anchoring: http.log on this box carries
    both `connectivity-check.ubuntu.com` and `connectivity-check.ubuntu.com.`
    for the same host. Left alone that splits every downstream group-by and
    makes domain-FP matching miss half the rows, so the trailing dot is
    stripped exactly once, here.

    IP literals are not enrichment - some clients send the IP as SNI, and
    PTR-style DNS queries can return numerics.
    """
    n = (name or "").strip().rstrip(".").lower()
    if not n or n == (dst or "").lower():
        return ""
    if _IP_RE.match(n):
        return ""
    # An IPv6 literal has colons and no dots; a hostname never has a colon.
    if ":" in n:
        return ""
    if any(c.isspace() for c in n):
        return ""
    return n


def _x509_cn(subject: str) -> str:
    """Extract CN= from an X509 Subject DN; fall back to the full string."""
    if not subject:
        return ""
    for part in subject.split(","):
        p = part.strip()
        if p.upper().startswith("CN="):
            return p[3:].strip()
    return subject


def _strip_v4(ipv6_str: str) -> str:
    """Turn ::ffff:192.168.50.1 into 192.168.50.1. Leave real IPv6 alone."""
    if ipv6_str and ipv6_str.startswith("::ffff:"):
        return ipv6_str[7:]
    return ipv6_str or ""


def _is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_multicast or a.is_reserved or a.is_unspecified)


# ── ClickHouse plumbing ──────────────────────────────────────────────────────

def _run(sql: str, ch_bin: str = CH_BIN, timeout: int = 15) -> list:
    """Run a query with FORMAT JSONEachRow; [] on any failure."""
    try:
        out = subprocess.run(
            [ch_bin, "--query", sql + " FORMAT JSONEachRow"],
            capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    if out.returncode != 0:
        return []
    rows = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def ch_dbs_for_window(days: int, ch_bin: str = CH_BIN) -> list:
    """Existing beaconbutty_YYYYMMDD DBs covering the last `days` days."""
    try:
        out = subprocess.run([ch_bin, "--query", "SHOW DATABASES"],
                             capture_output=True, text=True, timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        return []
    if out.returncode != 0:
        return []
    available = {ln.strip() for ln in out.stdout.splitlines()
                 if ln.strip().startswith("beaconbutty_")}
    dbs = []
    for i in range(days):
        d = (date.today() - timedelta(days=i)).strftime("%Y%m%d")
        name = f"beaconbutty_{d}"
        if name in available:
            dbs.append(name)
    return dbs


# ── tiers 1-4: ClickHouse ────────────────────────────────────────────────────

#: Max dst IPs per IN-list. The list is repeated once per daily DB, so the
#: generated SQL is O(chunk x len(dbs)); slow-cadence.py runs a 14-day window
#: over a few hundred candidates, which unchunked overruns ClickHouse's
#: max_query_size. 150 keeps the worst case comfortably inside it.
_CHUNK = 150


def _chunks(items):
    items = list(items)
    for i in range(0, len(items), _CHUNK):
        yield items[i:i + _CHUNK]


def _tier_sql(dbs, todo: set, ch_bin: str, consider) -> None:
    """Tiers 1-4. `consider(dst, raw_name, source, ts)` records a candidate and
    is responsible for skipping dsts that are already resolved."""

    def _left():
        return {d for d in todo if d not in consider.resolved}

    # 1. TLS SNI - most authoritative.
    for chunk in _chunks(todo):
        in_v6 = ",".join(f"'::ffff:{d}'" for d in chunk)
        union = " UNION ALL ".join(
            f"""SELECT IPv6NumToString(dst) AS d, server_name AS name, ts
                FROM {db}.ssl
                WHERE server_name != ''
                  AND IPv6NumToString(dst) IN ({in_v6})"""
            for db in dbs
        )
        sql = (f"SELECT d, argMax(name, ts) AS name, max(ts) AS ts_max "
               f"FROM ({union}) GROUP BY d")
        for r in _run(sql, ch_bin):
            consider(_strip_v4(r["d"]), r.get("name", ""), "SNI",
                     r.get("ts_max"))

    # 2. DNS history - any LAN-side query that resolved to dst.
    for chunk in _chunks(_left()):
        in_left = ",".join(f"'{d}'" for d in chunk)
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
        for r in _run(sql, ch_bin):
            consider(r["d"], r.get("name", ""), "DNS", r.get("ts_max"))

    # 3. TLS server cert Subject CN - for SNI-less / ECH flows.
    for chunk in _chunks(_left()):
        in_left_v6 = ",".join(f"'::ffff:{d}'" for d in chunk)
        union = " UNION ALL ".join(
            f"""SELECT IPv6NumToString(dst) AS d, server_subject AS name, ts
                FROM {db}.ssl
                WHERE server_subject != ''
                  AND IPv6NumToString(dst) IN ({in_left_v6})"""
            for db in dbs
        )
        sql = (f"SELECT d, argMax(name, ts) AS name, max(ts) AS ts_max "
               f"FROM ({union}) GROUP BY d")
        for r in _run(sql, ch_bin):
            consider(_strip_v4(r["d"]), _x509_cn(r.get("name", "")), "cert",
                     r.get("ts_max"))

    # 4. HTTP Host header - for plain HTTP flows.
    for chunk in _chunks(_left()):
        in_left_v6 = ",".join(f"'::ffff:{d}'" for d in chunk)
        union = " UNION ALL ".join(
            f"""SELECT IPv6NumToString(dst) AS d, host AS name, ts
                FROM {db}.http
                WHERE host != ''
                  AND IPv6NumToString(dst) IN ({in_left_v6})"""
            for db in dbs
        )
        sql = (f"SELECT d, argMax(name, ts) AS name, max(ts) AS ts_max "
               f"FROM ({union}) GROUP BY d")
        for r in _run(sql, ch_bin):
            consider(_strip_v4(r["d"]), r.get("name", ""), "HTTP",
                     r.get("ts_max"))


# ── tiers 5-6: Zeek files ────────────────────────────────────────────────────

def _zeek_dirs(days: int) -> list:
    """Daily Zeek log dirs covering the window, newest first, plus the live
    spool. Both /var/log/zeek/current and /opt/zeek/logs/current symlink to
    /opt/zeek/spool/zeek, so `current` covers today's not-yet-rotated logs."""
    dirs = []
    cur = ZEEK_LOG_DIR / "current"
    if cur.is_dir():
        dirs.append(cur)
    for i in range(days):
        d = ZEEK_LOG_DIR / (date.today() - timedelta(days=i)).strftime("%Y-%m-%d")
        if d.is_dir():
            dirs.append(d)
    return dirs


def _read_zeek(path: Path):
    """Yield (fields, row) for a Zeek TSV log, gz or plain.

    The header is re-read per file rather than assumed: Zeek 8 renamed the
    ssl.log cert columns to `cert_chain_fps`, and hard-coded indices would have
    silently produced garbage across an upgrade.
    """
    opener = gzip.open if path.suffix == ".gz" else open
    try:
        with opener(path, "rt", errors="replace") as fh:
            fields = None
            for line in fh:
                if line.startswith("#"):
                    if line.startswith("#fields"):
                        fields = line.rstrip("\n").split("\t")[1:]
                    continue
                if fields is None:
                    continue
                yield fields, line.rstrip("\n").split("\t")
    except (OSError, EOFError):
        return


def _col(fields, row, name):
    try:
        v = row[fields.index(name)]
    except (ValueError, IndexError):
        return ""
    return "" if v == "-" or v == "(empty)" else v


def _tier_quic_and_san(days: int, todo: set, consider) -> None:
    """Tiers 5 and 6, in one pass over the same daily directories.

    QUIC carries the SNI directly. For SAN we need a two-step join that has no
    ClickHouse equivalent: ssl.log maps dst -> cert_chain_fps, x509.log maps
    fingerprint -> san.dns. We only collect fingerprints for dsts still
    unresolved, so the x509 scan is usually skipped entirely.
    """
    if not todo:
        return
    dirs = _zeek_dirs(days)
    if not dirs:
        return

    want_fp = {}          # cert fingerprint -> dst
    for d in dirs:
        # tier 5 - QUIC SNI
        for path in sorted(d.glob("quic.*log*")) + sorted(d.glob("quic.log")):
            for fields, row in _read_zeek(path):
                dst = _col(fields, row, "id.resp_h")
                if dst not in todo or dst in consider.resolved:
                    continue
                consider(dst, _col(fields, row, "server_name"), "QUIC", None)

        # tier 6a - collect cert fingerprints for whatever is still unnamed
        for path in sorted(d.glob("ssl.*log*")) + sorted(d.glob("ssl.log")):
            for fields, row in _read_zeek(path):
                dst = _col(fields, row, "id.resp_h")
                if dst not in todo or dst in consider.resolved:
                    continue
                fps = _col(fields, row, "cert_chain_fps")
                if fps:
                    # Leaf certificate first; that is the one with the SANs.
                    want_fp.setdefault(fps.split(",")[0], dst)

    if not want_fp:
        return

    # tier 6b - resolve those fingerprints to SANs
    for d in dirs:
        if not want_fp:
            break
        for path in sorted(d.glob("x509.*log*")) + sorted(d.glob("x509.log")):
            for fields, row in _read_zeek(path):
                fp = _col(fields, row, "fingerprint")
                dst = want_fp.get(fp)
                if not dst or dst in consider.resolved:
                    continue
                san = _col(fields, row, "san.dns")
                if not san:
                    continue
                # Prefer the first non-wildcard SAN; a bare "*.example.com" is
                # a worse label than the apex it implies.
                names = [s for s in san.split(",") if s]
                pick = next((s for s in names if not s.startswith("*.")), "")
                if not pick and names:
                    pick = names[0].replace("*.", "", 1)
                consider(dst, pick, "SAN", None)
                want_fp.pop(fp, None)


# ── tiers 7-9: cached intel and reverse DNS ──────────────────────────────────

_DERP_CACHE: dict = {"ts": 0.0, "map": {}}
_DERP_TTL = 24 * 3600


def derp_map() -> dict:
    """`{ip: hostname}` for every Tailscale DERP relay, from the local client.

    DERP relays are a standing source of unnameable beacons here: several LAN
    devices run Tailscale, netcheck probes every relay in the map (STUN on
    3478 plus HTTPS), and none of it is nameable by the tiers above. Tailscale
    ships the relay list in its control-plane map rather than resolving it, so
    Zeek never sees a DNS lookup or an SNI, and Shodan's only name for most of
    them is the hosting provider's IP-derived PTR.

    `tailscale debug derp-map` is the authoritative answer and is already on
    this box. Cheap enough to call once a day and cache.
    """
    now = time.time()
    if _DERP_CACHE["map"] and now - _DERP_CACHE["ts"] < _DERP_TTL:
        return _DERP_CACHE["map"]
    out = {}
    try:
        p = subprocess.run(["tailscale", "debug", "derp-map"],
                           capture_output=True, text=True, timeout=10)
        if p.returncode == 0:
            data = json.loads(p.stdout)
            for region in (data.get("Regions") or {}).values():
                for node in (region.get("Nodes") or []):
                    host = node.get("HostName") or ""
                    if not host:
                        continue
                    for key in ("IPv4", "IPv6"):
                        addr = node.get(key) or ""
                        if addr:
                            out[addr] = host
    except (subprocess.TimeoutExpired, OSError, ValueError):
        out = {}
    # Cache even an empty result, so a box without Tailscale does not shell out
    # once per enrich() call.
    _DERP_CACHE.update(ts=now, map=out)
    return out


def _tier_derp(todo: set, consider) -> None:
    """Tier 7 - Tailscale DERP relay names."""
    if not any(d not in consider.resolved for d in todo):
        return
    dmap = derp_map()
    if not dmap:
        return
    for dst in todo:
        if dst in consider.resolved:
            continue
        if dmap.get(dst):
            consider(dst, dmap[dst], "derp", None)


def load_ip_intel(path: Path = IP_INTEL_FILE) -> dict:
    """Shodan InternetDB + AbuseIPDB cache, refreshed daily by
    beaconbutty-ip-intel.service. Read-only from here."""
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def is_ip_derived(name: str, ip: str) -> bool:
    """True if `name` is just `ip` re-encoded as a hostname.

    Cloud providers auto-generate PTRs that embed the address:
    `172-237-72-79.ip.linodeusercontent.com`, `ec2-3-8-1-2.compute.amazonaws.com`,
    `4.3.2.1.in-addr.arpa`. These are not identities - they carry no more
    information than the IP already shown next to them, and worse, displaying
    one crowds out the ASN owner ("Akamai Connected Cloud"), which at least
    names the provider.

    Detected by flattening every run of non-digits to a single separator and
    looking for the octets in order, forwards or reversed, plain or zero-padded
    - so it is agnostic to the provider's chosen separator and suffix.
    """
    octets = (ip or "").split(".")
    if len(octets) != 4 or not all(o.isdigit() for o in octets):
        return False
    flat = "-" + re.sub(r"[^0-9]+", "-", name or "") + "-"
    for seq in (octets, list(reversed(octets))):
        for form in ("-".join(seq), "-".join(o.zfill(3) for o in seq)):
            if f"-{form}-" in flat:
                return True
    return False


def _pick_shodan_hostname(hostnames, ip: str = "") -> str:
    """Shodan often returns several PTR-ish names for one IP. Prefer the
    shortest - it is the most canonical (`aidemos.meta.com` over
    `trunkstable.aidemos.meta.com`) - breaking ties alphabetically so the
    choice is stable across runs and cache rebuilds.

    IP-derived names are dropped rather than ranked last: if that is all Shodan
    has, the caller is better served by falling through to the ASN owner.
    """
    cands = [h for h in (hostnames or [])
             if h and not _IP_RE.match(h) and not is_ip_derived(h, ip)]
    if not cands:
        return ""
    return sorted(cands, key=lambda h: (len(h), h))[0]


def _tier_shodan(todo: set, intel: dict, consider) -> None:
    """Tier 7 - the cached Shodan hostname."""
    for dst in list(todo):
        if dst in consider.resolved:
            continue
        rec = intel.get(dst)
        if not rec:
            continue
        consider(dst,
                 _pick_shodan_hostname(
                     (rec.get("shodan") or {}).get("hostnames"), dst),
                 "shodan", None)


def org_hint_for(dst: str, intel: dict) -> str:
    """AbuseIPDB's domain for the address owner - "linode.com", "google.com".

    Deliberately NOT part of the ladder. It names whoever *owns* the address,
    not what is running on it, so it is never a hostname and must never reach
    anything that matches or generates FP patterns: 19 of these org domains
    already match a registered "*.<domain>" FP, so letting one through would
    suppress a finding on ASN ownership alone.

    It is returned in its own `org_hint` field rather than in `name` so a
    consumer cannot use it by accident - an earlier design flagged it with
    `weak: True` in the shared `name` field, and two of three consumers
    remembered to check the flag.
    """
    return ((intel.get(dst) or {}).get("abuseipdb") or {}).get("domain", "")


def _tier_ptr(todo: set, consider) -> None:
    """Tier 8 - live reverse DNS, public addresses only.

    dnsmasq already refuses to forward RFC1918 reverse lookups upstream, but
    this must not depend on that: a future resolver change should not turn an
    enrichment call into a leak of internal addressing. Bounded in wall-clock
    because it runs inside a page render.
    """
    left = [d for d in todo if d not in consider.resolved and _is_public(d)]
    if not left:
        return

    def _lookup(ip):
        try:
            return ip, socket.gethostbyaddr(ip)[0]
        except (OSError, socket.herror, socket.gaierror):
            return ip, ""

    deadline = time.monotonic() + PTR_TOTAL_TIMEOUT
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_lookup, ip) for ip in left]
        for fut in futures:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                ip, name = fut.result(timeout=min(remaining, PTR_LOOKUP_TIMEOUT))
            except Exception:
                continue
            # An IP-derived PTR is the address in disguise — see is_ip_derived.
            if name and not is_ip_derived(name, ip):
                consider(ip, name, "PTR", None)


# ── on-disk cache ────────────────────────────────────────────────────────────

def _load_name_cache(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_name_cache(cache: dict, path: Path) -> None:
    """Atomic replace. os.replace needs write permission on the *directory*,
    not the file - /var/lib/beaconbutty is drwxrwsr-x root:dm, so both the
    root-run timers and the dm-run webapp can update it. Mode 0664 (not the
    0600 tempfile default) so whichever writes first does not lock the other
    out of a plain in-place rewrite later.
    """
    try:
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".ip-names-")
        with os.fdopen(fd, "w") as fh:
            json.dump(cache, fh)
        os.chmod(tmp, 0o664)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except (OSError, NameError, UnboundLocalError):
            pass


# ── public API ───────────────────────────────────────────────────────────────

def enrich(dsts, days: int = 7, ch_bin: str = CH_BIN, intel: dict = None,
           use_cache: bool = True, cache_path: Path = NAME_CACHE_FILE,
           with_intel: bool = True) -> dict:
    """Resolve destination IPs to hostnames.

    Returns `{dst: {'name', 'source', 'when_days', 'org_hint'[, 'intel']}}` for
    every dst asked about; unresolved entries carry name "" and source "".

    `name` is always a hostname or "" — never an organisation. `org_hint` is
    the ASN owner's domain, set only when nothing named the host, and is safe
    to display but must never reach FP matching or FP-pattern prefill.

    `when_days` is approximate days since the most recent observation, and is
    None for tiers that carry no timestamp (QUIC/SAN/derp/shodan/PTR).
    """
    dsts = {d for d in dsts if d}
    if not dsts:
        return {}

    now = time.time()
    out: dict = {}
    todo: set = set()

    cache = _load_name_cache(cache_path) if use_cache else {}
    for d in dsts:
        c = cache.get(d)
        if (c and isinstance(c, dict) and c.get("v") == CACHE_VERSION
                and now - c.get("ts", 0) < NAME_CACHE_TTL):
            out[d] = {k: c.get(k) for k in
                      ("name", "source", "when_days", "org_hint")}
        else:
            todo.add(d)

    if todo:
        best: dict = {}

        def consider(dst, raw, source, ts):
            """Record the first (therefore highest-tier) name seen for a dst."""
            if dst not in todo or dst in best:
                return
            name = normalise_host(raw, dst)
            if not name:
                return
            best[dst] = {"name": name, "source": source, "ts": ts}

        consider.resolved = best      # tiers test this to skip settled dsts

        dbs = ch_dbs_for_window(days, ch_bin)
        if dbs:
            _tier_sql(dbs, todo, ch_bin, consider)

        _tier_quic_and_san(days, todo, consider)

        if intel is None:
            intel = load_ip_intel()
        _tier_derp(todo, consider)                         # tier 7 DERP map
        _tier_shodan(todo, intel, consider)                # tier 8 shodan
        _tier_ptr(todo, consider)                          # tier 9 PTR

        today_dt = date.today()
        for d in todo:
            b = best.get(d)
            if b:
                when_days = None
                if b.get("ts"):
                    try:
                        seen = datetime.strptime(str(b["ts"])[:10],
                                                 "%Y-%m-%d").date()
                        when_days = (today_dt - seen).days
                    except ValueError:
                        when_days = None
                entry = {"name": b["name"], "source": b["source"],
                         "when_days": when_days}
            else:
                entry = {"name": "", "source": "", "when_days": None}
            # Separate field, never merged into `name` — see org_hint_for.
            entry["org_hint"] = org_hint_for(d, intel) if not entry["name"] else ""
            out[d] = entry
            cache[d] = {**entry, "ts": now, "v": CACHE_VERSION}

        if use_cache:
            # Evict stale and superseded entries before writing, so the file
            # cannot grow without bound as the network meets new external IPs.
            for k in [k for k, v in cache.items()
                      if not isinstance(v, dict)
                      or v.get("v") != CACHE_VERSION
                      or now - v.get("ts", 0) > NAME_CACHE_TTL * 4]:
                del cache[k]
            _save_name_cache(cache, cache_path)

    if with_intel:
        if intel is None:
            intel = load_ip_intel()
        for dst, entry in out.items():
            e = intel.get(dst)
            if e:
                entry["intel"] = {
                    "shodan":    e.get("shodan", {}),
                    "abuseipdb": e.get("abuseipdb", {}),
                    "spamhaus":  e.get("spamhaus", {}),
                    "tor":       e.get("tor", {}),
                    "ts":        e.get("ts"),
                }

    return out


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: bb_enrich.py <ip> [ip ...]")
        raise SystemExit(2)
    res = enrich(sys.argv[1:], days=7, with_intel=False)
    for ip in sys.argv[1:]:
        r = res.get(ip, {})
        name = r.get("name") or "-"
        src = r.get("source") or "-"
        print(f"{ip:<40} {name:<50} [{src}]")
