#!/usr/bin/env python3
"""bb_fp — shared false-positive registry matching.

The `orgs` block matches an fnmatch pattern against the GeoIP ASN owner, so a
single entry covers a whole provider instead of a growing list of IP FPs. That
matters most for destinations no naming tier can reach: a VPN or relay that the
client connects to by IP, from a downloaded server list, across a rotating pool.

An org value is either a bare reason string (LAN-wide — the original v2 shape)
or `{"reason": str, "devices": [mac, ...]}` scoping the suppression to those
source devices. Device scoping is the default the UI sends, and it is the point:
"Mullvad is expected traffic from Dave's phone" says nothing about the same ASN
reaching a server or a doorbell.

This normalisation previously existed in three hand-synchronised copies —
webapp/app.py `_fp_org_entries`, slow-cadence.py `fp_orgs`, and
slow-cadence-digest.py `fp_filter` — each carrying a "change all three together"
comment. summarize.sh and the /beacons builder never grew a fourth, which is why
an org FP added through the UI silently did nothing on either of those views.
One implementation, imported everywhere, is the fix for both problems.

IMPORTANT: patterns match the RAW MaxMind org string ("31173 Services AB"), not
the friendly label bb_enrich.org_label() renders ("Mullvad VPN"). Matching the
label would break every org FP already written.
"""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path

FP_PATH = Path("/var/lib/beaconbutty/false-positives.conf")


def load_fp(path: Path = FP_PATH) -> dict:
    """The whole registry, or {} if unreadable."""
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def org_entries(fp_all_or_path=None) -> list:
    """Normalise the `orgs` block to `[(pattern, macs_or_None)]`.

    Accepts an already-loaded registry dict, a path, or nothing (default path).
    `None` for macs means the entry applies LAN-wide.
    """
    if fp_all_or_path is None:
        fp_all = load_fp()
    elif isinstance(fp_all_or_path, dict):
        fp_all = fp_all_or_path
    else:
        fp_all = load_fp(fp_all_or_path)

    entries = []
    for pat, val in (fp_all.get("orgs") or {}).items():
        if isinstance(val, dict):
            macs = {m.lower() for m in (val.get("devices") or [])}
            entries.append((pat, macs or None))
        else:
            entries.append((pat, None))
    return entries


def org_match(org: str, src_mac: str, entries) -> bool:
    """True if this ASN owner is FP'd — LAN-wide, or for this source device.

    `org` must be the raw MaxMind string. Matching is case-sensitive fnmatch,
    deliberately: entries like "*ACE*" were authored against case-sensitive
    behaviour, and relaxing it would silently widen them (see tasks/lessons.md).
    """
    if not org:
        return False
    src_mac = (src_mac or "").lower()
    for pat, macs in entries:
        if not fnmatch.fnmatch(org, pat):
            continue
        if macs is None or src_mac in macs:
            return True
    return False


def org_reason(org: str, src_mac: str, fp_all_or_path=None) -> str:
    """The configured reason for whichever org entry matched, or ""·

    Used by views that show *why* a row was suppressed rather than dropping it
    silently.
    """
    if not org:
        return ""
    if isinstance(fp_all_or_path, dict):
        fp_all = fp_all_or_path
    elif fp_all_or_path is None:
        fp_all = load_fp()
    else:
        fp_all = load_fp(fp_all_or_path)
    src_mac = (src_mac or "").lower()
    for pat, val in (fp_all.get("orgs") or {}).items():
        if not fnmatch.fnmatch(org, pat):
            continue
        if isinstance(val, dict):
            macs = {m.lower() for m in (val.get("devices") or [])}
            if macs and src_mac not in macs:
                continue
            return val.get("reason", "") or pat
        return val or pat
    return ""


# ---------------------------------------------------------------------------
# Tailscale DERP netcheck probes
# ---------------------------------------------------------------------------
#
# Every Tailscale node latency-probes EVERY DERP region on a fixed schedule, so
# a handful of tailnet devices generate a near-perfect beacon against dozens of
# relays. That is pure noise. But DERP relays also carry real, E2E-encrypted
# WireGuard payload that neither Tailscale nor we can inspect, so a compromised
# node exfiltrating over DERP looks exactly like legitimate relay use. A domain
# FP on "*.tailscale.com" suppresses both and is therefore a real detection
# hole — it was tried, and removed again, on 2026-08-13.
#
# The probe and the payload are separable, just not by port. Netcheck was
# assumed to be UDP/3478 only, which is why a "3478:udp" protocol FP was
# expected to cover it; in fact netcheck also runs an HTTPS leg on 443, and
# since a protocol FP may only suppress a row when EVERY component matches
# (correctly — else one keepalive hides the bulk traffic beside it), the 443
# leg keeps the whole row alive. The same trap sprang again on 2026-08-24
# with netcheck's ICMP latency leg — one 150-byte echo sweep per node, folded
# by RITA into the same row as the STUN probes. Observed live on this box:
#
#   probe   derp5e  275 conns    45,196 B  ->    164 B/conn
#   probe   derp7f  298 conns    65,275 B  ->    219 B/conn
#   relay   derp8g   22 conns   967,335 B  -> 43,969 B/conn
#
# What separates them is VOLUME, and by two orders of magnitude. Hence the gate
# below. The threshold sits below a single completed TLS handshake (~4-6 KB),
# so this cannot hide even one real DERP session — anything actually moving
# data breaks the gate and stays visible. That property is the whole point;
# do not raise MAX_PROBE_BYTES_PER_CONN without re-deriving it.
#
# Conditions 1 and 2 buy precision rather than safety: a DERP host contacted on
# an unexpected port stays visible whatever its volume.

#: Service components netcheck is allowed to use. A bare "port:proto" prefix
#: matches any Zeek service subfield ("443:tcp:", "443:tcp:ssl", ...).
#:
#: "icmp:8/0" is netcheck's ICMP latency leg, added 2026-08-24 after 38 rows
#: per tailnet node survived the gate on that one component alone. It is a
#: single sweep, not a per-region schedule like the STUN leg — on 2026-08-22
#: two Linux tailnet nodes each emitted exactly ONE icmp conn to each of 56
#: relays, all in the same second, 5 echo requests of ~30 B and one reply.
#: RITA folds that lone conn into the same (src, dst) row as the ~275 STUN
#: probes, so it cost nothing to produce and blocked the whole row.
#: Only echo request (type 8) is listed: "icmp:3/3" (port unreachable) does
#: occur on this network but never once against a DERP host, and an
#: unsolicited ICMP error from a relay is worth seeing.
#: "80:tcp" is a BARE port:proto prefix, like 3478 and 443 — not "80:tcp:http".
#: It was the one entry carrying its service subfield, and that made it the one
#: entry that could not match an empty subfield. Zeek writes "80:tcp:" when it
#: sees a port-80 connection it cannot classify as HTTP, which is precisely what
#: netcheck's HTTP latency leg looks like: too short to carry a response body it
#: could fingerprint. 68 rows across three days broke the gate on that component
#: alone, every one of them alongside 3478/443 probes to the same relay.
#: Widening it costs nothing in safety — the volume gate below is what makes
#: this suppression sound, and a port-80 row moving real data still breaks it.
DERP_PROBE_SERVICES = ("3478:udp", "443:tcp", "80:tcp", "icmp:8/0")

#: Above this, the row is carrying payload, not probing. See derivation above.
MAX_PROBE_BYTES_PER_CONN = 2000

#: Above this, a single packet is big enough to carry relayed content.
#:
#: Bytes-per-CONNECTION conflates rate with duration, and a long-lived flow
#: defeats it: an idle DERP session holds one TCP flow open for nine hours and
#: accumulates a large byte total while never filling a packet. Measured on
#: bb0 over four days, 504 DERP rows split cleanly —
#:
#:     suppressed by the B/conn gate   500 rows    64.0 - 95.7 B/pkt
#:     escaping, idle keepalive          3 rows    64.0 B/pkt   (418K-1.15M B/conn)
#:     escaping, genuine light relay     1 row    231.2 B/pkt
#:
#: 100 is both above every keepalive observed and below a structural floor:
#: a relayed WireGuard data frame is >= 32 B (16 B header + 16 B AEAD tag) and
#: rides on ~80 B of TLS/TCP/IP overhead, so content cannot appear in a packet
#: averaging under ~112 B. That floor holds however long the flow lives and
#: however many packets it sends, which is exactly what B/conn does not.
#:
#: A RATE test (bytes/sec) was considered and rejected for that reason: rate
#: multiplied by an unbounded duration hides an unbounded volume. Per-packet
#: cannot be accumulated around — moving bytes over DERP means filling packets.
MAX_PROBE_BYTES_PER_PACKET = 100

_DERP_HOSTS_CACHE: dict = {"map": None}
_DERP_BPP_CACHE: dict = {"map": None, "ts": 0.0}

#: How long derp_bytes_per_packet() reuses a result. The underlying RITA
#: databases are rebuilt hourly, so anything shorter just re-queries for the
#: same answer.
DERP_BPP_TTL_SECS = 900


def derp_hosts(refresh: bool = False) -> dict:
    """`{ip: hostname}` for every Tailscale DERP relay, or {} if unavailable.

    Delegates to bb_enrich.derp_map(), which shells out to the local Tailscale
    client and caches. Imported lazily so bb_fp stays dependency-light for
    callers that only need the registry matchers (bb_enrich pulls in GeoIP).
    """
    if _DERP_HOSTS_CACHE["map"] is not None and not refresh:
        return _DERP_HOSTS_CACHE["map"]
    try:
        import bb_enrich  # noqa: PLC0415 - lazy by design, see docstring
        out = bb_enrich.derp_map() or {}
    except Exception:
        out = {}
    _DERP_HOSTS_CACHE["map"] = out
    return out


def _is_probe_service(components) -> bool:
    """True when every service component is one netcheck legitimately uses.

    `components` must already be split — a plain split(",") is wrong because
    Zeek's own service subfield contains commas ("443:udp:quic,ssl" is ONE
    component). Callers that hold a raw RITA service string should split it
    with their existing component splitter first.
    """
    comps = [(c or "").strip() for c in (components or [])]
    comps = [c for c in comps if c]
    if not comps:
        return False
    return all(
        any(c == p or c.startswith(p + ":") for p in DERP_PROBE_SERVICES)
        for c in comps
    )


def is_derp_probe(dst: str, components, conns, total_bytes,
                  hosts: dict | None = None,
                  bytes_per_packet=None) -> str:
    """Hostname of the DERP relay when this row is netcheck probe traffic, else "".

    A truthy return means "suppress this row"; the hostname is returned rather
    than a bool so the caller can name the rule in its suppressed-rows table.

    `dst` is the destination IP, `components` the already-split service
    components, `conns` the connection count and `total_bytes` the byte total
    for the row. Missing or unparseable counts fail OPEN (return "") — an
    unknown volume must never be treated as a probe.

    `bytes_per_packet` is optional because not every caller can reach a packet
    count: RITA's report CSV has none, so the /beacons path looks it up with
    derp_bytes_per_packet() while the slow-cadence path carries it on the
    candidate. Omitted or unusable, only the bytes-per-connection test runs —
    i.e. exactly the behaviour that predates this argument.

    The two volume tests are INDEPENDENT and either is sufficient. They catch
    different shapes and neither subsumes the other:

      bytes/conn  the short netcheck burst — many tiny connections
      bytes/pkt   the long-lived idle session — few connections, hours long,
                  a large byte total, and not one full packet

    See MAX_PROBE_BYTES_PER_PACKET for why per-packet is the test that cannot
    be defeated by simply keeping the flow open longer.
    """
    dst = (dst or "").strip().replace("::ffff:", "")
    if not dst:
        return ""
    hosts = derp_hosts() if hosts is None else hosts
    host = hosts.get(dst, "")
    if not host:
        return ""
    if not _is_probe_service(components):
        return ""
    try:
        n_conns = int(conns)
        n_bytes = int(total_bytes)
    except (TypeError, ValueError):
        return ""
    if n_conns <= 0 or n_bytes < 0:
        return ""
    # Packets never carried content — true whatever the duration or the totals.
    # A zero or negative value is missing data, not "infinitely small packets".
    try:
        bpp = float(bytes_per_packet) if bytes_per_packet is not None else 0.0
    except (TypeError, ValueError):
        bpp = 0.0
    if 0 < bpp < MAX_PROBE_BYTES_PER_PACKET:
        return host
    if n_bytes / n_conns >= MAX_PROBE_BYTES_PER_CONN:
        return ""
    return host


def derp_bytes_per_packet(days: int = 3, ch_bin: str = "/usr/bin/clickhouse-client",
                          refresh: bool = False) -> dict:
    """`{(src, dst): bytes_per_packet}` for LAN→DERP pairs in the last `days`
    RITA databases, for callers whose row data carries no packet count.

    The value is the **maximum** across the days in the window, never the mean
    or the pooled total. A pair that filled packets on any single day has
    carried content and must stay visible; pooling would let a busy hour be
    averaged away under a week of keepalives, and pooled packets divided by one
    day's bytes would understate the ratio and over-suppress. Max is the
    conservative direction, and the only one that fails toward visibility.

    Returns {} on any failure — callers then pass None and the gate falls back
    to bytes-per-connection alone.
    """
    import time  # noqa: PLC0415 - kept local, this is the only user
    now = time.time()
    if (_DERP_BPP_CACHE["map"] is not None and not refresh
            and now - _DERP_BPP_CACHE["ts"] < DERP_BPP_TTL_SECS):
        return _DERP_BPP_CACHE["map"]

    hosts = derp_hosts()
    if not hosts:
        return {}
    try:
        import datetime  # noqa: PLC0415
        import subprocess  # noqa: PLC0415
        out = subprocess.run([ch_bin, "--query", "SHOW DATABASES"],
                             capture_output=True, text=True, timeout=5)
        available = {ln.strip() for ln in out.stdout.splitlines() if ln.strip()}
        dbs = []
        for i in range(max(1, days)):
            d = (datetime.date.today() - datetime.timedelta(days=i)).strftime("%Y%m%d")
            if f"beaconbutty_{d}" in available:
                dbs.append(f"beaconbutty_{d}")
        if not dbs:
            return {}
        # One row per (db, src, dst): the per-DAY ratio, so the max below is a
        # max over days rather than over an already-pooled figure.
        union = " UNION ALL ".join(
            f"""SELECT IPv6NumToString(src) AS s, IPv6NumToString(dst) AS d,
                       sumMerge(total_ip_bytes) AS b,
                       sumMerge(total_src_packets) + sumMerge(total_dst_packets) AS p
                FROM {db}.uconn GROUP BY src, dst"""
            for db in dbs
        )
        sql = (f"SELECT s, d, max(b / p) AS bpp FROM ({union}) "
               f"WHERE p > 0 GROUP BY s, d FORMAT TSV")
        res = subprocess.run([ch_bin, "--query", sql],
                             capture_output=True, text=True, timeout=30)
        if res.returncode != 0:
            return {}
        table = {}
        for line in res.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) != 3:
                continue
            src = parts[0].replace("::ffff:", "")
            dst = parts[1].replace("::ffff:", "")
            if dst not in hosts:
                continue
            try:
                table[(src, dst)] = float(parts[2])
            except ValueError:
                continue
    except Exception:
        return {}
    _DERP_BPP_CACHE["map"] = table
    _DERP_BPP_CACHE["ts"] = now
    return table
