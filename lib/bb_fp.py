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

_DERP_HOSTS_CACHE: dict = {"map": None}


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
                  hosts: dict | None = None) -> str:
    """Hostname of the DERP relay when this row is netcheck probe traffic, else "".

    A truthy return means "suppress this row"; the hostname is returned rather
    than a bool so the caller can name the rule in its suppressed-rows table.

    `dst` is the destination IP, `components` the already-split service
    components, `conns` the connection count and `total_bytes` the byte total
    for the row. Missing or unparseable counts fail OPEN (return "") — an
    unknown volume must never be treated as a probe.
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
    if n_bytes / n_conns >= MAX_PROBE_BYTES_PER_CONN:
        return ""
    return host
