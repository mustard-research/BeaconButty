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
