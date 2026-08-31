#!/usr/bin/env python3
"""
bb_outages.py — ISP connectivity outage history for BeaconButty.

wan-watchdog.sh already records every WAN loss and recovery to
/var/log/beaconbutty/watchdog.log, but only as isolated lines. This module
turns those lines into discrete outage events, keeps a durable history of
them, and summarises them per day.

Two consumers, one parser:
  * webapp/app.py imports it for the /health WAN card
  * healthcheck.sh shells to the CLI below for its Network Interfaces line

Resolution honesty
------------------
The watchdog probes on a fixed cadence, so an outage is only ever *detected*
within that window: the true start lies somewhere in the interval before the
first failing probe. Everything here reports the detected window and every
caller is expected to say so — an outage shorter than the gap between two probes
leaves no trace at all, so "0 outages" means "none seen", not "none happened".

The cadence CHANGED on 2026-08-30, from 5 minutes to 1, and since that date a
failing check also escalates to 10-second probing. History therefore spans two
resolutions. Do not present one figure as if it applied to both: rows carrying
an evidence file were measured under the new regime and have a real onset
bracket (`last_ok_at`); rows without predate it and are only good to ±5 min.

Why a history file
------------------
logrotate keeps 8 weeks of watchdog.log (weekly, rotate 8), so the logs alone
can never answer "how much downtime this year". `--persist` merges each parse
into /var/lib/beaconbutty/outage-history.json, keyed on outage start, so the
record outlives the log it came from. Merging is idempotent: re-parsing the
same log produces the same keys.

CLI:
    bb_outages.py --line       one-line summary for today (healthcheck.sh)
    bb_outages.py --json       full merged history as JSON
    bb_outages.py --persist    merge parse into the history file, then --line
"""

import gzip
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, date
from pathlib import Path

WATCHDOG_LOG   = Path(os.environ.get("BB_WATCHDOG_LOG",
                                     "/var/log/beaconbutty/watchdog.log"))
HISTORY_FILE   = Path(os.environ.get("BB_OUTAGE_HISTORY",
                                     "/var/lib/beaconbutty/outage-history.json"))
EVIDENCE_DIR   = Path(os.environ.get("BB_OUTAGE_EVIDENCE",
                                     "/var/lib/beaconbutty/outage-evidence"))

# An evidence file is keyed on when the watchdog ENTERED its failure branch;
# the outage start we parse here is when it LOGGED, and between the two sits the
# diagnostic burst (arping, gateway ping, traceroute) — tens of seconds. So the
# two timestamps never match exactly and we join on proximity instead. Distinct
# outages are always separated by a recovery, and therefore by at least one
# probe interval, so a window this size cannot select the wrong file.
EVIDENCE_MATCH_SECS = 180

# wan-watchdog.timer's current period (1 min since 2026-08-30). Used only to
# bound an outage whose recovery was never logged (the log was rotated or lost
# mid-outage); we credit it one more probe interval rather than guessing
# further. Deliberately NOT used to reconstruct historical durations — those
# were sampled at 5 min and their real bound is the recorded onset bracket.
PROBE_INTERVAL_SECS = 60

# Two failing probes further apart than this are treated as separate outages
# rather than one long one. Four missed probe intervals: tolerant of a couple
# of skipped timer runs, but short enough that a gap in the log (a log2ram
# loss, a reboot) cannot silently fuse two distinct outages into one.
MAX_PROBE_GAP_SECS = 21 * 60

# ── Log line grammar ─────────────────────────────────────────────────────────
# wan-watchdog.sh writes "<iso8601>  <message>" (two spaces). Lines without a
# timestamp exist (alert.sh's own output is appended to the same file) and are
# skipped rather than guessed at.
_LINE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2}|Z)?)\s\s+(.*)$")

_NO_IP_RE = re.compile(r"^WAN \(\S+\) has no IP address")

# Verdict text → machine class → display label.
#
# Two generations live here at once, and they must not be conflated.
#
# CURRENT (from lib/bb_wan_diag.py): grounded in measurement — carrier state
# plus an arping of the gateway, which runs below IP and so distinguishes a
# router that is absent from one that is present but not forwarding.
#
# LEGACY (pre-2026-08-30): classified on one bit, "did the gateway answer
# ICMP", which cannot tell those two apart. Its labels are deliberately
# rewritten to say what was *observed* rather than what the old code inferred.
# The old "fault in the link/CPE" wording was measurably wrong on bb0 — every
# outage it named had an unbroken carrier, an unchanged lease and a device that
# never left `activated` — so replaying it verbatim would keep asserting a
# conclusion the evidence contradicts.
_CLASSES = [
    # Current, most specific first — "answers ARP but not ICMP" contains
    # "does not answer" as a substring in neither direction, but order still
    # matters for the legacy wordings below.
    # These two MUST precede the plain "does not answer ARP" rule: both of
    # their verdicts contain that phrase, so a first-match scan would collapse
    # them into gateway_absent and throw away the discrimination.
    ("access gear is alive",    "gateway_vip_unclaimed",
                                "ISP gateway address unclaimed (access gear alive)"),
    ("segment has gone silent", "access_segment_down",
                                "WAN segment silent (isolated at L2)"),
    ("does not answer ARP",     "gateway_absent",   "ISP gateway unclaimed (cause not narrowed)"),
    ("answers ARP but not ICMP", "gateway_silent",  "ISP gateway present, not responding"),
    ("break is beyond the edge", "upstream_transit", "ISP upstream / transit"),
    ("carrier is down",         "link_down",        "Physical link down"),
    # Legacy wordings.
    ("unreachable too",         "link_fault",   "Gateway unreachable (cause not established)"),
    ("break is upstream",       "isp_upstream", "Upstream — gateway answered"),
    ("likely ISP outage",       "isp_upstream", "Upstream — gateway answered"),
    # Shared by both generations.
    ("no default route",        "no_route",     "Local routing fault"),
    ("no IP address",           "no_ip",        "WAN had no IP"),
]
CLASS_LABELS = {c: label for _, c, label in _CLASSES}
CLASS_LABELS["unknown"] = "Cause not established"

# Classes produced by the evidence-based classifier. Used by the UI to mark
# which rows carry real diagnosis and which predate it — a legacy row is not
# "unknown cause", it is "cause never established", and the difference matters
# when reading the history back.
EVIDENCE_CLASSES = {"gateway_absent", "gateway_silent", "upstream_transit",
                    "link_down", "gateway_vip_unclaimed", "access_segment_down"}
LEGACY_CLASSES   = {"link_fault", "isp_upstream"}


def _classify(message):
    for needle, cls, _ in _CLASSES:
        if needle in message:
            return cls
    return "unknown"


def log_paths(base=WATCHDOG_LOG):
    """
    Every readable generation of the watchdog log, live file first.

    Sorted so that plain rotations precede compressed ones for the same index;
    ordering does not actually matter because events are re-sorted by
    timestamp, but a stable order keeps the reported source list readable.
    """
    base = Path(base)
    paths = [base] if base.exists() else []
    parent, stem = base.parent, base.name
    if parent.is_dir():
        rotated = [p for p in parent.glob(stem + ".*")
                   if re.fullmatch(re.escape(stem) + r"\.\d+(\.gz)?", p.name)]
        rotated.sort(key=lambda p: (int(p.name.split(".")[2]
                                        if p.name.endswith(".gz")
                                        else p.name.split(".")[-1]),
                                    p.name))
        paths += rotated
    return [p for p in paths if os.access(p, os.R_OK)]


def parse_events(paths=None):
    """
    Extract (datetime, kind, message) triples from the watchdog logs.

    kind is 'down' (a failing probe) or 'up' (connectivity restored). DNS
    failures are deliberately ignored: the DNS tripwire also trips during a WAN
    outage, so counting it would double-count the same event, and a DNS-only
    failure is a resolver fault rather than lost ISP connectivity.
    """
    if paths is None:
        paths = log_paths()
    events = []
    for path in paths:
        opener = gzip.open if str(path).endswith(".gz") else open
        try:
            with opener(path, "rt", errors="replace") as fh:
                for line in fh:
                    m = _LINE_RE.match(line.rstrip("\n"))
                    if not m:
                        continue
                    stamp, msg = m.group(1), m.group(2)
                    if msg.startswith("WAN unreachable") or _NO_IP_RE.match(msg):
                        kind = "down"
                    elif msg.startswith("WAN connectivity restored"):
                        kind = "up"
                    else:
                        continue
                    try:
                        ts = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                    except ValueError:
                        continue
                    events.append((ts, kind, msg))
        except OSError:
            continue
    # Rotated generations are read newest-first, so a global sort is required
    # before the state machine below can run.
    events.sort(key=lambda e: e[0])
    return events


# Classes that are established by a witness rather than inferred from silence.
# Ordered most-severe first. These are ONE-WAY: once a check has established
# one, it is true of the outage, so a plain majority vote across checks is the
# wrong collapse — an outage whose ninth check finally caught a DHCP renewal
# would be reported on the strength of the eight checks that had no evidence
# yet, throwing away the only measurement that settled anything.
_WITNESSED = ("link_down", "access_segment_down", "gateway_vip_unclaimed")


def _collapse_classes(classes):
    """One class for the outage. Witnessed findings win; otherwise majority."""
    for cls in _WITNESSED:
        if cls in classes:
            return cls
    counted = Counter(classes)
    return counted.most_common(1)[0][0] if counted else "unknown"


def _finish(cur, end, ongoing, estimated):
    primary = _collapse_classes(cur["classes"])
    return {
        "start":         cur["start"].isoformat(),
        "end":           end.isoformat() if end else None,
        "duration_secs": max(0, int((end - cur["start"]).total_seconds())) if end else 0,
        "checks_failed": cur["checks"],
        "class":         primary,
        "verdict":       cur["verdict"],
        "ongoing":       ongoing,
        "end_estimated": estimated,
    }


def build_outages(events, now=None):
    """
    Collapse failing/recovering probes into discrete outages.

    An outage runs from its first failing probe to the 'restored' line that
    closes it. Three endings are possible:
      * closed by a restore line          — exact detected window
      * still failing, and recent         — ongoing=True, measured to now
      * failing, then the log goes quiet  — end_estimated=True, credited one
                                            further probe interval
    The third case is what a reboot or a lost log tail looks like; calling it
    estimated is better than either dropping the outage or pretending the
    recovery time is known.
    """
    if now is None:
        now = datetime.now().astimezone()
    outages, cur = [], None

    for ts, kind, msg in events:
        if kind == "down":
            if cur and (ts - cur["last"]).total_seconds() > MAX_PROBE_GAP_SECS:
                outages.append(_finish(
                    cur, cur["last"] + timedelta(seconds=PROBE_INTERVAL_SECS),
                    False, True))
                cur = None
            if cur is None:
                cur = {"start": ts, "last": ts, "checks": 0,
                       "classes": [], "verdict": ""}
            cur["last"] = ts
            cur["checks"] += 1
            cur["classes"].append(_classify(msg))
            # Keep the last verdict: the watchdog re-probes the gateway on
            # every failing run, so the newest one is the best-informed.
            cur["verdict"] = msg.split(" — ", 1)[-1] if " — " in msg else msg
        elif kind == "up" and cur is not None:
            outages.append(_finish(cur, ts, False, False))
            cur = None

    if cur is not None:
        if (now - cur["last"]).total_seconds() <= MAX_PROBE_GAP_SECS:
            outages.append(_finish(cur, now, True, False))
        else:
            outages.append(_finish(
                cur, cur["last"] + timedelta(seconds=PROBE_INTERVAL_SECS),
                False, True))
    return outages


# ── Durable history ──────────────────────────────────────────────────────────

# Completeness ranking, used when the same outage exists in both the history
# file and a fresh parse. An outage stored while it was still ongoing must be
# replaced by the closed version once the restore line lands, but a stored
# closed version must never be downgraded by a re-parse of a truncated log.
_RANK = {"closed": 2, "estimated": 1, "ongoing": 0}


def _rank(o):
    if o.get("ongoing"):
        return _RANK["ongoing"]
    return _RANK["estimated"] if o.get("end_estimated") else _RANK["closed"]


def load_history(path=HISTORY_FILE):
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    outages = data.get("outages") if isinstance(data, dict) else data
    return outages if isinstance(outages, list) else []


def merge(stored, parsed):
    """Union two outage lists on start time, keeping the more complete record."""
    by_start = {}
    for o in list(stored) + list(parsed):
        start = o.get("start")
        if not start:
            continue
        prev = by_start.get(start)
        # >= so the fresh parse wins ties: it reflects the current log.
        if prev is None or _rank(o) >= _rank(prev):
            by_start[start] = o
    return sorted(by_start.values(), key=lambda o: o["start"])


def save_history(outages, path=HISTORY_FILE):
    """Atomic same-directory replace, so a reader never sees a partial file."""
    path = Path(path)
    tmp = path.with_name(f".{path.name}.tmp")
    payload = {
        "version":    1,
        "updated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "outages":    outages,
    }
    with open(tmp, "w") as fh:
        json.dump(payload, fh, indent=2)
    os.chmod(tmp, 0o664)
    os.replace(tmp, path)


def load_evidence_index():
    """Every readable evidence file, keyed by the datetime it was opened at."""
    index = {}
    try:
        paths = sorted(EVIDENCE_DIR.glob("*.json"))
    except OSError:
        return index
    for path in paths:
        try:
            doc = json.loads(path.read_text())
            ts = datetime.fromisoformat(doc["outage_start"])
        except (OSError, json.JSONDecodeError, KeyError, ValueError):
            continue
        index[ts] = doc
    return index


def _witnesses(samples, outage):
    """
    Scan every sample for the two things that prove the ISP's access gear was
    alive while its gateway address answered nobody: a DHCP lease issued during
    the outage, and foreign broadcast still arriving on the WAN segment.
    """
    out = {}
    try:
        started = datetime.fromisoformat(outage["start"]).timestamp()
    except (KeyError, TypeError, ValueError):
        started = None

    if started is not None:
        for s in samples:
            issued = (s.get("dhcp") or {}).get("lease_issued_epoch")
            if issued and issued >= started:
                out["dhcp_issued_at"] = (s.get("dhcp") or {}).get("lease_issued_at")
                break

    # Total foreign broadcast across the whole outage, not per-sample: a single
    # 60s gap is a thin signal, the sum over a nine-check outage is not.
    counts = [(s.get("link") or {}).get("rx_broadcast") for s in samples]
    counts = [c for c in counts if isinstance(c, int)]
    if len(counts) >= 2 and counts[-1] >= counts[0]:
        out["l2_frames"] = counts[-1] - counts[0]
        try:
            out["l2_secs"] = int((datetime.fromisoformat(samples[-1]["at"])
                                  - datetime.fromisoformat(samples[0]["at"])).total_seconds())
        except (KeyError, TypeError, ValueError):
            pass
    return out


def _summarise_evidence(doc, outage):
    """
    Flatten an evidence document down to what the history panel shows.

    Takes the FIRST sample for the point-in-time facts: it is the one closest to
    the onset, and the expensive probes (traceroute, DHCP, tailscale) only run
    on that check. Sample count is carried separately so a long outage still
    shows that it was watched throughout.
    """
    samples = doc.get("samples") or []
    if not samples:
        return None
    first = samples[0]
    last = samples[-1]
    car = first.get("carrier") or {}
    arp = first.get("gateway_arp") or {}
    tr  = first.get("traceroute") or {}
    out = {
        "last_ok_at":      doc.get("last_ok_at"),
        "samples":         len(samples),
        "carrier":         car.get("carrier"),
        "carrier_changes": car.get("carrier_changes"),
        "gateway_arp":     arp.get("reachable"),
        "gateway_mac":     arp.get("mac"),
        "gateway_icmp":    first.get("gateway_icmp"),
        "traceroute_last": tr.get("last_responding"),
        "traceroute_target": tr.get("target"),
        "dhcp":            first.get("dhcp") or {},
        "tailscale":       first.get("tailscale") or {},
        "local_health":    first.get("local_health") or {},
        # The verdict the evidence itself reached. The log-line class is derived
        # from what the watchdog printed; this is what the samples support, and
        # on a witnessed outage the two agree by construction.
        "class":           doc.get("class"),
    }

    # Witnesses live on LATER samples, never the first — a lease renewed during
    # the outage can land on any check, and the broadcast delta needs a previous
    # sample to difference against. Reading only samples[0] (as this function
    # did until 2026-08-31) would collect the evidence and then never show it.
    out.update(_witnesses(samples, outage))
    # Bracket the onset. Escalation pins recovery to ~10s, but nothing can
    # recover the moment an outage BEGAN after the fact — it is only known to
    # lie between the last healthy check and the first failing one. Publishing
    # the upper bound alongside the measured span is the honest way to say so.
    if out["last_ok_at"] and outage.get("end"):
        try:
            span = (datetime.fromisoformat(outage["end"])
                    - datetime.fromisoformat(out["last_ok_at"])).total_seconds()
            out["duration_max_secs"] = max(0, int(span))
        except (ValueError, TypeError):
            pass
    return out


def attach_evidence(outages):
    """Join each outage to its evidence file, nearest-preceding within the window."""
    index = load_evidence_index()
    if not index:
        return outages
    for o in outages:
        try:
            start = datetime.fromisoformat(o["start"])
        except (KeyError, ValueError):
            continue
        best, best_gap = None, None
        for ts, doc in index.items():
            gap = (start - ts).total_seconds()
            if 0 <= gap <= EVIDENCE_MATCH_SECS and (best_gap is None or gap < best_gap):
                best, best_gap = doc, gap
        if best:
            ev = _summarise_evidence(best, o)
            if ev:
                o["evidence"] = ev
    return outages


def collect(persist=False, now=None):
    """
    The merged view: everything the history file holds, unioned with a fresh
    parse of whatever logs still exist. Read-only unless persist=True, so the
    webapp can call it on a GET without writing as the wrong user.
    """
    outages = attach_evidence(
        merge(load_history(), build_outages(parse_events(), now=now)))
    if persist:
        save_history(outages)
    return outages


# ── Summaries ────────────────────────────────────────────────────────────────

def fmt_duration(secs):
    """
    Format a duration, rounding to the nearest minute above a minute.

    Rounding rather than flooring is load-bearing for anything measured between
    two scheduled runs. The runs are an exact interval apart, but the timestamps
    we subtract are when each run *logged*, and the two do unequal work first: a
    failing check spends ~12s pinging dead externals and then the gateway before
    writing its line, while the recovering check writes after ~1s because the
    first host answers. Under the old 5-minute cadence a one-interval outage
    therefore measured ~289s, and flooring printed it as "4m" — a duration a
    5-minutely probe cannot possibly have observed, and an invitation to trust a
    precision this data does not have.

    Outages measured by the 10-second escalation (2026-08-30 onward) are genuine
    to ~10s and fall below the 60s branch, which prints exact seconds.
    """
    secs = int(secs or 0)
    if secs < 60:
        return f"{secs}s"
    mins = (secs + 30) // 60
    if mins < 60:
        return f"{mins}m"
    h, m = divmod(mins, 60)
    return f"{h}h {m}m" if m else f"{h}h"


def _local_day(iso):
    return iso[:10] if iso else ""


def summarise(outages, day=None):
    """Counts for one local day, plus the coverage the history can vouch for."""
    day = day or date.today().isoformat()
    today = [o for o in outages if _local_day(o.get("start")) == day]
    durations = [o.get("duration_secs", 0) for o in today]
    return {
        "day":            day,
        "count":          len(today),
        "total_secs":     sum(durations),
        "longest_secs":   max(durations) if durations else 0,
        "ongoing":        any(o.get("ongoing") for o in today),
        "history_count":  len(outages),
        "history_from":   _local_day(outages[0]["start"]) if outages else None,
    }


def summarise_range(outages, days, today=None):
    """
    Count and total downtime over the last `days` local days, today included.

    Compared on the date prefix rather than by subtracting timestamps, so the
    window means whole local days — the unit the history is presented in — and
    a DST change cannot shift the boundary by an hour.
    """
    today = today or date.today()
    first = (today - timedelta(days=days - 1)).isoformat()
    window = [o for o in outages if _local_day(o.get("start")) >= first]
    return {
        "days":       days,
        "count":      len(window),
        "total_secs": sum(o.get("duration_secs", 0) for o in window),
    }


def summary_line(summary):
    """The one-liner shown in the CLI health check and as the web card's link."""
    if summary["count"] == 0:
        return "No ISP outages today"
    n = summary["count"]
    line = f"{n} ISP outage{'s' if n != 1 else ''} today"
    line += f", longest {fmt_duration(summary['longest_secs'])}"
    if n > 1:
        line += f" ({fmt_duration(summary['total_secs'])} total)"
    if summary["ongoing"]:
        line += " — one still ongoing"
    return line


# How much history the panel shows before folding the rest away. The record
# itself is never truncated — outage-history.json keeps everything — this only
# bounds what renders by default, so the table stays readable as years accrue.
HISTORY_WINDOW_DAYS = 30


def partition_by_age(outages, days=HISTORY_WINDOW_DAYS, today=None):
    """
    Split into (recent, older) on whole local days.

    Compared on the date prefix, exactly as summarise_range does, so the two
    cannot disagree about which side of the boundary an outage falls on and a
    DST change cannot shift it by an hour.
    """
    today = today or date.today()
    first = (today - timedelta(days=days - 1)).isoformat()
    recent = [o for o in outages if _local_day(o.get("start")) >= first]
    older  = [o for o in outages if _local_day(o.get("start")) <  first]
    return recent, older


def summarise_set(outages):
    """Count, downtime and span for an arbitrary subset."""
    days = sorted({_local_day(o.get("start")) for o in outages if o.get("start")})
    return {
        "count":      len(outages),
        "total_secs": sum(o.get("duration_secs", 0) for o in outages),
        "from":       days[0] if days else None,
        "to":         days[-1] if days else None,
    }


def group_by_day(outages):
    """Newest day first, newest outage first within a day, with per-day totals."""
    days = {}
    for o in outages:
        days.setdefault(_local_day(o.get("start")), []).append(o)
    out = []
    for day in sorted(days, reverse=True):
        items = sorted(days[day], key=lambda o: o["start"], reverse=True)
        out.append({
            "day":        day,
            "count":      len(items),
            "total_secs": sum(o.get("duration_secs", 0) for o in items),
            "outages":    items,
        })
    return out


def main(argv):
    persist = "--persist" in argv
    outages = collect(persist=persist)
    if "--json" in argv:
        json.dump({"outages": outages,
                   "summary": summarise(outages),
                   "by_day":  group_by_day(outages)}, sys.stdout, indent=2)
        print()
        return 0
    s = summarise(outages)
    line = summary_line(s)
    if s["history_count"]:
        line += f"  (history: {s['history_count']} recorded since {s['history_from']})"
    print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
