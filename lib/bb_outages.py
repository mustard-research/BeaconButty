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
The watchdog probes every 5 minutes, so an outage is only ever *detected*
within that window: the true start lies somewhere in the 5 minutes before the
first failing probe, and the true end somewhere in the 5 minutes before the
recovery probe. Everything here reports the detected window and every caller
is expected to say so — an outage shorter than the gap between two probes
leaves no trace at all, so "0 outages" means "none seen", not "none happened".

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

# wan-watchdog.timer's period. Used only to bound an outage whose recovery was
# never logged (the log was rotated or lost mid-outage); we credit it one more
# probe interval rather than guessing further.
PROBE_INTERVAL_SECS = 5 * 60

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

# Verdict text → machine class → display label. The first two wordings are the
# current ones; "likely ISP outage" is the pre-2026-08-28 wording, kept so the
# backfilled history classifies old events instead of showing them as unknown.
_CLASSES = [
    ("unreachable too",      "link_fault",   "Link / CPE fault"),
    ("break is upstream",    "isp_upstream", "ISP outage — upstream"),
    ("likely ISP outage",    "isp_upstream", "ISP outage — upstream"),
    ("no default route",     "no_route",     "Local routing fault"),
    ("no IP address",        "no_ip",        "WAN had no IP"),
]
CLASS_LABELS = {c: label for _, c, label in _CLASSES}
CLASS_LABELS["unknown"] = "Cause not recorded"


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


def _finish(cur, end, ongoing, estimated):
    classes = Counter(cur["classes"])
    primary = classes.most_common(1)[0][0] if classes else "unknown"
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


def collect(persist=False, now=None):
    """
    The merged view: everything the history file holds, unioned with a fresh
    parse of whatever logs still exist. Read-only unless persist=True, so the
    webapp can call it on a GET without writing as the wrong user.
    """
    outages = merge(load_history(), build_outages(parse_events(), now=now))
    if persist:
        save_history(outages)
    return outages


# ── Summaries ────────────────────────────────────────────────────────────────

def fmt_duration(secs):
    secs = int(secs or 0)
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m"
    h, m = divmod(secs // 60, 60)
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
