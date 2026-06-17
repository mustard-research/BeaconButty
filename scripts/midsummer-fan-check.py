#!/usr/bin/env python3
"""
Midsummer fan-threshold check.

Runs once from a systemd timer on 2026-07-15 (scheduled 2026-04-24 after a
whisper.cpp stress test confirmed cool-ambient baseline peaks around 61.7 °C).
Compares the last 14 days of bb-watchdog temperature records against that
April baseline documented on the Fan Control vault page, checks for any
throttling events since last boot, and appends findings to the page with an
automatic git commit and push to origin.

Idempotent against the current date: if a block for today's date already
exists in the Fan Control page, it exits without writing or committing.
"""

import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from statistics import median

DATA_DIR = Path("/var/lib/beaconbutty/watchdog/data")
REPO_ROOT = Path("/home/dm/BeaconButty")
FAN_DOC = REPO_ROOT / "obsidian/BeaconButty/Hardware/Fan Control.md"
INSERT_BEFORE = "## Monitoring"
WINDOW_DAYS = 14


def load_window(today: datetime.date, days: int):
    records = []
    for i in range(days):
        d = today - datetime.timedelta(days=i)
        path = DATA_DIR / f"{d.isoformat()}.json"
        if not path.exists():
            continue
        with path.open() as f:
            data = json.load(f)
        records.extend(data.get("records", []))
    records.sort(key=lambda r: r["time"])
    return records


def count_transitions(records, key):
    n, prev = 0, None
    for r in records:
        cur = bool(r.get(key))
        if prev is not None and cur != prev:
            n += 1
        prev = cur
    return n


def parse_throttled():
    try:
        out = subprocess.check_output(
            ["vcgencmd", "get_throttled"], timeout=5
        ).decode().strip()
    except Exception as e:
        return f"unavailable ({e})", False
    m = re.search(r"throttled=0x([0-9a-fA-F]+)", out)
    if not m:
        return f"unexpected output: {out}", False
    val = int(m.group(1), 16)
    flags = []
    if val & (1 << 16): flags.append("under-voltage occurred")
    if val & (1 << 17): flags.append("freq-cap occurred")
    if val & (1 << 18): flags.append("freq-throttled occurred")
    if val & (1 << 19): flags.append("soft-temp-limit occurred")
    bad = bool(val & ((1 << 18) | (1 << 19)))
    desc = out + (" — " + ", ".join(flags) if flags else " — no throttling since boot")
    return desc, bad


def build_block(today_iso: str, records, throttle_desc: str, throttle_bad: bool):
    temps = [r["temp_c"] for r in records]
    idle = [r["temp_c"] for r in records
            if not r.get("rpi_fan") and not r.get("pironman_fan")]
    pi_pct = 100.0 * sum(1 for r in records if r.get("rpi_fan")) / len(records)
    pm_pct = 100.0 * sum(1 for r in records if r.get("pironman_fan")) / len(records)
    hours = len(records) / 60.0
    pi_cyc_hr = count_transitions(records, "rpi_fan") / hours
    pm_cyc_hr = count_transitions(records, "pironman_fan") / hours
    peak = max(temps)
    idle_med = median(idle) if idle else None

    if throttle_bad:
        rec = ("**Throttling occurred** — fans couldn't keep up. Lower the "
               "Pi cut-in (58 → 55 °C) and/or Pironman cut-in (60 → 57 °C) "
               "and rerun after a week.")
        change = True
    elif peak > 70:
        rec = (f"Peak {peak:.1f} °C exceeds 70 °C. No throttling yet, but "
               "headroom is shrinking — consider lowering Pironman cut-in "
               "to 57 °C to keep peaks < 65 °C.")
        change = True
    elif peak > 65:
        rec = (f"Peak {peak:.1f} °C. Above the Apr-24 baseline but still "
               "comfortably within envelope. Monitor; no change yet.")
        change = False
    else:
        rec = (f"Peak {peak:.1f} °C. Well within envelope; summer ambient "
               "did not shift peaks materially. No change needed.")
        change = False

    idle_cell = f"{idle_med:.1f} °C" if idle_med is not None else "n/a"
    span = (f"{records[0]['time'][:10]} → {records[-1]['time'][:10]}, "
            f"{len(records)} samples")

    return (
        f"\n### Midsummer check — {today_iso}\n\n"
        f"14-day window: {span}.\n\n"
        f"| Metric | Apr-24 baseline | {today_iso} |\n"
        f"|---|---|---|\n"
        f"| Idle temp (median, both fans off) | ~51.5 °C | {idle_cell} |\n"
        f"| Peak temp (any) | 61.7 °C (40-min stress) | {peak:.1f} °C |\n"
        f"| Pi fan duty cycle | n/a | {pi_pct:.1f}% |\n"
        f"| Pironman fan duty cycle | n/a | {pm_pct:.1f}% |\n"
        f"| Pi fan transitions / hr | ~7.5 (under load) | {pi_cyc_hr:.1f} |\n"
        f"| Pironman fan transitions / hr | ~10 (under load) | {pm_cyc_hr:.1f} |\n"
        f"| `vcgencmd get_throttled` | `0x0` | `{throttle_desc}` |\n\n"
        f"**Recommendation**: {rec}\n"
    ), change


def main():
    today = datetime.date.today()
    today_iso = today.isoformat()

    records = load_window(today, WINDOW_DAYS)
    if not records:
        print(f"no watchdog data found in last {WINDOW_DAYS} days under {DATA_DIR}",
              file=sys.stderr)
        return 1

    doc = FAN_DOC.read_text()
    if f"### Midsummer check — {today_iso}" in doc:
        print(f"Fan Control page already has a block for {today_iso}; skipping.")
        return 0
    if INSERT_BEFORE not in doc:
        print(f"marker '{INSERT_BEFORE}' not found in {FAN_DOC}; refusing to write",
              file=sys.stderr)
        return 2

    throttle_desc, throttle_bad = parse_throttled()
    block, change = build_block(today_iso, records, throttle_desc, throttle_bad)

    print(block)

    new_doc = doc.replace(INSERT_BEFORE, block + "\n" + INSERT_BEFORE, 1)
    FAN_DOC.write_text(new_doc)

    subprocess.run(["git", "-C", str(REPO_ROOT), "add", str(FAN_DOC)], check=True)
    summary = "threshold change recommended" if change else "no change needed"
    subprocess.run(
        ["git", "-C", str(REPO_ROOT), "commit", "-m",
         f"Fan Control: midsummer fan check ({today_iso}) — {summary}"],
        check=True,
    )
    subprocess.run(["git", "-C", str(REPO_ROOT), "push"], check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
