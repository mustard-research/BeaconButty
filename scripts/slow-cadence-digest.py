#!/usr/bin/env python3
"""
slow-cadence-digest.py — daily Slack roll-up of hunt-only candidates.

Posts a once-daily summary of the slow-cadence dashboard's top hunt
candidates — i.e. the periodic-egress findings that were *demoted* by
the alert gate (hyperscaler / shared-LAN) and so never paged in real
time. Designed to give the operator a low-volume daily nudge to glance
at the hunt surface without re-introducing the BAU-noise problem the
gate just fixed.

  • Reads /var/lib/beaconbutty/reports/slow-cadence.json (written hourly
    by slow-cadence.py) — no extra ClickHouse work here.
  • Picks the top N (default 10) hunt-only candidates ordered by
    persistence then hour-consistency.
  • Posts directly via Slack's chat.postMessage using the xoxp- token in
    /var/lib/beaconbutty/slack-config.json. Bypasses the Lambda alert
    pipeline so dedup doesn't suppress the daily firing and so we can
    use a multi-line markdown body.
  • Channel is `digest_channel` in slack-config.json if set, else the
    main `channel`. To split the hunt digest from real alerts, add:
        {"token": "...", "channel": "beacon-butty",
         "digest_channel": "beacon-butty-hunt"}

Run via beaconbutty-slow-cadence-digest.timer (daily 08:00 UTC).
"""

from __future__ import annotations

import fnmatch
import json
import os
import sys
import urllib.request
import urllib.error
from datetime import date

REPORT       = "/var/lib/beaconbutty/reports/slow-cadence.json"
SLACK_CONF   = "/var/lib/beaconbutty/slack-config.json"
ALERT_CONFIG = "/var/lib/beaconbutty/alert-config.json"
FP_PATH      = "/var/lib/beaconbutty/false-positives.conf"
LEASES       = "/var/lib/misc/dnsmasq.leases"
TOP_N        = 10


def fp_filter(cands: list[dict]) -> list[dict]:
    """Drop candidates matching the current FP registry (device/domain/org).
    The detector filters at scan time, but an FP added since its last run —
    or one added from the slow-beacons page itself — must not resurface in
    the morning digest."""
    try:
        with open(FP_PATH) as f:
            fp = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return cands
    doms = list(fp.get("domains", {}))
    orgs = list(fp.get("orgs", {}))
    macs = {m.lower() for m in fp.get("devices", {})}
    fp_ips: set[str] = set()
    try:
        with open(LEASES) as f:
            for line in f:
                p = line.split()
                if len(p) >= 3 and p[1].lower() in macs:
                    fp_ips.add(p[2])
    except FileNotFoundError:
        pass

    def match(host, pats):
        return bool(host) and any(
            fnmatch.fnmatch(host, pat)
            or (pat.startswith("*.") and host == pat[2:])
            for pat in pats)

    return [c for c in cands
            if c.get("src") not in fp_ips
            and not match(c.get("sni", ""), doms)
            and not match(c.get("dst", ""), doms)
            and not match(c.get("dst_org", ""), orgs)]


def is_enabled() -> bool:
    """Honour the per-type toggle in /health → Alert types. The digest
    posts directly to Slack (not via Lambda) so the toggle wouldn't
    otherwise apply — read it explicitly here."""
    try:
        with open(ALERT_CONFIG) as f:
            cfg = json.load(f)
        return bool(cfg.get("slow_cadence_digest", True))
    except (FileNotFoundError, json.JSONDecodeError):
        return True   # default-on, same convention as Lambda alerts


def load_report():
    try:
        with open(REPORT) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"slow-cadence report unreadable: {e}", file=sys.stderr)
        return None


def load_slack():
    try:
        with open(SLACK_CONF) as f:
            d = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"slack-config unreadable: {e}", file=sys.stderr)
        return None, None, None
    token   = d.get("token")
    channel = d.get("digest_channel") or d.get("channel")
    if not token or not channel:
        print("slack-config missing token or channel", file=sys.stderr)
        return None, None, None
    return token, channel, d.get("digest_channel") is not None


def format_candidate(idx: int, c: dict) -> str:
    target = c.get("sni") or c.get("http_host") or c.get("dst") or "?"
    org    = c.get("dst_org") or "unknown ASN"
    cc     = c.get("dst_cc") or ""
    talkers = c.get("lan_talkers") or 1
    hyper   = c.get("is_hyperscaler")
    src_lbl = c.get("src", "?")
    days    = c.get("days_seen", 0)
    rate    = c.get("conns_per_active_day", 0)
    hour    = c.get("modal_hour_utc", 0)
    cons    = int((c.get("hour_consistency") or 0) * 100)
    # Why was this demoted? — surfaces the gate's reasoning.
    reason_bits = []
    if hyper:
        reason_bits.append("☁ hyperscaler")
    if talkers and talkers > 1:
        reason_bits.append(f"{talkers} LAN talkers")
    reason = " · ".join(reason_bits) or "no demote reason"
    line1 = (f"`{idx:>2}.` `{src_lbl}` → `{target}:{c.get('dst_port', '?')}` "
             f"— {days}d, ~{rate}/d at {hour:02d}:00 UTC, {cons}% hour-cons")
    line2 = f"      _{org}{(' · ' + cc) if cc else ''} · {reason}_"
    return line1 + "\n" + line2


def build_message(report: dict):
    """Return (text, n_hunt) — text is None when there's nothing worth
    posting, so the caller can skip the Slack hit entirely on empty days."""
    cands = fp_filter(report.get("candidates", []))
    # Hunt-only: candidates the alert gate demoted (alert_eligible == False).
    hunt = [c for c in cands if not c.get("alert_eligible")]
    if not hunt:
        return None, 0
    hunt.sort(key=lambda c: (
        -c.get("days_seen", 0),
        -(c.get("hour_consistency") or 0),
    ))
    top    = hunt[:TOP_N]
    today  = date.today().isoformat()
    header = (
        f"*📋 Slow-cadence digest — {today}*  "
        f"_({len(top)} of {len(hunt)} hunt candidate"
        f"{'' if len(hunt) == 1 else 's'} shown)_\n\n"
        f"_Periodic egress that didn't page in real time — typically "
        f"hyperscaler-hosted SaaS or shared-LAN endpoints. Glance through; "
        f"investigate anything unfamiliar._"
    )
    body   = "\n\n" + "\n".join(format_candidate(i + 1, c)
                                for i, c in enumerate(top))
    footer = "\n\n_Full hunt surface: https://bb0/beacons/slow_"
    return header + body + footer, len(hunt)


def post(token: str, channel: str, text: str) -> bool:
    payload = json.dumps({
        "channel":  channel,
        "text":     text,
        "mrkdwn":   True,
        "unfurl_links": False,
        "unfurl_media": False,
    }).encode()
    req = urllib.request.Request(
        "https://slack.com/api/chat.postMessage",
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json; charset=utf-8",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        print(f"Slack post failed: {e}", file=sys.stderr)
        return False
    if not data.get("ok"):
        print(f"Slack returned not-ok: {data}", file=sys.stderr)
        return False
    return True


def main() -> int:
    if not is_enabled():
        print("slow_cadence_digest disabled in alert-config.json — skipping.")
        return 0
    report = load_report()
    if report is None:
        return 1
    msg, n_hunt = build_message(report)
    if msg is None:
        print("No hunt candidates — skipping Slack post.")
        return 0
    token, channel, separate = load_slack()
    if not token:
        return 1
    if post(token, channel, msg):
        ch_note = "dedicated digest channel" if separate else "main channel"
        print(f"Posted digest to {ch_note} #{channel}: "
              f"{min(TOP_N, n_hunt)} of {n_hunt} hunt candidates.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
