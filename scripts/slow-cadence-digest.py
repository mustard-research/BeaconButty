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
ASSETS_HISTORY = "/var/lib/beaconbutty/assets-history.json"
TOP_N        = 10


def fp_filter(cands: list[dict]) -> list[dict]:
    """Drop candidates matching the current FP registry
    (device/domain/protocol/org).
    The detector filters at scan time, but an FP added since its last run —
    or one added from the slow-beacons page itself — must not resurface in
    the morning digest.

    MIRROR: FP coverage here must match slow-cadence.py's scan-time filter
    (SNI, dst literal, every HTTP Host seen on the dst, device, protocol,
    org) or a candidate the detector suppressed reappears in the digest."""
    try:
        with open(FP_PATH) as f:
            fp = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return cands
    doms = list(fp.get("domains", {}))
    macs = {m.lower() for m in fp.get("devices", {})}
    protos = list(fp.get("protocols", {}))

    # Org entries are either a bare reason (LAN-wide) or {"reason","devices"}
    # scoped to specific MACs. Same normalisation as slow-cadence.py fp_orgs().
    org_entries: list[tuple[str, set[str] | None]] = []
    for pat, val in (fp.get("orgs") or {}).items():
        if isinstance(val, dict):
            scoped = {m.lower() for m in (val.get("devices") or [])}
            org_entries.append((pat, scoped or None))
        else:
            org_entries.append((pat, None))

    # IP → MAC from leases plus asset history; history matters because the
    # 14-day window covers IPs a device no longer holds.
    ip_mac: dict[str, str] = {}
    try:
        with open(ASSETS_HISTORY) as f:
            for hist_ip, info in json.load(f).items():
                mac = (info.get("mac") or "").lower()
                if mac:
                    ip_mac[hist_ip] = mac
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    try:
        with open(LEASES) as f:
            for line in f:
                p = line.split()
                if len(p) >= 3:
                    ip_mac[p[2]] = p[1].lower()
    except FileNotFoundError:
        pass

    def match(host, pats):
        return bool(host) and any(
            fnmatch.fnmatch(host, pat)
            or (pat.startswith("*.") and host == pat[2:])
            for pat in pats)

    def proto_match(services):
        """Same component semantics as slow-cadence.py fp_service_match() and
        webapp/app.py _fp_service_match(): EVERY component must be FP'd, so a
        keepalive FP can't hide un-FP'd traffic sharing the row. Each element
        is already one component, so commas inside it are Zeek's own service
        list and must not be split.

        A candidate written before the detector emitted `services` has nothing
        to match, so it falls through to the other filters rather than
        erroring — self-heals next run."""
        comps = [(s or "").strip() for s in (services or [])]
        comps = [c for c in comps if c]
        if not comps:
            return False
        return all(any(c == p or c.startswith(p + ":") for p in protos)
                   for c in comps)

    def org_match(org, src_mac):
        if not org:
            return False
        for pat, scoped in org_entries:
            if not fnmatch.fnmatch(org, pat):
                continue
            if scoped is None or src_mac in scoped:
                return True
        return False

    kept = []
    for c in cands:
        src_mac = ip_mac.get(c.get("src", ""), "")
        if src_mac and src_mac in macs:
            continue
        if match(c.get("sni", ""), doms) or match(c.get("dst", ""), doms):
            continue
        if any(match(h, doms) for h in (c.get("http_hosts") or [])):
            continue
        if org_match(c.get("dst_org", ""), src_mac):
            continue
        if proto_match(c.get("services")):
            continue
        kept.append(c)
    return kept


def is_enabled() -> bool:
    """Honour the per-type toggle in /health → Alert types. The digest
    posts directly to Slack (not via Lambda) so the toggle wouldn't
    otherwise apply — read it explicitly here."""
    try:
        with open(ALERT_CONFIG) as f:
            cfg = json.load(f)
        # Toggles live under the "enabled" key — same shape alert.sh reads.
        return bool(cfg.get("enabled", {}).get("slow_cadence_digest", True))
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
    # Why is this row here? — either it cleared the alert gate (and would
    # have paged, back when slow_cadence_beacon paged in real time), or it
    # was demoted and we surface the gate's reasoning.
    if c.get("alert_eligible"):
        reason = "⚠ sole LAN talker · non-hyperscaler"
        marker = "*!*"
    else:
        reason_bits = []
        if hyper:
            reason_bits.append("☁ hyperscaler")
        if talkers and talkers > 1:
            reason_bits.append(f"{talkers} LAN talkers")
        reason = " · ".join(reason_bits) or "no demote reason"
        marker = "   "
    line1 = (f"`{idx:>2}.`{marker} `{src_lbl}` → "
             f"`{target}:{c.get('dst_port', '?')}` "
             f"— {days}d, ~{rate}/d at {hour:02d}:00 UTC, {cons}% hour-cons")
    line2 = f"      _{org}{(' · ' + cc) if cc else ''} · {reason}_"
    return line1 + "\n" + line2


def build_message(report: dict):
    """Return (text, n_total) — text is None when there's nothing worth
    posting, so the caller can skip the Slack hit entirely on empty days.

    `slow_cadence_beacon` no longer pages in real time (every one of the 25
    it ever fired was a false alarm — the destinations are unbounded Chinese
    CDN/P2P hostnames, so per-domain FPs never converge). The digest is now
    the only channel for these findings, so gate-eligible candidates must
    appear here too — pinned above the hunt rows and flagged, never squeezed
    out of the top-N by hunt volume."""
    cands = fp_filter(report.get("candidates", []))
    by_persistence = lambda c: (-c.get("days_seen", 0),
                                -(c.get("hour_consistency") or 0))
    flagged = sorted((c for c in cands if c.get("alert_eligible")),
                     key=by_persistence)
    hunt    = sorted((c for c in cands if not c.get("alert_eligible")),
                     key=by_persistence)
    if not flagged and not hunt:
        return None, 0

    top    = flagged[:TOP_N]
    top   += hunt[:max(0, TOP_N - len(top))]
    total  = len(flagged) + len(hunt)
    today  = date.today().isoformat()
    lead   = (f"*{len(flagged)} flagged* (`!`) · {len(hunt)} hunt"
              if flagged else f"{len(hunt)} hunt candidate"
                              f"{'' if len(hunt) == 1 else 's'}")
    header = (
        f"*📋 Slow-cadence digest — {today}*  "
        f"_({len(top)} of {total} shown — {lead})_\n\n"
        f"_Periodic multi-day egress. Rows marked `!` cleared the alert gate "
        f"(sole LAN talker, non-hyperscaler dst) — look at those first. The "
        f"rest are hyperscaler-hosted or shared-LAN endpoints; glance through "
        f"and investigate anything unfamiliar._"
    )
    body   = "\n\n" + "\n".join(format_candidate(i + 1, c)
                                for i, c in enumerate(top))
    footer = "\n\n_Full hunt surface: https://bb0/beacons/slow_"
    return header + body + footer, total


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
    msg, n_total = build_message(report)
    if msg is None:
        print("No slow-cadence candidates — skipping Slack post.")
        return 0
    token, channel, separate = load_slack()
    if not token:
        return 1
    if post(token, channel, msg):
        ch_note = "dedicated digest channel" if separate else "main channel"
        print(f"Posted digest to {ch_note} #{channel}: "
              f"{min(TOP_N, n_total)} of {n_total} candidates.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
