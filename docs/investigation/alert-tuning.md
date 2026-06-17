---
tags: [beaconbutty/investigation]
created: 2026-04-16
---

# Alert Tuning

## RITA beacon scoring

RITA v5.1.1 scores each (source IP, destination IP) pair on a **0.0 – 1.0 scale** based on:

| Factor | Description |
|--------|-------------|
| **Regularity** | How consistent the interval is between connections (jitter analysis) |
| **Connection count** | More connections in the window = higher confidence |
| **Skew** | Consistency of packet sizes across connections |
| **Duration** | Short-duration connections with high regularity score highest |

A score of **1.0** represents near-perfect beaconing — extremely regular intervals, consistent sizes, many connections. Real malware C2 beacons often score 0.95–1.0.

### Score 0 with High classification

RITA marks **long-duration persistent connections** (e.g. a kept-alive TCP session) as `High` severity with a beacon score of `0`. These are **not beacons** — they are being flagged for different reasons (duration anomaly, not regularity).

The Device Hotlist and reports skip score-0 rows. Do not investigate score-0 entries as beacons.

## Alert threshold

Slack alerts fire when beacon score ≥ **1.0**.

This threshold was deliberately set at the maximum to reduce noise. Early experience showed that lowering to 0.8 or 0.9 generated frequent alerts from legitimate software with regular update checks.

## Alert gate (2026-05-06) — primary noise defence

Even with score ≥ 1.0, RITA's `high_score_beacon` was firing on long-running CDN flows (streaming, long polling). The same problem afflicted the new `slow_cadence_beacon` and the existing `persistent_beacon` (strobes). FP entries were structurally insufficient — every new SaaS provider or new device adds a new candidate, and on someone else's network the FP list starts empty.

A two-signal gate now decides whether `slow_cadence_beacon`, `high_score_beacon`, and `persistent_beacon` Slack-page:

1. **Lonely** — sole LAN device talking to this (dst, dst_port) over the 14-day window
2. **Non-hyperscaler** — dst ASN not in a token list (amazon, cloudflare, google, microsoft, apple, akamai, fastly, tencent, alibaba, …)

Both must be true to page. Failing either keeps the candidate on its dashboard (the **hunt** surface) — visible, badged with the demotion reason, but silent on Slack. Full write-up: [Alert Chain](../architecture/alert-chain.md).

> [!important]
> **Adding an FP entry is now the *secondary* fix for noise — try the gate first.**
>
> When a slow-cadence/high-score/persistent alert feels like noise, ask: "would the gate have caught this?" If the dst is on a hyperscaler ASN or shared with other LAN devices, the gate already handles it — no FP needed. Only reach for a fresh FP entry when the gate genuinely doesn't apply (e.g. a single device talking to a non-hyperscaler dst that's still legitimate).
>
> `threat_intel_hit` and `tor_contact` remain ungated — both carry independent strong signal.

The /health page surfaces gate stats (last run, fired, gated breakdown) so the operator can see the gate doing useful work even on quiet days.

### Slow-cadence threshold tweaks (same date)

- `MIN_HOUR_CONSISTENCY` raised 0.7 → 0.8 — benign SaaS clustered at 70-83%; real sleep-cycle C2 should cluster tighter.
- HTTP `host`/`useragent`/`uri_sample`/`method_mix` now surface in the dashboard for non-TLS flows (OCSP/CRL traffic shows up as `Microsoft-CryptoAPI/10.0` GET 100% with the OCSP-encoded URI prefix — instantly recognisable instead of "no SNI · Cloudflare").
- FP cascade now suppresses a candidate when **any** Host header observed on its shared CDN dst is FP'd — single `*.sectigo.com` entry kills the whole shared-IP OCSP candidate.

## Slack integration

| Item | Detail |
|------|--------|
| Workspace | `<your-slack-workspace>` |
| Channel | #beacon-butty |
| Token | xoxp- user token at `/var/lib/beaconbutty/slack-config.json` |
| Alert content | Device IP, hostname, beacon score, destination, connection count |
| Clear button | Health page — "Clear Slack Channel" purges all channel history |

## Suricata alerts

Suricata runs alongside RITA as a **signature-based IDS**. It uses the Emerging Threats Open ruleset and detects known-bad traffic patterns.

### Priority levels

| Priority | Meaning | Default visibility |
|----------|---------|-------------------|
| P1 | Critical — known malware C2, exploit traffic | Always shown |
| P2 | High — suspicious, worth investigating | Always shown |
| P3 | Medium — often noisy, may be FP | Hidden by default |
| P4 | Low | Hidden by default |

The Suricata page shows P1 and P2 by default. A "Show P3 (N)" toggle reveals lower-priority alerts. P3/P4 are hidden because they are frequently noisy (e.g. TLS version alerts from old devices, common scanning traffic).

### Alert sources

| File | Contents |
|------|---------|
| `/var/log/suricata/fast.log` | One-line summary per alert — used for counts and the webapp listing |
| `/var/log/suricata/eve.json` | Full JSON event log — used for alert detail and enrichment |

`eve.json` grows to ~200MB by end of day and is rotated daily by logrotate (14-day retention). Rotated archives are compressed and moved to `/var/lib/suricata/archive/` on NVMe. See [Webapp](../development/webapp.md) for the performance optimisations on this file.

## Interpreting a beacon alert

A typical alert workflow:

1. **Slack fires** with device IP + score
2. Open webapp → Beacons page → Device Hotlist → expand device
3. Check destination: GeoIP org, FQDN (if available from DNS), Zeek SNI
4. Check connection count and beacon period (time between connections)
5. Cross-reference with Suricata — has Suricata also flagged this destination?
6. If Suricata + RITA both flag the same destination, confidence is high

### Signs of genuine malware C2

- Destination has no clear organisational purpose (no obvious tech/cloud company)
- Domain was recently registered (check WHOIS creation date)
- Connections happen at identical intervals (zero jitter)
- Connections happen overnight / during non-business hours
- Multiple devices beaconing to the same destination
- Suricata also raises an alert on the same traffic
- TLS SNI shows an unfamiliar hostname with no obvious business purpose

### Active investigations

_None._

### Closed investigations

- **dnanudge.com** — Resolved 2026-04-22. iCloud Calendar subscription to a
  2022 DNA Nudge `.ics` feed that never parsed, so `dataaccessd` retried on
  every wake. Full write-up in *Incident Log*.
  TLS fingerprint was misleading — it's stack-level (URLSession) not
  process-level, so Safari and system daemons are indistinguishable on the
  wire.

## Detection-motivation reading

- *Print Me If You Dare (Cui 2011)* — why BB-class network visibility
  matters for embedded devices that have no host-based defence. The
  "reverse IP proxy" payload in the talk is precisely the outbound-beacon
  shape RITA scores near 1.0.
