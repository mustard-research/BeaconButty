---
tags: [beaconbutty/architecture]
created: 2026-04-17
---

# Alert Chain

All BeaconButty alerts flow through a single AWS Lambda that dispatches to Slack. This gives us: per-type enable/disable, dedup, retries, and a place to add future channels (email, PagerDuty) without touching the Pi.

```
bb0 script  ──►  scripts/alert.sh  ──►  HTTPS POST  ──►  API Gateway  ──►  Lambda  ──►  Slack #beacon-butty
                                           (with shared secret)
```

## Call site

Any script can emit an alert by calling:

```bash
alert.sh <type> <severity> <device> "<detail>"
```

Deployed as `/usr/local/bin/beaconbutty-alert.sh`. Source: `scripts/alert.sh`.

| Arg | Allowed values |
|-----|----------------|
| `type` | `high_score_beacon`, `persistent_beacon`, `threat_intel_hit`, `suricata_p1_lan`, `suricata_p1_repeated`, `new_device`, `traffic_anomaly`, `tor_contact`, `service_down`, `disk_critical`, `slow_cadence_digest` (direct Slack post — bypasses Lambda) |
| `severity` | `high`, `medium`, `low` |
| `device` | LAN IP (e.g. `192.168.50.42`) or hostname (e.g. `bb0`) |
| `detail` | Free-form string — shown in the Slack message body |

Examples:

```bash
beaconbutty-alert.sh high_score_beacon high 192.168.50.42 "Score 0.97 → evil.com (first seen today)"
beaconbutty-alert.sh service_down medium bb0 "Zeek is not running"
beaconbutty-alert.sh new_device medium 192.168.50.201 "MAC aa:bb:cc:dd:ee:ff (unknown vendor)"
```

## `new_device` detection

A MAC counts as new only if it has never been seen **and** is not on the FP device list. `scripts/assets.sh` unions three sources to form the baseline:

| Source | Purpose |
|--------|---------|
| `/var/lib/beaconbutty/known-macs.json` | Persistent ever-seen MAC set — script appends every current-run MAC on exit |
| `old_by_mac` (previous `assets.json` snapshot) | Seeds known-macs.json on upgrade so we don't re-alert the day the persistent file is introduced |
| `devices` keys in `/var/lib/beaconbutty/false-positives.conf` | User-declared-known devices |

If the baseline is empty (fresh install) the script suppresses all alerts — no baseline means no reliable "new". Previously we compared only to the previous-run cache; sporadic devices (scales, the bike) re-alerted every few days as DHCP leases expired and ARP entries aged out.

The alert path is also LAA-gated (2026-05-06) — see [`new_device` LAA gate (2026-05-06)](#new_device-laa-gate-2026-05-06) below.

## Transport

| Item | Value |
|------|-------|
| Endpoint | `https://<your-api-id>.execute-api.<region>.amazonaws.com/alert` (API Gateway) |
| Method | POST, `Content-Type: application/json` |
| Auth | `X-BeaconButty-Secret: <shared-alert-secret>` (shared header, validated by Lambda) |
| Timeout | 10 s (`curl --max-time 10`) |
| On failure | Exit 1, `echo` to stderr, row written to log regardless |

Payload (generated inline by Python):

```json
{
  "type":      "high_score_beacon",
  "severity":  "high",
  "device":    "192.168.50.42",
  "detail":    "Score 0.97 → evil.com",
  "timestamp": "2026-04-17T20:40:00Z"
}
```

## Per-type enable/disable

Config: `/var/lib/beaconbutty/alert-config.json`.

```json
{
  "enabled": {
    "high_score_beacon":    true,
    "service_down":         true,
    "new_device":           false,
    "suricata_p1_repeated": true
  }
}
```

`alert.sh` reads this file before sending. If the type's key is `false`, the script exits 0 without posting. Missing keys default to `true`.

> [!note]
> Disabling a type in the Pi's config is the noise knob. The Lambda dedup is a backup, not the first line of defence.

## Dedup

The Lambda suppresses duplicate alerts. When suppression fires, the Lambda returns HTTP 200 with body `Deduplicated`, and `alert.sh` logs:

```
Alert suppressed (duplicate): high_score_beacon / 192.168.50.42
```

Dedup state is held server-side (DynamoDB / Lambda-local). The key is approximately `(type, device, detail-hash)`. Exact TTL is set in the Lambda.

> [!warning] Detail strings must be stable
> The Lambda dedups on `(type, device, detail)` — including the full detail string. If the detail varies tick-to-tick (e.g. baking a per-tick connection count or timestamp into the message), every cron tick produces a new key and dedup never matches. Found 2026-05-05 when `ja4-threat-check.py` was paging the user 9× per device per 15 min because the detail included a growing TLS connection count. Fix: keep details stable per logical finding — operators open the dashboard for live numbers.

## Alert gate — lonely + non-hyperscaler (2026-05-06)

Alerts must be precise. A trickle of "novel periodic-egress destination" pages teaches the operator to ignore the channel inside a week — on a fresh deployment of this product on someone else's network, that erodes trust before they ever see a real finding. The structural fix is a confidence-multiplier gate, not an ever-growing FP list.

A finding only Slack-pages when it is **both**:

1. **Lonely** — `uniqExact(src) == 1` for the (dst, dst_port) over the 14-day window. Implants are device-specific; SaaS endpoints are reached by many devices on the LAN simultaneously.
2. **Non-hyperscaler ASN** — substring match against a token list (`amazon`, `cloudflare`, `google`, `microsoft`, `apple`, `akamai`, `fastly`, `tencent`, `alibaba`, …). Real C2 rarely hides on the major CDNs; when it does, the lonely check still catches the worst of it.

Anything that fails either check stays on its dashboard (the **hunt** surface) with a visible reason — the operator can see the gate decision per row.

| Alert type | Gated? | Why |
|---|---|---|
| `slow_cadence_beacon` | ✅ | Most periodic egress is benign SaaS; gate kept the hunt surface useful while quieting Slack |
| `high_score_beacon` | ✅ | RITA score 1.0 alone catches long-running CDN flows |
| `persistent_beacon` | ✅ | Strobes from streaming services / long polling are common |
| `threat_intel_hit` | ❌ | Exact JA4 match is high-confidence on its own |
| `tor_contact` | ❌ | Tor egress from a LAN device is page-worthy unconditionally |
| `service_down`, `disk_critical`, `new_device`, `suricata_p1_*` | ❌ | Independent strong signal; not periodic-egress detectors |

**Implementation:**

- Per-(dst, dst_port) talkers count comes from a single ClickHouse `uniqExact(src)` aggregation over the 14-day window. The IN-list scope filter is left to Python — embedding it 14× via UNION ALL overruns `max_query_size`.
- ASN org via `geoip2` and the `GeoLite2-ASN.mmdb` already on bb0.
- Both `scripts/slow-cadence.py` and `scripts/summarize.sh`'s Python heredoc maintain duplicate `HYPERSCALER_TOKENS` lists. Keep them in sync — comments in both files note the requirement. The heredoc can't easily import a shared module, so duplication beats indirection at this size.

**Stats:** Each detector writes its component's gate decision summary to `/var/lib/beaconbutty/reports/alert-gate-stats.json`:

```json
{
  "slow_cadence":  {"ts": "...", "fired": 0, "gated": {"hyperscaler": 2, "shared_lan": 0}},
  "daily_summary": {"ts": "...", "fired": {"high_score_beacon": 1, ...},
                                  "gated":  {"high_score_beacon": {"hyperscaler": 5, "shared_lan": 3}, ...}}
}
```

`/health` reads this file and renders an **Alert Gate** panel — last-run timestamp + fired/gated breakdown per component. Confidence-builder when the channel is quiet; diagnostic when it isn't ("ah, 47 things gated — that's why I haven't been paged").

## `new_device` LAA gate (2026-05-06)

Separate single-signal gate, applied in `assets.sh`'s alert loop. A MAC with the **locally-administered bit set** (LAA — bit `0x02` of the first octet) is almost certainly an OS-generated randomised MAC: iOS, macOS, Android, and Windows all rotate per-network for privacy. These rotate every few weeks and would page repeatedly without ever representing a genuinely new device.

The alert path skips LAA MACs entirely and increments a `gated.mac_randomised` counter on the `new_device` subkey of `alert-gate-stats.json`. Globally-assigned MACs from real OUIs continue to alert as before. Devices remain visible on `/assets` either way — the gate only removes the Slack page, not the dashboard signal.

The `/health` Alert Types table notes "(LAA-randomised MACs gated)" beside the `new_device` row so the operator can tell at a glance.

## Slow-cadence digest (2026-05-06)

Daily roll-up of the slow-cadence dashboard's hunt-only candidates — the periodic-egress findings that the gate demoted (hyperscaler / shared-LAN) and so never paged in real time. Designed to give a low-volume morning nudge to glance at the hunt surface without re-introducing the BAU-noise problem the gate just fixed.

| | |
|---|---|
| Script | `scripts/slow-cadence-digest.py` (deployed `/usr/local/bin/beaconbutty-slow-cadence-digest.py`) |
| Cadence | Daily 08:00 UTC (= 09:00 BST) — `beaconbutty-slow-cadence-digest.timer` |
| Source data | `/var/lib/beaconbutty/reports/slow-cadence.json` (no extra ClickHouse work) |
| Selection | Top 10 hunt-only candidates, ordered by persistence then hour-consistency |
| Transport | **Direct `chat.postMessage`** with the xoxp- token in `slack-config.json`; bypasses the Lambda alert pipeline |
| Channel | `digest_channel` in `slack-config.json` if set, else falls back to main `channel` |
| Toggle | Honours `slow_cadence_digest` in `alert-config.json` (per-type toggle on `/health`) |

**Why direct Slack post (not Lambda):**

- Lambda dedup would suppress repeat firings of the same digest body
- Multi-line markdown body for the per-candidate breakdown
- Natural place to add a separate channel without touching Lambda env vars

**Silent-on-empty.** When there are zero hunt candidates demoted, the script exits before posting — no "all clear" message. Daily "nothing to see" notifications are themselves the kind of BAU noise the alert philosophy is meant to prevent. The digest only fires on days when there's something worth glancing at.

To split the digest into its own Slack channel:

```json
{"token": "xoxp-...", "channel": "<your-slack-channel>",
 "digest_channel": "<your-slack-channel>-hunt"}
```

## JA4 alert policy (2026-05-05)

`ja4-threat-check.py` fires `threat_intel_hit` alerts only on **exact** JA4-DB matches (`source == "ja4db"`). **Cipher-family** matches (`source == "ja4db-cipher"`, where only the cipher portion of a JA4 maps to a known threat label) are deliberately excluded — the cipher hash is shared across many legitimate clients, so the false-positive rate is too high to page on. Cipher-family classification is still visible per-fingerprint in the **JA4 Inventory** card on `/network`. Devices whose MAC is on the FP list are skipped entirely (dnsmasq.leases lookup, same pattern as `slow-cadence.py`).

## Slack delivery

| Item | Value |
|------|-------|
| Workspace | `<your-slack-workspace>` |
| Channel | `#beacon-butty` |
| Token | `xoxp-` user token stored on bb0 at `/var/lib/beaconbutty/slack-config.json` (used by `beacon-report.sh` for its daily post) |
| Lambda → Slack | Separate bot token held inside Lambda env — not on bb0 |

> [!note]
> There are **two** paths into Slack:
> - **Daily report** (`beacon-report.sh`) posts directly with the xoxp token on bb0.
> - **Operational alerts** (`alert.sh`) go via the Lambda, which has its own token.
>
> This means: "Clear Slack Channel" on the Health page only needs the xoxp token (channel-wide history delete); the Lambda pipeline doesn't need to be touched.

## Local audit trail

Every attempt (success, dedup, or failure) is appended to `/var/log/beaconbutty/alerts.log`:

```
2026-04-17T20:40:12Z  high_score_beacon  high  192.168.50.42  HTTP=200  Score 0.97 → evil.com
2026-04-17T21:40:08Z  high_score_beacon  high  192.168.50.42  HTTP=200  Score 0.97 → evil.com   ← dedup'd
2026-04-17T22:12:44Z  service_down       medium bb0           HTTP=502  Zeek is not running     ← delivery failed
```

On log2ram — nightly-synced to NVMe. For long-term retention, archived copies land in `/var/lib/beaconbutty/logs/` via logrotate.

## Test alert (webapp)

Health page → **Test Alert** button fires a `service_down` low-severity message through the full chain. Use it to verify:
- Lambda + API Gateway reachable
- Shared secret still valid
- Slack delivery from the Lambda side

If the test alert succeeds but real alerts don't show up, the problem is downstream of the transport — check per-type enable flags.

## Failure modes

| Symptom | Likely cause |
|---------|-------------|
| `HTTP=403` | Shared secret mismatch (Lambda env var changed, or `alert.sh` edited) |
| `HTTP=502` / `504` | API Gateway or Lambda cold start timeout — rare |
| `HTTP=200` + `Deduplicated` | Expected when the same event fires repeatedly within TTL |
| Exit 0, `"Alert type 'X' is disabled"` | Type muted in `alert-config.json` |
| No log line at all | Script not executed — check the caller's journalctl or run `beaconbutty-alert.sh` manually |

## See also

- [Alert Tuning](../investigation/alert-tuning.md) — beacon score thresholds; the alert gate (2026-05-06) is now the primary noise defence, FP entries secondary
- [Health Monitoring](../operation/health-monitoring.md) — Test Alert button, Clear Slack Channel button
- [Hardening](../security/hardening.md) — the shared secret is not in a secrets manager; it's hard-coded in `scripts/alert.sh`. See secrets table there.
