---
tags: [beaconbutty/investigation, beaconbutty/detection]
created: 2026-05-04
---

# Slow-Cadence Beacons — Going Beyond Stock RITA

> Built 2026-05-04 in direct response to reporting on a "C2 on a sleep
> cycle" PRC-attributed campaign hitting Polish and Asian critical
> networks. RITA out of the box would have missed this campaign. The
> slow-cadence detector exists to fill that structural blind spot.

## What stock RITA covers

Active CountermeasuresOpens RITA v5 scores beacons within a single
calendar day, against a single ClickHouse database
(`beaconbutty_YYYYMMDD`). The default scoring config includes:

| Setting | Default | Effect |
|---|---|---|
| `unique_connection_threshold` | 4 | A `(src,dst)` pair needs ≥4 connections in the day to be eligible for scoring at all. |
| `duration_min_hours_seen` | 6 | The pair must span ≥6 hours of the day. |
| `score_thresholds.high` | 100 | High-confidence beacon cutoff. |

This is excellent at catching the textbook beacon: a Cobalt Strike
implant at 30–60 s sleep, hundreds to thousands of connections per day,
spread across most of the working day. But it has a structural blind
spot.

## RITA's blind spot

The per-day, threshold-based design means anything sleeping longer than
a few hours is invisible. Roughly:

| Implant sleep | Conns/day | Stock RITA outcome |
|---|---|---|
| ≤90 min | ≥16 | scored cleanly |
| 6 h | 4 | scored, marginal |
| **8 h** | **3** | **below `unique_connection_threshold` → never scored** |
| 24 h | 1 | invisible — no histogram, no scoring possible |
| 3+ days | <1/day | invisible — most daily DBs don't even contain the row |

Lowering `unique_connection_threshold` to 2 or 3 would explode false
positives without actually covering the >24 h zone — that part is
**structural**, not threshold-tuning. RITA databases are
day-scoped; nothing in the import pipeline correlates across them.

## What the slow-cadence detector adds

`scripts/slow-cadence.py` (deployed to
`/usr/local/bin/beaconbutty-slow-cadence.py`, run hourly via
`beaconbutty-slow-cadence.timer` at `*:35`) is a **cross-DB**
correlator that targets the blind zone directly.

**Algorithm:**

1. List the most recent 14 daily ClickHouse databases
   (`beaconbutty_YYYYMMDD`).
2. `UNION ALL` their `conn` tables (filtered to egress, non-DNS, non-NTP).
3. Group by `(src, dst, dst_port)`.
4. Keep pairs that:
   - appear on **≥5 distinct days** (`MIN_DAYS_SEEN`),
   - average **≤6 connections per active day** (`MAX_CONNS_PER_DAY` —
     deliberately RITA's blind zone),
   - cluster **≥70% of timestamps within ±1h of a modal hour**
     (`MIN_HOUR_CONSISTENCY` — distinguishes scheduled check-ins from
     bursty session traffic).
5. Resolve `dst → SNI` from `ssl.server_name` (latest-day argMax) for
   FP matching and human review.
6. Match SNI against the existing `false-positives.conf` domain list.

**Output:** `/var/lib/beaconbutty/reports/slow-cadence.json`, rendered
at `/beacons/slow` in the webapp.

**Persistence:** `/var/lib/beaconbutty/slow-cadence-known.json` records
the set of `(src,dst,port)` tuples ever observed at-or-above threshold.
The very first run is a seed pass — it populates this file silently,
otherwise the initial 350-odd legitimate cloud check-ins (Samsung TV,
Withings, Apple iCloud, MS Intune, Cloudflare WARP, etc.) would all
page Slack on day one. After that, **only newly-crossing tuples fire
alerts**.

**Alerting:** new tuples → `beaconbutty-alert.sh slow_cadence_beacon
medium <src> "<detail>"` → existing AWS Lambda → Slack
`#beacon-butty`. New alert type registered in
`/var/lib/beaconbutty/alert-config.json` so it can be toggled with the
others.

## Coverage table — bb0 today

What each layer of the stack catches:

| Implant profile | Stock RITA | JA4 fingerprint | Slow-cadence |
|---|:---:|:---:|:---:|
| Cobalt Strike, 60 s sleep | ✅ scored High | ✅ if known JA4 | — (too noisy) |
| Empire/Sliver, 5 min sleep | ✅ scored | ✅ if known JA4 | — |
| Bespoke, 1 h sleep, jittered | ⚠ marginal | ✅ if known JA4 | ✅ |
| Bespoke, 6 h sleep, fixed time of day | ❌ below threshold | ✅ if known JA4 | ✅ |
| Bespoke, 24 h sleep | ❌ invisible | ✅ if known JA4 | ✅ |
| Bespoke, weekly check-in | ❌ invisible | ✅ if known JA4 | ❌ window too short |
| Single-stage dropper, novel JA4 | ❌ invisible | ❌ unknown | ✅ if it persists |

JA4 still wins the moment a sample is fingerprinted and published — it
catches the implant on a single TLS handshake regardless of cadence.
The slow-cadence detector is what catches the **first** persistent
appearance of an implant whose JA4 isn't in any threat feed yet.

## Other ways we already exceed stock RITA

The slow-cadence detector is the latest piece, but the wider stack
already extends RITA significantly:

- **JA4 / JA4+ fingerprinting** (FoxIO Zeek package, integrated
  2026-05-04) — scores TLS *clients* by fingerprint, classifies into
  malware families (Cobalt Strike, Sliver, Havoc, Qakbot, Pikabot,
  Darkgate, IcedID, Lumma, ngrok, Mythic, Brute Ratel) via the
  ja4plus-mapping CSV refreshed weekly.
- **L2 / ARP anomaly detection** — Zeek 8 fires `arp_request` /
  `arp_reply` / `bad_arp` events but ships no ARP logger; we wrote
  our own (`config/zeek/site/arp-log.zeek`) plus a panel that flags
  gateway impersonation, MAC churn, and bad ARP. Out of scope for
  RITA entirely.
- **Suricata IDS overlay** — RITA does volumetric/statistical
  detection, Suricata does signature/protocol detection. Both feed the
  same FP registry and Slack alert pipeline.
- **First-seen JA4 device tracking** — per-device fingerprint history
  with `first_seen` < today as the "known" predicate, so a backfill
  can't mask the new-today signal.
- **Triggered PCAP capture** — operator-driven, watches up to 3
  domains; rolling 24 × 5-minute pcaps with `tcpdump -i any` (required
  because bb0 is the NAT router). Any slow-cadence candidate that
  needs deeper inspection can be promoted into a watched domain in one
  click.
- **DHCP-history-aware FP suppression** — `summarize.sh` resolves
  historical IP↔MAC bindings from `dhcp.log` so an FP'd MAC stays
  suppressed even when the device's IP has rotated.

## Operating notes

- Initial seed (2026-05-04): 360 candidates, 339 with SNI. Top hits
  are legit cloud check-ins. Walk-down with the per-row "Add to FP"
  button shrinks the panel to genuine residual signal.
- Window is bounded by Zeek log retention (`LogExpireInterval = 14`).
  To detect implants on weekly cadences, retention must increase first.
- Modal-hour clustering only catches **daily-periodic** implants. A
  beacon that's exactly every 6 h (4 hits/day, 4 different hours)
  wouldn't show modal-hour clustering — would need an FFT or
  autocorrelation pass on inter-arrival deltas. Future work if it
  becomes a real-world threat.

## UI — `/beacons/slow`

The page is built for fast triage rather than reading. Layout decisions
that landed during the 2026-05-04 build:

- **Group by source.** Rows are grouped by source IP and ordered with
  the heaviest groups first. Each group gets a header with a coloured
  destination-count badge (red ≥10, yellow ≥5, green <5) and a single
  `FP src` button. Above 5 destinations a hint reads "→ FP src is more
  efficient than N domain entries".
- **Per-row `FP dst`.** Editable pattern (default `*.<sld>` if SNI
  present, else literal dst IP). Reason pre-fills with the GeoIP ASN
  org so the common case is two Enter presses. Posts to
  `/fps/add-domain` with `next=/beacons/slow`.
- **`FP src` at the group level.** Posts to `/fps/add` (which
  resolves IP→MAC via dnsmasq leases). Silences all of that source's
  rows in one click.
- **GeoIP attribution.** Every row shows ASN org + country code under
  the destination IP. No-SNI rows that used to read "—" now read
  "no SNI · Amazon.com, Inc." or "no SNI · Tencent Building,
  Kejizhongyi Avenue" — actionable without a manual whois.
- **Render-time FP filter.** The route re-applies the FP list on
  every render, so a freshly-added FP drops the row on the redirect
  rather than waiting for the next detector tick. Three paths: SNI
  domain pattern, dst IP literal, source MAC.
- **Coherent ghost view on `/assets`.** A device that disappeared
  mid-window (e.g. someone's laptop went home for the weekend) still
  shows on `/assets` as a dimmed "ghost · Nd" row, populated from
  `/var/lib/beaconbutty/assets-history.json` written by `assets.sh`
  each run and seeded once from Zeek `dhcp.log` archives via
  `scripts/seed-assets-history.py`. Stops the cross-page disconnect
  where slow-cadence pointed at a device assets had no record of.
