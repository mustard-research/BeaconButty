# Teams-relay C2 detector (DragonForce / Backdoor.Turn)

## The attack

In June 2026 Symantec published analysis of `Backdoor.Turn`, a Go-based payload deployed by the DragonForce ransomware operation. It's the first in-the-wild implementation of Praetorian's 2025 "Ghost Calls" proof of concept: hide C2 traffic inside legitimate Microsoft Teams TURN relay sessions.

The mechanic:

1. Acquire an anonymous Teams visitor token from Microsoft's Skype-backed identity service. No M365 account required — anyone can be a "visitor".
2. Use that token to allocate a legitimate Microsoft TURN relay on UDP/3478 (and TCP/443 fallback) — the same relay servers your real Teams calls use.
3. Tunnel QUIC through that allocation to the attacker's real C2.

On the wire, every packet leaving the infected host goes to a legitimate Microsoft Azure IP, with a legitimate Microsoft TLS certificate, on a port indistinguishable from a real Teams call. Destination-based filtering can't catch it without breaking Teams for the whole network.

References:
- [Hidden in Teams: DragonForce Attackers Weaponize Microsoft Teams Relays](https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor) — Symantec, 2026-06-16
- [Ghost Calls](https://www.praetorian.com/blog/ghost-calls/) — Praetorian's 2025 PoC

## Why existing BeaconButty detectors miss it

| Detector | Failure mode |
|---|---|
| RITA periodicity scoring | It's a continuous QUIC session, not periodic check-ins. No beacon signature. |
| Slow-cadence detector | Same — looks for low-rate periodic connections over days. |
| IP threat-intel enrichment | Destination IP is Microsoft Azure; clean across Shodan / AbuseIPDB / Spamhaus / Tor. |
| JA4 ja4db threat lookup | A Go-runtime QUIC fingerprint is too generic to alert on broadly. |

## What the detector does

`teams-relay-check.py` (runs every 15 min from `beaconbutty-teams-relay-check.timer`) classifies LAN-source flows as Teams-bound by SNI suffix match OR by destination IP in the Microsoft Teams CIDR set, then evaluates three signals against the configured thresholds:

| Signal | Default | Rationale |
|---|---|---|
| **new-JA4** | seeded after 1-day grace | A Teams desktop client's JA4 is stable. A Go binary's QUIC fingerprint will not match it. The detector keeps a per-device baseline of Teams-bound JA4s in `/var/lib/beaconbutty/device-teams-ja4-history.json` and only fires after the device has been observed for at least one full day (avoids day-1 false positives). |
| **long-flow** | duration > 2 h | Real Teams calls rarely exceed two hours. A C2 tunnel often stays open for the working day or longer. |
| **low-bw** | < 30 kbps over flows ≥ 60 s | A real audio-only Teams call uses ~50–100 kbps. Video calls use hundreds. A C2 tunnel shipping commands runs at single-digit kbps. The 60-second floor avoids tripping on STUN-keepalive chatter. |

**Alert gate: `new-JA4` plus at least one other signal must correlate to page.** Without the new-JA4 discriminator, the structural signals (long-flow / low-bw) trip routinely on legitimate Teams idle behaviour — presence WebSockets sit open all day on TCP/443; TURN keepalives send bytes/sec on UDP/443. `new-JA4` alone is also too noisy (it fires whenever a device's Teams JA4 list grows, e.g. after a Teams app update). The DragonForce shape — a Go binary using an unfamiliar TLS stack to hold a low-bandwidth or long-duration tunnel through Teams CIDRs — trips at least two signals AND has new-JA4 as one of them.

Severities: `new-JA4 + 1 other` → `medium`; `new-JA4 + 2 others` → `high`. Alert detail is stable per `(src, dst, dst_port, proto)` so Lambda dedup collapses repeat firings.

Single-signal findings and non-`new-JA4` multi-signal findings still appear in the `/health` Teams card for hunting — they just don't page Slack. A per-device-per-run hard cap (default 5) is a backstop against future tuning regressions.

Both thresholds are editable from the **Health** page → **Teams Relay Detector** card. Changes are written to `/var/lib/beaconbutty/teams-detector-config.json` and picked up on the detector's next run (no restart).

## Teams CIDR / SNI list

The detector ships with a bundled seed at `config/teams-cidrs.json` (current as of 2026-06-17). A daily timer (`beaconbutty-teams-cidr-refresh.timer`, 03:30) pulls the live list from `endpoints.office.com` and overwrites `/var/lib/beaconbutty/teams-cidrs.json`. The "Microsoft 365 Skype service area" entries (legacy name; Microsoft 365 still tags Teams there) are the canonical source. The detector reads the live file if present, falling back to the bundled seed otherwise.

## Limitations

- **Bespoke malware can match Teams JA4.** A sufficiently motivated attacker using a `utls`-style Client Hello mimic will collapse the new-JA4 signal. We catch off-the-shelf Backdoor.Turn whose JA4 is whatever Go's `crypto/tls` (or its QUIC equivalent) happens to emit.
- **No endpoint correlation.** "Is this *really* a Teams call?" can only be answered authoritatively from the endpoint (process tree, M365 sign-in state). BeaconButty has no endpoint visibility.
- **Encrypted-SNI QUIC.** TURN allocations over UDP/3478 and QUIC traffic where the SNI is encrypted in the Initial packet are caught only by CIDR matching. If Microsoft shifts Teams to fresh IP ranges before the daily refresh runs, there's a window during which new flows won't be classified as Teams-bound.

## Tuning

If real Teams use on your network exceeds the defaults (e.g. a long all-day call), raise `max_duration_hours` from the Health page. If you see false positives on bandwidth, raise `min_kbps` — but going much above ~50 kbps risks tripping on audio-only legitimate calls. The detector logs to `/var/log/beaconbutty/teams-relay.log` and writes a per-run report to `/var/lib/beaconbutty/reports/teams-relay.json` (rendered in the Health page card).
