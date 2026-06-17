---
tags: [beaconbutty, research, supply-chain, iot, residential-proxy, vo1d, coverage-confirmed]
created: 2026-04-24
updated: 2026-04-24
source: LinkedIn Pulse post by Johny Metellus (CIO/PMP/CISSP), Feb 15 2026
source-url: https://www.linkedin.com/pulse/i-had-idea-my-amazon-projector-criminal-proxy-node-johny-pft9e/
confidence: credible practitioner report — author is a named CIO/CISSP, technical
  detail (packet-capture methodology, Vo1d signature correlation, VirusTotal
  corroboration) is consistent with the wider 2024-2025 residential-proxy
  IoT threat landscape (Vo1d, BadBox, Peachpit per Google TAG, HUMAN, Lumen).
---

# AODIN X1BQ Projector — pre-installed residential-proxy malware

Practitioner writeup of a consumer smart projector bought on Amazon that
shipped with **pre-installed malware** that silently enrolled the device
as a residential proxy node, routing third-party (criminal) traffic
through the owner's home IP for ~2 months before the author caught it.

**Why this is in the BB vault:** the detection shape — unknown embedded
device, periodic DNS to a look-alike C2 domain, fingerprint exfil within
seconds of first boot — is exactly what BB's Zeek → RITA → beacon-score
pipeline plus Suricata ruleset is built to catch on a home LAN.

**TL;DR on coverage**: bb0 has **five dedicated Vo1d local rules** and
**~24 ET Open LVCHA residential-proxy DNS rules** actively loaded. If an
AODIN-class device joined 192.168.50.0/24, Suricata would alert on the
first DNS query and RITA would beacon-score the 65-second cadence the
next hourly run. See [Coverage on bb0](#coverage-on-bb0) below for the verification.

## Source and credibility

- **Author**: Johny Metellus — CIO, PMP, CISSP. Personal LinkedIn Pulse
  post, 2026-02-15.
- **Methodology in the post** is concrete and repeatable:
  - Manual Wireshark packet capture at the gateway.
  - Correlation with VirusTotal (11/93 vendors flagged the C2).
  - Open-port fingerprinting against published **Vo1d** botnet IoCs.
  - OPNsense + Security Onion as the defender stack.
- **Context**: residential-proxy monetisation of pre-infected consumer
  Android-based IoT is an established 2024-2025 threat family documented
  by Google TAG (BadBox), HUMAN Security (Peachpit), Dr.Web (Vo1d), and
  Lumen Black Lotus Labs. Metellus' findings fit that template.
- **Treatment**: credible primary-account research. Used here as a
  detection-design cross-check, not re-verified against the author's
  raw pcap.

## Device and timeline

| Field | Value |
|---|---|
| Device | **AODIN X1BQ Smart Projector** |
| Amazon ASIN | `B0DGX51JPC` |
| Purchased | December 2025 |
| Firmware timestamp | September 2025 (pre-retail — **supply-chain injection**, not post-sale OTA) |
| Dwell time before detection | ~2 months |
| Detection method | Manual Wireshark packet capture, VirusTotal correlation |
| Defender stack (author) | OPNsense firewall, Security Onion IDS |

Supply-chain placement (firmware baked in at the factory, before retail
packaging) is the critical framing: no post-sale trigger, no user
misstep. Plug-in = compromise.

## Indicators of Compromise

From the author's writeup (and published GitHub rule set):

| Type | Value | Notes |
|---|---|---|
| DNS C2 | `o.fecebbbk.xyz` | Typosquat of `o.facebook.com`. Queried every ~65 s. |
| C2 reputation | 11/93 VirusTotal vendors | ThreatYeti risk 9.2/10 |
| UDP heartbeat | `|00 00 cd|` magic bytes, UDP/16000 | Vo1d family |
| HTTP OTA | `111.230.36.129:8080` | "fake OTA" registration |
| TCP C2 | `38.55.17.113:12000` | C2 registration server |
| Port footprint | 13 simultaneously open ports | Vo1d signature |
| First-boot exfil | MAC + device ID + IMEI within ~2.17 s of power-on | Fingerprint for proxy-node enrolment |
| C2 architecture | Three-tier (entry / allocator / target) | Typical commercial residential-proxy structure |

## Coverage on bb0

Verified 2026-04-24. All of the following are live in production.

### Suricata — custom local rules

File: `/var/lib/suricata/rules/local.rules`

| SID | Target | Rule |
|---|---|---|
| 1000030 | DNS to `fecebbbk.xyz` | `alert dns any any -> any any (dns.query; content:"fecebbbk.xyz"; nocase; …)` |
| 1000031 | Vo1d UDP heartbeat magic bytes | `alert udp any any -> any 16000 (content:"|00 00 cd|"; offset:1; depth:3; …)` |
| 1000032 | Fake OTA registration | `alert http any any -> 111.230.36.129 8080 (…)` |
| 1000033 | C2 registration server | `alert tcp any any -> 38.55.17.113 12000 (…)` |
| 1000034 | DNS beaconing threshold (3+ queries/5 min) | `alert dns … content:"fecebbbk"; threshold: type both, track by_src, count 3, seconds 300; …` |

All five classtype `trojan-activity`. No SID 1000030-1000034 has ever
fired in `eve.json` — consistent with no compromised device on the LAN.

### Suricata — ET Open ruleset

File: `/var/lib/suricata/rules/suricata.rules`, loaded by
`/etc/suricata/suricata.yaml → rule-files: [local.rules, suricata.rules]`.

- **LVCHA Chinese-VPN / residential-proxy DNS family**: ~24 rules
  (SIDs 2067502-2067530+), tagged `Residential_Proxy_Services` +
  `VPN_Services`, MITRE `T1572 Protocol_Tunneling`, reference Silent
  Push 2026-02 writeup. Dotprefix/endswith matches for
  `*.lvcha.org`, `*.lvchaapp.store`, `*.lcapp.{shop,icu,xyz,sbs,qpon,my,bond}`,
  `*.lcpro.{qpon,bar,cc,icu,cfd,vip,top,shop}`, `*.lcvpn.{sbs,qpon,cyou}`,
  `*.lvcha.{store,qpon,in}`, `*.lvchaapp.{cc,icu,vip}`,
  `*.lvchavpn.cfd`, `*.lcabc.icu`, `*.lcapi.shop`, and several more.
- Total `Residential_Proxy` / `LVCHA` tagged rule lines: **129**.
- Broader ET Open coverage includes other Android-TV botnet families
  (BadBox, Peachpit) under their own ET INFO / ET MALWARE categories —
  not individually audited here, but in the loaded set.

### Engine state

From current `eve.json` stats (last stats-tick before this update):

```
last_reload:    2026-04-24T06:26:14+0100
rules_loaded:   49828
rules_failed:   0
rules_skipped:  0
service status: active
```

Rules parsed clean, no skips, service healthy.

### RITA / beacon-score pipeline

Orthogonal to the Suricata rules, the RITA pipeline would catch this
independently:

- **65-second periodic DNS** is textbook beacon behaviour — fixed
  cadence, low jitter, single destination.
- Zeek's `dns.log` records every query. `rita-analyze.sh` runs hourly
  and feeds ClickHouse. Beacon score threshold is **1.0** per
  [Alert Tuning](alert-tuning.md); a 65-s clock is very close to the ceiling on RITA's
  timing-interval score.
- Even if the local Suricata DNS signature were missing, the beacon
  score alone would surface the device on the daily 07:00 report and
  the Slack alert chain.

### False-positive registry

`/var/lib/beaconbutty/false-positives.conf` — **no entries for
`fecebbbk`, `vo1d`, or `lvcha`**. The look-alike C2 could in principle
be misread as a legitimate Facebook telemetry domain by a rushed human;
the note at [Do not allow-list](#do-not-allow-list) below is a reminder.

## Why coverage holds up

Three independent layers would trip on an AODIN-class device:

1. **Signature** — Suricata local rule 1000030 alerts on the first DNS
   query to `fecebbbk.xyz`.
2. **Behavioural** — RITA scores the 65-s cadence and beacon-report.sh
   puts it on the daily report (and Slack) within 24 h.
3. **Asset** — `assets.sh` flags the new MAC against
   `known-macs.json ∪ old_by_mac ∪ FP devices`; the unfamiliar device
   lands on the Assets page with an "unknown" label and no hostname.

All three independent, all three on NVMe-logged evidence trails. Worst
case (one path misses) the other two still fire.

## Residual considerations

### Do not allow-list

`o.fecebbbk.xyz` **must not** end up in `false-positives.conf` or any
safe-list. The look-alike works on humans; if a future triage session
sees repeated alerts and assumes "Facebook telemetry, FP it", coverage
collapses. The only way a domain enters the
safe list is an explicit user instruction, so this is a human-process
guardrail rather than a code change.

### Other Vo1d/BadBox/Peachpit variants

The five local rules target exactly the IoCs Metellus published. The
Vo1d family uses multiple C2 domains and the campaign evolves. ET Open
is the long-tail for that — the 2026-02 LVCHA additions above suggest
the ruleset is being maintained in step with the campaign. No action
needed now; revisit if a new Vo1d writeup lands.

### IoT VLAN segmentation

bb0's LAN is flat 192.168.50.0/24. Metellus' key recommendation is
VLAN-segregating IoT devices so a compromise can't pivot. bb0 can't
usefully segment itself (it *is* the router) but the architectural
option — egress-filter an IoT VLAN via dnsmasq + iptables on eth1.X —
is worth a sentence on [Hardening](../security/hardening.md) for future-home-network scope.
Out of scope today; flagged.

### Typosquat-flag builder

Not implemented. An Investigate flag category for FQDNs with
Levenshtein ≤ 2 from a top-1k brand (Google, Facebook, Apple, Microsoft,
Amazon, …) would generalise this detection beyond the specific C2
domain. Cheap in code, FP risk needs tuning. **Parked** — record in
[Alert Tuning](alert-tuning.md) if/when that page gets the section.

## Related

- *Print Me If You Dare (Cui 2011)* — same structural class (firmware-
  resident, network-only visibility, embedded device as pivot).
- *Dead ICS Beacon PoC* — periodic-DNS-beacon detection shape.
- [Alert Tuning](alert-tuning.md) — beacon-score 1.0 threshold context.
- [False Positive Workflow](false-positive-workflow.md) — how a new-MAC "projector" would triage.
- *Incident Log* — template destination if an AODIN-class device ever
  does show up.
