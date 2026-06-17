---
tags: [beaconbutty/architecture]
created: 2026-04-16
---

# System Overview

BeaconButty is a network-based malware C2 beacon detector. Rather than relying on endpoint agents or signature databases, it analyses *traffic patterns* to find beaconing behaviour — the characteristic regular check-ins that malware makes to its command-and-control infrastructure.

## What it detects

A beacon is a connection from a LAN device to an external host that happens on a suspiciously regular schedule — typically every few minutes to every few hours. Malware uses beacons to receive instructions, exfiltrate data, or confirm the infected host is still alive.

BeaconButty uses RITA's statistical analysis to score these connections and surface high-confidence candidates. It complements this with Suricata signature-based IDS alerts for known-bad traffic.

## Component stack

| Layer | Tool | Role |
|-------|------|------|
| Capture | Zeek 8 | Passive packet capture; writes conn.log, ssl.log, dns.log etc. |
| Analysis | RITA v5.1.1 | Statistical beacon scoring on Zeek logs |
| Storage | ClickHouse | Column-store database for RITA results |
| IDS | Suricata | Signature-based alerts (Emerging Threats ruleset) |
| Reporting | Custom scripts | Daily reports, Slack alerts |
| UI | Flask webapp | Browser-based dashboard on HTTPS :443 |

## Why this approach

**No endpoint agents needed.** The Pi sits in-path as the LAN's NAT router. Every device on the network — including IoT, BYOD, and guests — is covered without any software installation on those devices.

**Pattern-based, not signature-based.** RITA detects beaconing by its statistical regularity, not by matching known malware signatures. This catches novel and unknown malware that evades AV.

**Low false-positive rate.** RITA's scoring is calibrated to distinguish true beacons from regular software update checks, telemetry pings, and cloud sync traffic. The safe-destination filter (by ASN and domain suffix) further reduces noise. Remaining FPs are managed per-device in a registry.

## Key design decisions

**Raspberry Pi 5 8GB as the NAT router.** Reasonable cost (~£170), low power (~8W idle), and has enough CPU for Zeek + RITA on a home/small-office LAN. The router position gives full bidirectional LAN traffic visibility without a managed switch.

**NVMe storage.** ClickHouse write amplification is too heavy for an SD card. An NVMe SSD via the Pironman case's M.2 slot is used for the OS and all data.

**log2ram.** `/var/log` is a 1GB tmpfs to reduce NVMe wear from frequent log writes. Suricata live logs (`eve.json`, `stats.log`), Zeek daily log dirs, and dnsmasq.log are written here — eliminating ~250MB/day of continuous NVMe writes. log2ram syncs to NVMe once daily at 23:55. Rotated archives are offloaded to NVMe after compression (`/var/lib/suricata/archive/`, `/var/lib/beaconbutty/logs/`). Reports and ClickHouse data live outside `/var/log`.

**RITA v5.1.1.** The most recent version with a ClickHouse backend. Older RITA versions used MongoDB.

**ClickHouse.** Column-store analytical database, well-suited to RITA's time-series beacon scoring queries. Requires a clean shutdown before OS reboot — see [Reboot Procedure](../operation/reboot-procedure.md).

## Rejected options

**Pi-hole on bb0** (considered 2026-05-21, declined). Pi-hole would add proactive DNS sinkholing of known-bad C2/ad/tracker domains via blocklists, with a query-log UI as a bonus. Rejected because bb0's role is *detection*: sinkholing known-bad domains masks exactly the signals RITA/Zeek score on — resolved-but-blocked C2 disappears from beacon reports. Secondary costs: web UI port clash with bb-graphs on 80/443, extra RAM/CPU/log2ram pressure alongside Zeek+Suricata+ClickHouse, and pihole-FTL would replace dnsmasq (another moving part in the NAT critical path). If Pi-hole is ever wanted, the cleanest split is to run it on bb1 or a separate container so blocking and detection don't fight each other on the same host.

See also: [Network Topology](network-topology.md), [Data Pipeline](data-pipeline.md), [Hardware Setup](../hardware/hardware-setup.md)
