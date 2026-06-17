---
tags: [beaconbutty]
created: 2026-04-16
updated: 2026-04-25
---

# BeaconButty

BeaconButty is a network beacon detector designed to identify malware C2 (command-and-control) check-ins on a company LAN. It runs on a Raspberry Pi 5 configured as the network's NAT router, giving it full visibility into all LAN traffic without endpoint agents or managed switch port mirroring.

## At a glance

```
eth1 (all LAN ↔ internet) ─▶ Zeek ─▶ log files ─▶ RITA (hourly) ─▶ ClickHouse
                                                                        │
             Slack <your-slack-channel> ◀─ Lambda ◀─ alert.sh ◀─┬── beacon-report.sh (daily 07:00)
                                                         ├── suricata-alert-check (hourly)
                                                         └── bb-graphs webapp (on-demand)
```

## Architecture

- [System Overview](architecture/system-overview.md) — design rationale
- [Network Topology](architecture/network-topology.md) — interfaces, DHCP/DNS, LAN device inventory
- [Data Pipeline](architecture/data-pipeline.md) — Zeek → RITA → ClickHouse → report → Slack
- [Services](architecture/services.md) — systemd services and dependencies
- [Log2Ram Usage](architecture/log2ram-usage.md) — what's in RAM, when it syncs to NVMe
- [Alert Chain](architecture/alert-chain.md) — alert.sh → Lambda → Slack

## Hardware

- [Hardware Setup](hardware/hardware-setup.md) — Pi 5 8 GB + Pironman 5 + NVMe
- [Fan Control](hardware/fan-control.md) — RPi active cooler + Pironman case fan (tiered)
- [OLED Display](hardware/oled-display.md) — SSD1306 status display

## Operation

- [Daily Operations](operation/daily-operations.md) — morning workflow, weekly checks
- [Backup & Recovery](operation/backup-and-recovery.md) — rpi-clone USB, DR priority
- [Health Monitoring](operation/health-monitoring.md) — `beaconbutty-health.sh`, dashboard tiles
- [Reboot Procedure](operation/reboot-procedure.md) — clean ClickHouse shutdown via wrapper
- [Capacity & Performance](operation/capacity-and-performance.md) — RAM/disk/CPU budgets, upgrade triggers
- [Troubleshooting](operation/troubleshooting.md) — "when X breaks → do Y"
- *Glob-Parsed Config Directories* — why `.bak` files in `/etc/*.d/` are latent landmines (2026-05-12 incident analysis)
- *Upgrade Log* — chronological system change history

## Security

- [Hardening](security/hardening.md) — SSH, firewall, fail2ban, sysctl, secrets inventory

## Development

- [Webapp](development/webapp.md) — Flask app, pages, critical patterns
- [Scripts & Timers](development/scripts-and-timers.md) — deployed scripts, timer schedule, data-path alignment rules
- *Public Repo* — checklist before making the repo public
- *Public Website Assets* — refresh workflow for the public Beacon Butty page (screenshots, brochure, anonymisation)
- [Licensing](development/licensing.md) — Zeek/ClickHouse/Suricata/RITA licence analysis for commercialisation

## Investigation

- [False Positive Workflow](investigation/false-positive-workflow.md) — how to assess and register FPs
- [Alert Tuning](investigation/alert-tuning.md) — beacon score interpretation, Suricata priorities
- *Incident Log* — active and historical investigations
- *Dead ICS Beacon PoC* — `.ics` subscription beacon research (path closed; see page)
- *Print Me If You Dare (Cui 2011)* — HP LaserJet RFU firmware-reflash research (28C3), threat-model notes
- [AODIN Projector Proxy Node (Metellus 2026)](investigation/case-aodin-projector-proxy.md) — Amazon smart projector shipped pre-infected as residential-proxy node; IOCs and BB implications
- [External IP Intel](investigation/external-ip-intel.md) — Shodan InternetDB + AbuseIPDB enrichment for bare external IPs (Tencent CDN trigger 2026-05-13)
- [Slow-Cadence Beacons](investigation/slow-cadence-beacons.md) — multi-day low-rate detection covering RITA's sleep-cycle blind spot

## Open operational items

Pending decisions and known cosmetic warnings that aren't blocking but shouldn't get forgotten. Keep this short — resolve or document, don't let it grow.

- **Zeek 8.1 ClusterBackend = ZeroMQ vs Broker** (deferred 2026-05-13). Zeek 8.1's default backend flipped to ZeroMQ, which needs `UseWebSocket = 1`. We kept `UseWebSocket = 0` because Bookworm's `python3-websockets` (10.x) is too old; Zeek currently runs on Broker fallback. Live impact: `zeekctl status` shows a persistent ZeroMQ warning; `zeekctl netstats`/`print` don't work but aren't used routinely. Decision options: pin `ClusterBackend = Broker` explicitly (lowest risk) or install newer websockets + flip ZeroMQ on. See *Upgrade Log* and [Troubleshooting](operation/troubleshooting.md).
- **NetworkManager-wait-online.service shows `failed` post-boot** (since at least 2026-05-13). Cosmetic — `nm-online` times out trying to wait for a single "fully configured" state on the multi-homed setup (eth0 + eth1 + wlan0 + tailscale0). Doesn't affect any service that depends on the network (everything's been up well before this 30 s timer fires). Mask the unit if it ever becomes load-bearing for ordering.

## Quick reference

| Task | Command |
|------|---------|
| Full health check | `sudo beaconbutty-health.sh` |
| Today's beacon summary | `beaconbutty-summary.sh` |
| List false positives | `beaconbutty-fp.sh list` |
| Add false positive | `beaconbutty-fp.sh add <ip> "<reason>"` |
| Fire a test alert | Webapp → Health → **Test Alert** |
| View reports | `ls /var/lib/beaconbutty/reports/` |
| Check core services | `systemctl is-active zeek clickhouse-server dnsmasq bb-graphs suricata` |
| Check failed units | `systemctl --failed --no-legend` |
| log2ram usage | `df -h /var/log` |
| Re-apply hardening | `sudo /home/dm/BeaconButty/scripts/harden.sh` |

## Key paths

| Path | Purpose |
|------|---------|
| `/usr/local/bin/beaconbutty-*.sh` | Deployed operational scripts |
| `/var/lib/beaconbutty/reports/` | Beacon report files (NVMe) |
| `/var/lib/beaconbutty/false-positives.conf` | False positive registry (NVMe) |
| `/var/lib/beaconbutty/assets.json` | LAN asset cache (NVMe) |
| `/var/lib/beaconbutty/slack-config.json` | Slack xoxp token (NVMe, mode 600) |
| `/var/lib/beaconbutty/alert-config.json` | Per-type alert enable/disable (NVMe) |
| `/var/log/beaconbutty/` | Operational logs (log2ram tmpfs) |
| `/var/log/zeek/` | Zeek rotated daily dirs (log2ram, 7 d) |
| `/opt/zeek/spool/zeek/` | Zeek live log spool (separate 128 MB tmpfs) |
| `/var/lib/clickhouse/` | ClickHouse data + logs (NVMe) |
| `/var/log/suricata/` | Suricata eve.json + fast.log (log2ram) |
| `/var/lib/suricata/archive/` | Suricata rotated `.gz` archives (NVMe) |
| `/var/log/dnsmasq.log` | dnsmasq query log (log2ram) |
| `/var/lib/beaconbutty/logs/` | dnsmasq rotated archives (NVMe) |
| `/etc/rita/config.hjson` | RITA configuration |
| `/etc/log2ram.conf` | log2ram tmpfs config |

Full canonical path table in [Data Pipeline](architecture/data-pipeline.md) and [Log2Ram Usage](architecture/log2ram-usage.md).
