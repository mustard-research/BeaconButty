# BeaconButty — Claude Code Instructions

## What this system is
Network beacon detector for detecting malware C2 check-ins on a company LAN.
Stack: Zeek 8 (packet capture) → RITA v5.1.1 (beacon scoring) → ClickHouse (storage).
Running on a Raspberry Pi 5 8 GB (hostname: bb0) configured as the network's NAT router.
Previous node was bb1 (Pi 5 4 GB) — decommissioned after migration.

## If running ON the Raspberry Pi (bb0)
You have direct access to the live production system. Useful things to do:

- **Hardening review** — check SSH config, firewall rules, fail2ban, unattended-upgrades,
  open ports, running services, sysctl settings. Compare against `scripts/harden.sh`.
- **System health** — run `sudo beaconbutty-health.sh` or check systemd timers, disk usage,
  log2ram status, Zeek/ClickHouse/dnsmasq/Suricata service status.
- **Log analysis** — beacon reports at `/var/lib/beaconbutty/reports/`, operational logs
  at `/var/log/beaconbutty/`, ClickHouse logs at `/var/lib/clickhouse/logs/`.
- **Live beacon data** — run `beaconbutty-summary.sh` for today's findings.
- **False positives** — `beaconbutty-fp.sh list/add/remove` to manage the registry.

## Key paths on the Pi
| Path | Purpose |
|------|---------|
| `/usr/local/bin/beaconbutty-*.sh` | Deployed operational scripts |
| `/usr/local/bin/rita-analyze.sh` | Hourly RITA import |
| `/usr/local/bin/beacon-report.sh` | Daily report (07:00) |
| `/var/lib/beaconbutty/reports/` | Beacon report files |
| `/var/lib/beaconbutty/assets.json` | LAN asset cache |
| `/var/lib/beaconbutty/false-positives.conf` | False positive registry |
| `/var/log/beaconbutty/` | Operational logs (on log2ram) |
| `/var/lib/clickhouse/logs/` | ClickHouse logs (on NVMe) |
| `/var/lib/suricata/log/` | Suricata logs — eve.json, fast.log (on NVMe) |
| `/opt/zeek/logs/` | Zeek daily log directories |
| `/etc/rita/config.hjson` | RITA configuration |
| `/etc/clickhouse-server/config.d/logs.xml` | ClickHouse log path override |

## Network
- eth0 — WAN (DHCP from ISP)
- eth1 — LAN (192.168.50.1/24, Zeek capture interface)
- DHCP pool: 192.168.50.100–.200
- DNS: dnsmasq → 1.1.1.1 / 8.8.8.8

## Known LAN devices
| IP | Device |
|----|--------|
| 192.168.50.1 | The Pi itself |
| 192.168.50.42 | Peloton exercise bike |
| 192.168.50.160 | Awair air quality monitor (registered as false positive — ICMP telemetry) |
| 192.168.50.237 | iPhone (randomised MAC, has Baidu/TikTok apps) |
| 192.168.50.117 | Unknown device — excessive DNS, MAC 78:20:51:23:c8:99 |

## log2ram
log2ram is intentionally kept (SSD write wear reduction). `/var/log` is a 128M tmpfs.
Large data must NOT go under `/var/log` — use `/var/lib/beaconbutty/` instead.
ClickHouse logs were moved to `/var/lib/clickhouse/logs/` for this reason.

## User preferences
- Concise answers
- Proactively catch and fix bugs
- UK prices for hardware recommendations
