---
tags: [beaconbutty/hardware]
created: 2026-04-16
---

# Hardware Setup

## Main board

**Raspberry Pi 5 — 8GB RAM** (hostname: `bb0`)

| Spec | Value |
|------|-------|
| CPU | Broadcom BCM2712, quad-core Cortex-A76 @ 2.4GHz |
| RAM | 8GB LPDDR4X |
| Storage | NVMe SSD (boots from NVMe via Pironman case) |
| OS | Raspberry Pi OS 64-bit (Debian Bookworm base) |
| Kernel | 6.12.75+rpt-rpi-2712 (as of Apr 2026) |

## Case: Pironman 5

The Pi lives in a **Pironman 5** case by SunFounder. The case provides:

- M.2 NVMe slot via PCIe — used as primary boot drive
- SSD1306 128×64 OLED status display (I2C)
- Addressable RGB LED strip
- GPIO-controlled case fan
- Physical power button with LED indicator

See [OLED Display](oled-display.md) and [Fan Control](fan-control.md) for display and cooling details.

## Network adapters

| Adapter | Interface | Role |
|---------|-----------|------|
| Built-in Ethernet | eth0 | WAN — connected to ISP router |
| USB Ethernet dongle | eth1 | LAN — Zeek capture interface |
| Built-in WiFi | wlan0 | Secondary LAN path |

Zeek captures on `eth1`. Using a separate USB adapter for the LAN keeps the Pi's built-in NIC free for WAN and avoids any ambiguity in capture interface selection.

## Storage layout

| Mount | Type | Purpose |
|-------|------|---------|
| `/` | NVMe | Root filesystem — OS, apps, data |
| `/var/log` | tmpfs 1G (log2ram) | Reduces NVMe wear from log writes; nightly sync at 23:55 |
| `/var/log/suricata/` | tmpfs (log2ram) | Suricata live logs: eve.json, stats.log, fast.log |
| `/var/log/zeek/` | tmpfs (log2ram) | Zeek rotated daily dirs (7-day retention via `zeekctl cron`) |
| `/var/log/dnsmasq.log` | tmpfs (log2ram) | dnsmasq DNS query log (~28MB/day) |
| `/opt/zeek/spool/zeek/` | tmpfs 128M (standalone) | Zeek live-write spool — log files updated every second |
| `/opt/zeek/spool/` (parent) | NVMe | Zeek state.db, zeekctl config, tmp/ (used during rotation) |
| `/var/lib/clickhouse/` | NVMe | ClickHouse data + logs |
| `/var/lib/beaconbutty/` | NVMe | Reports, FP registry, assets |
| `/var/lib/beaconbutty/logs/` | NVMe | Rotated dnsmasq .gz archives (moved here after nightly rotation) |
| `/var/lib/suricata/archive/` | NVMe | Rotated Suricata .gz archives (moved here after nightly rotation) |

> [!important]
> **log2ram** keeps `/var/log` in RAM (1G), syncing to NVMe once daily at 23:55. Suricata eve.json (~250MB/day projected), Zeek rotated logs, and dnsmasq.log are the primary beneficiaries.
>
> **Zeek spool tmpfs** (separate 128M mount on `/opt/zeek/spool/zeek/`) protects the live-writing Zeek log files that update every second — ~150–200MB/day of continuous NVMe writes eliminated. `state.db` and zeekctl metadata stay on NVMe (parent spool dir) so they survive reboot.
>
> Total NVMe write reduction: ~400MB/day of continuous small writes → single nightly batch sync. ClickHouse logs are in `/var/lib/clickhouse/logs/` (not log2ram — large and infrequent).
>
> **Trade-off:** Hard power loss loses log2ram contents since last 23:55 sync, and up to 1 hour of in-progress Zeek logs from the spool tmpfs. Rotated archives (hourly) are safe in log2ram; nightly sync preserves them to NVMe.

## USB clone backup drive

A 465.8GB USB enclosure is used for full-disk NVMe backups via rpi-clone. See [Backup & Recovery](../operation/backup-and-recovery.md) for the procedure.

> [!note]
> This USB enclosure reports `rm=false` in `lsblk` (incorrectly — it is removable). The webapp detects it via `tran=usb` instead of the removable flag.

## Power

The Pi draws approximately 8–12W under normal BeaconButty workload. It is powered via USB-C. No UPS is currently in place — a hard power loss will lose any log2ram contents not yet flushed to NVMe.

## Previous hardware

**bb1** — Raspberry Pi 5 4GB (LAN IP: 192.168.50.137, Tailscale: `<tailscale-ip>`). Originally the BeaconButty detection node; migrated to bb0 (8GB) for extra RAM headroom with ClickHouse. bb1 is still in active use for other purposes — do not treat it as decommissioned.
