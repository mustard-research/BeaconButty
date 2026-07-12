---
tags: [beaconbutty/operation]
created: 2026-04-17
---

# Capacity & Performance

Current sizing, steady-state footprints, and trigger points for when bb0 would need more resources.

## Live snapshot (2026-06-16)

| Resource | Used | Total | Headroom |
|----------|------|-------|---------|
| RAM | 5.0 GB | 7.9 GB | 3.0 GB available |
| NVMe `/` | 53 GB | 235 GB | 173 GB free (24% used) |
| log2ram `/var/log` | ~460 MB | 1.0 GB | ~565 MB free (45% used) |
| Zeek spool tmpfs | ~3 MB | 128 MB | ~125 MB free |
| ClickHouse data | 4.8 GB | — | — |
| BeaconButty data | 80 MB | — | — |

Pull latest with:

```bash
free -h && df -h / /var/log && du -sh /var/lib/clickhouse /var/lib/beaconbutty
```

## RAM budget (peak scenario)

| Consumer | Typical RSS |
|----------|------------|
| ClickHouse | ~2.5–2.9 GB steady (14-day peak 2.86 GB); **4 GiB hard cap** from `config.d/memory.xml` — dropped from 5 GiB on 2026-07-12 since steady state never approached it. Was 3 GiB pre-2026-06-16, which proved too tight as the cumulative dataset grew (see *Upgrade Log*); if `code: 241` returns, raise it again (see *Troubleshooting*) |
| Zeek workers | ~300–500 MB |
| Suricata | ~1.3–1.5 GB (full ET ruleset + af-packet buffers) |
| `bb-graphs` (Flask) | ~150–300 MB |
| dnsmasq | ~10–20 MB |
| log2ram tmpfs | ~460 MB (counted as used by the kernel) |
| Zeek spool tmpfs | ~3–10 MB |
| Kernel / OS / everything else | ~500 MB |

Steady state is ~65 % used: ≈2 GB genuinely available plus ~2.5 GB of reclaimable cache, and ~800 MB of cold pages parked in swap with no churn (normal). The 8 GB Pi model was chosen specifically for ClickHouse + Zeek co-residence. The 4 GB bb1 node showed OOM pressure under RITA import bursts — why bb0 exists.

Live view: the **/system page** charts memory history (since 2026-07-12) alongside CPU and lists current per-service consumers with OK/HIGH badges against expected ceilings.

## NVMe capacity

The NVMe is a 500 GB SSD. Live usage is 16 GB → **97% headroom**. Dominant consumers:

- **ClickHouse** (~3.2 GB, growing) — main long-term growth vector
- OS + installed packages (~8 GB)
- Docker images / dev junk (varies)
- `/var/log.hdd/` log2ram mirror (~500 MB)

### ClickHouse growth projection

System log tables have a **14-day TTL** via `/etc/clickhouse-server/config.d/system-log-ttl.xml`. Beacon / connection data is retained indefinitely by default (RITA-managed).

Rough growth rate: ~200–400 MB/week of new ClickHouse data under current LAN traffic. At that rate:

| Horizon | Projected ClickHouse |
|---------|---------------------|
| 6 months | ~8–15 GB |
| 1 year | ~15–25 GB |
| 2 years | ~30–50 GB |

Well within 500 GB, but worth revisiting when LAN traffic volume changes materially.

### NVMe endurance (write wear)

The Pironman's NVMe is consumer-grade (TBW ~300–600 depending on SKU). Writes log2ram was designed to eliminate: **~400 MB/day of continuous small writes**, aggregated to a nightly batch. Without log2ram, 400 MB/day × 365 = ~146 GB/year just from logs — would add years of wear over time. With log2ram + Zeek spool tmpfs: that continuous load drops to the bytes it is now.

Check SMART:

```bash
sudo smartctl -a /dev/nvme0n1 | grep -E 'Data Units|Percent|Critical|Power_On'
```

- `Percentage Used` — the headline number. Watch for >50% as a replacement trigger.
- `Data Units Written` (512-byte units) — multiply by 512 for bytes written lifetime.

## log2ram headroom

Current `SIZE=1G`, steady-state ~460 MB. Logrotate transient bursts can add ~100–200 MB during a rotation (copytruncate duplicates temporarily).

| Scenario | Peak | Status |
|----------|------|-------|
| Steady state | ~460 MB | 45% — healthy |
| During logrotate | ~600 MB | 60% — healthy |
| Under sustained alert storm (10× Suricata volume) | ~1 GB+ | Would exhaust — needs bump |

Previous bumps: 128M → 512M (2026-04-16) → 1G (2026-04-17). See *Upgrade Log* and [Log2Ram Usage](../architecture/log2ram-usage.md).

## CPU / thermal

- **CPU idle**: ~5–15% across 4 cores
- **Peak load**: Hourly RITA import spikes one core to ~100% for 30–90 seconds
- **CPU temp**: typically 55–62°C — right at the RPi active cooler threshold (on at 58°C, off at 54°C). See [Fan Control](../hardware/fan-control.md).
- **Pironman case fan**: only kicks in (60°C threshold) during heavy sustained load

Throttling history:

```bash
vcgencmd get_throttled
# 0x0 = healthy
# Any other value = throttled or previously throttled (reset on reboot)
```

## Network throughput

The Pi NICs and USB-ethernet dongle handle typical home/small-office LAN (<100 Mb/s sustained). Zeek captures at line rate on eth1. Bottleneck is not bandwidth — it's Zeek CPU during flow-heavy bursts.

Check for dropped packets:

```bash
sudo zeekctl diag | grep -i drop
# or
ip -s link show eth1 | grep -A1 RX
```

If `rx_dropped` climbs, the Pi is losing traffic — investigate CPU, buffer tuning, or upgrade.

## When to upgrade bb0

Triggers for a hardware refresh or migration:

| Trigger | Threshold | Next step |
|---------|-----------|-----------|
| NVMe `Percentage Used` | >50% | Plan NVMe replacement; rpi-clone → fresh drive |
| ClickHouse size | >200 GB | Consider shorter retention or external ClickHouse |
| RAM pressure (swap activity sustained) | `vmstat 10` showing `si/so > 0` sustained | Bigger Pi or offload Suricata to bb1 |
| Suricata packet drops | >1% of captured flows | CPU-bound; tune or upgrade |
| log2ram peak | sustained >80% | Bump `SIZE` in `/etc/log2ram.conf` |
| CPU thermal throttling | `vcgencmd get_throttled != 0x0` in normal ops | Clean fans, check ambient, consider additional cooling |

## Scaling notes

- **bb1** (Pi 5 4 GB) is still active for other purposes and could serve as a warm spare for bb0 if needed. Would need restore from USB clone.
- The detection stack (Zeek + RITA + ClickHouse) runs comfortably on the Pi 5 8 GB. Moving off Pi would only be necessary at 10× current LAN traffic or multi-site aggregation.
- **RAM is the first real ceiling** — ClickHouse is greedy during large RITA imports.

## See also

- [Log2Ram Usage](../architecture/log2ram-usage.md) — canonical log2ram write patterns and rotation
- [Hardware Setup](../hardware/hardware-setup.md) — full mount table and power draw
- [Fan Control](../hardware/fan-control.md) — thermal thresholds
- *Upgrade Log* — prior capacity-driven changes
- [Reboot Procedure](reboot-procedure.md) — why reboots are expensive (ClickHouse shutdown) — informs planning
