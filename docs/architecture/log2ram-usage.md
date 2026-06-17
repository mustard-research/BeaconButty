---
tags: [beaconbutty/architecture]
created: 2026-04-17
---

# Log2Ram Usage

log2ram is a kept fixture of bb0, not a "nice to have." The Pi writes enough log data per day (~400 MB of continuous small writes pre-migration) to meaningfully chew through NVMe endurance. By staging everything in RAM and flushing once per day, continuous write amplification becomes a single nightly batch.

This page is the definitive source on **what's on log2ram, when it syncs off, and where rotated archives end up on NVMe**. Changes here must be mirrored into [Data Pipeline](data-pipeline.md) and [Hardware Setup](../hardware/hardware-setup.md).

## How log2ram works (short version)

1. On boot, `log2ram.service` mounts a **tmpfs** at `/var/log` (1 GB).
2. The contents of `/var/log` on the underlying NVMe are copied into the tmpfs at mount time — so reads/writes behave as if nothing had changed.
3. All writes to `/var/log` now hit RAM. The NVMe copy is stale until the next sync.
4. `log2ram-daily.timer` fires at **23:55 every night**, calling `systemctl reload log2ram.service`, which rsync's the tmpfs **back down** to `/var/log` on NVMe.
5. Reboot/shutdown also trigger a flush. **Hard power loss** (pulling the plug) skips the flush — anything written since the last 23:55 sync is lost.

## Configuration

`/etc/log2ram.conf` — key values on bb0:

| Setting | Value | Notes |
|---------|-------|-------|
| `SIZE` | `1G` | tmpfs cap. Was 128M originally → 512M (2026-04-16) → 1G (2026-04-17). See *Upgrade Log*. |
| `PATH_DISK` | `/var/log` | What gets RAM-backed |
| `ZL2R` | `false` | Zstd compression of RAM disk disabled (we have headroom) |
| `LOG_DISK_SIZE` | `256M` | Cap on the NVMe-side mirror |

Unit files:

- `log2ram.service` — mounts the tmpfs at boot (one-shot).
- `log2ram-daily.timer` → `log2ram-daily.service` — `OnCalendar=*-*-* 23:55:00`, runs `systemctl reload log2ram.service` which triggers the rsync back to NVMe.

## What's on log2ram

Everything under `/var/log/`. The high-volume residents are:

| Source | Live path | Approx. daily write volume |
|--------|----------|----------------------------|
| **Suricata** | `/var/log/suricata/eve.json`, `fast.log`, `stats.log` | ~200–250 MB (eve.json dominates) |
| **Zeek rotated archives** | `/var/log/zeek/YYYY-MM-DD/` | ~25 MB/day rotated-in; steady state ~350 MB for 14 days |
| **dnsmasq queries** | `/var/log/dnsmasq.log` | ~28 MB/day |
| **BeaconButty operational** | `/var/log/beaconbutty/*.log` — includes `alerts.log`, report runs, housekeeping, etc. | ~1–5 MB/day |
| **Systemd / package / auth** | `/var/log/syslog`, `daemon.log`, `auth.log`, `apt/`, `fail2ram/`, `journal/` (partial) | Small |

Not on log2ram (deliberately excluded — too large, too hot, or database-critical):

| Source | Path | Reason |
|--------|------|--------|
| **ClickHouse logs** | `/var/lib/clickhouse/logs/` | Large; DB-adjacent; configured via `config.d/logs.xml` |
| **Zeek live spool** | `/opt/zeek/spool/zeek/` | Its own separate 128M tmpfs (live files update every second; RAM-backed but NOT part of log2ram's `/var/log` mount) |
| **Zeek state.db + metadata** | `/opt/zeek/spool/` (parent) | Must survive reboot |
| **BeaconButty data** | `/var/lib/beaconbutty/` | Reports, FP registry, assets — persistent |
| **Rotated archives** | See below | Moved off log2ram at rotation time |

> [!important]
> `/var/log` is for **active, hot** log files. Anything large or database-critical must use `/var/lib/...` instead. This is the single most common mistake when adding new logging.

## Rotation / offload schedule

The point of log2ram isn't just "logs in RAM" — it's "rotated archives get shipped back to NVMe before the tmpfs fills up." Each high-volume source has its own logrotate config that handles the offload.

### Suricata → `/var/lib/suricata/archive/`

`/etc/logrotate.d/suricata`:

```
/var/log/suricata/*.log
/var/log/suricata/*.json {
    rotate 14
    daily
    missingok
    compress
    copytruncate
    sharedscripts
    olddir /var/lib/suricata/archive
    createolddir 0755 root root
    postrotate
        /bin/kill -HUP $(cat /var/run/suricata.pid)
    endscript
}
```

- **Daily**, keep **14** archives
- `copytruncate` — Suricata keeps writing to the same inode, logrotate copies + truncates in place
- `olddir` places rotated `.gz` files directly on NVMe and runs the `.1→.2→…→.14` rename chain there — so archives never accumulate in log2ram and a full 14-day history is preserved

> [!warning] Earlier config had a silent-overwrite bug (fixed 2026-04-24)
> The pre-2026-04-24 config used a `lastaction` with `find … -exec mv {} /var/lib/suricata/archive/ \;`. Plain `mv` clobbers, so every daily rotation overwrote yesterday's `fast.log.1.gz` / `eve.json.1.gz` in the archive dir. The `.2`→`.14` slots never got populated because the rename chain ran in the live dir (always empty after each lastaction sweep), so `rotate 14` was a lie — only today + yesterday ever existed. Switched to `olddir` which does the renumbering natively.

### Zeek archives → stay on log2ram for 14 days

Zeek rotates itself (via `zeekctl cron`, scheduled in root's crontab every 5 min). On each rotation:

1. Live logs in `/opt/zeek/spool/zeek/*.log` are sealed, gzipped, and moved to the current-day dated dir: `/var/log/zeek/YYYY-MM-DD/<log>.gz`.
2. `LogExpireInterval = 14` in `/opt/zeek/etc/zeekctl.cfg` — `zeekctl cron` deletes dated dirs older than 14 days. **Unit is days, not hours.**
3. There is **no offload to NVMe for Zeek archives** — they're born on log2ram and die on log2ram. They reach NVMe only via the nightly 23:55 rsync.

This matches Suricata's 14-day archive convention. ~350 MB steady-state footprint against the 1G log2ram cap leaves comfortable headroom, and RITA reads these hourly.

### dnsmasq → `/var/lib/beaconbutty/logs/`

The dnsmasq block lives in `/etc/logrotate.d/beaconbutty`:

```
/var/log/dnsmasq.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
    copytruncate
    olddir /var/lib/beaconbutty/logs
    createolddir 0755 root root
}
```

- **Daily**, keep **14** archives
- Archives live in `/var/lib/beaconbutty/logs/` on NVMe via `olddir` (same pattern as Suricata)
- Had the same lastaction-mv overwrite bug as Suricata; fixed 2026-04-24 — see the warning callout above

### BeaconButty operational → stay on log2ram (weekly, 8 weeks)

`/etc/logrotate.d/beaconbutty`:

```
/var/log/beaconbutty/*.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
}
```

Small footprint — no offload configured. Contents persist in log2ram for 8 weeks' worth of rotations and rejoin NVMe only at the nightly sync.

### Everything else (syslog, auth, apt, fail2ban…)

Standard Debian logrotate defaults. All archives live in `/var/log/...` (log2ram) and sync to NVMe at 23:55.

## Nightly sync (23:55)

```bash
systemctl list-timers log2ram-daily.timer
journalctl -u log2ram-daily.service --since "2 days ago" --no-pager
```

The sync runs `rsync` from the tmpfs to `/var/log.hdd/` on NVMe — so the NVMe copy is at most 24 hours stale. On reboot, log2ram reads from `/var/log.hdd/` back into tmpfs.

> [!warning]
> **Hard power loss lost-data window**: last entry of any log file since the 23:55 sync is gone. Rotated archives (Suricata + dnsmasq) are safe because they've already been moved to NVMe on rotation. BeaconButty operational logs, current-day live log tails (eve.json, dnsmasq.log, syslog), and any journal spillover are the exposed surface.

## Live monitoring

```bash
# Current usage
df -h /var/log

# Top space users inside log2ram
sudo du -sh /var/log/* 2>/dev/null | sort -rh | head

# Mount info (confirms tmpfs + size)
mount | grep '/var/log '

# Next scheduled sync
systemctl list-timers log2ram-daily.timer

# Last sync run
journalctl -u log2ram-daily.service --since "2 days ago" --no-pager
```

Dashboard tile (webapp) shows current log2ram utilisation at a glance.

## Data-flow summary (what ends up where)

```
LIVE WRITES                               AFTER ROTATION                     AFTER 23:55 SYNC
─────────────────                         ──────────────────                  ──────────────────
Suricata eve.json                 ─▶ log2ram ─▶ gz ─▶ /var/lib/suricata/archive/ (NVMe)
Suricata fast.log                 ─▶ log2ram ─▶ gz ─▶ /var/lib/suricata/archive/ (NVMe)
Zeek live (/opt/zeek/spool/zeek/) ─▶ tmpfs 128M ─▶ gz ─▶ /var/log/zeek/YYYY-MM-DD/ (log2ram, 7d)
dnsmasq queries                   ─▶ log2ram ─▶ gz ─▶ /var/lib/beaconbutty/logs/ (NVMe)
BeaconButty operational           ─▶ log2ram ─▶ gz ─▶ /var/log/beaconbutty/ (log2ram)
syslog / auth / apt / fail2ban    ─▶ log2ram ─▶ gz ─▶ /var/log/... (log2ram)

All log2ram content ─────────────────────────────────────── rsync'd to NVMe at 23:55 ──▶ /var/log.hdd/
```

## Capacity headroom

See [Capacity & Performance](../operation/capacity-and-performance.md) for the budget math. Short version: steady-state ~460 MB against a 1G cap leaves roughly 2× headroom for logrotate transient bursts.

## See also

- [Hardware Setup](../hardware/hardware-setup.md) — full mount table
- [Data Pipeline](data-pipeline.md) — canonical path table
- *Upgrade Log* — the two log2ram bumps (128M → 512M → 1G)
- [Troubleshooting](../operation/troubleshooting.md) — what to do when `/var/log` fills up or the nightly sync skips
- [Health Monitoring](../operation/health-monitoring.md) — log2ram tmpfs % is one of the System checks
