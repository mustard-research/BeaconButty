---
tags: [beaconbutty/architecture]
created: 2026-04-17
---

# Log2Ram Usage

log2ram is a kept fixture of bb0, not a "nice to have." The Pi writes enough log data per day (~400 MB of continuous small writes pre-migration) to meaningfully chew through NVMe endurance. By staging everything in RAM and flushing once per day, continuous write amplification becomes a single nightly batch.

This page is the definitive source on **what's on log2ram, when it syncs off, and where rotated archives end up on NVMe**. Changes here must be mirrored into [Data Pipeline](data-pipeline.md) and [Hardware Setup](../hardware/hardware-setup.md).

## How log2ram works (short version)

> [!warning] Rescoped 2026-08-28 — log2ram no longer covers all of `/var/log`
> It now RAM-backs **only `/var/log/zeek` and `/var/log/suricata`**. Everything else in
> `/var/log` — the systemd journal, `beaconbutty/`, `dnsmasq.log`, `fail2ban.log`, `apt/`,
> `dpkg.log` — lives directly on NVMe and survives an unclean shutdown.
>
> **Why:** log2ram flushes only on clean shutdown and at 23:55. Before this change a power
> cut or panic lost up to ~24h of *every* log, including `watchdog.log` and `alerts.log` —
> precisely the evidence needed after an incident. The 2026-08-28 WAN outage survived only
> because the reboot happened to be clean.

1. On boot, `log2ram.service` mounts a **tmpfs** over each path in `PATH_DISK` (1 GB cap each).
2. The on-NVMe contents of each path are copied into its tmpfs at mount time, so reads/writes behave as if nothing had changed.
3. Writes to those paths hit RAM. The NVMe copy is stale until the next sync. Writes anywhere else under `/var/log` go straight to NVMe.
4. `log2ram-daily.timer` fires at **23:55 every night**, rsync'ing each tmpfs **back down** to its NVMe backing store.
5. Reboot/shutdown also trigger a flush. **Hard power loss** skips it — anything written to the RAM-backed paths since the last 23:55 sync is lost. That is now an acceptable loss (traffic logs only), which is the entire point of the rescope.

## Configuration

`/etc/log2ram.conf` — key values on bb0:

| Setting | Value | Notes |
|---------|-------|-------|
| `SIZE` | `1G` | tmpfs cap. Was 128M originally → 512M (2026-04-16) → 1G (2026-04-17). See *Upgrade Log*. |
| `PATH_DISK` | `/var/log/zeek;/var/log/suricata` | What gets RAM-backed. **Semicolon-separated, not spaces.** Applies `SIZE` per path. Was `/var/log` until 2026-08-28. |
| `ZL2R` | `false` | Zstd compression of RAM disk disabled (we have headroom) |
| `LOG_DISK_SIZE` | `256M` | Cap on the NVMe-side mirror |

Unit files:

- `log2ram.service` — mounts the tmpfs at boot (one-shot).
- `log2ram-daily.timer` → `log2ram-daily.service` — `OnCalendar=*-*-* 23:55:00`, runs `systemctl reload log2ram.service` which triggers the rsync back to NVMe.

## The fill risk

If a tmpfs fills **before** the 23:55 sync, further writes fail **silently** — logs are dropped with no error. This is the single most important failure mode of the design.

`beaconbutty-health.sh` watches it. It reads `PATH_DISK` from `/etc/log2ram.conf` and checks each mounted path in turn; it previously guarded on `mountpoint -q /var/log`, which turned the whole check into a silent no-op the moment `/var/log` stopped being a mount (i.e. from the 2026-08-28 rescope onwards).

| Usage | Status |
|---|---|
| < 70 % | ✓ OK |
| 70–84 % | ⚠ WARN |
| ≥ 85 % | ✗ FAIL — "may drop logs before 23:55 sync" |

The dashboard log2ram tile uses the same 70 / 85 thresholds.

## What's on log2ram

Only the two bulk traffic-log paths:

| Source | Live path | Backing store on NVMe | Approx. volume |
|--------|----------|----------------------|----------------|
| **Zeek rotated archives** | `/var/log/zeek/YYYY-MM-DD/` | `/var/log/hdd.zeek` | ~40 MB/day rotated-in; steady state ~515 MB for 14 days |
| **Suricata** | `/var/log/suricata/eve.json`, `fast.log`, `stats.log` | `/var/log/hdd.suricata` | ~11 MB live (eve.json trimmed to alert/anomaly only) |

### Durable on NVMe (rescoped off log2ram 2026-08-28)

These are the logs you need *after* an incident, so they must survive an unclean stop:

| Source | Path | Why it matters |
|--------|------|----------------|
| **systemd journal** | `/var/log/journal/` | Persistent since 2026-08-28 — see below |
| **BeaconButty operational** | `/var/log/beaconbutty/*.log` | `watchdog.log`, `alerts.log` — the incident record |
| **dnsmasq queries** | `/var/log/dnsmasq.log` | ~28 MB/day; diagnosed the 2026-08-28 WAN outage |
| **Package / auth** | `apt/`, `dpkg.log`, `fail2ban.log`, `unattended-upgrades/`, `letsencrypt/` | Change and access history |

Cost of moving these to NVMe is ~40 MB/day (~15 GB/yr) against a 238 GB drive rated
~100 TB+ TBW — negligible. Note log2ram already wrote the same bytes to its backing store
on every sync, so this changed write *frequency*, not volume.

### Persistent journal

`/etc/systemd/journald.conf.d/99-beaconbutty-persistent.conf` sets `Storage=persistent`
(512M cap, 1 month). **The `99-` prefix is load-bearing:** Raspberry Pi OS ships
`/usr/lib/systemd/journald.conf.d/40-rpi-volatile-storage.conf` with `Storage=volatile`,
and drop-ins apply in lexical order, so anything sorting below `40-` is silently
overridden. Verify with `systemd-analyze cat-config systemd/journald.conf | grep '^Storage='`
(last line wins) — never by reading our file alone.

Not on log2ram (deliberately excluded — too large, too hot, or database-critical):

| Source | Path | Reason |
|--------|------|--------|
| **ClickHouse logs** | `/var/lib/clickhouse/logs/` | Large; DB-adjacent; configured via `config.d/logs.xml` |
| **Zeek live spool** | `/opt/zeek/spool/zeek/` | Its own separate 128M tmpfs (live files update every second; RAM-backed but NOT part of log2ram's `/var/log` mount) |
| **Zeek state.db + metadata** | `/opt/zeek/spool/` (parent) | Must survive reboot |
| **BeaconButty data** | `/var/lib/beaconbutty/` | Reports, FP registry, assets — persistent |
| **Rotated archives** | See below | Moved off log2ram at rotation time |
| **`/var/hdd.log`** | `/var/hdd.log` | Empty leftover of the pre-2026-08-28 whole-`/var/log` layout. `log2ram.service` still names it in `RequiresMountsFor`, so leave the directory in place. |

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

`/var/log/dnsmasq.log` itself is on NVMe since the 2026-08-28 rescope, so this rotation is now about **retention**, not about getting the data off RAM. The block lives in `/etc/logrotate.d/beaconbutty`:

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

### BeaconButty operational → NVMe (weekly, 8 weeks)

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

Small footprint — no offload configured, and none needed: since the rescope `/var/log/beaconbutty/` is written straight to NVMe, so `watchdog.log` and `alerts.log` are durable the instant they are written rather than at 23:55.

### Everything else (journal, auth, apt, fail2ban…)

Standard Debian logrotate defaults, and since the rescope these paths are ordinary NVMe files — log2ram is not involved at any point in their life.

> [!important] Rule of thumb
> New BeaconButty data files go under `/var/lib/beaconbutty/`, **never** under `/var/log`. Anything bulk placed under `/var/log/zeek` or `/var/log/suricata` competes for a 1 G tmpfs and, when it fills, is dropped silently. ClickHouse's server logs were moved to `/var/lib/clickhouse/logs/` for exactly this reason.

## Nightly sync (23:55)

```bash
systemctl list-timers log2ram-daily.timer
journalctl -u log2ram-daily.service --since "2 days ago" --no-pager
```

The sync rsyncs each tmpfs down to its **own** backing store on NVMe — `/var/log/zeek` → `/var/log/hdd.zeek`, `/var/log/suricata` → `/var/log/hdd.suricata` — so each NVMe copy is at most 24 hours stale. On boot, log2ram copies the backing store back up into tmpfs. (`/var/hdd.log` is the empty leftover of the pre-rescope whole-`/var/log` layout; `log2ram.service` still names it in `RequiresMountsFor`, so leave the directory in place.)

> [!warning]
> **Hard power-loss window**: for the two RAM-backed paths, everything written since the last 23:55 sync is gone. Since the rescope that is Zeek's traffic logs and Suricata's `eve.json` / `fast.log` / `stats.log` only — bulk evidence that regenerates continuously, not the incident record. Rotated Suricata archives are already safe on NVMe. Everything wanted *after* an incident — the journal, `beaconbutty/watchdog.log`, `beaconbutty/alerts.log`, `dnsmasq.log` — no longer lives in RAM at all.

### Verified on the 2026-08-28 reboot

First reboot after the rescope, at 21:30. All three properties held:

| Property | Evidence |
|---|---|
| Shutdown writeback completes | log2ram's own rsync logged `sent 459,553,001 bytes … total size is 458,833,398` |
| Nothing lost in the round trip | `2026-08-27` and `2026-08-28` under `/var/log/zeek` matched their `hdd.zeek` counterparts exactly — 472 files / 38,972,950 B and 536 files / 33,588,635 B |
| The journal survives a reboot | `journalctl --list-boots` listed the pre-reboot boot (16:54 → 21:29) alongside the new one — the first reboot on which it did |

`beaconbutty-health.sh` came back all-green afterwards: 51% of the zeek tmpfs, 2% of the suricata one, no failed units, Zeek capturing 912 conn rows in the first five minutes.

> [!tip] `du` overstates the tmpfs — don't read a size gap as data loss
> `/var/log/zeek` reports 518M against 454M for `/var/log/hdd.zeek`. That is tmpfs page accounting over ~15k small gzips. When checking a writeback, compare apparent bytes (`find … -printf '%s\n'`) and file counts, never `du`.

## Live monitoring

```bash
# Current usage of each RAM-backed path
df -h /var/log/zeek /var/log/suricata

# Top space users inside the zeek tmpfs
sudo du -sh /var/log/zeek/* 2>/dev/null | sort -rh | head

# Confirm what is actually RAM-backed — and, just as usefully, what is not
findmnt -t tmpfs | grep log2ram

# Next scheduled sync
systemctl list-timers log2ram-daily.timer

# Last sync run
journalctl -u log2ram-daily.service --since "2 days ago" --no-pager
```

Dashboard tile (webapp) shows current log2ram utilisation at a glance.

## Data-flow summary (what ends up where)

```
LIVE WRITES                                AFTER ROTATION                              DURABILITY
───────────                                ──────────────                              ──────────
Zeek live (/opt/zeek/spool/zeek/)  ─▶ own 128M tmpfs ─▶ gz ─▶ /var/log/zeek/<date>/    log2ram, 14d
Suricata eve.json / fast.log       ─▶ /var/log/suricata     ─▶ gz ─▶ /var/lib/suricata/archive/   NVMe on rotation
dnsmasq queries                    ─▶ /var/log/dnsmasq.log  ─▶ gz ─▶ /var/lib/beaconbutty/logs/   NVMe throughout
BeaconButty operational            ─▶ /var/log/beaconbutty/ ─▶ gz ─▶ same dir                     NVMe throughout
systemd journal                    ─▶ /var/log/journal/     ─▶ vacuum at 512M / 1 month           NVMe throughout
ClickHouse server logs             ─▶ /var/lib/clickhouse/logs/                                   NVMe throughout

Only the two RAM-backed paths need a sync ── 23:55 daily + clean stop ──▶ /var/log/hdd.zeek
                                                                         /var/log/hdd.suricata
```

## Capacity headroom

See [Capacity & Performance](../operation/capacity-and-performance.md) for the budget math. Short version: steady-state ~460 MB against a 1G cap leaves roughly 2× headroom for logrotate transient bursts.

### Sizing history

| Date | Change |
|---|---|
| (initial) | `SIZE=128M` |
| 2026-04-16 | → `512M`; Suricata + Zeek logs consolidated under `/var/log` for unified log2ram management |
| 2026-04-17 | → `1G` |
| 2026-05-15 | Suricata `eve.json` trimmed to `alert`/`anomaly` — `/var/log` 70 % → 48 %. See *Upgrade Log*. |
| 2026-08-28 | Rescoped: `PATH_DISK` narrowed from `/var/log` to `/var/log/zeek;/var/log/suricata`, `SIZE` applied **per path** |

The Pi 5 has 8 GB RAM, so two 1 G tmpfs caps are comfortable. If usage creeps back toward 70 %, prefer **reducing log volume** (the eve.json trim is the model) over enlarging the tmpfs — a bigger tmpfs only defers the problem.

## See also

- [Hardware Setup](../hardware/hardware-setup.md) — full mount table
- [Data Pipeline](data-pipeline.md) — canonical path table
- *Upgrade Log* — the two log2ram bumps (128M → 512M → 1G)
- [Troubleshooting](../operation/troubleshooting.md) — what to do when `/var/log` fills up or the nightly sync skips
- [Health Monitoring](../operation/health-monitoring.md) — log2ram tmpfs % is one of the System checks
