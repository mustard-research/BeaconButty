---
tags: [beaconbutty/operation]
created: 2026-04-16
---

# Backup & Recovery

## Full DR procedure

The definitive disaster recovery procedure is in **`RESTORE.md`** in the repository root. It covers the full rebuild sequence including hardware, OS, services, and data restoration. Keep it updated whenever backup contents or the service list changes.

## Three backup tiers

The Backup page (last tab in the nav) offers three tiers, increasing in completeness and disk cost:

| Tier | Contents | Size | Cadence | Output |
|------|----------|------|---------|--------|
| Config snapshot | Scripts, systemd units, config files, webapp source, FP registry | ~30 MB | Daily 02:00 (last 14) | `config-YYYY-MM-DD.tar.gz` |
| **Full archive** | Rootfs + ClickHouse data + logs (not bootable) | ~10 GB | Weekly Sun 03:00 (last 4) | `archive-YYYY-MM-DD.tar.gz` |
| Full-disk clone | Bootable byte-for-byte NVMe clone | ~17 GB on 32+ GB stick | Manual | `rpi-clone` to USB |

All three are triggered from the webapp Backup page. Config snapshot and full archive also have systemd timers; full-disk clone is manual only (it wipes the target drive).

### Tier 1 — Config snapshot

Daily `tar.gz` of everything in the "config surface" — all `/usr/local/bin/beaconbutty-*.sh` scripts, systemd units, `/etc/rita/`, Suricata config, NetworkManager profiles, iptables rules, `/home/dm/BeaconButty/`, Let's Encrypt renewal config, false-positive registry, Slack config, etc. See `scripts/backup.sh` for the full file list.

- Runs from `beaconbutty-backup.timer` at 02:00 daily
- Retention: last 14 kept (~2 weeks)
- Restore: RESTORE.md Option A

Also writes `packages-YYYY-MM-DD.txt` (dpkg selections) alongside each snapshot.

### Tier 2 — Full archive

Full rootfs tarball — captures everything a config snapshot has **plus ClickHouse history, Zeek/Suricata logs, installed binaries** under `/usr/local/` etc. Archives `/`, `/boot/firmware`, and `/var/log` (log2ram tmpfs) with `--one-file-system` so volatile mounts (`/tmp`, `/dev`, `/proc`) are skipped.

- Runs from `beaconbutty-archive.timer` on Sunday 03:00, with `RandomizedDelaySec=5m` and `Persistent=true`
- Script: `scripts/backup-archive.sh` (runs direct from repo, not deployed to `/usr/local/bin/`)
- Retention: last 4 kept (~4 weeks)
- Uses `flock` on `/var/lock/beaconbutty-archive.lock` to prevent overlap between manual webapp runs and the timer
- **ClickHouse is stopped** during tar for a consistent snapshot, then restarted. Pauses the Beacons page for 3–10 min depending on CH data size
- Restore: RESTORE.md Option B — extract over a fresh Pi OS Lite install with `tar -xzpf archive-*.tar.gz -C / --numeric-owner --xattrs`

The archive is **not bootable** — it's a tar for over-extracting onto a fresh OS. For a bootable recovery target, use Tier 3.

### Tier 3 — Full-disk USB clone (rpi-clone)

Full-disk NVMe clone to a USB enclosure using `rpi-clone`. The clone is bootable — in a disaster scenario, plug the USB drive in and boot from it.

1. Plug in the USB drive (465.8GB enclosure, appears as `sda`)
2. Webapp → **Backup** page → Full-Disk Clone section
3. Select `sda` and click **Clone to USB**
4. A pulsing yellow badge in the card header shows the clone is running
5. Takes approximately 7 minutes for a 16GB used NVMe
6. When the badge disappears, verify: `mount | grep sda` — if nothing is mounted, it is safe to unplug
7. rpi-clone unmounts all partitions on completion — no manual unmount needed

> [!note]
> The USB enclosure for this drive reports `rm=false` in `lsblk` (a firmware quirk — it is genuinely removable). The webapp detects it via `tran=usb` rather than the removable flag.

The USB clone captures **everything on the NVMe** — full OS, all packages, configs, Zeek logs, ClickHouse data, webapp, secrets (Slack token, AWS credentials, TLS private key). Restore: RESTORE.md Option C.

## Git repository backup

The git repo (`github.com/...`) covers the *code and configuration*:

- `scripts/` — all operational scripts
- `webapp/` — Flask app and templates
- `systemd/` — service and timer unit files
- `config/` — configuration files

The git repo does **not** contain:
- Live Zeek logs or ClickHouse data
- Secrets: `slack-config.json`, AWS credentials, TLS private key
- `/var/lib/beaconbutty/` data files (reports, FP registry)

## HTTPS certificate

Let's Encrypt certificate obtained via **Route 53 DNS challenge** (certbot).

| Item | Detail |
|------|--------|
| Certificate authority | Let's Encrypt |
| Challenge method | DNS-01 via Route 53 |
| IAM user | certbot-beaconbutty — Route 53 permissions only |
| Renewal | Twice-daily certbot timer; deploy hook restarts `bb-graphs.service` |
| Private key | `/etc/letsencrypt/live/<domain>/privkey.pem` |

> [!warning]
> The TLS private key is root-only by default. The certbot deploy hook must set appropriate group permissions so `bb-graphs.service` can read it. If the webapp fails to start after a cert renewal, check privkey permissions.
> 
> AWS CLI operations for Route 53 (and anything blocked by the FORCE_MFA policy) require `--profile mfa`.

## Verifying an archive

To prove an `archive-YYYY-MM-DD.tar.gz` is readable without doing a full restore:

```bash
sudo gzip -t /var/lib/beaconbutty/backups/archive-YYYY-MM-DD.tar.gz
sudo tar -tzf /var/lib/beaconbutty/backups/archive-YYYY-MM-DD.tar.gz | wc -l
sudo tar -tzf /var/lib/beaconbutty/backups/archive-YYYY-MM-DD.tar.gz | grep -c "^var/lib/clickhouse/"
```

Healthy numbers (as of 2026-04-19): ~375k entries total, ~100k under `var/lib/clickhouse/`, ~4k under `boot/firmware/` + `var/log/`.

This only proves **archive integrity**, not ClickHouse data consistency. If ClickHouse was running during the tar (it shouldn't be — the script stops it), the archive structure is still sound but CH metadata inside may be slightly out-of-sync with parts on disk. On restore, CH would start up but may discard in-flight parts or log orphan warnings. Committed data is preserved because MergeTree parts are immutable once written.

## Recovery priority order

In a total loss scenario:

1. **Boot USB clone** (if available) — fastest path back to full operation, preserves ClickHouse history and TLS key
2. **Full archive** (if available, no clone) — extract onto fresh Pi OS Lite; keeps ClickHouse history, needs TLS cert re-issue
3. **Config snapshot + git** (no clone, no archive) — rebuild OS, install packages from `packages-*.txt`, extract config snapshot; ClickHouse history is lost, fresh collection begins immediately
4. **Git only** (nothing else) — rebuild from scratch using repo + RESTORE.md, re-enter all secrets manually

Historical beacon data (ClickHouse) is preserved in tiers 1 and 2, but NOT in the config snapshot or the git repo.
