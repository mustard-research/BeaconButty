---
tags: [beaconbutty/development]
created: 2026-04-16
---

# Scripts & Timers

All operational scripts are deployed to `/usr/local/bin/`. Source lives in `scripts/` in the repository.

## Deployed scripts

Deployment happens via `scripts/05_configure.sh` (lines 89–104) using `install -m 755`. Repo source is the authoritative copy — always edit the repo and re-deploy, never hand-patch `/usr/local/bin/` (see [Data-path alignment](#data-path-alignment)).

| Repo file | Deployed path | Triggered by | Purpose |
|-----------|---------------|--------------|---------|
| `analyze.sh` | `rita-analyze.sh` | `rita-analyze.timer` | Hourly RITA import of Zeek logs into ClickHouse |
| `report.sh` | `beacon-report.sh` | `beacon-report.timer` | Daily 07:00 beacon report + Slack alert |
| `summarize.sh` | `beaconbutty-summary.sh` | Manual | Human-readable CLI beacon summary |
| `morning-check.sh` | `beaconbutty-morning.sh` | Manual | Combined health + RITA + report + summary |
| `healthcheck.sh` | `beaconbutty-health.sh` | `beaconbutty-health.timer` + Health page | Full system health check |
| `housekeeping.sh` | `beaconbutty-housekeeping.sh` | `beaconbutty-housekeeping.timer` | Zeek dir + RITA dataset + Suricata log cleanup |
| `assets.sh` | `beaconbutty-assets.sh` | `beaconbutty-assets.timer` | Refresh LAN asset cache |
| `backup.sh` | `beaconbutty-backup.sh` | `beaconbutty-backup.timer` + webapp | Daily config snapshot (KEEP=14) / webapp Full-Disk Clone page |
| `backup-archive.sh` | runs direct from repo (no deploy) | `beaconbutty-archive.timer` + webapp | Weekly Sun 03:00 full rootfs tar (~10 GB, KEEP=4) — stops ClickHouse for consistent snapshot |
| `alert.sh` | `beaconbutty-alert.sh` | Called by other scripts | Slack notification dispatcher |
| `suricata-alert-check.sh` | `beaconbutty-suricata-alert-check.sh` | `suricata-alert-check.timer` | Hourly scan of fast.log, dedup + notify |
| `fp.sh` | `beaconbutty-fp.sh` | Manual CLI | False-positive registry tool |
| `harden.sh` | `beaconbutty-harden.sh` | Manual | System hardening / audit |
| `clickhouse-upgrade.sh` | `beaconbutty-clickhouse-upgrade.sh` | Manual (interactive, `--yes` to skip prompt) | Safe ClickHouse upgrade: preflight → snapshot config.d/ → pause RITA → apt-mark unhold/install/re-hold → verify (config.d intact, SELECT 1, memory cap within ceiling, dataset count, **schema canary**) → resume RITA + wait for new `=== done:` marker. Stops on any verify failure; snapshot kept at `/var/lib/beaconbutty/ch-upgrade/<UTC-ts>/` for manual recovery. Added 2026-06-16 in response to that day's silent-degradation incident. The schema canary (creates + drops a RITA-shaped `AggregatingMergeTree`) was added 2026-07-24: the workload check only re-imports into *today's* dataset, which already exists, so it never exercises `CREATE TABLE` and a schema-validation change stays hidden until the next midnight rollover — see *Upgrade Log* |
| `midsummer-fan-check.py` | `beaconbutty-midsummer-fan-check.py` | `beaconbutty-midsummer-fan-check.timer` (one-shot 2026-07-15) | Compare summer temps to Apr-24 baseline on [Fan Control](../hardware/fan-control.md) |
| `wan-watchdog.sh` | `wan-watchdog.sh` | `wan-watchdog.timer` (5 min) | WAN failure detection + auto-recover (nmcli-only since 2026-07-03) |
| `bb-watchdog` | `bb-watchdog` | `bb-watchdog.service` (daemon) | Thermal & health watchdog — 60 s telemetry incl. `mem_pct` + top CPU/memory consumers (since 2026-07-12), fan hysteresis, LED health signal, 30-min health checks |
| `bb0-display.py` | `bb0-display.py` | `bb0-display.service` | OLED display + Pironman LED control |
| `bb0-led` | `bb0-led` | Called by display script | LED strip control |
| `bb0-fan` | `bb0-fan` | Called by display script | Pironman fan control |
| `reboot-wrapper` | `/usr/local/sbin/reboot` | Intercepts `sudo reboot` | Clean shutdown before reboot |
| `bb-reboot` | `/usr/local/bin/bb-reboot` | Called by reboot wrapper | Pre-stop ClickHouse, notify Slack |
| `ip-intel.py` | `beaconbutty-ip-intel.py` | `beaconbutty-ip-intel.timer` | Daily refresh of external IP threat-intel cache (Shodan InternetDB + AbuseIPDB + Spamhaus DROP + Tor exit list) — see [External IP Intel](../investigation/external-ip-intel.md) |
| `teams-cidr-refresh.py` | `beaconbutty-teams-cidr-refresh.py` | `beaconbutty-teams-cidr-refresh.timer` | Daily 03:30 — pull live Microsoft Teams CIDR + URL list from `endpoints.office.com`; output to `/var/lib/beaconbutty/teams-cidrs.json` |
| `teams-relay-check.py` | `beaconbutty-teams-relay-check.py` | `beaconbutty-teams-relay-check.timer` | Every 15 min — DragonForce / Backdoor.Turn detector (Teams TURN C2 channel). See [Teams-Relay Detection](../investigation/teams-relay-detection.md) |

## Timer schedule

| Timer unit | Schedule | Script called |
|------------|----------|---------------|
| `rita-analyze.timer` | Hourly :05 | `rita-analyze.sh` |
| `suricata-alert-check.timer` | Hourly :04 | `beaconbutty-suricata-alert-check.sh` |
| `beacon-report.timer` | Daily 07:00 | `beacon-report.sh` |
| `beaconbutty-housekeeping.timer` | Daily 08:00 | `beaconbutty-housekeeping.sh` |
| `beaconbutty-health.timer` | Daily 09:30 | `beaconbutty-health.sh` |
| `beaconbutty-assets.timer` | Every 6h :27 | `beaconbutty-assets.sh` |
| `beaconbutty-backup.timer` | Daily 02:00 | `beaconbutty-backup.sh` |
| `beaconbutty-archive.timer` | Weekly Sun 03:00 (+5m jitter) | `scripts/backup-archive.sh` (full archive) |
| `log2ram-daily.timer` | Daily 23:55 | `log2ram-daily.service` (sync to NVMe) |
| `suricata-update.timer` | Daily ~06:30 | `suricata-update` |
| `geoipupdate.timer` | Wed + Sat | `geoipupdate` |
| `certbot.timer` | Twice daily | `certbot renew` |
| `beaconbutty-midsummer-fan-check.timer` | **One-shot 2026-07-15 10:00** | `beaconbutty-midsummer-fan-check.py` (self-disables after firing) |
| `beaconbutty-ip-intel.timer` | Daily 07:30 | `beaconbutty-ip-intel.py` (Shodan + AbuseIPDB + Spamhaus DROP + Tor exit external IP enrichment) |

## Data-path alignment

Every consumer script and the webapp has defaults/constants pointing at canonical data paths. When those paths change (as in the 2026-04-16 log2ram migration), **every** consumer must be updated — repo source AND the deployed `/usr/local/bin/` copy.

**Rules of engagement when moving a data path:**

1. `grep -rn '<old-path>' scripts/ webapp/ manage.sh setup.sh migrate.sh` — enumerate consumers.
2. For each deployed script, `diff` against repo to detect hand-patches that never made it back (the 2026-04-17 audit found `rita-analyze.sh` in this state).
3. Update repo first, then redeploy with `install -m 755 scripts/X.sh /usr/local/bin/<deployed-name>`.
4. Restart bb-graphs + any affected timer services.
5. Verify each consumer with a non-empty line count / sample query.
6. Fix installer scripts (`08_install_*`, `05_configure.sh`, `setup.sh`, `migrate.sh`) so a future rebuild doesn't regress.
7. Clean orphan data at the old path.

> [!warning]
> Silent drift is the default failure mode. A script reading a stale path doesn't throw — it returns empty and happily exits 0. Always verify with output, not exit codes.

## RITA import details

```bash
# Must run from /etc/rita/ — needs .env (ClickHouse credentials) in CWD
cd /etc/rita && rita import <log-directory> <dataset-name>

# Parse rita list output with grep -oP — field format uses variable whitespace
rita list | grep -oP '<pattern>'
```

> [!warning]
> Running `rita` from any directory other than `/etc/rita/` will fail because it cannot find the `.env` file.

`rita-analyze.sh` reads Zeek logs from `/var/log/zeek/` (log2ram). The `LOG_DIR` variable defaults to this path. Override with `LOG_DIR=/other/path` if needed. See [Data-path alignment](#data-path-alignment) for the consumer-audit rules.

## Asset cache build

`beaconbutty-assets.sh` builds `/var/lib/beaconbutty/assets.json` by merging three sources:

1. **Live dnsmasq leases** — `/var/lib/misc/dnsmasq.leases` (MAC, IP, hostname for currently-leased devices)
2. **Zeek known_hosts.log** — observed active hosts
3. **Previous assets.json** — carry-forward for devices not currently online

**Priority rule**: live dnsmasq/Zeek data always wins over the carried-forward value. Carry-forward only runs after all live sources have been consulted. This ensures a device that has been renamed or re-leased shows its current state, not a stale cached one.

## False positive CLI

```bash
# List all registered FPs with reasons
beaconbutty-fp.sh list

# Add a device FP
beaconbutty-fp.sh add <ip> "<reason>"

# Remove an FP
beaconbutty-fp.sh remove <ip>
```

FPs are stored in `/var/lib/beaconbutty/false-positives.conf`.

> [!important]
> After adding an FP via CLI, the webapp's `_NETWORK_CACHE` will not reflect the change until the cache expires or the service restarts. The webapp's own FP-write path busts the cache automatically. CLI writes do not.

## Reboot wrapper

`scripts/reboot-wrapper` is deployed to `/usr/local/sbin/reboot`. It intercepts all `sudo reboot` calls before they reach `/usr/sbin/reboot` (the systemctl symlink), thanks to `/usr/local/sbin` appearing first in the sudo PATH.

Pass `--force` or `-f` to bypass and call the real reboot directly. See [Reboot Procedure](../operation/reboot-procedure.md).

## Hardening

`scripts/harden.sh` was used during initial system hardening. It covers SSH config, firewall rules, fail2ban, unattended-upgrades, open ports, and sysctl settings. It can be re-run to audit the current state against the baseline.

```bash
sudo /home/dm/BeaconButty/scripts/harden.sh
```
