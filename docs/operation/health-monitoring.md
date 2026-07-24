---
tags: [beaconbutty/operation]
created: 2026-04-16
---

# Health Monitoring

## Health page

The webapp Health page (`/health`) runs `sudo beaconbutty-health.sh --json` and renders the result as per-section cards with coloured ✓/!/✗ indicators and a summary badge (all-passed / N warn / N fail). The page also provides:
- **OLED display toggle** — blank/restore the display without stopping the service
- **Clear Slack Channel** button — purges all message history from `#beacon-butty`
- **Test Alert** button — fires a manual alert through the Lambda/Slack chain
- **TLS cert card** — domain, issue/expiry dates, days remaining (colour-gated at 30/14 days)

> [!note]
> The Health page is accessible via the **Health tile on the Dashboard** only — it is not in the main navigation. This is intentional (it's a power-user/ops page).

## beaconbutty-health.sh

Run time: approximately 10 seconds. 45 checks across 9 sections. Supports `--json` for structured webapp consumption; default output is colourised text for terminal use.

| Section | Checks |
|---------|--------|
| System | uptime, memory, disk, load, CPU temp, throttling history (`vcgencmd get_throttled`), log2ram tmpfs %, **Sustained-high CPU** (rolling 60-min mean reported by bb-watchdog — `ELEVATED` when ≥60%, `normal` otherwise; alert + diagnostic snapshot at `/var/lib/beaconbutty/watchdog/high-cpu-events/<UTC-ts>.json` — see *Upgrade Log*), time sync (`timedatectl`), pending reboot |
| Network Interfaces | eth0/eth1 link + IP, WAN reachability (ping 1.1.1.1) |
| Routing & Firewall | IP forwarding, NAT MASQUERADE, FORWARD rule, IPv4/IPv6 INPUT=DROP, external DNS resolution (flags Tailscale-only resolver) |
| Services | clickhouse-server, **ClickHouse version vs apt candidate** (informational; WARN ≥3 ClickHouse releases behind, since CH versions encode YY.M and one release ≈ one month — drives the safe-upgrade flow described in *Upgrade Log*), dnsmasq, bb-graphs, Tailscale, TLS cert expiry (WARN<30d, FAIL<14d), Zeek via zeekctl |
| Zeek Logging | conn.log / dns.log presence+freshness, completed daily dirs, **capture rate** (new conn rows in last 5 min — catches "up but not capturing") |
| RITA / ClickHouse | RITA binary, dataset count, **SELECT 1 query probe** (catches a wedged server), data size |
| Suricata IDS | service status, **capture liveness** (`stats.log` freshness — rewritten every 60s regardless of traffic; threshold 180s), eve.json size + last alert/anomaly age (informational only), today's alerts by priority, rule file age |
| Systemd Timers | all scheduled timers enabled + next-run time |
| Recent Activity | last RITA analyse (attempt), **RITA last successful import** (parses `=== done:` marker — WARN ≥90 min, FAIL ≥6 h; catches silent breakage like the 2026-05-30→06-16 memory-limit incident where the hourly timer kept firing but never completed), failed services, beacon report count, **backup freshness** (WARN>1d, FAIL>7d) |
| Reboot Readiness (2026-05-12) | `dnsmasq --test`, `logrotate -d`, `visudo -c`, sweep of `/etc/{dnsmasq.d,logrotate.d,apt/apt.conf.d,sudoers.d,cron.d}` for `*.bak`/`*.old`/`*.disabled`/`*.dpkg-*`/`*.ucf-*` stragglers — **auto-quarantined** to `/var/lib/beaconbutty/config-quarantine/<UTC-ts>/` (2026-05-13) with the destination path baked into the `config_stray_files` Slack alert. Catches the class of dormant `.bak` that broke dnsmasq on 2026-05-12 reboot — see [Reboot Procedure](reboot-procedure.md) and *Incident Log* |

Usage:

```bash
# Colourised text (terminal)
sudo beaconbutty-health.sh

# Structured JSON (webapp / automation)
sudo beaconbutty-health.sh --json
```

### JSON schema

```json
{
  "timestamp": "2026-04-17T19:40:00+01:00",
  "failures": 0,
  "warnings": 0,
  "sections": [
    { "name": "System", "checks": [ {"status": "ok|warn|fail", "message": "..."} ] }
  ]
}
```

## Dashboard tiles

The webapp dashboard provides at-a-glance system health:

| Tile | Data source |
|------|------------|
| CPU Temperature | `vcgencmd measure_temp` via `psutil` |
| CPU % | `psutil.cpu_percent(interval=0.5)` |
| Memory % | `psutil` |
| Uptime | `psutil.boot_time()` |
| Beaconing Devices | Unique non-FP source IPs in latest report file |
| Suricata Alerts | P1/P2/P3 badge counts from `fast.log` |
| Health | Link → `/health` page |

The header subtitle shows: `bb0 · <date/time> · ethernet: <eth1 IP> · tailscale: <tailscale IP>`.

## Slack alerts

High-score beacons (score ≥ 1.0) trigger a Slack message to `#beacon-butty`.

| Item | Detail |
|------|--------|
| Workspace | `<your-slack-workspace>` |
| Channel | #beacon-butty |
| Token | xoxp- user token at `/var/lib/beaconbutty/slack-config.json` |
| Threshold | Score ≥ 1.0 (intentionally high — see [Alert Tuning](../investigation/alert-tuning.md)) |

## Logs

| Log | Location | Persistence |
|-----|---------|------------|
| Operational logs | `/var/log/beaconbutty/` | log2ram tmpfs — **lost on hard power loss** |
| ClickHouse | `/var/lib/clickhouse/logs/` | NVMe — persistent |
| Suricata | `/var/log/suricata/eve.json`, `fast.log` | log2ram tmpfs — **lost on hard power loss** |
| Suricata archives | `/var/lib/suricata/archive/*.gz` | NVMe — persistent |
| Zeek rotated | `/var/log/zeek/<date>/` | log2ram tmpfs — **lost on hard power loss** |
| Zeek live spool | `/opt/zeek/spool/zeek/` | separate 128M tmpfs — **lost on hard power loss (up to 1h of data)** |
| dnsmasq queries | `/var/log/dnsmasq.log` | log2ram tmpfs — **lost on hard power loss** |
| dnsmasq archives | `/var/lib/beaconbutty/logs/dnsmasq.log.*.gz` | NVMe — persistent |
| Systemd journal | `journalctl` | RAM + journal files |

> [!warning]
> `/var/log/beaconbutty/` lives on log2ram (tmpfs). A hard power loss (pulling the plug) will lose any log entries not yet flushed to NVMe. This is an accepted trade-off for SSD wear reduction.

## Known benign failures

Some units are expected to appear in `systemctl --failed`. Recognise them so you don't chase them:

| Unit | Why it fails | Action |
|------|-------------|--------|
| `NetworkManager-wait-online.service` | Times out at boot waiting for NM `startup-complete` — race with tailscale0/wlan0 coming up async. Drop-in at `/etc/systemd/system/NetworkManager-wait-online.service.d/override.conf` caps it at 30s. At runtime `nm-online -s -q` returns in <100ms, so the failure is cosmetic for downstream units that gate on `network-online.target`. | `systemctl reset-failed NetworkManager-wait-online.service` if it's sticky |
| `rita-analyze.service` | Only when the log shows `all files were previously imported` **and no error** — RITA exits non-zero when a run has nothing new to do. | `systemctl reset-failed rita-analyze.service` |

> [!warning]
> **"Benign" is a conclusion, not a default.** The rita-analyze row above is
> conditional on the last run being error-free, and the health check enforces
> that: it slices the log back to the most recent `=== rita-analyze started:`
> marker and lets a real error outrank the benign message.
>
> This matters because **one run walks every retained Zeek day**. Early
> datasets legitimately log "already imported" while a later one hard-fails, so
> the two messages coexist in the same tail. The original check was a flat
> `tail -30 | grep`, which matched the benign line and reported *"cause is
> benign"* while new-day database creation was failing outright (2026-07-24).
> The check now prints RITA's actual error text instead. Fixed in
> `scripts/healthcheck.sh`; see *Upgrade Log*.

## Post-reboot ownership check

After any reboot that involves `log2ram.service` restarting (kernel upgrade, manual remount), verify that `/var/log/zeek/` and its dated subdirs retain the correct ownership and setgid bit:

```bash
stat -c '%U:%G %A %n' /var/log/zeek /var/log/zeek/$(date +%F)
# expected: root:zeek drwxr-sr-x (the s is the setgid bit)
```

If the parent shows `root:root`, future daily dirs will inherit the wrong group. Fix:

```bash
sudo chgrp -R zeek /var/log/zeek
sudo chmod g+rx /var/log/zeek
sudo chmod g+s /var/log/zeek/*/
```

> [!note]
> The root cause is that after a log2ram tmpfs remount, the mount point is recreated as `root:root` unless the systemd unit or tmpfiles.d enforces otherwise. This bit us on 2026-04-17.

## Useful diagnostic commands

```bash
# Service health
systemctl --failed --no-legend
systemctl status bb-graphs suricata zeek

# Recent errors across all services
journalctl -p err -b --no-pager -n 30

# ClickHouse connectivity
clickhouse-client --query "SELECT 1"

# Zeek is capturing (should see recent timestamps)
ls -lt /opt/zeek/spool/zeek/*.log | head -5

# Disk
df -h /
du -sh /var/lib/clickhouse/data/
df -h /var/log   # log2ram usage (1G — Suricata + Zeek rotated logs + dnsmasq)
```
