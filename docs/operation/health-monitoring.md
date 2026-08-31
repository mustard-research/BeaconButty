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
| System | uptime, memory, disk, load, CPU temp, throttling history (`vcgencmd get_throttled`), **log2ram tmpfs %** (2026-08-28: now reads `PATH_DISK` from `/etc/log2ram.conf` and reports each mounted path — it previously guarded on `mountpoint -q /var/log`, which made the whole check a silent no-op once `/var/log` stopped being a mount), **journal persistence** (FAILs if effective `Storage=` is not `persistent`), **Sustained-high CPU** (rolling 60-min mean reported by bb-watchdog — `ELEVATED` when ≥60%, `normal` otherwise; alert + diagnostic snapshot at `/var/lib/beaconbutty/watchdog/high-cpu-events/<UTC-ts>.json` — see *Upgrade Log*), time sync (`timedatectl`), pending reboot |
| Network Interfaces | eth0/eth1 link + IP, WAN reachability (ping 1.1.1.1) |
| Routing & Firewall | IP forwarding, NAT MASQUERADE, FORWARD rule, IPv4/IPv6 INPUT=DROP, external DNS resolution (flags Tailscale-only resolver), **SSH peer allowlist** (systemd `IPAddressDeny=any`) and **webapp ingress allowlist** (the `_restrict_to_local_networks` guard in `app.py`) — both are second-layer controls that would otherwise vanish silently, leaving iptables as the only thing keeping a public-IP box's unauthenticated console off the internet |
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

## ISP outage tracking (added 2026-08-30)

`wan-watchdog.sh` has always logged WAN losses and recoveries, but nothing aggregated them — `/health` showed only the latest reading, and logrotate keeps just 8 weeks of `watchdog.log`, so "how much downtime this year" was unanswerable.

### Where it surfaces

| Surface | What you get |
|---|---|
| `/health` → WAN / ISP card | A one-line summary that is **always a link**, even at zero outages ("No ISP outages today · N recorded since YYYY-MM-DD"). Clicking opens the full history grouped by day, with per-day totals and a rolling 30-day figure. |
| `beaconbutty-health.sh` → Network Interfaces | The same one-liner as an informational `OK` row. |
| `bb_outages.py` CLI | `--line` (one-liner), `--json` (full history), `--persist` (merge into the durable store). |

Deliberately `OK`, never `WARN`: an ISP outage is not a bb0 fault and nothing here can action it, so a warning would sit amber all day and train the eye to skip the section — the same reasoning as the starved-frames delta. An outage happening *now* still surfaces as the existing WAN-unreachable `FAIL`.

### How the record survives its source log

`lib/bb_outages.py` collapses the log lines into discrete outages and merges them into `/var/lib/beaconbutty/outage-history.json`, keyed on outage start so re-parsing is idempotent. Daily housekeeping calls `--persist`; the webapp **never writes** — it unions the stored history with a fresh in-memory parse, so today's outages appear without waiting for housekeeping, and root's write can never race the webapp's read.

### Evidence-based classification

`lib/bb_wan_diag.py` runs on every failing check. **ARP is the discriminator**: it sits below IP, so it answers from a router that is on the wire but refusing to forward — the one thing a ping cannot tell you.

| Evidence | Class | Means |
|---|---|---|
| carrier down | `link_down` | our link or the CPE — go and look at it |
| gateway silent to ARP, access gear provably alive | `gateway_vip_unclaimed` | the gateway *address* is unclaimed while the ISP's kit is up — **not** an access outage |
| gateway silent to ARP, segment silent too | `access_segment_down` | no foreign broadcast either — we are isolated at layer 2 |
| gateway silent to ARP, no witness yet | `gateway_absent` | nothing claims the gateway address; cause not narrowed |
| answers ARP, not ICMP | `gateway_silent` | edge present, not handling our traffic |
| answers both | `upstream_transit` | break is beyond the edge; traceroute names the last live hop |

It uses `arping`, **not** `ip neigh`: the neighbour cache holds a `REACHABLE` entry for minutes after a router disappears, so reading it would report the gateway present throughout the very outage being diagnosed. A cache is evidence about the past, not the present.

#### Two witnesses that ARP silence alone cannot supply (2026-08-31)

ARP silence was doing two jobs: it fires both when the ISP's edge is genuinely gone and when the edge is up while its virtual address goes unclaimed. Those need different conversations with the ISP, so two independent witnesses now separate them. Either one alone is sufficient.

**1. A DHCP lease issued *during* the outage.** Derived as `expiry − lease_time` from `nmcli` — the DHCP client is never invoked, because doing that behind NetworkManager's back is what caused the 2026-07-01 resolver incident. On 2026-08-31 a DHCPACK landed at **09:56:50, four minutes into a total blackout**, from a gateway that ignored ARP throughout. Equipment that is off the wire cannot serve DHCP, so the verdict "the edge router is off the wire" was false as written.

**2. Foreign broadcast still arriving**, counted for free by `ethtool -S eth0 → rx_broadcast_frames`. The ISP's access gear beacons a proprietary frame (`aa:bb:cc:dd:ee:e1`, a vendor OUI distinct from anything on our LAN, ethertype `0x9998`) about every five seconds, so the counter climbing proves the segment is live regardless of whether anything answers us at IP. This is deliberately **not** keyed on that MAC or ethertype — pin the probe to today's fingerprint and it silently reports "segment dead" for ever after a kit swap.

Both are **one-way**: they may only ever upgrade a verdict, never downgrade one. Their absence proves nothing — renewals are ~52 minutes apart, and the first check of an outage has no earlier counter to difference against — so the fallback says the cause was not narrowed rather than guessing.

> [!note] VRRP advertisements are not observable, and this is settled
> The obvious probe here would be to watch for VRRP adverts and see whether a master exists. The ISP filters IP protocol 112 from the customer port: tested 2026-08-31 with a six-second listen, zero packets. Do not spend the run's time budget retrying it.

Both new probes are local reads costing ~20 ms in total, so they run on **every** sample rather than once per outage. That placement is the point: the DHCP renewal that disproved the old verdict was the *fifth* check of the outage, and a first-check-only probe would have missed it in both of that day's outages.

Per-outage evidence — carrier and `carrier_changes`, gateway ARP with MAC, gateway ICMP, per-host external ICMP, traceroute hops, DHCP lease/device state **and derived issue time**, **interface counters (`rx_broadcast_frames`, rx/tx packets)**, **conntrack and throttling state**, Tailscale backend — lands in `/var/lib/beaconbutty/outage-evidence/<start>.json` and renders as a sub-row under its outage. Files are pruned at 365 days by housekeeping; both the history and the evidence are in the config backup.

> [!warning]
> **The pre-2026-08-30 classifier was measurably wrong, and its rows are relabelled "cause not established" rather than replayed.** It split outages on one bit — did the gateway answer ICMP — which cannot tell an *absent* router from a *blackholing* one. It called five outages a "link/CPE fault" when every one had an unbroken carrier, a metronomic lease and a device that never left `activated`; meanwhile the single genuine 4-second link drop fell between two probes and was never recorded at all. Do not reinstate a cause the probe cannot establish.

> [!warning]
> **The 2026-08-30 generation overclaimed in its turn.** Its `gateway_absent` verdict asserted "the edge router is off the wire" — a physical state ARP silence cannot establish, and one the box's own journal disproved the next day. When a classifier asserts a physical state, ask what *else* would have to be silent if it were true, then check that it actually was.

### Resolution, and its limits

The check runs **every minute** (5-minutely before 2026-08-30) and a failing check escalates to **10-second** probing until recovery or `RUN_DEADLINE_SECS`.

| Quantity | Bounded by | Now |
|---|---|---|
| Recovery time | escalation loop | ±10 s while the loop runs, ~60 s between ticks |
| **Onset time** | **base cadence only** | **±1 min** |
| Duration | both of the above | reported as a measured span plus an "at most" bracket |

Onset is the half no escalation can fix: by the time a check fails, the moment it went down has already passed. It is instead **bracketed** from the last healthy run's `checked_at` in `wan-status.json`, and each row shows "began between X and Y — at most Z".

> [!note]
> The history spans **two sampling resolutions**. Rows with an evidence sub-row were measured under the current regime and carry a real onset bracket; older rows were sampled 5-minutely and are good only to ±5 min. The panel says so per-row — never quote a single accuracy figure for the whole table.

### Invariants worth not breaking

- **`FAIL_THRESHOLD` is derived, never hard-coded.** It gates the NetworkManager re-apply and the DNS `service_down` alert, and both mean *"broken for a quarter of an hour"*. As the bare count `3` it would have silently become 3 minutes the instant the cadence changed. It is now `FAIL_AFTER_SECS / CHECK_INTERVAL_SECS`, with `CHECK_INTERVAL_SECS` passed from the service unit and single-sourced from the timer — 15 minutes at any cadence. **Retune the timer and retune that `Environment=` line with it.**
- **`RUN_DEADLINE_SECS` (45 s) must stay below `CHECK_INTERVAL_SECS`.** Overlapping runs make systemd skip ticks, which stops the failure count advancing once per tick and breaks the arithmetic above. It also bounds the *whole run*, not just the loop — the diagnostic burst before it is variable, and a ceiling measured from the end of the burst leaves total runtime one slow traceroute away from a `SIGTERM` at `TimeoutStartSec`.
- **The DNS tripwire holds its counter while the WAN is unreachable.** A lookup cannot succeed there, so it used to count a guaranteed failure every check and eventually fire *"DNS resolution failing — check resolv.conf nameservers"* in the middle of an ISP outage, pointing the reader at the resolver. It has no signal to offer with the WAN down, so it abstains.

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
