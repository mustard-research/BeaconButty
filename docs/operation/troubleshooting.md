---
tags: [beaconbutty/operation]
created: 2026-04-17
---

# Troubleshooting

"When X breaks → do Y." Start with the Health page (`/health` or `sudo beaconbutty-health.sh`) — it catches most of these automatically. Fall back to this page when the health check points at a symptom but not a fix.

## First move, always

```bash
# Fastest signal: any failed units?
systemctl --failed --no-legend

# Full sweep, ~10 seconds
sudo beaconbutty-health.sh

# Recent errors across the system
sudo journalctl -p err -b --no-pager -n 50
```

## Zeek

### Zeek is "running" but no new log data

Symptom: `beaconbutty-health.sh` → "Zeek Logging: capture rate = 0 conn rows in last 5 min."

```bash
# Is the process actually on the wire?
ps -ef | grep '[z]eek'
sudo zeekctl status

# Live log files should be updating every second
ls -lt /opt/zeek/spool/zeek/*.log | head -5

# Interface plumbed?
ip -br link show eth1
sudo tcpdump -i eth1 -c 5 -nn
```

**Common causes**: eth1 cable/USB dongle reseat, zeek crashed silently (systemd reports active until it tries to restart), or capture buffer full after a traffic spike.

**Fix**: `sudo zeekctl deploy` (re-applies config + restarts cleanly).

### Zeek dir ownership drift after reboot

After log2ram remount, `/var/log/zeek/` may come back as `root:root` instead of `root:zeek`. New daily dirs inherit the wrong ownership and the setgid bit is missing. See [Health Monitoring](health-monitoring.md).

### Orphan daily dirs accumulating

`zeekctl cron` in root's crontab enforces `LogExpireInterval=168h` (7 days). If it's not scheduled, daily dirs grow without bound.

```bash
sudo crontab -l | grep zeekctl
# Expected: */5 * * * * /opt/zeek/bin/zeekctl cron
```

### Harmless warnings on `zeekctl status` / `deploy`

Two recurring warnings are **cosmetic** and not signs of a problem. Don't try to fix them blindly — both are documented choices.

**`Warning: zeekctl netstats and print commands with cluster backend 'ZeroMQ' require UseWebSocket = 1`**

Appears on every `zeekctl status` since the 2026-05-13 Zeek 8.1 upgrade. Background: 8.1 made ZeroMQ the default `ClusterBackend`, which requires `UseWebSocket = 1`. We kept `UseWebSocket = 0` because Debian Bookworm's `python3-websockets` is too old (10.x; need ≥12). Zeek currently runs on Broker fallback, which still works fine. The two affected commands (`zeekctl netstats`, `zeekctl print`) aren't used routinely — capture and rotation are unaffected. Long-term decision (pin Broker vs. upgrade websockets + flip ZeroMQ) is tracked in the [main index](../index.md).

**`Error: error running post-terminate for zeek: mv: cannot move '/opt/zeek/spool/zeek' … : Device or resource busy`**

Appears at the start of every `zeekctl deploy`. `/opt/zeek/spool/zeek` is its own 128 MB tmpfs (intentional, to spare NVMe wear), so zeekctl's post-terminate cross-filesystem `mv` can't work. Deploy still completes successfully — policies install, Zeek restarts, capture resumes. Only effect: forensic state from that one deploy cycle isn't preserved in the post-terminate stash. **Don't remove the tmpfs** to "fix" it.

To verify a deploy really succeeded despite the warnings:

```bash
sudo zeekctl status   # PID should be fresh
stat -c '%y %s' /opt/zeek/logs/current/conn.log   # mtime should be recent and size > 0
```

## RITA

### RITA import failing or empty

```bash
# Run from /etc/rita/ — needs .env in CWD
cd /etc/rita && rita list
cd /etc/rita && rita import /var/log/zeek/<YYYY-MM-DD>/ test-dataset
```

**Gotcha**: running `rita` from any other directory fails with a cryptic ClickHouse connection error — it cannot find `.env`. Always `cd /etc/rita` first.

### RITA timer stopped firing

```bash
systemctl status rita-analyze.timer rita-analyze.service
journalctl -u rita-analyze.service --since "24 hours ago" --no-pager
```

If the timer is `active (waiting)` but there's no recent service invocation, check `OnCalendar` in the unit. Manual kick: `sudo systemctl start rita-analyze.service`.

### RITA running but not completing (memory limit)

```bash
# The "RITA last successful import" health-check entry is the first sign.
# Confirm with:
grep "memory limit exceeded" /var/log/beaconbutty/analyze.log | tail -5
clickhouse-client --query "SELECT value FROM system.server_settings WHERE name='max_server_memory_usage'"
```

If you see `code: 241, message: (total) memory limit exceeded`, the explicit `max_server_memory_usage` cap is too low for the cumulative dataset. Bump it in `/etc/clickhouse-server/config.d/memory.xml` (NOT the main `config.xml` — that's a dpkg conffile and can be touched on package upgrades):

```xml
<?xml version="1.0"?>
<clickhouse>
    <max_server_memory_usage replace="replace">5368709120</max_server_memory_usage>
</clickhouse>
```

Restart ClickHouse, re-run `sudo /usr/local/bin/rita-analyze.sh` to backfill. Root-cause history in *Upgrade Log*.

## ClickHouse

### ClickHouse won't start

```bash
sudo systemctl status clickhouse-server
sudo journalctl -u clickhouse-server --since "1 hour ago" --no-pager -n 100
```

Common causes:
- **Unclean shutdown** after watchdog reboot — check for `.broken` parts in `/var/lib/clickhouse/store/`. CH usually recovers automatically but may take a minute.
- **Disk full** on `/` — `df -h /`. Truncate `/var/lib/clickhouse/logs/` or enforce the system-log TTL.
- **Config parse error** from a recent edit to `config.d/` — `clickhouse-server --check-config`.

### ClickHouse query probe fails in health check

```bash
clickhouse-client --query "SELECT 1"
# If this hangs or errors, the server is wedged. Two common causes:

# 1. Memory limit reached (OvercommitTracker kills even SELECT 1).
#    Check current limit vs actual RSS:
clickhouse-client --query "SELECT value FROM system.server_settings WHERE name='max_server_memory_usage'"
ps -p $(pidof clickhouse-server) -o rss=  # in KB

# 2. Server genuinely hung:
sudo systemctl restart clickhouse-server
```

### Upgrading ClickHouse

Don't `apt upgrade` ClickHouse by hand. Use the wrapper:

```bash
sudo beaconbutty-clickhouse-upgrade.sh        # interactive
sudo beaconbutty-clickhouse-upgrade.sh --yes  # skip confirmation
```

It preflights (health check green, no in-flight RITA import, disk free), snapshots `/etc/clickhouse-server/` to `/var/lib/beaconbutty/ch-upgrade/<UTC-ts>/`, pauses the RITA timer, runs `apt-get install` with `--force-confold`, then verifies: config.d/ overrides untouched, SELECT 1 responds, `max_server_memory_usage` and dataset count unchanged, and one full rita-analyze cycle produces a fresh `=== done:` marker. **Stops on any verify failure** — no auto-rollback (ClickHouse storage formats may not downgrade cleanly). On stop, the snapshot dir is your recovery starting point.

### ClickHouse config.d overrides missing after package upgrade

This shouldn't happen if you use the wrapper above — it verifies each override against its pre-upgrade snapshot. The 2026-05-13 upgrade (pre-wrapper) silently shipped without `config.d/logs.xml` (logs → log2ram) and a working `max_server_memory_usage` (3 GiB default cap, too low). Manual recovery if you somehow end up there:

```bash
# After the upgrade, verify both overrides survive:
ls /etc/clickhouse-server/config.d/{logs,memory,system-log-ttl}.xml

# If logs.xml is gone, ClickHouse will write 200 MB/day to /var/log (log2ram) — re-create:
sudo tee /etc/clickhouse-server/config.d/logs.xml >/dev/null <<'EOF'
<?xml version="1.0"?>
<clickhouse>
    <logger>
        <log>/var/lib/clickhouse/logs/clickhouse-server.log</log>
        <errorlog>/var/lib/clickhouse/logs/clickhouse-server.err.log</errorlog>
    </logger>
</clickhouse>
EOF
sudo chown clickhouse:clickhouse /etc/clickhouse-server/config.d/logs.xml
sudo mkdir -p /var/lib/clickhouse/logs && sudo chown clickhouse:clickhouse /var/lib/clickhouse/logs
sudo systemctl restart clickhouse-server
```

Re-hold once verified: `sudo apt-mark hold clickhouse-server clickhouse-client clickhouse-common-static`.

### System log tables growing forever

The 14-day TTL is in `/etc/clickhouse-server/config.d/system-log-ttl.xml`. Confirm it's loaded:

```bash
clickhouse-client --query "SHOW CREATE TABLE system.query_log FORMAT Raw" | grep -i ttl
```

## Suricata

### `fast.log` stopped updating

```bash
sudo systemctl status suricata
sudo tail -f /var/log/suricata/fast.log
```

**If suricata is running but quiet**: rule update failed. Rule file age is in the health check.

```bash
sudo suricata-update
sudo systemctl reload suricata   # or restart if reload fails
```

### Too many P3/P4 alerts

These are hidden by default on the Suricata page. If they leak into P1/P2 counts, the ruleset or classification changed after an update. Review `/var/log/suricata/fast.log` for the noisy signature and disable via `/etc/suricata/disable.conf`, then `sudo suricata-update && sudo systemctl reload suricata`.

## dnsmasq

### LAN devices lose network / can't resolve

```bash
sudo systemctl status dnsmasq
sudo journalctl -u dnsmasq --since "30 min ago" --no-pager

# Upstream resolvers reachable?
dig @1.1.1.1 example.com +short
dig @8.8.8.8 example.com +short

# Live lease file
sudo cat /var/lib/misc/dnsmasq.leases
```

**LAN outage** is by definition critical — dnsmasq is the DHCP server for the whole network. If the daemon is crashed, restart immediately: `sudo systemctl restart dnsmasq`.

### dnsmasq fails to start after a reboot

If `systemctl status dnsmasq` shows the `ExecStartPre=/usr/share/dnsmasq/systemd-helper checkconfig` step exited non-zero, the config in `/etc/dnsmasq.d/` no longer parses. The fastest fingerprint:

```bash
sudo journalctl -u dnsmasq --no-pager -n 20 | grep -iE 'duplicate|invalid|FAILED to start'
```

A message like `duplicate dhcp-host IP address 192.168.50.137 at line 16 of /etc/dnsmasq.d/<file>` almost always means a stray `.bak`, `.old`, or dated copy is being parsed alongside the live file. See *Glob-Parsed Config Directories* for the full mechanism. Quick fix:

```bash
sudo mkdir -p /var/backups/dnsmasq
sudo mv /etc/dnsmasq.d/*.bak* /etc/dnsmasq.d/*.old /var/backups/dnsmasq/ 2>/dev/null || true
sudo /usr/share/dnsmasq/systemd-helper checkconfig   # must print nothing and exit 0
sudo systemctl start dnsmasq
```

Then validate that bb-watchdog re-greens the case LEDs: `sudo bb-watchdog status`.

### `/etc/resolv.conf` broken on the Pi itself

`harden.sh` catches this indirectly via `getent hosts deb.debian.org`. Recovery:

```bash
sudo unlink /etc/resolv.conf
printf 'nameserver 1.1.1.1\n' | sudo tee /etc/resolv.conf
```

## Tailscale

### Remote access gone

```bash
sudo tailscale status
sudo tailscale up --reset   # re-authenticate if needed
sudo systemctl status tailscaled
```

**Firewall check**: `sudo iptables -L INPUT -n | grep tailscale` — the ACCEPT rule on `tailscale0` must be in place (re-run `harden.sh` if missing). UDP/41641 on eth0 likewise.

## Webapp (`bb-graphs`)

### 502 / can't reach HTTPS

```bash
sudo systemctl status bb-graphs
sudo journalctl -u bb-graphs --since "10 min ago" --no-pager -n 50
```

**Template changes not appearing**: Flask caches templates in production — always `sudo systemctl restart bb-graphs` after editing `webapp/templates/`.

**TLS cert permissions**: if the service fails to start right after a renewal, check privkey perms (see [Backup & Recovery](backup-and-recovery.md)).

### `_NETWORK_CACHE` stale after FP change

CLI writes to `/var/lib/beaconbutty/false-positives.conf` don't bust the cache. Either wait for it to expire or `sudo systemctl restart bb-graphs`. Webapp-initiated FP changes bust the cache automatically.

## log2ram

### `/var/log` filling up

```bash
df -h /var/log
du -sh /var/log/* 2>/dev/null | sort -rh | head
```

Normal working set is ~400–500 MB. If over 800 MB, likely a log loop or rotation not firing. Check which logrotate config is in play (`/etc/logrotate.d/`). Force a rotation for Suricata: `sudo logrotate -f /etc/logrotate.d/suricata`.

Trim dnsmasq live log: `sudo truncate -s 0 /var/log/dnsmasq.log && sudo systemctl restart dnsmasq`.

### Nightly sync skipped

```bash
systemctl status log2ram-daily.timer log2ram-daily.service
sudo journalctl -u log2ram-daily.service --since "2 days ago" --no-pager
```

## SSH lockout

If `harden.sh` disabled passwords and your key doesn't work:

1. Physical console access: TV + keyboard on the HDMI + USB ports.
2. Log in as `dm`.
3. Remove or edit `/etc/ssh/sshd_config.d/99-beaconbutty-hardening.conf`.
4. `sudo systemctl reload sshd`.
5. Install your key, re-run `harden.sh`.

## fail2ban over-banned your own IP

```bash
sudo fail2ban-client status sshd
sudo fail2ban-client unban <your-ip>
```

If you want your subnet permanently exempt, add it to `ignoreip` in `/etc/fail2ban/jail.d/beaconbutty-ssh.conf` (the default already exempts `192.168.50.0/24`).

## Reboot hangs

Covered in [Reboot Procedure](reboot-procedure.md). Summary: the wrapper at `/usr/local/sbin/reboot` pre-stops ClickHouse. If a raw `/usr/sbin/reboot` was used and the system hung, force a power cycle; recovery is clean because of the 14-day TTL and log2ram nightly sync.

## WAN outage

`bb-watchdog` auto-recovers most ISP blips — see `scripts/wan-watchdog.sh`. Manual override:

```bash
# Drop + renew DHCP on eth0
sudo ip link set eth0 down
sudo ip link set eth0 up
sudo dhclient -r eth0 && sudo dhclient eth0

# Or via NetworkManager (bb-wan connection)
sudo nmcli connection down bb-wan && sudo nmcli connection up bb-wan
```

## Backup clone failing

See [Backup & Recovery](backup-and-recovery.md) — common causes: wrong device selected (not `sda`), USB enclosure not spun up, `rpi-clone` already running (check `pgrep rpi-clone`).

## See also

- [Health Monitoring](health-monitoring.md) — `beaconbutty-health.sh` catches most of these pre-emptively
- [Reboot Procedure](reboot-procedure.md) — watchdog hang prevention
- [Hardening](../security/hardening.md) — SSH / fail2ban / firewall
- *Upgrade Log* — known issues introduced by past upgrades
