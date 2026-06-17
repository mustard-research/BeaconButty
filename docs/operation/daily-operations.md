---
tags: [beaconbutty/operation]
created: 2026-04-16
---

# Daily Operations

BeaconButty is largely autonomous. Most operations are automated via systemd timers. Manual intervention is only needed when alerts fire or when something breaks.

## Automated daily schedule

| Time | Task | Output |
|------|------|--------|
| Continuous | Zeek packet capture | `/var/log/zeek/<date>/` |
| Every hour | RITA imports Zeek logs | ClickHouse updated with latest scores |
| 07:00 | Beacon report generated | `/var/lib/beaconbutty/reports/beacon-report-<date>.txt` |
| 07:00 | Slack alert (if score ≥ 1.0) | `#beacon-butty` in your Slack workspace |
| Daily | Housekeeping | Log rotation, old report cleanup |
| Wed/Sat | GeoIP update | MaxMind GeoLite2 databases refreshed |
| Twice daily | Cert renewal check | Let's Encrypt via certbot |

## Morning review workflow

1. Check Slack `#beacon-butty` for overnight alerts
2. If alerts: open the webapp → **Beacons** page → review Device Hotlist
3. For each flagged device: check score, destination IP/domain, protocol, connection count
4. Cross-reference destination with GeoIP annotation (org, city, country)
5. Decision:
   - **Known device + known/benign destination** → add to false positives (see [False Positive Workflow](../investigation/false-positive-workflow.md))
   - **Known device + unknown destination** → investigate
   - **Unknown device** → identify via Assets page, check MAC vendor
   - **Score ≥ 0.9 + unknown destination + unknown device** → treat as potential incident

## Quick CLI checks

```bash
# Today's beacon summary (human-readable)
beaconbutty-summary.sh

# View today's report directly
cat /var/lib/beaconbutty/reports/beacon-report-$(date +%Y-%m-%d).txt

# Full health check (~10 seconds)
sudo beaconbutty-health.sh

# Check all core services are running
systemctl is-active zeek clickhouse-server dnsmasq bb-graphs suricata

# Check for any failed units
systemctl --failed --no-legend

# Last RITA import
journalctl -u rita-analyze.timer --since "2 hours ago" --no-pager
```

## Weekly checks

- Webapp → Health page: review all service statuses and cert expiry
- Check disk usage: `df -h /` and `du -sh /var/lib/clickhouse/`
- Review Suricata page in the webapp — look for persistent P1/P2 alert patterns
- Consider running a USB clone backup — see [Backup & Recovery](backup-and-recovery.md)

## Investigating a specific device

```bash
# SSH to a LAN host (substitute your device's IP)
ssh user@192.168.50.50

# Check recent Zeek SSL connections from a device
zcat /var/log/zeek/$(date +%Y-%m-%d)/ssl*.gz | grep "192.168.50.50"

# Check DNS queries from a device (today's live log)
grep "192.168.50.50" /var/log/zeek/current/dns.log
```

## False positive management

```bash
# List registered FPs
beaconbutty-fp.sh list

# Add a device
beaconbutty-fp.sh add 192.168.50.50 "Example device — regular telemetry"

# Remove an FP
beaconbutty-fp.sh remove 192.168.50.50
```

See [False Positive Workflow](../investigation/false-positive-workflow.md) for the full assessment process.
