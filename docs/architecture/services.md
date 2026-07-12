---
tags: [beaconbutty/architecture]
created: 2026-04-16
---

# Services

All services are managed by systemd. The webapp runs as `bb-graphs.service` — this is a legacy name from when the app was a simple graphs dashboard; it has grown considerably since.

## Core services

| Service | Description | Critical? |
|---------|-------------|-----------|
| `zeek` | Packet capture on eth1 | Yes — core detection |
| `clickhouse-server` | ClickHouse analytical database | Yes — must stop cleanly before reboot |
| `dnsmasq` | DHCP + DNS for the LAN | Yes — LAN would lose connectivity |
| `bb-graphs` | Flask webapp on HTTPS :443 | No — UI only |
| `suricata` | Signature-based IDS | No — supplementary |
| `bb0-display` | OLED status display + Pironman LED control | No |
| `tailscaled` | Tailscale VPN daemon | No — remote access only |
| `NetworkManager` | Manages all interfaces (eth0 bb-wan, eth1 bb-lan, wlan0, tailscale0) | Yes — LAN/WAN both go through NM |
| `log2ram` | Mounts `/var/log` as a 1G tmpfs; one-shot at boot | Yes — without it `/var/log` is empty on the NVMe mount point |
| `bb-watchdog` | Thermal & health watchdog: 60 s telemetry (temp, CPU, memory, top consumers → daily JSON), Pironman fan hysteresis, LED health signal, 30-min health checks | No — telemetry, fan control and LED signal degrade |
| `news-digest` | Daily news-digest email (ancillary, not BB) — see *News Digest* | No |

> [!warning]
> **Never stop `bb0-display.service`** to blank the display. Stopping the service clears the LED strip and shows a "REBOOTING" message on the OLED. Use the flag file toggle instead — see [OLED Display](../hardware/oled-display.md).

> [!warning]
> **Flask caches templates in production mode.** Always `sudo systemctl restart bb-graphs` after editing any file in `webapp/templates/`.

> [!note]
> **Zeek `ClusterBackend` is on the Broker fallback, not the 8.1 default ZeroMQ.** When Zeek 8.1 landed (2026-05-13) the package default flipped to ZeroMQ, which needs `UseWebSocket = 1`. We kept `UseWebSocket = 0` in `/opt/zeek/etc/zeekctl.cfg` because Debian Bookworm's `python3-websockets` is too old. `zeekctl status` will keep showing a cosmetic ZeroMQ warning until that's resolved — see the [main index](../index.md) for the pending decision and [Troubleshooting](../operation/troubleshooting.md) for what the warning means.

## Systemd timers

The full list of timers (BeaconButty + system) is maintained in [Scripts & Timers](../development/scripts-and-timers.md). The ones most critical to the detection pipeline:

- `rita-analyze.timer` — hourly, drives Zeek → ClickHouse ingestion
- `beacon-report.timer` — daily 07:00, generates the report and sends the Slack alert
- `beaconbutty-health.timer` — daily 09:30, full system health sweep
- `log2ram-daily.timer` — daily 23:55, syncs the `/var/log` tmpfs back to NVMe
- `news-digest.timer` — daily 03:00, runs the ancillary news-digest email service

## Checking service status

```bash
# All core services at once
systemctl is-active zeek clickhouse-server dnsmasq bb-graphs suricata bb0-display

# Any failed units
systemctl --failed --no-legend

# Full health check (recommended)
sudo beaconbutty-health.sh

# Individual service status
systemctl status <service-name>

# Follow a service's logs
journalctl -fu <service-name>
```

## Service dependencies and startup order

On boot, systemd starts services in dependency order. ClickHouse must be running before RITA can import, and RITA results must be in ClickHouse before the webapp can show network intelligence data. In practice, `rita-analyze.timer` fires after the first full hour, so there is up to an hour of latency after a reboot before new data appears.

## HTTPS and certificate

`bb-graphs.service` serves on port 443 using a Let's Encrypt certificate obtained via Route 53 DNS challenge. The certbot IAM user has Route 53 permissions scoped to the BeaconButty domain. The deploy hook on renewal restarts `bb-graphs.service`.

See [Backup & Recovery](../operation/backup-and-recovery.md) for details on the certificate and DR.
