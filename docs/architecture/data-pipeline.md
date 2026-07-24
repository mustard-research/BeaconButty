---
tags: [beaconbutty/architecture]
created: 2026-04-16
---

# Data Pipeline

The full pipeline from raw packets to Slack alert runs continuously and automatically.

## Pipeline diagram

```
eth1 (all LAN ↔ internet traffic)
    │
    ▼
┌─────────────────────────────────────────┐
│  Zeek 8 — continuous packet capture     │
│  Writes hourly log files:               │
│    /var/log/zeek/<YYYY-MM-DD>/          │
│    conn.log, ssl.log, dns.log,          │
│    http.log, known_hosts.log, etc.      │
└─────────────────┬───────────────────────┘
                  │ every hour (systemd timer)
                  ▼
┌─────────────────────────────────────────┐
│  rita-analyze.sh                        │
│  cd /etc/rita && rita import            │
│    <log-dir> <dataset>                  │
│  Imports completed hourly log dirs      │
│  into ClickHouse                        │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│  ClickHouse                             │
│  RITA beacon scores, connection stats   │
│  14-day TTL on system log tables        │
└──────┬──────────────────────────────────┘
       │                    │
       │ daily 07:00        │ on-demand
       ▼                    ▼
┌────────────────┐   ┌──────────────────────┐
│ beacon-report  │   │  Flask webapp        │
│ .sh            │   │  Reads reports +     │
│ Writes report  │   │  queries ClickHouse  │
│ Sends Slack    │   │  directly            │
│ alert          │   └──────────────────────┘
└────────────────┘
```

## Zeek log format

Zeek writes tab-separated log files. Key logs used by BeaconButty:

| Log | Contents |
|-----|---------|
| `conn.log` | All connection records (src, dst, port, bytes, duration) |
| `ssl.log` | TLS handshake metadata (SNI, JA3, cipher, key exchange) |
| `dns.log` | DNS query/response records |
| `http.log` | HTTP requests (host, URI, user-agent) |
| `known_hosts.log` | Observed LAN hosts (used for asset cache) |

Logs are rotated hourly into dated directories: `/var/log/zeek/YYYY-MM-DD/` (log2ram, 7-day retention).
Live (current hour) logs are in `/opt/zeek/spool/zeek/` which is its own 128M tmpfs (symlinked as `/var/log/zeek/current/`). State and zeekctl metadata in the parent `/opt/zeek/spool/` remain on NVMe.

## RITA import

RITA must run from `/etc/rita/` — it reads its `.env` file (ClickHouse credentials) from the current working directory.

```bash
cd /etc/rita && rita import <log-directory> <dataset-name>
```

The dataset name conventionally matches the date of the logs. RITA parses the Zeek conn.log and related files to compute beacon scores for each (source IP, destination IP) pair.

> [!important]
> RITA CLI output must be parsed with `grep -oP`, not naive field splitting — the output format uses variable whitespace.

## ClickHouse

RITA writes its results into ClickHouse (local socket connection). Key characteristics:

- Column-store database — very fast for analytical queries over millions of rows
- **One database per day**, `beaconbutty_YYYYMMDD` — so RITA issues a fresh round of `CREATE TABLE` at every midnight rollover, not just on first install. Anything that changes how ClickHouse validates schemas therefore surfaces at 00:0x, hours after the change that caused it (see *Troubleshooting*)
- System log tables have a **14-day TTL** configured via `/etc/clickhouse-server/config.d/system-log-ttl.xml`
- RITA's aggregating tables (`uconn`, `usni`, `exploded_dns`, `port_info`, `rare_signatures`, `tls_proto`, `http_proto`, `mime_type_uris`, `dns_tmp`) carry dimension columns outside their sorting key, which ClickHouse 26.7+ rejects by default. `/etc/clickhouse-server/config.d/merge-tree-compat.xml` enables `allow_dimensions_outside_sorting_key` to permit it
- ClickHouse **must be stopped cleanly before OS reboot** — if the kernel reboot fires while ClickHouse is running, the hardware watchdog can loop and the system hangs indefinitely

See [Reboot Procedure](../operation/reboot-procedure.md) for how this is handled.

## Report generation

`beacon-report.sh` runs at 07:00 daily. It:

1. Queries the **last 3 RITA daily databases** and prints each as its own dated section into a single file
2. Filters out false positives and safe destinations
3. Writes a text report to `/var/lib/beaconbutty/reports/beacon-report-<date>.txt`
4. If any beacons score ≥ 1.0, sends a Slack message to `#beacon-butty`

> [!warning] Each report file bundles 3 days, so a persistent beacon appears as one CSV row **per day**. Any consumer that counts rows (rather than distinct `(src, dst, fqdn)` beacons) inflates its counts — `get_beacon_data`, `summarize.sh` and `build_new_beacons` all dedup. See [Webapp](../development/webapp.md).

## Webapp data access

The Flask webapp reads beacon data two ways:

- **Report files** — parsed from `/var/lib/beaconbutty/reports/` for the Beacons page
- **Direct ClickHouse queries** — for network intelligence (DNS entropy, connection counts) on the Network page

## Key paths

| Path | Contents |
|------|---------|
| `/var/log/zeek/` | Zeek rotated daily directories (log2ram, 7d) |
| `/opt/zeek/spool/zeek/` | Live Zeek log writes (own 128M tmpfs; symlinked as `/var/log/zeek/current/`) |
| `/opt/zeek/spool/` | Zeek state.db + zeekctl metadata (NVMe, parent of above) |
| `/etc/rita/config.hjson` | RITA configuration |
| `/etc/rita/.env` | RITA ClickHouse credentials |
| `/var/lib/beaconbutty/reports/` | Beacon report text files |
| `/var/lib/beaconbutty/false-positives.conf` | FP registry |
| `/var/lib/beaconbutty/assets.json` | LAN asset cache |
| `/var/log/dnsmasq.log` | dnsmasq DNS query log (log2ram — lost on hard power loss) |
| `/var/lib/beaconbutty/logs/` | Rotated dnsmasq .gz archives (NVMe — persistent) |
| `/var/log/beaconbutty/` | Operational logs (log2ram — lost on hard power loss) |
| `/var/lib/clickhouse/logs/` | ClickHouse logs (NVMe — persistent) |

> [!warning]
> `/var/log` is a 1G log2ram tmpfs, synced to NVMe once daily at 23:55. Do not write large or database-critical data here — use `/var/lib/beaconbutty/` or `/var/lib/clickhouse/` instead.
