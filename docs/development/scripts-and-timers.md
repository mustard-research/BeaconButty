---
tags: [beaconbutty/development]
created: 2026-04-16
---

# Scripts & Timers

All operational scripts are deployed to `/usr/local/bin/`. Source lives in `scripts/` in the repository. Shared Python modules live in `lib/` and deploy to `/usr/local/lib/beaconbutty/`.

## Shared library — `lib/` (2026-08-14)

Two modules are imported by the webapp *and* by the one-shot scripts, so behaviour cannot drift between the dashboard and the CLI:

| Module | Deployed path | Purpose |
|---|---|---|
| `lib/bb_enrich.py` | `/usr/local/lib/beaconbutty/bb_enrich.py` | 9-tier IP→hostname ladder, `org_label()` display aliases |
| `lib/bb_fp.py` | `/usr/local/lib/beaconbutty/bb_fp.py` | FP-registry `orgs` normalisation and matching |

Consumers resolve them **repo checkout first, then the deployed copy**, so a dev run picks up local edits:

```python
for _p in (str(Path(__file__).resolve().parent.parent / "lib"),
           "/usr/local/lib/beaconbutty"):
    if _p not in sys.path:
        sys.path.append(_p)
import bb_enrich
```

`summarize.sh` is bash wrapping a `python3 - <<'PYEOF'` heredoc, so it has no `__file__` to derive a repo path from; the wrapper exports **`BB_LIB_DIR`** and the heredoc reads that instead.

**Why they exist.** Both replaced logic that had been copied into three or more places. The enrichment ladder existed as a 4-tier version in the webapp, a 2-tier re-implementation in `slow-cadence.py`, and not at all in `summarize.sh`. The org-FP matcher existed in three hand-synchronised copies, each carrying a "change all three together" comment — and two further consumers (`/beacons`, `summarize.sh`) never got a copy at all, so org FPs silently did nothing there. If a contract lives in more than one file it will drift; put it in `lib/`.

## Deployed scripts

Deployment happens via `scripts/05_configure.sh` using `install -m 755`. Repo source is the authoritative copy — always edit the repo and re-deploy, never hand-patch `/usr/local/bin/` (see [Data-path alignment](#data-path-alignment)).

**Three scripts had no install line until 2026-08-14** and were being deployed by hand, so a repo change could sit unshipped indefinitely: `slow-cadence.py`, `slow-cadence-digest.py` and `ip-intel.py`. All three are now installed by `05_configure.sh`. `config/org-aliases.json` is seeded to `/var/lib/beaconbutty/` **only if absent**, since it is hand-edited on the box.

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

## Summary device prints — `LIKELY BENIGN` (rewritten 2026-08-24)

`summarize.sh` labels a source IP by what it talks to: `DEVICE_PRINTS` maps
destination keywords to a device label, and `fingerprint()` returns the first
entry that hits. Display only — it names rows, it never suppresses them — but it
is the line an operator reads as "this is a recognised device", so it is worth
getting right. Three rules, all learned from the same bug:

**1. A print must discriminate.** The first entry was
`(['tailscale.com', 'anthropic.com'], 'The Pi')`, true when the Pi was the only
tailnet node and the only box running Claude Code, and quietly false the day a
second node joined. Four devices ended up labelled "The Pi" — and the Pi itself
never appeared in the table at all, because as the router it is rarely a beacon
*source*. Before adding a print, ask what **else** now produces that signal: a
print earns its place by what it excludes.

**2. Identity prints first, attribute prints last.** `fingerprint()` returns the
first match, so a broad early entry pre-empts every precise one behind it — one
Mac matched five prints and displayed the least informative. "Ubuntu machine"
says what a device **is**; "Device with Signal" says what it happens to **run**.
Anything phrased "device with/running X" belongs at the bottom of the list.

**3. Match whole DNS labels, anchored at the end.** Keywords were matched with a
bare `kw in dest`, which made every short one a liability — `fing.com` matched
`surfing.com`, and `garmin.com` matched an attacker-chosen
`evil-garmin.com.example.net`. `print_match()` now splits both sides on `.` and
compares label runs. Anchoring is at the **end** by default, because an
unanchored label run still accepts `tailscale.com.evil.io`, and prepending a
real domain to one you control is the cheaper forgery of the two.

A keyword that deliberately stops short of a regional TLD says so with a
**trailing dot**, which flips the anchor to the start:

```python
'thumbnails-photos.amazon.'   # .co.uk / .com / .de
'icloud.com'                  # end-anchored: matches mask.icloud.com,
                              # rejects icloud.com.phish.example
```

`_dns_labels()` strips what callers actually pass before splitting: the
` (1.2.3.4)` annotation `annotate_dest` appends, the `:80` RITA leaves on some
FQDNs, and RITA's inconsistent root-anchoring trailing dot. Under substring
matching those three only worked by accident.

> [!note]
> This is a **display heuristic, not authentication**. It stops a domain name
> from claiming to be a recognised device; it does not prove what the device is.
> The same anchoring discipline applies to — but is separate from — the FP
> domain matcher, which has its own apex rule. See
> [False Positive Workflow](../investigation/false-positive-workflow.md#domain-pattern-matching).

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

# Domain / protocol FPs
beaconbutty-fp.sh add-domain '*.example.com' "<reason>"
beaconbutty-fp.sh add-protocol '123:udp:ntp'  "<reason>"

# Organisation FP — fnmatch against the GeoIP ASN owner.
# Scoped to devices by default; --global for LAN-wide (rarely what you want).
beaconbutty-fp.sh add-org '*ExampleCloud*' "<reason>" --device <ip|mac>[,<ip|mac>]
beaconbutty-fp.sh add-org '*ExampleCloud*' "<reason>" --global
beaconbutty-fp.sh remove-org '*ExampleCloud*'
```

Repeat `--device` **unions** the MAC set rather than replacing it; omitting
`--device` on an existing scoped entry widens it back to LAN-wide. Both
transitions print a `Note:` line. `list` shows an indented scope line per org
entry. See
[False Positive Workflow](../investigation/false-positive-workflow.md#device-scoped-org-fps).

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
