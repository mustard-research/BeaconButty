# BeaconButty — Disaster Recovery & Restore Guide

This document lives in the git repo so it's available on GitHub even if bb0 is dead.

---

## What you have to work with

### Config snapshot (`config-YYYY-MM-DD.tar.gz`)
Daily automated snapshots (02:00) stored in `/var/lib/beaconbutty/backups/`, last 14 kept (~2 weeks).
Download from the **Backup** page of the webapp while the Pi is still running.
Also download the matching `packages-YYYY-MM-DD.txt` file.

**Included in snapshot:**
- All BeaconButty scripts (`/usr/local/bin/beaconbutty-*.sh`, `beacon-report.sh`, `rita-analyze.sh`, etc.)
- All systemd units and timers
- Full webapp source (`/home/dm/BeaconButty/`)
- Network config: NetworkManager profiles (eth0 WAN / eth1 LAN), dnsmasq, iptables rules, sysctl tweaks, promiscuous-mode interface hooks
- App config: RITA (`/etc/rita/`), Suricata, ClickHouse log path override, Zeek site policy
- False positive registry, asset cache, Slack config
- SSH server config, fail2ban, sudoers entries, log2ram config
- Boot firmware config (`/boot/firmware/config.txt`, `cmdline.txt`)
- certbot renewal config, ACME account, deploy hook, AWS credentials for Route 53

**NOT included — needs separate action:**
| Item | Action |
|------|--------|
| ClickHouse beacon data | Lost unless USB clone. Fresh install collects new data immediately. |
| TLS certificate files | Re-issue via `certbot` after restore — renewal config and AWS credentials are in the snapshot so this is a one-liner (see post-restore steps) |
| Tailscale auth | Re-auth with `sudo tailscale up` |
| SSH host keys | Regenerated automatically on first boot — update `~/.ssh/known_hosts` on client machines |

### Full archive (`archive-YYYY-MM-DD.tar.gz`)
Weekly automated snapshot (Sunday 03:00) plus on-demand from the Backup page. A compressed tarball of the whole rootfs + `/boot/firmware` + `/var/log` (log2ram), ~10 GB. Last 4 kept. Captures **ClickHouse history**, Zeek/Suricata logs, and everything a config snapshot has, but is **not bootable** — you restore by extracting it over a fresh Pi OS Lite install (see Option B).

### Full-disk USB clone
Made via rpi-clone from the Backup page. The USB drive is itself a bootable Pi OS — you can boot directly from it and use it as a live system or clone it back to a new NVMe. Includes ClickHouse history.

---

## Option A — Config snapshot restore

**When to use:** Pi hardware is intact but OS is corrupted, or migrating to a new Pi where you don't need to preserve historical beacon data.

### Step 1 — Flash fresh OS

1. Download **Raspberry Pi OS Lite (64-bit)** (no desktop) from raspberrypi.com.
2. Flash it to a new NVMe using Raspberry Pi Imager.
   - In Imager's OS customisation: set hostname (e.g. `bb0`), username (e.g. `dm`), enable SSH with your public key.
3. Boot the Pi and SSH in. (The example values in this guide use hostname `bb0` and user `dm` — adjust to your site.)

### Step 2 — Get basic network access

The full network config (NetworkManager profiles, promiscuous-mode hooks, iptables, sysctl) is in the snapshot and will be restored in Step 4.  For now you just need SSH access to transfer the snapshot.

On a fresh Pi OS install, NetworkManager defaults to DHCP on all interfaces — connect eth0 to your existing LAN and it will get an IP automatically.  SSH in, then continue to Step 3.

### Step 3 — Install large dependencies

These are not restored from the snapshot — they must be installed fresh:

```bash
sudo apt update && sudo apt upgrade -y

# Core capture / analysis stack
sudo apt install -y zeek clickhouse-server clickhouse-client

# RITA v5 — check current release at github.com/activecm/rita
curl -L https://github.com/activecm/rita/releases/latest/download/rita_linux_arm64 \
  -o /usr/local/bin/rita && sudo chmod +x /usr/local/bin/rita

# IDS
sudo apt install -y suricata suricata-update

# Router / network services
sudo apt install -y dnsmasq iptables-persistent

# System
sudo apt install -y log2ram fail2ban python3-pip git

# BeaconButty webapp
sudo pip3 install flask gunicorn requests
```

> Exact package names and versions may vary. Cross-reference `packages-YYYY-MM-DD.txt` from the snapshot for the full list.

### Step 4 — Extract the snapshot

Copy the snapshot tarball to the Pi, then extract it over `/`:

```bash
scp config-YYYY-MM-DD.tar.gz <user>@<host>:~
ssh <user>@<host>
sudo tar -xzf ~/config-YYYY-MM-DD.tar.gz -C /
```

This restores all scripts, configs, systemd units, the webapp, false positives, and assets in one shot.

### Step 5 — Restore package selections (optional but thorough)

```bash
sudo dpkg --set-selections < packages-YYYY-MM-DD.txt
sudo apt-get -y dselect-upgrade
```

### Step 6 — Enable all services

```bash
sudo systemctl daemon-reload

sudo systemctl enable --now \
  zeek.service \
  bb-graphs.service \
  bb-watchdog.service \
  bb0-display.service \
  beaconbutty-assets.timer \
  beaconbutty-backup.timer \
  beaconbutty-health.timer \
  beaconbutty-housekeeping.timer \
  beacon-report.timer \
  rita-analyze.timer \
  suricata-alert-check.timer \
  suricata-update.timer \
  wan-watchdog.timer \
  iptables.service \
  ip6tables.service \
  log2ram.service \
  log2ram-daily.timer
```

### Step 7 — Post-restore tasks

See **Post-restore checklist** below.

### Step 8 — Reboot

```bash
sudo reboot
```

After reboot, visit `https://<your-host>` or `http://<lan-gateway-ip>:5000` and confirm the dashboard loads with today's data starting to appear.

---

## Option B — Full archive restore

**When to use:** You want to recover the entire system, including ClickHouse beacon history and logs, but you don't have (or don't want to use) a bootable clone. Requires a fresh Pi OS Lite install first — the archive is extracted over the top of it.

### Step 1 — Flash fresh OS

Same as Option A Step 1: flash Raspberry Pi OS Lite (64-bit) to a new NVMe, configure hostname and user, SSH in.

### Step 2 — Transfer the archive

Copy the `archive-YYYY-MM-DD.tar.gz` from your USB stick (or wherever you saved it) onto the Pi. For a 10 GB file, `rsync` is more resilient than `scp`:
```bash
rsync -P archive-2026-04-19.tar.gz <user>@<host>:/tmp/
```

### Step 3 — Stop services and extract

Services that hold files open must be stopped so their state in the archive overwrites cleanly:
```bash
sudo systemctl stop clickhouse-server zeek suricata bb-graphs log2ram || true
sudo tar -xzpf /tmp/archive-2026-04-19.tar.gz -C / --numeric-owner --xattrs
```
The archive includes `/etc`, `/var/lib/clickhouse`, `/home/dm/BeaconButty`, installed binaries under `/usr/local/bin`, systemd units — everything the running system had at snapshot time.

### Step 4 — Reload and reboot

```bash
sudo systemctl daemon-reload
sudo reboot
```

### Step 5 — Verify

After reboot, check services come up cleanly:
```bash
systemctl status zeek clickhouse-server suricata bb-graphs
sudo beaconbutty-health.sh
```

If services fail to start with missing-library errors, the base OS is newer than the archive's packages. Run:
```bash
sudo apt update && sudo apt -f install
```

> **Not in the archive:** TLS cert private key files under `/etc/letsencrypt/archive/` are not included for safety. Re-run the certbot deploy hook or re-issue the cert after restore.
> **Tailscale:** auth token may need refresh — `sudo tailscale up`.

---

## Option C — Full-disk USB clone restore

**When to use:** Complete bare-metal restore including ClickHouse beacon history. The USB clone is a bootable Pi OS image — you can boot from it directly.

### Scenario C1 — NVMe failed, replacing it

1. Power off bb0. Remove the failed NVMe.
2. Insert the USB clone stick.
3. The Pi 5 default boot order tries NVMe before USB. With no NVMe present it should fall through to USB automatically. If it doesn't boot, adjust the EEPROM:
   ```bash
   sudo rpi-eeprom-config --edit
   # Set: BOOT_ORDER=0xf416   (USB before NVMe, NVMe before SD)
   ```
4. Power on — Pi boots from the USB clone (it's a full working system).
5. Insert a new blank NVMe (via USB-C NVMe adapter or directly into the M.2 slot).
6. Clone from USB back to the new NVMe:
   ```bash
   sudo rpi-clone nvme0n1
   ```
7. Power off. Remove the USB stick. Restore the original boot order if you changed it:
   ```bash
   sudo rpi-eeprom-config --edit
   # Set: BOOT_ORDER=0xf461   (NVMe before USB — normal operation)
   ```
8. Power on — Pi boots from the restored NVMe.

### Scenario C2 — Migrating to a new Pi 5

1. Insert the USB clone into the new Pi 5 (no NVMe installed yet).
2. Boot the new Pi from USB.
3. Insert a new blank NVMe (via adapter or M.2 slot).
4. Clone USB → NVMe:
   ```bash
   sudo rpi-clone nvme0n1
   ```
5. Power off. Remove USB stick. Boot from NVMe.

> After a migration (new Pi hardware), Tailscale will need re-authorisation and the SSH host key will have changed — update `known_hosts` on your client.

---

## Post-restore checklist

After any of the restore options, verify these items:

### Network
- [ ] `ip addr show eth0` — WAN interface has an IP from the ISP
- [ ] `ip addr show eth1` — shows `192.168.50.1/24`
- [ ] LAN clients can reach the internet (NAT/iptables working)
- [ ] `sudo systemctl status dnsmasq` — running, no errors

### BeaconButty services
- [ ] `sudo systemctl status zeek` — active, capturing on eth1
- [ ] `sudo systemctl status bb-graphs` — Flask webapp running
- [ ] `sudo systemctl status clickhouse-server` — running
- [ ] `sudo beaconbutty-health.sh` — overall system health check

### TLS certificate (Options A & B — Option C clones the existing cert)

The certbot renewal config and AWS credentials for Route 53 are restored from the snapshot, so re-issuing is a single command:

```bash
sudo certbot certonly --dns-route53 -d <your-host>
```

The deploy hook (`/etc/letsencrypt/renewal-hooks/deploy/restart-bb-graphs.sh`) fixes the private key permissions and restarts the webapp automatically — no manual steps needed after certbot runs.

### Slack alerts
`/var/lib/beaconbutty/slack-config.json` is restored from the snapshot.
Verify permissions are correct (the webapp runs as `dm`):
```bash
sudo chown dm:dm /var/lib/beaconbutty/slack-config.json
sudo chmod 600 /var/lib/beaconbutty/slack-config.json
```
Then test from the Health page → **Test Alert**.

> If you need to re-create it from scratch (token revoked etc.):
> ```json
> { "token": "xoxp-YOUR-TOKEN-HERE", "channel": "<your-slack-channel>" }
> ```

### Tailscale
```bash
sudo tailscale up
# Follow the auth URL printed
sudo tailscale status   # confirm host appears in tailnet
```

### First beacon data
RITA imports run hourly. After ~1 hour:
```bash
beaconbutty-summary.sh
```
You should see beacon scores appearing. The daily alert runs at 07:00.

---

## Pi 5 EEPROM boot order reference

| Value | Order |
|-------|-------|
| `0xf416` | USB → NVMe → SD → restart |
| `0xf461` | NVMe → USB → SD → restart *(normal operation)* |
| `0xf41` | NVMe → SD → restart *(no USB)* |

```bash
# Check current boot order
sudo rpi-eeprom-config | grep BOOT_ORDER

# Edit boot order
sudo rpi-eeprom-config --edit
```

---

## Quick-reference: key paths

| Path | Contents |
|------|----------|
| `/var/lib/beaconbutty/backups/` | Config snapshots |
| `/var/lib/beaconbutty/false-positives.conf` | FP registry (in snapshot) |
| `/var/lib/beaconbutty/assets.json` | LAN asset cache (in snapshot) |
| `/var/lib/beaconbutty/slack-config.json` | Slack token (in snapshot) |
| `/var/lib/beaconbutty/reports/` | Daily beacon reports |
| `/var/lib/clickhouse/` | Beacon database (NOT in snapshot) |
| `/etc/rita/config.hjson` | RITA config (in snapshot) |
| `/etc/letsencrypt/renewal/` | certbot renewal config (in snapshot) |
| `/etc/letsencrypt/archive/` | TLS cert files including private key (NOT in snapshot — re-issue after restore) |
| `/usr/local/bin/beaconbutty-*.sh` | Operational scripts (in snapshot) |
| `/home/dm/BeaconButty/` | Full webapp source (in snapshot) |
