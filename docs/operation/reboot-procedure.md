---
tags: [beaconbutty/operation]
created: 2026-04-16
---

# Reboot Procedure

## Normal reboot

```bash
sudo reboot
```

That's it. The command is automatically intercepted by a wrapper that does the right thing.

## Why a custom reboot script was needed

After the April 2026 system upgrade (ClickHouse 26.2.4 → 26.3.9), a reboot hung indefinitely. Root cause: **ClickHouse did not stop before the kernel triggered the hardware watchdog**, causing the watchdog to fire a reset loop. The system would spin at the watchdog reset stage and never complete the boot.

The fix is to pre-stop ClickHouse cleanly before calling the real reboot.

## How it works

`/usr/local/sbin/reboot` is a wrapper script that intercepts all `sudo reboot` calls. It takes precedence over `/usr/sbin/reboot` (which is a symlink to `systemctl`) because `/usr/local/sbin` appears earlier in the sudo PATH.

### What `bb-reboot` does

1. Sends a Slack notification to `#beacon-butty`: "BeaconButty rebooting"
2. Stops `clickhouse-server` and waits for it to fully exit
3. Calls `systemctl reboot`
4. Displays "REBOOTING" on the OLED and holds the LED state

Since 2026-07-06: a failed ClickHouse stop or log2ram flush logs a WARNING and **still proceeds to the reboot** — previously `set -e` aborted the script, so a scripted `sudo reboot` could silently leave the box up.

### Files

| File | Location | Purpose |
|------|---------|---------|
| Wrapper | `/usr/local/sbin/reboot` | Intercepts `sudo reboot` |
| bb-reboot script | `/usr/local/bin/bb-reboot` | The actual clean shutdown logic |
| Repo copy | `scripts/reboot-wrapper` | Source of truth |
| Repo copy | `scripts/bb-reboot` | Source of truth |

## Verifying the wrapper is active

```bash
sudo which reboot
# Should return: /usr/local/sbin/reboot
# If it returns /usr/sbin/reboot, the wrapper is not deployed
```

## Force reboot (bypass bb-reboot)

If bb-reboot itself is broken, or you need an immediate reboot without the clean shutdown sequence:

```bash
sudo reboot --force
# or
sudo reboot -f
```

The wrapper detects `--force` / `-f`, **strips the flag**, and calls `/usr/sbin/reboot` directly — bypassing bb-reboot but still performing a normal systemd reboot.

> [!warning]
> Fixed 2026-07-06: the wrapper used to pass `-f`/`--force` **through** to the real reboot, where those flags mean a *hard* reboot (skip systemd shutdown entirely — no ClickHouse stop, no clean unmounts): the most dangerous reboot available, from the flag meant to be the escape hatch. If you genuinely need a hard reboot, call `/usr/sbin/reboot -f` explicitly. Bypassing bb-reboot still risks the ClickHouse watchdog hang — only use it when bb-reboot itself is broken.

## After a reboot — what to expect

- **Boot time**: approximately 30–60 seconds to reach all services running
- **Display**: OLED comes on with system info; Pironman LEDs active
- **Services**: all core services start automatically
- **RITA import**: first import fires at the next full hour — up to 60 minutes latency before new data
- **Display state**: OLED display will be **on** by default (flag file persists `"0"` on NVMe)
- **Webapp**: available on HTTPS :443 within ~30 seconds of boot

## Post-reboot verification

A reboot is the only routine event that exercises log2ram's writeback, so check it every time rather than assuming. Four commands:

```bash
# 1. Nothing failed to come back
systemctl --failed
journalctl -b -p 3 --no-pager | tail

# 2. The previous boot is still in the journal (proves persistent storage)
journalctl --list-boots | tail -3

# 3. log2ram flushed on the way down, and re-mounted on the way up
findmnt -t tmpfs | grep log2ram
sudo tail -3 /var/log/zeek/log2ram.log        # look for the rsync "sent N bytes" line

# 4. Full sweep
sudo beaconbutty-health.sh
```

For step 3, compare **apparent bytes and file counts**, not `du` — tmpfs page accounting makes the RAM copy look 10–15 % larger than its backing store even when the two are byte-identical:

```bash
for d in /var/log/zeek/2026-*; do
  n=$(basename "$d")
  echo "$n ram=$(find "$d" -type f -printf '%s\n' | awk '{t+=$1}END{print t}')" \
       "disk=$(sudo find /var/log/hdd.zeek/$n -type f -printf '%s\n' | awk '{t+=$1}END{print t}')"
done
```

Known-benign journal noise at priority ≤ 3 on every boot: two `alsa-restore.rules` GOTO warnings from udev, one `raspberrypi-firmware … returned status 0x80000001`, and two `wpa_supplicant` nl80211 messages about signal-strength monitoring on wlan0.

Reference numbers from the 2026-08-28 reboot (the first after the log2ram rescope): 1.4 s kernel + 21.9 s userspace to `multi-user.target`, writeback of 458,833,398 B complete, both boots present in the journal, all health checks green. See [Log2Ram Usage](../architecture/log2ram-usage.md).

See [Health Monitoring](health-monitoring.md) for the full check list.
