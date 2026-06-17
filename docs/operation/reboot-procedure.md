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

The wrapper detects `--force` / `-f` and calls `/usr/sbin/reboot` directly, bypassing bb-reboot entirely.

> [!warning]
> Force rebooting without stopping ClickHouse first risks the watchdog hang. Only use `--force` if bb-reboot is non-functional and you need to recover the system.

## After a reboot — what to expect

- **Boot time**: approximately 30–60 seconds to reach all services running
- **Display**: OLED comes on with system info; Pironman LEDs active
- **Services**: all core services start automatically
- **RITA import**: first import fires at the next full hour — up to 60 minutes latency before new data
- **Display state**: OLED display will be **on** by default (flag file persists `"0"` on NVMe)
- **Webapp**: available on HTTPS :443 within ~30 seconds of boot

See [Health Monitoring](health-monitoring.md) for post-reboot verification commands.
