---
tags: [beaconbutty/hardware]
created: 2026-04-16
---

# OLED Display

The Pironman 5 case includes a 128×64 SSD1306 OLED display showing real-time system status. It is managed by a custom Python script alongside the Pironman LED strip.

## Service

| Item | Value |
|------|-------|
| Service | `bb0-display.service` |
| Script | `/usr/local/bin/bb0-display.py` |
| Runs as | Continuous loop, updating each cycle |

> [!warning]
> The service is **`bb0-display.service`** — not `bb-display`. Don't confuse the two.

## What it shows

- Hostname and LAN IP address
- CPU temperature and load
- Memory usage
- Uptime
- Current alert/beacon status

## Brightness schedule

The display automatically dims at night to reduce light pollution:

| Time window | Brightness |
|-------------|-----------|
| 23:00 – 06:00 | Very dim |
| 06:00 – 09:00 | Low |
| 09:00 – 20:00 | Normal |
| 20:00 – 23:00 | Evening dim |

## User blanking (webapp toggle)

The display can be blanked from the webapp Health page without touching the service.

| Item | Value |
|------|-------|
| Flag file | `/var/lib/beaconbutty/display-off` |
| Storage | NVMe — **persists across reboots** |
| Content `"1"` | Display blanked |
| Content `"0"` | Display active |

The display script checks this flag each loop cycle. The webapp Health page provides a toggle switch that reads and writes this flag via the `/api/display` endpoint.

Display defaults to **on** after a reboot (`"0"` persists on NVMe).

> [!danger]
> **Never stop `bb0-display.service` to blank the display.** Stopping the service:
> - Clears the LED strip to black
> - Shows "REBOOTING" on the OLED
> 
> Use the flag file / webapp toggle instead. The service stopping is only intended to mean the Pi is about to reboot.

## LED strip

The Pironman RGB LED strip is also managed by `bb0-display.py` via `bb0-led`. The LED strip mirrors the Pi's operational state:
- Normal operation: colour pattern
- Shutting down / rebooting: specific "REBOOTING" state
- Display blanked by flag: LEDs continue normally (unaffected by user blanking)
