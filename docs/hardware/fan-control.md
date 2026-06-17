---
tags: [beaconbutty/hardware]
created: 2026-04-16
---

# Fan Control

bb0 has two independent cooling systems configured as a tiered strategy — the RPi active cooler handles the typical operating range, and the Pironman case fan kicks in as a backup if the Pi fan can't keep up.

## Two fans

### 1. Raspberry Pi Active Cooler (built-in)

- Official Raspberry Pi Active Cooler (heatsink + blower)
- Controlled by the Pi firmware via `/sys/class/thermal/cooling_device*`
- Configured via `dtparam` settings in `/boot/firmware/config.txt`
- **Thresholds**: on at 58°C, off at 54°C (4°C hysteresis)

### 2. Pironman Case Fan (GPIO-controlled)

- Small axial fan in the Pironman 5 case
- Controlled by `bb-watchdog` script via GPIO pin 6 (not the pironman5 daemon)
- **Thresholds**: on at 60°C, off at 55°C (5°C hysteresis)

## Tiered cooling strategy

```
Temperature    RPi Cooler    Pironman Fan
─────────────────────────────────────────
< 54°C         off           off
54–58°C        off (hyst.)   off
≥ 58°C         ON            off
58–60°C        ON            off
≥ 60°C         ON            ON
55–60°C        ON            ON (hyst.)
< 55°C         ON            off
< 54°C         off           off
```

The RPi active cooler handles the typical 58–60°C operating range. The Pironman fan is a backup that only spins up under heavy sustained load (RITA import, ClickHouse queries).

## Configuration files

| File | Purpose |
|------|---------|
| `/boot/firmware/config.txt` | RPi active cooler thresholds via `dtparam` |
| `/usr/local/bin/bb-watchdog` | Pironman fan control script |

## Dashboard tile

The webapp dashboard (`/`) has a **Fans** tile between CPU Temp and CPU, showing live ON/OFF for both fans:

- **Pi**: read from `/sys/class/thermal/cooling_device0/cur_state` (`>0` = on). Non-clickable — the thermal governor re-asserts this value within ~1s from the `config.txt` hysteresis, so a UI toggle would be meaningless without editing config and rebooting.
- **Pironman**: read from `/var/lib/beaconbutty/watchdog/fan-state` (written by `bb-watchdog`). **Clickable** — click the badge to force the fan on or off for 10 minutes.

ON = blue badge, OFF = grey badge. Dashboard auto-refreshes every 60s, so the tile lags live state by up to a minute. If either source path moves, update `get_system_stats()` in `webapp/app.py`.

### Manual Pironman override

Clicking the Pironman badge hits `POST /api/pironman-fan` with `{"state": "on"|"off"}`. The webapp writes two files:

| File | Purpose |
|------|---------|
| `/var/lib/beaconbutty/watchdog/fan-override.json` | `{state, expires}` — 10-minute TTL |
| `/var/lib/beaconbutty/watchdog/fan-state` | Immediate `on`/`off` so `bb0-display.py` flips GPIO within 0.5s |

On each 60-second tick `bb-watchdog` reads the override file. If the expiry is in the future, it re-asserts the manual state and skips the hysteresis check; if expired or malformed, it deletes the file and resumes temperature-based control. A yellow `MANUAL` label shows on the tile while an override is live.

**Click semantics**: if an override is already active, clicking the badge **clears** it (`POST /api/pironman-fan` with `{"clear": true}`) — the MANUAL label disappears on the next refresh and auto-control resumes within one watchdog tick. Otherwise the click posts `{"state": "on"|"off"}` to flip to the opposite state for 10 minutes.

**Clear re-applies hysteresis immediately**: on `{clear: true}` the webapp mirrors bb-watchdog's 60 / 55 °C hysteresis against the current CPU temp and rewrites `fan-state` before returning. Without this, the button kept showing a stale ON for up to the next 60-second watchdog tick. If the thresholds change, update both `bb-watchdog` and `_pironman_reapply_auto()` in `webapp/app.py`.

## Temperature chart

The webapp System page (`/system`) shows CPU temperature with both fans' threshold lines overlaid, and a CPU-usage chart stacked below:

- **Green lines**: RPi Active Cooler thresholds (58°C on / 54°C off)
- **Yellow lines**: Pironman Fan thresholds (60°C on / 55°C off)

Chart features:
- Y-axis uses p2/p98 percentile bounds + 20% manual grace padding to suppress outlier spikes without hiding normal operating range
- Multi-day views (3-day, 7-day) aggregate data using **maximum** temperature per hour (not average), preserving thermal spikes
- Chart is always destroyed and recreated on view switch — Chart.js inline plugins only fire on chart creation, not on `chart.update()`
- Data is thinned to 150 points client-side for the dense today view (~900 raw data points)

## Stress-test observations (2026-04-24)

~40 minutes of sustained load from a whisper.cpp transcription running at
~300 % CPU (4 threads busy) gave a natural stress test. Minute-sampled
data from `/var/lib/beaconbutty/watchdog/data/2026-04-24.json`:

| Phase | Temp range | Pi cooler | Pironman fan |
|---|---|---|---|
| Idle baseline | 50–53 °C | off | off |
| cmake build | 55–57 °C | on | off |
| Whisper sustained | 54.5 – **61.7** °C | on (~5 brief off cycles) | on (~6–7 cycles) |
| Post-load (1 min) | 61.1 → 48.5 °C | off | off |

Peak was **61.7 °C** — Pi 5 soft-throttle is 80 °C, so ~18 °C of headroom
throughout. `vcgencmd get_throttled` returned `0x0` (no throttling). The
12.6 °C drop in the minute after load ended confirms both fans are doing
their job.

### Cycling behaviour under sustained load

Both fans oscillated because the workload's steady-state temperature sat
across each fan's hysteresis band:
- Pi cooler (58 / 54 °C) — cycled ~5 times.
- Pironman (60 / 55 °C) — cycled 6–7 times; whisper's per-minute temp
  swings crossed both thresholds repeatedly.

### Tuning options considered

| Option | Pironman on / off | Effect |
|---|---|---|
| Current | 60 / 55 | Fires under moderate load; ~6–7 cycles in 40 min |
| Raise cut-in | 62 / 55 (7 °C hyst.) | Still fires, ~half the cycling |
| True-backup | 65 / 55 (10 °C hyst.) | Would have stayed off entirely for this workload |

### Decision — 2026-04-24

**Thresholds kept at 58/54 (Pi) and 60/55 (Pironman).** Preference is to
err toward cooler operation rather than optimise for reduced fan cycling.
Revisit if:
- Audible cycling becomes annoying during routine workloads, **or**
- A heavier sustained workload (e.g. whisper + RITA import overlap)
  ever pushes peaks > 70 °C, **or**
- Throttling is observed (`vcgencmd get_throttled` != `0x0`), **or**
- London summer ambient rises materially — this stress test was Apr 24
  with cool spring ambient. Expect baseline idle and peak-under-load to
  shift upward through Jun–Aug; re-check the same workload in midsummer
  and compare against this record.

If thresholds are ever changed, update three places in lockstep:
`bb-watchdog` (`FAN_ON_TEMP` / `FAN_OFF_TEMP`), `_pironman_reapply_auto()`
in `webapp/app.py`, and the threshold-line constants in the temperature
chart template.

### Scheduled midsummer re-check — 2026-07-15

A one-shot systemd timer `beaconbutty-midsummer-fan-check.timer` is armed
to fire at **2026-07-15 10:00 Europe/London**. It runs
`/usr/local/bin/beaconbutty-midsummer-fan-check.py` which:

1. Loads the last 14 days of records from
   `/var/lib/beaconbutty/watchdog/data/*.json`.
2. Computes idle-baseline median, peak temp, per-fan duty cycle, and
   per-fan transition rate.
3. Checks `vcgencmd get_throttled` for any sticky throttle bits since
   boot.
4. Appends a `### Midsummer check — 2026-07-15` block to this page with
   a side-by-side comparison against the Apr-24 baseline above.
5. Makes a local git commit and pushes to `origin` (SSH key on bb0).

Threshold-change logic in the script:

| Condition | Recommendation |
|---|---|
| Throttle bits set (freq-throttle or soft-temp-limit) | Lower cut-ins (Pi 55, Pironman 57) |
| Peak > 70 °C, no throttling | Lower Pironman cut-in to 57 °C |
| Peak 65–70 °C, no throttling | Monitor, no change |
| Peak < 65 °C, no throttling | No change |

Sources tracked in repo: `scripts/midsummer-fan-check.py`,
`systemd/beaconbutty-midsummer-fan-check.{service,timer}`.

## Monitoring

```bash
# Current CPU temperature
vcgencmd measure_temp

# Check for throttling
vcgencmd get_throttled
# 0x0 = healthy; any other value = throttled or previously throttled

# Fan state (RPi cooler)
cat /sys/class/thermal/cooling_device*/cur_state
```
