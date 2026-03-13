#!/opt/pironman5/venv/bin/python3
"""
bb0-display.py — OLED status display for bb0 (BeaconButty router Pi)

Shows (128×64 SSD1306):
  Line 0: hostname + CPU temperature
  Line 1: CPU usage % + bar graph
  Line 2: Tailscale IP
  Line 3: LAN IP (eth1)
  Line 4: Uptime

Install:
  sudo cp bb0-display.py /usr/local/bin/bb0-display.py
  sudo chmod +x /usr/local/bin/bb0-display.py
  sudo cp bb0-display.service /etc/systemd/system/
  sudo systemctl enable --now bb0-display
"""

import json
import signal
import time
import socket
import subprocess as sp
from datetime import datetime
from pathlib import Path

import psutil
import gpiozero
from PIL import ImageFont
from pm_auto.ssd1306 import SSD1306

# ── Fan control ───────────────────────────────────────────────────────────────
FAN_PIN       = 6
FAN_STATE_FILE = Path("/var/lib/beaconbutty/watchdog/fan-state")    # write "on" or "off" to toggle

class Fan:
    def __init__(self, pin):
        self._dev = gpiozero.DigitalOutputDevice(pin)
        self._state = False

    def sync(self):
        """Read state file and apply if changed."""
        if not FAN_STATE_FILE.exists():
            return
        try:
            want = FAN_STATE_FILE.read_text().strip().lower()
            if want == "on" and not self._state:
                self._dev.on()
                self._state = True
            elif want == "off" and self._state:
                self._dev.off()
                self._state = False
        except Exception:
            pass

    def off(self):
        self._dev.off()

    @property
    def state(self):
        return self._state

# ── LED control ───────────────────────────────────────────────────────────────
LED_STATE_FILE     = Path("/var/lib/beaconbutty/watchdog/led-state.json")
LED_COUNT          = 4
LED_DEFAULT_COLOR  = "#0a1aff"
LED_DEFAULT_BRI    = 50
LED_DEFAULT_STYLE  = "breathing"
LED_DEFAULT_SPEED  = 50

class LED:
    def __init__(self):
        self._ws       = None
        self._last_sig = None
        try:
            from pm_auto.ws2812 import WS2812
            self._ws = WS2812(config={
                'rgb_led_count':  LED_COUNT,
                'rgb_enable':     False,
                'rgb_color':      LED_DEFAULT_COLOR,
                'rgb_brightness': LED_DEFAULT_BRI,
                'rgb_style':      LED_DEFAULT_STYLE,
                'rgb_speed':      LED_DEFAULT_SPEED,
            })
            if self._ws.is_ready():
                self._ws.start()
        except Exception as e:
            print(f"LED init failed: {e}")

    def sync(self):
        """Read state file and apply config changes to the WS2812 thread."""
        if self._ws is None or not self._ws.is_ready():
            return
        try:
            if LED_STATE_FILE.exists():
                state = json.loads(LED_STATE_FILE.read_text())
            else:
                state = {}
            enable = bool(state.get("enable", False))
            color  = state.get("color",      LED_DEFAULT_COLOR)
            bri    = int(state.get("brightness", LED_DEFAULT_BRI))
            style  = state.get("style",      LED_DEFAULT_STYLE)
            speed  = int(state.get("speed",  LED_DEFAULT_SPEED))
            sig = (enable, color, bri, style, speed)
            if sig == self._last_sig:
                return
            self._ws.update_config({
                'rgb_enable':     enable,
                'rgb_color':      color,
                'rgb_brightness': bri,
                'rgb_style':      style,
                'rgb_speed':      speed,
            })
            self._last_sig = sig
        except Exception as e:
            print(f"LED sync error: {e}")

    def off(self):
        if self._ws and self._ws.is_ready():
            try:
                self._ws.stop()
            except Exception:
                pass

# ── Layout (128×64 display) ───────────────────────────────────────────────────
MARGIN_Y   = [0, 13, 26, 38, 51]   # y position of each of the 5 lines
BAR_X      = 31                     # bar graph left edge (after "CPU")
BAR_W      = 52                     # bar graph width
BAR_H      = 8                      # bar graph height
BAR_TOP    = 3                      # top margin inside the line
FONT_SIZE  = 14
FONT_SMALL = 9

# Try DejaVuSansMono first (crisp, monospace), fall back to Minecraftia from
# the pironman5 package, then PIL's built-in default.
FONT_PATHS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/mnt/sdcard/home/dm/fonts/DejaVuSansMono.ttf",
]

# ── Brightness schedule ───────────────────────────────────────────────────────
# Each entry: (start_hour_inclusive, end_hour_exclusive, contrast_0_to_255)
# Checked in order; first match wins.  Overnight ranges use start > end.
BRIGHTNESS_SCHEDULE = [
    (23, 6,  5),    # 11 pm – 6 am  : very dim   (OLED longevity)
    (6,  9,  60),   # 6 am – 9 am   : low-medium
    (9,  20, 180),  # 9 am – 8 pm   : normal
    (20, 23, 80),   # 8 pm – 11 pm  : evening dim
]

def get_target_contrast():
    h = datetime.now().hour
    for start, end, contrast in BRIGHTNESS_SCHEDULE:
        if start > end:                     # overnight range wraps midnight
            if h >= start or h < end:
                return contrast
        else:
            if start <= h < end:
                return contrast
    return 180                              # fallback

# ── Helpers ───────────────────────────────────────────────────────────────────
def load_font(size):
    for path in FONT_PATHS:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()

def get_temp():
    try:
        out = sp.getoutput("vcgencmd measure_temp")
        return float(out.split("=")[1].split("'")[0])
    except Exception:
        try:
            with open("/sys/class/thermal/thermal_zone0/temp") as f:
                return float(f.read()) / 1000
        except Exception:
            return 0.0

def get_uptime():
    delta = datetime.now() - datetime.fromtimestamp(psutil.boot_time())
    s = str(delta).split(".")[0].replace(" days,", "d")
    return f"Up: {s}"

def is_undervolt():
    try:
        out = sp.getoutput("vcgencmd get_throttled")
        val = int(out.split("=")[1], 16)
        return bool(val & 0x1)  # bit 0 = currently undervolted
    except Exception:
        return False

def get_ip(iface):
    if iface.startswith("tail"):
        prefix = "T"
    elif iface.startswith("eth"):
        prefix = "L"
    else:
        prefix = "W"
    addrs = psutil.net_if_addrs().get(iface, [])
    for addr in addrs:
        if addr.family == socket.AddressFamily.AF_INET:
            return f"{prefix} {addr.address}"
    return f"{prefix} unavailable"

# ── Shutdown display ──────────────────────────────────────────────────────────
def draw_shutdown(oled, font):
    oled.clear()
    d = oled.draw
    msg = "REBOOTING"
    w = font.getlength(msg)
    bbox = font.getbbox(msg)
    h = bbox[3] - bbox[1]
    x = (oled.width  - w) / 2
    y = (oled.height - h) / 2
    d.text((x, y), msg, font=font, fill=1)
    oled.display()

# ── Render ────────────────────────────────────────────────────────────────────
def draw_frame(oled, font, font_small):
    oled.clear()
    d = oled.draw

    # Line 0: hostname + temperature
    temp = get_temp()
    d.text((0, MARGIN_Y[0]),
           f"Node: {socket.gethostname()}  {temp:.1f}°C",
           font=font, fill=1)

    # Line 1: CPU % + bar graph
    cpu = psutil.cpu_percent()
    d.text((0, MARGIN_Y[1]), "CPU", font=font, fill=1)
    if cpu < 100:
        d.text((78, MARGIN_Y[1]), f"{cpu:5.1f}%", font=font, fill=1)
        y = MARGIN_Y[1] + BAR_TOP
        d.rectangle((BAR_X, y, BAR_X + BAR_W, y + BAR_H), outline=1, fill=0)
        d.rectangle((BAR_X, y, BAR_X + int(BAR_W * cpu / 100), y + BAR_H), fill=1)
    else:
        y = MARGIN_Y[1] + BAR_TOP
        d.rectangle((BAR_X, y, BAR_X + 95, y + BAR_H), fill=1)
        d.text((65, y - 2), "100%", font=font_small, fill=0)

    # Line 2: Tailscale IP
    d.text((0, MARGIN_Y[2]), get_ip("tailscale0"), font=font, fill=1)

    # Line 3: LAN IP (eth1)
    d.text((0, MARGIN_Y[3]), get_ip("eth1"), font=font, fill=1)

    # Line 4: Uptime (+ '*' if currently undervolted)
    uptime = get_uptime()
    if is_undervolt():
        uptime += " *"
    d.text((0, MARGIN_Y[4]), uptime, font=font, fill=1)

    oled.display()

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    oled = SSD1306()
    if not oled.is_ready():
        print("OLED not ready — check I2C is enabled (dtparam=i2c_arm=on in /boot/firmware/config.txt)")
        return

    font       = load_font(FONT_SIZE)
    font_small = load_font(FONT_SMALL)
    fan        = Fan(FAN_PIN)
    led        = LED()

    current_contrast = None   # track applied contrast so we only write on change
    running = True

    def _sigterm(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, _sigterm)

    try:
        while running:
            try:
                fan.sync()
                led.sync()

                contrast = get_target_contrast()
                if contrast != current_contrast:
                    oled.oled.set_contrast(contrast)
                    current_contrast = contrast

                draw_frame(oled, font, font_small)
            except Exception as e:
                print(f"Display error: {e}")
            time.sleep(0.5)
    finally:
        try:
            draw_shutdown(oled, font)
        except Exception:
            pass
        fan.off()
        led.off()

if __name__ == "__main__":
    main()
