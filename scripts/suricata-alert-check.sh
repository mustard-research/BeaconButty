#!/usr/bin/env bash
# suricata-alert-check.sh — check fast.log for new P1 Suricata alerts and send
# notifications. Called hourly by suricata-alert-check.timer.
#
# Fires:
#   suricata_p1_lan      — P1 alert where source is a 192.168.50.x LAN device
#   suricata_p1_repeated — same P1 rule fired more than REPEAT_THRESHOLD times today
#
# Deduplication is handled by the Lambda (6h window for high severity), so this
# script can safely run every hour without flooding Slack.

set -euo pipefail

FAST_LOG="/var/log/suricata/fast.log"
ALERT_BIN="${ALERT_BIN:-beaconbutty-alert.sh}"
LAN_PREFIX="${LAN_PREFIX:-192.168.50.}"
REPEAT_THRESHOLD="${REPEAT_THRESHOLD:-5}"

# Nothing to do if Suricata isn't installed or log is absent
[[ -x "$(command -v suricata 2>/dev/null || true)" ]] || exit 0
[[ -f "$FAST_LOG" ]] || exit 0

command -v "$ALERT_BIN" &>/dev/null || exit 0

TODAY_DATE=$(date +%m/%d/%Y)

python3 - "$FAST_LOG" "$TODAY_DATE" "$LAN_PREFIX" "$REPEAT_THRESHOLD" "$ALERT_BIN" <<'PYEOF'
import re, subprocess, sys
from collections import defaultdict

fast_log       = sys.argv[1]
today_date     = sys.argv[2]
lan_prefix     = sys.argv[3]
repeat_thresh  = int(sys.argv[4])
alert_bin      = sys.argv[5]

# Pattern: MM/DD/YYYY-HH:MM:SS.ffffff  [**] [1:SID:rev] MSG [**] [Classification: X] [Priority: N] {PROTO} SRC:PORT -> DST:PORT
LOG_RE = re.compile(
    r'^(\d{2}/\d{2}/\d{4})-\S+\s+\[.*?\]\s+\[1:(\d+):\d+\]\s+(.*?)\s+\[.*?\]\s+'
    r'\[Priority:\s*(\d+)\]\s+\{(\w+)\}\s+(\S+)\s*->\s*(\S+)'
)

p1_today = []         # (sid, msg, proto, src, dst)
sid_count = defaultdict(int)   # sid → count of P1 hits today

with open(fast_log, errors='replace') as f:
    for line in f:
        if not line.startswith(today_date):
            continue
        m = LOG_RE.match(line)
        if not m:
            continue
        _, sid, msg, priority, proto, src, dst = m.groups()
        if int(priority) != 1:
            continue
        sid_count[sid] += 1
        p1_today.append((sid, msg, proto, src, dst))

def send(atype, severity, device, detail):
    subprocess.run([alert_bin, atype, severity, device, detail],
                   capture_output=True)

# suricata_p1_lan — P1 alerts where the LAN device is the source
seen_lan = set()  # (sid, src) — avoid duplicate alerts for same rule+device
for sid, msg, proto, src, dst in p1_today:
    src_host = src.rsplit(':', 1)[0]
    if not src_host.startswith(lan_prefix):
        continue
    key = (sid, src_host)
    if key in seen_lan:
        continue
    seen_lan.add(key)
    detail = f"SID {sid} — {msg[:80]} ({proto} {src} → {dst})"
    send('suricata_p1_lan', 'high', src_host, detail)

# suricata_p1_repeated — any P1 rule that fired ≥ REPEAT_THRESHOLD times today
seen_rep = set()
for sid, count in sid_count.items():
    if count < repeat_thresh or sid in seen_rep:
        continue
    seen_rep.add(sid)
    # Find msg for this sid
    msg = next((m for s, m, *_ in p1_today if s == sid), 'unknown rule')
    detail = f"SID {sid} fired {count}× today — {msg[:80]}"
    send('suricata_p1_repeated', 'high', 'bb0', detail)

print(f"P1 alerts today: {len(p1_today)}  LAN-source alerts: {len(seen_lan)}  Repeated SIDs: {len(seen_rep)}")
PYEOF
