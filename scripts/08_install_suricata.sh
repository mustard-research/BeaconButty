#!/usr/bin/env bash
set -euo pipefail

# 08_install_suricata.sh — Install and configure Suricata IDS
#
# Suricata passively monitors eth1 alongside Zeek (IDS mode, AF_PACKET).
# Requires 8 GB RAM — exits cleanly on a 4 GB Pi with an explanatory message.
#
# What it does:
#   1. Checks available RAM — exits gracefully if < 6 GB
#   2. Installs Suricata from the Debian repository
#   3. Configures HOME_NET, capture interface, and log directory (/var/log/suricata)
#   4. Fetches Emerging Threats Open rules via suricata-update
#   5. Installs a daily rule-update systemd timer (06:00, before the 07:00 report)
#   6. Enables and starts the Suricata service
#
# Usage:
#   sudo ./scripts/08_install_suricata.sh
#
# Override defaults:
#   CAPTURE_IFACE=eth1 LAN_SUBNET=192.168.50.0/24 sudo -E ./scripts/08_install_suricata.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CAPTURE_IFACE="${CAPTURE_IFACE:-eth1}"
LAN_SUBNET="${LAN_SUBNET:-192.168.50.0/24}"
SURICATA_LOG_DIR="/var/log/suricata"
SURICATA_CONF="/etc/suricata/suricata.yaml"

[[ $EUID -ne 0 ]] && { echo "Run as root: sudo ./scripts/08_install_suricata.sh"; exit 1; }

# ── Colours ───────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    RED='\033[0;31m';   RESET='\033[0m'; BOLD='\033[1m'
else
    GREEN=''; YELLOW=''; RED=''; RESET=''; BOLD=''
fi

OK()   { echo -e "  ${GREEN}✓${RESET}  $*"; }
WARN() { echo -e "  ${YELLOW}!${RESET}  $*"; }
FAIL() { echo -e "  ${RED}✗${RESET}  $*"; }
INFO() { echo -e "  ${BOLD}→${RESET}  $*"; }

echo ""
echo -e "${BOLD}BeaconButty — Suricata IDS Installation${RESET}"
echo "────────────────────────────────────────────────────"

# ── 1. RAM check ──────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}RAM Check${RESET}"

MEM_TOTAL_MB=$(awk '/MemTotal/ {printf "%.0f", $2/1024}' /proc/meminfo)

if [[ "$MEM_TOTAL_MB" -lt 6000 ]]; then
    echo ""
    WARN "This system has ${MEM_TOTAL_MB} MB RAM."
    echo ""
    WARN "Suricata with Emerging Threats Open rules requires ~400 MB on top of"
    WARN "the existing Zeek + ClickHouse stack — too little headroom on a 4 GB Pi."
    echo ""
    INFO "Run this script again after migrating to the 8 GB Pi."
    echo ""
    exit 0
fi

OK "RAM: ${MEM_TOTAL_MB} MB — sufficient for Suricata."

# ── 2. Install Suricata ───────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Installation${RESET}"

if command -v suricata &>/dev/null; then
    EXISTING_VER=$(suricata --build-info 2>/dev/null | awk '/^Version/ {print $2}' | head -1 || echo "unknown")
    OK "Suricata already installed: ${EXISTING_VER}"
else
    INFO "Installing suricata..."
    apt-get update -qq
    apt-get install -y --no-install-recommends suricata
    OK "Suricata installed."
fi

SURICATA_VER=$(suricata --build-info 2>/dev/null | awk '/^Version/ {print $2}' | head -1 || echo "unknown")
INFO "Version: ${SURICATA_VER}"

# suricata-update is bundled with suricata on Bookworm; guard against older releases
if ! command -v suricata-update &>/dev/null; then
    INFO "Installing suricata-update separately..."
    apt-get install -y --no-install-recommends python3-suricata-update 2>/dev/null || \
        { FAIL "suricata-update not found — install manually: apt-get install python3-suricata-update"; exit 1; }
fi
OK "suricata-update: available."

# ── 3. Configure Suricata ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Configuration${RESET}"

# Log directory on log2ram (/var/log); rotated .gz archives are moved to
# /var/lib/suricata/archive/ (NVMe) by the logrotate lastaction hook.
mkdir -p "$SURICATA_LOG_DIR"
chmod 755 "$SURICATA_LOG_DIR"
OK "Log directory: ${SURICATA_LOG_DIR}  (log2ram; archives go to /var/lib/suricata/archive)"

# Apply BeaconButty settings to suricata.yaml using Python for reliable
# substitutions in the large, complex YAML file.
python3 - "$CAPTURE_IFACE" "$LAN_SUBNET" "$SURICATA_LOG_DIR" "$SURICATA_CONF" <<'PYEOF'
import sys, re

iface     = sys.argv[1]
subnet    = sys.argv[2]
log_dir   = sys.argv[3].rstrip('/') + '/'
conf_file = sys.argv[4]

with open(conf_file) as f:
    content = f.read()

changes = []

# HOME_NET — replace the quoted value (default has many RFC1918 ranges)
new_content, n = re.subn(
    r'(HOME_NET:\s*")[^"]*(")',
    f'\\g<1>[{subnet}]\\2',
    content
)
if n:
    changes.append(f'HOME_NET: [{subnet}]')
content = new_content

# default-log-dir — move from /var/log/suricata/ to NVMe path
new_content, n = re.subn(
    r'^(default-log-dir:\s*).*$',
    f'\\g<1>{log_dir}',
    content, flags=re.MULTILINE
)
if n:
    changes.append(f'default-log-dir: {log_dir}')
content = new_content

# af-packet interface — first entry after the af-packet: key
new_content, n = re.subn(
    r'(af-packet:\s*\n\s*-\s*interface:\s*)\S+',
    f'\\g<1>{iface}',
    content
)
if n:
    changes.append(f'af-packet interface: {iface}')
content = new_content

# default-rule-path — point to where suricata-update writes rules
new_content, n = re.subn(
    r'^(default-rule-path:\s*).*$',
    r'\g<1>/var/lib/suricata/rules',
    content, flags=re.MULTILINE
)
if n:
    changes.append('default-rule-path: /var/lib/suricata/rules')
content = new_content

with open(conf_file, 'w') as f:
    f.write(content)

for c in changes:
    print(f'  Applied: {c}')
if not changes:
    print('  Warning: no substitutions matched — review suricata.yaml manually')
PYEOF

OK "suricata.yaml: configured."

# Trim eve.json to alert/anomaly events only. flow/dns/tls/quic/http/files/stats
# are ~95% of eve.json's volume (~230M/day) and fully duplicate Zeek's own
# dns/conn/ssl logs — nothing consumes them (webapp parse_eve_json_today,
# beaconbutty-ip-intel.py and the health check all filter event_type=="alert").
# Trimming keeps the /var/log log2ram tmpfs from filling.
python3 - "$SURICATA_CONF" <<'PYEOF'
import sys

conf_file = sys.argv[1]
with open(conf_file) as f:
    s = f.read()

start_marker = "        - http:\n"
end_marker   = "        #- netflow\n"

if start_marker not in s and "eve.json trimmed to alert/anomaly" in s:
    print("  eve.json types already trimmed — skipping")
elif start_marker not in s or end_marker not in s:
    print("  Warning: eve-log types block not found — trim eve.json manually")
else:
    start = s.index(start_marker)
    end   = s.index(end_marker) + len(end_marker)
    new_block = (
        "        # -- BeaconButty: eve.json trimmed to alert/anomaly only --\n"
        "        # flow/dns/tls/quic/http/files/stats duplicate Zeek's own\n"
        "        # dns/conn/ssl logs and nothing reads them; trimming keeps the\n"
        "        # /var/log log2ram tmpfs from filling. Uncomment to restore.\n"
        "        #- http:\n"
        "        #- dns:\n"
        "        #- tls:\n"
        "        #- files:\n"
        "        #- drop:\n"
        "        #- smtp:\n"
        "        #- ftp\n"
        "        #- rdp\n"
        "        #- nfs\n"
        "        #- smb\n"
        "        #- tftp\n"
        "        #- ike\n"
        "        #- dcerpc\n"
        "        #- krb5\n"
        "        #- bittorrent-dht\n"
        "        #- snmp\n"
        "        #- rfb\n"
        "        #- sip\n"
        "        #- quic:\n"
        "        #- dhcp:\n"
        "        #- ssh\n"
        "        #- mqtt:\n"
        "        #- http2\n"
        "        #- pgsql:\n"
        "        #- stats:\n"
        "        #- flow\n"
        "        #- netflow\n"
    )
    with open(conf_file, 'w') as f:
        f.write(s[:start] + new_block + s[end:])
    print("  Applied: eve.json types trimmed to alert/anomaly")
PYEOF
OK "suricata.yaml: eve.json trimmed (alert/anomaly only)."

# Logrotate — live logs are on log2ram (${SURICATA_LOG_DIR}), rotated archives
# land on NVMe via olddir. `olddir` is the correct way to do this: logrotate
# manages the .1→.2→…→.14 rename chain in the archive dir itself. A plain
# `mv` in lastaction would overwrite yesterday's .1.gz on every rotation.
mkdir -p /var/lib/suricata/archive
chmod 755 /var/lib/suricata/archive
cat > /etc/logrotate.d/suricata <<EOF
${SURICATA_LOG_DIR}/*.log
${SURICATA_LOG_DIR}/*.json
{
	rotate 14
	daily
	missingok
	compress
	copytruncate
	sharedscripts
	olddir /var/lib/suricata/archive
	createolddir 0755 root root
	postrotate
		/bin/kill -HUP \$(cat /var/run/suricata.pid)
	endscript
}
EOF
OK "logrotate: ${SURICATA_LOG_DIR}/*.{log,json} → /var/lib/suricata/archive (rotate 14, daily)"

# ── 4. Fetch Emerging Threats Open rules ──────────────────────────────────────
echo ""
echo -e "${BOLD}Rules — Emerging Threats Open${RESET}"

mkdir -p /var/lib/suricata/rules

INFO "Fetching ET Open rules (this may take a moment)..."

# Capture suricata-update output and show only meaningful lines
suricata-update 2>&1 | \
    grep -E "(Loaded|Fetching|Writing|Enabled|Disabled|Created|rule files|rules)" | \
    while IFS= read -r line; do INFO "$line"; done || true

if [[ -f /var/lib/suricata/rules/suricata.rules ]]; then
    RULE_COUNT=$(grep -c '^alert' /var/lib/suricata/rules/suricata.rules 2>/dev/null) || RULE_COUNT=0
    OK "Rules loaded: ${RULE_COUNT} active rules."
else
    WARN "Rule file not found at /var/lib/suricata/rules/suricata.rules"
    INFO "Run manually after install: sudo suricata-update"
fi

# Custom local signatures — suricata.yaml lists local.rules in rule-files,
# so Suricata fails to start on a rebuild if this file is never installed.
if [[ -f "$SCRIPT_DIR/config/local.rules" ]]; then
    install -m 0644 "$SCRIPT_DIR/config/local.rules" /var/lib/suricata/rules/local.rules
    OK "local.rules installed ($(grep -c '^alert' /var/lib/suricata/rules/local.rules 2>/dev/null || echo 0) custom rules)."
fi

# ── 5. Deploy threshold config (suppresses stream engine noise) ───────────────
if [[ -f "$SCRIPT_DIR/config/threshold.config" ]]; then
    cp "$SCRIPT_DIR/config/threshold.config" /etc/suricata/threshold.config
    OK "threshold.config deployed (stream engine SIDs suppressed)."
fi

# ── 6. Install daily rule-update timer ────────────────────────────────────────
echo ""
echo -e "${BOLD}Daily Rule Update Timer${RESET}"

cp "$SCRIPT_DIR/systemd/suricata-update.service" /etc/systemd/system/
cp "$SCRIPT_DIR/systemd/suricata-update.timer"   /etc/systemd/system/
systemctl daemon-reload
systemctl enable suricata-update.timer
OK "suricata-update.timer: enabled  (daily at 06:00, before the 07:00 report)"

# ── 6. Enable and start Suricata ──────────────────────────────────────────────
echo ""
echo -e "${BOLD}Suricata Service${RESET}"

# Config validation (suricata -T does not require the interface to be up)
if suricata -T -c "$SURICATA_CONF" -l "$SURICATA_LOG_DIR" 2>/dev/null; then
    OK "Config validation: passed."
else
    WARN "Config validation returned warnings — check: sudo suricata -T -c $SURICATA_CONF"
fi

systemctl enable suricata
systemctl restart suricata
sleep 3

if systemctl is-active --quiet suricata; then
    OK "Suricata: running."
else
    FAIL "Suricata failed to start — check: journalctl -u suricata -n 50"
fi

echo ""
echo "────────────────────────────────────────────────────"
echo -e "${BOLD}Suricata IDS installation complete.${RESET}"
echo ""
echo "  Monitor alerts:  sudo tail -f ${SURICATA_LOG_DIR}/fast.log"
echo "  Full EVE JSON:   ${SURICATA_LOG_DIR}/eve.json"
echo "  Rule updates:    daily at 06:00 via suricata-update.timer"
echo "  Health check:    beaconbutty-health.sh"
echo ""
