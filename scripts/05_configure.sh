#!/usr/bin/env bash
set -euo pipefail

# Apply all configuration files and set up systemd timers.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ZEEK_PREFIX="${ZEEK_PREFIX:-/opt/zeek}"
CAPTURE_IFACE="${CAPTURE_IFACE:-eth1}"
LOCAL_NETWORKS="${LOCAL_NETWORKS:-10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}"

ZEEK_ETC="$ZEEK_PREFIX/etc"
ZEEK_SITE="$ZEEK_PREFIX/share/zeek/site"

# ── Zeek configuration ────────────────────────────────────────────────────────
echo "Configuring Zeek..."

cp "$SCRIPT_DIR/config/zeek/node.cfg"    "$ZEEK_ETC/node.cfg"
cp "$SCRIPT_DIR/config/zeek/zeekctl.cfg" "$ZEEK_ETC/zeekctl.cfg"
cp "$SCRIPT_DIR/config/zeek/site/local.zeek" "$ZEEK_SITE/local.zeek"

# Inject the actual capture interface name into node.cfg
sed -i "s/__CAPTURE_IFACE__/$CAPTURE_IFACE/" "$ZEEK_ETC/node.cfg"

# Build networks.cfg from the LOCAL_NETWORKS variable
{
    echo "# BeaconButty: local network prefixes"
    echo "# Connections FROM these addresses are treated as internal."
    echo ""
    IFS=',' read -ra nets <<< "$LOCAL_NETWORKS"
    for net in "${nets[@]}"; do
        printf "%-22s Private\n" "$(echo "$net" | tr -d ' ')"
    done
} > "$ZEEK_ETC/networks.cfg"

echo "  Zeek will watch interface: $CAPTURE_IFACE"
echo "  Local networks:"
grep -v '^#\|^$' "$ZEEK_ETC/networks.cfg" | sed 's/^/    /'

# ── Capture interface setup ───────────────────────────────────────────────────
echo "Configuring capture interface $CAPTURE_IFACE..."

# Promiscuous mode: capture all frames, not just those addressed to us
ip link set "$CAPTURE_IFACE" promisc on || \
    echo "  Warning: could not set promisc on $CAPTURE_IFACE (may not exist yet)"

# Disable hardware offloading features that can cause Zeek to see
# reassembled/incomplete packets rather than the wire-level traffic.
ethtool -K "$CAPTURE_IFACE" \
    rx off tx off sg off tso off ufo off gso off gro off lro off 2>/dev/null || \
    echo "  Warning: ethtool not fully supported on $CAPTURE_IFACE (common on USB NICs)"

# Persist across reboots. The interface is NetworkManager-managed, so
# ifupdown stanzas under /etc/network/interfaces.d/ never apply — use an
# NM dispatcher hook instead.
install -m 755 "$SCRIPT_DIR/config/network-manager/99-bb-capture-offload" \
    /etc/NetworkManager/dispatcher.d/99-bb-capture-offload

# ── RITA configuration ────────────────────────────────────────────────────────
echo "Configuring RITA..."
mkdir -p /etc/rita /etc/rita/threat_intel_feeds
cp "$SCRIPT_DIR/config/rita/config.hjson"             /etc/rita/config.hjson
cp "$SCRIPT_DIR/config/rita/http_extensions_list.csv" /etc/rita/http_extensions_list.csv

# Write ClickHouse connection env file (sourced by systemd units and scripts)
cat > /etc/rita/env <<'EOF'
DB_ADDRESS=localhost:9000
CLICKHOUSE_USERNAME=default
CLICKHOUSE_PASSWORD=
LOG_LEVEL=1
CONFIG_DIR=/etc/rita
CONFIG_FILE=/etc/rita/config.hjson
LOGGING_ENABLED=false
EOF
chmod 640 /etc/rita/env

# RITA v5 also looks for a .env file in its working directory
cp /etc/rita/env /etc/rita/.env
chmod 640 /etc/rita/.env

# ── Analysis and report scripts ───────────────────────────────────────────────
echo "Installing helper scripts..."
install -m 755 "$SCRIPT_DIR/scripts/analyze.sh"        /usr/local/bin/rita-analyze.sh
install -m 755 "$SCRIPT_DIR/scripts/report.sh"         /usr/local/bin/beacon-report.sh
install -m 755 "$SCRIPT_DIR/scripts/housekeeping.sh"   /usr/local/bin/beaconbutty-housekeeping.sh
install -m 755 "$SCRIPT_DIR/scripts/healthcheck.sh"    /usr/local/bin/beaconbutty-health.sh
install -m 755 "$SCRIPT_DIR/scripts/morning-check.sh"  /usr/local/bin/beaconbutty-morning.sh
install -m 755 "$SCRIPT_DIR/scripts/harden.sh"         /usr/local/bin/beaconbutty-harden.sh
install -m 755 "$SCRIPT_DIR/scripts/summarize.sh"     /usr/local/bin/beaconbutty-summary.sh
install -m 755 "$SCRIPT_DIR/scripts/assets.sh"        /usr/local/bin/beaconbutty-assets.sh
install -m 755 "$SCRIPT_DIR/scripts/fp.sh"            /usr/local/bin/beaconbutty-fp.sh
install -m 755 "$SCRIPT_DIR/scripts/backup.sh"        /usr/local/bin/beaconbutty-backup.sh
install -m 755 "$SCRIPT_DIR/scripts/alert.sh"         /usr/local/bin/beaconbutty-alert.sh
install -m 755 "$SCRIPT_DIR/scripts/suricata-alert-check.sh" /usr/local/bin/beaconbutty-suricata-alert-check.sh
install -m 755 "$SCRIPT_DIR/scripts/bb-watchdog"      /usr/local/bin/bb-watchdog
install -m 755 "$SCRIPT_DIR/scripts/bb0-display.py"   /usr/local/bin/bb0-display.py
install -m 755 "$SCRIPT_DIR/scripts/bb0-led"          /usr/local/bin/bb0-led
install -m 755 "$SCRIPT_DIR/scripts/bb0-fan"          /usr/local/bin/bb0-fan

mkdir -p /var/lib/beaconbutty/reports
mkdir -p /var/lib/beaconbutty/backups
mkdir -p /var/log/beaconbutty
# alerts.log written by both root (systemd) and dm (interactive) — owned by dm
touch /var/log/beaconbutty/alerts.log
chown dm:dm /var/log/beaconbutty/alerts.log
# alert-config.json written by webapp (runs as dm)
touch /var/lib/beaconbutty/alert-config.json
chown dm:dm /var/lib/beaconbutty/alert-config.json

# ── GeoIP config ──────────────────────────────────────────────────────────────
if [[ -f "$SCRIPT_DIR/config/GeoIP.conf" ]]; then
    install -m 640 "$SCRIPT_DIR/config/GeoIP.conf" /etc/GeoIP.conf
    mkdir -p /var/lib/GeoIP
    geoipupdate || echo "  Warning: geoipupdate failed — check /etc/GeoIP.conf credentials"
else
    echo "  Warning: config/GeoIP.conf not found — GeoIP lookups will be unavailable"
    echo "           Copy your MaxMind GeoIP.conf to /etc/GeoIP.conf and run: geoipupdate"
fi

# ── Sudoers ───────────────────────────────────────────────────────────────────
echo "Installing sudoers rules..."
cat > /etc/sudoers.d/bb-health <<'EOF'
# BeaconButty health check — webapp runs as dm, needs root to read system state
dm ALL=(root) NOPASSWD: /usr/local/bin/beaconbutty-health.sh
EOF
chmod 440 /etc/sudoers.d/bb-health

cat > /etc/sudoers.d/bb-backup <<'EOF'
# BeaconButty backup — webapp triggers config backup and rpi-clone
dm ALL=(root) NOPASSWD: /usr/local/bin/beaconbutty-backup.sh
dm ALL=(root) NOPASSWD: /usr/local/bin/rpi-clone *
dm ALL=(root) NOPASSWD: /usr/bin/rpi-clone *
EOF
chmod 440 /etc/sudoers.d/bb-backup

# ── Systemd units ─────────────────────────────────────────────────────────────
echo "Installing systemd units..."
cp "$SCRIPT_DIR/systemd/"*.service \
   "$SCRIPT_DIR/systemd/"*.timer \
   /etc/systemd/system/

systemctl daemon-reload
systemctl enable zeek
systemctl enable --now bb-graphs.service
systemctl enable --now bb-watchdog.service
# bb0-display requires Pironman5 (/opt/pironman5/venv) — skip if not installed
if [[ -x /opt/pironman5/venv/bin/python3 ]]; then
    systemctl enable --now bb0-display.service
else
    echo "  Skipping bb0-display.service — Pironman5 not installed."
    echo "  Run manage.sh > Installation > Install Pironman5, then:"
    echo "    sudo systemctl enable --now bb0-display.service"
fi
systemctl enable --now rita-analyze.timer
systemctl enable --now beacon-report.timer
systemctl enable --now beaconbutty-housekeeping.timer
systemctl enable --now beaconbutty-assets.timer
systemctl enable --now beaconbutty-backup.timer
systemctl enable --now wan-watchdog.timer
systemctl enable --now beaconbutty-health.timer
# Suricata alert check — only enable if Suricata is installed
if command -v suricata &>/dev/null; then
    systemctl enable --now suricata-alert-check.timer
else
    echo "  Skipping suricata-alert-check.timer — Suricata not installed."
fi

# zeek-cron.timer — supervises Zeek workers (zeek.service is a oneshot
# wrapper whose "active" state means nothing after boot; zeekctl cron is
# what actually restarts crashed workers).
systemctl enable --now zeek-cron.timer

# ── Log rotation ──────────────────────────────────────────────────────────────
cat > /etc/logrotate.d/beaconbutty <<'EOF'
# BeaconButty operational logs (on log2ram — weekly, keep 8 weeks).
# copytruncate: bb-pcap-watch appends to its log via an open fd for the
# daemon's whole lifetime — a rename-rotate would leave it writing to a
# deleted inode (logs lost, tmpfs space invisibly held) until restart.
/var/log/beaconbutty/*.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    copytruncate
}

# dnsmasq query log (live on log2ram; archives live on NVMe via olddir —
# lastaction-mv would silently overwrite yesterday's .1.gz on every rotation)
/var/log/dnsmasq.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
    copytruncate
    olddir /var/lib/beaconbutty/logs
    createolddir 0755 root root
}
EOF

# ── Deploy Zeek ───────────────────────────────────────────────────────────────
echo "Deploying Zeek (this runs zeekctl deploy)..."
"$ZEEK_PREFIX/bin/zeekctl" deploy

echo ""
echo "Configuration applied."
