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

# Persist across reboots via /etc/network/interfaces.d/
mkdir -p /etc/network/interfaces.d
IFACE_CONF="/etc/network/interfaces.d/${CAPTURE_IFACE}"
cat > "$IFACE_CONF" <<EOF
# BeaconButty capture interface — no IP address, promiscuous mode
auto ${CAPTURE_IFACE}
iface ${CAPTURE_IFACE} inet manual
    up ip link set \$IFACE promisc on
    up ethtool -K \$IFACE rx off tx off sg off tso off ufo off gso off gro off lro off || true
    up ip link set \$IFACE up
EOF

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

mkdir -p /var/lib/beaconbutty/reports
mkdir -p /var/log/beaconbutty

# ── Systemd units ─────────────────────────────────────────────────────────────
echo "Installing systemd units..."
cp "$SCRIPT_DIR/systemd/"*.service \
   "$SCRIPT_DIR/systemd/"*.timer \
   /etc/systemd/system/

systemctl daemon-reload
systemctl enable zeek
systemctl enable --now rita-analyze.timer
systemctl enable --now beacon-report.timer
systemctl enable --now beaconbutty-housekeeping.timer
systemctl enable --now beaconbutty-assets.timer

# ── Log rotation ──────────────────────────────────────────────────────────────
cat > /etc/logrotate.d/beaconbutty <<'EOF'
# BeaconButty operational logs (on log2ram — weekly, keep 8 weeks)
/var/log/beaconbutty/*.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
}

# dnsmasq query log (on NVMe — daily, keep 30 days; signal dnsmasq to reopen)
/var/lib/beaconbutty/logs/dnsmasq.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
    postrotate
        killall -USR2 dnsmasq 2>/dev/null || true
    endscript
}
EOF

# ── Deploy Zeek ───────────────────────────────────────────────────────────────
echo "Deploying Zeek (this runs zeekctl deploy)..."
"$ZEEK_PREFIX/bin/zeekctl" deploy

echo ""
echo "Configuration applied."
