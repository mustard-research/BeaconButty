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
# local.zeek does `@load ./arp-log`, so this is not optional: without it Zeek
# dies with "fatal error: can't find ./arp-log" and never starts. It had no
# install line and was only ever deployed by hand.
cp "$SCRIPT_DIR/config/zeek/site/arp-log.zeek" "$ZEEK_SITE/arp-log.zeek"

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

# The WAN NIC's default 512-descriptor RX ring overruns under router load
# (rx_resource_errors); size it up on every interface up, same mechanism.
install -m 755 "$SCRIPT_DIR/config/network-manager/99-bb-wan-ring" \
    /etc/NetworkManager/dispatcher.d/99-bb-wan-ring

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

# ── Shared Python library ─────────────────────────────────────────────────────
# bb_enrich is imported by summarize.sh, slow-cadence.py and the webapp, which
# each resolve it from here after trying their own repo checkout.
echo "Installing shared library..."
install -d -m 755 /usr/local/lib/beaconbutty
install -m 644 "$SCRIPT_DIR/lib/bb_enrich.py"          /usr/local/lib/beaconbutty/bb_enrich.py
# bb_fp holds the FP registry matchers and the DERP probe gate. summarize.sh and
# the slow-cadence scripts resolve it ONLY from here (no repo fallback), so a
# missing install line means the daily report can silently run a different gate
# from the webapp. It had none and was being deployed by hand.
install -m 644 "$SCRIPT_DIR/lib/bb_fp.py"              /usr/local/lib/beaconbutty/bb_fp.py
# bb_outages is imported by the webapp and executed as a CLI by healthcheck.sh
# and housekeeping.sh, so it needs the execute bit the other modules don't.
install -m 755 "$SCRIPT_DIR/lib/bb_outages.py"         /usr/local/lib/beaconbutty/bb_outages.py
# bb_wan_diag is executed by wan-watchdog.sh on every failing check. If it goes
# missing the watchdog still runs but classifies every outage as "unknown", so
# beaconbutty-health.sh asserts its presence rather than letting the diagnosis
# quietly degrade to nothing.
install -m 755 "$SCRIPT_DIR/lib/bb_wan_diag.py"        /usr/local/lib/beaconbutty/bb_wan_diag.py

# Display-only ASN owner aliases. Seeded once and never overwritten — this file
# is hand-edited on the box, so a reinstall must not discard local entries.
if [[ ! -f /var/lib/beaconbutty/org-aliases.json ]]; then
    install -m 664 "$SCRIPT_DIR/config/org-aliases.json" /var/lib/beaconbutty/org-aliases.json
fi

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
install -m 755 "$SCRIPT_DIR/scripts/stash-packages.sh" /usr/local/bin/beaconbutty-stash-packages.sh
install -m 755 "$SCRIPT_DIR/scripts/suricata-alert-check.sh" /usr/local/bin/beaconbutty-suricata-alert-check.sh
install -m 755 "$SCRIPT_DIR/scripts/bb-watchdog"      /usr/local/bin/bb-watchdog
install -m 755 "$SCRIPT_DIR/scripts/bb0-display.py"   /usr/local/bin/bb0-display.py
# These three had no install line and were being deployed by hand, so a repo
# change could sit unshipped indefinitely. They share the bb_enrich ladder
# above (ip-intel.py writes the cache that its shodan/whois tiers read).
install -m 755 "$SCRIPT_DIR/scripts/slow-cadence.py"  /usr/local/bin/beaconbutty-slow-cadence.py
install -m 755 "$SCRIPT_DIR/scripts/slow-cadence-digest.py" /usr/local/bin/beaconbutty-slow-cadence-digest.py
install -m 755 "$SCRIPT_DIR/scripts/ip-intel.py"      /usr/local/bin/beaconbutty-ip-intel.py
install -m 755 "$SCRIPT_DIR/scripts/bb0-led"          /usr/local/bin/bb0-led
install -m 755 "$SCRIPT_DIR/scripts/bb0-fan"          /usr/local/bin/bb0-fan
# wan-watchdog.sh had no install line at all and was being deployed by hand —
# the same gap the three scripts above were fixed for.
install -m 755 "$SCRIPT_DIR/scripts/wan-watchdog.sh"  /usr/local/bin/wan-watchdog.sh
# Nine more with the same gap, found 2026-09-20 by diffing every deployed file
# against the install lines. Each is named in a systemd unit's ExecStart, so on a
# fresh install those units failed with "No such file or directory" — the timers
# existed and did nothing. Sweep with:
#   for f in /usr/local/bin/beaconbutty-*; do grep -qr "$(basename "$f")" scripts/0*.sh || echo "$f"; done
install -m 755 "$SCRIPT_DIR/scripts/clickhouse-upgrade.sh"  /usr/local/bin/beaconbutty-clickhouse-upgrade.sh
install -m 755 "$SCRIPT_DIR/scripts/ja4db-refresh.sh"       /usr/local/bin/beaconbutty-ja4db-refresh.sh
install -m 755 "$SCRIPT_DIR/scripts/ja4-history-update.py"  /usr/local/bin/beaconbutty-ja4-history-update.py
install -m 755 "$SCRIPT_DIR/scripts/ja4-threat-check.py"    /usr/local/bin/beaconbutty-ja4-threat-check.py
install -m 755 "$SCRIPT_DIR/scripts/l2-alert-check.sh"      /usr/local/bin/beaconbutty-l2-alert-check.sh
install -m 755 "$SCRIPT_DIR/scripts/midsummer-fan-check.py" /usr/local/bin/beaconbutty-midsummer-fan-check.py
install -m 755 "$SCRIPT_DIR/scripts/pcap-watch.py"          /usr/local/bin/beaconbutty-pcap-watch.py
install -m 755 "$SCRIPT_DIR/scripts/teams-cidr-refresh.py"  /usr/local/bin/beaconbutty-teams-cidr-refresh.py
install -m 755 "$SCRIPT_DIR/scripts/teams-relay-check.py"   /usr/local/bin/beaconbutty-teams-relay-check.py
# Two more named in unit ExecStart lines with no install line. resolv-conf-guard
# is the mitigation from the 2026-07-01 blanked-resolv.conf incident, so a fresh
# install silently shipping without it is exactly the wrong failure.
install -m 755 "$SCRIPT_DIR/scripts/resolv-conf-guard.sh"   /usr/local/bin/resolv-conf-guard.sh
install -m 755 "$SCRIPT_DIR/scripts/tailscale-cert-renew.sh" /usr/local/bin/tailscale-cert-renew.sh

mkdir -p /var/lib/beaconbutty/reports
mkdir -p /var/lib/beaconbutty/outage-evidence
mkdir -p /var/lib/beaconbutty/backups
mkdir -p /var/log/beaconbutty
# State dir is written by BOTH root (timer scripts) and dm (webapp: FP
# registry via fp.sh, alert-config, domain-watch, teams config). All writers
# use atomic tmp+rename, which needs DIRECTORY write permission — group dm
# + setgid so either side can replace files regardless of file owner.
chgrp dm /var/lib/beaconbutty
chmod 2775 /var/lib/beaconbutty
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
    systemctl enable suricata-update.timer
else
    echo "  Skipping suricata-alert-check.timer — Suricata not installed."
fi

# These twelve were enabled by hand on bb0 and never added here, so a fresh
# install copied the units in and left every one of them inert: no IP intel, no
# JA4 refresh/history/threat checks, no slow-cadence detection, no Teams-relay
# detection, no weekly archive, no TLS renewal. Found 2026-09-20 by diffing
# `systemctl is-enabled` against the enable lines in this script.
#
# Plain `enable`, NOT `--now`, for everything with Persistent=true: a Persistent
# timer started with no stamp file treats itself as having missed its window and
# fires immediately, so `--now` here would kick off every catch-up job at once on
# a freshly built Pi — including beaconbutty-archive, which stops ClickHouse for
# ~16 minutes. They arm on the next boot, which a fresh install gets anyway from
# 07_router_mode.sh.
systemctl enable beaconbutty-archive.timer
systemctl enable beaconbutty-ip-intel.timer
systemctl enable beaconbutty-ja4db-refresh.timer
systemctl enable beaconbutty-ja4-history.timer
systemctl enable beaconbutty-slow-cadence.timer
systemctl enable beaconbutty-slow-cadence-digest.timer
systemctl enable beaconbutty-teams-cidr-refresh.timer
systemctl enable beaconbutty-teams-relay-check.timer
systemctl enable tailscale-cert-renew.timer
# Persistent=no on these two, so there is no catch-up burst to avoid.
systemctl enable --now beaconbutty-ja4-threat-check.timer
systemctl enable --now beaconbutty-l2-alert-check.timer
#
# Deliberately NOT enabled: beaconbutty-midsummer-fan-check.timer is a one-shot
# for 2026-07-15 that has already passed. Persistent=true means enabling it now
# would fire it immediately on every new install, for an event that is over.

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
# ── JA4 fingerprinting package ────────────────────────────────────────────────
# Supplies ja4/ja4s/ja4h/ja4x/ja4ssh/ja4d/ja4l/ja4t. Without it there are no
# ja4*.log streams, so /network's JA4 panels, beaconbutty-ja4-threat-check and
# beaconbutty-ja4-history all have nothing to read. Script-only (no compiled
# plugin), so it survives a Zeek major upgrade untouched.
#
# Licensing: the Zeek package is BSD-3. JA4+ carries FoxIO licence terms for
# commercial redistribution — see docs/development/licensing.md. We install it
# here, we do not vendor it.
if command -v "$ZEEK_PREFIX/bin/zkg" &>/dev/null; then
    echo "Installing the JA4 Zeek package..."
    "$ZEEK_PREFIX/bin/zkg" autoconfig --force >/dev/null 2>&1 || true
    if "$ZEEK_PREFIX/bin/zkg" install --force zeek/foxio/ja4; then
        echo "  JA4 installed."
    else
        echo "  WARNING: JA4 install failed — ja4*.log will be absent and the"
        echo "           JA4 panels and timers will have no data."
        echo "           Retry: sudo $ZEEK_PREFIX/bin/zkg install zeek/foxio/ja4"
    fi
else
    echo "  WARNING: zkg not found — skipping JA4 package."
fi

echo "Deploying Zeek (this runs zeekctl deploy)..."
"$ZEEK_PREFIX/bin/zeekctl" deploy

echo ""
echo "Configuration applied."
