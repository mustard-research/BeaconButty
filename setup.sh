#!/usr/bin/env bash
set -euo pipefail

# BeaconButty - Network Beacon Detector
# Zeek + RITA on Raspberry Pi 4/5 (64-bit ARM)
#
# Hardware requirements:
#   - Raspberry Pi 4 or 5, minimum 4GB RAM (8GB recommended)
#   - 64-bit Raspberry Pi OS (Debian Bookworm) or Ubuntu 22.04/24.04 arm64
#   - Capture interface on a SPAN/mirror port (see README for network setup)
#   - Management interface for SSH access
#   - USB SSD strongly recommended over SD card for log storage
#
# Default interface assumptions:
#   eth0  = management (SSH access, keep this reachable)
#   eth1  = capture   (USB-to-Ethernet on SPAN port, no IP needed)
#
# Override before running:
#   CAPTURE_IFACE=enx001122334455 sudo -E ./setup.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Configuration ──────────────────────────────────────────────────────────────
export CAPTURE_IFACE="${CAPTURE_IFACE:-eth1}"
export MGMT_IFACE="${MGMT_IFACE:-eth0}"
export ZEEK_PREFIX="${ZEEK_PREFIX:-/opt/zeek}"
export LOG_DIR="${LOG_DIR:-/var/log/zeek}"
export RITA_DB_NAME="${RITA_DB_NAME:-beaconbutty}"
export LOCAL_NETWORKS="${LOCAL_NETWORKS:-10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}"
# ──────────────────────────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    echo "Error: run as root   sudo ./setup.sh"
    echo "       or with env:  CAPTURE_IFACE=eth1 sudo -E ./setup.sh"
    exit 1
fi

ARCH=$(uname -m)
if [[ "$ARCH" != "aarch64" ]]; then
    echo "Error: requires a 64-bit ARM system (aarch64), got: $ARCH"
    echo "Enable 64-bit mode: add 'arm_64bit=1' to /boot/firmware/config.txt and reboot."
    exit 1
fi

echo "═══════════════════════════════════════════════════════"
echo "  BeaconButty — Network Beacon Detector"
echo "═══════════════════════════════════════════════════════"
echo "  Capture interface : $CAPTURE_IFACE"
echo "  Management iface  : $MGMT_IFACE"
echo "  Zeek install path : $ZEEK_PREFIX"
echo "  Log directory     : $LOG_DIR"
echo "  RITA database     : $RITA_DB_NAME"
echo "  Local networks    : $LOCAL_NETWORKS"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "  NOTE: Zeek may compile from source — allow 45-90 minutes."
echo ""
read -r -p "  Proceed? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

for script in \
    scripts/01_system_deps.sh \
    scripts/02_install_zeek.sh \
    scripts/03_install_clickhouse.sh \
    scripts/04_install_rita.sh \
    scripts/05_configure.sh
do
    echo ""
    echo "── $script ──────────────────────────────────────────"
    bash "$SCRIPT_DIR/$script"
done

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Setup complete!"
echo ""
echo "  Check Zeek status  :  zeekctl status"
echo "  Run analysis now   :  /usr/local/bin/rita-analyze.sh"
echo "  View beacon report :  /usr/local/bin/beacon-report.sh"
echo ""
echo "  Systemd timers (auto-run hourly/daily):"
echo "    systemctl status rita-analyze.timer"
echo "    systemctl status beacon-report.timer"
echo ""
echo "  ── Next step: choose a network capture mode ────────"
echo "  Router mode (Pi does NAT, full internal IP visibility):"
echo "    sudo -E ./scripts/07_router_mode.sh"
echo "═══════════════════════════════════════════════════════"
