#!/usr/bin/env bash
# beaconbutty-backup.sh — config snapshot
#
# Creates a dated tar.gz of all system files changed during BeaconButty setup.
# Keeps the last 14 daily snapshots (~2 weeks, matches Zeek/ClickHouse
# retention windows). Run by a systemd timer or triggered manually from
# the web UI.
#
# Usage:  sudo beaconbutty-backup.sh

set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root: sudo $0"; exit 1; }

BACKUP_DIR="/var/lib/beaconbutty/backups"
KEEP=14
STAMP=$(date +%Y-%m-%d)
OUT="${BACKUP_DIR}/config-${STAMP}.tar.gz"
PKG="${BACKUP_DIR}/packages-${STAMP}.txt"

mkdir -p "$BACKUP_DIR"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

log "BeaconButty config snapshot — ${STAMP}"
log "Output: ${OUT}"

# ── Config tar ────────────────────────────────────────────────────────────────
tar -czf "$OUT" \
    --ignore-failed-read \
    --warning=no-file-changed \
    --exclude='home/dm/BeaconButty/.git' \
    --exclude='home/dm/BeaconButty/beacon-1.png' \
    --exclude='home/dm/BeaconButty/beacon-header.png' \
    --exclude='home/dm/BeaconButty/screenshots' \
    --exclude='home/dm/BeaconButty/brochure.pdf' \
    --exclude='home/dm/BeaconButty/network-diagram.pdf' \
    --exclude='home/dm/BeaconButty/GeoLite2-*.tar.gz' \
    --exclude='*/__pycache__' \
    --exclude='*/.DS_Store' \
    /boot/firmware/config.txt \
    /boot/firmware/cmdline.txt \
    /usr/local/bin/bb0-display.py \
    /usr/local/bin/bb0-fan \
    /usr/local/bin/bb0-led \
    /usr/local/bin/bb-watchdog \
    /usr/local/bin/beaconbutty-alert.sh \
    /usr/local/bin/beaconbutty-assets.sh \
    /usr/local/bin/beaconbutty-backup.sh \
    /usr/local/bin/beaconbutty-fp.sh \
    /usr/local/bin/beaconbutty-harden.sh \
    /usr/local/bin/beaconbutty-health.sh \
    /usr/local/bin/beaconbutty-housekeeping.sh \
    /usr/local/bin/beaconbutty-morning.sh \
    /usr/local/bin/beaconbutty-summary.sh \
    /usr/local/bin/beacon-report.sh \
    /usr/local/bin/rita-analyze.sh \
    /usr/local/bin/wan-watchdog.sh \
    /etc/systemd/system/bb0-display.service \
    /etc/systemd/system/bb-graphs.service \
    /etc/systemd/system/bb-watchdog.service \
    /etc/systemd/system/beaconbutty-assets.service \
    /etc/systemd/system/beaconbutty-assets.timer \
    /etc/systemd/system/beaconbutty-backup.service \
    /etc/systemd/system/beaconbutty-backup.timer \
    /etc/systemd/system/beaconbutty-health.service \
    /etc/systemd/system/beaconbutty-health.timer \
    /etc/systemd/system/beaconbutty-housekeeping.service \
    /etc/systemd/system/beaconbutty-housekeeping.timer \
    /etc/systemd/system/beacon-report.service \
    /etc/systemd/system/beacon-report.timer \
    /etc/systemd/system/iptables.service \
    /etc/systemd/system/ip6tables.service \
    /etc/systemd/system/log2ram.service \
    /etc/systemd/system/log2ram-daily.service \
    /etc/systemd/system/log2ram-daily.timer \
    /etc/systemd/system/rita-analyze.service \
    /etc/systemd/system/rita-analyze.timer \
    /etc/systemd/system/suricata-alert-check.service \
    /etc/systemd/system/suricata-alert-check.timer \
    /etc/systemd/system/suricata-update.service \
    /etc/systemd/system/suricata-update.timer \
    /etc/systemd/system/wan-watchdog.service \
    /etc/systemd/system/wan-watchdog.timer \
    /etc/systemd/system/zeek.service \
    /etc/NetworkManager/system-connections/bb-lan.nmconnection \
    /etc/NetworkManager/system-connections/bb-wan.nmconnection \
    /etc/network/interfaces.d/ \
    /etc/dhcpcd.conf \
    /etc/dnsmasq.d/beaconbutty.conf \
    /etc/iptables/rules.v4 \
    /etc/iptables/rules.v6 \
    /etc/rita/ \
    /etc/suricata/suricata.yaml \
    /etc/suricata/threshold.config \
    /etc/clickhouse-server/config.d/ \
    /etc/GeoIP.conf \
    /etc/fail2ban/jail.d/beaconbutty-ssh.conf \
    /etc/sudoers.d/bb-health \
    /etc/sudoers.d/bb-backup \
    /etc/sudoers.d/beaconbutty-suricatasc \
    /etc/sysctl.d/99-beaconbutty-capture.conf \
    /etc/sysctl.d/99-beaconbutty-hardening.conf \
    /etc/sysctl.d/99-beaconbutty-router.conf \
    /etc/ssh/sshd_config \
    /etc/log2ram.conf \
    /etc/letsencrypt/accounts/ \
    /etc/letsencrypt/cli.ini \
    /etc/letsencrypt/renewal/ \
    /etc/letsencrypt/renewal-hooks/ \
    /root/.aws/credentials \
    /var/lib/beaconbutty/false-positives.conf \
    /var/lib/beaconbutty/assets.json \
    /var/lib/beaconbutty/slack-config.json \
    /home/dm/BeaconButty/ \
    /opt/zeek/share/zeek/site/local.zeek \
    2>/dev/null || log "WARNING: tar exited non-zero — some files may be missing from the archive (check paths above)"

# ── Package list ──────────────────────────────────────────────────────────────
log "Saving package list: ${PKG}"
dpkg --get-selections > "$PKG"

# ── Rotation ──────────────────────────────────────────────────────────────────
log "Rotating old snapshots (keeping last ${KEEP})..."
ls -t "${BACKUP_DIR}"/config-*.tar.gz   2>/dev/null | tail -n +$((KEEP+1)) | xargs -r rm -f
ls -t "${BACKUP_DIR}"/packages-*.txt    2>/dev/null | tail -n +$((KEEP+1)) | xargs -r rm -f

SIZE=$(du -sh "$OUT" 2>/dev/null | cut -f1 || echo "?")
COUNT=$(ls "${BACKUP_DIR}"/config-*.tar.gz 2>/dev/null | wc -l)
log "Done. Size: ${SIZE}  Snapshots on disk: ${COUNT}"
