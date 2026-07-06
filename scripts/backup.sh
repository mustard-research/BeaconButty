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

# Snapshots contain AWS credentials, ACME account keys and the Slack token.
# Dir is setgid so files inherit its group (the webapp user's group, for the
# Backup page's download links); no access for other users.
umask 027
install -d -m 2750 "$BACKUP_DIR"

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
    /usr/local/bin/ \
    /usr/local/sbin/reboot \
    /etc/systemd/system/ \
    /etc/NetworkManager/system-connections/bb-lan.nmconnection \
    /etc/NetworkManager/system-connections/bb-wan.nmconnection \
    /etc/NetworkManager/dispatcher.d/99-bb-capture-offload \
    /etc/beaconbutty/ \
    /etc/apt/apt.conf.d/52beaconbutty-autoupdate \
    /etc/ssl/tailscale/ \
    /var/spool/cron/crontabs/root \
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
    /etc/sudoers.d/ \
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
