#!/usr/bin/env bash
# beaconbutty-backup-archive.sh — full-rootfs snapshot (config + data + logs)
#
# Creates a dated tar.gz of the entire rootfs + /boot/firmware, excluding
# pseudo-filesystems and volatile paths. ClickHouse is stopped for the
# duration of the tar to guarantee a consistent snapshot of /var/lib/clickhouse.
#
# Output:  /var/lib/beaconbutty/backups/archive-YYYY-MM-DD.tar.gz
# Retention: last 4 archives kept (~4 weeks at weekly cadence).
#
# Usage:   sudo beaconbutty-backup-archive.sh
#
# Restore: see RESTORE.md Option C.

set -uo pipefail
[[ $EUID -ne 0 ]] && { echo "Run as root: sudo $0"; exit 1; }

BACKUP_DIR="/var/lib/beaconbutty/backups"
KEEP=4
STAMP=$(date +%Y-%m-%d)
OUT="${BACKUP_DIR}/archive-${STAMP}.tar.gz"
LOCK="/var/lock/beaconbutty-archive.lock"

mkdir -p "$BACKUP_DIR"

# Prevent overlapping runs (manual webapp trigger + weekly timer)
exec 200>"$LOCK"
if ! flock -n 200; then
    echo "Another archive run is already in progress — exiting."
    exit 0
fi

log() { echo "[$(date '+%H:%M:%S')] $*"; }

log "BeaconButty full archive — ${STAMP}"
log "Output: ${OUT}"

# ── Stop ClickHouse for a consistent snapshot ────────────────────────────────
CH_WAS_RUNNING=0
if systemctl is-active --quiet clickhouse-server; then
    CH_WAS_RUNNING=1
    log "Stopping clickhouse-server for consistent snapshot..."
    systemctl stop clickhouse-server
fi

restart_clickhouse() {
    if [[ $CH_WAS_RUNNING -eq 1 ]]; then
        log "Restarting clickhouse-server..."
        systemctl start clickhouse-server || log "WARNING: failed to restart clickhouse-server"
    fi
}
trap restart_clickhouse EXIT

# ── Create archive ───────────────────────────────────────────────────────────
log "Creating archive (this may take several minutes)..."
tar -czf "$OUT" \
    --numeric-owner \
    --xattrs \
    --one-file-system \
    --ignore-failed-read \
    --warning=no-file-changed \
    --exclude="${BACKUP_DIR}" \
    --exclude='/var/cache/apt/archives/*.deb' \
    --exclude='/home/dm/BeaconButty/.git' \
    --exclude='/home/dm/BeaconButty/screenshots' \
    --exclude='/home/dm/BeaconButty/beacon-1.png' \
    --exclude='/home/dm/BeaconButty/beacon-header.png' \
    --exclude='/home/dm/BeaconButty/brochure.pdf' \
    --exclude='/home/dm/BeaconButty/network-diagram.pdf' \
    --exclude='/home/dm/BeaconButty/GeoLite2-*.tar.gz' \
    --exclude='*/__pycache__' \
    --exclude='*/.DS_Store' \
    --exclude='*.swp' \
    -- \
    / \
    /boot/firmware \
    /var/log \
    2>&1 | grep -v 'socket ignored' || true

TAR_RC=${PIPESTATUS[0]}
if [[ $TAR_RC -ne 0 && $TAR_RC -ne 1 ]]; then
    log "ERROR: tar exited with code ${TAR_RC}"
    exit $TAR_RC
fi

# ── Restart ClickHouse ───────────────────────────────────────────────────────
restart_clickhouse
trap - EXIT

# ── Rotation ─────────────────────────────────────────────────────────────────
log "Rotating old archives (keeping last ${KEEP})..."
ls -t "${BACKUP_DIR}"/archive-*.tar.gz 2>/dev/null | tail -n +$((KEEP+1)) | xargs -r rm -f

SIZE=$(du -sh "$OUT" 2>/dev/null | cut -f1 || echo "?")
COUNT=$(ls "${BACKUP_DIR}"/archive-*.tar.gz 2>/dev/null | wc -l)
log "Done. Size: ${SIZE}  Archives on disk: ${COUNT}"
