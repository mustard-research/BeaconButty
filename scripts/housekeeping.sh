#!/usr/bin/env bash
set -euo pipefail

# housekeeping.sh
#
# Daily storage housekeeping for BeaconButty.
# Removes old Zeek log directories and RITA datasets beyond the retention window.
# Called by beaconbutty-housekeeping.timer each morning after the daily report.

ZEEK_LOG_DIR="${LOG_DIR:-/var/log/zeek}"
RITA_DB_PREFIX="${RITA_DB_NAME:-beaconbutty}"
RETAIN_DAYS="${RETAIN_DAYS:-30}"
LOGFILE="/var/log/beaconbutty/housekeeping.log"

# Load ClickHouse connection variables (needed for rita delete)
[[ -f /etc/rita/env ]] && source /etc/rita/env
export DB_ADDRESS="${DB_ADDRESS:-localhost:9000}"
export CLICKHOUSE_USERNAME="${CLICKHOUSE_USERNAME:-default}"
export CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-}"

mkdir -p /var/log/beaconbutty
exec >> "$LOGFILE" 2>&1

echo ""
echo "=== housekeeping started: $(date --iso-8601=seconds) ==="
echo "    Retention window : ${RETAIN_DAYS} days"

CUTOFF=$(date --date="${RETAIN_DAYS} days ago" +%Y%m%d)

# ── Zeek log directories ──────────────────────────────────────────────────────
echo ""
echo "-- Zeek logs under $ZEEK_LOG_DIR --"

ZEEK_DELETED=0
while IFS= read -r dir; do
    # Directory names are YYYY-MM-DD; strip dashes for numeric comparison
    dir_date=$(basename "$dir" | tr -d '-')
    if [[ "$dir_date" -lt "$CUTOFF" ]]; then
        size=$(du -sh "$dir" 2>/dev/null | cut -f1 || echo '?')
        echo "  Deleting $dir  ($size)"
        rm -rf "$dir"
        (( ZEEK_DELETED++ )) || true
    fi
done < <(find "$ZEEK_LOG_DIR" \
    -maxdepth 1 -mindepth 1 \
    -type d \
    -name '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]' \
    | sort)

echo "  Zeek directories deleted: $ZEEK_DELETED"

# ── RITA datasets ─────────────────────────────────────────────────────────────
echo ""
echo "-- RITA datasets --"

RITA_DELETED=0
if command -v rita &>/dev/null; then
    # rita looks for .env in the current directory — must run from /etc/rita
    while IFS= read -r db; do
        # Dataset names are beaconbutty_YYYYMMDD
        db_date="${db#${RITA_DB_PREFIX}_}"
        if [[ "$db_date" =~ ^[0-9]{8}$ ]] && [[ "$db_date" -lt "$CUTOFF" ]]; then
            echo "  Deleting RITA dataset: $db"
            if (cd /etc/rita && rita delete --non-interactive "$db" 2>/dev/null); then
                (( RITA_DELETED++ )) || true
            else
                echo "  Warning: failed to delete $db"
            fi
        fi
    done < <((cd /etc/rita && rita list 2>/dev/null) | grep -oP "${RITA_DB_PREFIX}_[0-9]{8}" | sort)
else
    echo "  rita not found — skipping dataset cleanup"
fi

echo "  RITA datasets deleted: $RITA_DELETED"

# ── Suricata rotated logs ─────────────────────────────────────────────────────
SURICATA_LOG_DIR="/var/log/suricata"

if command -v suricata &>/dev/null && [[ -d "$SURICATA_LOG_DIR" ]]; then
    echo ""
    echo "-- Suricata logs under $SURICATA_LOG_DIR --"

    SURI_DELETED=0
    while IFS= read -r f; do
        size=$(du -sh "$f" 2>/dev/null | cut -f1 || echo '?')
        echo "  Deleting $f  ($size)"
        rm -f "$f"
        (( SURI_DELETED++ )) || true
    done < <(find "$SURICATA_LOG_DIR" \
        -maxdepth 1 \
        -type f \
        \( -name "*.log.*" -o -name "*.json.*" \) \
        -mtime +"$RETAIN_DAYS" \
        2>/dev/null | sort)

    echo "  Suricata old log files deleted: $SURI_DELETED"
fi

# ── Beacon reports ───────────────────────────────────────────────────────────
REPORTS_DIR="/var/lib/beaconbutty/reports"
echo ""
echo "-- Beacon reports under $REPORTS_DIR --"

REPORTS_DELETED=0
while IFS= read -r f; do
    # Filenames are beacon-report-YYYYMMDD.txt
    file_date=$(basename "$f" | grep -oP '\d{8}')
    if [[ "$file_date" -lt "$CUTOFF" ]]; then
        echo "  Deleting $f"
        rm -f "$f"
        (( REPORTS_DELETED++ )) || true
    fi
done < <(find "$REPORTS_DIR" -maxdepth 1 -type f -name 'beacon-report-*.txt' | sort)

echo "  Beacon reports deleted: $REPORTS_DELETED"

# ── dnsmasq rotated logs ──────────────────────────────────────────────────────
DNSMASQ_LOG_DIR="/var/lib/beaconbutty/logs"  # archives only; live log is on log2ram
echo ""
echo "-- dnsmasq logs under $DNSMASQ_LOG_DIR --"

DNSMASQ_DELETED=0
while IFS= read -r f; do
    size=$(du -sh "$f" 2>/dev/null | cut -f1 || echo '?')
    echo "  Deleting $f  ($size)"
    rm -f "$f"
    (( DNSMASQ_DELETED++ )) || true
done < <(find "$DNSMASQ_LOG_DIR" \
    -maxdepth 1 \
    -type f \
    -name "dnsmasq.log.*.gz" \
    -mtime +"$RETAIN_DAYS" \
    2>/dev/null | sort)

echo "  dnsmasq old log files deleted: $DNSMASQ_DELETED"

# ── Backups ───────────────────────────────────────────────────────────────────
BACKUPS_DIR="/var/lib/beaconbutty/backups"
echo ""
echo "-- Backups under $BACKUPS_DIR --"

BACKUPS_DELETED=0
while IFS= read -r f; do
    echo "  Deleting $f"
    rm -f "$f"
    (( BACKUPS_DELETED++ )) || true
done < <(find "$BACKUPS_DIR" \
    -maxdepth 1 \
    -type f \
    -mtime +"$RETAIN_DAYS" \
    2>/dev/null | sort)

echo "  Old backups deleted: $BACKUPS_DELETED"

# ── Disk usage summary ────────────────────────────────────────────────────────
echo ""
echo "-- Disk usage after housekeeping --"
df -h / | tail -1 | awk '{print "  Filesystem: used=" $3 "  avail=" $4 "  use%=" $5}'
du -sh "$ZEEK_LOG_DIR" 2>/dev/null | awk '{print "  Zeek logs: " $1}'
du -sh /var/lib/clickhouse 2>/dev/null | awk '{print "  ClickHouse: " $1}' || true
if command -v suricata &>/dev/null && [[ -d "$SURICATA_LOG_DIR" ]]; then
    du -sh "$SURICATA_LOG_DIR" 2>/dev/null | awk '{print "  Suricata logs: " $1}' || true
fi

echo ""
echo "=== housekeeping done: $(date --iso-8601=seconds) ==="

logger -t beaconbutty \
    "Housekeeping: deleted ${ZEEK_DELETED} Zeek dirs, ${RITA_DELETED} RITA datasets, ${REPORTS_DELETED} beacon reports, ${DNSMASQ_DELETED} dnsmasq logs, ${BACKUPS_DELETED} backups (>${RETAIN_DAYS}d)"
