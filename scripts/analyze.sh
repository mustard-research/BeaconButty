#!/usr/bin/env bash
set -euo pipefail

# rita-analyze.sh
#
# Imports the most recently completed Zeek log directory into RITA and
# runs beacon analysis.  Called every hour by rita-analyze.timer.
#
# Zeek rotates logs into dated subdirectories:
#   /var/log/zeek/2024-01-15/    ← yesterday (complete)
#   /var/log/zeek/current/       ← today (still writing)
#
# We only import the most recent COMPLETE day directory (not "current").
# RITA v5 databases are named:  beaconbutty_YYYYMMDD

RITA_DB_PREFIX="${RITA_DB_NAME:-beaconbutty}"
LOG_DIR="${LOG_DIR:-/var/log/zeek}"
RITA_CONFIG="/etc/rita/config.hjson"
LOGFILE="/var/log/beaconbutty/analyze.log"

# Load ClickHouse connection variables
# shellcheck source=/etc/rita/env
[[ -f /etc/rita/env ]] && source /etc/rita/env

export DB_ADDRESS="${DB_ADDRESS:-localhost:9000}"
export CLICKHOUSE_USERNAME="${CLICKHOUSE_USERNAME:-default}"
export CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-}"

mkdir -p /var/log/beaconbutty
exec >> "$LOGFILE" 2>&1

echo ""
echo "=== rita-analyze started: $(date --iso-8601=seconds) ==="

# Find all completed dated log directories (not "current" which is still writing)
mapfile -t LOG_DIRS < <(find "$LOG_DIR" \
    -maxdepth 1 \
    -mindepth 1 \
    -type d \
    -name '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]' \
    | sort)

if [[ ${#LOG_DIRS[@]} -eq 0 ]]; then
    echo "No completed Zeek log directories found under $LOG_DIR"
    echo "Zeek may still be writing the first day of logs — check: zeekctl status"
    exit 0
fi

# Run rita from /etc/rita so it finds its .env file
cd /etc/rita

# Fetch existing datasets once to avoid a rita list call per directory.
# rita list renders a box-drawing table, so extract the dataset names —
# a whole-line grep against the raw output can never match.
EXISTING_DBS=$(rita list 2>/dev/null | grep -oP "${RITA_DB_PREFIX}_[0-9]{8}" | sort -u || true)

# Today's dir receives new hour-chunks all day, and yesterday's gets its
# final 23:00-00:00 chunk at midnight rotation — both must be re-imported
# even when their DB already exists (RITA only ingests new files). Older
# dirs with an existing DB are genuinely done.
TODAY_TAG=$(date +%F)
YESTERDAY_TAG=$(date -d yesterday +%F)

IMPORTED=0
SKIPPED=0
for LATEST_DIR in "${LOG_DIRS[@]}"; do
    DATE_TAG=$(basename "$LATEST_DIR")            # e.g. 2024-01-15
    DB="${RITA_DB_PREFIX}_${DATE_TAG//-/}"        # e.g. beaconbutty_20240115

    echo ""
    echo "Log directory : $LATEST_DIR"
    echo "RITA database : $DB"

    DB_EXISTS=0
    echo "$EXISTING_DBS" | grep -qx "$DB" && DB_EXISTS=1

    if [[ $DB_EXISTS -eq 1 && "$DATE_TAG" != "$TODAY_TAG" && "$DATE_TAG" != "$YESTERDAY_TAG" ]]; then
        echo "Already imported — skipping."
        (( SKIPPED++ )) || true
        continue
    fi

    echo "Importing and analysing (RITA v5 does both in one step)..."
    RITA_OUT=$(rita import \
        --config "$RITA_CONFIG" \
        --database "$DB" \
        --logs "$LATEST_DIR" 2>&1) && RITA_RC=0 || RITA_RC=$?
    echo "$RITA_OUT"
    if [[ $RITA_RC -eq 0 ]]; then
        (( IMPORTED++ )) || true
    elif echo "$RITA_OUT" | grep -q "all files were previously imported"; then
        echo "Note: all files already imported — nothing new to process."
        (( SKIPPED++ )) || true
    elif [[ $DB_EXISTS -eq 1 ]]; then
        # DB present and import errored — a no-op re-import refusal (exact
        # wording varies across RITA releases) must not kill the hourly
        # pipeline. A genuine first-import failure still aborts below.
        echo "Note: rc=${RITA_RC} for existing dataset — treating as up-to-date."
        (( SKIPPED++ )) || true
    else
        exit $RITA_RC
    fi
done

echo ""
echo "=== done: imported=${IMPORTED} skipped=${SKIPPED}  $(date --iso-8601=seconds) ==="
