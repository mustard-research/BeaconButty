#!/usr/bin/env bash
set -euo pipefail

# beacon-report.sh
#
# Queries RITA v5 for the last 3 days of databases and prints findings.
# RITA v5 presents all finding types (beacons, long connections, strobes,
# threat intel) through a single 'view' command.
#
# Output goes to stdout AND a dated report file.
# Called daily by beacon-report.timer; also runnable manually.

RITA_DB_PREFIX="${RITA_DB_NAME:-beaconbutty}"
REPORT_DIR="/var/lib/beaconbutty/reports"
REPORT_FILE="${REPORT_DIR}/beacon-report-$(date +%Y%m%d).txt"
RITA_CONFIG="/etc/rita/config.hjson"

# Load ClickHouse connection variables
[[ -f /etc/rita/env ]] && source /etc/rita/env

export DB_ADDRESS="${DB_ADDRESS:-localhost:9000}"
export CLICKHOUSE_USERNAME="${CLICKHOUSE_USERNAME:-default}"
export CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-}"

mkdir -p "$REPORT_DIR"

# Run rita from /etc/rita so it finds its .env file
cd /etc/rita

# ── Helpers ───────────────────────────────────────────────────────────────────
hr() { printf '%.0s─' {1..60}; echo; }

{
    echo ""
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║   BeaconButty Threat Report                         ║"
    printf  "║   Generated : %-38s║\n" "$(date '+%Y-%m-%d %H:%M %Z')"
    echo "╚══════════════════════════════════════════════════════╝"
    echo ""

    # Collect the last 3 completed daily databases
    mapfile -t DATABASES < <(
        rita list 2>/dev/null \
        | grep -oE "${RITA_DB_PREFIX}_[0-9]+" \
        | sort \
        | tail -n 3
    )

    if [[ ${#DATABASES[@]} -eq 0 ]]; then
        # NB: this exit only leaves the { … } | tee subshell, not the
        # script — the marker line is checked after the pipe.
        echo "  No RITA databases found."
        echo "  Run:  rita-analyze.sh"
        echo ""
        exit 0
    fi

    for DB in "${DATABASES[@]}"; do
        DATE_PART="${DB#${RITA_DB_PREFIX}_}"   # e.g. 20240115
        DISPLAY_DATE="${DATE_PART:0:4}-${DATE_PART:4:2}-${DATE_PART:6:2}"

        echo "┌─ $DISPLAY_DATE ─────────────────────────────────────────"
        echo ""
        hr

        # RITA v5: single 'view --stdout' command outputs all findings as CSV
        if ! rita view \
                --config "$RITA_CONFIG" \
                --stdout \
                "$DB" 2>&1; then
            echo "  ERROR: rita view failed for $DB — check ClickHouse and RITA logs"
        fi

        echo ""
        echo "└──────────────────────────────────────────────────────────"
        echo ""
    done

} | tee "$REPORT_FILE"

# The no-databases early-exit above only left the subshell — don't keep (or
# log success for) a placeholder report.
if grep -q 'No RITA databases found' "$REPORT_FILE" 2>/dev/null; then
    logger -t beaconbutty "Daily report skipped — no RITA databases yet"
    rm -f "$REPORT_FILE"
    exit 0
fi

# Send a summary line to syslog so it appears in journalctl
FINDING_COUNT=$(grep -cE '^(Critical|High|Medium|Low|None),' "$REPORT_FILE" 2>/dev/null) || FINDING_COUNT=0
logger -t beaconbutty "Daily report written: $REPORT_FILE  (${FINDING_COUNT} CSV rows)"

echo "Report saved to: $REPORT_FILE"
