#!/usr/bin/env bash
# morning-check.sh — BeaconButty morning review
#
# 1. Runs the health check to confirm all components are up.
# 2. Forces a fresh RITA import/analysis of yesterday's logs if not done yet.
# 3. Prints (or regenerates) today's beacon threat report.
# 4. Summarises the top suspicious connections for quick triage.
#
# Usage:
#   sudo /usr/local/bin/beaconbutty-morning.sh

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    RED='\033[0;31m';   RESET='\033[0m'; BOLD='\033[1m'; CYAN='\033[0;36m'
else
    GREEN=''; YELLOW=''; RED=''; RESET=''; BOLD=''; CYAN=''
fi

ZEEK_PREFIX="${ZEEK_PREFIX:-/opt/zeek}"
LOG_DIR="${LOG_DIR:-/var/log/zeek}"
REPORT_DIR="/var/lib/beaconbutty/reports"
RITA_DB_PREFIX="${RITA_DB_NAME:-beaconbutty}"

# Score threshold above which a finding is highlighted as suspicious
ALERT_THRESHOLD="${BEACON_ALERT_THRESHOLD:-0.7}"

# ── Header ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║   BeaconButty Morning Check                         ║${RESET}"
printf "${BOLD}${CYAN}║   %-52s║${RESET}\n" "$(date '+%A %d %B %Y  %H:%M %Z')"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""

# ── Step 1: Health check ──────────────────────────────────────────────────────
echo -e "${BOLD}[ 1/4 ]  System health${RESET}"
echo "────────────────────────────────────────────────────"
/usr/local/bin/beaconbutty-health.sh || true   # don't abort on failures
echo ""

# ── Step 2: Ensure RITA has analysed the most recent complete day ─────────────
echo -e "${BOLD}[ 2/4 ]  RITA analysis${RESET}"
echo "────────────────────────────────────────────────────"

# Load ClickHouse connection variables
[[ -f /etc/rita/env ]] && source /etc/rita/env
export DB_ADDRESS="${DB_ADDRESS:-localhost:9000}"
export CLICKHOUSE_USERNAME="${CLICKHOUSE_USERNAME:-default}"
export CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-}"

RITA_CONFIG="/etc/rita/config.hjson"

LATEST_DIR=$(find "$LOG_DIR" \
    -maxdepth 1 -mindepth 1 \
    -type d \
    -name '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]' \
    | sort | tail -n 1)

if [[ -z "$LATEST_DIR" ]]; then
    echo -e "  ${YELLOW}!${RESET}  No completed Zeek log directories yet — Zeek may still be writing its first day."
    echo ""
else
    DATE_TAG=$(basename "$LATEST_DIR")
    DB="${RITA_DB_PREFIX}_${DATE_TAG//-/}"

    # Run rita from /etc/rita so it finds its .env file
    if ( cd /etc/rita && rita list 2>/dev/null ) | grep -q "$DB"; then
        echo -e "  ${GREEN}✓${RESET}  RITA dataset ${DB} already imported."
    else
        echo -e "  Importing ${LATEST_DIR} into RITA dataset ${DB}..."
        ( cd /etc/rita && rita import \
            --config "$RITA_CONFIG" \
            --database "$DB" \
            --logs "$LATEST_DIR" ) \
            && echo -e "  ${GREEN}✓${RESET}  Import complete." \
            || echo -e "  ${RED}✗${RESET}  Import failed — check /var/log/beaconbutty/analyze.log"
    fi
    echo ""
fi

# ── Step 3: Generate / display today's report ─────────────────────────────────
echo -e "${BOLD}[ 3/4 ]  Beacon threat report${RESET}"
echo "────────────────────────────────────────────────────"

TODAY_REPORT="${REPORT_DIR}/beacon-report-$(date +%Y%m%d).txt"

if [[ ! -f "$TODAY_REPORT" ]]; then
    echo "  Generating report..."
    /usr/local/bin/beacon-report.sh
else
    cat "$TODAY_REPORT"
fi
echo ""

# ── Step 4: Top alerts summary ────────────────────────────────────────────────
echo -e "${BOLD}[ 4/4 ]  Triage summary  (score ≥ ${ALERT_THRESHOLD})${RESET}"
echo "────────────────────────────────────────────────────"

# RITA v5 view --stdout outputs CSV.  First field is typically the beacon score.
# We filter for lines where the score field is a number >= ALERT_THRESHOLD.
ALERT_COUNT=0

mapfile -t DATABASES < <(
    (cd /etc/rita && rita list) 2>/dev/null \
    | grep -oE "${RITA_DB_PREFIX}_[0-9]+" \
    | sort | tail -n 3
)

if [[ ${#DATABASES[@]} -eq 0 ]]; then
    echo -e "  ${YELLOW}!${RESET}  No RITA datasets available yet."
else
    for DB in "${DATABASES[@]}"; do
        DATE_PART="${DB#${RITA_DB_PREFIX}_}"
        DISPLAY_DATE="${DATE_PART:0:4}-${DATE_PART:4:2}-${DATE_PART:6:2}"

        # Parse CSV header to find "Beacon Score" column, then filter data rows
        SCORE_COL=0
        while IFS= read -r line; do
            if [[ "$SCORE_COL" -eq 0 ]]; then
                # Header line — locate "Beacon Score" column (1-based index for cut)
                IFS=',' read -ra FIELDS <<< "$line"
                for i in "${!FIELDS[@]}"; do
                    field=$(echo "${FIELDS[$i]}" | tr -d ' ')
                    if [[ "$field" == "BeaconScore" ]]; then
                        SCORE_COL=$(( i + 1 ))
                        break
                    fi
                done
                continue
            fi
            [[ "$SCORE_COL" -eq 0 ]] && continue
            SCORE=$(echo "$line" | cut -d',' -f"$SCORE_COL" | tr -d ' ')
            # RITA prints a perfect score as integer "1" — decimal part optional
            if [[ "$SCORE" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                if awk "BEGIN{exit !($SCORE >= $ALERT_THRESHOLD)}"; then
                    echo -e "  ${RED}${SCORE}${RESET}  ${DISPLAY_DATE}  ${line#*,}"
                    ALERT_COUNT=$(( ALERT_COUNT + 1 ))
                fi
            fi
        done < <(cd /etc/rita && rita view --config "$RITA_CONFIG" --stdout "$DB" 2>/dev/null || true)
    done

    if [[ "$ALERT_COUNT" -eq 0 ]]; then
        echo -e "  ${GREEN}✓${RESET}  No findings above ${ALERT_THRESHOLD} in the last 3 days."
    else
        echo ""
        echo -e "  ${BOLD}${ALERT_COUNT} finding(s) require attention.${RESET}"
        echo ""
        echo "  To investigate a suspicious source IP:"
        echo "    arp -n                                          # IP → MAC → device"
        echo "    cat /var/lib/misc/dnsmasq.leases               # DHCP hostname lookup"
        echo "    sudo grep <src_ip> /var/log/zeek/current/conn.log | tail -30"
    fi
fi

echo ""
echo "════════════════════════════════════════════════════"
echo -e "${BOLD}Morning check complete.${RESET}"
echo ""
