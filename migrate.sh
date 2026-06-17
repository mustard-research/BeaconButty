#!/usr/bin/env bash
set -euo pipefail

# migrate.sh — BeaconButty migration assistant
#
# Moves BeaconButty from one Pi to another with no data loss.
#
# Usage:
#   sudo ./migrate.sh export              # OLD Pi — package up data
#   sudo ./migrate.sh import <archive>   # NEW Pi — apply data after full setup
#        ./migrate.sh checklist          # Print the complete step-by-step guide

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ZEEK_LOG_DIR="${LOG_DIR:-/var/log/zeek}"
DATA_DIR="/var/lib/beaconbutty"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
DEFAULT_ARCHIVE="/tmp/beaconbutty-migration-${TIMESTAMP}.tar.gz"

# ── Colours ───────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'
    CYAN='\033[0;36m';  RESET='\033[0m';     BOLD='\033[1m'; DIM='\033[2m'
else
    GREEN=''; YELLOW=''; RED=''; CYAN=''; RESET=''; BOLD=''; DIM=''
fi

OK()   { echo -e "  ${GREEN}✓${RESET}  $*"; }
WARN() { echo -e "  ${YELLOW}!${RESET}  $*"; }
FAIL() { echo -e "  ${RED}✗${RESET}  $*"; }
INFO() { echo -e "  ${BOLD}→${RESET}  $*"; }
STEP() { echo -e "\n${BOLD}${CYAN}$*${RESET}"; echo "────────────────────────────────────────────────────"; }
NOTE() { echo -e "  ${DIM}$*${RESET}"; }

# ─────────────────────────────────────────────────────────────────────────────
usage() {
    echo ""
    echo -e "${BOLD}BeaconButty Migration Assistant${RESET}"
    echo ""
    echo "  Usage:"
    echo "    sudo ./migrate.sh export              # OLD Pi: package up data"
    echo "    sudo ./migrate.sh import <archive>   # NEW Pi: apply data"
    echo "         ./migrate.sh checklist          # Print full migration guide"
    echo ""
    exit 1
}

[[ $# -lt 1 ]] && usage

CMD="$1"

# ═════════════════════════════════════════════════════════════════════════════
# CHECKLIST
# ═════════════════════════════════════════════════════════════════════════════
if [[ "$CMD" == "checklist" ]]; then
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${CYAN}║   BeaconButty — Migration Checklist                 ║${RESET}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════╝${RESET}"
    echo ""

    echo -e "${BOLD}PHASE 1 — Prepare the new Pi  (do this while old Pi is still running)${RESET}"
    echo ""
    echo "  [ ] Flash 64-bit Raspberry Pi OS Lite (Bookworm) to the new Pi's NVMe/SD"
    NOTE     "Use Raspberry Pi Imager: set hostname, enable SSH, add your public key"
    echo ""
    echo "  [ ] First SSH into the new Pi and clone the repo:"
    NOTE     "git clone <your-repo-url>  ~/BeaconButty"
    echo ""
    echo "  [ ] Copy your SSH public key across before running harden.sh:"
    NOTE     "ssh-copy-id <user>@<new-pi-ip>"
    echo ""
    echo "  [ ] Run the full installation sequence:"
    NOTE     "sudo ./setup.sh                        # ~45-90 min (Zeek compiles)"
    NOTE     "sudo ./scripts/07_router_mode.sh       # configures routing — REBOOTS"
    NOTE     "sudo bash scripts/harden.sh"
    NOTE     "sudo bash scripts/08_install_suricata.sh   # 8 GB Pi only"
    echo ""

    echo -e "${BOLD}PHASE 2 — Migrate data from the old Pi${RESET}"
    echo ""
    echo "  [ ] On the OLD Pi, create the migration archive:"
    NOTE     "sudo ./migrate.sh export"
    echo ""
    echo "  [ ] Copy the archive to the new Pi:"
    NOTE     "scp /tmp/beaconbutty-migration-*.tar.gz <user>@<new-pi-ip>:/tmp/"
    NOTE     "  or: copy to a USB drive and transfer physically"
    echo ""
    echo "  [ ] On the NEW Pi, apply the migration archive:"
    NOTE     "sudo ./migrate.sh import /tmp/beaconbutty-migration-*.tar.gz"
    echo ""

    echo -e "${BOLD}PHASE 3 — Cutover  (brief network outage)${RESET}"
    echo ""
    echo "  [ ] Verify the new Pi is healthy before the swap:"
    NOTE     "sudo beaconbutty-health.sh"
    echo ""
    echo "  [ ] Power off the old Pi"
    echo ""
    echo "  [ ] Move cables to the new Pi:"
    NOTE     "eth0 ← WAN cable (from ISP router/modem)"
    NOTE     "eth1 ← LAN cable (to your switch)"
    echo ""
    echo "  [ ] Power on the new Pi and verify:"
    NOTE     "sudo beaconbutty-health.sh          # all services green"
    NOTE     "zeekctl status                      # Zeek: running"
    NOTE     "sudo beaconbutty-morning.sh          # full morning check"
    echo ""
    echo "  [ ] Test that LAN clients get DHCP and have internet access"
    echo ""
    echo "  [ ] Keep the old Pi powered off for a few days — easy rollback if needed"
    echo ""

    echo -e "${BOLD}USEFUL COMMANDS ON THE NEW PI${RESET}"
    echo ""
    echo "  sudo beaconbutty-health.sh          # full health check"
    echo "  sudo beaconbutty-morning.sh          # health + RITA + report + summary"
    echo "  beaconbutty-fp.sh list               # verify false positives migrated"
    echo "  sudo beaconbutty-summary.sh          # today's beacon summary"
    echo "  sudo tail -f /var/log/suricata/fast.log   # Suricata alerts (live)"
    echo ""
    exit 0
fi

# ═════════════════════════════════════════════════════════════════════════════
# EXPORT (run on old Pi)
# ═════════════════════════════════════════════════════════════════════════════
if [[ "$CMD" == "export" ]]; then

    [[ $EUID -ne 0 ]] && { echo "Run as root: sudo ./migrate.sh export"; exit 1; }

    ARCHIVE="${2:-$DEFAULT_ARCHIVE}"
    STAGING=$(mktemp -d /tmp/beaconbutty-export-XXXXXX)
    trap 'rm -rf "$STAGING"' EXIT

    echo ""
    echo -e "${BOLD}BeaconButty Migration Export${RESET}"
    echo "────────────────────────────────────────────────────"

    # ── Gather data ──────────────────────────────────────────────────────────
    STEP "Collecting data"

    mkdir -p "${STAGING}/lib" "${STAGING}/zeek-logs"

    # False positives — essential
    if [[ -f "${DATA_DIR}/false-positives.conf" ]]; then
        cp "${DATA_DIR}/false-positives.conf" "${STAGING}/lib/"
        FP_COUNT=$(python3 -c "import json; d=json.load(open('${DATA_DIR}/false-positives.conf')); print(len(d))" 2>/dev/null || echo "?")
        OK "false-positives.conf  (${FP_COUNT} entries)"
    else
        WARN "false-positives.conf not found — skipping"
    fi

    # Beacon reports
    REPORT_COUNT=0
    if [[ -d "${DATA_DIR}/reports" ]]; then
        mkdir -p "${STAGING}/lib/reports"
        find "${DATA_DIR}/reports" -name "beacon-report-*.txt" \
            -exec cp {} "${STAGING}/lib/reports/" \;
        REPORT_COUNT=$(find "${STAGING}/lib/reports" -name "*.txt" | wc -l)
        OK "Beacon reports: ${REPORT_COUNT} file(s)"
    fi

    # Asset cache
    if [[ -f "${DATA_DIR}/assets.json" ]]; then
        cp "${DATA_DIR}/assets.json" "${STAGING}/lib/"
        ASSET_COUNT=$(python3 -c "import json; d=json.load(open('${DATA_DIR}/assets.json')); print(len(d))" 2>/dev/null || echo "?")
        OK "assets.json  (${ASSET_COUNT} hosts)"
    fi

    # manage.sh config
    if [[ -f "${SCRIPT_DIR}/.beaconbutty.env" ]]; then
        cp "${SCRIPT_DIR}/.beaconbutty.env" "${STAGING}/"
        OK ".beaconbutty.env  (manage.sh settings)"
    fi

    # ── Optional: Zeek logs ───────────────────────────────────────────────────
    STEP "Zeek log directories (optional)"

    ZEEK_DIRS=()
    if [[ -d "$ZEEK_LOG_DIR" ]]; then
        mapfile -t ALL_ZEEK_DIRS < <(find "$ZEEK_LOG_DIR" \
            -maxdepth 1 -mindepth 1 -type d \
            -name '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]' | sort)

        if [[ ${#ALL_ZEEK_DIRS[@]} -eq 0 ]]; then
            INFO "No completed Zeek log directories found."
        else
            echo ""
            echo "  Zeek log directories available:"
            TOTAL_SIZE=0
            for dir in "${ALL_ZEEK_DIRS[@]}"; do
                SIZE_KB=$(du -sk "$dir" 2>/dev/null | cut -f1)
                TOTAL_SIZE=$(( TOTAL_SIZE + SIZE_KB ))
                printf "    %-35s  %s\n" "$(basename "$dir")" "$(du -sh "$dir" 2>/dev/null | cut -f1)"
            done
            TOTAL_MB=$(( TOTAL_SIZE / 1024 ))
            COMPRESSED_EST=$(( TOTAL_MB / 6 ))   # Zeek logs compress ~6:1
            echo ""
            echo "    Total: ~${TOTAL_MB} MB  (estimated compressed: ~${COMPRESSED_EST} MB)"
            echo ""

            read -r -p "  Include Zeek logs for RITA historical analysis on new Pi? [y/N] " inc_zeek
            if [[ "$inc_zeek" =~ ^[Yy]$ ]]; then
                echo ""
                read -r -p "  How many days to include? [all ${#ALL_ZEEK_DIRS[@]}]: " zeek_days_input
                if [[ -z "$zeek_days_input" ]]; then
                    ZEEK_DIRS=("${ALL_ZEEK_DIRS[@]}")
                else
                    # Take the most recent N days
                    mapfile -t ZEEK_DIRS < <(printf '%s\n' "${ALL_ZEEK_DIRS[@]}" | tail -n "$zeek_days_input")
                fi
                INFO "Including ${#ZEEK_DIRS[@]} Zeek log directories."
                for dir in "${ZEEK_DIRS[@]}"; do
                    cp -r "$dir" "${STAGING}/zeek-logs/"
                done
                OK "Zeek logs copied."
            else
                INFO "Skipping Zeek logs.  RITA will start fresh on the new Pi."
            fi
        fi
    else
        INFO "Zeek log directory not found at ${ZEEK_LOG_DIR} — skipping."
    fi

    # ── Write manifest ────────────────────────────────────────────────────────
    cat > "${STAGING}/MANIFEST.txt" <<EOF
BeaconButty Migration Archive
Generated : $(date '+%Y-%m-%d %H:%M %Z')
Source Pi : $(hostname)

Contents:
  lib/false-positives.conf    — false positive registry
  lib/assets.json             — LAN asset cache
  lib/reports/                — historical beacon reports
  .beaconbutty.env            — manage.sh configuration (if present)
  zeek-logs/                  — Zeek daily log directories (if included)

To apply on the new Pi:
  sudo ./migrate.sh import <this-file>
EOF

    # ── Create archive ────────────────────────────────────────────────────────
    STEP "Creating archive"

    INFO "Writing ${ARCHIVE}..."
    tar -czf "$ARCHIVE" -C "$STAGING" .
    ARCHIVE_SIZE=$(du -sh "$ARCHIVE" | cut -f1)
    OK "Archive created: ${ARCHIVE}  (${ARCHIVE_SIZE})"

    # ── Print next steps ──────────────────────────────────────────────────────
    echo ""
    echo "════════════════════════════════════════════════════"
    echo -e "${BOLD}Export complete.  Next steps:${RESET}"
    echo ""
    echo "  1. Copy this archive to the new Pi:"
    LAN_IP=$(ip -4 addr show eth1 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 | head -1 || echo "<old-pi-ip>")
    echo "       scp ${LAN_IP}:${ARCHIVE} <user>@<new-pi-ip>:/tmp/"
    echo ""
    echo "  2. On the new Pi, run the setup sequence first if not already done:"
    echo "       sudo ./setup.sh"
    echo "       sudo ./scripts/07_router_mode.sh"
    echo "       sudo bash scripts/harden.sh"
    echo "       sudo bash scripts/08_install_suricata.sh   # 8 GB Pi only"
    echo ""
    echo "  3. Then apply this archive:"
    echo "       sudo ./migrate.sh import /tmp/$(basename "$ARCHIVE")"
    echo ""
    echo "  Run './migrate.sh checklist' for the full step-by-step guide."
    echo ""

    exit 0
fi

# ═════════════════════════════════════════════════════════════════════════════
# IMPORT (run on new Pi after full setup)
# ═════════════════════════════════════════════════════════════════════════════
if [[ "$CMD" == "import" ]]; then

    [[ $EUID -ne 0 ]] && { echo "Run as root: sudo ./migrate.sh import <archive>"; exit 1; }
    [[ $# -lt 2 ]] && { echo "Usage: sudo ./migrate.sh import <archive.tar.gz>"; exit 1; }

    ARCHIVE="$2"
    [[ ! -f "$ARCHIVE" ]] && { FAIL "Archive not found: ${ARCHIVE}"; exit 1; }

    echo ""
    echo -e "${BOLD}BeaconButty Migration Import${RESET}"
    echo "────────────────────────────────────────────────────"

    # ── Prerequisite checks ───────────────────────────────────────────────────
    STEP "Checking prerequisites"

    PREREQ_FAIL=0

    # ClickHouse
    if systemctl is-active --quiet clickhouse-server 2>/dev/null; then
        OK "ClickHouse: running"
    else
        FAIL "ClickHouse not running — run: sudo ./setup.sh"
        PREREQ_FAIL=1
    fi

    # RITA
    if [[ -x /usr/local/bin/rita ]]; then
        OK "RITA: installed"
    else
        FAIL "RITA not found — run: sudo ./setup.sh"
        PREREQ_FAIL=1
    fi

    # Zeek
    if [[ -x "${ZEEK_LOG_DIR%/logs}/bin/zeekctl" ]] || command -v zeekctl &>/dev/null; then
        ZEEKCTL=$(command -v zeekctl 2>/dev/null || echo "/opt/zeek/bin/zeekctl")
        if "$ZEEKCTL" status 2>/dev/null | grep -q running; then
            OK "Zeek: running"
        else
            WARN "Zeek: installed but not running — start with: zeekctl start"
        fi
    else
        FAIL "Zeek not found — run: sudo ./setup.sh"
        PREREQ_FAIL=1
    fi

    # Router mode (NAT MASQUERADE rule)
    if iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q MASQUERADE; then
        OK "Router mode: configured  (NAT active)"
    else
        FAIL "Router mode not configured — run: sudo ./scripts/07_router_mode.sh"
        PREREQ_FAIL=1
    fi

    # SSH hardening drop-in
    if [[ -f /etc/ssh/sshd_config.d/99-beaconbutty-hardening.conf ]]; then
        OK "SSH hardening: applied"
    else
        WARN "SSH hardening not applied — run: sudo bash scripts/harden.sh"
    fi

    # Suricata (only expected on 8 GB Pi)
    MEM_MB=$(awk '/MemTotal/ {printf "%.0f", $2/1024}' /proc/meminfo)
    if [[ "$MEM_MB" -ge 6000 ]]; then
        if systemctl is-active --quiet suricata 2>/dev/null; then
            OK "Suricata: running"
        else
            WARN "Suricata not running — run: sudo bash scripts/08_install_suricata.sh"
        fi
    else
        NOTE "Suricata: skipped (4 GB Pi)"
    fi

    if [[ "$PREREQ_FAIL" -ne 0 ]]; then
        echo ""
        FAIL "Prerequisites not met — complete the setup steps above, then re-run."
        echo ""
        INFO "Full guide: ./migrate.sh checklist"
        echo ""
        exit 1
    fi

    # ── Extract archive ───────────────────────────────────────────────────────
    STEP "Extracting archive"

    STAGING=$(mktemp -d /tmp/beaconbutty-import-XXXXXX)
    trap 'rm -rf "$STAGING"' EXIT

    tar -xzf "$ARCHIVE" -C "$STAGING"
    OK "Archive extracted."

    if [[ -f "${STAGING}/MANIFEST.txt" ]]; then
        echo ""
        NOTE "Archive manifest:"
        sed 's/^/    /' "${STAGING}/MANIFEST.txt"
        echo ""
    fi

    # ── Apply data ────────────────────────────────────────────────────────────
    STEP "Applying migrated data"

    mkdir -p "$DATA_DIR/reports"

    # False positives
    if [[ -f "${STAGING}/lib/false-positives.conf" ]]; then
        cp "${STAGING}/lib/false-positives.conf" "${DATA_DIR}/false-positives.conf"
        FP_COUNT=$(python3 -c "import json; d=json.load(open('${DATA_DIR}/false-positives.conf')); print(len(d))" 2>/dev/null || echo "?")
        OK "false-positives.conf applied  (${FP_COUNT} entries)"
    else
        WARN "false-positives.conf not in archive — skipping"
    fi

    # Beacon reports
    if [[ -d "${STAGING}/lib/reports" ]]; then
        cp "${STAGING}/lib/reports"/*.txt "${DATA_DIR}/reports/" 2>/dev/null || true
        COUNT=$(find "${DATA_DIR}/reports" -name "*.txt" | wc -l)
        OK "Beacon reports: ${COUNT} file(s) applied"
    fi

    # Asset cache
    if [[ -f "${STAGING}/lib/assets.json" ]]; then
        cp "${STAGING}/lib/assets.json" "${DATA_DIR}/assets.json"
        ASSET_COUNT=$(python3 -c "import json; d=json.load(open('${DATA_DIR}/assets.json')); print(len(d))" 2>/dev/null || echo "?")
        OK "assets.json applied  (${ASSET_COUNT} hosts)"
        NOTE "Run 'sudo beaconbutty-assets.sh' soon to refresh with new Pi's ARP table"
    fi

    # manage.sh config
    if [[ -f "${STAGING}/.beaconbutty.env" ]]; then
        cp "${STAGING}/.beaconbutty.env" "${SCRIPT_DIR}/.beaconbutty.env"
        OK ".beaconbutty.env applied  (manage.sh settings restored)"
    fi

    # ── Zeek logs ─────────────────────────────────────────────────────────────
    ZEEK_DIR_COUNT=$(find "${STAGING}/zeek-logs" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l)

    if [[ "$ZEEK_DIR_COUNT" -gt 0 ]]; then
        STEP "Restoring Zeek log directories  (${ZEEK_DIR_COUNT} days)"

        mkdir -p "$ZEEK_LOG_DIR"
        IMPORTED_ZEEK=0
        for dir in "${STAGING}/zeek-logs"/*/; do
            [[ -d "$dir" ]] || continue
            DAYNAME=$(basename "$dir")
            DEST="${ZEEK_LOG_DIR}/${DAYNAME}"
            if [[ -d "$DEST" ]]; then
                NOTE "${DAYNAME}: already exists — skipping"
            else
                cp -r "$dir" "$DEST"
                OK "${DAYNAME}: restored"
                (( IMPORTED_ZEEK++ )) || true
            fi
        done

        # Run RITA analysis on any newly copied log directories
        if [[ "$IMPORTED_ZEEK" -gt 0 ]]; then
            echo ""
            INFO "Running RITA analysis on ${IMPORTED_ZEEK} restored log directories..."
            /usr/local/bin/rita-analyze.sh 2>&1 | tail -5 || \
                WARN "RITA analysis encountered issues — check /var/log/beaconbutty/analyze.log"
            OK "RITA analysis complete."
        fi
    else
        NOTE "No Zeek logs in archive — RITA will build history as new logs accumulate."
    fi

    # ── Run health check ──────────────────────────────────────────────────────
    STEP "Health check"

    /usr/local/bin/beaconbutty-health.sh || true

    # ── Cutover instructions ──────────────────────────────────────────────────
    echo ""
    echo "════════════════════════════════════════════════════"
    echo -e "${BOLD}Import complete.  Ready for cutover.${RESET}"
    echo ""
    echo "  When you are ready to switch over:"
    echo ""
    echo "  1. Power off the OLD Pi"
    echo ""
    echo "  2. Move cables to this Pi:"
    echo "       eth0 ← WAN  (cable from ISP router/modem)"
    echo "       eth1 ← LAN  (cable to your switch)"
    echo ""
    echo "  3. After reconnecting, verify:"
    echo "       sudo beaconbutty-health.sh"
    echo "       zeekctl status"
    echo "       sudo beaconbutty-morning.sh"
    echo ""
    echo "  4. Test that LAN clients get DHCP and have internet access."
    echo ""
    WARN "Keep the old Pi powered off for a few days before decommissioning —"
    WARN "easy rollback if anything is unexpected."
    echo ""

    exit 0
fi

# Unknown command
echo "Unknown command: $CMD"
usage
