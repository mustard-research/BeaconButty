#!/usr/bin/env bash
# manage.sh — BeaconButty Management Console
#
# Interactive menu to run any BeaconButty script with the correct parameters.
# Configuration is persisted in .beaconbutty.env (gitignored) so you don't
# have to re-enter values every session.
#
# Usage:
#   sudo ./manage.sh          # interactive menu
#   sudo ./manage.sh <number> # jump directly to a menu item

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS="$SCRIPT_DIR/scripts"
CONFIG_FILE="$SCRIPT_DIR/.beaconbutty.env"

# ── Colours ────────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    B='\033[1m';      DIM='\033[2m';    RESET='\033[0m'
    GREEN='\033[32m'; YELLOW='\033[33m'; RED='\033[31m'
    CYAN='\033[36m';  BLUE='\033[34m';  MAGENTA='\033[35m'
else
    B=''; DIM=''; RESET='' GREEN=''; YELLOW=''; RED=''; CYAN=''; BLUE=''; MAGENTA=''
fi

hdr()  { echo -e "\n${B}${CYAN}$*${RESET}"; }
info() { echo -e "  ${GREEN}▸${RESET} $*"; }
warn() { echo -e "  ${YELLOW}⚠${RESET}  $*"; }
err()  { echo -e "  ${RED}✗${RESET}  $*"; }
sep()  { echo -e "${DIM}$(printf '─%.0s' {1..60})${RESET}"; }

# ── Config persistence ─────────────────────────────────────────────────────────
# Defaults
CAPTURE_IFACE="${CAPTURE_IFACE:-eth1}"
MGMT_IFACE="${MGMT_IFACE:-eth0}"
WAN_IFACE="${WAN_IFACE:-eth0}"
ZEEK_PREFIX="${ZEEK_PREFIX:-/opt/zeek}"
LOG_DIR="${LOG_DIR:-/opt/zeek/logs}"
RITA_DB_NAME="${RITA_DB_NAME:-beaconbutty}"
LOCAL_NETWORKS="${LOCAL_NETWORKS:-10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}"
RETAIN_DAYS="${RETAIN_DAYS:-30}"
BEACON_THRESHOLD="${BEACON_THRESHOLD:-0.80}"

load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    fi
}

save_config() {
    cat > "$CONFIG_FILE" <<EOF
# BeaconButty persistent configuration — edit or run manage.sh > Configure
CAPTURE_IFACE="$CAPTURE_IFACE"
MGMT_IFACE="$MGMT_IFACE"
WAN_IFACE="$WAN_IFACE"
ZEEK_PREFIX="$ZEEK_PREFIX"
LOG_DIR="$LOG_DIR"
RITA_DB_NAME="$RITA_DB_NAME"
LOCAL_NETWORKS="$LOCAL_NETWORKS"
RETAIN_DAYS="$RETAIN_DAYS"
BEACON_THRESHOLD="$BEACON_THRESHOLD"
EOF
    info "Configuration saved to $CONFIG_FILE"
}

# ── Helpers ────────────────────────────────────────────────────────────────────
require_root() {
    if [[ $EUID -ne 0 ]]; then
        err "This action requires root.  Re-run with: sudo ./manage.sh"
        press_enter
        return 1
    fi
}

press_enter() {
    echo ""
    read -r -p "  Press Enter to continue..." _ || true
}

# Prompt for a value, showing current setting, keeping it if user just hits Enter
prompt() {
    local label="$1" varname="$2"
    local current="${!varname}"
    local input
    echo -n "  $label [${current}]: "
    read -r input
    [[ -n "$input" ]] && printf -v "$varname" '%s' "$input"
}

run_script() {
    local script="$1"; shift
    echo ""
    sep
    info "Running: $script $*"
    sep
    echo ""
    local rc=0
    bash "$script" "$@" || rc=$?
    echo ""
    sep
    if [[ $rc -eq 0 ]]; then
        info "Completed successfully."
    else
        err "Exited with code $rc."
    fi
    press_enter
}

run_with_env() {
    local script="$1"; shift
    echo ""
    sep
    info "Running: $(basename "$script") $*"
    sep
    echo ""
    local rc=0
    env \
        CAPTURE_IFACE="$CAPTURE_IFACE" \
        MGMT_IFACE="$MGMT_IFACE" \
        WAN_IFACE="$WAN_IFACE" \
        ZEEK_PREFIX="$ZEEK_PREFIX" \
        LOG_DIR="$LOG_DIR" \
        RITA_DB_NAME="$RITA_DB_NAME" \
        LOCAL_NETWORKS="$LOCAL_NETWORKS" \
        RETAIN_DAYS="$RETAIN_DAYS" \
        BEACON_THRESHOLD="$BEACON_THRESHOLD" \
        bash "$script" "$@" || rc=$?
    echo ""
    sep
    if [[ $rc -eq 0 ]]; then
        info "Completed successfully."
    else
        err "Exited with code $rc."
    fi
    press_enter
}

# ── Menu actions ───────────────────────────────────────────────────────────────

do_full_setup() {
    require_root || return
    hdr "Full Setup — Install all components"
    info "This runs: system deps → Zeek → ClickHouse → RITA → configure"
    echo ""
    info "Current settings (edit via 'Configure' first if needed):"
    show_config_inline
    echo ""
    read -r -p "  Proceed with full setup? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { warn "Aborted."; press_enter; return; }
    run_with_env "$SCRIPT_DIR/setup.sh"
}

do_system_deps() {
    require_root || return
    hdr "Step 1 — Install System Dependencies"
    run_script "$SCRIPTS/01_system_deps.sh"
}

do_install_zeek() {
    require_root || return
    hdr "Step 2 — Install Zeek"
    info "ZEEK_PREFIX: $ZEEK_PREFIX"
    run_with_env "$SCRIPTS/02_install_zeek.sh"
}

do_install_clickhouse() {
    require_root || return
    hdr "Step 3 — Install ClickHouse"
    run_with_env "$SCRIPTS/03_install_clickhouse.sh"
}

do_install_rita() {
    require_root || return
    hdr "Step 4 — Install RITA"
    run_script "$SCRIPTS/04_install_rita.sh"
}

do_configure() {
    require_root || return
    hdr "Step 5 — Apply Configuration"
    info "Capture iface: $CAPTURE_IFACE  |  Zeek: $ZEEK_PREFIX  |  Networks: $LOCAL_NETWORKS"
    run_with_env "$SCRIPTS/05_configure.sh"
}

do_router_mode() {
    require_root || return
    hdr "Router Mode Setup"
    warn "This rewrites network configuration and REBOOTS the system."
    warn "Ensure you have console/serial access before proceeding."
    echo ""
    info "WAN interface : $WAN_IFACE  (DHCP from ISP)"
    info "LAN interface : $CAPTURE_IFACE  (serves internal network)"
    echo ""
    read -r -p "  Are you sure you want to configure router mode? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { warn "Aborted."; press_enter; return; }
    run_with_env "$SCRIPTS/07_router_mode.sh"
}

do_harden() {
    require_root || return
    hdr "Security Hardening"
    info "Hardens SSH, firewall, fail2ban, and unattended-upgrades."
    run_script "$SCRIPTS/harden.sh"
}

do_install_suricata() {
    require_root || return
    hdr "Install Suricata IDS"
    info "Installs Suricata in passive IDS mode alongside Zeek."
    info "Requires 8 GB RAM — exits cleanly on a 4 GB Pi."
    echo ""
    MEM_MB=$(awk '/MemTotal/ {printf "%.0f", $2/1024}' /proc/meminfo)
    if [[ "$MEM_MB" -lt 6000 ]]; then
        warn "This Pi has ${MEM_MB} MB RAM — Suricata requires 8 GB."
        warn "Run this after migrating to the 8 GB Pi."
        press_enter
        return
    fi
    run_with_env "$SCRIPTS/08_install_suricata.sh"
}

do_morning_check() {
    require_root || return
    hdr "Morning Check"
    info "Runs health check, ensures yesterday's RITA import is done, shows report."
    run_with_env "$SCRIPTS/morning-check.sh"
}

do_analyze() {
    require_root || return
    hdr "Run RITA Analysis"
    info "Imports the most recent complete Zeek log day into RITA."
    info "RITA DB prefix: $RITA_DB_NAME  |  Log dir: $LOG_DIR"
    run_with_env "$SCRIPTS/analyze.sh"
}

do_report() {
    require_root || return
    hdr "Generate Beacon Report"
    info "Queries RITA for the last 3 days and writes a dated report file."
    run_with_env "$SCRIPTS/report.sh"
}

do_summarize() {
    require_root || return
    hdr "View Summary"
    echo ""
    echo -n "  Report file path (leave blank for today's auto-detect): "
    read -r report_arg
    echo -n "  Beacon score threshold [${BEACON_THRESHOLD}]: "
    read -r thresh_input
    [[ -n "$thresh_input" ]] && BEACON_THRESHOLD="$thresh_input"

    if [[ -n "$report_arg" ]]; then
        run_with_env "$SCRIPTS/summarize.sh" "$report_arg"
    else
        run_with_env "$SCRIPTS/summarize.sh"
    fi
}

do_healthcheck() {
    require_root || return
    hdr "Health Check"
    run_script "$SCRIPTS/healthcheck.sh"
}

do_wan_watchdog() {
    require_root || return
    hdr "WAN Watchdog — Manual Run"
    info "WAN interface: $WAN_IFACE"
    info "Normally run by systemd timer every 5 minutes."
    run_with_env "$SCRIPTS/wan-watchdog.sh"
}

do_housekeeping() {
    require_root || return
    hdr "Storage Housekeeping"
    info "Removes Zeek logs and RITA datasets older than $RETAIN_DAYS days."
    echo ""
    read -r -p "  Confirm housekeeping (retain last ${RETAIN_DAYS} days)? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { warn "Aborted."; press_enter; return; }
    run_with_env "$SCRIPTS/housekeeping.sh"
}

do_assets() {
    require_root || return
    hdr "LAN Asset Inventory"
    info "Builds inventory from ARP table, nmap OUI database, and Zeek DHCP logs."
    run_with_env "$SCRIPTS/assets.sh"
}

do_fp_list() {
    hdr "False Positives — List"
    run_script "$SCRIPTS/fp.sh" list
}

do_fp_add() {
    require_root || return
    hdr "False Positives — Add"
    echo ""
    echo -n "  IP address to whitelist: "
    read -r fp_ip
    if [[ -z "$fp_ip" ]]; then
        err "IP address required."
        press_enter
        return
    fi
    echo -n "  Reason (max 50 chars): "
    read -r fp_reason
    if [[ -z "$fp_reason" ]]; then
        err "Reason required."
        press_enter
        return
    fi
    run_script "$SCRIPTS/fp.sh" add "$fp_ip" "$fp_reason"
}

do_fp_remove() {
    require_root || return
    hdr "False Positives — Remove"
    echo ""
    # Show current list first
    bash "$SCRIPTS/fp.sh" list 2>/dev/null || true
    echo ""
    echo -n "  IP address to remove: "
    read -r fp_ip
    if [[ -z "$fp_ip" ]]; then
        err "IP address required."
        press_enter
        return
    fi
    run_script "$SCRIPTS/fp.sh" remove "$fp_ip"
}

show_config_inline() {
    echo -e "  ${DIM}CAPTURE_IFACE  = ${CAPTURE_IFACE}${RESET}"
    echo -e "  ${DIM}MGMT_IFACE     = ${MGMT_IFACE}${RESET}"
    echo -e "  ${DIM}WAN_IFACE      = ${WAN_IFACE}${RESET}"
    echo -e "  ${DIM}ZEEK_PREFIX    = ${ZEEK_PREFIX}${RESET}"
    echo -e "  ${DIM}LOG_DIR        = ${LOG_DIR}${RESET}"
    echo -e "  ${DIM}RITA_DB_NAME   = ${RITA_DB_NAME}${RESET}"
    echo -e "  ${DIM}LOCAL_NETWORKS = ${LOCAL_NETWORKS}${RESET}"
    echo -e "  ${DIM}RETAIN_DAYS    = ${RETAIN_DAYS}${RESET}"
    echo -e "  ${DIM}BEACON_THRESHOLD = ${BEACON_THRESHOLD}${RESET}"
}

do_edit_config() {
    hdr "Configuration"
    echo ""
    echo -e "  ${B}Current values${RESET} (press Enter to keep, type new value to change):"
    echo ""
    prompt "Capture interface (Zeek/LAN)" CAPTURE_IFACE
    prompt "Management interface (SSH)"   MGMT_IFACE
    prompt "WAN interface (router mode)"  WAN_IFACE
    prompt "Zeek install prefix"          ZEEK_PREFIX
    prompt "Zeek log directory"           LOG_DIR
    prompt "RITA database name prefix"    RITA_DB_NAME
    prompt "Local networks (comma-sep)"   LOCAL_NETWORKS
    prompt "Log retention (days)"         RETAIN_DAYS
    prompt "Beacon score threshold (0-1)" BEACON_THRESHOLD
    echo ""
    save_config
    press_enter
}

# ── Main menu ──────────────────────────────────────────────────────────────────

print_menu() {
    clear
    echo -e "${B}${CYAN}"
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║         BeaconButty — Management Console                 ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -e "  ${DIM}Capture: ${CAPTURE_IFACE}  │  Zeek: ${ZEEK_PREFIX}  │  RITA DB: ${RITA_DB_NAME}${RESET}"
    echo ""

    echo -e "  ${B}${YELLOW}── INSTALLATION ─────────────────────────────────────────${RESET}"
    echo -e "   ${B}1${RESET}  Full Setup (01→05, all components)"
    echo -e "   ${B}2${RESET}  System Dependencies"
    echo -e "   ${B}3${RESET}  Install Zeek"
    echo -e "   ${B}4${RESET}  Install ClickHouse"
    echo -e "   ${B}5${RESET}  Install RITA"
    echo -e "   ${B}6${RESET}  Apply Configuration"
    echo -e "   ${B}7${RESET}  Router Mode Setup"
    echo -e "   ${B}8${RESET}  Security Hardening"
    echo -e "   ${B}9${RESET}  Install Suricata IDS  ${DIM}(8 GB Pi only)${RESET}"
    echo ""

    echo -e "  ${B}${YELLOW}── DAILY OPERATIONS ─────────────────────────────────────${RESET}"
    echo -e "  ${B}10${RESET}  Morning Check  ${DIM}(health + import + report)${RESET}"
    echo -e "  ${B}11${RESET}  Run RITA Analysis"
    echo -e "  ${B}12${RESET}  Generate Beacon Report"
    echo -e "  ${B}13${RESET}  View Summary"
    echo -e "  ${B}14${RESET}  Health Check"
    echo -e "  ${B}15${RESET}  WAN Watchdog  ${DIM}(manual run)${RESET}"
    echo -e "  ${B}16${RESET}  Storage Housekeeping"
    echo ""

    echo -e "  ${B}${YELLOW}── ASSET & FALSE POSITIVE MANAGEMENT ───────────────────${RESET}"
    echo -e "  ${B}17${RESET}  LAN Asset Inventory"
    echo -e "  ${B}18${RESET}  False Positives — List"
    echo -e "  ${B}19${RESET}  False Positives — Add"
    echo -e "  ${B}20${RESET}  False Positives — Remove"
    echo ""

    echo -e "  ${B}${YELLOW}── MIGRATION ────────────────────────────────────────────${RESET}"
    echo -e "  ${B}21${RESET}  Migration — Export  ${DIM}(package data from this Pi)${RESET}"
    echo -e "  ${B}22${RESET}  Migration — Import  ${DIM}(apply data on new Pi)${RESET}"
    echo -e "  ${B}23${RESET}  Migration — Checklist"
    echo ""
    echo -e "  ${B}${YELLOW}── SETTINGS ─────────────────────────────────────────────${RESET}"
    echo -e "  ${B}24${RESET}  Edit Configuration"
    echo -e "  ${B}25${RESET}  Show Current Configuration"
    echo ""
    echo -e "   ${B}0${RESET}  Exit"
    echo ""
    sep
}

dispatch() {
    case "$1" in
        1)  do_full_setup ;;
        2)  do_system_deps ;;
        3)  do_install_zeek ;;
        4)  do_install_clickhouse ;;
        5)  do_install_rita ;;
        6)  do_configure ;;
        7)  do_router_mode ;;
        8)  do_harden ;;
        9)  do_install_suricata ;;
        10) do_morning_check ;;
        11) do_analyze ;;
        12) do_report ;;
        13) do_summarize ;;
        14) do_healthcheck ;;
        15) do_wan_watchdog ;;
        16) do_housekeeping ;;
        17) do_assets ;;
        18) do_fp_list ;;
        19) do_fp_add ;;
        20) do_fp_remove ;;
        21) require_root && run_script "$SCRIPT_DIR/migrate.sh" export ;;
        22) require_root && run_script "$SCRIPT_DIR/migrate.sh" import ;;
        23) bash "$SCRIPT_DIR/migrate.sh" checklist; press_enter ;;
        24) do_edit_config ;;
        25) hdr "Current Configuration"; echo ""; show_config_inline; press_enter ;;
        0)  echo ""; info "Goodbye."; echo ""; exit 0 ;;
        *)  warn "Unknown option: $1" ;;
    esac
}

# ── Entry point ────────────────────────────────────────────────────────────────

load_config

# Non-interactive: jump directly to item if passed as argument
if [[ $# -ge 1 ]]; then
    dispatch "$1"
    exit 0
fi

# Interactive loop
while true; do
    print_menu
    echo -n "  Select [0-25]: "
    read -r choice || true
    dispatch "${choice:-}"
done
