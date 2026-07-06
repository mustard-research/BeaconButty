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
LOG_DIR="${LOG_DIR:-/var/log/zeek}"
RITA_DB_NAME="${RITA_DB_NAME:-beaconbutty}"
LOCAL_NETWORKS="${LOCAL_NETWORKS:-10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}"
RETAIN_DAYS="${RETAIN_DAYS:-30}"
BEACON_THRESHOLD="${BEACON_THRESHOLD:-0.80}"
LEASES_FILE="/var/lib/misc/dnsmasq.leases"

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

do_suricata_review() {
    hdr "Suricata Events Review"

    EVE="/var/log/suricata/eve.json"
    FAST="/var/log/suricata/fast.log"

    if [[ ! -f "$EVE" ]]; then
        warn "Suricata eve.json not found at $EVE"
        warn "Is Suricata installed and running?"
        press_enter
        return
    fi

    echo ""
    echo -e "  ${B}Options:${RESET}"
    echo -e "   ${B}1${RESET}  Summary — today's alerts grouped by signature"
    echo -e "   ${B}2${RESET}  Recent alerts — last N events"
    echo -e "   ${B}3${RESET}  Live tail — follow fast.log in real time"
    echo -e "   ${B}4${RESET}  Trace alerts to LAN devices  ${DIM}(via Zeek conn.log)${RESET}"
    echo -e "   ${B}0${RESET}  Back"
    echo ""
    echo -n "  Select [0-4]: "
    read -r sub

    case "$sub" in
        1)
            echo ""
            echo -n "  Skip priority-3 engine noise? [Y/n]: "
            read -r skip_p3
            python3 - "$EVE" "${skip_p3:-y}" <<'PYEOF'
import json, sys
from collections import defaultdict
from datetime import datetime, timezone

eve_file = sys.argv[1]
skip_p3  = sys.argv[2].lower() not in ('n', 'no')

today = datetime.now(timezone.utc).date()
sigs  = defaultdict(lambda: {'count': 0, 'priority': 0, 'srcs': set(), 'last': ''})

with open(eve_file) as f:
    for line in f:
        try:
            evt = json.loads(line)
        except Exception:
            continue
        if evt.get('event_type') != 'alert':
            continue
        if evt.get('timestamp', '')[:10] != str(today):
            continue
        alert = evt.get('alert', {})
        pri   = alert.get('severity', 3)
        if skip_p3 and pri >= 3:
            continue
        sig   = alert.get('signature', '(unknown)')
        sigs[sig]['count']    += 1
        sigs[sig]['priority']  = pri
        sigs[sig]['srcs'].add(evt.get('src_ip', ''))
        sigs[sig]['last']      = evt.get('timestamp', '')[:19].replace('T', ' ')

label = "priority 1–2 only" if skip_p3 else "all priorities"
if not sigs:
    print(f"\n  No Suricata alerts today ({label}).")
else:
    print(f"\n  Today's alerts ({label}):\n")
    print(f"  {'P':>2}  {'Count':>5}  {'Srcs':>4}  {'Last Seen':<19}  Signature")
    print("  " + "\u2500" * 76)
    for sig, d in sorted(sigs.items(), key=lambda x: (x[1]['priority'], -x[1]['count'])):
        print(f"  {d['priority']:>2}  {d['count']:>5}  {len(d['srcs']):>4}  {d['last']:<19}  {sig[:50]}")
PYEOF
            press_enter
            ;;
        2)
            echo ""
            echo -n "  How many recent alerts to show [20]: "
            read -r n_alerts
            echo ""
            echo -n "  Skip priority-3 engine noise? [Y/n]: "
            read -r skip_p3
            python3 - "$EVE" "${n_alerts:-20}" "${skip_p3:-y}" <<'PYEOF'
import json, sys

eve_file = sys.argv[1]
n        = int(sys.argv[2])
skip_p3  = sys.argv[3].lower() not in ('n', 'no')

alerts = []
with open(eve_file) as f:
    for line in f:
        try:
            evt = json.loads(line)
        except Exception:
            continue
        if evt.get('event_type') != 'alert':
            continue
        if skip_p3 and evt.get('alert', {}).get('severity', 3) >= 3:
            continue
        alerts.append(evt)

recent = alerts[-n:]
label  = "priority 1–2 only" if skip_p3 else "all priorities"
if not recent:
    print(f"\n  No alerts found ({label}).")
else:
    print(f"\n  Last {len(recent)} alerts ({label}):\n")
    for evt in recent:
        alert = evt.get('alert', {})
        ts    = evt.get('timestamp', '')[:19].replace('T', ' ')
        pri   = alert.get('severity', '?')
        sig   = alert.get('signature', '(unknown)')[:55]
        src   = evt.get('src_ip', '')
        sport = evt.get('src_port', '')
        dst   = evt.get('dest_ip', '')
        dport = evt.get('dest_port', '')
        proto = evt.get('proto', '')
        print(f"  [{ts}] P{pri}  {sig}")
        print(f"    {proto}  {src}:{sport} \u2192 {dst}:{dport}\n")
PYEOF
            press_enter
            ;;
        3)
            echo ""
            info "Tailing $FAST — press Ctrl-C to stop."
            echo ""
            tail -f "$FAST" || true
            press_enter
            ;;
        4)
            if [[ $EUID -ne 0 ]]; then
                warn "This option requires root (needs access to Zeek logs)."
                press_enter
                return
            fi
            WAN_IP=$(ip -4 addr show "$WAN_IFACE" 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1)
            if [[ -z "$WAN_IP" ]]; then
                warn "Could not determine WAN IP from interface $WAN_IFACE."
                press_enter
                return
            fi
            python3 - "$FAST" "/var/log/zeek" "$WAN_IP" "$LEASES_FILE" <<'PYEOF'
import re, sys, os, gzip
from datetime import datetime
from collections import defaultdict

fast_log    = sys.argv[1]
zeek_base   = sys.argv[2]
wan_ip      = sys.argv[3]
leases_file = sys.argv[4]

ip_to_host = {}
try:
    with open(leases_file) as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 4 and parts[3] != '*':
                ip_to_host[parts[2]] = parts[3]
except FileNotFoundError:
    pass

def host(ip):
    h = ip_to_host.get(ip, '')
    return f"{ip} ({h})" if h else ip

FAST_RE = re.compile(
    r'(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2})\.\d+\s+\[\*\*\]\s+\[\S+\]\s+(.*?)\s+\[\*\*\]'
    r'.*?\{(\w+)\}\s+([\d.]+):(\d+)\s+->\s+([\d.]+):(\d+)'
)

alerts_raw = []
try:
    with open(fast_log) as f:
        for line in f:
            m = FAST_RE.search(line)
            if not m:
                continue
            ts_str, sig, proto, src_ip, src_port, dst_ip, dst_port = m.groups()
            if dst_ip == wan_ip:
                ext_ip, ext_port = src_ip, int(src_port)
            elif src_ip == wan_ip:
                ext_ip, ext_port = dst_ip, int(dst_port)
            else:
                ext_ip, ext_port = dst_ip, int(dst_port)
            ts = datetime.strptime(ts_str, '%m/%d/%Y-%H:%M:%S')
            alerts_raw.append((ts, sig.strip(), proto, ext_ip, ext_port))
except FileNotFoundError:
    print(f"  fast.log not found: {fast_log}")
    sys.exit(1)

if not alerts_raw:
    print("  No alerts in fast.log.")
    sys.exit(0)

ext_ips    = set(a[3] for a in alerts_raw)
date_hours = defaultdict(set)
for ts, *_ in alerts_raw:
    d = ts.strftime('%Y-%m-%d')
    for dh in range(max(0, ts.hour - 1), min(24, ts.hour + 2)):
        date_hours[d].add(dh)

ext_to_lans = defaultdict(set)
files_checked = 0
for date_str, hours in date_hours.items():
    zeek_dir = os.path.join(zeek_base, date_str)
    if not os.path.isdir(zeek_dir):
        continue
    for h in sorted(hours):
        fname = f"conn.{h:02d}:00:00-{(h+1):02d}:00:00.log.gz"
        fpath = os.path.join(zeek_dir, fname)
        if not os.path.exists(fpath):
            continue
        files_checked += 1
        try:
            with gzip.open(fpath, 'rt') as f:
                for line in f:
                    if line.startswith('#'):
                        continue
                    parts = line.split('\t')
                    if len(parts) >= 6 and parts[4] in ext_ips:
                        ext_to_lans[parts[4]].add(parts[2])
        except Exception:
            continue

print(f"\n  {len(alerts_raw)} alert(s), {len(ext_ips)} external IP(s), {files_checked} Zeek file(s) searched\n")

# Group unique (ext_ip, ext_port, sig) by LAN device
# An alert touching multiple LAN devices appears under each
lan_to_alerts = defaultdict(set)   # lan_ip -> {(ext_str, sig)}
unresolved    = set()              # (ext_str, sig) with no LAN match

seen = set()
for ts, sig, proto, ext_ip, ext_port in alerts_raw:
    key = (ext_ip, sig)
    if key in seen:
        continue
    seen.add(key)
    ext_str = f"{ext_ip}:{ext_port}"
    lans = ext_to_lans.get(ext_ip, set())
    if lans:
        for lan in lans:
            lan_to_alerts[lan].add((ext_str, sig))
    else:
        unresolved.add((ext_str, sig))

print(f"  {'LAN Device':<28} {'External IP':<24} Signature")
print("  " + "\u2500" * 88)

for lan_ip in sorted(lan_to_alerts):
    label    = host(lan_ip)
    entries  = sorted(lan_to_alerts[lan_ip])
    first    = True
    for ext_str, sig in entries:
        dev_col = label if first else ''
        print(f"  {dev_col:<28} {ext_str:<24} {sig[:36]}")
        first = False
    print()

if unresolved:
    print(f"  {'(inbound / not in Zeek)':<28} {'External IP':<24} Signature")
    print("  " + "\u2500" * 88)
    for ext_str, sig in sorted(unresolved):
        print(f"  {'': <28} {ext_str:<24} {sig[:36]}")
PYEOF
            press_enter
            ;;
        0|"") return ;;
        *) warn "Unknown option." ; press_enter ;;
    esac
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
    echo -n "  IP or MAC address to whitelist: "
    read -r fp_ip
    if [[ -z "$fp_ip" ]]; then
        err "IP or MAC address required."
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
    echo -n "  IP or MAC address to remove: "
    read -r fp_ip
    if [[ -z "$fp_ip" ]]; then
        err "IP or MAC address required."
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

# ── Installation sub-menu ──────────────────────────────────────────────────────

do_install_pironman5() {
    require_root || return
    hdr "Install Pironman5"
    info "Installs the SunFounder Pironman5 case software (OLED display, fan control, LEDs)."
    info "Only needed if bb0 is installed in a Pironman5 case."
    echo ""

    if [[ -x /opt/pironman5/venv/bin/python3 ]]; then
        info "Pironman5 already installed at /opt/pironman5/venv"
        press_enter
        return
    fi

    read -r -p "  Install Pironman5? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { warn "Aborted."; press_enter; return; }

    echo ""
    sep
    info "Cloning SunFounder Pironman5 installer..."
    sep
    echo ""

    local tmp_dir
    tmp_dir=$(mktemp -d)
    local rc=0

    git clone --depth=1 https://github.com/sunfounder/pironman5.git "$tmp_dir/pironman5" || rc=$?
    if [[ $rc -ne 0 ]]; then
        err "Failed to clone Pironman5 repository."
        rm -rf "$tmp_dir"
        press_enter
        return
    fi

    pushd "$tmp_dir/pironman5" > /dev/null
    python3 install.py || rc=$?
    popd > /dev/null
    rm -rf "$tmp_dir"

    echo ""
    sep
    if [[ $rc -eq 0 ]]; then
        info "Pironman5 installed successfully."
        echo ""
        info "Enabling bb0-display.service..."
        systemctl enable --now bb0-display.service && \
            info "bb0-display.service enabled." || \
            warn "Failed to enable bb0-display.service — check logs with: journalctl -u bb0-display.service"
    else
        err "Pironman5 installation failed (exit $rc)."
    fi
    press_enter
}

do_installation_menu() {
    while true; do
        clear
        echo -e "${B}${CYAN}"
        echo "  ╔══════════════════════════════════════════════════════════╗"
        echo "  ║         BeaconButty — Installation & Setup               ║"
        echo "  ╚══════════════════════════════════════════════════════════╝"
        echo -e "${RESET}"
        echo -e "   ${B}1${RESET}  Full Setup (01→05, all components)"
        echo -e "   ${B}2${RESET}  System Dependencies"
        echo -e "   ${B}3${RESET}  Install Zeek"
        echo -e "   ${B}4${RESET}  Install ClickHouse"
        echo -e "   ${B}5${RESET}  Install RITA"
        echo -e "   ${B}6${RESET}  Apply Configuration"
        echo -e "   ${B}7${RESET}  Router Mode Setup"
        echo -e "   ${B}8${RESET}  Security Hardening"
        echo -e "   ${B}9${RESET}  Install Suricata IDS  ${DIM}(8 GB Pi only)${RESET}"
        echo -e "  ${B}10${RESET}  Install Pironman5  ${DIM}(case OLED display + fan control)${RESET}"
        echo ""
        echo -e "   ${B}0${RESET}  Back"
        echo ""
        sep
        echo -n "  Select [0-10]: "
        read -r choice || true
        case "${choice:-}" in
            1) do_full_setup ;;
            2) do_system_deps ;;
            3) do_install_zeek ;;
            4) do_install_clickhouse ;;
            5) do_install_rita ;;
            6) do_configure ;;
            7) do_router_mode ;;
            8) do_harden ;;
            9) do_install_suricata ;;
            10) do_install_pironman5 ;;
            0|"") return ;;
            *) warn "Unknown option: ${choice}" ;;
        esac
    done
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

    echo -e "  ${B}${YELLOW}── DAILY OPERATIONS ─────────────────────────────────────${RESET}"
    echo -e "   ${B}1${RESET}  Morning Check  ${DIM}(health + import + report)${RESET}"
    echo -e "   ${B}2${RESET}  Run RITA Analysis"
    echo -e "   ${B}3${RESET}  Generate Beacon Report"
    echo -e "   ${B}4${RESET}  View Summary"
    echo -e "   ${B}5${RESET}  Health Check"
    echo -e "   ${B}6${RESET}  WAN Watchdog  ${DIM}(manual run)${RESET}"
    echo -e "   ${B}7${RESET}  Storage Housekeeping"
    echo -e "   ${B}8${RESET}  Suricata Events Review"
    echo ""

    echo -e "  ${B}${YELLOW}── ASSET & FALSE POSITIVE MANAGEMENT ───────────────────${RESET}"
    echo -e "   ${B}9${RESET}  LAN Asset Inventory"
    echo -e "  ${B}10${RESET}  False Positives — List"
    echo -e "  ${B}11${RESET}  False Positives — Add"
    echo -e "  ${B}12${RESET}  False Positives — Remove"
    echo ""

    echo -e "  ${B}${YELLOW}── MIGRATION ────────────────────────────────────────────${RESET}"
    echo -e "  ${B}13${RESET}  Migration — Export  ${DIM}(package data from this Pi)${RESET}"
    echo -e "  ${B}14${RESET}  Migration — Import  ${DIM}(apply data on new Pi)${RESET}"
    echo -e "  ${B}15${RESET}  Migration — Checklist"
    echo ""
    echo -e "  ${B}${YELLOW}── SETTINGS ─────────────────────────────────────────────${RESET}"
    echo -e "  ${B}16${RESET}  Edit Configuration"
    echo -e "  ${B}17${RESET}  Show Current Configuration"
    echo -e "  ${B}18${RESET}  Installation & Setup  ${DIM}(Zeek, RITA, ClickHouse…)${RESET}"
    echo ""
    echo -e "   ${B}0${RESET}  Exit"
    echo ""
    sep
}

dispatch() {
    case "$1" in
        1)  do_morning_check ;;
        2)  do_analyze ;;
        3)  do_report ;;
        4)  do_summarize ;;
        5)  do_healthcheck ;;
        6)  do_wan_watchdog ;;
        7)  do_housekeeping ;;
        8)  do_suricata_review ;;
        9)  do_assets ;;
        10) do_fp_list ;;
        11) do_fp_add ;;
        12) do_fp_remove ;;
        13) require_root && run_script "$SCRIPT_DIR/migrate.sh" export ;;
        14) require_root && run_script "$SCRIPT_DIR/migrate.sh" import ;;
        15) bash "$SCRIPT_DIR/migrate.sh" checklist; press_enter ;;
        16) do_edit_config ;;
        17) hdr "Current Configuration"; echo ""; show_config_inline; press_enter ;;
        18) do_installation_menu ;;
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

# Interactive loop. `|| true`: a failed menu action (e.g. non-root picking a
# root-only item) must return to the menu, not kill the console via set -e.
while true; do
    print_menu
    echo -n "  Select [0-18]: "
    read -r choice || true
    dispatch "${choice:-}" || true
done
