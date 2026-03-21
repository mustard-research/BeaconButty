#!/usr/bin/env bash
# healthcheck.sh — BeaconButty system health check
#
# Checks every component and prints a colour-coded summary.
# Exit code: 0 = all OK, 1 = one or more failures.
#
# Usage:
#   sudo /usr/local/bin/beaconbutty-health.sh
#   sudo ./scripts/healthcheck.sh

# ── Colours ───────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    RED='\033[0;31m';   RESET='\033[0m'; BOLD='\033[1m'
else
    GREEN=''; YELLOW=''; RED=''; RESET=''; BOLD=''
fi

OK()   { echo -e "  ${GREEN}✓${RESET}  $*"; }
WARN() { echo -e "  ${YELLOW}!${RESET}  $*"; WARNINGS=$(( WARNINGS + 1 )); }
FAIL() { echo -e "  ${RED}✗${RESET}  $*"; FAILURES=$(( FAILURES + 1 )); }

FAILURES=0
WARNINGS=0

ZEEK_PREFIX="${ZEEK_PREFIX:-/opt/zeek}"
LOG_DIR="${LOG_DIR:-/opt/zeek/logs}"

# ── Header ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}BeaconButty Health Check — $(date '+%Y-%m-%d %H:%M %Z')${RESET}"
echo "────────────────────────────────────────────────────"

# ── 1. System ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}System${RESET}"

# Uptime
UPTIME=$(uptime -p 2>/dev/null || uptime)
OK "Uptime: $UPTIME"

# Memory
MEM_TOTAL=$(awk '/MemTotal/ {printf "%.0f", $2/1024}' /proc/meminfo)
MEM_AVAIL=$(awk '/MemAvailable/ {printf "%.0f", $2/1024}' /proc/meminfo)
MEM_PCT=$(( (MEM_TOTAL - MEM_AVAIL) * 100 / MEM_TOTAL ))
if [[ "$MEM_PCT" -lt 80 ]]; then
    OK "Memory: ${MEM_PCT}% used  (${MEM_AVAIL} MB free of ${MEM_TOTAL} MB)"
elif [[ "$MEM_PCT" -lt 90 ]]; then
    WARN "Memory: ${MEM_PCT}% used  (${MEM_AVAIL} MB free of ${MEM_TOTAL} MB)"
else
    FAIL "Memory: ${MEM_PCT}% used  (${MEM_AVAIL} MB free of ${MEM_TOTAL} MB) — critically low"
fi

# Disk
DISK_PCT=$(df / | awk 'NR==2 {gsub(/%/,"",$5); print $5}')
DISK_AVAIL=$(df -h / | awk 'NR==2 {print $4}')
if [[ "$DISK_PCT" -lt 80 ]]; then
    OK "Disk (/): ${DISK_PCT}% used  (${DISK_AVAIL} free)"
elif [[ "$DISK_PCT" -lt 90 ]]; then
    WARN "Disk (/): ${DISK_PCT}% used  (${DISK_AVAIL} free)"
else
    FAIL "Disk (/): ${DISK_PCT}% used  (${DISK_AVAIL} free) — critically full"
fi

# Load average
LOAD=$(cut -d' ' -f1-3 /proc/loadavg)
NCPU=$(nproc)
LOAD1=$(cut -d' ' -f1 /proc/loadavg | cut -d. -f1)
if [[ "$LOAD1" -le "$NCPU" ]]; then
    OK "Load average: $LOAD  (${NCPU} CPUs)"
else
    WARN "Load average: $LOAD  (${NCPU} CPUs) — elevated"
fi

# ── 2. Network interfaces ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Network Interfaces${RESET}"

for iface in eth0 eth1; do
    if ip link show "$iface" &>/dev/null; then
        STATE=$(ip link show "$iface" | grep -oP '(?<=state )\w+')
        IP=$(ip -4 addr show "$iface" 2>/dev/null | awk '/inet / {print $2}' | head -1)
        if [[ "$STATE" == "UP" ]]; then
            if [[ -n "$IP" ]]; then
                OK "${iface}: UP  ($IP)"
            else
                if [[ "$iface" == "eth1" ]]; then
                    OK "${iface}: UP  (no IP — correct for capture interface)"
                else
                    WARN "${iface}: UP but no IP address"
                fi
            fi
        else
            FAIL "${iface}: $STATE"
        fi
    else
        FAIL "${iface}: interface not found"
    fi
done

# WAN connectivity
if ping -c 1 -W 3 -q 1.1.1.1 &>/dev/null; then
    WAN_IP=$(ip -4 addr show eth0 2>/dev/null | awk '/inet / {print $2}' | head -1)
    OK "WAN reachable  (eth0: $WAN_IP)"
else
    FAIL "WAN unreachable — cannot ping 1.1.1.1"
fi

# ── 3. Routing & Firewall ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Routing & Firewall${RESET}"

# IP forwarding
if [[ "$(cat /proc/sys/net/ipv4/ip_forward)" == "1" ]]; then
    OK "IP forwarding: enabled"
else
    FAIL "IP forwarding: disabled — LAN clients cannot reach WAN"
fi

# NAT MASQUERADE on eth0
if iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE &>/dev/null 2>&1; then
    OK "NAT MASQUERADE: present on eth0"
else
    WARN "NAT MASQUERADE: no rule for -o eth0 — LAN clients may lack internet"
fi

# FORWARD rule LAN→WAN
if iptables -C FORWARD -i eth1 -o eth0 -m conntrack --ctstate NEW,RELATED,ESTABLISHED \
        -j ACCEPT &>/dev/null 2>&1; then
    OK "FORWARD rule: eth1 → eth0 present"
else
    WARN "FORWARD rule: eth1 → eth0 missing — check iptables"
fi

# External DNS — also flag if resolv.conf is pointing at Tailscale's resolver
if grep -q "100\.100\.100\.100" /etc/resolv.conf 2>/dev/null; then
    WARN "DNS: resolv.conf uses 100.100.100.100 (Tailscale) — system services may fail external lookups"
elif python3 -c "import socket; socket.setdefaulttimeout(3); socket.getaddrinfo('cloudflare.com', 80)" &>/dev/null 2>&1; then
    RESOLVERS=$(grep "^nameserver" /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ' | sed 's/ $//')
    OK "External DNS: resolving OK  (resolvers: ${RESOLVERS:-system default})"
else
    WARN "External DNS: failed to resolve cloudflare.com"
fi

# ── 4. Services ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Services${RESET}"

check_service() {
    local name="$1" label="$2"
    if systemctl is-active --quiet "$name" 2>/dev/null; then
        local since
        since=$(systemctl show "$name" --property=ActiveEnterTimestamp \
            | cut -d= -f2 | sed 's/ [A-Z]*$//')
        OK "${label}: running  (since ${since:-unknown})"
    else
        local status
        status=$(systemctl is-active "$name" 2>/dev/null || true)
        FAIL "${label}: ${status:-not found}"
    fi
}

check_service clickhouse-server  "ClickHouse"
check_service dnsmasq             "dnsmasq (DHCP/DNS)"

# Tailscale
if systemctl is-active --quiet tailscaled 2>/dev/null; then
    TS_IP=$(ip -4 addr show tailscale0 2>/dev/null | awk '/inet / {print $2}' | head -1)
    TS_PEERS=$(tailscale status 2>/dev/null | grep -c "^100\." || echo 0)
    if [[ -n "$TS_IP" ]]; then
        OK "Tailscale: connected  ($TS_IP, ${TS_PEERS} node(s) visible)"
    else
        WARN "Tailscale: daemon running but not connected"
    fi
else
    FAIL "Tailscale: tailscaled not running"
fi

# Zeek via zeekctl
if [[ -x "${ZEEK_PREFIX}/bin/zeekctl" ]]; then
    ZEEK_OUT=$(${ZEEK_PREFIX}/bin/zeekctl status 2>/dev/null)
    if echo "$ZEEK_OUT" | grep -q '\brunning\b'; then
        ZEEK_PID=$(echo "$ZEEK_OUT" | awk '/running/ {print $5}' | head -1)
        OK "Zeek: running  (pid ${ZEEK_PID:-?})"
    else
        # Skip header lines — match the 'zeek' worker row directly
        ZEEK_STATUS=$(echo "$ZEEK_OUT" | awk '/^zeek[[:space:]]/ {print $4}' | head -1)
        FAIL "Zeek: ${ZEEK_STATUS:-not running}"
    fi
else
    FAIL "Zeek: zeekctl not found at ${ZEEK_PREFIX}/bin/zeekctl"
fi

# ── 4. Zeek logs ──────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Zeek Logging${RESET}"

CURRENT="${LOG_DIR}/current"
if [[ -d "$CURRENT" ]]; then
    for logfile in conn.log dns.log; do
        if [[ -f "${CURRENT}/${logfile}" ]]; then
            SIZE=$(du -sh "${CURRENT}/${logfile}" 2>/dev/null | cut -f1)
            AGE=$(( $(date +%s) - $(stat -c %Y "${CURRENT}/${logfile}") ))
            if [[ "$AGE" -lt 120 ]]; then
                OK "${logfile}: present  (${SIZE}, modified ${AGE}s ago)"
            else
                WARN "${logfile}: present but not modified in ${AGE}s — Zeek may be idle"
            fi
        else
            FAIL "${logfile}: missing from ${CURRENT}"
        fi
    done

    # Count completed daily directories
    DAILY_COUNT=$(find "$LOG_DIR" -maxdepth 1 -type d \
        -name '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]' | wc -l)
    OK "Completed daily log directories: ${DAILY_COUNT}"
else
    FAIL "Zeek current log directory not found: $CURRENT"
fi

# ── 5. RITA / ClickHouse data ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}RITA / ClickHouse${RESET}"

if [[ -x /usr/local/bin/rita ]]; then
    OK "RITA binary: present  (/usr/local/bin/rita)"

    # Load env for ClickHouse connection
    [[ -f /etc/rita/env ]] && source /etc/rita/env
    export DB_ADDRESS="${DB_ADDRESS:-localhost:9000}"
    export CLICKHOUSE_USERNAME="${CLICKHOUSE_USERNAME:-default}"
    export CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-}"

    # rita needs to run from /etc/rita so it finds its .env file
    # rita list outputs a box-drawing table; extract dataset names from column 2
    RITA_LIST=$(cd /etc/rita && rita list 2>/dev/null | awk -F'│' '/beaconbutty_/ {gsub(/ /,"",$2); print $2}')
    DB_COUNT=$(echo "$RITA_LIST" | grep -c "beaconbutty_" || true)
    if [[ "$DB_COUNT" -gt 0 ]]; then
        LATEST_DB=$(echo "$RITA_LIST" | sort | tail -1)
        OK "RITA datasets: ${DB_COUNT}  (latest: ${LATEST_DB})"
    else
        WARN "RITA datasets: none yet — run rita-analyze.sh after Zeek logs accumulate"
    fi
else
    FAIL "RITA binary not found at /usr/local/bin/rita"
fi

# ClickHouse data size
CH_SIZE=$(du -sh /var/lib/clickhouse 2>/dev/null | cut -f1 || echo "unknown")
OK "ClickHouse data: ${CH_SIZE}"

# ── 6. Suricata IDS ───────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Suricata IDS${RESET}"

SURICATA_LOG_DIR="/var/log/suricata"

if ! command -v suricata &>/dev/null; then
    MEM_TOTAL_MB=$(awk '/MemTotal/ {printf "%.0f", $2/1024}' /proc/meminfo)
    if [[ "$MEM_TOTAL_MB" -lt 6000 ]]; then
        OK "Suricata: not installed  (4 GB Pi — requires 8 GB)"
    else
        WARN "Suricata: not installed  (run: sudo ./scripts/08_install_suricata.sh)"
    fi
else
    SURICATA_VER=$(suricata --build-info 2>/dev/null | awk '/^Version/ {print $2}' | head -1 || echo "unknown")
    check_service suricata "Suricata ${SURICATA_VER}"

    EVE_JSON="${SURICATA_LOG_DIR}/eve.json"
    if [[ -f "$EVE_JSON" ]]; then
        EVE_SIZE=$(du -sh "$EVE_JSON" 2>/dev/null | cut -f1)
        EVE_AGE=$(( $(date +%s) - $(stat -c %Y "$EVE_JSON") ))
        if [[ "$EVE_AGE" -lt 300 ]]; then
            OK "eve.json: active  (${EVE_SIZE}, modified ${EVE_AGE}s ago)"
        else
            WARN "eve.json: not updated in ${EVE_AGE}s — Suricata may not be capturing"
        fi
        ALERT_COUNT=$(grep -c '"event_type":"alert"' "$EVE_JSON" 2>/dev/null || echo 0)
        if [[ "$ALERT_COUNT" -gt 0 ]]; then
            WARN "Alerts in current log: ${ALERT_COUNT}  (review: sudo tail -f ${SURICATA_LOG_DIR}/fast.log)"
        else
            OK "Alerts in current log: 0"
        fi
    else
        WARN "eve.json not found — Suricata may still be starting"
    fi

    if [[ -f /var/lib/suricata/rules/suricata.rules ]]; then
        RULE_COUNT=$(grep -c '^alert' /var/lib/suricata/rules/suricata.rules 2>/dev/null || echo 0)
        RULE_AGE_DAYS=$(( ( $(date +%s) - $(stat -c %Y /var/lib/suricata/rules/suricata.rules) ) / 86400 ))
        OK "Rules: ${RULE_COUNT} active  (updated ${RULE_AGE_DAYS}d ago)"
    else
        WARN "Rule file not found — run: sudo suricata-update"
    fi
fi

# ── 7. Systemd timers ─────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Systemd Timers${RESET}"

check_timer() {
    local name="$1" label="$2"
    if systemctl is-enabled --quiet "${name}.timer" 2>/dev/null; then
        local next
        next=$(systemctl list-timers "${name}.timer" --no-legend 2>/dev/null \
            | awk '{print $1, $2}' | head -1)
        OK "${label}: enabled  (next: ${next:-unknown})"
    else
        WARN "${label}: timer not enabled"
    fi
}

check_timer rita-analyze              "RITA analyse (hourly)"
check_timer beacon-report             "Beacon report (07:00)"
check_timer beaconbutty-housekeeping  "Housekeeping (08:00)"
check_timer wan-watchdog              "WAN watchdog (5 min)"

if command -v suricata &>/dev/null; then
    check_timer suricata-update "Suricata rule update (06:00)"
fi

# ── 7. Recent log activity ────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Recent Activity${RESET}"

ANALYZE_LOG="/var/log/beaconbutty/analyze.log"
if [[ -f "$ANALYZE_LOG" ]]; then
    LAST_RUN=$(grep "rita-analyze started" "$ANALYZE_LOG" 2>/dev/null | tail -1 \
        | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' || echo "never")
    OK "Last RITA analyse: $LAST_RUN"
    # Check if the service is sitting in a failed state and why
    if systemctl is-failed --quiet rita-analyze.service 2>/dev/null; then
        LAST_LOG=$(tail -30 "$ANALYZE_LOG" 2>/dev/null)
        if echo "$LAST_LOG" | grep -q "all files were previously imported"; then
            WARN "rita-analyze.service: failed state — cause is benign (all files already imported); rita-analyze.sh has been fixed to exit 0 in this case"
        else
            FAIL "rita-analyze.service: last run failed — check $ANALYZE_LOG"
        fi
    fi
else
    WARN "RITA analyse log not found — has rita-analyze.sh run yet?"
fi

REPORT_COUNT=$(find /var/lib/beaconbutty/reports -name "beacon-report-*.txt" 2>/dev/null | wc -l)
if [[ "$REPORT_COUNT" -gt 0 ]]; then
    LATEST_REPORT=$(find /var/lib/beaconbutty/reports -name "beacon-report-*.txt" \
        | sort | tail -1)
    OK "Beacon reports: ${REPORT_COUNT}  (latest: $(basename "$LATEST_REPORT"))"
else
    WARN "No beacon reports yet — generated daily at 07:00"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────────────────"
if [[ "$FAILURES" -eq 0 && "$WARNINGS" -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}All checks passed.${RESET}"
elif [[ "$FAILURES" -eq 0 ]]; then
    echo -e "${YELLOW}${BOLD}${WARNINGS} warning(s), no failures.${RESET}"
else
    echo -e "${RED}${BOLD}${FAILURES} failure(s), ${WARNINGS} warning(s).${RESET}"
fi
echo ""

exit $(( FAILURES > 0 ? 1 : 0 ))
