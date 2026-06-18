#!/usr/bin/env bash
# healthcheck.sh — BeaconButty system health check
#
# Checks every component and prints a colour-coded summary.
# Exit code: 0 = all OK, 1 = one or more failures.
#
# Usage:
#   sudo /usr/local/bin/beaconbutty-health.sh
#   sudo ./scripts/healthcheck.sh

# ── Site-local overrides ──────────────────────────────────────────────────────
if [[ -f /etc/beaconbutty/local.env ]]; then
    set -a; . /etc/beaconbutty/local.env; set +a
fi
BB_HOST="${BB_HOST:-beaconbutty.local}"
BB_TLS_CERT_DIR="${BB_TLS_CERT_DIR:-/etc/letsencrypt/live}"

# ── Flags ─────────────────────────────────────────────────────────────────────
JSON_MODE=0
if [[ "${1:-}" == "--json" ]]; then
    JSON_MODE=1
    shift
fi

# ── Colours ───────────────────────────────────────────────────────────────────
if [[ -t 1 && "$JSON_MODE" == "0" ]]; then
    GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    RED='\033[0;31m';   RESET='\033[0m'; BOLD='\033[1m'
else
    GREEN=''; YELLOW=''; RED=''; RESET=''; BOLD=''
fi

# Current section name — set by section(); referenced by OK/WARN/FAIL in JSON mode.
CURRENT_SECTION=""
JSON_TMP=""
if [[ "$JSON_MODE" == "1" ]]; then
    JSON_TMP=$(mktemp)
    trap 'rm -f "$JSON_TMP"' EXIT
fi

section() {
    CURRENT_SECTION="$1"
    if [[ "$JSON_MODE" == "0" ]]; then
        echo ""
        echo -e "${BOLD}${1}${RESET}"
    fi
}

# Emit a check result. TAB-separated tuple to JSON_TMP in JSON mode; coloured line otherwise.
OK() {
    if [[ "$JSON_MODE" == "1" ]]; then
        printf '%s\t%s\t%s\n' "$CURRENT_SECTION" "ok" "$*" >> "$JSON_TMP"
    else
        echo -e "  ${GREEN}✓${RESET}  $*"
    fi
}
WARN() {
    if [[ "$JSON_MODE" == "1" ]]; then
        printf '%s\t%s\t%s\n' "$CURRENT_SECTION" "warn" "$*" >> "$JSON_TMP"
    else
        echo -e "  ${YELLOW}!${RESET}  $*"
    fi
    WARNINGS=$(( WARNINGS + 1 ))
}
FAIL() {
    if [[ "$JSON_MODE" == "1" ]]; then
        printf '%s\t%s\t%s\n' "$CURRENT_SECTION" "fail" "$*" >> "$JSON_TMP"
    else
        echo -e "  ${RED}✗${RESET}  $*"
    fi
    FAILURES=$(( FAILURES + 1 ))
}

FAILURES=0
WARNINGS=0
SEND_ALERTS="${SEND_ALERTS:-0}"

ALERT_BIN="${ALERT_BIN:-beaconbutty-alert.sh}"

# Fire a non-blocking alert if the alert script is available.
send_alert() {
    if command -v "$ALERT_BIN" &>/dev/null; then
        "$ALERT_BIN" "$@" 2>/dev/null || true
    fi
}

ZEEK_PREFIX="${ZEEK_PREFIX:-/opt/zeek}"
LOG_DIR="${LOG_DIR:-/var/log/zeek}"

# ── Header ────────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == "0" ]]; then
    echo ""
    echo -e "${BOLD}BeaconButty Health Check — $(date '+%Y-%m-%d %H:%M %Z')${RESET}"
    echo "────────────────────────────────────────────────────"
fi

# ── 1. System ─────────────────────────────────────────────────────────────────
section "System"

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
    send_alert disk_critical high bb0 "Disk ${DISK_PCT}% used (${DISK_AVAIL} free)"
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

# CPU temperature
if command -v vcgencmd &>/dev/null; then
    TEMP=$(vcgencmd measure_temp 2>/dev/null | grep -oP '\d+\.\d+')
    TEMP_INT=${TEMP%.*}
    if [[ -n "$TEMP_INT" ]]; then
        if [[ "$TEMP_INT" -lt 70 ]]; then
            OK "CPU temperature: ${TEMP}°C"
        elif [[ "$TEMP_INT" -lt 80 ]]; then
            WARN "CPU temperature: ${TEMP}°C — elevated"
        else
            FAIL "CPU temperature: ${TEMP}°C — critical"
        fi
    fi

    # Throttling — bits 0-3 = currently throttled, bits 16-19 = occurred since boot.
    # Distinguish "active now" (WARN) from "stale historical flag" (OK with note).
    THROTTLED=$(vcgencmd get_throttled 2>/dev/null | cut -d= -f2)
    if [[ "$THROTTLED" == "0x0" ]]; then
        OK "Throttling: none since boot"
    elif [[ -n "$THROTTLED" ]]; then
        CURRENT_BITS=$(( THROTTLED & 0xF ))
        if [[ "$CURRENT_BITS" -ne 0 ]]; then
            WARN "Throttling active now: ${THROTTLED} — see 'vcgencmd get_throttled' bits 0-3"
        else
            OK "Throttling: clear now (${THROTTLED} — historical flag only)"
        fi
    fi
fi

# log2ram tmpfs (/var/log) — silently drops logs if it fills before daily sync
if mountpoint -q /var/log 2>/dev/null; then
    LOG2RAM_PCT=$(df /var/log | awk 'NR==2 {gsub(/%/,"",$5); print $5}')
    LOG2RAM_USED=$(df -h /var/log | awk 'NR==2 {print $3}')
    LOG2RAM_SIZE=$(df -h /var/log | awk 'NR==2 {print $2}')
    if [[ "$LOG2RAM_PCT" -lt 70 ]]; then
        OK "log2ram (/var/log): ${LOG2RAM_PCT}% used  (${LOG2RAM_USED} of ${LOG2RAM_SIZE})"
    elif [[ "$LOG2RAM_PCT" -lt 85 ]]; then
        WARN "log2ram (/var/log): ${LOG2RAM_PCT}% used  (${LOG2RAM_USED} of ${LOG2RAM_SIZE})"
    else
        FAIL "log2ram (/var/log): ${LOG2RAM_PCT}% used  (${LOG2RAM_USED} of ${LOG2RAM_SIZE}) — may drop logs before 23:55 sync"
    fi
fi

# Sustained-high-CPU state — reflects bb-watchdog's rolling 60-min CPU detector.
# WARN here if the detector is currently in elevated state; latest event file
# has the diagnostic snapshot.
HIGH_CPU_STATE="/var/lib/beaconbutty/watchdog/high-cpu-state.json"
if systemctl is-active --quiet bb-watchdog 2>/dev/null; then
    IN_ELEV="False"
    LAST_TS=""
    if [[ -f "$HIGH_CPU_STATE" ]]; then
        IN_ELEV=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('in_elevated_state', False))" "$HIGH_CPU_STATE" 2>/dev/null || echo "False")
        LAST_TS=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('last_alert_ts') or '')" "$HIGH_CPU_STATE" 2>/dev/null || echo "")
    fi
    if [[ "$IN_ELEV" == "True" ]]; then
        LATEST_EVENT=$(ls -t /var/lib/beaconbutty/watchdog/high-cpu-events/*.json 2>/dev/null | head -1 || true)
        if [[ -n "$LATEST_EVENT" ]]; then
            TOP_COMM=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); tp=d.get('top_processes') or [{}]; print(tp[0].get('comm','?'))" "$LATEST_EVENT" 2>/dev/null || echo "?")
            WARN "Sustained-high CPU: ELEVATED  (last alert ${LAST_TS}, top consumer: ${TOP_COMM}; diagnostic: ${LATEST_EVENT})"
        else
            WARN "Sustained-high CPU: ELEVATED  (last alert ${LAST_TS})"
        fi
    else
        OK "Sustained-high CPU: normal"
    fi
fi

# Time synchronisation — clock skew breaks TLS and log correlation
NTP_SYNCED=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
if [[ "$NTP_SYNCED" == "yes" ]]; then
    OK "Time sync: synchronised"
else
    WARN "Time sync: not synchronised (timedatectl)"
fi

# Pending reboot after unattended-upgrades
if [[ -f /var/run/reboot-required ]]; then
    PKGS=""
    [[ -f /var/run/reboot-required.pkgs ]] && \
        PKGS=" ($(wc -l < /var/run/reboot-required.pkgs) package(s))"
    WARN "Pending reboot: /var/run/reboot-required exists${PKGS}"
else
    OK "Pending reboot: none"
fi

# ── 2. Network interfaces ─────────────────────────────────────────────────────
section "Network Interfaces"

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
    send_alert service_down high bb0 "WAN unreachable (cannot ping 1.1.1.1)"
fi

# ── 3. Routing & Firewall ─────────────────────────────────────────────────────
section "Routing & Firewall"

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

# IPv4 INPUT default policy — must be DROP
IPV4_INPUT_POLICY=$(iptables -L INPUT --line-numbers -n 2>/dev/null | head -1 | grep -oP 'policy \K\w+' || echo "UNKNOWN")
if [[ "$IPV4_INPUT_POLICY" == "DROP" ]]; then
    OK "IPv4 INPUT policy: DROP"
else
    FAIL "IPv4 INPUT policy: ${IPV4_INPUT_POLICY} — should be DROP (run beaconbutty-harden.sh)"
    send_alert service_down high bb0 "IPv4 INPUT policy is ${IPV4_INPUT_POLICY} — firewall not in place"
fi

# IPv6 INPUT and FORWARD default policies — must be DROP
if command -v ip6tables &>/dev/null; then
    IPV6_INPUT_POLICY=$(ip6tables -L INPUT --line-numbers -n 2>/dev/null | head -1 | grep -oP 'policy \K\w+' || echo "UNKNOWN")
    IPV6_FWD_POLICY=$(ip6tables -L FORWARD --line-numbers -n 2>/dev/null | head -1 | grep -oP 'policy \K\w+' || echo "UNKNOWN")
    if [[ "$IPV6_INPUT_POLICY" == "DROP" && "$IPV6_FWD_POLICY" == "DROP" ]]; then
        OK "IPv6 INPUT/FORWARD policy: DROP"
    else
        FAIL "IPv6 policies: INPUT=${IPV6_INPUT_POLICY} FORWARD=${IPV6_FWD_POLICY} — should both be DROP (run beaconbutty-harden.sh)"
        send_alert service_down high bb0 "IPv6 firewall not in place: INPUT=${IPV6_INPUT_POLICY} FORWARD=${IPV6_FWD_POLICY}"
    fi
else
    WARN "ip6tables not found — IPv6 firewall cannot be verified"
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
section "Services"

check_service() {
    local name="$1" label="$2" do_alert="${3:-}"
    if systemctl is-active --quiet "$name" 2>/dev/null; then
        local since
        since=$(systemctl show "$name" --property=ActiveEnterTimestamp \
            | cut -d= -f2 | sed 's/ [A-Z]*$//')
        OK "${label}: running  (since ${since:-unknown})"
    else
        local status
        status=$(systemctl is-active "$name" 2>/dev/null || true)
        FAIL "${label}: ${status:-not found}"
        [[ -n "$do_alert" ]] && send_alert service_down high bb0 "${label} is not running (${status:-not found})"
    fi
}

check_service clickhouse-server  "ClickHouse"  alert

# ClickHouse version staleness — informational unless very far behind.
# Versions encode YY.M.patch.build, so we measure "months behind" from
# the year+month components (no need for a date table). Packages are
# apt-mark hold'd to prevent surprise upgrades — see Upgrade Log
# 2026-06-16 for the latent-regression incident that led to the hold.
CH_INSTALLED=$(dpkg-query -W -f='${Version}' clickhouse-server 2>/dev/null || true)
CH_CANDIDATE=$(LC_ALL=C apt-cache policy clickhouse-server 2>/dev/null \
    | awk '/Candidate:/ {print $2}')
CH_HELD=""
if apt-mark showhold 2>/dev/null | grep -qx "clickhouse-server"; then
    CH_HELD="; held"
fi
if [[ -n "$CH_INSTALLED" && -n "$CH_CANDIDATE" && "$CH_CANDIDATE" != "(none)" ]]; then
    if [[ "$CH_INSTALLED" == "$CH_CANDIDATE" ]]; then
        OK "ClickHouse version: ${CH_INSTALLED}  (up to date${CH_HELD})"
    else
        # Parse YY.M from each version (first two dotted components)
        inst_y=$(echo "$CH_INSTALLED" | cut -d. -f1)
        inst_m=$(echo "$CH_INSTALLED" | cut -d. -f2)
        cand_y=$(echo "$CH_CANDIDATE" | cut -d. -f1)
        cand_m=$(echo "$CH_CANDIDATE" | cut -d. -f2)
        BEHIND_MONTHS="?"
        if [[ "$inst_y" =~ ^[0-9]+$ && "$cand_y" =~ ^[0-9]+$ ]]; then
            BEHIND_MONTHS=$(( (cand_y - inst_y) * 12 + (cand_m - inst_m) ))
        fi
        # "release" vs "releases" pluralisation
        REL_WORD="releases"
        [[ "$BEHIND_MONTHS" == "1" ]] && REL_WORD="release"
        VERSION_STR="${CH_INSTALLED}  (latest: ${CH_CANDIDATE}, ${BEHIND_MONTHS} ${REL_WORD} behind${CH_HELD})"
        UPGRADE_HINT="run: sudo beaconbutty-clickhouse-upgrade.sh"
        if [[ "$BEHIND_MONTHS" =~ ^[0-9]+$ ]] && (( BEHIND_MONTHS >= 3 )); then
            WARN "ClickHouse version: ${VERSION_STR} — ${UPGRADE_HINT}"
        else
            OK "ClickHouse version: ${VERSION_STR} — ${UPGRADE_HINT}"
        fi
    fi
fi

check_service dnsmasq             "dnsmasq (DHCP/DNS)"  alert
check_service bb-graphs           "Webapp (bb-graphs)"  alert

# Tailscale
if systemctl is-active --quiet tailscaled 2>/dev/null; then
    TS_IP=$(ip -4 addr show tailscale0 2>/dev/null | awk '/inet / {print $2}' | head -1)
    TS_PEERS=$(tailscale status 2>/dev/null | grep -c "^100\.") || TS_PEERS=0
    if [[ -n "$TS_IP" ]]; then
        OK "Tailscale: connected  ($TS_IP, ${TS_PEERS} node(s) visible)"
    else
        WARN "Tailscale: daemon running but not connected"
    fi
else
    FAIL "Tailscale: tailscaled not running"
fi

# TLS certificate expiry — matches the cert card on the Health page
CERT_FILE="${BB_TLS_CERT_DIR}/${BB_HOST}/fullchain.pem"
if [[ -f "$CERT_FILE" ]]; then
    CERT_END=$(openssl x509 -in "$CERT_FILE" -noout -enddate 2>/dev/null | cut -d= -f2)
    CERT_END_EPOCH=""
    [[ -n "$CERT_END" ]] && CERT_END_EPOCH=$(date -d "$CERT_END" +%s 2>/dev/null)
    if [[ -n "$CERT_END_EPOCH" ]]; then
        DAYS_LEFT=$(( (CERT_END_EPOCH - $(date +%s)) / 86400 ))
        if [[ "$DAYS_LEFT" -gt 30 ]]; then
            OK "TLS cert: ${DAYS_LEFT} days remaining"
        elif [[ "$DAYS_LEFT" -gt 14 ]]; then
            WARN "TLS cert: ${DAYS_LEFT} days remaining — renew soon"
        else
            FAIL "TLS cert: ${DAYS_LEFT} days remaining — expires soon (check certbot)"
        fi
    else
        WARN "TLS cert: could not parse expiry date from ${CERT_FILE}"
    fi
else
    WARN "TLS cert: ${CERT_FILE} not found"
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
        send_alert service_down high bb0 "Zeek is not running (${ZEEK_STATUS:-not running})"
    fi
else
    FAIL "Zeek: zeekctl not found at ${ZEEK_PREFIX}/bin/zeekctl"
    send_alert service_down high bb0 "Zeek not installed — zeekctl not found"
fi

# ── 4. Zeek logs ──────────────────────────────────────────────────────────────
section "Zeek Logging"

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

    # conn.log capture rate — rows with ts newer than 5 min ago
    # Catches "Zeek process up but not capturing" (mtime alone can lie).
    # Zeek rotates conn.log hourly, so if the health check runs in the first
    # few minutes of an hour, the live file only covers a few seconds. Also
    # scan the most recent archived conn.*.log.gz so the window is faithful
    # across rotation boundaries.
    if [[ -f "${CURRENT}/conn.log" ]]; then
        FIVE_MIN_AGO=$(( $(date +%s) - 300 ))
        LIVE_CONNS=$(awk -v t="$FIVE_MIN_AGO" '!/^#/ && ($1+0) > t' \
            "${CURRENT}/conn.log" 2>/dev/null | wc -l)
        # Pull archive rows only when the live file was rotated inside the
        # window. Otherwise the live file already covers it.
        LIVE_FIRST_TS=$(awk '!/^#/{print int($1); exit}' \
            "${CURRENT}/conn.log" 2>/dev/null)
        ARCH_CONNS=0
        if [[ -n "$LIVE_FIRST_TS" && "$LIVE_FIRST_TS" -gt "$FIVE_MIN_AGO" ]]; then
            LATEST_ARCHIVE=$(ls -t "$LOG_DIR"/[0-9]*/conn.*.log.gz 2>/dev/null | head -1)
            if [[ -n "$LATEST_ARCHIVE" ]]; then
                ARCH_CONNS=$(zcat "$LATEST_ARCHIVE" 2>/dev/null \
                    | awk -v t="$FIVE_MIN_AGO" '!/^#/ && ($1+0) > t' | wc -l)
            fi
        fi
        RECENT_CONNS=$(( LIVE_CONNS + ARCH_CONNS ))
        if [[ "$RECENT_CONNS" -gt 10 ]]; then
            OK "Capture rate: ${RECENT_CONNS} conn rows in last 5 min"
        elif [[ "$RECENT_CONNS" -gt 0 ]]; then
            WARN "Capture rate: only ${RECENT_CONNS} conn rows in last 5 min — light traffic or partial capture"
        else
            FAIL "Capture rate: 0 conn rows in last 5 min — Zeek may be up but not capturing"
        fi
    fi
else
    FAIL "Zeek current log directory not found: $CURRENT"
fi

# ── 5. RITA / ClickHouse data ─────────────────────────────────────────────────
section "RITA / ClickHouse"

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

# ClickHouse query probe — "service up" is not the same as "actually responsive"
if command -v clickhouse-client &>/dev/null; then
    CH_ARGS=(--user="${CLICKHOUSE_USERNAME:-default}")
    [[ -n "${CLICKHOUSE_PASSWORD:-}" ]] && CH_ARGS+=(--password="$CLICKHOUSE_PASSWORD")
    CH_PROBE=$(timeout 5 clickhouse-client "${CH_ARGS[@]}" -q "SELECT 1" 2>/dev/null)
    if [[ "$CH_PROBE" == "1" ]]; then
        OK "ClickHouse query probe: responsive  (SELECT 1 OK)"
    else
        FAIL "ClickHouse query probe: unresponsive — server may be wedged"
        send_alert service_down high bb0 "ClickHouse not responding to SELECT 1"
    fi
fi

# ClickHouse data size
CH_SIZE=$(du -sh /var/lib/clickhouse 2>/dev/null | cut -f1 || echo "unknown")
OK "ClickHouse data: ${CH_SIZE}"

# ── 6. Suricata IDS ───────────────────────────────────────────────────────────
section "Suricata IDS"

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
    check_service suricata "Suricata ${SURICATA_VER}" alert

    # stats.log is rewritten every 60s regardless of traffic — the reliable capture-liveness
    # signal. eve.json now carries only alert/anomaly events (trimmed 2026-05-15), so a stale
    # eve.json just means a quiet network, not a Suricata failure.
    STATS_LOG="${SURICATA_LOG_DIR}/stats.log"
    if [[ -f "$STATS_LOG" ]]; then
        STATS_AGE=$(( $(date +%s) - $(stat -c %Y "$STATS_LOG") ))
        if [[ "$STATS_AGE" -lt 180 ]]; then
            OK "Capture: active  (stats.log updated ${STATS_AGE}s ago)"
        else
            WARN "Capture: stats.log not updated in ${STATS_AGE}s — Suricata may not be capturing"
        fi
    else
        WARN "stats.log not found — Suricata may still be starting"
    fi

    EVE_JSON="${SURICATA_LOG_DIR}/eve.json"
    if [[ -f "$EVE_JSON" ]]; then
        EVE_SIZE=$(du -sh "$EVE_JSON" 2>/dev/null | cut -f1)
        EVE_AGE=$(( $(date +%s) - $(stat -c %Y "$EVE_JSON") ))
        OK "eve.json: ${EVE_SIZE}  (last alert/anomaly ${EVE_AGE}s ago)"
        TODAY_DATE=$(date +%m/%d/%Y)
        FAST_LOG="${SURICATA_LOG_DIR}/fast.log"
        TODAY_ALERTS=$(grep -c "^${TODAY_DATE}" "$FAST_LOG" 2>/dev/null) || TODAY_ALERTS=0
        HIGH_PRI=$(grep "^${TODAY_DATE}" "$FAST_LOG" 2>/dev/null | grep -c '\[Priority: [12]\]') || HIGH_PRI=0
        if [[ "$HIGH_PRI" -gt 0 ]]; then
            WARN "Today's alerts: ${TODAY_ALERTS}  (${HIGH_PRI} high-priority P1/P2 — review: sudo tail -f ${FAST_LOG})"
        else
            OK "Today's alerts: ${TODAY_ALERTS}  (no high-priority alerts)"
        fi
    else
        WARN "eve.json not found — Suricata may still be starting"
    fi

    if [[ -f /var/lib/suricata/rules/suricata.rules ]]; then
        RULE_COUNT=$(grep -c '^alert' /var/lib/suricata/rules/suricata.rules 2>/dev/null) || RULE_COUNT=0
        RULE_AGE_DAYS=$(( ( $(date +%s) - $(stat -c %Y /var/lib/suricata/rules/suricata.rules) ) / 86400 ))
        OK "Rules: ${RULE_COUNT} active  (updated ${RULE_AGE_DAYS}d ago)"
    else
        WARN "Rule file not found — run: sudo suricata-update"
    fi
fi

# ── 7. Systemd timers ─────────────────────────────────────────────────────────
section "Systemd Timers"

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
check_timer beaconbutty-health        "Health check (09:30)"
check_timer wan-watchdog              "WAN watchdog (5 min)"

if command -v suricata &>/dev/null; then
    check_timer suricata-update "Suricata rule update (06:00)"
fi

# ── 7.5 Reboot readiness ──────────────────────────────────────────────────────
# Catch latent failures that wouldn't show up as a live-service problem but
# would block the next restart. The 2026-05-12 dnsmasq incident — a .bak file
# left in /etc/dnsmasq.d/ took the LAN offline at the next reboot — is the
# motivating case. See obsidian/.../Glob-Parsed Config Directories.md.
section "Reboot Readiness"

# Daemon pre-start validators: would the service come back on next boot?
if [[ -x /usr/share/dnsmasq/systemd-helper ]]; then
    if /usr/share/dnsmasq/systemd-helper checkconfig >/dev/null 2>&1; then
        OK "dnsmasq: config would start cleanly"
    else
        FAIL "dnsmasq: config would FAIL on next boot — run: sudo /usr/share/dnsmasq/systemd-helper checkconfig"
        send_alert config_invalid high bb0 "dnsmasq config invalid — would fail to start on reboot"
    fi
fi
if command -v logrotate &>/dev/null; then
    if logrotate -d /etc/logrotate.conf >/dev/null 2>&1; then
        OK "logrotate: config parses cleanly"
    else
        FAIL "logrotate: config has errors — run: sudo logrotate -d /etc/logrotate.conf"
    fi
fi
if command -v visudo &>/dev/null; then
    if visudo -cqf /etc/sudoers >/dev/null 2>&1; then
        OK "sudoers: config parses cleanly"
    else
        FAIL "sudoers: config has errors — run: sudo visudo -c"
    fi
fi

# Sweep glob-everything .d/ directories for stray backup-style files that
# daemons silently parse (filename suffix doesn't protect — see incident).
STRAY=()
for d in /etc/dnsmasq.d /etc/logrotate.d /etc/apt/apt.conf.d /etc/sudoers.d /etc/cron.d; do
    [[ -d "$d" ]] || continue
    while IFS= read -r f; do STRAY+=("$f"); done < <(
        find "$d" -maxdepth 1 -type f \
            \( -name '*.bak' -o -name '*.bak.*' -o -name '*.old' -o -name '*.orig' \
               -o -name '*.save' -o -name '*~' -o -name '*.disabled' \
               -o -name '*.dpkg-old' -o -name '*.dpkg-dist' -o -name '*.dpkg-new' \
               -o -name '*.ucf-old' -o -name '*.ucf-dist' -o -name '*.ucf-new' \) \
            2>/dev/null
    )
done
if (( ${#STRAY[@]} == 0 )); then
    OK "no stray .bak/.old/.dpkg-* files in glob-parsed config dirs"
else
    # Auto-quarantine: move each stray OUT of the parse path so daemons can't
    # reload it at restart (root-cause was an 18-day-dormant dnsmasq .bak that
    # broke DHCP/DNS at reboot — incident 2026-05-12).
    QUARANTINE_TS=$(date -u +%Y%m%dT%H%M%SZ)
    QUARANTINE_BASE="/var/lib/beaconbutty/config-quarantine/${QUARANTINE_TS}"
    install -d -m 0700 "$QUARANTINE_BASE" 2>/dev/null || true
    MOVED=()
    FAILED=()
    for f in "${STRAY[@]}"; do
        dest="${QUARANTINE_BASE}${f}"
        if install -d -m 0700 "$(dirname "$dest")" 2>/dev/null && mv -- "$f" "$dest" 2>/dev/null; then
            FAIL "stray config artefact: $f — quarantined to $dest"
            MOVED+=("${f}→${dest}")
        else
            FAIL "stray config artefact: $f — quarantine move FAILED, manual cleanup required"
            FAILED+=("$f")
        fi
    done
    if (( ${#MOVED[@]} > 0 )); then
        # Join with "; " for human-readable detail (IFS joins on first byte only).
        MOVED_LIST=""
        for m in "${MOVED[@]}"; do
            MOVED_LIST+="${MOVED_LIST:+; }${m}"
        done
        send_alert config_stray_files high bb0 "${#MOVED[@]} stray file(s) quarantined: ${MOVED_LIST}"
    fi
    if (( ${#FAILED[@]} > 0 )); then
        send_alert config_stray_files high bb0 "${#FAILED[@]} stray file(s) — quarantine FAILED, manual cleanup: ${FAILED[*]}"
    fi
fi

# ── 8. Recent log activity ────────────────────────────────────────────────────
section "Recent Activity"

ANALYZE_LOG="/var/log/beaconbutty/analyze.log"
if [[ -f "$ANALYZE_LOG" ]]; then
    LAST_RUN=$(grep "rita-analyze started" "$ANALYZE_LOG" 2>/dev/null | tail -1 \
        | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' || echo "never")
    OK "Last RITA analyse: $LAST_RUN"

    # Age of the last *successful* import. rita-analyze.sh only prints
    # "=== done:" if it ran end-to-end without dying — a mid-flight
    # ClickHouse memory error (or any other fatal exit) suppresses it.
    # The hourly timer means a healthy system has a done-marker every hour;
    # gaps point at silent breakage that "last attempt" timestamps miss.
    LAST_DONE=$(grep "^=== done:" "$ANALYZE_LOG" 2>/dev/null | tail -1 \
        | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}' || true)
    if [[ -n "$LAST_DONE" ]]; then
        LAST_DONE_SEC=$(date -d "$LAST_DONE" +%s 2>/dev/null || echo 0)
        if [[ "$LAST_DONE_SEC" -gt 0 ]]; then
            AGE_SEC=$(( $(date +%s) - LAST_DONE_SEC ))
            AGE_MIN=$(( AGE_SEC / 60 ))
            if (( AGE_SEC >= 21600 )); then
                FAIL "RITA last successful import: ${AGE_MIN} min ago — hourly timer broken for ≥6h"
            elif (( AGE_SEC >= 5400 )); then
                WARN "RITA last successful import: ${AGE_MIN} min ago — at least one hourly run failed"
            else
                OK "RITA last successful import: ${AGE_MIN} min ago"
            fi
        fi
    else
        WARN "No '=== done:' marker found in $ANALYZE_LOG — rita-analyze.sh has not completed a run"
    fi

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

for _svc in beacon-report beaconbutty-housekeeping beaconbutty-backup; do
    if systemctl is-failed --quiet "${_svc}.service" 2>/dev/null; then
        FAIL "${_svc}.service: last run failed — check: journalctl -u ${_svc}.service -n 50"
    fi
done

REPORT_COUNT=$(find /var/lib/beaconbutty/reports -name "beacon-report-*.txt" 2>/dev/null | wc -l)
if [[ "$REPORT_COUNT" -gt 0 ]]; then
    LATEST_REPORT=$(find /var/lib/beaconbutty/reports -name "beacon-report-*.txt" \
        | sort | tail -1)
    OK "Beacon reports: ${REPORT_COUNT}  (latest: $(basename "$LATEST_REPORT"))"
else
    WARN "No beacon reports yet — generated daily at 07:00"
fi

# Backup freshness — daily config snapshot (02:00)
BACKUP_DIR="/var/lib/beaconbutty/backups"
LATEST_BACKUP=$(find "$BACKUP_DIR" -maxdepth 1 -name "config-*.tar.gz" 2>/dev/null \
    | sort | tail -1)
if [[ -n "$LATEST_BACKUP" ]]; then
    BACKUP_AGE_SEC=$(( $(date +%s) - $(stat -c %Y "$LATEST_BACKUP") ))
    BACKUP_AGE_DAYS=$(( BACKUP_AGE_SEC / 86400 ))
    BACKUP_NAME=$(basename "$LATEST_BACKUP")
    if [[ "$BACKUP_AGE_DAYS" -lt 1 ]]; then
        AGE_STR="$(( BACKUP_AGE_SEC / 3600 ))h"
    else
        AGE_STR="${BACKUP_AGE_DAYS}d"
    fi
    if [[ "$BACKUP_AGE_DAYS" -le 1 ]]; then
        OK "Latest backup: ${BACKUP_NAME}  (${AGE_STR} old)"
    elif [[ "$BACKUP_AGE_DAYS" -le 3 ]]; then
        WARN "Latest backup: ${BACKUP_NAME}  (${AGE_STR} old — timer may be stuck)"
    else
        FAIL "Latest backup: ${BACKUP_NAME}  (${AGE_STR} old — backups not running)"
    fi
else
    WARN "No backups found in ${BACKUP_DIR}"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == "0" ]]; then
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
fi

# ── Catch-all alert (only from scheduled timer, not interactive/webapp runs) ──
if [[ "$SEND_ALERTS" == "1" && "$FAILURES" -gt 0 ]]; then
    send_alert health_check_fail high bb0 \
        "Health check: ${FAILURES} failure(s), ${WARNINGS} warning(s) — review the Health page"
fi

# ── JSON output ───────────────────────────────────────────────────────────────
if [[ "$JSON_MODE" == "1" ]]; then
    python3 - "$JSON_TMP" "$FAILURES" "$WARNINGS" <<'PY'
import json, sys
from datetime import datetime
tmp, failures, warnings = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
sections_map = {}
order = []
with open(tmp) as f:
    for line in f:
        parts = line.rstrip("\n").split("\t", 2)
        if len(parts) != 3:
            continue
        sec, status, msg = parts
        if sec not in sections_map:
            sections_map[sec] = []
            order.append(sec)
        sections_map[sec].append({"status": status, "message": msg})
out = {
    "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
    "failures": failures,
    "warnings": warnings,
    "sections": [{"name": s, "checks": sections_map[s]} for s in order],
}
print(json.dumps(out, indent=2))
PY
fi

exit $(( FAILURES > 0 ? 1 : 0 ))
