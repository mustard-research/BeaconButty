#!/usr/bin/env bash
set -euo pipefail

# wan-watchdog.sh
#
# Runs every minute via wan-watchdog.timer (was 5-minutely until 2026-08-30 —
# the cadence bounds how precisely an outage's ONSET can be known, which no
# amount of escalation after detection can improve). Two independent checks:
#   1. WAN interface has an IP (self-recover only for our stack)
#   2. External DNS still resolves (tripwire for a silently-broken resolv.conf)
#
# When the external probes fail we additionally probe the ISP gateway, purely to
# classify the outage in the log: gateway up means the break is upstream of it
# (nothing we can do, and a reboot will not help), gateway down means the fault
# is in the link between us and the ISP. See the 2026-08-22 outage, where the
# log could not distinguish the two and a reboot was tried for no benefit.
#
# Reachability is monitored but NOT self-healed: three consecutive ping
# failures with a valid WAN IP means the ISP is down, not us — invoking a
# DHCP client behind NetworkManager's back has historically wiped
# /etc/resolv.conf (2026-07-01 outage) and released NM's own lease, so we
# now log-only for that branch.
#
# State:
#   /var/lib/beaconbutty/wan-fails       — consecutive ping-failure count
#   /var/lib/beaconbutty/dns-fails       — consecutive DNS-failure count
#   /var/lib/beaconbutty/wan-status.json — machine-readable state for /health
#   /var/log/beaconbutty/watchdog.log    — human-readable log

WAN_IFACE="${WAN_IFACE:-eth0}"
NM_CONN="${NM_CONN:-bb-wan}"    # NetworkManager connection profile for WAN
# The threshold is a DURATION, not a number of checks. It gates two actions —
# re-applying the NM connection when the WAN has no IP, and firing the DNS
# service_down alert — and both mean "this has been broken for a quarter of an
# hour", not "this failed three times". Expressing it as a bare count meant the
# cadence change on 2026-08-30 (5 min → 1 min) would have silently retuned both
# from 15 minutes to 3 without a line of either being touched.
#
# CHECK_INTERVAL_SECS comes from the service unit, single-sourced from the
# timer's OnUnitActiveSec. This division is only valid while a run cannot
# outlast one tick — see RUN_DEADLINE_SECS below, which is what guarantees it.
CHECK_INTERVAL_SECS="${CHECK_INTERVAL_SECS:-60}"
FAIL_AFTER_SECS="${FAIL_AFTER_SECS:-900}"          # 15 min, unchanged since 2026-07
FAIL_THRESHOLD=$(( FAIL_AFTER_SECS / CHECK_INTERVAL_SECS ))
(( FAIL_THRESHOLD < 1 )) && FAIL_THRESHOLD=1

# Overridable so the failure path can be exercised against blackholed addresses
# without breaking the WAN. Nothing in production sets it.
PROBE_HOSTS="${PROBE_HOSTS:-1.1.1.1 8.8.8.8}"
DNS_PROBE_HOST="${DNS_PROBE_HOST:-cloudflare.com}"

# Once a check fails, drop to this cadence until we see recovery. Without it,
# recovery is only ever noticed by the next scheduled run, so every outage
# measures a whole probe interval and a 3-second VRRP failover is
# indistinguishable from a nine-minute transit break — which is precisely the
# question the classification is trying to answer. The ceiling leaves ~90s of
# slack before the timer refires; TimeoutStartSec must exceed it (see the unit).
# Bound the WHOLE run, not just the loop. The diagnostic burst before it is
# variable (a traceroute walking its full hop budget against a dead path is the
# slow case), so a ceiling measured from the end of the burst leaves total
# runtime unbounded and one slow burst away from a SIGTERM at TimeoutStartSec —
# which would kill the watchdog in the middle of the outage it exists to watch.
#
# It must also stay BELOW CHECK_INTERVAL_SECS. Two runs overlapping would make
# systemd skip ticks, which stops the consecutive-failure count advancing once
# per minute and quietly breaks the FAIL_THRESHOLD arithmetic above. That is why
# the long escalation ceiling shrank when the cadence went to 1 min: at this
# cadence the timer itself supplies the repetition, so the in-run loop only has
# to cover the gap until the next tick.
RUN_DEADLINE_SECS="${RUN_DEADLINE_SECS:-45}"
ESCALATE_INTERVAL="${ESCALATE_INTERVAL:-10}"

# Overridable alongside PROBE_HOSTS so a simulated outage can be run against
# scratch state and a scratch log instead of production ones. Nothing in
# production sets either.
STATE_DIR="${STATE_DIR:-/var/lib/beaconbutty}"
STATE_FILE="${STATE_DIR}/wan-fails"
DNS_STATE_FILE="${STATE_DIR}/dns-fails"
WAN_STATUS_FILE="${STATE_DIR}/wan-status.json"
# Start of the outage currently in progress, so every failing check appends its
# evidence to the same file. Removed on recovery.
OUTAGE_START_FILE="${STATE_DIR}/wan-outage-start"
DIAG_BIN="${DIAG_BIN:-/usr/local/lib/beaconbutty/bb_wan_diag.py}"
LOGFILE="${LOGFILE:-/var/log/beaconbutty/watchdog.log}"
ALERT_SH="/usr/local/bin/beaconbutty-alert.sh"

mkdir -p "$STATE_DIR" "$(dirname "$LOGFILE")"

log() {
    local msg="$*"
    echo "$(date --iso-8601=seconds)  $msg" >> "$LOGFILE"
    logger -t beaconbutty-watchdog "$msg"
}

read_count() { cat "$1" 2>/dev/null || echo 0; }
write_count() { echo "$2" > "$1"; }

# Default gateway for the WAN interface. The `dev $WAN_IFACE` scoping is
# load-bearing, not tidiness: bb0 is multi-homed (eth0 WAN + wlan0 on the LAN)
# and BOTH carry a default route, so an unscoped lookup also returns
# 192.168.50.1 — our own eth1 address, which always pings and would report a
# healthy gateway in the middle of a total WAN outage.
# `|| true` guards the pipeline against `set -o pipefail` when the iface is gone.
wan_gateway() {
    ip -4 route show default dev "$WAN_IFACE" 2>/dev/null \
        | awk '/via/ {print $3; exit}' || true
}

# Publish machine-readable state for the /health page. Written on EVERY run,
# the healthy ones included, so the dashboard can show "checked at HH:MM" and
# distinguish "all well" from "watchdog has stopped running".
#
# Atomic via same-filesystem mktemp + mv, so the webapp can never read a
# half-written file. All interpolated values are IPs, integers or strings we
# generate ourselves, so none of them can contain a quote or backslash.
write_status() {
    local state="$1" verdict="$2" gw="$3" gw_reach="$4" fails="$5" dns_ok="$6"
    local tmp
    tmp=$(mktemp "${STATE_DIR}/.wan-status.XXXXXX") || return 0
    cat > "$tmp" <<EOF
{
  "state": "${state}",
  "verdict": "${verdict}",
  "wan_iface": "${WAN_IFACE}",
  "wan_ip": "${WAN_IP:-}",
  "gateway": "${gw}",
  "gateway_reachable": ${gw_reach},
  "fails": ${fails},
  "threshold": ${FAIL_THRESHOLD},
  "dns_ok": ${dns_ok},
  "checked_at": "$(date --iso-8601=seconds)"
}
EOF
    chmod 644 "$tmp"
    mv -f "$tmp" "$WAN_STATUS_FILE" || rm -f "$tmp"
}

# ── DHCP renewal via NetworkManager only ──────────────────────────────────────
# On bb0 NM owns eth0 (see scripts/07_router_mode.sh). NEVER invoke the
# `dhclient` or `dhcpcd` binaries directly — dhcpcd-base is installed as a
# transitive dep but running the daemon behind NM's back releases NM's lease
# and its 20-resolv.conf hook overwrites /etc/resolv.conf with an empty file.
renew_wan_lease() {
    if command -v nmcli >/dev/null 2>&1 \
       && nmcli -t -f NAME con show --active 2>/dev/null | grep -qx "$NM_CONN"; then
        log "Renewing $NM_CONN via nmcli (device reapply $WAN_IFACE)"
        nmcli device reapply "$WAN_IFACE" 2>/dev/null || \
            { nmcli connection down "$NM_CONN" 2>/dev/null || true;
              sleep 1;
              nmcli connection up   "$NM_CONN" 2>/dev/null || true; }
    else
        log "SKIPPED: no NetworkManager connection '$NM_CONN' active — refusing to invoke dhcpcd/dhclient (would wipe /etc/resolv.conf)"
    fi
}

# When did we last see a healthy WAN? wan-status.json records checked_at on
# every run, healthy ones included, so reading it before we overwrite it brackets
# the onset: the outage began somewhere between LAST_OK_AT and the first failing
# check. Escalation can pin recovery to ~10s but nothing can pin the start after
# the fact, so this bracket is the only honest answer to "how long was it down".
LAST_OK_AT=""
if [[ -f "$WAN_STATUS_FILE" ]]; then
    LAST_OK_AT=$(python3 -c '
import json, sys
try:
    st = json.load(open(sys.argv[1]))
    print(st.get("checked_at", "") if st.get("state") == "ok" else "")
except Exception:
    print("")
' "$WAN_STATUS_FILE" 2>/dev/null || true)
fi

# ── Check 1: WAN interface has an IP ──────────────────────────────────────────
# `|| true` is required, not defensive noise: if $WAN_IFACE does not exist at
# all (driver crash, NIC renamed, cable-side rename), `ip` exits non-zero and
# `set -o pipefail` + `set -e` would kill the script HERE — silently skipping
# the very recovery branch below that exists to handle a missing interface.
WAN_IP=$(ip -4 addr show "$WAN_IFACE" 2>/dev/null | awk '/inet / {print $2}' | head -1 || true)

if [[ -z "$WAN_IP" ]]; then
    FAILS=$(( $(read_count "$STATE_FILE") + 1 ))
    write_count "$STATE_FILE" "$FAILS"
    log "WAN ($WAN_IFACE) has no IP address. Fail ${FAILS}/${FAIL_THRESHOLD}"

    if [[ "$FAILS" -ge "$FAIL_THRESHOLD" ]]; then
        renew_wan_lease
        write_count "$STATE_FILE" 0
    fi
    # DNS is untestable without an IP, so report unknown rather than guessing.
    write_status "no_ip" "WAN interface $WAN_IFACE has no IP address" \
                 "" null "$FAILS" null
    exit 0
fi

# ── Check 2: Can we reach upstream hosts? ─────────────────────────────────────
REACHABLE=false
for host in $PROBE_HOSTS; do
    if ping -c 2 -W 3 -q "$host" &>/dev/null; then
        REACHABLE=true
        break
    fi
done

if $REACHABLE; then
    PREV_FAILS=$(read_count "$STATE_FILE")
    write_count "$STATE_FILE" 0
    [[ "$PREV_FAILS" -gt 0 ]] && log "WAN connectivity restored (was at ${PREV_FAILS} failures). WAN IP: $WAN_IP"
    rm -f "$OUTAGE_START_FILE"
    STATE=ok
    VERDICT="WAN reachable"
    GW=$(wan_gateway)            # cheap route lookup, no probe — the externals
    GW_REACH=true                # answered, so the gateway is up by definition
    FAILS=0
else
    FAILS=$(( $(read_count "$STATE_FILE") + 1 ))
    write_count "$STATE_FILE" "$FAILS"
    GW=$(wan_gateway)

    # One outage start for the whole event, so every failing check appends its
    # evidence to the same file and the shape over time is recoverable.
    if [[ ! -f "$OUTAGE_START_FILE" ]]; then
        date --iso-8601=seconds > "$OUTAGE_START_FILE"
        FIRST_CHECK=1
    else
        FIRST_CHECK=0
    fi
    OUTAGE_START=$(cat "$OUTAGE_START_FILE")

    # Diagnose. The helper arpings the gateway — ARP runs below IP, so it
    # answers even from a router that is refusing to forward, which is the one
    # thing a ping cannot tell us. It also reads carrier and lease state, and on
    # the FIRST failing check of an outage traceroutes to find where packets
    # die. See lib/bb_wan_diag.py for why the old ICMP-only split was useless.
    STATE=""; VERDICT=""; GW_REACH=null
    if [[ -x "$DIAG_BIN" ]]; then
        DIAG_ARGS=(--iface "$WAN_IFACE" --gateway "$GW" --externals-down
                   --outage-start "$OUTAGE_START" --probe-hosts "$PROBE_HOSTS")
        [[ -n "$LAST_OK_AT"     ]] && DIAG_ARGS+=(--last-ok "$LAST_OK_AT")
        [[ "$FIRST_CHECK" == 1  ]] && DIAG_ARGS+=(--full)
        # `|| true` so a broken helper degrades to the fallback below rather
        # than killing the watchdog under `set -e` in the middle of an outage.
        DIAG=$("$DIAG_BIN" "${DIAG_ARGS[@]}" 2>/dev/null || true)
        if [[ -n "$DIAG" ]]; then
            STATE=$(cut -f1 <<<"$DIAG")
            VERDICT=$(cut -f2 <<<"$DIAG")
            GW_REACH=$(cut -f3 <<<"$DIAG")
        fi
    fi

    # Fallback: keep working (with the weaker verdict) if the helper is absent
    # or failed, rather than logging an outage with no classification at all.
    if [[ -z "$STATE" ]]; then
        if [[ -z "$GW" ]]; then
            STATE=no_route; GW_REACH=null
            VERDICT="no default route via $WAN_IFACE — local routing fault, not the ISP"
        else
            STATE=unknown; GW_REACH=null
            VERDICT="gateway $GW unreachable — cause not established (diagnostic helper unavailable)"
        fi
    fi

    log "WAN unreachable (probed: $PROBE_HOSTS). WAN IP: $WAN_IP. Fail ${FAILS}/${FAIL_THRESHOLD} — $VERDICT"
    # Historic behaviour was to renew DHCP here; that helps nothing when the
    # ISP is down and, worse, ran dhcpcd behind NM's back and wiped
    # /etc/resolv.conf (2026-07-01 incident).

    # ── Escalate: probe every ESCALATE_INTERVAL until recovery ────────────────
    # Publish the failing state FIRST — the loop below can hold this run for
    # minutes, and the dashboard must not keep serving the previous healthy
    # reading for that whole time.
    write_status "$STATE" "$VERDICT" "$GW" "$GW_REACH" "$FAILS" null
    # SECONDS is time since the script started, so this compares against the
    # whole run rather than restarting the clock after the burst.
    while (( SECONDS < RUN_DEADLINE_SECS )); do
        # Check there is room for a whole interval before sleeping — otherwise a
        # coarse sleep walks straight past the deadline the whole point of which
        # is to finish before the next tick.
        (( RUN_DEADLINE_SECS - SECONDS < ESCALATE_INTERVAL )) && break
        sleep "$ESCALATE_INTERVAL"
        for host in $PROBE_HOSTS; do
            if ping -c 1 -W 2 -q "$host" &>/dev/null; then
                log "WAN connectivity restored (was at ${FAILS} failures). WAN IP: $WAN_IP"
                write_count "$STATE_FILE" 0
                rm -f "$OUTAGE_START_FILE"
                # DNS is deliberately not tested on this path: we recovered
                # seconds ago and the resolver may not have caught up yet, so a
                # probe now would report a failure that is not one. The next
                # scheduled run tests it a minute from now.
                write_status ok "WAN reachable — recovered during fast probe" \
                             "$GW" true 0 null
                exit 0
            fi
        done
    done
fi

# ── Check 3: DNS tripwire ─────────────────────────────────────────────────────
# Only runs when we actually have a WAN IP so that an ISP outage doesn't
# masquerade as a DNS fault — and, since 2026-08-30, only when the WAN is
# actually REACHABLE.
#
# A lookup cannot succeed while the WAN is down, so running it there guaranteed
# a failure, advanced dns-fails on every check, and eventually fired a
# service_down alert reading "DNS resolution failing — check resolv.conf
# nameservers" in the middle of an ISP outage. That happened on 2026-08-14: the
# log shows "Fail 3/3 — likely ISP outage" followed 40s later by "DNS lookup
# failed. Fail 3/3", pointing the reader at the resolver when the cause was the
# ISP. The tripwire exists to catch a SILENTLY broken resolv.conf while the
# network is otherwise fine; with the WAN down it has no signal to offer, so it
# holds its counter rather than counting a failure it cannot attribute.
if ! $REACHABLE; then
    DNS_OK=null
elif getent hosts "$DNS_PROBE_HOST" >/dev/null 2>&1; then
    DNS_OK=true
    PREV_DNS_FAILS=$(read_count "$DNS_STATE_FILE")
    write_count "$DNS_STATE_FILE" 0
    [[ "$PREV_DNS_FAILS" -ge "$FAIL_THRESHOLD" ]] && log "DNS resolution restored ($DNS_PROBE_HOST)"
else
    DNS_OK=false
    DNS_FAILS=$(( $(read_count "$DNS_STATE_FILE") + 1 ))
    write_count "$DNS_STATE_FILE" "$DNS_FAILS"
    NSLIST=$(grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ' | sed 's/ $//')
    log "DNS lookup for $DNS_PROBE_HOST failed. Fail ${DNS_FAILS}/${FAIL_THRESHOLD}. resolv.conf nameservers: '${NSLIST:-NONE}'"
    # Fire once when we cross the threshold. Detail is stable (no timestamps/counts)
    # so the Lambda dedup on (type,device,detail) collapses repeated fires.
    if [[ "$DNS_FAILS" -eq "$FAIL_THRESHOLD" && -x "$ALERT_SH" ]]; then
        "$ALERT_SH" service_down high bb0 "DNS resolution failing — /etc/resolv.conf nameservers: '${NSLIST:-NONE}'" \
            >>"$LOGFILE" 2>&1 || true
    fi
fi

write_status "$STATE" "$VERDICT" "$GW" "$GW_REACH" "$FAILS" "$DNS_OK"

# Under `set -e`, the trailing `[[ ]] && log` on line ~105 propagates its false
# result as the script's exit code. Terminate explicitly.
exit 0
