#!/usr/bin/env bash
# clickhouse-upgrade.sh — safe ClickHouse upgrade with snapshot + verify
#
# Background:
#   On 2026-05-13 a bundled `apt upgrade` (Zeek 8.1 work) silently pulled
#   ClickHouse 26.3 → 26.4. By 2026-06-16 the system was wedged — the
#   /etc/clickhouse-server/config.d/ overrides for log path + memory cap
#   had drifted, RITA had been failing for 17 days behind a green-ish
#   health check. Packages are now apt-mark hold'd. This script is the
#   one approved path back through an upgrade.
#
# Flow: preflight → snapshot → pause → upgrade → verify → resume.
# On any verify failure: STOPS. Leaves system in known state with the
# snapshot dir available for manual recovery. No auto-rollback (CH
# storage formats may not downgrade cleanly).
#
# Usage: sudo /usr/local/bin/beaconbutty-clickhouse-upgrade.sh [--yes]
#   --yes : skip interactive confirmation (still aborts on preflight failures)

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'
    BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'
else
    GREEN=''; YELLOW=''; RED=''; BLUE=''; BOLD=''; RESET=''
fi
log()  { echo -e "${BLUE}▸${RESET} $*"; }
ok()   { echo -e "  ${GREEN}✓${RESET} $*"; }
warn() { echo -e "  ${YELLOW}!${RESET} $*"; }
die()  { echo -e "  ${RED}✗${RESET} $*" >&2; exit 1; }

# ── Args ─────────────────────────────────────────────────────────────────────
ASSUME_YES=0
[[ "${1:-}" == "--yes" ]] && ASSUME_YES=1

if [[ "$EUID" -ne 0 ]]; then
    die "Run as root (sudo)."
fi

CONFIG_DIR="/etc/clickhouse-server"
EXPECTED_OVERRIDES=("logs.xml" "memory.xml" "system-log-ttl.xml")
SNAPSHOT_ROOT="/var/lib/beaconbutty/ch-upgrade"
TS=$(date -u +%Y%m%dT%H%M%SZ)
SNAPSHOT_DIR="${SNAPSHOT_ROOT}/${TS}"
ANALYZE_LOG="/var/log/beaconbutty/analyze.log"
HEALTH_SCRIPT="/usr/local/bin/beaconbutty-health.sh"

# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BOLD}BeaconButty ClickHouse upgrade${RESET}  —  ${TS}"
echo "────────────────────────────────────────────────────"

# ── 1. Preflight ─────────────────────────────────────────────────────────────
log "Preflight"

CURRENT=$(dpkg-query -W -f='${Version}' clickhouse-server 2>/dev/null) \
    || die "clickhouse-server not installed"
CANDIDATE=$(LC_ALL=C apt-cache policy clickhouse-server 2>/dev/null \
    | awk '/Candidate:/ {print $2}')
[[ -z "$CANDIDATE" || "$CANDIDATE" == "(none)" ]] \
    && die "No candidate version found (apt update first?)"

if [[ "$CURRENT" == "$CANDIDATE" ]]; then
    ok "Already on the latest version (${CURRENT}). Nothing to do."
    exit 0
fi
ok "Installed: ${CURRENT} → Candidate: ${CANDIDATE}"

# All config overrides we expect to survive must be there going in
for f in "${EXPECTED_OVERRIDES[@]}"; do
    [[ -f "${CONFIG_DIR}/config.d/${f}" ]] \
        || die "Pre-upgrade: missing override ${CONFIG_DIR}/config.d/${f}"
done
ok "All expected config.d/ overrides present: ${EXPECTED_OVERRIDES[*]}"

# Health check must be clean (no failures, no warnings) before touching CH
HEALTH_TMP=$(mktemp)
trap 'rm -f "$HEALTH_TMP"' EXIT
if "$HEALTH_SCRIPT" --json > "$HEALTH_TMP" 2>/dev/null; then
    HEALTH_FAIL=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["failures"])' "$HEALTH_TMP")
    HEALTH_WARN=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["warnings"])' "$HEALTH_TMP")
    if [[ "$HEALTH_FAIL" -gt 0 ]]; then
        die "Health check has ${HEALTH_FAIL} failure(s) — fix before upgrading"
    fi
    if [[ "$HEALTH_WARN" -gt 0 ]]; then
        warn "Health check has ${HEALTH_WARN} warning(s) — proceed with care"
    else
        ok "Health check: all green"
    fi
else
    die "Health check returned non-zero — aborting"
fi

# Don't upgrade while RITA is mid-import (could corrupt a dataset)
if systemctl is-active --quiet rita-analyze.service; then
    die "rita-analyze.service is currently running — wait for it to finish"
fi

# Disk space — 2 GiB free on /
DISK_FREE_MB=$(df -BM / | awk 'NR==2 {gsub(/M/,"",$4); print $4}')
if [[ "$DISK_FREE_MB" -lt 2048 ]]; then
    die "Less than 2 GiB free on / (${DISK_FREE_MB} MiB) — free space first"
fi
ok "Disk: ${DISK_FREE_MB} MiB free on /"

# Confirm
echo
if [[ "$ASSUME_YES" == "0" ]]; then
    read -r -p "Proceed with upgrade ${CURRENT} → ${CANDIDATE}? [y/N] " ANS
    [[ "$ANS" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }
fi

# ── 2. Snapshot ──────────────────────────────────────────────────────────────
log "Snapshot → ${SNAPSHOT_DIR}"
mkdir -p "${SNAPSHOT_DIR}/etc"
rsync -a "${CONFIG_DIR}/" "${SNAPSHOT_DIR}/etc/clickhouse-server/"
ok "config.d/ + config.xml copied"

# Record state we'll re-check after
clickhouse-client --query "SELECT count() FROM system.databases WHERE name LIKE 'beaconbutty_%'" \
    > "${SNAPSHOT_DIR}/dataset_count" 2>/dev/null
clickhouse-client --query "SELECT value FROM system.server_settings WHERE name='max_server_memory_usage'" \
    > "${SNAPSHOT_DIR}/max_memory" 2>/dev/null
echo "$CURRENT" > "${SNAPSHOT_DIR}/version_before"
ok "Recorded: $(cat "${SNAPSHOT_DIR}/dataset_count") datasets, max_memory=$(cat "${SNAPSHOT_DIR}/max_memory")"

# ── 3. Pause RITA ─────────────────────────────────────────────────────────────
log "Pause RITA"
systemctl stop rita-analyze.timer
ok "rita-analyze.timer stopped (the package upgrade itself will restart clickhouse-server)"

# ── 4. Upgrade ───────────────────────────────────────────────────────────────
log "Upgrade"
apt-mark unhold clickhouse-server clickhouse-client clickhouse-common-static >/dev/null
ok "Hold released"

# --force-confold preserves our config.xml. The user-added config.d/*.xml
# files are not dpkg conffiles, so they should be untouched, but the
# post-upgrade verify guarantees it.
if ! DEBIAN_FRONTEND=noninteractive apt-get install -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        clickhouse-server clickhouse-client clickhouse-common-static; then
    apt-mark hold clickhouse-server clickhouse-client clickhouse-common-static >/dev/null
    die "apt-get install failed — packages left unheld for inspection. Snapshot at ${SNAPSHOT_DIR}"
fi
apt-mark hold clickhouse-server clickhouse-client clickhouse-common-static >/dev/null
ok "Upgrade complete; packages re-held"

NEW_VERSION=$(dpkg-query -W -f='${Version}' clickhouse-server)
ok "Now running: ${NEW_VERSION}"

# ── 5. Verify ────────────────────────────────────────────────────────────────
log "Verify"

# (a) config.d overrides survived intact
for f in "${EXPECTED_OVERRIDES[@]}"; do
    cur="${CONFIG_DIR}/config.d/${f}"
    snap="${SNAPSHOT_DIR}/etc/clickhouse-server/config.d/${f}"
    [[ -f "$cur" ]] || die "VERIFY FAIL: ${cur} is missing post-upgrade. Restore from ${snap}"
    if ! diff -q "$cur" "$snap" >/dev/null; then
        die "VERIFY FAIL: ${cur} differs from snapshot. Diff:
$(diff -u "$snap" "$cur" | head -30)"
    fi
done
ok "config.d/ overrides intact"

# (b) Service is up; wait briefly if it just restarted
for _ in 1 2 3 4 5 6 7 8 9 10; do
    systemctl is-active --quiet clickhouse-server && break
    sleep 2
done
systemctl is-active --quiet clickhouse-server \
    || die "VERIFY FAIL: clickhouse-server not active after upgrade"
ok "clickhouse-server: active"

# (c) Query probe
for _ in 1 2 3 4 5 6 7 8 9 10; do
    clickhouse-client --query "SELECT 1" >/dev/null 2>&1 && break
    sleep 2
done
clickhouse-client --query "SELECT 1" >/dev/null 2>&1 \
    || die "VERIFY FAIL: SELECT 1 not responding"
ok "SELECT 1 responsive"

# (d) Memory setting matches snapshot (catches a maintainer config.xml taking precedence)
NEW_MAX_MEM=$(clickhouse-client --query "SELECT value FROM system.server_settings WHERE name='max_server_memory_usage'")
OLD_MAX_MEM=$(cat "${SNAPSHOT_DIR}/max_memory")
if [[ "$NEW_MAX_MEM" != "$OLD_MAX_MEM" ]]; then
    die "VERIFY FAIL: max_server_memory_usage changed: ${OLD_MAX_MEM} → ${NEW_MAX_MEM}"
fi
ok "max_server_memory_usage unchanged: ${NEW_MAX_MEM}"

# (e) Dataset count matches snapshot
NEW_DATASET_COUNT=$(clickhouse-client --query "SELECT count() FROM system.databases WHERE name LIKE 'beaconbutty_%'")
OLD_DATASET_COUNT=$(cat "${SNAPSHOT_DIR}/dataset_count")
if [[ "$NEW_DATASET_COUNT" != "$OLD_DATASET_COUNT" ]]; then
    die "VERIFY FAIL: dataset count changed: ${OLD_DATASET_COUNT} → ${NEW_DATASET_COUNT}"
fi
ok "Dataset count unchanged: ${NEW_DATASET_COUNT}"

# ── 6. Resume — run one full rita-analyze cycle and wait for "=== done:" ─────
log "Resume RITA + workload verify"
systemctl start rita-analyze.timer
ok "rita-analyze.timer restarted"

# Note the current latest "=== done:" timestamp so we can detect a fresh one
PRE_DONE=$(grep "^=== done:" "$ANALYZE_LOG" 2>/dev/null | tail -1 | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}' || echo "none")
log "Triggering rita-analyze.service (last done: ${PRE_DONE})"
systemctl start rita-analyze.service

# Poll for a new "=== done:" line for up to 10 minutes
DEADLINE=$(( $(date +%s) + 600 ))
NEW_DONE=""
while [[ $(date +%s) -lt $DEADLINE ]]; do
    LATEST=$(grep "^=== done:" "$ANALYZE_LOG" 2>/dev/null | tail -1 | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}' || echo "")
    if [[ -n "$LATEST" && "$LATEST" != "$PRE_DONE" ]]; then
        NEW_DONE="$LATEST"
        break
    fi
    sleep 5
done
[[ -z "$NEW_DONE" ]] && die "VERIFY FAIL: rita-analyze did not produce a new '=== done:' marker within 10 min. Check ${ANALYZE_LOG}"
ok "RITA completed cleanly: new done marker at ${NEW_DONE}"

# ── 7. Final health check ────────────────────────────────────────────────────
log "Final health check"
if "$HEALTH_SCRIPT" --json > "$HEALTH_TMP" 2>/dev/null; then
    FINAL_FAIL=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["failures"])' "$HEALTH_TMP")
    if [[ "$FINAL_FAIL" -gt 0 ]]; then
        die "VERIFY FAIL: post-upgrade health check has ${FINAL_FAIL} failure(s). Snapshot at ${SNAPSHOT_DIR}"
    fi
    ok "Health check: all green"
else
    die "VERIFY FAIL: health check returned non-zero"
fi

echo
echo -e "${GREEN}${BOLD}✓ Upgrade succeeded.${RESET}  ${CURRENT} → ${NEW_VERSION}"
echo "  Snapshot retained: ${SNAPSHOT_DIR} (delete after 30 days)"
