#!/usr/bin/env bash
#
# mac-detect-dead-ics.sh — detect dead macOS Calendar subscriptions.
#
# A calendar subscription whose .ics URL returns something other than valid
# ICS (HTML error page, login page, 4xx/5xx) causes macOS's dataaccessd to
# retry the fetch on every wake, indefinitely — a silent background beacon
# replicated across every Apple device linked to the same iCloud account.
#
# This script enumerates the local Mac's calendar subscriptions, fetches
# each URL, and reports which ones are broken.
#
# Requires macOS and Full Disk Access for the terminal running it:
#   System Settings → Privacy & Security → Full Disk Access →
#   add Terminal (or iTerm etc.) → restart the terminal.
#
# Usage:
#   ./mac-detect-dead-ics.sh
#
# Exit status:
#   0  no broken subscriptions
#   1  at least one broken subscription
#   2  not running on macOS
#   3  cannot read Calendar.sqlitedb (likely no Full Disk Access)

set -eu
set -o pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS only." >&2
  exit 2
fi

# Colour if stdout is a TTY — defined early so progress lines can use it.
if [[ -t 1 ]]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; D=$'\e[2m'; B=$'\e[1m'; X=$'\e[0m'
else
  R=""; G=""; Y=""; D=""; B=""; X=""
fi

step() { printf '%s==>%s %s\n' "$B" "$X" "$*"; }

# Prove FDA is effective for this shell before trying anything TCC-gated.
# /Library/Application Support/com.apple.TCC/TCC.db exists on every modern
# Mac and is readable only with Full Disk Access (or root). A successful
# sqlite3 query of it is a reliable canary.
check_fda() {
  step "Checking Full Disk Access..." >&2
  if sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" \
             "SELECT 1 FROM access LIMIT 1;" >/dev/null 2>&1; then
    printf '    FDA: %sgranted%s\n' "$G" "$X" >&2
    return 0
  fi
  local parent_pid term
  parent_pid=$(ps -o ppid= -p $$ | tr -d ' ')
  term=$(ps -o comm= -p "$parent_pid" 2>/dev/null | sed -e 's/^ *//' -e 's/ *$//')
  printf '    FDA: %sNOT granted%s for this shell\n' "$R" "$X" >&2
  printf '    Hosting process: %s (PID %s)\n' "${term:-unknown}" "$parent_pid" >&2
  cat >&2 <<EOF

macOS grants FDA per-app; Terminal.app's grant does not cover other
apps (iTerm, VS Code, JetBrains, Claude Code, SSH sessions, etc.).

Fix:
  System Settings → Privacy & Security → Full Disk Access
  Add or toggle on the app that owns the hosting process above, then
  fully quit and relaunch it. New tabs inherit the old grant state.

If the hosting process is a small helper (login, sh, zsh), the real
owner is its parent app bundle — trace it with:
  ps -xao pid,ppid,comm | awk '\$1==$parent_pid || \$2==$parent_pid'
EOF
  return 1
}

# Calendar.sqlitedb has lived in several places across macOS versions
# (classic ~/Library/Calendars, group containers, etc.). Enumerate every
# copy Spotlight knows about, then pick the first one with a ZCALENDAR
# table (Core Data calendar store). If none match, dump each candidate's
# schema so the user can report back which variant this Mac is using.
find_caldb() {
  local p classic="$HOME/Library/Calendars/Calendar.sqlitedb"
  step "Looking for Calendar.sqlitedb..." >&2

  # Gather candidates: classic path + mdfind hits (falls back to find
  # on systems where mdfind returns nothing for $HOME).
  local candidates=() seen=""
  [[ -f "$classic" ]] && { candidates+=("$classic"); seen+="$classic"$'\n'; }
  local mdfind_out
  mdfind_out=$(mdfind -name 'Calendar.sqlitedb' 2>/dev/null || true)
  if [[ -z "$mdfind_out" ]]; then
    mdfind_out=$(find "$HOME/Library" -name 'Calendar.sqlitedb' 2>/dev/null || true)
  fi
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    [[ $'\n'"$seen" == *$'\n'"$p"$'\n'* ]] && continue
    candidates+=("$p")
    seen+="$p"$'\n'
  done <<<"$mdfind_out"

  if (( ${#candidates[@]} == 0 )); then
    printf '    no Calendar.sqlitedb found\n' >&2
    return 1
  fi

  local variant="" usable="" failed=()
  for p in "${candidates[@]}"; do
    printf '    candidate: %s\n' "$p" >&2
    if [[ ! -r "$p" ]]; then
      printf '      %sunreadable%s\n' "$R" "$X" >&2
      failed+=("$p")
      continue
    fi
    if sqlite3 "$p" "SELECT 1 FROM ZCALENDAR LIMIT 1;" >/dev/null 2>&1; then
      printf '      %susable (classic Core Data schema)%s\n' "$G" "$X" >&2
      usable="$p"; variant="classic"; break
    fi
    if sqlite3 "$p" "SELECT 1 FROM Calendar LIMIT 1;" >/dev/null 2>&1; then
      printf '      %susable (modern flat schema)%s\n' "$G" "$X" >&2
      usable="$p"; variant="modern"; break
    fi
    printf '      readable but neither ZCALENDAR nor Calendar table present\n' >&2
    failed+=("$p")
  done

  if [[ -n "$usable" ]]; then
    printf '%s|%s' "$variant" "$usable"
    return 0
  fi

  printf '\n' >&2
  printf '%sNo candidate has a recognised calendar schema. Tables found:%s\n' "$Y" "$X" >&2
  for p in "${failed[@]}"; do
    [[ ! -r "$p" ]] && continue
    printf '  %s\n' "$p" >&2
    sqlite3 "$p" ".tables" 2>/dev/null \
      | tr -s ' \t\n' '\n' \
      | sed '/^$/d;s/^/      /' >&2
    printf '\n' >&2
  done
  return 1
}

# Introspect the modern Calendar table and pick column names for
# title / subscription-url / refresh-interval / refresh-date. Column
# names have shifted across macOS versions, so match by pattern rather
# than hard-coding. Echoes: "title|url|interval|date" (or empties).
modern_columns() {
  local db="$1" cols c title="" url="" interval="" date=""
  cols=$(sqlite3 "$db" "PRAGMA table_info(Calendar);" 2>/dev/null \
         | awk -F'|' '{print $2}')
  while IFS= read -r c; do
    [[ -z "$c" ]] && continue
    case "$c" in
      title|name|display_name|displayName)
        [[ -z "$title" ]] && title="$c" ;;
      subcal_url|subscribed_url|subscription_url|external_url|url)
        [[ -z "$url" ]] && url="$c" ;;
      refresh_interval|subscription_refresh_interval|refreshInterval)
        [[ -z "$interval" ]] && interval="$c" ;;
      refresh_date|last_refresh|last_refresh_date|refreshDate)
        [[ -z "$date" ]] && date="$c" ;;
    esac
  done <<<"$cols"
  printf '%s|%s|%s|%s' "$title" "$url" "$interval" "$date"
}

check_fda || exit 3

FOUND=$(find_caldb) || {
  cat >&2 <<EOF

No Calendar.sqlitedb with a recognised schema was found. If a newer
macOS version is using a schema this script doesn't know yet, paste
the "Tables found" block above and the script can be taught the new
layout.
EOF
  exit 3
}
VARIANT="${FOUND%%|*}"
CALDB="${FOUND#*|}"

SEP=$'\x1f'   # unit separator — unambiguous field separator

if [[ "$VARIANT" == "classic" ]]; then
  SQL="
  SELECT
    Z_PK,
    COALESCE(NULLIF(ZTITLE1,''), NULLIF(ZTITLE,''), '<untitled>'),
    ZSUBSCRIPTIONURL,
    COALESCE(ZREFRESHINTERVAL, 0),
    COALESCE(ZREFRESHDATE, '')
  FROM ZCALENDAR
  WHERE ZSUBSCRIPTIONURL IS NOT NULL
    AND ZSUBSCRIPTIONURL != ''
  ORDER BY 2;
  "
else
  COLS=$(modern_columns "$CALDB")
  IFS='|' read -r T_COL U_COL I_COL D_COL <<<"$COLS"
  if [[ -z "$U_COL" ]]; then
    printf '%sCould not find a subscription URL column on Calendar table.%s\n' "$R" "$X" >&2
    printf 'Columns present:\n' >&2
    sqlite3 "$CALDB" "PRAGMA table_info(Calendar);" 2>/dev/null \
      | awk -F'|' '{printf "  %s (%s)\n", $2, $3}' >&2
    exit 3
  fi
  printf '    columns: title=%s url=%s interval=%s date=%s\n' \
         "${T_COL:-<none>}" "$U_COL" "${I_COL:-<none>}" "${D_COL:-<none>}" >&2
  SQL="
  SELECT
    ROWID,
    COALESCE(NULLIF(${T_COL:-''}, ''), '<untitled>'),
    $U_COL,
    COALESCE(${I_COL:-0}, 0),
    COALESCE(${D_COL:-''}, '')
  FROM Calendar
  WHERE $U_COL IS NOT NULL AND $U_COL != ''
  ORDER BY 2;
  "
fi

step "Querying subscriptions from Calendar.sqlitedb ($VARIANT schema)..."
# Collect rows (bash 3.2 safe — no mapfile)
ROWS=()
while IFS= read -r line; do
  ROWS+=("$line")
done < <(sqlite3 -separator "$SEP" "$CALDB" "$SQL")

total=${#ROWS[@]}
if (( total == 0 )); then
  echo "No calendar subscriptions found. Nothing to do."
  exit 0
fi

step "Checking $total calendar subscription(s) (20s timeout each)..."
printf '%s(using %s)%s\n' "$D" "$CALDB" "$X"
echo

broken=0
ok=0
unreachable=0

tmp=$(mktemp -t ics_body)
trap 'rm -f "$tmp"' EXIT

i=0
for row in "${ROWS[@]}"; do
  IFS="$SEP" read -r pk title url interval last <<<"$row"
  i=$((i + 1))

  # Live progress line — carriage-return so the verdict block overwrites it
  # on a TTY but still scrolls visibly on a pipe.
  if [[ -t 1 ]]; then
    printf '%s[%d/%d] fetching %s...%s\r' "$D" "$i" "$total" "$title" "$X"
  else
    printf '[%d/%d] fetching %s...\n' "$i" "$total" "$title"
  fi

  : > "$tmp"
  metrics=$(curl -sSL --max-time 20 --compressed \
                 -H 'Accept: text/calendar, text/x-vcalendar;q=0.5, */*;q=0.1' \
                 --write-out '%{http_code}\n%{content_type}\n%{url_effective}' \
                 --output "$tmp" \
                 "$url" 2>/dev/null \
           || echo $'000\n\n')

  http=$(printf '%s' "$metrics"  | awk 'NR==1')
  ctype=$(printf '%s' "$metrics" | awk 'NR==2')
  eurl=$(printf '%s' "$metrics"  | awk 'NR==3')
  # macOS tr/cut choke on non-UTF-8 bytes in error-page bodies; force C locale.
  first=$(head -c 200 "$tmp" | head -1 | LC_ALL=C tr -d '\r' | LC_ALL=C cut -c1-80)

  if [[ -z "$http" || "$http" == "000" ]]; then
    verdict="UNREACHABLE"; colour="$Y"; sym="?"; reason="network error or timeout"
    unreachable=$((unreachable + 1))
  elif [[ "$first" == BEGIN:VCALENDAR* ]]; then
    verdict="OK";          colour="$G"; sym="✓"; reason="returns valid ICS (HTTP $http)"
    ok=$((ok + 1))
  else
    verdict="BROKEN";      colour="$R"; sym="✗"; reason="HTTP $http, body is not ICS"
    broken=$((broken + 1))
  fi

  printf '%s%s %s%s  %s"%s"%s %s(rowid %s)%s\n' \
         "$colour" "$sym" "$verdict" "$X" \
         "$B" "$title" "$X" "$D" "$pk" "$X"
  printf '   URL:          %s\n' "$url"
  [[ -n "$eurl" && "$eurl" != "$url" ]] && \
    printf '   Final URL:    %s\n' "$eurl"
  printf '   Content-Type: %s\n' "${ctype:-<none>}"
  printf '   Body starts:  %s%s%s\n' "$D" "${first:-<empty>}" "$X"

  if [[ "$interval" != "0" ]]; then
    refresh_line="every ${interval}s"
  else
    refresh_line="interval not set"
  fi
  if [[ -z "$last" ]]; then
    printf '   Refresh:      %s, %slast refresh: NEVER%s\n' \
           "$refresh_line" "$R" "$X"
  else
    printf '   Refresh:      %s, last refresh recorded\n' "$refresh_line"
  fi

  printf '   %s%s%s\n' "$colour" "$reason" "$X"
  echo
done

printf '%sSummary:%s %s%d broken%s, %s%d ok%s, %s%d unreachable%s, %d total\n' \
       "$B" "$X" "$R" "$broken" "$X" "$G" "$ok" "$X" "$Y" "$unreachable" "$X" "$total"

if (( broken > 0 )); then
  cat <<EOF

${Y}To remove a broken subscription:${X}
  Calendar.app → right-click the calendar in the sidebar → Unsubscribe

Note: iCloud-synced subscriptions may resync back if only removed locally.
If Unsubscribe doesn't stick, sign in to iCloud.com → Calendar and remove
the calendar there too.
EOF
fi

exit $(( broken > 0 ? 1 : 0 ))
