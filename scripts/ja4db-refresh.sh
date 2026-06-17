#!/usr/bin/env bash
#
# Refresh the FoxIO ja4plus-mapping.csv used to classify JA4 fingerprints
# into Application/Library/OS labels. Weekly cron-friendly: short timeout,
# atomic install, fails closed (existing file preserved on error).
#
# Source: https://github.com/FoxIO-LLC/ja4
# CSV columns: Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes

set -euo pipefail

URL="https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv"
DEST="/var/lib/beaconbutty/ja4db.csv"
TMP="$(mktemp /tmp/ja4db.XXXXXX.csv)"
trap 'rm -f "$TMP"' EXIT

echo "[ja4db-refresh] $(date -u +%FT%TZ) fetching $URL"

if ! curl -fsSL --max-time 30 "$URL" -o "$TMP"; then
    echo "[ja4db-refresh] curl failed — keeping existing $DEST" >&2
    exit 1
fi

# Sanity check: must have a header row and at least one ja4 entry.
if ! head -1 "$TMP" | grep -q '^Application,'; then
    echo "[ja4db-refresh] header missing — refusing to install" >&2
    exit 2
fi
rows=$(wc -l < "$TMP")
if [ "$rows" -lt 5 ]; then
    echo "[ja4db-refresh] only $rows rows — suspect, refusing to install" >&2
    exit 3
fi

install -m 0644 "$TMP" "$DEST"
echo "[ja4db-refresh] installed $DEST ($rows rows)"
