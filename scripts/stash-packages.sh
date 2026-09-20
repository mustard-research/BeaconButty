#!/usr/bin/env bash
set -euo pipefail

# stash-packages.sh
#
# Keep a durable copy of the .deb for every apt-held package, at the version
# actually installed.
#
# Why: `apt-mark hold` stops an unwanted upgrade. It does nothing to preserve
# the artifact you would need to go back to, and the two look like the same
# safety net. On 2026-09-20 Zeek 8.2.2 was gone from the openSUSE repo while we
# were still running it — that repo carries one build per line — so the upgrade
# to 9.0.0 had no downgrade path before it started.
#
# Why the held set: it is precisely the set we have decided to pin, so it needs
# no separate list to drift out of date. Add a hold, it gets stashed.
#
# Why not /var/cache/apt/archives: that is apt's working directory, not a
# stash. It demonstrably did not retain 8.2.2 (only 8.1.1 and 9.0.0 survived
# there), so it cannot be relied on for this.
#
# Why .debs rather than a file-tree tarball: `dpkg -i` restores the files *and*
# the package database. A tarball over /opt leaves dpkg believing the newer
# version is still installed — it buys a working system, not a consistent one.
#
# Idempotent and safe to run repeatedly; called from daily housekeeping.

STASH_DIR="${STASH_DIR:-/var/lib/beaconbutty/pkg-stash}"
KEEP_VERSIONS="${KEEP_VERSIONS:-2}"   # installed + one step back
ARCH=$(dpkg --print-architecture)

mkdir -p "$STASH_DIR"

stashed=0 already=0 failed=0
FAILED_PKGS=()

for pkg in $(apt-mark showhold); do
    ver=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)
    [[ -z "$ver" ]] && continue                     # held but not installed

    # apt encodes ':' in an epoch as %3a in the filename.
    fname="${pkg}_${ver//:/%3a}_${ARCH}.deb"
    [[ -f "$STASH_DIR/$fname" ]] && { (( already++ )) || true; continue; }

    # Some packages are Architecture: all.
    alt="${pkg}_${ver//:/%3a}_all.deb"
    [[ -f "$STASH_DIR/$alt" ]] && { (( already++ )) || true; continue; }

    got=""
    # 1. apt's cache, if it still holds this exact version. No network needed.
    for cand in "/var/cache/apt/archives/$fname" "/var/cache/apt/archives/$alt"; do
        [[ -f "$cand" ]] && { got="$cand"; break; }
    done

    if [[ -n "$got" ]]; then
        cp -n "$got" "$STASH_DIR/$(basename "$got")"
        target="$STASH_DIR/$(basename "$got")"
    else
        # 2. The repo. Pinned to the installed version explicitly — a bare
        #    `apt-get download <pkg>` fetches the *candidate*, which for a held
        #    package is the version we are deliberately not running.
        target=""
        if (cd "$STASH_DIR" && apt-get download -q "${pkg}=${ver}" >/dev/null 2>&1); then
            target=$(ls -t "$STASH_DIR/${pkg}"_*.deb 2>/dev/null | head -1)
        fi
    fi

    # 3. Neither — this package is currently un-rollback-able. Say so loudly:
    #    it is the exact condition this script exists to detect early.
    if [[ -z "$target" || ! -f "$target" ]]; then
        echo "  UNSTASHABLE: ${pkg}=${ver} is in neither the apt cache nor the repo"
        FAILED_PKGS+=("${pkg}=${ver}")
        (( failed++ )) || true
        continue
    fi

    # A truncated .deb restores nothing. Prove it is readable before counting it.
    if ! dpkg-deb --info "$target" >/dev/null 2>&1; then
        echo "  CORRUPT: $(basename "$target") failed dpkg-deb --info, discarding"
        rm -f "$target"
        FAILED_PKGS+=("${pkg}=${ver}")
        (( failed++ )) || true
        continue
    fi

    echo "  Stashed $(basename "$target")"
    (( stashed++ )) || true
done

# Prune to the newest KEEP_VERSIONS per package. Grouped on the name before the
# first underscore, which is the deb filename convention.
pruned=0
while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    while IFS= read -r old; do
        echo "  Pruning $(basename "$old")"
        rm -f "$old"
        (( pruned++ )) || true
    done < <(ls -t "$STASH_DIR/${name}"_*.deb 2>/dev/null | tail -n +$((KEEP_VERSIONS + 1)))
done < <(ls "$STASH_DIR"/*.deb 2>/dev/null | xargs -r -n1 basename | sed 's/_.*//' | sort -u)

cat > "$STASH_DIR/RESTORE.txt" <<EOF
Held-package .deb stash — written by beaconbutty-stash-packages.sh
Last run: $(date --iso-8601=seconds)

These are the .debs for every apt-held package at the version installed when
this ran, kept because a vendor repo may drop the release you are running
before you next upgrade (the openSUSE Zeek repo keeps one build per line, and
that is exactly how 8.2.2 became unavailable while we were on it).

To roll a package back:

  sudo apt-mark unhold <pkg>
  sudo dpkg -i $STASH_DIR/<pkg>_<version>_<arch>.deb
  sudo apt-mark hold <pkg>

Install the whole set at once where packages depend on each other (Zeek does):

  sudo dpkg -i $STASH_DIR/zeek*_<version>_*.deb $STASH_DIR/libbroker-dev_<version>_*.deb

For Zeek, follow with 'zeekctl deploy'. For ClickHouse, prefer
beaconbutty-clickhouse-upgrade.sh's verification steps afterwards.

Unlike a tarball over /opt, dpkg -i keeps the package database consistent.
EOF

echo "  Package stash: ${stashed} added, ${already} already present, ${pruned} pruned, ${failed} unstashable"
echo "  Stash size: $(du -sh "$STASH_DIR" 2>/dev/null | cut -f1)  (keeping ${KEEP_VERSIONS} versions per package)"

if (( failed )); then
    echo "  WARNING: no rollback artifact exists for: ${FAILED_PKGS[*]}"
fi
exit 0
