#!/usr/bin/env bash
set -euo pipefail

# Install RITA v5 (Real Intelligence Threat Analytics)
# https://github.com/activecm/rita
#
# RITA reads Zeek conn.log/dns.log/ssl.log and scores each
# (src → dst) pair for beaconing behaviour using:
#   - Inter-arrival time regularity (coefficient of variation + MADM)
#   - Data size consistency
#   - Connection count and duration
#   - Strobe detection (high-frequency port scanners)

RITA_VERSION="v5.1.2"   # Check https://github.com/activecm/rita/releases for latest
RITA_BIN="/usr/local/bin/rita"
GO_ROOT="/usr/local/go"
GO_INSTALL_VERSION="1.24.1"  # Latest LTS-ish; RITA requires >= 1.22.3

VERSION_FILE="/var/lib/beaconbutty/rita-version"
INSTALLED_VER=$(cat "$VERSION_FILE" 2>/dev/null || true)

# The old skip printed ${RITA_VERSION} — the *pin* — for whatever binary happened
# to be on disk, so it claimed the new version the moment the pin moved and the
# script could never upgrade anything. Compare the recorded build tag instead.
if [[ -x "$RITA_BIN" ]]; then
    if [[ "$INSTALLED_VER" == "$RITA_VERSION" ]]; then
        echo "RITA already installed (${RITA_VERSION})"
        exit 0
    fi
    if [[ -z "$INSTALLED_VER" ]]; then
        echo "RITA is installed but its build tag was never recorded."
        echo "  RITA v5 has no --version flag, so the tag cannot be recovered"
        echo "  from the binary. If you know it, write it to ${VERSION_FILE}."
    else
        echo "RITA ${INSTALLED_VER} is installed; this script pins ${RITA_VERSION}."
    fi
    # Not automatic: a rebuild takes 5-15 min on a Pi and swaps the analysis
    # engine underneath a live pipeline. setup.sh re-runs this script, and that
    # must not silently become an engine upgrade.
    if [[ "${RITA_FORCE_REBUILD:-0}" != "1" ]]; then
        echo "  Not rebuilding. To upgrade deliberately:"
        echo "    sudo RITA_FORCE_REBUILD=1 ./scripts/04_install_rita.sh"
        echo "  Pause rita-analyze.timer first, and check the next midnight"
        echo "  rollover — RITA creates a database per day, so a schema change"
        echo "  only shows up when the new day's tables are created."
        exit 0
    fi
    echo "RITA_FORCE_REBUILD=1 — rebuilding at ${RITA_VERSION}."
fi

echo "Installing RITA ${RITA_VERSION} (building from source)..."

# ── Install Go if needed (Debian Bookworm ships Go 1.19, too old) ─────────────
GO_OK=false
if command -v go &>/dev/null; then
    # go version outputs: "go version go1.22.3 linux/arm64"
    GO_MINOR=$(go version | grep -oP 'go\K1\.(\d+)' | cut -d. -f2 || echo 0)
    [[ "${GO_MINOR:-0}" -ge 22 ]] && GO_OK=true
fi
# Also check if we already installed Go ourselves
if [[ -x "${GO_ROOT}/bin/go" ]]; then
    GO_MINOR=$("${GO_ROOT}/bin/go" version | grep -oP 'go\K1\.(\d+)' | cut -d. -f2 || echo 0)
    [[ "${GO_MINOR:-0}" -ge 22 ]] && GO_OK=true
fi

if [[ "$GO_OK" != true ]]; then
    echo "Installing Go ${GO_INSTALL_VERSION} (required >= 1.22.3)..."
    curl -fsSL "https://go.dev/dl/go${GO_INSTALL_VERSION}.linux-arm64.tar.gz" \
        -o /tmp/go.tar.gz
    rm -rf "$GO_ROOT"
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    # Persist Go in PATH for future sessions
    cat > /etc/profile.d/go.sh <<'GOPATH_EOF'
export PATH="/usr/local/go/bin:$PATH"
GOPATH_EOF
    echo "Go ${GO_INSTALL_VERSION} installed."
fi

export PATH="${GO_ROOT}/bin:${PATH}"

# ── Build RITA from source ─────────────────────────────────────────────────────
echo "Building RITA ${RITA_VERSION} — this takes ~5-15 min on Pi..."

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

git clone --depth=1 --branch "${RITA_VERSION}" \
    https://github.com/activecm/rita.git "$BUILD_DIR"

( cd "$BUILD_DIR" && go build -o "$RITA_BIN" . )

# ── Verify ─────────────────────────────────────────────────────────────────────
# RITA v5 has no --version flag; use --help as a smoke test
"$RITA_BIN" --help &>/dev/null || {
    echo "ERROR: RITA binary failed to run after build."
    exit 1
}

# Record the tag we built, because the binary cannot tell you. RITA v5 has no
# --version flag and `go version -m` reports the module as "(devel)", so the
# built tag exists nowhere on the system once this script exits. The health
# check reads this file — the alternative is hard-coding a number in the health
# check that silently goes stale the next time RITA_VERSION moves.
# mkdir -p, NOT `install -d -m`: install resets the mode of an EXISTING
# directory. 05_configure.sh makes this dir 2775 root:dm because both root
# and dm (the webapp) do atomic tmp+rename writes in it, which need
# directory write permission. Re-running this script alone once clobbered
# that back to 755 and silently broke every FP registry write (2026-09-20).
mkdir -p /var/lib/beaconbutty
printf '%s\n' "${RITA_VERSION}" > /var/lib/beaconbutty/rita-version

echo "RITA installed: ${RITA_VERSION}"
