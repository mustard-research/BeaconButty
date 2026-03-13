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

RITA_VERSION="v5.1.1"   # Check https://github.com/activecm/rita/releases for latest
RITA_BIN="/usr/local/bin/rita"
GO_ROOT="/usr/local/go"
GO_INSTALL_VERSION="1.24.1"  # Latest LTS-ish; RITA requires >= 1.22.3

if [[ -x "$RITA_BIN" ]]; then
    echo "RITA already installed (${RITA_VERSION})"
    exit 0
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

echo "RITA installed: ${RITA_VERSION}"
