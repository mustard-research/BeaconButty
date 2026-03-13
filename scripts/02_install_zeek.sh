#!/usr/bin/env bash
set -euo pipefail

# Install Zeek network analysis framework
#
# Strategy:
#   1. Try pre-built ARM64 packages from OpenSUSE Build Service (fast, ~2 min)
#   2. Fall back to compiling from source if packages unavailable (slow, ~60-90 min on Pi 4)

ZEEK_PREFIX="${ZEEK_PREFIX:-/opt/zeek}"
ZEEK_VERSION="7.0.4"   # Check https://zeek.org/get-zeek/ for latest stable

if [[ -x "$ZEEK_PREFIX/bin/zeek" ]]; then
    echo "Zeek already installed at $ZEEK_PREFIX ($("${ZEEK_PREFIX}/bin/zeek" --version 2>&1 | head -1))"
    exit 0
fi

# ── Option 1: OBS pre-built packages ─────────────────────────────────────────
install_zeek_packages() {
    local OBS_BASE="https://download.opensuse.org/repositories/security:/zeek/Debian_12"

    echo "Trying Zeek packages from OpenSUSE Build Service..."

    curl -fsSL "${OBS_BASE}/Release.key" \
        | gpg --dearmor -o /etc/apt/trusted.gpg.d/zeek.gpg

    echo "deb ${OBS_BASE}/ /" > /etc/apt/sources.list.d/zeek.list
    apt-get update -qq

    # OBS installs to /opt/zeek — check arm64 availability first
    if apt-cache show zeek 2>/dev/null | grep -q "Architecture: arm64\|Architecture: all"; then
        apt-get install -y --reinstall zeek
        ln -sf /opt/zeek/bin/zeek    /usr/local/bin/zeek
        ln -sf /opt/zeek/bin/zeekctl /usr/local/bin/zeekctl
        echo "Zeek installed from OBS packages."
        return 0
    else
        echo "ARM64 OBS packages not available — will compile from source."
        rm -f /etc/apt/sources.list.d/zeek.list /etc/apt/trusted.gpg.d/zeek.gpg
        apt-get update -qq
        return 1
    fi
}

# ── Option 2: Compile from source ────────────────────────────────────────────
install_zeek_source() {
    local BUILD_DIR="/tmp/zeek-src"
    local NCPU
    NCPU=$(nproc)

    echo "Compiling Zeek ${ZEEK_VERSION} from source using ${NCPU} cores..."
    echo "This typically takes 45-90 minutes on a Raspberry Pi 4."

    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"

    curl -fsSL "https://download.zeek.org/zeek-${ZEEK_VERSION}.tar.gz" \
        -o "${BUILD_DIR}/zeek.tar.gz"

    tar -xzf "${BUILD_DIR}/zeek.tar.gz" -C "$BUILD_DIR"
    cd "${BUILD_DIR}/zeek-${ZEEK_VERSION}"

    ./configure \
        --prefix="$ZEEK_PREFIX" \
        --disable-broker-tests \
        --disable-zeekctl-tests

    make -j"$NCPU"
    make install

    # Make Zeek binaries available system-wide
    echo "export PATH=${ZEEK_PREFIX}/bin:\$PATH" > /etc/profile.d/zeek.sh
    ln -sf "${ZEEK_PREFIX}/bin/zeek"    /usr/local/bin/zeek
    ln -sf "${ZEEK_PREFIX}/bin/zeekctl" /usr/local/bin/zeekctl

    rm -rf "$BUILD_DIR"
    echo "Zeek compiled and installed."
}

install_zeek_packages || install_zeek_source

echo "Installed: $("${ZEEK_PREFIX}/bin/zeek" --version 2>&1 | head -1)"
