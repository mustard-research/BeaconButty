#!/usr/bin/env bash
set -euo pipefail

# Install system packages needed to compile Zeek and run RITA/MongoDB

echo "Updating package lists..."
apt-get update -qq

# Zeek build dependencies
ZEEK_BUILD_DEPS=(
    cmake
    make
    gcc
    g++
    python3
    python3-dev
    python3-websockets
    swig
    flex
    bison
    libpcap-dev
    libssl-dev
    zlib1g-dev
    libmaxminddb-dev  # GeoIP lookup in Zeek
    libkrb5-dev       # Kerberos protocol analysis
    binutils
)

# Runtime/tooling dependencies
RUNTIME_DEPS=(
    curl
    wget
    gnupg
    apt-transport-https
    ca-certificates
    git
    jq               # JSON processing in report scripts
    net-tools        # ifconfig, netstat
    ethtool          # NIC offload control
    logrotate
)

ALL_DEPS=("${ZEEK_BUILD_DEPS[@]}" "${RUNTIME_DEPS[@]}")

echo "Installing ${#ALL_DEPS[@]} packages..."
apt-get install -y --no-install-recommends "${ALL_DEPS[@]}"

# Increase kernel network buffer sizes to reduce packet drops under load.
# Zeek on a busy link can drop packets if the OS buffer is too small.
sysctl -w net.core.rmem_max=134217728     # 128 MB max receive buffer
sysctl -w net.core.rmem_default=25165824  # 24 MB default
sysctl -w net.core.netdev_max_backlog=5000

cat > /etc/sysctl.d/99-beaconbutty-capture.conf <<'EOF'
# BeaconButty: enlarge network buffers to reduce packet drops
net.core.rmem_max=134217728
net.core.rmem_default=25165824
net.core.netdev_max_backlog=5000
EOF

echo "System dependencies installed."
