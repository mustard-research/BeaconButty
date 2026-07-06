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
    python3-pip
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
    geoipupdate      # MaxMind GeoLite2 database updates
)

ALL_DEPS=("${ZEEK_BUILD_DEPS[@]}" "${RUNTIME_DEPS[@]}")

echo "Installing ${#ALL_DEPS[@]} packages..."
apt-get install -y --no-install-recommends "${ALL_DEPS[@]}"

# ── Python packages (webapp + summarize.sh) ───────────────────────────────────
echo "Installing Python packages..."
pip3 install --break-system-packages flask psutil geoip2

# ── log2ram (reduce SSD write wear by keeping /var/log in RAM) ────────────────
if ! command -v log2ram &>/dev/null; then
    echo "Installing log2ram..."
    curl -fsSL https://raw.githubusercontent.com/azlux/log2ram/master/install.sh | bash
    # Set RAM log size to 1 GB — matches live bb0 (journal + dnsmasq +
    # suricata + beaconbutty logs overflow the old 128M within a day,
    # destroying live logs; see the 2026-04-15 Suricata gap).
    sed -i 's/^SIZE=.*/SIZE=1G/' /etc/log2ram.conf 2>/dev/null || true
else
    echo "log2ram already installed."
fi

# ── rpi-clone (full-disk USB backup) ─────────────────────────────────────────
if ! command -v rpi-clone &>/dev/null; then
    echo "Installing rpi-clone..."
    curl -fsSL https://raw.githubusercontent.com/geerlingguy/rpi-clone/master/rpi-clone \
        -o /usr/local/bin/rpi-clone
    chmod +x /usr/local/bin/rpi-clone
else
    echo "rpi-clone already installed."
fi

# ── Kernel network buffers ────────────────────────────────────────────────────
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
