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

# ── log2ram (reduce SSD write wear by keeping the BULK logs in RAM) ───────────
# Scope matters here. log2ram only writes back to disk on clean shutdown and once
# daily at 23:55 (log2ram-daily.timer), so anything it holds is lost in a power cut
# or panic. We therefore RAM only the high-churn traffic logs and leave every
# forensically useful log durable on NVMe. See CLAUDE.md "log2ram" (2026-08-28).
if ! command -v log2ram &>/dev/null; then
    echo "Installing log2ram..."
    curl -fsSL https://raw.githubusercontent.com/azlux/log2ram/master/install.sh | bash
    # 1 GB per RAM'd path — Zeek alone holds ~515M (14-day retention).
    sed -i 's/^SIZE=.*/SIZE=1G/' /etc/log2ram.conf 2>/dev/null || true
else
    echo "log2ram already installed."
fi

# Rescope to the bulk traffic logs only. NOTE: PATH_DISK is SEMICOLON-separated.
# Durable on NVMe as a result: the systemd journal, /var/log/beaconbutty (watchdog
# + alerts), dnsmasq.log, fail2ban.log, apt/, dpkg.log, unattended-upgrades/.
if [[ -f /etc/log2ram.conf ]]; then
    sed -i 's|^PATH_DISK=.*|PATH_DISK="/var/log/zeek;/var/log/suricata"|' /etc/log2ram.conf
    echo "log2ram PATH_DISK: $(grep '^PATH_DISK=' /etc/log2ram.conf)"
fi

# ── Persistent systemd journal ────────────────────────────────────────────────
# Raspberry Pi OS ships /usr/lib/systemd/journald.conf.d/40-rpi-volatile-storage.conf
# with Storage=volatile. Drop-ins apply in LEXICAL order, so ours must sort after
# "40-" to win — hence the 99- prefix. Anything lower is silently overridden and the
# system looks healthy while keeping no journal across an unclean reboot.
# Verify with: systemd-analyze cat-config systemd/journald.conf | grep '^Storage='
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/99-beaconbutty-persistent.conf <<'JOURNALD'
[Journal]
Storage=persistent
SystemMaxUse=512M
SystemMaxFileSize=64M
MaxRetentionSec=1month
JOURNALD
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal 2>/dev/null || true
systemctl restart systemd-journald 2>/dev/null || true
echo "journal storage: $(systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep '^Storage=' | tail -1)"

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
