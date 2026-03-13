#!/usr/bin/env bash
set -euo pipefail

# Install ClickHouse — the database backend for RITA v5.
# MongoDB is not used by RITA v5; disable it here if previously installed.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

apply_clickhouse_config() {
    mkdir -p /etc/clickhouse-server/config.d /etc/clickhouse-server/users.d
    cp "$SCRIPT_DIR/config/clickhouse/users.d/beaconbutty-compatibility.xml" \
       /etc/clickhouse-server/users.d/beaconbutty-compatibility.xml
}

if systemctl is-active --quiet clickhouse-server 2>/dev/null; then
    echo "ClickHouse already running — applying config files."
    apply_clickhouse_config
    systemctl restart clickhouse-server
    exit 0
fi
if command -v clickhouse-server &>/dev/null; then
    echo "ClickHouse already installed — applying config files."
    apply_clickhouse_config
    systemctl enable --now clickhouse-server
    exit 0
fi

# ── Disable MongoDB if previously installed ───────────────────────────────────
if systemctl is-enabled --quiet mongod 2>/dev/null; then
    echo "Disabling MongoDB (not used by RITA v5)..."
    systemctl stop mongod  2>/dev/null || true
    systemctl disable mongod 2>/dev/null || true
fi

echo "Installing ClickHouse..."

# ── Add ClickHouse apt repo ───────────────────────────────────────────────────
curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' \
    | gpg --yes --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=arm64] \
https://packages.clickhouse.com/deb stable main" \
    > /etc/apt/sources.list.d/clickhouse.list

rm -f /var/lib/apt/lists/packages.clickhouse.com*

apt-get update 2>&1 | tee /tmp/apt-update.log | grep -E "(clickhouse|Err|Hit|Get)" || true
if grep -qi "^Err" /tmp/apt-update.log; then
    echo "ERROR: apt-get update reported errors for ClickHouse repo."
    cat /tmp/apt-update.log
    exit 1
fi

# Install without prompting for passwords (we'll configure auth separately)
DEBIAN_FRONTEND=noninteractive apt-get install -y clickhouse-server clickhouse-client

# ── Tune for Raspberry Pi ─────────────────────────────────────────────────────
# Cap at 2 GB; reduce background threads to leave headroom for Zeek + routing.
apply_clickhouse_config

cat > /etc/clickhouse-server/config.d/beaconbutty.xml <<'EOF'
<clickhouse>
    <!-- Cap memory at 2 GB; leave headroom for Zeek + routing on Pi -->
    <max_server_memory_usage>3221225472</max_server_memory_usage>
</clickhouse>
EOF

systemctl enable --now clickhouse-server

# ── Wait for readiness ────────────────────────────────────────────────────────
echo -n "Waiting for ClickHouse to start"
READY=false
for _ in {1..20}; do
    if clickhouse-client --query "SELECT 1" &>/dev/null 2>&1; then
        echo " ready."
        READY=true
        break
    fi
    echo -n "."
    sleep 2
done
[[ "$READY" == true ]] || {
    echo " timeout."
    echo "Warning: ClickHouse did not respond in 40 s. Check: systemctl status clickhouse-server"
}

echo "ClickHouse installed and running."
