#!/usr/bin/env bash
set -euo pipefail

# BeaconButty — Router Mode Setup
#
# Configures the Raspberry Pi as a NAT router + Zeek sensor:
#
#   [ISP Ethernet] ── eth0 (WAN, DHCP from ISP)
#                         Pi (NAT + DHCP server + Zeek)
#                     eth1 (LAN, static IP)
#                         │
#                   [Managed switch]
#                    /    |    \
#                 [AP] [PC1] [PC2]
#
# Zeek captures on eth1 and sees every internal host's real IP.
#
# ── IMPORTANT: READ BEFORE RUNNING ───────────────────────────────────────────
# This script writes new network configuration and reboots.
# After reboot:
#   - eth0 gets a DHCP address from your ISP (WAN, do not use for SSH)
#   - eth1 becomes the LAN gateway at LAN_IP (default 192.168.50.1)
#   - Connect your switch/computer to eth1, then SSH to 192.168.50.1
# ─────────────────────────────────────────────────────────────────────────────
#
# Override any default before running:
#   WAN_IFACE=eth0 LAN_IFACE=eth1 LAN_IP=192.168.1.1 sudo -E ./scripts/07_router_mode.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Configuration ─────────────────────────────────────────────────────────────
WAN_IFACE="${WAN_IFACE:-eth0}"          # Faces ISP, gets DHCP
LAN_IFACE="${LAN_IFACE:-eth1}"          # Faces internal switch, static IP
LAN_IP="${LAN_IP:-192.168.50.1}"        # Pi's LAN address; also DHCP gateway & DNS
LAN_PREFIX="${LAN_PREFIX:-24}"          # /24 = 255.255.255.0
DHCP_START="${DHCP_START:-192.168.50.20}"
DHCP_END="${DHCP_END:-192.168.50.250}"
DHCP_LEASE="${DHCP_LEASE:-24h}"
DNS_UPSTREAM="${DNS_UPSTREAM:-1.1.1.1,8.8.8.8}"  # Comma-separated upstream resolvers

ZEEK_PREFIX="${ZEEK_PREFIX:-/opt/zeek}"
# ─────────────────────────────────────────────────────────────────────────────

# ── Network address helpers ───────────────────────────────────────────────────
# Pure-bash IPv4 arithmetic — works for any prefix length, not just /24.
_ip_to_int() { local a b c d; IFS=. read -r a b c d <<< "$1"; echo $(( (a<<24)+(b<<16)+(c<<8)+d )); }
_int_to_ip() { local n=$1; echo "$(( (n>>24)&255 )).$(( (n>>16)&255 )).$(( (n>>8)&255 )).$(( n&255 ))"; }
_prefix_to_mask() { echo $(( 0xFFFFFFFF ^ ((1 << (32-$1)) - 1) )); }

LAN_MASK=$(_prefix_to_mask "$LAN_PREFIX")
LAN_NET="$(_int_to_ip $(( $(_ip_to_int "$LAN_IP") & LAN_MASK )))/${LAN_PREFIX}"
NETMASK="$(_int_to_ip "$LAN_MASK")"   # dotted-decimal for legacy /etc/network/interfaces

# ── Pre-flight checks ─────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && { echo "Error: run as root (sudo -E ./scripts/07_router_mode.sh)"; exit 1; }

for iface in "$WAN_IFACE" "$LAN_IFACE"; do
    if ! ip link show "$iface" &>/dev/null; then
        echo "Error: interface $iface not found."
        echo "Available interfaces: $(ip -br link show | awk '{print $1}' | grep -v lo | tr '\n' ' ')"
        exit 1
    fi
done

# ── Warning banner ────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   BeaconButty — Router Mode Setup                       ║"
echo "╠══════════════════════════════════════════════════════════╣"
printf "║  WAN interface  : %-38s║\n" "$WAN_IFACE  (faces ISP, DHCP)"
printf "║  LAN interface  : %-38s║\n" "$LAN_IFACE  (faces switch, static)"
printf "║  LAN gateway IP : %-38s║\n" "$LAN_IP/$LAN_PREFIX"
printf "║  DHCP pool      : %-38s║\n" "$DHCP_START – $DHCP_END"
printf "║  Upstream DNS   : %-38s║\n" "$DNS_UPSTREAM"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  The Pi will REBOOT at the end of this script.          ║"
echo "║  After reboot, SSH to: $LAN_IP                      ║"
echo "║  (Connect your switch/PC to $LAN_IFACE first)              ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
read -r -p "  Proceed? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Install required packages
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "── Step 1: Installing packages ──────────────────────────────"
apt-get update -qq
apt-get install -y --no-install-recommends \
    dnsmasq \
    iptables \
    iptables-persistent \
    netfilter-persistent

# ─────────────────────────────────────────────────────────────────────────────
# Step 2: Configure network interfaces
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "── Step 2: Configuring network interfaces ───────────────────"

# Detect which network manager is active and configure accordingly
if systemctl is-active --quiet NetworkManager; then
    echo "  Network manager: NetworkManager"

    # Remove any existing BeaconButty-managed connections on these interfaces
    nmcli -g UUID,DEVICE con show | awk -F: -v wan="$WAN_IFACE" -v lan="$LAN_IFACE" \
        '$2==wan || $2==lan {print $1}' \
        | xargs -r -I{} nmcli con del {} 2>/dev/null || true

    # WAN: DHCP from ISP, is the default route
    nmcli con add type ethernet \
        ifname "$WAN_IFACE" \
        con-name "bb-wan" \
        ipv4.method auto \
        ipv6.method ignore \
        connection.autoconnect yes \
        ipv4.route-metric 100

    # LAN: static IP, NOT the default route (WAN carries the default route)
    nmcli con add type ethernet \
        ifname "$LAN_IFACE" \
        con-name "bb-lan" \
        ipv4.method manual \
        ipv4.addresses "${LAN_IP}/${LAN_PREFIX}" \
        ipv4.never-default yes \
        ipv6.method ignore \
        connection.autoconnect yes

    # Tell NetworkManager not to manage DNS — dnsmasq owns that
    mkdir -p /etc/NetworkManager/conf.d
    cat > /etc/NetworkManager/conf.d/99-beaconbutty.conf <<'EOF'
[main]
dns=none
EOF

elif systemctl is-active --quiet networking; then
    echo "  Network manager: /etc/network/interfaces"

    # Back up existing interface configs
    for iface in "$WAN_IFACE" "$LAN_IFACE"; do
        [[ -f "/etc/network/interfaces.d/$iface" ]] && \
            cp "/etc/network/interfaces.d/$iface" \
               "/etc/network/interfaces.d/$iface.pre-router-backup"
    done

    cat > /etc/network/interfaces.d/beaconbutty-router <<EOF
# BeaconButty router mode — generated by 07_router_mode.sh
auto $WAN_IFACE
iface $WAN_IFACE inet dhcp
    metric 100

auto $LAN_IFACE
iface $LAN_IFACE inet static
    address $LAN_IP
    netmask $NETMASK
    up ip link set \$IFACE promisc on
EOF

else
    echo "ERROR: Cannot detect network manager (tried NetworkManager and networking)."
    echo "Configure $WAN_IFACE (DHCP) and $LAN_IFACE (static $LAN_IP/$LAN_PREFIX) manually."
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Enable IP forwarding
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "── Step 3: Enabling IP forwarding ───────────────────────────"

sysctl -w net.ipv4.ip_forward=1

cat > /etc/sysctl.d/99-beaconbutty-router.conf <<EOF
# BeaconButty: enable IPv4 forwarding for NAT routing
net.ipv4.ip_forward=1
EOF
# Note: net.bridge.bridge-nf-call-iptables is intentionally omitted.
# It requires the br_netfilter module which is not loaded in pure router mode
# and its absence would cause sysctl to error at boot.

# ─────────────────────────────────────────────────────────────────────────────
# Step 4: Configure iptables NAT and firewall
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "── Step 4: Configuring iptables NAT ────────────────────────"

# Flush everything and start clean
iptables -F
iptables -t nat -F
iptables -t mangle -F
iptables -X 2>/dev/null || true

# ── Default policies ──────────────────────────────────────────────────────────
iptables -P INPUT   DROP    # Block all inbound by default
iptables -P FORWARD DROP    # Block all forwarding by default
iptables -P OUTPUT  ACCEPT  # Allow all outbound from Pi itself

# ── INPUT: Pi's own traffic ───────────────────────────────────────────────────
# Loopback
iptables -A INPUT -i lo -j ACCEPT

# Established / related connections (responses to Pi's own outbound)
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Everything from the LAN is trusted (SSH, DNS, DHCP, etc.)
iptables -A INPUT -i "$LAN_IFACE" -j ACCEPT

# ICMP from LAN only — prevents pinging the Pi's WAN IP from the internet
iptables -A INPUT -i "$LAN_IFACE" -p icmp --icmp-type echo-request -j ACCEPT

# Drop everything else inbound on WAN
iptables -A INPUT -i "$WAN_IFACE" -j DROP

# ── FORWARD: LAN ↔ WAN ───────────────────────────────────────────────────────
# LAN → WAN: allow all outbound connections
iptables -A FORWARD -i "$LAN_IFACE" -o "$WAN_IFACE" \
    -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

# WAN → LAN: only allow responses to established connections
iptables -A FORWARD -i "$WAN_IFACE" -o "$LAN_IFACE" \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ── NAT: masquerade LAN traffic as Pi's WAN IP ───────────────────────────────
iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE

# ── Save rules ────────────────────────────────────────────────────────────────
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
echo "  iptables rules saved to /etc/iptables/rules.v4"

# ─────────────────────────────────────────────────────────────────────────────
# Step 5: Configure dnsmasq (DHCP + DNS for LAN)
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "── Step 5: Configuring dnsmasq ─────────────────────────────"

# Ensure target directories exist before writing into them
mkdir -p /etc/dnsmasq.d /etc/systemd/resolved.conf.d /var/log/beaconbutty

# systemd-resolved listens on 127.0.0.53:53 and conflicts with dnsmasq.
# Disable its stub listener; dnsmasq takes over DNS for the LAN.
cat > /etc/systemd/resolved.conf.d/99-beaconbutty.conf <<'EOF'
[Resolve]
DNSStubListener=no
EOF

# Pi's own resolver — point directly to upstream.
# dnsmasq handles DNS for LAN clients; the Pi itself resolves via 1.1.1.1/8.8.8.8.
# Replace any symlink (e.g. systemd-resolved stub) with a static file now.
[[ -L /etc/resolv.conf ]] && unlink /etc/resolv.conf
cat > /etc/resolv.conf <<EOF
# BeaconButty: static resolv.conf — Pi resolves upstream directly
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF

# Build the upstream server list for dnsmasq
DNSMASQ_SERVERS=""
IFS=',' read -ra DNS_LIST <<< "$DNS_UPSTREAM"
for dns in "${DNS_LIST[@]}"; do
    DNSMASQ_SERVERS+="server=$(echo "$dns" | tr -d ' ')"$'\n'
done

cat > /etc/dnsmasq.d/beaconbutty.conf <<EOF
# BeaconButty dnsmasq configuration — DHCP server + DNS forwarder for LAN

# Listen only on the LAN interface (never on WAN)
interface=${LAN_IFACE}
bind-interfaces
except-interface=${WAN_IFACE}
except-interface=lo

# ── DHCP ──────────────────────────────────────────────────────────────────────
dhcp-range=${DHCP_START},${DHCP_END},${DHCP_LEASE}
dhcp-option=option:router,${LAN_IP}           # Default gateway
dhcp-option=option:dns-server,${LAN_IP}       # Pi is the DNS server for clients
dhcp-option=option:domain-name,beaconbutty.local

# Static DHCP leases — add one line per device:
#   dhcp-host=<mac>,<hostname>,<ip>
# Example (commented out — uncomment and edit for your own devices):
#dhcp-host=aa:bb:cc:dd:ee:ff,laptop,192.168.50.50
#dhcp-host=11:22:33:44:55:66,nas,192.168.50.51

# Log DHCP assignments (useful for correlating Zeek IPs to hostnames)
dhcp-leasefile=/var/lib/misc/dnsmasq.leases
log-dhcp

# ── DNS forwarding ─────────────────────────────────────────────────────────────
${DNSMASQ_SERVERS}
# Security: don't forward bare hostnames or RFC1918 reverse lookups upstream
domain-needed
bogus-priv
no-resolv                   # Ignore /etc/resolv.conf for upstream; use server= above

# Cache 1000 DNS entries to speed up repeated lookups
cache-size=1000

# Log all DNS queries to syslog (tagged 'dnsmasq') for debugging
# Comment this out on a busy network to reduce log noise
log-queries
log-facility=/var/log/dnsmasq.log
EOF

# Ensure dnsmasq waits for interfaces to be fully up before starting.
# The default After=network.target fires too early; network-online.target
# waits for eth1 to have an address, preventing "unknown interface" failures.
mkdir -p /etc/systemd/system/dnsmasq.service.d
cat > /etc/systemd/system/dnsmasq.service.d/wait-for-network.conf <<'UNIT'
[Unit]
After=network-online.target
Wants=network-online.target
UNIT

systemctl daemon-reload
systemctl enable dnsmasq
echo "  dnsmasq configured — will start on reboot."

# ─────────────────────────────────────────────────────────────────────────────
# Step 6: Configure capture interface for Zeek
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "── Step 6: Updating Zeek configuration ─────────────────────"

ZEEK_ETC="$ZEEK_PREFIX/etc"

if [[ -f "$ZEEK_ETC/node.cfg" ]]; then
    # Update capture interface to LAN_IFACE
    sed -i "s|^interface=.*|interface=${LAN_IFACE}|" "$ZEEK_ETC/node.cfg"
    echo "  node.cfg: capture interface set to $LAN_IFACE"
else
    echo "  Warning: $ZEEK_ETC/node.cfg not found — run setup.sh first."
fi

if [[ -f "$ZEEK_ETC/networks.cfg" ]]; then
    # Add the LAN subnet if not already present
    if ! grep -q "^${LAN_NET}" "$ZEEK_ETC/networks.cfg"; then
        printf "%-22s Private\n" "$LAN_NET" >> "$ZEEK_ETC/networks.cfg"
        echo "  networks.cfg: added $LAN_NET"
    else
        echo "  networks.cfg: $LAN_NET already present"
    fi
fi

# In router mode, eth1 has an IP — promiscuous mode still helps but isn't
# strictly necessary. Keep it for consistency with previous capture setup.
cat > "/etc/network/interfaces.d/${LAN_IFACE}-capture" <<EOF
# BeaconButty: keep LAN interface in promiscuous mode for Zeek
post-up ip link set ${LAN_IFACE} promisc on
post-up ethtool -K ${LAN_IFACE} rx off tx off sg off tso off gso off gro off lro off || true
EOF

# ─────────────────────────────────────────────────────────────────────────────
# Step 7: Install WAN watchdog
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "── Step 7: Installing WAN watchdog ─────────────────────────"

install -m 755 "$SCRIPT_DIR/scripts/wan-watchdog.sh" /usr/local/bin/wan-watchdog.sh

cp "$SCRIPT_DIR/systemd/wan-watchdog.service" /etc/systemd/system/
cp "$SCRIPT_DIR/systemd/wan-watchdog.timer"   /etc/systemd/system/

systemctl daemon-reload
systemctl enable wan-watchdog.timer
echo "  WAN watchdog enabled (runs every 5 minutes after reboot)."

# ─────────────────────────────────────────────────────────────────────────────
# Step 8: Reboot
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Configuration complete. Rebooting in 10 seconds...     ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  After reboot:                                          ║"
echo "║    1. Connect your switch or PC to $LAN_IFACE               ║"
echo "║    2. You will receive DHCP from $DHCP_START+       ║"
echo "║    3. SSH to $LAN_IP                              ║"
echo "║    4. Check status:  zeekctl status                     ║"
echo "║                      systemctl status dnsmasq           ║"
echo "║                      systemctl status wan-watchdog.timer║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

sleep 10
systemctl reboot
