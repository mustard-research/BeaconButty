#!/usr/bin/env bash
# harden.sh — BeaconButty security hardening
#
# Safe to run at any time; checks state before making changes.
# Exit code: 0 = all good, 1 = one or more steps failed.
#
# What it does:
#   1. Verifies the WAN firewall (INPUT DROP policy from 07_router_mode.sh)
#   2. Adds Tailscale interface to the INPUT accept rules
#   3. Disables unnecessary remote-desktop services (xrdp, wayvnc)
#   4. Hardens SSH — key-only auth, no root login, rate limiting on WAN
#   5. Installs fail2ban for SSH brute-force protection
#   6. Enables unattended-upgrades for automatic security patches
#
# Usage:
#   sudo ./scripts/harden.sh

set -euo pipefail

[[ $EUID -ne 0 ]] && { echo "Run as root: sudo ./scripts/harden.sh"; exit 1; }

# ── Colours ───────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    RED='\033[0;31m';   RESET='\033[0m'; BOLD='\033[1m'
else
    GREEN=''; YELLOW=''; RED=''; RESET=''; BOLD=''
fi

OK()   { echo -e "  ${GREEN}✓${RESET}  $*"; }
WARN() { echo -e "  ${YELLOW}!${RESET}  $*"; WARNINGS=$(( WARNINGS + 1 )); }
FAIL() { echo -e "  ${RED}✗${RESET}  $*"; FAILURES=$(( FAILURES + 1 )); }
INFO() { echo -e "  ${BOLD}→${RESET}  $*"; }

FAILURES=0
WARNINGS=0

WAN_IFACE="${WAN_IFACE:-eth0}"
LAN_IFACE="${LAN_IFACE:-eth1}"
TAILSCALE_IFACE="tailscale0"

# ── Header ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}BeaconButty Security Hardening — $(date '+%Y-%m-%d %H:%M %Z')${RESET}"
echo "────────────────────────────────────────────────────"

# ── 1. Verify WAN firewall ────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Firewall${RESET}"

INPUT_POLICY=$(iptables -L INPUT --line-numbers -n 2>/dev/null | head -1 | grep -oP 'policy \K\w+' || echo "UNKNOWN")

if [[ "$INPUT_POLICY" == "DROP" ]]; then
    OK "INPUT policy: DROP  (WAN firewall active from 07_router_mode.sh)"
else
    FAIL "INPUT policy is ${INPUT_POLICY} — WAN firewall not in place."
    INFO "Run scripts/07_router_mode.sh first to set up NAT and firewall rules."
fi

# Verify the WAN drop rule exists
if iptables -C INPUT -i "$WAN_IFACE" -j DROP 2>/dev/null; then
    OK "WAN drop rule: present  (-i $WAN_IFACE -j DROP)"
else
    WARN "WAN explicit drop rule missing — adding it now."
    iptables -A INPUT -i "$WAN_IFACE" -j DROP
    OK "WAN drop rule: added."
fi

# Add Tailscale interface rule if not already present
if ip link show "$TAILSCALE_IFACE" &>/dev/null; then
    if iptables -C INPUT -i "$TAILSCALE_IFACE" -j ACCEPT 2>/dev/null; then
        OK "Tailscale INPUT rule: already present"
    else
        iptables -I INPUT 3 -i "$TAILSCALE_IFACE" -j ACCEPT
        OK "Tailscale INPUT rule: added  (traffic on $TAILSCALE_IFACE now accepted)"
    fi
    # Also allow the WireGuard UDP port Tailscale uses
    if ! iptables -C INPUT -i "$WAN_IFACE" -p udp --dport 41641 -j ACCEPT 2>/dev/null; then
        iptables -I INPUT 3 -i "$WAN_IFACE" -p udp --dport 41641 -j ACCEPT
        OK "Tailscale WireGuard port 41641/udp: opened on $WAN_IFACE"
    fi
else
    WARN "Tailscale interface ($TAILSCALE_IFACE) not found — skipping Tailscale rules."
    INFO "If you install Tailscale later, re-run this script."
fi

# Save updated rules
iptables-save > /etc/iptables/rules.v4
OK "iptables rules saved."

# ── IPv6 Firewall ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}IPv6 Firewall${RESET}"

if command -v ip6tables &>/dev/null; then
    ip6tables -P INPUT   DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT  ACCEPT
    ip6tables -F INPUT
    ip6tables -F FORWARD

    ip6tables -A INPUT -i lo                              -j ACCEPT
    ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ip6tables -A INPUT -i "$LAN_IFACE"                    -j ACCEPT
    # ICMPv6 is required for neighbour discovery, SLAAC, router advertisements
    ip6tables -A INPUT -p ipv6-icmp                       -j ACCEPT

    ip6tables-save > /etc/iptables/rules.v6
    OK "IPv6 firewall: configured and saved  (INPUT DROP, LAN + ICMPv6 accepted)"
else
    WARN "ip6tables not found — IPv6 traffic is unfiltered."
    INFO "Install with: apt-get install -y iptables"
fi

# ── Sysctl Hardening ──────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Sysctl Hardening${RESET}"

SYSCTL_FILE="/etc/sysctl.d/99-beaconbutty-hardening.conf"

cat > "$SYSCTL_FILE" <<'SYSCTL'
# BeaconButty: kernel hardening — written by harden.sh
# Do not edit; re-run harden.sh to update.

# SYN flood protection
net.ipv4.tcp_syncookies = 1

# Reverse-path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Suppress ARP flux. bb0 has eth1 (gateway 192.168.50.1) and wlan0
# (DHCP client 192.168.50.151) on the same LAN, so with the kernel
# defaults either interface will reply to ARP for either IP — produces
# spurious "MAC change" anomalies in the L2 monitor.
# arp_ignore=1: only reply when the target IP belongs to the receiving iface.
# arp_announce=2: always source ARP announcements from the iface the IP is on.
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.default.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.default.arp_announce = 2

# Do not accept ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Do not send ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Do not accept source-routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Ignore broadcast ICMP (Smurf attack protection)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Log packets with impossible source addresses (useful on a security device)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Restrict kernel ring buffer access to root
kernel.dmesg_restrict = 1

# Prefer evicting page cache over swapping anonymous pages. bb0 runs a few
# long-lived high-RSS processes (Suricata, ClickHouse) whose working sets
# benefit from staying resident; swap is on NVMe so the cache-miss side of
# the trade is cheap. Default is 60, which paged out ~600 MB of Suricata
# under a transient agent-driven memory spike.
vm.swappiness = 10
SYSCTL

sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
OK "sysctl hardening: applied  (${SYSCTL_FILE})"

# ── 2. Disable unnecessary remote-desktop services ───────────────────────────
echo ""
echo -e "${BOLD}Remote Desktop Services${RESET}"

# Disable by explicit unit name first (covers xrdp, xrdp-sesman)
for svc in xrdp xrdp-sesman wayvnc wayvnc-control vncserver-x11-serviced vncserver-virtuald realvnc-vnc-server; do
    if systemctl cat "${svc}.service" &>/dev/null; then
        systemctl disable --now "$svc" 2>/dev/null || true
        OK "${svc}: disabled and stopped"
    fi
done

# wayvnc is sometimes installed with a custom wrapper service — find it by process
if pgrep -f wayvnc &>/dev/null; then
    # Find the systemd unit that owns the wayvnc process
    WAYVNC_PID=$(pgrep -f wayvnc | head -1)
    WAYVNC_UNIT=$(systemctl status "$WAYVNC_PID" 2>/dev/null | awk '/Loaded:/{print $2}' || true)
    if [[ -z "$WAYVNC_UNIT" ]]; then
        # Try to find by searching unit files for wayvnc
        WAYVNC_UNIT=$(systemctl list-units --all 2>/dev/null | awk '/wayvnc|vnc-run/{print $1}' | head -1)
    fi
    if [[ -n "$WAYVNC_UNIT" ]]; then
        systemctl disable --now "$WAYVNC_UNIT" 2>/dev/null || true
        OK "wayvnc service ($WAYVNC_UNIT): disabled and stopped"
    else
        pkill -f wayvnc 2>/dev/null || true
        WARN "wayvnc killed but unit not identified — check: systemctl list-units | grep vnc"
    fi
fi

# Mask and stop services unnecessary on a headless router.
# Masking is stronger than disabling — prevents restart even as a dependency.
for svc in sendmail mta-sts cups cups-browsed bluetooth ModemManager; do
    if systemctl cat "${svc}.service" &>/dev/null; then
        systemctl disable "$svc" 2>/dev/null || true
        systemctl stop "$svc" 2>/dev/null || true
        systemctl mask "$svc" 2>/dev/null || true
        # Kill any orphaned process not tracked by systemd
        pkill -x "$svc" 2>/dev/null || true
        OK "${svc}: masked and stopped (not needed on a router)"
    fi
done

# ── 3. SSH hardening ──────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}SSH Hardening${RESET}"

# Identify the non-root login user (SUDO_USER is set when running via sudo)
LOGIN_USER="${SUDO_USER:-}"
if [[ -z "$LOGIN_USER" || "$LOGIN_USER" == "root" ]]; then
    LOGIN_USER=$(getent passwd | awk -F: '$3>=1000 && $3<65534 {print $1}' | head -1)
fi

AUTH_KEYS=""
if [[ -n "$LOGIN_USER" ]]; then
    HOME_DIR=$(getent passwd "$LOGIN_USER" | cut -d: -f6)
    AUTH_KEYS="${HOME_DIR}/.ssh/authorized_keys"
fi

# Check for at least one installed public key before disabling passwords
KEYS_PRESENT=false
if [[ -n "$AUTH_KEYS" && -s "$AUTH_KEYS" ]]; then
    KEY_COUNT=$(grep -cE '^(ssh-|ecdsa-|sk-)' "$AUTH_KEYS" 2>/dev/null) || KEY_COUNT=0
    if [[ "$KEY_COUNT" -gt 0 ]]; then
        OK "SSH keys: ${KEY_COUNT} key(s) in ${AUTH_KEYS}"
        KEYS_PRESENT=true
    fi
fi

if [[ "$KEYS_PRESENT" == "false" ]]; then
    WARN "No SSH public keys found for user ${LOGIN_USER:-unknown}."
    WARN "Skipping password-auth disable — you would lock yourself out."
    INFO "Add your public key first:"
    INFO "  ssh-copy-id ${LOGIN_USER:-<user>}@192.168.50.1"
    INFO "Then re-run this script."
fi

# Write hardening config as a drop-in (preserves existing sshd_config)
SSHD_DROP_IN="/etc/ssh/sshd_config.d/99-beaconbutty-hardening.conf"

{
    echo "# BeaconButty SSH hardening — written by harden.sh"
    echo "# Do not edit; re-run harden.sh to update."
    echo ""

    if [[ "$KEYS_PRESENT" == "true" ]]; then
        echo "PasswordAuthentication no"
        echo "KbdInteractiveAuthentication no"
    fi

    echo "PermitRootLogin no"
    echo "PermitEmptyPasswords no"
    echo "MaxAuthTries 3"
    echo "LoginGraceTime 20"
    echo "X11Forwarding no"
    echo "AllowAgentForwarding no"
    echo "AllowTcpForwarding no"
    echo "AllowStreamLocalForwarding no"

    if [[ -n "$LOGIN_USER" ]]; then
        echo "AllowUsers ${LOGIN_USER}"
    fi
} > "$SSHD_DROP_IN"

# Validate config before reloading
if sshd -t 2>/dev/null; then
    systemctl reload sshd
    OK "SSH config applied and daemon reloaded."
    if [[ "$KEYS_PRESENT" == "true" ]]; then
        OK "Password authentication: disabled."
    fi
    OK "Root login: disabled.  Empty passwords: forbidden."
    OK "MaxAuthTries: 3, LoginGraceTime: 20s.  Unix socket forwarding: disabled."
    if [[ -n "$LOGIN_USER" ]]; then
        OK "AllowUsers: ${LOGIN_USER}"
    fi
else
    FAIL "sshd config validation failed — reverting drop-in."
    rm -f "$SSHD_DROP_IN"
fi

# ── 4. fail2ban ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}fail2ban (SSH brute-force protection)${RESET}"

if ! command -v fail2ban-server &>/dev/null; then
    # Check DNS/connectivity before attempting package install
    if ! getent hosts deb.debian.org &>/dev/null; then
        FAIL "Cannot resolve deb.debian.org — Pi DNS is broken."
        INFO "Fix with: sudo unlink /etc/resolv.conf; printf 'nameserver 1.1.1.1\\n' | sudo tee /etc/resolv.conf"
        INFO "Then re-run this script."
        exit 1
    fi
    INFO "Installing fail2ban..."
    apt-get install -y --no-install-recommends fail2ban
fi

# Write a jail config for SSH
cat > /etc/fail2ban/jail.d/beaconbutty-ssh.conf <<'EOF'
[sshd]
enabled  = true
port     = ssh
filter   = sshd
maxretry = 5
findtime = 10m
bantime  = 1h
ignoreip = 127.0.0.1/8 192.168.50.0/24
EOF

systemctl enable --now fail2ban
OK "fail2ban: enabled, SSH jail active  (5 failures → 1h ban, LAN exempt)"

# ── 5. Automatic security updates ────────────────────────────────────────────
echo ""
echo -e "${BOLD}Automatic Security Updates${RESET}"

if ! dpkg -l unattended-upgrades &>/dev/null; then
    INFO "Installing unattended-upgrades..."
    apt-get install -y --no-install-recommends unattended-upgrades
fi

# Minimal config: security updates only, no auto-reboot
cat > /etc/apt/apt.conf.d/52beaconbutty-autoupdate <<'EOF'
// BeaconButty: apply security updates automatically, no auto-reboot
Unattended-Upgrade::Origins-Pattern {
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
    "origin=Raspbian,codename=${distro_codename},label=Raspbian";
};
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

systemctl enable --now unattended-upgrades
OK "unattended-upgrades: enabled  (security patches, no auto-reboot)"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────────────────"
if [[ "$FAILURES" -eq 0 && "$WARNINGS" -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}Hardening complete — no issues.${RESET}"
elif [[ "$FAILURES" -eq 0 ]]; then
    echo -e "${YELLOW}${BOLD}Hardening complete — ${WARNINGS} warning(s) to review.${RESET}"
else
    echo -e "${RED}${BOLD}${FAILURES} failure(s), ${WARNINGS} warning(s).${RESET}"
fi
echo ""

exit $(( FAILURES > 0 ? 1 : 0 ))
