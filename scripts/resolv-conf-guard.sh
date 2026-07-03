#!/usr/bin/env bash
set -euo pipefail

# resolv-conf-guard.sh
#
# Writes the canonical /etc/resolv.conf and freezes it with `chattr +i` so
# nothing can silently blank it. Runs as a systemd oneshot at boot
# (resolv-conf-guard.service, After=network-pre.target) and can be re-run
# manually after a legitimate config change.
#
# Also seeds /etc/resolv.conf.head with the same content — if anything ever
# does successfully regenerate resolv.conf from a template (dhcpcd hook,
# resolvconf, etc.) it will still contain a working nameserver line.
#
# See: memory/project_dns_resolv_incident.md, memory/project_bb0_wlan0.md

RESOLV=/etc/resolv.conf
HEAD=/etc/resolv.conf.head

# bb0's own dnsmasq on 192.168.50.1 (eth1) — 127.0.0.1 is refused, see
# project_bb0_wlan0.md — plus a public fallback for the case where dnsmasq
# is down.
CONTENT='# BeaconButty: managed by resolv-conf-guard.service — do not edit by hand
# See scripts/resolv-conf-guard.sh
nameserver 192.168.50.1
nameserver 8.8.8.8
'

[[ $EUID -ne 0 ]] && { echo "resolv-conf-guard: must run as root" >&2; exit 1; }

write_frozen() {
    local target="$1"
    # Clear any existing immutable flag before we can write
    chattr -i "$target" 2>/dev/null || true
    printf '%s' "$CONTENT" > "$target"
    chmod 0644 "$target"
    chattr +i "$target"
}

write_frozen "$RESOLV"
write_frozen "$HEAD"

echo "resolv-conf-guard: /etc/resolv.conf and /etc/resolv.conf.head written and marked immutable"
