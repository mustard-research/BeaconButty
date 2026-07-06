#!/bin/bash
# Renew the Tailscale TLS certificate for the BeaconButty webapp.
# Run monthly by tailscale-cert-renew.timer.
#
# Requires BB_TS_CERT_HOST in /etc/beaconbutty/local.env, e.g.:
#   BB_TS_CERT_HOST=myhost.tailXXXX.ts.net
set -euo pipefail

[[ -f /etc/beaconbutty/local.env ]] && source /etc/beaconbutty/local.env
if [[ -z "${BB_TS_CERT_HOST:-}" ]]; then
    echo "BB_TS_CERT_HOST not set in /etc/beaconbutty/local.env — skipping" >&2
    exit 0
fi

tailscale cert --cert-file /etc/ssl/tailscale/bb0.crt --key-file /etc/ssl/tailscale/bb0.key "$BB_TS_CERT_HOST"
chmod 644 /etc/ssl/tailscale/bb0.crt
chmod 640 /etc/ssl/tailscale/bb0.key
chown root:dm /etc/ssl/tailscale/bb0.key
systemctl restart bb-graphs.service
