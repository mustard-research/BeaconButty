---
tags: [beaconbutty/architecture]
created: 2026-04-16
---

# Network Topology

The Pi (hostname `bb0`) sits between the ISP router and the LAN, acting as a NAT router. This gives Zeek full visibility into all LAN traffic without needing a managed switch with port mirroring.

## Physical layout

```
[Internet]
    │
[ISP Router]
    │
  eth0 (bb0) ── WAN, DHCP from ISP
    │
  eth1 (bb0) ── LAN, 192.168.50.1/24, Zeek capture interface
    │
[LAN switch]
    │
[LAN devices]
```

## Interfaces

| Interface | MAC | Role | Address |
|-----------|-----|------|---------|
| eth0 | `aa:bb:cc:dd:ee:f0` | WAN — upstream to ISP router | DHCP (e.g. 203.0.113.45) |
| eth1 | `aa:bb:cc:dd:ee:ff` | LAN — gateway, Zeek capture | 192.168.50.1/24 (static) |
| wlan0 | `aa:bb:cc:dd:ee:f1` | WiFi — secondary LAN path, **DHCP client of bb0's own dnsmasq** | 192.168.50.151/24 (DHCP) |
| tailscale0 | n/a | Remote access VPN | `<tailscale-ip>` |

> [!note] bb0 is multi-homed on its own LAN
> Both `eth1` and `wlan0` sit on `192.168.50.0/24`. With kernel ARP defaults this produces "ARP flux" — either interface replies for the other's IP — which the L2 monitor flags as MAC-change anomalies. Mitigated by `arp_ignore=1` + `arp_announce=2` in the hardening sysctls (see [Hardening](../security/hardening.md)) **and** by the L2 builder auto-suppressing any IP whose MACs are entirely from `/sys/class/net/*/address`. So the Pi has two different MACs visibly active on the LAN by design.

## DNS and DHCP

**dnsmasq** handles both DHCP and DNS for the LAN:
- DHCP pool: `192.168.50.20 – 192.168.50.250`
- Upstream DNS: `1.1.1.1` (Cloudflare) and `8.8.8.8` (Google)
- Provides hostname resolution for LAN devices — used by the webapp for device labels in reports

## Zeek capture

Zeek captures on `eth1` (the LAN-facing interface). It sees all traffic between LAN devices and the internet. It does not see purely local LAN-to-LAN traffic unless that traffic routes through the Pi.

## Tailscale

bb0 is enrolled in Tailscale under `<your tailscale user>`. Provides secure remote access without port forwarding. HTTPS is handled by Let's Encrypt, not Tailscale certs — see [Backup & Recovery](../operation/backup-and-recovery.md).

| Node | Tailscale IP | Notes |
|------|-------------|-------|
| bb0 | `<tailscale-ip>` | This Pi — BeaconButty |
| bb1 | `<tailscale-ip>` | Pi 5 4GB — still active |
| (other tailnet nodes) | `<tailscale-ip>` | Desktops, laptops, lab boxes |

## Known LAN devices

The format below shows the kind of inventory the appliance maintains; substitute your own devices. Examples:

| IP | Device | Notes |
|----|--------|-------|
| 192.168.50.1 | bb0 (this Pi) | Router / BeaconButty |
| 192.168.50.50 | Example: smart exercise bike | Regular telemetry |
| 192.168.50.60 | Example: family laptop | Multi-user macOS |
| 192.168.50.137 | bb1 | Pi 5 4GB |
| 192.168.50.160 | Example: air-quality monitor | FP registered — ICMP telemetry |
| 192.168.50.200 | Example: phone | Randomised MAC |
| 192.168.50.80 | Example: Amazon Echo Show | DHCP hostname `echoshow-…` |
| 192.168.50.147 | Example: Amazon Kindle | No DHCP hostname; Fire OS |

Devices with randomised MACs (most modern phones and some laptops), Nvidia Jetson boards, and various IoT (smart-home, fitness) typically show up here too.

> [!note]
> Kindles and Fire devices do a benign once-daily UDP NAT-traversal punch to an Amazon EC2 pool (`23.23.189.0/24`, ports 33434/40317/49317) — it trips `/beacons/slow` but is normal Amazon device connectivity. Amazon devices are FP'd by MAC (identified 2026-05-16).

> [!note]
> Devices with randomised MACs (most modern phones and some laptops) can change their LAN IP across DHCP renewals. False positive registrations are currently keyed by IP, which means they may break if a device's IP changes. Keying by MAC is a known improvement — see [False Positive Workflow](../investigation/false-positive-workflow.md).
