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

## ISP outages — what the evidence supports (2026-08-30)

The WAN gateway's MAC sits in the IANA **VRRP virtual-router** range, so the ISP terminates us on a redundant router pair and the gateway address is a floating virtual IP rather than a box on the end of our cable. During a failover no router owns that virtual MAC, so it goes silent — which is why "the gateway did not answer" cannot, on its own, mean "our link is broken".

**Treat "VRRP failover" as unproven.** The virtual MAC proves the topology is redundant, not that a failover happened, and a VRRP failover is sub-second to ~3 s while observed outages survive a 12-second probe burst and often two consecutive checks. Watching for VRRP adverts would settle it directly and is **not available to us**: the ISP filters IP protocol 112 from the customer port (tested 2026-08-31, zero packets in six seconds). What *is* available, since 2026-08-31, are two indirect witnesses — a DHCP lease issued mid-outage, and foreign broadcast still arriving on the segment — which distinguish "the edge is gone" from "the gateway address is unclaimed while the edge is up". On 2026-08-31 both of that day's outages were the latter — see [Health Monitoring](../operation/health-monitoring.md).

What the evidence has ruled out for the outages recorded so far:

| Hypothesis | Ruled out by |
|---|---|
| Our link or CPE | no carrier transition during any of them; the one genuine 4-second carrier drop correlated with **no** recorded outage |
| Session reset at the ISP access gear | DHCP renewals metronomic and the address unchanged throughout; the NM device never left `activated` |
| Our own stack | lease valid, default route present, `FORWARD`/NAT unchanged |

That leaves a forwarding break beyond our NIC — genuinely the ISP — but *which* sort is what the classification exists to answer.

## Interfaces

| Interface | MAC | Role | Address |
|-----------|-----|------|---------|
| eth0 | `aa:bb:cc:dd:ee:f0` | WAN — upstream to ISP router | DHCP, **routable public /24** (e.g. 203.0.113.45) |
| eth1 | `aa:bb:cc:dd:ee:ff` | LAN — gateway, Zeek capture | 192.168.50.1/24 (static) |
| wlan0 | `aa:bb:cc:dd:ee:f1` | WiFi — secondary LAN path, **DHCP client of bb0's own dnsmasq** | 192.168.50.151/24 (DHCP) |
| tailscale0 | n/a | Remote access VPN | `<tailscale-ip>` |

> [!warning] Check whether your WAN address is routable before trusting the firewall alone
> On this deployment the ISP hands out a public address rather than CGNAT, which makes bb0 directly internet-facing: its own firewall is the primary barrier, not an upstream NAT. Worth re-verifying on any new install — `curl -s ifconfig.me` matching the address on `eth0` means there is nothing in front of you.
>
> Because `sshd` and the webapp both bind `0.0.0.0`, netfilter would otherwise be a single point of failure, so each carries a second control that does not depend on it. See [Hardening](../security/hardening.md). Also worth confirming: no DNAT or port forwards, `FORWARD` policy `DROP` with WAN→LAN limited to `RELATED,ESTABLISHED`, no UPnP/NAT-PMP, and Tailscale advertising no subnet routes.

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

### Tailscale traffic in beacon detection

Tailscale clients constantly latency-probe **every** DERP region, so far-flung
relays show up as beacon-shaped destinations even though a tailnet only ever
relays through the one region it picks. Netcheck probes on three legs, each
found separately:

| Leg | Traffic | Cadence |
|---|---|---|
| STUN | UDP 3478 | continuous, ~275 conns/relay/day |
| HTTPS | `GET /generate_204?t=<epoch>`, `Go-http-client/1.1` UA | continuous |
| ICMP | 5 echo requests of ~30 B (found 2026-08-24) | one sweep, all relays at once |

Suppression is deliberately **not** by host or domain FP: DERP relays carry
end-to-end-encrypted WireGuard that neither Tailscale nor the sensor can
inspect, so blanket-suppressing the destination would hide exfiltration over
the tailnet. A `*.tailscale.com` wildcard should be narrowed to the
control-plane endpoints (`controlplane.`, `log.`, `pkgs.`, `login.`) so
`derp*` stays visible.

Nor is a `3478:udp` protocol FP enough on the main beacon surfaces: RITA
bundles all three legs into one row, and a protocol FP may only suppress a row
when *every* component matches. What separates probe from payload is **volume**
— see [False Positive Workflow](../investigation/false-positive-workflow.md#structural-gate-tailscale-derp-netcheck-added-2026-08-15)
for the structural gate, and [Slow-Cadence Beacons](../investigation/slow-cadence-beacons.md#worked-example-tailscale-derp-relays)
for the case that started it.

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
