---
tags: [beaconbutty/security]
created: 2026-04-17
---

# Security & Hardening

bb0 is a network appliance with a WAN interface exposed to the ISP, so hardening is not optional. The authoritative source is `scripts/harden.sh` — re-run it at any time to verify and re-apply the baseline.

```bash
sudo /home/dm/BeaconButty/scripts/harden.sh
```

The script is idempotent and reports per-section ✓/!/✗ with a final failures+warnings summary. Exit 0 = clean, 1 = at least one failure.

## Attack surface

| Interface | Exposure | Policy |
|-----------|---------|--------|
| `eth0` (WAN) | Public internet via ISP router | **INPUT DROP** — only Tailscale WireGuard UDP/41641 and ESTABLISHED,RELATED accepted |
| `eth1` (LAN) | Trusted 192.168.50.0/24 | INPUT ACCEPT |
| `wlan0` | Secondary LAN | Same as eth1 |
| `tailscale0` | Tailnet (authenticated peers) | INPUT ACCEPT |
| `lo` | Loopback | ACCEPT |

## Firewall (iptables)

Baseline written by `07_router_mode.sh`, verified + extended by `harden.sh`:

- `INPUT` policy **DROP** (explicit `-i eth0 -j DROP` as a belt-and-braces).
- `FORWARD` policy set up for NAT: LAN→WAN MASQUERADE via `POSTROUTING`, return traffic via conntrack.
- Tailscale rules: `INPUT -i tailscale0 -j ACCEPT` + `INPUT -i eth0 -p udp --dport 41641 -j ACCEPT`.
- IPv6: `INPUT DROP`, `FORWARD DROP`, LAN + ICMPv6 ACCEPT. ICMPv6 must stay open — required for neighbour discovery, SLAAC, RA.

Rules persist via `iptables-save > /etc/iptables/rules.v4` (and `.v6`). `netfilter-persistent` service restores on boot.

```bash
# View current rules
sudo iptables -L -n -v
sudo iptables -t nat -L -n -v
sudo ip6tables -L -n -v

# Re-verify and re-apply
sudo /home/dm/BeaconButty/scripts/harden.sh
```

## SSH

Hardening is applied as a drop-in at `/etc/ssh/sshd_config.d/99-beaconbutty-hardening.conf` — the main `sshd_config` is untouched.

| Setting | Value |
|---------|-------|
| `PasswordAuthentication` | `no` (only if keys are present — otherwise skipped to avoid lockout) |
| `KbdInteractiveAuthentication` | `no` |
| `PermitRootLogin` | `no` |
| `PermitEmptyPasswords` | `no` |
| `MaxAuthTries` | `3` |
| `LoginGraceTime` | `20` seconds |
| `X11Forwarding` | `no` |
| `AllowAgentForwarding` | `no` |
| `AllowTcpForwarding` | `no` |
| `AllowStreamLocalForwarding` | `no` |
| `AllowUsers` | `dm` (the non-root login user) |

> [!warning]
> `harden.sh` will **not** disable password auth if `~dm/.ssh/authorized_keys` is empty. If you're locked out, re-enable with a one-time drop-in override, log in, install your key, and re-run the script.

```bash
# Validate before reload
sudo sshd -t

# Reload
sudo systemctl reload sshd
```

## fail2ban

SSH brute-force protection. Jail config at `/etc/fail2ban/jail.d/beaconbutty-ssh.conf`:

| Setting | Value |
|---------|-------|
| `maxretry` | 5 failures |
| `findtime` | 10 min |
| `bantime` | 1 hour |
| `ignoreip` | `127.0.0.1/8`, `192.168.50.0/24` |

```bash
# See current bans
sudo fail2ban-client status sshd

# Unban an address
sudo fail2ban-client unban <ip>
```

## Unattended security upgrades

Config: `/etc/apt/apt.conf.d/52beaconbutty-autoupdate`.

- Security patches only (Debian-Security + Raspbian label).
- **No auto-reboot** — a reboot requires a clean ClickHouse stop (see [Reboot Procedure](../operation/reboot-procedure.md)).
- `APT::Periodic::Update-Package-Lists = 1`, `Unattended-Upgrade = 1`.
- Service: `unattended-upgrades.service` (enabled + started by harden.sh).

```bash
# Dry-run pending security updates
sudo unattended-upgrades --dry-run --debug

# Trigger a run now
sudo unattended-upgrade -d
```

## Masked services

Services unnecessary on a headless router are disabled + masked (mask prevents restart even as a dependency):

`sendmail`, `mta-sts`, `cups`, `cups-browsed`, `bluetooth`, `ModemManager`

Remote-desktop daemons disabled + stopped if present:
`xrdp`, `xrdp-sesman`, `wayvnc`, `wayvnc-control`, `vncserver-x11-serviced`, `vncserver-virtuald`, `realvnc-vnc-server`

## Sysctl hardening

Written to `/etc/sysctl.d/99-beaconbutty-hardening.conf`:

| Setting | Value | Purpose |
|---------|-------|---------|
| `net.ipv4.tcp_syncookies` | 1 | SYN flood protection |
| `net.ipv4.conf.all.rp_filter` | 1 | Reverse-path anti-spoofing |
| `net.ipv4.conf.all.arp_ignore` | 1 | Reply only when target IP is on receiving iface (kills ARP flux from bb0's eth1+wlan0 both sitting on the LAN) |
| `net.ipv4.conf.all.arp_announce` | 2 | Announce from the iface the IP lives on |
| `net.ipv4.conf.all.accept_redirects` | 0 | Don't accept ICMP redirects |
| `net.ipv4.conf.all.send_redirects` | 0 | Don't send ICMP redirects |
| `net.ipv4.conf.all.accept_source_route` | 0 | Drop source-routed packets |
| `net.ipv4.icmp_echo_ignore_broadcasts` | 1 | Smurf protection |
| `net.ipv4.conf.all.log_martians` | 1 | Log packets with impossible source IPs |
| `kernel.dmesg_restrict` | 1 | Restrict kernel ring buffer to root |
| `vm.swappiness` | 10 | Prefer evicting page cache over swapping anonymous pages — keeps Suricata/ClickHouse working sets resident; on NVMe the cache-miss side is cheap |

## Secrets on disk

| Secret | Path | Protection |
|--------|------|-----------|
| Let's Encrypt private key | `/etc/letsencrypt/live/<domain>/privkey.pem` | root-only; certbot deploy hook sets group perms for `bb-graphs` |
| Slack user token (xoxp) | `/var/lib/beaconbutty/slack-config.json` | mode 600 |
| AWS credentials | `~/.aws/credentials` (certbot IAM + MFA profile) | mode 600 |
| Alert shared secret | Hard-coded in `scripts/alert.sh` (`<shared-alert-secret>`) | Validated by Lambda via `X-BeaconButty-Secret` header |
| SSH host keys | `/etc/ssh/ssh_host_*` | Standard sshd perms |
| Tailscale state | `/var/lib/tailscale/` | root-only |

> [!danger]
> All secrets live on the NVMe, which is cloned by `rpi-clone`. The USB clone drive therefore contains **every** production secret — keep it physically secured.

## AWS IAM (FORCE_MFA)

All AWS CLI calls that hit user-level APIs (Route53 domains, IAM itself) are blocked by the `FORCE_MFA` policy unless called with an MFA-assumed session. Use `--profile mfa`:

```bash
aws route53domains list-domains --profile mfa
aws iam list-users --profile mfa
```

Route53-for-DNS challenges via certbot use a dedicated IAM user (`certbot-beaconbutty`) with Route 53 permissions scoped to the BeaconButty domain. That user's long-lived access key doesn't require MFA — it's deliberately limited-scope.

## Audit checklist

Run at any time; quick sanity sweep:

```bash
# Firewall posture
sudo iptables -L INPUT -n -v | head -20
sudo ip6tables -L INPUT -n -v | head

# SSH posture
sudo sshd -T | grep -E 'permitrootlogin|passwordauthentication|maxauthtries|allowusers'

# Open ports (all interfaces)
sudo ss -tulnp

# Failed SSH attempts (recent)
sudo journalctl -u ssh -u sshd --since "24 hours ago" | grep -i 'failed\|invalid'

# fail2ban bans
sudo fail2ban-client status sshd

# Pending security updates
sudo apt list --upgradable 2>/dev/null | grep -i security

# sysctl hardening in effect
sudo sysctl -a 2>/dev/null | grep -E 'rp_filter|syncookies|log_martians|accept_redirects' | head
```

## Open CVEs being tracked

| CVE | Name | Status | Notes |
|-----|------|--------|-------|
| CVE-2026-31431 | "Copy Fail" — kernel LPE via `authencesn` | **Vulnerable, awaiting rpt kernel rebuild** (as of 2026-05-02) | Local-only; bb0 only shell user is `dm`. Mitigation (blacklist `authencesn` module) held in reserve. See *Upgrade Log*. |

The rpt kernel ships through `archive.raspberrypi.com`, **not** Debian-Security — so it will **not** be picked up by `unattended-upgrades`. Watch for it manually:

```bash
sudo apt update && apt list --upgradable 2>/dev/null | grep linux-image
```

## Known benign failure

`NetworkManager-wait-online.service` may appear in `systemctl --failed` — see [Health Monitoring](../operation/health-monitoring.md).

## See also

- [Network Topology](../architecture/network-topology.md) — interface roles + Tailscale
- [Backup & Recovery](../operation/backup-and-recovery.md) — TLS cert handling and DR
- [Reboot Procedure](../operation/reboot-procedure.md) — why no auto-reboot on unattended-upgrades
- [Troubleshooting](../operation/troubleshooting.md) — SSH lockout recovery, fail2ban cleanup
