# BeaconButty docs

Project overview lives in the top-level [README](../README.md). This `docs/` tree is the deeper material — design rationale, install/operate playbooks, and threat-case writeups.

- **[architecture/](architecture/)** — system design, services, data pipeline, alert chain, log2ram strategy
- **[hardware/](hardware/)** — Pi build, cooling, OLED display
- **[operation/](operation/)** — daily operations, health monitoring, backup & recovery, capacity, troubleshooting, reboot procedure
- **[security/](security/)** — hardening (SSH, firewall, fail2ban, sudoers)
- **[development/](development/)** — webapp internals, full script/timer inventory, licensing
- **[investigation/](investigation/)** — false-positive workflow, alert tuning, slow-cadence detector design, external IP intel, threat case studies

Start with [architecture/system-overview.md](architecture/system-overview.md) for the design rationale; [hardware/hardware-setup.md](hardware/hardware-setup.md) for the bill of materials; [`../RESTORE.md`](../RESTORE.md) for the install playbook (written as DR but doubles as the most rigorous install path).
