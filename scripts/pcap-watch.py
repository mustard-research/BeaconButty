#!/usr/bin/env python3
"""
bb-pcap-watch — long-running daemon that captures targeted PCAPs for the
domains listed in /var/lib/beaconbutty/domain-watch.json.

Lifecycle per domain:
  - Add: clean any leftover PCAP dir, resolve IPs (getent + Zeek dns.log
    last 10 min), spawn `tcpdump -G 300 -W 24` with a BPF filter pinned to
    those IPs. PCAP files land in /var/lib/beaconbutty/pcaps/<sanitised>/.
  - Refresh: every poll cycle, re-resolve IPs. If new IPs have appeared,
    SIGINT the running tcpdump (it flushes the active file) and respawn
    with the widened filter.
  - Remove: SIGINT tcpdump, remove the rolling PCAP dir entirely. Snapshots
    elsewhere are untouched.

Files in pcap dirs are root-owned but the parent dir has the setgid bit
and group=dm, so new files inherit group=dm and the webapp can read them.

The daemon is intentionally simple: synchronous loop, no threads, no
inotify, no asyncio. tcpdump and the kernel do the heavy lifting; this
script just reconciles desired-vs-actual state every few seconds.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

CONFIG_PATH   = Path("/var/lib/beaconbutty/domain-watch.json")
PCAP_ROOT     = Path("/var/lib/beaconbutty/pcaps")
ZEEK_DNS_LOG  = Path("/var/log/zeek/current/dns.log")
INTERFACE     = "any"      # see all interfaces — bb0 is the NAT router, so
                           #     LAN devices' traffic to a watched domain
                           #     traverses eth1→eth0 with NAT in between.
                           #     Listening on `any` catches both pre- and
                           #     post-NAT, plus bb0's own outbound.
ROTATE_SECS   = 300         # 5 min per file
RING_FILES    = 24          # 24 × 5min = 2h rolling window per domain
POLL_INTERVAL = 5           # seconds between reconciliation passes
DNS_LOG_LOOKBACK = 600      # seconds of dns.log to scan for fresh IPs

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=logging.INFO,
    stream=sys.stdout,
)
log = logging.getLogger("pcap-watch")


def sanitise(domain: str) -> str:
    return re.sub(r"[^a-z0-9.-]", "_", domain.lower())[:120]


def load_config() -> list[str]:
    try:
        cfg = json.loads(CONFIG_PATH.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    raw = cfg.get("domains")
    if raw is None:
        legacy = (cfg.get("domain") or "").strip()
        raw = [legacy] if legacy else []
    cleaned = []
    seen = set()
    for d in raw:
        if not isinstance(d, str):
            continue
        d = d.strip().lower()
        if d and d not in seen:
            seen.add(d)
            cleaned.append(d)
    return cleaned[:3]


def ensure_pcap_root() -> None:
    PCAP_ROOT.mkdir(parents=True, exist_ok=True)
    try:
        shutil.chown(PCAP_ROOT, group="dm")
    except (LookupError, PermissionError):
        pass
    os.chmod(PCAP_ROOT, 0o2775)
    snaps = PCAP_ROOT / "snapshots"
    snaps.mkdir(exist_ok=True)
    try:
        shutil.chown(snaps, group="dm")
    except (LookupError, PermissionError):
        pass
    os.chmod(snaps, 0o2775)
    # Setgid bit on the per-domain dirs is set when we create them.


def domain_dir(domain: str) -> Path:
    return PCAP_ROOT / sanitise(domain)


def prepare_domain_dir(domain: str) -> Path:
    """Create (or reuse) the per-domain dir with setgid+group=dm so child
    PCAPs inherit it. An existing dir is kept: the tcpdump ring rotates its
    own files, remove() handles deliberate cleanup, and wiping here would
    destroy up to 2h of capture on every daemon restart — the shutdown path
    deliberately preserves these dirs."""
    d = domain_dir(domain)
    d.mkdir(parents=True, exist_ok=True)
    try:
        shutil.chown(d, group="dm")
    except (LookupError, PermissionError):
        pass
    # 02750 = setgid + rwxr-x---
    os.chmod(d, 0o2750)
    return d


def cleanup_domain_dir(domain: str) -> None:
    d = domain_dir(domain)
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)


MAX_DOMAIN_DIR_BYTES = int(os.environ.get("BB_PCAP_DIR_CAP_MB", "2048")) * 1024 * 1024


def enforce_dir_cap(domain: str) -> None:
    """The tcpdump ring caps file COUNT (-G/-W) but not per-file size — a
    high-volume domain (busy CDN at 50 Mbps ≈ 1.9 GB per 5-min file) could
    exhaust the NVMe and take ClickHouse down with it. Trim oldest ring
    files (never the newest, which tcpdump is writing) past the cap."""
    d = domain_dir(domain)
    try:
        files = sorted(d.glob("*.pcap"), key=lambda p: p.stat().st_mtime)
        total = sum(f.stat().st_size for f in files)
    except OSError:
        return
    while len(files) > 1 and total > MAX_DOMAIN_DIR_BYTES:
        oldest = files.pop(0)
        try:
            size = oldest.stat().st_size
            oldest.unlink()
        except OSError:
            break
        total -= size
        log.warning("dir cap: removed %s (%.0f MB) from %s ring",
                    oldest.name, size / 1048576, domain)


def resolve_via_getent(domain: str) -> set[str]:
    out: set[str] = set()
    for cmd in (["getent", "ahostsv4", domain], ["getent", "ahostsv6", domain]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if r.returncode != 0:
            continue
        for line in r.stdout.splitlines():
            parts = line.split()
            if not parts:
                continue
            try:
                ip = ipaddress.ip_address(parts[0])
            except ValueError:
                continue
            # Drop IPv4-mapped IPv6 addresses — tcpdump's BPF compiler
            # accepts them but kernel-level traffic is the bare IPv4, so
            # those filter terms never match anything.
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                continue
            out.add(str(ip))
    return out


def resolve_via_dns_log(domain: str) -> set[str]:
    """Scan the live Zeek dns.log for recent A/AAAA answers whose query
    contains `domain` (case-insensitive substring, matching the existing
    flagger semantics)."""
    out: set[str] = set()
    if not ZEEK_DNS_LOG.exists():
        return out
    cutoff = time.time() - DNS_LOG_LOOKBACK
    domain_lc = domain.lower()
    try:
        fields = None
        with ZEEK_DNS_LOG.open("rt", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("#fields\t"):
                    fields = line.split("\t")[1:]
                    continue
                if line.startswith("#") or not line.strip() or not fields:
                    continue
                parts = line.split("\t")
                if len(parts) < len(fields):
                    continue
                row = dict(zip(fields, parts))
                try:
                    ts = float(row.get("ts", "0") or 0)
                except ValueError:
                    continue
                if ts < cutoff:
                    continue
                query = (row.get("query") or "").lower()
                if domain_lc not in query:
                    continue
                ans = row.get("answers", "") or ""
                for token in ans.split(","):
                    token = token.strip()
                    if not token or token == "-":
                        continue
                    try:
                        ipaddress.ip_address(token)
                        out.add(token)
                    except ValueError:
                        pass
    except OSError:
        pass
    return out


def resolve_ips(domain: str) -> set[str]:
    return resolve_via_getent(domain) | resolve_via_dns_log(domain)


def build_bpf(ips: set[str]) -> str:
    if not ips:
        return ""
    return " or ".join(f"host {ip}" for ip in sorted(ips))


def spawn_tcpdump(domain: str, ips: set[str]) -> subprocess.Popen | None:
    bpf = build_bpf(ips)
    if not bpf:
        log.info("no IPs yet for %s — deferring tcpdump start", domain)
        return None
    pcap_dir = domain_dir(domain)
    pattern = str(pcap_dir / "%H%M%S.pcap")
    cmd = [
        "tcpdump",
        "-i", INTERFACE,
        "-n",
        "-U",                  # packet-buffered; flush per packet so the
                               #    webapp sees data without waiting for the
                               #    5-minute rotation.
        "-G", str(ROTATE_SECS),
        "-W", str(RING_FILES),
        "-w", pattern,
        bpf,
    ]
    log.info("starting tcpdump for %s (%d IPs): %s",
             domain, len(ips), " ".join(cmd))
    # stderr to a file, not a PIPE: nothing drains a pipe while tcpdump
    # runs, so 64 KB of chatter would block it and silently stall capture.
    # The reaper reads this file's tail when tcpdump dies.
    with open(pcap_dir / ".tcpdump.err", "wb") as errf:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=errf,
            start_new_session=True,
        )
    return proc


def stop_tcpdump(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGINT)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        log.warning("tcpdump pid %s did not exit on SIGINT — sending SIGTERM",
                    proc.pid)
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.wait(timeout=5)
        except ProcessLookupError:
            pass
        except subprocess.TimeoutExpired:
            # A wedged tcpdump would keep writing into a dir we may be
            # about to delete — invisible disk usage on deleted inodes.
            log.warning("tcpdump pid %s survived SIGTERM — SIGKILL", proc.pid)
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                proc.wait(timeout=5)
            except Exception:
                pass


class Daemon:
    def __init__(self):
        # domain -> {"proc": Popen|None, "ips": set[str]}
        self.captures: dict[str, dict] = {}
        self._stop = False

    def handle_signal(self, signum, _frame):
        log.info("received signal %s — shutting down", signum)
        self._stop = True

    def reconcile(self, desired: list[str]) -> None:
        for domain in list(self.captures):
            if domain not in desired:
                self.remove(domain)
        for domain in desired:
            if domain not in self.captures:
                self.add(domain)

    def add(self, domain: str) -> None:
        log.info("adding watch: %s", domain)
        prepare_domain_dir(domain)
        ips = resolve_ips(domain)
        proc = spawn_tcpdump(domain, ips) if ips else None
        self.captures[domain] = {"proc": proc, "ips": ips}

    def remove(self, domain: str) -> None:
        log.info("removing watch: %s", domain)
        ctx = self.captures.pop(domain, None)
        if ctx and ctx.get("proc"):
            stop_tcpdump(ctx["proc"])
        cleanup_domain_dir(domain)

    def refresh(self) -> None:
        for domain, ctx in list(self.captures.items()):
            # Reap if tcpdump died unexpectedly (we'll respawn).
            if ctx["proc"] is not None and ctx["proc"].poll() is not None:
                rc = ctx["proc"].returncode
                err = b""
                try:
                    err = (domain_dir(domain) / ".tcpdump.err").read_bytes()
                except OSError:
                    pass
                log.warning("tcpdump for %s exited rc=%s — %s",
                            domain, rc, err[-400:].decode(errors="replace"))
                ctx["proc"] = None

            enforce_dir_cap(domain)
            ips_now = resolve_ips(domain)
            new_ips = ips_now - ctx["ips"]
            need_start = ctx["proc"] is None and ips_now
            need_restart = bool(new_ips) and ctx["proc"] is not None
            if need_start:
                ctx["ips"] = ips_now
                ctx["proc"] = spawn_tcpdump(domain, ips_now)
            elif need_restart:
                log.info("widening BPF for %s — +%d IPs", domain, len(new_ips))
                stop_tcpdump(ctx["proc"])
                ctx["ips"] = ctx["ips"] | ips_now
                ctx["proc"] = spawn_tcpdump(domain, ctx["ips"])

    def shutdown_all(self) -> None:
        for domain, ctx in self.captures.items():
            log.info("shutdown: stopping %s", domain)
            if ctx.get("proc"):
                stop_tcpdump(ctx["proc"])
            # Note: do NOT delete pcap dirs on daemon shutdown — service
            # restart should not nuke a user's active capture.
        self.captures.clear()

    def run(self) -> int:
        signal.signal(signal.SIGTERM, self.handle_signal)
        signal.signal(signal.SIGINT, self.handle_signal)
        ensure_pcap_root()
        last_mtime = -1.0
        while not self._stop:
            try:
                mtime = CONFIG_PATH.stat().st_mtime
            except OSError:
                mtime = 0.0
            if mtime != last_mtime:
                desired = load_config()
                log.info("config mtime changed — desired set: %s", desired)
                self.reconcile(desired)
                last_mtime = mtime
            self.refresh()
            time.sleep(POLL_INTERVAL)
        self.shutdown_all()
        return 0


if __name__ == "__main__":
    sys.exit(Daemon().run())
