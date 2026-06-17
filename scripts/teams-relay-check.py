#!/usr/bin/env python3
"""
teams-relay-check.py — detect C2 traffic hidden inside Microsoft Teams TURN
relay sessions (DragonForce Backdoor.Turn / "Ghost Calls" pattern).

The attack: malware acquires an anonymous Teams visitor token, allocates a
legitimate Microsoft TURN relay, and tunnels QUIC through it back to the
attacker's real C2. Network-side, the destination IP, SNI, and TLS cert
all belong to Microsoft — destination-based filtering can't catch it.

The detector classifies LAN-source flows as Teams-bound by SNI suffix
match OR destination IP in the Microsoft Teams CIDR set, then evaluates
three signals against per-device baselines:

  1. new-JA4    — JA4 client fingerprint never seen for this device on
                  any Teams-bound flow before (after a 1-day grace seed).
                  A Teams desktop client's JA4 is stable; a Go-based
                  malware's QUIC fingerprint will not match it.

  2. long-flow  — Teams-bound flow held open longer than the configured
                  max_duration_hours threshold (default 2h). Real Teams
                  calls rarely exceed this.

  3. low-bw     — bytes-per-second below the configured min_kbps threshold
                  (default 30 kbps; below typical Teams audio-only).
                  A C2 tunnel ships KB/s; a real call ships hundreds.

Any one signal trips an alert; combinations escalate severity.

Output:
  - One alert per (src_device, dst_ip) finding per Lambda dedup window
  - JSON summary at /var/lib/beaconbutty/reports/teams-relay.json for /health
  - Updates per-device-Teams-JA4 baseline at
    /var/lib/beaconbutty/device-teams-ja4-history.json

Run via beaconbutty-teams-relay-check.timer (every 15 min).
"""

from __future__ import annotations

import gzip
import ipaddress
import json
import os
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import date, datetime
from pathlib import Path

# ── Site-local config ─────────────────────────────────────────────────────────
def _load_local_env(path: str = "/etc/beaconbutty/local.env") -> None:
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

_load_local_env()
LAN_NETS = [ipaddress.ip_network(os.environ.get("BB_LAN_SUBNET", "192.168.50.0/24"))]

# ── Paths ─────────────────────────────────────────────────────────────────────
ZEEK_LOG_DIR    = Path("/var/log/zeek")
CIDR_FILE_LIVE  = Path("/var/lib/beaconbutty/teams-cidrs.json")
CIDR_FILE_SEED  = Path("/home/dm/BeaconButty/config/teams-cidrs.json")
CONFIG_FILE     = Path("/var/lib/beaconbutty/teams-detector-config.json")
HISTORY_FILE    = Path("/var/lib/beaconbutty/device-teams-ja4-history.json")
REPORT_FILE     = Path("/var/lib/beaconbutty/reports/teams-relay.json")
FP_FILE         = Path("/var/lib/beaconbutty/false-positives.conf")
DHCP_LEASES     = Path("/var/lib/misc/dnsmasq.leases")
ALERT_BIN       = Path("/usr/local/bin/beaconbutty-alert.sh")

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_CONFIG = {
    "enabled": True,
    "max_duration_hours":     2.0,
    "min_kbps":               30.0,
    "min_flow_seconds":       300,   # bandwidth signal only on flows ≥ 5 min
    "max_alerts_per_device":  5,     # hard cap per run, regardless of findings
}

# ── Config / CIDR / FP loading ────────────────────────────────────────────────
def load_config() -> dict:
    try:
        cfg = json.loads(CONFIG_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        cfg = {}
    out = dict(DEFAULT_CONFIG)
    out.update({k: v for k, v in cfg.items() if k in DEFAULT_CONFIG})
    # Persist defaults on first read so the webapp can edit them.
    if not CONFIG_FILE.exists():
        write_atomic(CONFIG_FILE, out)
    return out


def load_cidrs() -> dict:
    for p in (CIDR_FILE_LIVE, CIDR_FILE_SEED):
        if p.exists():
            try:
                return json.loads(p.read_text())
            except json.JSONDecodeError:
                continue
    return {"ipv4_cidrs": [], "sni_suffixes": [], "sni_exact": []}


def load_fp_macs() -> set[str]:
    macs: set[str] = set()
    try:
        for line in FP_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if parts and ":" in parts[0] and len(parts[0]) == 17:
                macs.add(parts[0].lower())
    except FileNotFoundError:
        pass
    return macs


def fp_source_ips(fp_macs: set[str]) -> set[str]:
    if not fp_macs or not DHCP_LEASES.exists():
        return set()
    ips: set[str] = set()
    for line in DHCP_LEASES.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1].lower() in fp_macs:
            ips.add(parts[2])
    return ips


def load_history() -> dict:
    try:
        return json.loads(HISTORY_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def write_atomic(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, indent=2, sort_keys=False)
            f.write("\n")
        os.chmod(tmp, 0o644)   # mkstemp default is 0600; webapp runs as 'dm'
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


# ── Zeek log parsing (lifted from ja4-threat-check.py pattern) ────────────────
def iter_zeek_rows(path: Path):
    opener = gzip.open if str(path).endswith(".gz") else open
    fields = None
    try:
        with opener(path, "rt", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("#fields\t"):
                    fields = line.split("\t")[1:]
                elif line.startswith("#") or not line:
                    continue
                elif fields:
                    parts = line.split("\t")
                    if len(parts) >= len(fields):
                        yield dict(zip(fields, parts))
    except OSError:
        return


def log_paths(stem: str, target: date) -> list[Path]:
    paths: list[Path] = []
    day_dir = ZEEK_LOG_DIR / target.strftime("%Y-%m-%d")
    if day_dir.is_dir():
        paths.extend(sorted(day_dir.glob(f"{stem}.*.log.gz")))
        paths.extend(sorted(day_dir.glob(f"{stem}.*.log")))
    cur = ZEEK_LOG_DIR / "current" / f"{stem}.log"
    if cur.exists():
        paths.append(cur)
    return paths


# ── Helpers ───────────────────────────────────────────────────────────────────
def is_lan(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in LAN_NETS)


def build_cidr_check(ipv4_cidrs: list[str]):
    nets = []
    for c in ipv4_cidrs:
        try:
            nets.append(ipaddress.ip_network(c))
        except ValueError:
            continue
    def is_teams_ip(ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in nets)
    return is_teams_ip


def build_sni_check(sni_suffixes: list[str], sni_exact: list[str]):
    suffixes = tuple(s.lower() for s in sni_suffixes)
    exacts   = {s.lower() for s in sni_exact}
    def is_teams_sni(sni: str) -> bool:
        if not sni or sni == "-":
            return False
        s = sni.lower()
        return s in exacts or s.endswith(suffixes)
    return is_teams_sni


def f(row: dict, key: str) -> str:
    v = row.get(key, "")
    return v if v not in ("-", "(empty)") else ""


def parse_float(s: str) -> float:
    try:
        return float(s)
    except (TypeError, ValueError):
        return 0.0


# ── Detector core ─────────────────────────────────────────────────────────────
def collect_today_flows(is_teams_ip, is_teams_sni, fp_ips: set[str]) -> dict:
    """Return {(src, dst, dst_port): {duration, bytes, ja4_seen, via}} for
    each Teams-bound flow originating on the LAN today.

    The conn.log row carries duration + ip_bytes. The ssl.log row carries
    JA4 + SNI. We join on (orig, orig_port, resp, resp_port) when SNI says
    Teams, OR fall back to dst-IP-in-CIDR matching from conn.log alone for
    QUIC/UDP-3478 flows that don't appear in ssl.log."""
    today = date.today()

    # Pass 1 — ssl.log: collect SNI-classified Teams flows + their JA4
    ssl_keys: dict[tuple, dict] = {}
    for p in log_paths("ssl", today):
        for row in iter_zeek_rows(p):
            sni = f(row, "server_name")
            dst = f(row, "id.resp_h")
            if not (is_teams_sni(sni) or is_teams_ip(dst)):
                continue
            src = f(row, "id.orig_h")
            if not is_lan(src) or src in fp_ips:
                continue
            key = (src, dst, f(row, "id.resp_p"))
            slot = ssl_keys.setdefault(key, {"ja4s": set(), "snis": set(), "via": "sni"})
            ja4 = f(row, "ja4")
            if ja4:
                slot["ja4s"].add(ja4)
            if sni:
                slot["snis"].add(sni)

    # Pass 2 — conn.log: pick up duration + bytes for matching flows AND
    # discover Teams-CIDR flows that never appeared in ssl.log (UDP/3478,
    # QUIC with encrypted SNI).
    #
    # Key by (src, dst, dst_port, proto) — TCP/443 and UDP/443 to the same
    # Teams IP are *different* flows (TLS signalling vs media/TURN) and must
    # not be conflated when summing duration and bytes.
    flows: dict[tuple, dict] = {}
    for p in log_paths("conn", today):
        for row in iter_zeek_rows(p):
            src  = f(row, "id.orig_h")
            dst  = f(row, "id.resp_h")
            dstp = f(row, "id.resp_p")
            prot = (f(row, "proto") or "").lower()
            if not is_lan(src) or src in fp_ips:
                continue
            ssl_key = (src, dst, dstp)           # ssl.log has no proto column
            key     = (src, dst, dstp, prot)
            ssl_hit  = ssl_key in ssl_keys
            cidr_hit = is_teams_ip(dst)
            if not (ssl_hit or cidr_hit):
                continue

            duration = parse_float(f(row, "duration"))
            ip_bytes = parse_float(f(row, "orig_ip_bytes")) + parse_float(f(row, "resp_ip_bytes"))

            slot = flows.setdefault(key, {
                "src": src, "dst": dst, "dst_port": dstp,
                "duration_sec": 0.0, "ip_bytes": 0.0,
                "ja4s": set(), "snis": set(),
                "via": "sni" if ssl_hit else "cidr",
                "proto": prot,
            })
            # A long flow can be split across multiple conn.log rows (rotation,
            # half-closed reconnects). Sum durations + bytes so we measure the
            # device's total Teams-bound footprint for this dst+proto.
            slot["duration_sec"] += duration
            slot["ip_bytes"]     += ip_bytes
            # JA4s only come from TLS (TCP) rows in ssl.log — attach them to
            # the TCP flow only; UDP/QUIC flows don't carry JA4 in this build.
            if ssl_hit and prot == "tcp":
                slot["ja4s"] |= ssl_keys[ssl_key]["ja4s"]
                slot["snis"] |= ssl_keys[ssl_key]["snis"]

    return flows


def evaluate(flows: dict, history: dict, cfg: dict) -> tuple[list[dict], dict]:
    """Apply the three signals. Returns (findings, updated_history).
    Findings are stable per (src, dst, dst_port) for Lambda dedup."""
    max_dur_sec = cfg["max_duration_hours"] * 3600.0
    min_bps     = cfg["min_kbps"] * 1000.0 / 8.0      # kbps → bytes per sec
    min_flow    = cfg["min_flow_seconds"]
    findings: list[dict] = []

    # Track JA4s we observed today by device for history update.
    today_by_device: dict[str, set[str]] = defaultdict(set)

    for key, v in flows.items():
        src, dst, dst_port = v["src"], v["dst"], v["dst_port"]
        ja4s   = v["ja4s"]
        durs   = v["duration_sec"]
        bytesv = v["ip_bytes"]
        proto  = (v.get("proto") or "").lower()
        device_hist = history.get(src, {})
        known_ja4s = set(device_hist.get("teams_ja4s", []))
        seeded     = bool(device_hist.get("seeded"))
        first_seen = device_hist.get("first_seen") or date.today().isoformat()

        for ja4 in ja4s:
            today_by_device[src].add(ja4)

        # Day-1 is seed-only across ALL signals: the detector records today's
        # flows into the per-device baseline but stays silent. From day 2+ the
        # intrinsic signals (long-flow / low-bw) fire normally; the new-JA4
        # signal additionally compares against the prior-days JA4 set.
        if not seeded:
            continue

        signals = []

        # 1) New JA4 — fires if a TLS/QUIC Teams flow used a JA4 the device
        #    has never used on Teams traffic before.
        new_ja4s = [j for j in ja4s if j and j not in known_ja4s]
        if new_ja4s:
            signals.append("new-JA4")

        # 2) Long flow — duration > threshold.
        if durs > max_dur_sec:
            signals.append("long-flow")

        # 3) Low bandwidth — UDP-only (TURN media / QUIC over UDP/443), flows
        #    lasting at least min_flow seconds. TLS-on-TCP/443 setup flows are
        #    legitimately short and not meaningful for this signal.
        if proto == "udp" and durs >= min_flow:
            bps = bytesv / max(durs, 1.0)
            if bps < min_bps:
                signals.append("low-bw")

        if not signals:
            continue

        # Severity: 2 signals = medium, 3 signals = high. (Single-signal
        # findings stay in the report for hunting but are gated out of
        # the alert path; see main() for the alert gate.)
        severity = "high" if len(signals) >= 3 else ("medium" if len(signals) >= 2 else "low")
        findings.append({
            "src":         src,
            "dst":         dst,
            "dst_port":    dst_port,
            "signals":     sorted(signals),
            "severity":    severity,
            "duration_h":  round(durs / 3600.0, 2),
            "ip_kbytes":   round(bytesv / 1024.0, 1),
            "kbps":        round(bytesv * 8 / 1000.0 / max(durs, 1.0), 2),
            "ja4s":        sorted(ja4s),
            "snis":        sorted(v["snis"]),
            "via":         v["via"],
            "proto":       v["proto"],
            "new_ja4s":    sorted(new_ja4s) if seeded else [],
            "first_seen":  first_seen,
        })

    # Update history: union today's JA4s into per-device baseline; mark seeded.
    today_iso = date.today().isoformat()
    updated_history = dict(history)
    for src, ja4_set in today_by_device.items():
        entry = dict(updated_history.get(src, {}))
        prior = set(entry.get("teams_ja4s", []))
        entry["teams_ja4s"] = sorted(prior | ja4_set)
        entry["last_seen"]  = today_iso
        entry.setdefault("first_seen", today_iso)
        # First run records but doesn't fire; mark seeded so next run will.
        entry["seeded"]     = entry.get("seeded", False) or entry["first_seen"] < today_iso
        updated_history[src] = entry

    return findings, updated_history


def fire_alert(finding: dict) -> None:
    if not ALERT_BIN.exists():
        return
    signals = "+".join(finding["signals"])
    detail  = (f"Teams relay anomaly on {finding['dst']}:{finding['dst_port']}/{finding['proto']}: "
               f"{signals} (via {finding['via']})")
    subprocess.run(
        [str(ALERT_BIN), "teams_relay_anomaly", finding["severity"],
         finding["src"], detail],
        check=False,
    )


def main() -> int:
    cfg = load_config()
    if not cfg["enabled"]:
        # Still write a stub report so the webapp can show "disabled".
        write_atomic(REPORT_FILE, {
            "generated": datetime.now().isoformat(timespec="seconds"),
            "enabled":   False,
            "findings":  [],
        })
        return 0

    cidrs    = load_cidrs()
    is_teams_ip  = build_cidr_check(cidrs.get("ipv4_cidrs", []))
    is_teams_sni = build_sni_check(cidrs.get("sni_suffixes", []), cidrs.get("sni_exact", []))
    fp_ips   = fp_source_ips(load_fp_macs())
    history  = load_history()

    flows                 = collect_today_flows(is_teams_ip, is_teams_sni, fp_ips)
    findings, new_history = evaluate(flows, history, cfg)

    # Alert gate: alert ONLY when 'new-JA4' is present AND at least one
    # other signal corroborates. Rationale:
    #   - new-JA4 alone: too noisy on day-2 (baseline only seeded yesterday)
    #     and after Teams app updates (legitimate JA4 changes).
    #   - long-flow / low-bw alone or together: Teams idle behaviour
    #     (presence WebSockets, TURN keepalives) trips these routinely
    #     on real LAN traffic.
    #   - new-JA4 + long-flow OR new-JA4 + low-bw: device using an
    #     unfamiliar TLS stack on a Teams flow that's also structurally
    #     anomalous (too long, or too low-bw for media). This is the
    #     DragonForce-pattern shape.
    # Single-signal and non-new-JA4 multi-signal findings still land in
    # the report JSON for hunting via the /health page.
    per_device_cap = int(cfg.get("max_alerts_per_device", 5))
    fired_by_device: dict[str, int] = defaultdict(int)
    for f_ in findings:
        src   = f_["src"]
        sigs  = f_["signals"]
        alerts = ("new-JA4" in sigs) and (len(sigs) >= 2)
        if not alerts:
            reason = "single-signal" if len(sigs) < 2 else "no new-JA4"
            print(f"finding (dashboard-only, {reason}): {src} -> {f_['dst']}:{f_['dst_port']}  "
                  f"{','.join(sigs)}")
            continue
        if fired_by_device[src] >= per_device_cap:
            print(f"finding (over per-device cap): {src} -> {f_['dst']}:{f_['dst_port']}  "
                  f"{','.join(sigs)}  sev={f_['severity']}  [SUPPRESSED]")
            continue
        print(f"finding: {src} -> {f_['dst']}:{f_['dst_port']}  "
              f"{','.join(sigs)}  sev={f_['severity']}")
        fire_alert(f_)
        fired_by_device[src] += 1

    write_atomic(HISTORY_FILE, new_history)
    write_atomic(REPORT_FILE, {
        "generated":     datetime.now().isoformat(timespec="seconds"),
        "enabled":       True,
        "config":        cfg,
        "cidr_version":  cidrs.get("version"),
        "cidr_source":   cidrs.get("source"),
        "flows_scanned": len(flows),
        "findings":      findings,
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
