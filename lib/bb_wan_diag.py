#!/usr/bin/env python3
"""
bb_wan_diag.py — evidence gathering and classification for a WAN outage.

Called by wan-watchdog.sh on every failing check. The shell keeps the control
flow (it is well-tested and carries hard-won safety constraints about never
touching DHCP behind NetworkManager's back); this does the diagnosis, because
appending structured evidence to a JSON file from bash is a losing game.

Why this exists
---------------
The watchdog used to classify an outage on a single bit: did the default
gateway answer ICMP. That cannot tell a router that is *absent* from one that is
*present but not forwarding* — both are silence — so its `isp_upstream` /
`link_fault` split carried no information. Measured on bb0 it got the answer
exactly backwards: the one genuine 4-second link drop (2026-08-29 21:11:46,
carrier down/up plus a DHCP re-transaction) was never classified at all, while
five outages with a demonstrably healthy link, an unchanged lease and a device
that never left `activated` were all reported as "fault in the link/CPE".

The discriminator is ARP. It runs below IP, so a gateway that is on the wire but
blackholing still answers it. Combined with carrier state and lease state that
separates the cases that actually differ in what you would do about them:

    carrier down                  → our link or the CPE. Go look at it.
    gateway silent at L2          → the ISP's edge is gone from the wire —
                                    VRRP with no master, or an access outage.
    gateway answers ARP, not ICMP → edge is present but not handling traffic
                                    for us; control-plane or reconvergence.
    gateway answers both          → the break is beyond the edge, in transit.

Output: one TAB-separated `class<TAB>verdict` line on stdout for the shell to
log, and a per-outage JSON file under EVIDENCE_DIR holding every sample taken
during the outage, so the shape over time is recoverable afterwards.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

EVIDENCE_DIR = Path(os.environ.get("BB_OUTAGE_EVIDENCE",
                                   "/var/lib/beaconbutty/outage-evidence"))

# Classification → the label the UI shows. Keyed the same as bb_outages so the
# two files agree; see feedback on mirrored contracts drifting.
CLASSES = {
    "link_down":       "Physical link down",
    "no_ip":           "WAN had no IP",
    "no_route":        "Local routing fault",
    "gateway_absent":  "ISP gateway off the wire",
    "gateway_silent":  "ISP gateway present, not responding",
    "upstream_transit": "ISP upstream / transit",
    "unknown":         "Cause not established",
}


def _run(cmd, timeout):
    """Run a probe. Returns (ok, stdout). Never raises — a missing binary or a
    hung probe must degrade to 'unknown', not abort the watchdog mid-outage."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode == 0, p.stdout
    except (OSError, subprocess.SubprocessError):
        return False, ""


# ── Individual probes ────────────────────────────────────────────────────────

def probe_carrier(iface):
    """L1 state, straight from sysfs — no subprocess, no timeout, always works.

    carrier_changes is included because it is the only counter that can prove a
    link bounced *between* two probes: a 4-second drop is invisible to a
    5-minutely ping but leaves a permanent mark here.
    """
    out = {"carrier": None, "carrier_changes": None, "operstate": None}
    for key, fname in (("carrier", "carrier"),
                       ("carrier_changes", "carrier_changes"),
                       ("operstate", "operstate")):
        try:
            val = Path(f"/sys/class/net/{iface}/{fname}").read_text().strip()
            out[key] = int(val) if val.isdigit() else val
        except (OSError, ValueError):
            pass
    return out


def probe_gateway_arp(iface, gateway):
    """
    The discriminator: is the gateway on the wire at all?

    ARP is below IP, so this answers even when the router refuses to forward or
    to reply to ICMP. A VRRP virtual address mid-election has no master claiming
    the virtual MAC, so this is exactly the probe that catches a failover.

    Uses arping rather than reading `ip neigh`, because the neighbour cache can
    hold a REACHABLE entry for minutes after the router has gone — a stale
    cache would report the gateway present throughout the outage.
    """
    ok, out = _run(["arping", "-I", iface, "-c", "2", "-w", "4", gateway], 8)
    mac = None
    m = re.search(r"\[([0-9A-Fa-f:]{17})\]", out)
    if m:
        mac = m.group(1).lower()
    return {"reachable": ok, "mac": mac}


def probe_icmp(iface, target):
    ok, _ = _run(["ping", "-I", iface, "-c", "2", "-W", "3", "-q", target], 10)
    return ok


def probe_traceroute(iface, target, max_hops=8):
    """
    How far do packets actually get? Names the last hop that answered, which is
    the difference between 'died at our ISP's edge' and 'died in transit'.

    -n skips DNS (which is likely broken anyway during a WAN outage and would
    otherwise stall every hop), -q 1 sends one probe per hop, -w 1 waits a
    second. Worst case is therefore ~max_hops seconds against a dead path.
    """
    ok, out = _run(["traceroute", "-n", "-i", iface, "-w", "1", "-q", "1",
                    "-m", str(max_hops), target], max_hops + 8)
    hops, last = [], None
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)\s+(\S+)", line)
        if not m:
            continue
        n, addr = int(m.group(1)), m.group(2)
        hops.append({"hop": n, "addr": addr})
        if addr != "*":
            last = {"hop": n, "addr": addr}
    return {"ran": ok or bool(hops), "hops": hops, "last_responding": last,
            "target": target}


def probe_dhcp(iface):
    """
    Lease state, read-only. NEVER renews: invoking a DHCP client behind
    NetworkManager's back wiped /etc/resolv.conf in the 2026-07-01 incident.

    A lease that changed or a device that left `activated` around an outage
    means the session was reset at the ISP's access gear — a different fault,
    and a different conversation with them, than a forwarding break.
    """
    out = {"device_state": None, "lease_expiry": None, "address": None,
           "dhcp_server": None}
    ok, txt = _run(["nmcli", "-t", "-f", "GENERAL.STATE,IP4.ADDRESS,DHCP4.OPTION",
                    "device", "show", iface], 8)
    if not ok:
        return out
    for line in txt.splitlines():
        if line.startswith("GENERAL.STATE:"):
            out["device_state"] = line.split(":", 1)[1].strip()
        elif line.startswith("IP4.ADDRESS"):
            out["address"] = line.split(":", 1)[1].strip()
        elif "dhcp_server_identifier" in line:
            out["dhcp_server"] = line.split("=", 1)[-1].strip()
        elif "= expiry" in line or "expiry =" in line:
            out["lease_expiry"] = line.split("=", 1)[-1].strip()
    return out


def probe_tailscale():
    """
    An independent witness. tailscaled maintains its own connections over the
    same WAN, so its view corroborates ours without sharing our probe path —
    this is how the 2026-08-29 outages were confirmed as ISP-side by hand.
    """
    ok, out = _run(["tailscale", "status", "--json", "--peers=false"], 8)
    if not ok:
        return {"backend_state": None, "online": None}
    try:
        st = json.loads(out)
        return {"backend_state": st.get("BackendState"),
                "online": (st.get("Self") or {}).get("Online")}
    except (json.JSONDecodeError, AttributeError):
        return {"backend_state": None, "online": None}


# ── Classification ───────────────────────────────────────────────────────────

def classify(ev):
    """
    Derive the cause from the evidence, in order of how local the fault is.

    Every branch is grounded in something measured. Where the evidence does not
    separate two causes the class says so rather than picking one — the whole
    point of this rewrite is that an unsupported guess is worse than an honest
    'not established'.
    """
    car = ev.get("carrier", {})
    if car.get("carrier") == 0 or car.get("operstate") == "down":
        return "link_down", (
            f"{ev['iface']} carrier is down — the fault is our link or the CPE, "
            "not the ISP's network")

    if not ev.get("gateway"):
        return "no_route", (
            f"no default route via {ev['iface']} — local routing fault, not the ISP")

    arp = ev.get("gateway_arp") or {}
    gw = ev["gateway"]

    if not arp.get("reachable"):
        return "gateway_absent", (
            f"link is up but ISP gateway {gw} does not answer ARP — the edge "
            "router is off the wire (VRRP with no master, or an access-side outage)")

    if not ev.get("gateway_icmp"):
        return "gateway_silent", (
            f"ISP gateway {gw} answers ARP but not ICMP — the edge is on the "
            "wire but not handling our traffic")

    tr = (ev.get("traceroute") or {}).get("last_responding")
    where = f", last hop to answer was {tr['addr']} at hop {tr['hop']}" if tr else ""
    return "upstream_transit", (
        f"ISP gateway {gw} answers ARP and ICMP — the break is beyond the edge, "
        f"in the ISP's network{where}. A reboot will not help")


# ── Evidence file ────────────────────────────────────────────────────────────

def _evidence_path(outage_start):
    # Colons are legal on ext4 but make the filename painful to handle in shell
    # and in URLs, so flatten them the way the report files already do.
    return EVIDENCE_DIR / (re.sub(r"[:+]", "-", outage_start) + ".json")


def append_sample(outage_start, sample, last_ok_at=None):
    """
    Append this check's evidence to the outage's file, creating it on the first
    failing check. Read-modify-write is safe here because wan-watchdog.service
    is a Type=oneshot with a single instance — systemd will not run two at once.
    """
    path = _evidence_path(outage_start)
    try:
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        try:
            doc = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            doc = {"outage_start": outage_start, "samples": []}
        if last_ok_at and not doc.get("last_ok_at"):
            doc["last_ok_at"] = last_ok_at
        doc["samples"].append(sample)
        doc["class"] = sample.get("class")
        doc["verdict"] = sample.get("verdict")
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc, indent=2))
        os.chmod(tmp, 0o664)
        os.replace(tmp, path)
    except OSError:
        pass  # evidence is a bonus; never let it break the watchdog
    return path


def gather(iface, gateway, full=False, probe_hosts=()):
    ev = {
        "at":      datetime.now().astimezone().isoformat(timespec="seconds"),
        "iface":   iface,
        "gateway": gateway or None,
        "carrier": probe_carrier(iface),
    }
    ev["gateway_arp"]  = probe_gateway_arp(iface, gateway) if gateway else None
    ev["gateway_icmp"] = probe_icmp(iface, gateway) if gateway else False
    ev["external_icmp"] = {h: probe_icmp(iface, h) for h in probe_hosts}
    # The expensive probes run once per outage, on the first failing check. A
    # traceroute on every check would add ~8s to each and tell us the same thing.
    if full:
        ev["traceroute"] = probe_traceroute(iface, next(iter(probe_hosts), "1.1.1.1"))
        ev["dhcp"]       = probe_dhcp(iface)
        ev["tailscale"]  = probe_tailscale()
    cls, verdict = classify(ev)
    ev["class"], ev["verdict"] = cls, verdict
    return ev


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--iface", required=True)
    ap.add_argument("--gateway", default="")
    ap.add_argument("--outage-start", required=True)
    ap.add_argument("--last-ok", default="")
    ap.add_argument("--probe-hosts", default="1.1.1.1 8.8.8.8")
    ap.add_argument("--full", action="store_true",
                    help="also run traceroute/DHCP/tailscale (first check only)")
    ap.add_argument("--json", action="store_true", help="print the sample too")
    a = ap.parse_args(argv)

    ev = gather(a.iface, a.gateway, full=a.full,
                probe_hosts=tuple(a.probe_hosts.split()))
    append_sample(a.outage_start, ev, last_ok_at=a.last_ok or None)
    # The shell reads this: class TAB verdict TAB gateway-ICMP.
    # The third field feeds wan-status.json's existing `gateway_reachable`, so
    # it stays ICMP-based: the dashboard has rendered it as reachable/unreachable
    # for months and the ARP nuance belongs in the verdict text, not in a
    # silently redefined boolean.
    if not ev.get("gateway"):
        icmp = "null"
    else:
        icmp = "true" if ev.get("gateway_icmp") else "false"
    print(f"{ev['class']}\t{ev['verdict']}\t{icmp}")
    if a.json:
        print(json.dumps(ev, indent=2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
