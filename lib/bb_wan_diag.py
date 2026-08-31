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
    gateway silent at L2          → nothing is claiming the gateway address.
    gateway answers ARP, not ICMP → edge is present but not handling traffic
                                    for us; control-plane or reconvergence.
    gateway answers both          → the break is beyond the edge, in transit.

ARP silence, though, is still two causes wearing one face: an edge that is
genuinely gone, and an edge that is up while its virtual address goes unclaimed.
Added 2026-08-31, two witnesses separate them, either alone sufficient:

  * a DHCP lease issued DURING the outage. bb0 saw exactly this on 2026-08-31 —
    a DHCPACK at 09:56:50, four minutes into a total blackout, from a gateway
    that ignored ARP throughout. Equipment that is off the wire cannot serve
    DHCP, so this settles it. Derived from nmcli's expiry minus lease time; the
    client is never invoked (see probe_dhcp).
  * foreign broadcast still arriving on the WAN segment, counted for free by
    the driver. The ISP's access gear beacons every ~5s, so the counter moving
    proves the segment is live independently of anything answering us at IP.

Both are one-way: they may only ever upgrade a verdict. Their absence proves
nothing — renewals are ~52 min apart, and the first check of an outage has no
earlier counter to difference against — so the fallback stays honest and says
the cause was not narrowed rather than guessing.

VRRP advertisements would have been the obvious probe and are NOT usable: the
ISP filters IP protocol 112 from the customer port. Tested 2026-08-31, six
seconds, zero packets. Do not spend the runtime budget retrying it.

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
    "gateway_absent":  "ISP gateway unclaimed (cause not narrowed)",
    "gateway_vip_unclaimed": "ISP gateway address unclaimed (access gear alive)",
    "access_segment_down":   "WAN segment silent (isolated at L2)",
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
    scheduled ping but leaves a permanent mark here.
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
           "dhcp_server": None, "lease_time": None, "lease_issued_epoch": None,
           "lease_issued_at": None}
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
        elif "dhcp_lease_time" in line:
            out["lease_time"] = line.split("=", 1)[-1].strip()
        elif "= expiry" in line or "expiry =" in line:
            out["lease_expiry"] = line.split("=", 1)[-1].strip()

    # When the current lease was handed to us. nmcli exposes the absolute
    # expiry and the lease duration but not the issue time, and the issue time
    # is the whole point: if it falls inside the outage then the ISP's DHCP
    # service answered us mid-blackout, which no amount of ICMP silence can
    # argue with. Derived rather than scraped from the journal so it works
    # under any log retention and needs no extra privilege.
    try:
        out["lease_issued_epoch"] = int(out["lease_expiry"]) - int(out["lease_time"])
        out["lease_issued_at"] = datetime.fromtimestamp(
            out["lease_issued_epoch"]).astimezone().isoformat(timespec="seconds")
    except (TypeError, ValueError):
        pass
    return out


def probe_link_counters(iface):
    """
    Liveness evidence for the WAN segment itself, for free.

    rx_broadcast_frames is the one that matters. bb0's WAN segment carries a
    proprietary L2 broadcast from the ISP's Huawei access gear about every five
    seconds (ethertype 0x9998), so the counter climbs ~12 times a minute for as
    long as that equipment is on the wire — whether or not anything is
    answering us at IP. That makes it an independent witness to the exact
    question ARP silence leaves open: is the ISP's access network still there,
    or have we been isolated?

    Deliberately NOT keyed on that MAC or ethertype. If the ISP swaps the kit
    the beacon changes shape, and a probe pinned to today's fingerprint would
    quietly start reporting "segment dead" forever after — the failure mode
    where a guard degrades to a no-op. Counting all inbound broadcast keeps the
    signal meaningful across a hardware change.

    No capture, no sleep, no root: ethtool -S is a read of driver counters, so
    this adds nothing to the run's time budget.
    """
    out = {"rx_broadcast": None, "rx_packets": None, "tx_packets": None}
    ok, txt = _run(["ethtool", "-S", iface], 8)
    if ok:
        for line in txt.splitlines():
            k, _, v = line.partition(":")
            if k.strip() == "rx_broadcast_frames":
                try:
                    out["rx_broadcast"] = int(v.strip())
                except ValueError:
                    pass
    for key, fname in (("rx_packets", "rx_packets"), ("tx_packets", "tx_packets")):
        try:
            out[key] = int(Path(
                f"/sys/class/net/{iface}/statistics/{fname}").read_text().strip())
        except (OSError, ValueError):
            pass
    return out


def probe_local_health():
    """
    Clear bb0 of suspicion, automatically.

    CLAUDE.md's standing instruction before blaming the ISP is to check
    conntrack/neighbour saturation and the Pi's throttling state. Doing that by
    hand after the fact is worthless — the numbers have recovered by then — so
    sample them while the outage is happening. Cheap reads; no network I/O.
    """
    out = {"conntrack": None, "conntrack_max": None, "throttled": None}
    for key, path in (("conntrack", "/proc/sys/net/netfilter/nf_conntrack_count"),
                      ("conntrack_max", "/proc/sys/net/netfilter/nf_conntrack_max")):
        try:
            out[key] = int(Path(path).read_text().strip())
        except (OSError, ValueError):
            pass
    ok, txt = _run(["vcgencmd", "get_throttled"], 5)
    if ok and "=" in txt:
        out["throttled"] = txt.strip().split("=", 1)[1]
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

def _dhcp_witness(ev, outage_start):
    """
    Did the ISP's DHCP service hand us a lease *during* this outage?

    If it did, the access equipment was up and processing our traffic while the
    gateway address was answering nothing — which forecloses "the edge is off
    the wire" and "the access network is down" in one measurement. This is the
    evidence that caught the 2026-08-31 outages: a DHCPACK at 09:56:50, four
    minutes into a total blackout, on a gateway that had ignored ARP throughout.

    Conservative on purpose: the lease must have been issued at or after the
    recorded outage start, never merely "recently". Absence proves nothing —
    renewals are ~52 minutes apart, so most short outages contain none — so
    this may only ever upgrade a verdict, never downgrade one.
    """
    issued = (ev.get("dhcp") or {}).get("lease_issued_epoch")
    if not issued or not outage_start:
        return None
    try:
        start = datetime.fromisoformat(outage_start).timestamp()
    except (TypeError, ValueError):
        return None
    if issued < start:
        return None
    return (ev.get("dhcp") or {}).get("lease_issued_at") or str(issued)


# A beacon roughly every 5s means a 15s gap with none is a real silence rather
# than a scheduling artefact. Below that the sample says nothing either way.
L2_SILENCE_SECS = 15


def _l2_witness(ev, prev):
    """
    Is foreign L2 traffic still arriving on the WAN segment?

    Differences this sample's broadcast counter against the previous sample's.
    Returns (frames, seconds) or None when it cannot be computed — the first
    failing check of an outage has nothing to diff against, and that is fine:
    the DHCP witness is equally blind on sample one, and every outage bb0 has
    recorded ran long enough to reach sample two.
    """
    if not prev:
        return None
    now_c = (ev.get("link") or {}).get("rx_broadcast")
    was_c = (prev.get("link") or {}).get("rx_broadcast")
    if now_c is None or was_c is None:
        return None
    try:
        secs = (datetime.fromisoformat(ev["at"])
                - datetime.fromisoformat(prev["at"])).total_seconds()
    except (KeyError, TypeError, ValueError):
        return None
    if secs <= 0:
        return None
    # A counter that went backwards means the interface was reset between
    # samples; report nothing rather than a nonsense negative rate.
    if now_c < was_c:
        return None
    return now_c - was_c, secs


def classify(ev, outage_start=None, prev=None):
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
        # ARP silence alone cannot tell an absent edge from a present one whose
        # virtual address nobody is currently claiming. Two independent
        # witnesses can, and either one is enough.
        dhcp_at = _dhcp_witness(ev, outage_start)
        l2 = _l2_witness(ev, prev)

        if dhcp_at:
            return "gateway_vip_unclaimed", (
                f"ISP gateway {gw} does not answer ARP, but the ISP's access "
                f"gear is alive — its DHCP service issued us a lease at "
                f"{dhcp_at}, during this outage. The gateway address is "
                "unclaimed, not the access network down")

        if l2 and l2[0] > 0:
            return "gateway_vip_unclaimed", (
                f"ISP gateway {gw} does not answer ARP, but the ISP's access "
                f"gear is alive — {l2[0]} foreign broadcast frame(s) still "
                f"arrived on {ev['iface']} in the last {int(l2[1])}s. The "
                "gateway address is unclaimed, not the access network down")

        if l2 and l2[0] == 0 and l2[1] >= L2_SILENCE_SECS:
            return "access_segment_down", (
                f"ISP gateway {gw} does not answer ARP and the WAN segment has "
                f"gone silent — no foreign broadcast on {ev['iface']} for "
                f"{int(l2[1])}s. We are isolated at layer 2; this is an "
                "access-side outage, not a routing fault")

        return "gateway_absent", (
            f"link is up but ISP gateway {gw} does not answer ARP — nothing is "
            "claiming the gateway address. No independent witness yet to say "
            "whether the ISP's access gear is still alive")

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


def previous_sample(outage_start):
    """Last sample recorded for this outage, or None on the first failing
    check. Needed before gather() so the L2 counter has something to diff."""
    try:
        doc = json.loads(_evidence_path(outage_start).read_text())
        return (doc.get("samples") or [])[-1]
    except (OSError, json.JSONDecodeError, IndexError, TypeError):
        return None


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


def gather(iface, gateway, full=False, probe_hosts=(), externals_down=False,
           outage_start=None, prev=None):
    ev = {
        "at":      datetime.now().astimezone().isoformat(timespec="seconds"),
        "iface":   iface,
        "gateway": gateway or None,
        "carrier": probe_carrier(iface),
        # Both are local reads — no network, no measurable cost — so they run on
        # every sample rather than once per outage. That matters: the DHCP
        # renewal that disproved "edge off the wire" on 2026-08-31 landed on the
        # fifth check of the outage, not the first, and a first-check-only probe
        # would have missed it in both of that day's outages.
        "link":    probe_link_counters(iface),
        "dhcp":    probe_dhcp(iface),
    }
    ev["gateway_arp"]  = probe_gateway_arp(iface, gateway) if gateway else None
    ev["gateway_icmp"] = probe_icmp(iface, gateway) if gateway else False
    # The watchdog only calls this AFTER every external probe has already
    # failed, so re-pinging them costs ~6s per dead host to learn what the
    # caller already knows — and on a 60s check cadence that duplication is a
    # meaningful slice of the budget the run has to finish inside. Standalone
    # invocations still probe, so the tool stays honest when run by hand.
    if externals_down:
        ev["external_icmp"] = {h: False for h in probe_hosts}
    else:
        ev["external_icmp"] = {h: probe_icmp(iface, h) for h in probe_hosts}
    # The expensive probes run once per outage, on the first failing check. A
    # traceroute on every check would add ~8s to each and tell us the same thing.
    if full:
        ev["traceroute"]   = probe_traceroute(iface, next(iter(probe_hosts), "1.1.1.1"))
        ev["tailscale"]    = probe_tailscale()
        ev["local_health"] = probe_local_health()
    cls, verdict = classify(ev, outage_start=outage_start, prev=prev)
    ev["class"], ev["verdict"] = cls, verdict
    return ev


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--iface", required=True)
    ap.add_argument("--gateway", default="")
    ap.add_argument("--outage-start", required=True)
    ap.add_argument("--last-ok", default="")
    ap.add_argument("--probe-hosts", default="1.1.1.1 8.8.8.8")
    ap.add_argument("--externals-down", action="store_true",
                    help="caller has already established every probe host is "
                         "unreachable; record that instead of re-probing")
    ap.add_argument("--full", action="store_true",
                    help="also run traceroute/DHCP/tailscale (first check only)")
    ap.add_argument("--json", action="store_true", help="print the sample too")
    a = ap.parse_args(argv)

    ev = gather(a.iface, a.gateway, full=a.full,
                probe_hosts=tuple(a.probe_hosts.split()),
                externals_down=a.externals_down,
                outage_start=a.outage_start,
                prev=previous_sample(a.outage_start))
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
