#!/usr/bin/env python3
"""
slow-cadence.py — multi-day low-rate beacon detector.

RITA only scores within a single day. A C2 implant on a long sleep cycle
(once per day, once per N hours) generates too few connections per day to
clear RITA's `unique_connection_threshold`, so it stays invisible.

This script complements RITA by looking ACROSS the last 14 daily ClickHouse
databases (beaconbutty_YYYYMMDD) for (src, dst, dst_port) tuples that:

  • appear on at least MIN_DAYS_SEEN distinct days
  • average no more than MAX_CONNS_PER_DAY connections per active day
  • cluster at a consistent hour-of-day (low jitter)

The output is JSON for the dashboard panel; nothing here writes to the
existing RITA tables.

Output: /var/lib/beaconbutty/reports/slow-cadence.json
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import json
import os
import statistics
import subprocess
import sys
from collections import Counter
from pathlib import Path

# Shared IP→hostname enrichment ladder (also used by webapp/app.py and
# summarize.sh). Repo checkout first so a dev run picks up local edits, then
# the deployed copy installed by scripts/05_configure.sh.
for _p in (str(Path(__file__).resolve().parent.parent / "lib"),
           "/usr/local/lib/beaconbutty"):
    if _p not in sys.path:
        sys.path.append(_p)
import bb_enrich
import bb_fp

CH_BIN = "/usr/bin/clickhouse-client"
WINDOW_DAYS = 14
MIN_DAYS_SEEN = 5
MAX_CONNS_PER_DAY = 6
MIN_HOUR_CONSISTENCY = 0.8  # ≥80% of conns within ±1h of modal hour
MAX_TS_PER_PAIR = 500       # cap groupArray to bound memory

OUTPUT = "/var/lib/beaconbutty/reports/slow-cadence.json"
KNOWN_PATH = "/var/lib/beaconbutty/slow-cadence-known.json"
GATE_STATS = "/var/lib/beaconbutty/reports/alert-gate-stats.json"
FP_PATH = "/var/lib/beaconbutty/false-positives.conf"
ALERT_BIN = "/usr/local/bin/beaconbutty-alert.sh"

# Substring tokens (case-insensitive) for the major cloud / CDN / SaaS
# providers. C2 traffic almost never originates from these ASNs, while
# legitimate periodic egress overwhelmingly does. Used as one half of the
# Slack-alert gate — the other half is "only one LAN device talks to this
# dst". A candidate must be BOTH lonely AND non-hyperscaler to page.
HYPERSCALER_TOKENS = (
    "amazon", "cloudflare", "google", "microsoft", "apple", "akamai",
    "fastly", "netflix", "facebook", "meta platforms", "meta-llc",
    "twitter", "github", "salesforce", "adobe", "oracle",
    "linode", "digitalocean", "stackpath", "bunny.net", "cdn77",
    "keycdn", "alibaba", "tencent", "byteplus", "bytedance",
    "ovh", "hetzner", "leaseweb", "limelight", "edgio", "cloudfront",
    "verizon", "at&t", "comcast", "level 3", "lumen", "centurylink",
    "incapsula", "imperva", "sucuri", "stackpath",
)


def is_hyperscaler(org: str) -> bool:
    """True if the ASN org name contains a known hyperscaler / major-CDN
    token. Substring matching keeps the list short and copes with MaxMind's
    inconsistent capitalisation/punctuation across ASN entries."""
    if not org:
        return False
    low = org.lower()
    return any(t in low for t in HYPERSCALER_TOKENS)


_GEOIP_ASN  = None
_GEOIP_CITY = None
try:
    import geoip2.database as _g2db
    _GEOIP_ASN  = _g2db.Reader('/var/lib/GeoIP/GeoLite2-ASN.mmdb')
    _GEOIP_CITY = _g2db.Reader('/var/lib/GeoIP/GeoLite2-City.mmdb')
except Exception:
    pass


def geoip_lookup(ip: str) -> tuple[str, str]:
    """Return (asn_org, country_code) for an IP, both possibly empty."""
    org = cc = ""
    try:
        if _GEOIP_ASN:
            org = _GEOIP_ASN.asn(ip).autonomous_system_organization or ""
    except Exception:
        pass
    try:
        if _GEOIP_CITY:
            cc = _GEOIP_CITY.city(ip).country.iso_code or ""
    except Exception:
        pass
    return org, cc


def ch(query: str) -> str:
    """Pipe the query in via stdin — the SNI resolver builds an IN-list that
    can exceed ARG_MAX when many destinations are flagged."""
    return subprocess.run(
        [CH_BIN], input=query, capture_output=True,
        text=True, timeout=300, check=True,
    ).stdout


def recent_dbs() -> list[str]:
    out = ch("SHOW DATABASES")
    dbs = sorted(d for d in out.splitlines() if d.startswith("beaconbutty_2"))
    return dbs[-WINDOW_DAYS:]


def fp_domains() -> list[str]:
    try:
        with open(FP_PATH) as f:
            return list(json.load(f).get("domains", {}).keys())
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def fp_protocols() -> list[str]:
    """Protocol FPs — registered per service component, e.g. "3478:udp".

    Without this the registry's protocol entries had no effect on slow-cadence
    at all: STUN/NTP-style keepalives have no SNI and their HTTP Host (when
    there is one) is the bare dst IP, so neither the domain nor the org path
    can reach them.

    MIRROR: matching lives in fp_service_match() here, in
    slow-cadence-digest.py, and in webapp/app.py `_fp_service_match` —
    change all three together."""
    try:
        with open(FP_PATH) as f:
            return list(json.load(f).get("protocols", {}).keys())
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def fp_service_match(services: list[str], pats: list[str]) -> bool:
    """True when EVERY observed service component is covered by a protocol FP.

    A protocol FP asserts a protocol is boring, not that a destination is, so
    one FP'd component must not suppress a row that also carries un-FP'd
    traffic — see webapp/app.py `_fp_service_match` for the Tailscale DERP
    case that motivated this.

    Each element of `services` is already one "port:proto:service" component
    (groupUniqArray builds them individually), so unlike the webapp there is
    nothing to split here: a comma inside an element belongs to Zeek's own
    service list, e.g. "443:udp:quic,ssl". A pattern matches exactly or as a
    prefix at a ':' boundary, so "3478:udp" covers "3478:udp:stun"."""
    if not services or not pats:
        return False
    for comp in services:
        comp = (comp or "").strip()
        if not comp:
            continue
        if not any(comp == pat or comp.startswith(pat + ":") for pat in pats):
            return False
    return True


def fp_orgs() -> list[tuple[str, set[str] | None]]:
    """Org FPs — fnmatch against the GeoIP ASN owner. Implementation shared
    with the webapp, the digest and summarize.sh via lib/bb_fp.py."""
    return bb_fp.org_entries(FP_PATH)


def fp_org_match(org: str, src_mac: str, entries) -> bool:
    """True if this ASN owner is FP'd, either LAN-wide or for this device."""
    return bb_fp.org_match(org, src_mac, entries)


def ip_to_mac_map() -> dict[str, str]:
    """LAN IP → MAC, from current dnsmasq leases plus the rolling asset
    history. History matters here for the same reason it does in
    fp_source_ips(): the 14-day window covers IPs a device no longer holds."""
    mapping: dict[str, str] = {}
    try:
        with open("/var/lib/beaconbutty/assets-history.json") as f:
            for hist_ip, info in json.load(f).items():
                mac = (info.get("mac") or "").lower()
                if mac:
                    mapping[hist_ip] = mac
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    # Live leases win over history for an IP that has since been reassigned.
    try:
        with open("/var/lib/misc/dnsmasq.leases") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    mapping[parts[2]] = parts[1].lower()
    except FileNotFoundError:
        pass
    return mapping


def fp_source_ips() -> set[str]:
    """LAN source IPs whose MAC appears in the FP devices list — used to
    drop entire devices from slow-cadence output."""
    try:
        with open(FP_PATH) as f:
            fp_macs = {m.lower() for m in json.load(f).get("devices", {}).keys()}
    except (FileNotFoundError, json.JSONDecodeError):
        return set()
    if not fp_macs:
        return set()

    ips: set[str] = set()
    try:
        with open("/var/lib/misc/dnsmasq.leases") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[1].lower() in fp_macs:
                    ips.add(parts[2])
    except FileNotFoundError:
        pass
    # Also cover IPs the MAC held earlier in the window — current leases
    # alone lose an FP'd device that renumbered or went offline.
    try:
        with open("/var/lib/beaconbutty/assets-history.json") as f:
            for hist_ip, info in json.load(f).items():
                if (info.get("mac") or "").lower() in fp_macs:
                    ips.add(hist_ip)
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return ips


def fp_match(host: str, patterns: list[str]) -> bool:
    if not host:
        return False
    for pat in patterns:
        if fnmatch.fnmatch(host, pat):
            return True
        if pat.startswith("*.") and host == pat[2:]:
            return True
    return False


def fetch_pairs(dbs: list[str]) -> list[dict]:
    """Single-pass cross-DB aggregation. We rely on the dst_local=false +
    low-rate prefilter to keep groupArray sizes bounded; cap at MAX_TS_PER_PAIR
    as belt-and-braces."""
    inner = " UNION ALL ".join(
        f"""SELECT src, dst, dst_port, ts, proto, service,
                   src_ip_bytes, dst_ip_bytes FROM {db}.conn
            WHERE dst_local = false AND src_local = true
              AND proto IN ('tcp', 'udp')
              AND service NOT IN ('dns', 'ntp')"""
        for db in dbs
    )
    # `services` is the RITA-style "port:proto:service" component set for the
    # group, carried through onto each candidate so the digest and the webapp
    # can re-apply protocol FPs without going back to ClickHouse.
    sql = f"""
    SELECT
        IPv6NumToString(src)        AS src,
        IPv6NumToString(dst)        AS dst,
        dst_port                    AS dst_port,
        count()                     AS total_conns,
        uniqExact(toDate(ts))       AS days_seen,
        -- ip_bytes, not orig/resp_bytes: the latter inflate on sequence wrap.
        -- Feeds the DERP netcheck gate, which separates probe from relay by
        -- bytes-per-connection (see lib/bb_fp.is_derp_probe).
        sum(src_ip_bytes + dst_ip_bytes) AS total_bytes,
        groupUniqArray(concat(toString(dst_port), ':',
                              toString(proto), ':',
                              toString(service)))      AS services,
        groupArray({MAX_TS_PER_PAIR})(toUInt32(ts))    AS ts_list,
        groupArray({MAX_TS_PER_PAIR})(toUInt8(toHour(ts))) AS hr_list
    FROM ({inner})
    GROUP BY src, dst, dst_port
    HAVING days_seen >= {MIN_DAYS_SEEN}
       AND total_conns <= days_seen * {MAX_CONNS_PER_DAY}
    FORMAT JSONEachRow
    """
    out = ch(sql)
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def resolve_names(dst_ips: set[str]) -> dict[str, dict]:
    """Best-effort dst IP → hostname, via the shared enrichment ladder.

    This used to be a local SNI-only lookup, which left every SNI-less
    destination (STUN relays, bare-IP HTTP, QUIC-only services) permanently
    anonymous on /beacons/slow — and therefore impossible to match a domain FP
    against. bb_enrich adds DNS history, cert Subject/SAN, QUIC SNI, the cached
    Shodan hostname and reverse DNS behind the same call.

    Keys are the v4-stripped form the caller uses, not RITA's ::ffff: form.
    """
    if not dst_ips:
        return {}
    stripped = {ip.replace("::ffff:", "") for ip in dst_ips}
    try:
        return bb_enrich.enrich(stripped, days=WINDOW_DAYS, with_intel=False)
    except Exception as e:                       # never fail the whole run
        print(f"name resolution failed: {e}", file=sys.stderr)
        return {}


def resolve_http(dbs: list[str], dst_ips: set[str]) -> dict[str, dict]:
    """Best-effort dst IP → HTTP metadata. Same scan-then-filter pattern as
    the old resolve_sni; the http table is small enough to scan once across the
    window. Per dst we surface:

      - host:        most-recent Host header (argMax by ts) — for display
      - hosts:       list of distinct Host headers (for FP matching, since a
                     shared CDN IP can serve many domains and any one being
                     FP'd is enough to call the dst benign)
      - useragent:   most-common non-empty UA, truncated
      - uri_sample:  most-common URI prefix (first 60 chars)
      - method_mix:  e.g. "GET 95% · POST 5%"
    """
    if not dst_ips:
        return {}
    union = " UNION ALL ".join(
        f"""SELECT IPv6NumToString(dst) AS dst_str,
                   host, useragent,
                   substring(uri, 1, 60) AS uri_pfx,
                   method, ts
            FROM {db}.http
            WHERE host != ''"""
        for db in dbs
    )
    sql = f"""
    SELECT dst_str AS dst,
           argMax(host, ts)                       AS host_recent,
           groupUniqArray(host)                   AS hosts,
           topKIf(1)(useragent, useragent != '')  AS ua_arr,
           topK(1)(uri_pfx)                       AS uri_arr,
           countIf(method = 'GET')                AS get_n,
           countIf(method = 'POST')               AS post_n,
           countIf(method NOT IN ('GET', 'POST')) AS other_n,
           count()                                AS total_n
    FROM ({union})
    GROUP BY dst_str
    FORMAT JSONEachRow
    """
    try:
        out = ch(sql)
    except subprocess.CalledProcessError as e:
        print(f"HTTP resolution failed: {e.stderr[:500]}", file=sys.stderr)
        return {}
    http_map: dict[str, dict] = {}
    for line in out.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row["dst"] not in dst_ips:
            continue
        total = row["total_n"] or 1
        parts = []
        if row["get_n"]:
            parts.append(f"GET {row['get_n'] * 100 // total}%")
        if row["post_n"]:
            parts.append(f"POST {row['post_n'] * 100 // total}%")
        if row["other_n"]:
            parts.append(f"other {row['other_n'] * 100 // total}%")
        ua_arr = row.get("ua_arr") or []
        uri_arr = row.get("uri_arr") or []
        http_map[row["dst"]] = {
            "host":        row["host_recent"],
            "hosts":       row.get("hosts") or [],
            "useragent":   (ua_arr[0] if ua_arr else "")[:120],
            "uri_sample":  uri_arr[0] if uri_arr else "",
            "method_mix":  " · ".join(parts),
        }
    return http_map


def count_lan_talkers(dbs: list[str], dst_set: set[str]) -> dict:
    """For each (dst, dst_port), count distinct LAN srcs that touched it
    across the window. Filtering by dst is left to Python — embedding the
    IN-list 14 times overruns max_query_size, and the full aggregation is
    bounded by the number of distinct (dst, dst_port) pairs (~few thousand)
    rather than raw row count, so it's cheap. The intuition: shared SaaS
    endpoints are reached by many LAN devices; a C2 implant is on exactly
    one. A "lonely" pair (talkers == 1) is one of the two ingredients of
    the alert gate."""
    if not dst_set:
        return {}
    union = " UNION ALL ".join(
        f"""SELECT IPv6NumToString(dst) AS dst_str, dst_port, src
            FROM {db}.conn
            WHERE dst_local = false AND src_local = true
              AND proto IN ('tcp', 'udp')
              AND service NOT IN ('dns', 'ntp')"""
        for db in dbs
    )
    sql = f"""
    SELECT dst_str AS dst, dst_port, uniqExact(src) AS talkers
    FROM ({union})
    GROUP BY dst_str, dst_port
    FORMAT JSONEachRow
    """
    try:
        out = ch(sql)
    except subprocess.CalledProcessError as e:
        print(f"lan_talkers query failed: {e.stderr[:500]}", file=sys.stderr)
        return {}
    result: dict = {}
    for line in out.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row["dst"] in dst_set:
            result[(row["dst"], int(row["dst_port"]))] = row["talkers"]
    return result


def hour_consistency(hours: list[int]) -> tuple[float, int]:
    """Fraction of timestamps within ±1h (mod 24) of the modal hour."""
    if not hours:
        return 0.0, 0
    bins = [0] * 24
    for h in hours:
        bins[h] += 1
    mode = bins.index(max(bins))
    near = sum(bins[(mode + d) % 24] for d in (-1, 0, 1))
    return near / len(hours), mode


def interval_cv(timestamps: list[int]) -> float | None:
    """Coefficient of variation of inter-arrival intervals, in seconds."""
    if len(timestamps) < 3:
        return None
    ts = sorted(timestamps)
    diffs = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
    mean = statistics.mean(diffs)
    if mean == 0:
        return None
    return statistics.pstdev(diffs) / mean


def write_gate_stats(fired: int, gated_hyper: int, gated_shared: int) -> None:
    """Atomically update the slow_cadence subkey of the shared gate-stats
    file. Read by /health to surface "the gate is doing useful work"."""
    try:
        with open(GATE_STATS) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}
    data["slow_cadence"] = {
        "ts":    dt.datetime.now(dt.timezone.utc)
                   .replace(microsecond=0).isoformat(),
        "fired": fired,
        "gated": {"hyperscaler": gated_hyper, "shared_lan": gated_shared},
    }
    tmp = GATE_STATS + ".tmp"
    os.makedirs(os.path.dirname(GATE_STATS), exist_ok=True)
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, GATE_STATS)


def main() -> int:
    dbs = recent_dbs()
    if len(dbs) < MIN_DAYS_SEEN:
        print(f"only {len(dbs)} daily DBs available, need {MIN_DAYS_SEEN}",
              file=sys.stderr)
        return 1

    pairs = fetch_pairs(dbs)
    dst_ips = {p["dst"] for p in pairs}
    name_map = resolve_names(dst_ips)
    http_map = resolve_http(dbs, dst_ips)
    talkers_map = count_lan_talkers(dbs, dst_ips)
    fp_pats = fp_domains()
    fp_srcs = fp_source_ips()
    org_pats = fp_orgs()
    proto_pats = fp_protocols()
    derp_hosts = bb_fp.derp_hosts()
    ip_mac = ip_to_mac_map()

    candidates = []
    for r in pairs:
        cons, modal_hr = hour_consistency(r["hr_list"])
        if cons < MIN_HOUR_CONSISTENCY:
            continue
        dst_ip = r["dst"].replace("::ffff:", "")
        src_ip = r["src"].replace("::ffff:", "")
        http_info = http_map.get(r["dst"], {})
        name_info = name_map.get(dst_ip, {})
        # bb_enrich never returns an organisation in `name`, so this is a
        # hostname or empty; the ASN owner arrives separately as `org_hint`.
        sni = name_info.get("name", "")
        # FP exclusion paths: SNI matches, ANY HTTP Host header for this dst
        # matches (shared CDN IPs serve many hosts — one FP'd is enough),
        # the dst IP literal matches, or the source LAN device is FP'd.
        if fp_match(sni, fp_pats) or fp_match(dst_ip, fp_pats):
            continue
        if any(fp_match(h, fp_pats) for h in http_info.get("hosts", [])):
            continue
        if src_ip in fp_srcs:
            continue
        # Protocol FP — the only handle on NAT-traversal keepalives (STUN on
        # 3478, etc), which carry no SNI and whose HTTP Host is the dst IP.
        # Deliberately port+proto scoped rather than host scoped: a relay's
        # bulk traffic on 443 stays visible.
        if fp_service_match(r.get("services", []), proto_pats):
            continue
        # DERP netcheck probe. The protocol FP above cannot reach it: netcheck
        # also probes 443, and a row bundling 443 with 3478 is (rightly) not
        # fully covered. Volume-gated, so a relay actually carrying WireGuard
        # payload still surfaces. See lib/bb_fp.py.
        if bb_fp.is_derp_probe(dst_ip, r.get("services", []),
                               r["total_conns"], r.get("total_bytes", 0),
                               hosts=derp_hosts):
            continue

        dst_org, dst_cc = geoip_lookup(dst_ip)
        # Org FPs may be scoped to specific source devices — "Chinese CDN
        # traffic from Xin's phone is baseline" must not also suppress the
        # same ASN reaching a server or an IoT device.
        if fp_org_match(dst_org, ip_mac.get(src_ip, ""), org_pats):
            continue
        hyper = is_hyperscaler(dst_org)
        talkers = talkers_map.get((r["dst"], r["dst_port"]), 1)
        # Slack-alert gate: only page when a single LAN device is talking
        # to a non-hyperscaler dst. Everything else is dashboard-only.
        eligible = talkers == 1 and not hyper

        candidates.append({
            "src": src_ip,
            "dst": dst_ip,
            "dst_port": r["dst_port"],
            "services": r.get("services", []),
            "sni": sni,
            # Provenance for the UI: "SNI" is an observed handshake, "shodan"
            # or "PTR" is inference. Worth showing — an operator FP'ing a
            # destination should know how confident the name is.
            "dst_name_source": name_info.get("source", ""),
            # ASN owner's domain — display only, never FP-matched. Set only
            # when nothing actually named the host.
            "dst_name_weak":   name_info.get("org_hint", ""),
            "http_host":       http_info.get("host", ""),
            "http_hosts":      http_info.get("hosts", []),
            "http_useragent":  http_info.get("useragent", ""),
            "http_uri_sample": http_info.get("uri_sample", ""),
            "http_method_mix": http_info.get("method_mix", ""),
            "days_seen": r["days_seen"],
            "total_conns": r["total_conns"],
            # Carried so the digest and the webapp can re-apply the DERP
            # netcheck gate without going back to ClickHouse. Candidates
            # written before this existed have no key; both consumers treat
            # that as "no volume data" and fall through rather than guessing.
            "total_bytes": r.get("total_bytes", 0),
            "conns_per_active_day": round(
                r["total_conns"] / r["days_seen"], 2
            ),
            "modal_hour_utc": modal_hr,
            "hour_consistency": round(cons, 3),
            "interval_cv": (
                round(c, 3) if (c := interval_cv(r["ts_list"])) is not None
                else None
            ),
            # Raw MaxMind string — org FPs, is_hyperscaler() and the
            # "*<first word>*" FP prefill all key on this. Never alias it.
            "dst_org":        dst_org,
            # Friendly form for rendering only ("31173 Services AB" is Mullvad).
            "dst_org_label":  bb_enrich.org_label(dst_org),
            "dst_cc":         dst_cc,
            "is_hyperscaler": hyper,
            "lan_talkers":    talkers,
            "alert_eligible": eligible,
        })

    # Most suspicious first: longest persistence, then tightest cadence.
    candidates.sort(key=lambda c: (
        -c["days_seen"],
        c["interval_cv"] if c["interval_cv"] is not None else 99,
    ))

    output = {
        "generated_at": dt.datetime.now(dt.timezone.utc)
                          .replace(microsecond=0).isoformat(),
        "window_days": len(dbs),
        "thresholds": {
            "min_days_seen": MIN_DAYS_SEEN,
            "max_conns_per_active_day": MAX_CONNS_PER_DAY,
            "min_hour_consistency": MIN_HOUR_CONSISTENCY,
        },
        "candidates": candidates,
    }

    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    tmp = OUTPUT + ".tmp"
    with open(tmp, "w") as f:
        json.dump(output, f, indent=2)
    os.replace(tmp, OUTPUT)
    print(f"{len(candidates)} slow-cadence candidate(s) "
          f"over {len(dbs)} days → {OUTPUT}")

    fire_alerts_for_new(candidates)
    return 0


def fire_alerts_for_new(candidates: list[dict]) -> None:
    """Diff against the known-pair state file. First-time pairs (i.e. ones
    that have just crossed the slow-cadence threshold) fire a Slack alert
    via the existing beaconbutty-alert.sh pipeline.

    On first ever run the state file is absent — we seed it without alerting,
    otherwise the initial 350+ legit cloud check-ins would all page."""
    pair_keys = {
        f"{c['src']}|{c['dst']}|{c['dst_port']}" for c in candidates
    }

    seed_run = not os.path.exists(KNOWN_PATH)
    known: set[str] = set()
    if not seed_run:
        try:
            with open(KNOWN_PATH) as f:
                # Older state files keyed pairs with the IPv6-mapped
                # "::ffff:" prefix. Normalise on load so a mid-life
                # format change doesn't look like 200+ "new" pairs.
                known = {
                    k.replace("::ffff:", "")
                    for k in json.load(f).get("pairs", [])
                }
        except (OSError, json.JSONDecodeError):
            seed_run = True   # corrupt → reseed

    new_keys = pair_keys - known
    fired = 0
    gated_hyper = 0
    gated_shared = 0
    if seed_run:
        print(f"Seed run — recording {len(pair_keys)} pairs without alerting.")
    else:
        for c in candidates:
            key = f"{c['src']}|{c['dst']}|{c['dst_port']}"
            if key not in new_keys:
                continue
            # Alert gate — only Slack-page when the candidate is genuinely
            # interesting: single LAN talker AND non-hyperscaler dst.
            # Everything else stays on the dashboard for hunting.
            if not c.get("alert_eligible"):
                if c.get("is_hyperscaler"):
                    gated_hyper += 1
                elif (c.get("lan_talkers") or 1) > 1:
                    gated_shared += 1
                continue
            target = c["sni"] or c.get("http_host") or c["dst"]
            org = c.get("dst_org") or "unknown ASN"
            detail = (
                f"Slow-cadence beacon: {target}:{c['dst_port']}, "
                f"{c['days_seen']} days, ~{c['conns_per_active_day']}/day "
                f"at {c['modal_hour_utc']:02d}:00 UTC "
                f"(hour-cons {int(c['hour_consistency'] * 100)}%) — "
                f"sole LAN talker, ASN: {org}"
            )[:240]
            try:
                subprocess.run(
                    [ALERT_BIN, "slow_cadence_beacon", "medium",
                     c["src"], detail],
                    timeout=15, check=False,
                )
                fired += 1
            except (FileNotFoundError, subprocess.TimeoutExpired) as e:
                print(f"alert send failed for {key}: {e}", file=sys.stderr)
        gated = gated_hyper + gated_shared
        print(f"New pairs: {len(new_keys)} (fired {fired}, "
              f"gated {gated}: hyperscaler={gated_hyper}, "
              f"shared_lan={gated_shared}).")
    write_gate_stats(fired, gated_hyper, gated_shared)

    # Persist the union — once seen, don't re-alert even if FP'd later and
    # then un-FP'd. Trim only by truncation if the file gets unwieldy.
    tmp = KNOWN_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"pairs": sorted(pair_keys | known)}, f)
    os.replace(tmp, KNOWN_PATH)


if __name__ == "__main__":
    sys.exit(main())
