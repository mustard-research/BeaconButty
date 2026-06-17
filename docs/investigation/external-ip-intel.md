---
created: 2026-05-13
tags: [beaconbutty, threat-intel, enrichment]
---
# External IP threat-intel (Shodan + AbuseIPDB + Spamhaus DROP + Tor)

Added 2026-05-13 (commits `73f3682`, `0715992`, `9af08da`). Augments [Webapp](../development/webapp.md) for the cases where Zeek's logs give nothing to work with — direct-IP beacons with no SNI, no DNS, no completed TLS handshake, no HTTP Host header. The trigger was investigating `43.175.230.151` on the beacon hotlist — Tencent CDN in Singapore, opaque to every Zeek-side source. Two free APIs plus two free bulk lists fill the gap.

## Sources

### Shodan InternetDB (free, no key)
`GET https://internetdb.shodan.io/<ip>` — returns:
- `ports` — open ports Shodan has observed on the host
- `hostnames` — rDNS-derived names
- `cpes` — software fingerprints
- `tags` — high-level classifications (`cdn`, `cloud`, `tor`, `honeypot`, `proxy`, `compromised`, `self-signed`, etc.)
- `vulns` — known CVE exposures

**Gotcha:** Shodan returns **HTTP 403** to Python's default urllib User-Agent. Set a custom `User-Agent` header. `curl` works because its default UA isn't blocked. Took a while to spot because the script silently records empty Shodan data instead of erroring — the cache showed all entries with `abuseipdb` filled in and `shodan` empty.

### AbuseIPDB `/api/v2/check` (free tier 1000 lookups/day)
Requires an API key, stored at `/var/lib/beaconbutty/threat-intel.json` (root:0600, never committed). Returns:
- `abuseConfidenceScore` (0-100)
- `countryCode`, `usageType`, `isp`, `domain`
- `totalReports`, `numDistinctUsers`, `lastReportedAt`

### Spamhaus DROP / EDROP (free, no key) — added 2026-05-13 (`9af08da`)
`GET https://www.spamhaus.org/drop/drop.txt` + `drop_v6.txt` — Spamhaus's "Don't Route Or Peer" netblocks: networks consistently hosting cybercrime infrastructure. **EDROP was folded into DROP in late 2024**, so `drop.txt` alone covers both. Format: `CIDR ; SBL<id>` lines.

We do **one bulk fetch per run** (not per-IP — there's no per-IP endpoint, and there's no rate limit on the static file), cache the CIDR list to `/var/lib/beaconbutty/spamhaus-drop.json` for debug and fallback, then check every cached IP against the list. First run: **1611 CIDRs**.

A DROP hit drives the badge **red** — this is high-confidence "the netblock itself is malicious", complementing AbuseIPDB's per-IP score. The SBL ID surfaces in the tooltip so it's easy to look up at https://www.spamhaus.org/sbl/.

### Tor exit nodes (free, no key) — added 2026-05-13 (`9af08da`)
`GET https://check.torproject.org/torbulkexitlist` — authoritative current exit-node list from the Tor Project. Plain-text, one IP per line. We do one bulk fetch per run, cache to `/var/lib/beaconbutty/tor-exits.json`, check every cached IP for set membership. First run: **1353 exit IPs**.

Shodan already tags some IPs `tor`, but coverage is incomplete (Shodan's crawl doesn't see every exit, and tags are stale). The Tor Project's own list is canonical. A Tor exit hit drives the badge **red** — legitimate-but-suspicious for outbound LAN traffic.

### Fetch resilience
Both bulk lists have a fallback: if the daily fetch fails, the script loads the previous sidecar file. That way a transient network blip doesn't erase coverage. The Shodan/AbuseIPDB selective-refetch logic doesn't apply (these lookups are free local set-membership checks, re-stamped on every run).

## Pipeline

1. **`scripts/ip-intel.py`** → deployed to `/usr/local/bin/beaconbutty-ip-intel.py` (root). Walks distinct external IPv4 dsts from `threat_mixtape` and Suricata `eve.json` across the last 7 days. Ranks targets by recency (today first), caps at 800 lookups per run (stays under AbuseIPDB free tier).
2. Cache at **`/var/lib/beaconbutty/ip-intel-cache.json`** (atomic-replace writes, world-readable so the webapp can read it). Per-entry TTL 30 days, GC after 60 days for IPs no longer in the target set. Selective re-fetch — only re-queries the source that's missing from a cached entry, so a transient Shodan failure doesn't burn AbuseIPDB quota.
3. **`beaconbutty-ip-intel.timer`** fires daily at **07:30 BST**.

## Webapp surfacing

A `TI` badge renders next to bare external IPs everywhere they appear:
- `/beacons` Top Beacons (server-side) + HB/MB/LB/AB modals + Investigate (JS-side)
- `/network` New Beacons row
- `/suricata` LAN-device rows, unresolved table src + dst, per-alert ext_ip
- `/beacons/slow` candidate rows

Hover/focus shows the bb-pop tooltip with usage type, ISP, domain, Shodan tags, CVEs, port count, rDNS.

### Badge colour rationale

- **red** (`badge-high`): AbuseIPDB score ≥ **75** OR Shodan vulns non-empty OR Shodan tags ∩ `{tor, vpn, proxy, honeypot, compromised, malware, ics, nuclear}` OR **Spamhaus DROP hit** OR **Tor exit-list hit**
- **yellow** (`badge-med`): AbuseIPDB 1-74 OR Shodan ports ≥ 50 OR any other Shodan tag
- **grey** (`badge-none`): data present, nothing flagged

The thresholds were tuned in [Tuning history](#tuning-history) after the initial release proved too noisy.

## Tuning history

**v1 (commit 73f3682, 2026-05-13):**
- red = AbuseIPDB ≥ 25, *any* Shodan tag, or any Shodan vulns
- Result on a 837-IP cache: **~160 IPs lit up red**. Most were false positives:
    - Every Cloudflare IP red on `tag=cdn`
    - Every Microsoft 365 / GitHub Pages / Anthropic / Akamai IP red on AbuseIPDB co-tenant scores in the 25-50 band
    - `smtp.gmail.com` red on `tags=['self-signed', 'starttls']` — both routine for SMTP

**v2 (commit 0715992, same day):**
- red threshold raised to AbuseIPDB ≥ 75 (matches AbuseIPDB's own "high confidence" cutoff). The 25-75 band reflects co-tenant abuse on shared-cloud usage types (`Data Center/Web Hosting/Transit`, `Content Delivery Network`), not the specific endpoint — see [Shared cloud abuse scores](#shared-cloud-abuse-scores).
- Shodan tag short-list trimmed to genuinely-malicious-aligned tags only. Excluded: `cdn`, `cloud`, `database`, `videogame`, `devops`, `self-signed`, `starttls`, `eol-os`, `eol-product`. Excluded tags still surface in the tooltip — they just don't escalate the badge colour.
- Result: ~160 red → **13 red**. Of the 13, the most interesting are two Chinese IPs Shodan tags as **both honeypot AND proxy**: `116.62.13.223` and `47.96.149.233`. If LAN traffic ever hits those, the badge will be unmissable.

**v3 (commit 9af08da, same day):**
- Added Spamhaus DROP and Tor exit-list as two new red-badge signals.
- First run after the addition: 1611 DROP CIDRs, 1353 Tor exits; **0 hits in the current 1606-IP cache**. Our beacon set is mainly mainstream cloud (Apple, Microsoft, Google, AWS, Cloudflare, Anthropic), none of which appear on either list — exactly as expected. Coverage is now in place if anything ever lands on either list.
- Why both go straight to red: Spamhaus DROP is a deliberately conservative list of networks consistently hosting cybercrime infra — a hit is a strong signal. Tor exit nodes aren't malicious in themselves but for an outbound C2 channel from a home LAN they're a sharp anomaly, and Tor is already in `_hot_shodan_tags` (red via Shodan), so adding the authoritative list is just upgrading coverage.

## Shared cloud abuse scores

AbuseIPDB scores 25-75 on shared-cloud `usage_type` are co-tenant noise, not endpoint signal. Cloudflare, Azure, AWS CDN, GitHub Pages, Anthropic API endpoints, Akamai edges all sit in this band because *someone* abused those IPs at *some* point and the score is cumulative across tenants.

Above 75 is where AbuseIPDB themselves are confident — that's where the score belongs to the current host rather than reflecting historical churn through the IP allocation pool.

If we ever want a tighter score-based alert (lower threshold), pair it with a `usage_type` whitelist — `ISP`, `Mobile/Cellular`, `University/College/School` have much less shared-tenancy noise.

## The Tencent CDN case (the original trigger)

`43.175.230.151` showed on the beacon hotlist as a bare IP. Zeek captured:
- 8 short connections from 3 LAN devices (a laptop, a phone, another phone)
- Ports 80 and 443
- `service=""` — no protocol identified
- Mix of `RSTO`/`RSTR`/`SF` — short, often reset
- Zero rows in `ssl.log`, `dns.log`, `http.log` for that dst

Zeek-side enrichment came up empty across all four sources (SNI, DNS history, cert subject, HTTP Host) because nothing in the wire data identified the host. External probes:
- No rDNS
- WHOIS: AS139341 ACE-SG, 6 Collyer Quay (SG hosting), netname `ACE-SG`
- `HEAD /` → 405 with `Connection: close`, no `Server:` banner
- TLS without SNI: empty handshake

**Shodan InternetDB:** 697 open ports across the full 0-65535 range — including obsolete protocols (port 13 daytime, 21 FTP, 49 login, 70 gopher, 79 finger). Profile of a deceptive responder / multi-protocol proxy endpoint.

**AbuseIPDB:** score 0 (no abuse history), but the metadata is the gold — `domain: tencent.com`, `isp: ACEVILLE PTE.LTD.`, `usage_type: Content Delivery Network`. ACEVILLE PTE.LTD. is Tencent's Singapore CDN tenant.

**Conclusion:** Known Tencent CDN endpoint, hit by hardcoded IP from Chinese apps on family devices. Consistent with WeChat / Tencent app bootstrap traffic — expected baseline (see [Alert Tuning](alert-tuning.md)). Not malicious, but the absence of every Zeek-side signal made it look suspicious until external intel filled in the picture.

This is the canonical case the feature was built to handle.

## Operational notes

- **Backfill duration:** first run takes ~10 min for ~800 IPs (sleep budget between API calls). Subsequent daily runs do only deltas — a handful of new IPs.
- **Quota safety:** AbuseIPDB 1000/day free tier > our MAX_PER_RUN cap of 800, so even worst-case never throttles. If we raise the cap above 1000, the script needs 429 handling on the AbuseIPDB side.
- **Privacy:** every query tells the provider which IPs bb0 is curious about. For threat intel that's expected, but worth flagging if anyone asks.
- **Key rotation:** the AbuseIPDB key is in `/var/lib/beaconbutty/threat-intel.json`. Rotate via https://www.abuseipdb.com/account/api and overwrite the JSON — the next timer run picks it up automatically (no restart needed).

## Files

| Repo path | Deployed / referenced as |
|---|---|
| `scripts/ip-intel.py` | `/usr/local/bin/beaconbutty-ip-intel.py` |
| `systemd/beaconbutty-ip-intel.service` | `/etc/systemd/system/...` |
| `systemd/beaconbutty-ip-intel.timer` | enabled, daily 07:30 BST |
| `webapp/templates/_intel_badge.html` | Jinja macro `intel_badge(intel)` |
| `webapp/templates/beacons.html` | JS twin `intelBadgeHtml()` for dynamic modal rows |
| `webapp/app.py` | `load_ip_intel()` + `ip_intel(ip)` helpers; `enrich_ips_batch()` attaches `intel` sub-dict |
| `/var/lib/beaconbutty/threat-intel.json` | AbuseIPDB API key (root:0600, NOT in repo) |
| `/var/lib/beaconbutty/ip-intel-cache.json` | the per-IP cache (root:0644) |
| `/var/lib/beaconbutty/spamhaus-drop.json` | DROP CIDR sidecar (debug + fetch-failure fallback) |
| `/var/lib/beaconbutty/tor-exits.json` | Tor exit-IP sidecar (debug + fetch-failure fallback) |
| `/var/log/beaconbutty/ip-intel.log` | run log |
