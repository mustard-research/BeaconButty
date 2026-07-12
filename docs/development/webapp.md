---
tags: [beaconbutty/development]
created: 2026-04-16
---

# Webapp

The BeaconButty web interface is a Flask application served over HTTPS on port 443.

## Screenshot gallery

| | |
|---|---|
| ![Dashboard](../img/bb-dashboard.png) | ![Beacons](../img/bb-beacons.png) |
| **Dashboard** — stat tiles, alert digest, fan & log2ram | **Beacons** — RITA hotlist, FP workflow, JA4/ASN/TI enrichment |
| ![Slow Beacons](../img/bb-slow-beacons.png) | ![Network Intel](../img/bb-network-intel.png) |
| **Slow Beacons** — multi-day low-rate detector | **Network Intel** — top talkers, new beacons, exfil, JA4 inventory |
| ![Health](../img/bb-health.png) | ![Suricata](../img/bb-suricata.png) |
| **Health** — structured component cards, Slack controls | **Suricata** — alert summary with STREAM/QUIC noise filtered |
| ![LAN Assets](../img/bb-lan-assets.png) | ![Bandwidth](../img/bb-bandwidth.png) |
| **LAN Assets** — live + ghost devices, JA4 threat badge | **Bandwidth** — Top Talkers from RITA ClickHouse `conn` |
| ![System](../img/bb-system.png) | ![False Positives](../img/bb-fps.png) |
| **System** — CPU temp, load and memory with fan thresholds | **False Positives** — registry with per-pattern reason |


## Stack

| Item | Detail |
|------|--------|
| Framework | Flask (Python 3) |
| Service | `bb-graphs.service` (legacy name) |
| Source | `webapp/app.py` |
| Templates | `webapp/templates/` (Jinja2) |
| Static assets | `webapp/static/` |
| TLS | Let's Encrypt certificate |

> [!warning]
> **Flask caches templates in production mode.** Always `sudo systemctl restart bb-graphs` after editing any file in `webapp/templates/`. Changes will not appear until the service restarts.

## Pages

| Route | Page | Notes |
|-------|------|-------|
| `/` | Dashboard | Stat tiles incl. Fans (Pi + Pironman ON/OFF) and Network Intel "N issues" (TLS + DNS + New Beacons only) |
| `/system` | System | Stacked Chart.js: CPU temp with fan threshold lines (top), CPU + memory usage 0-100 % with top-consumer tooltips and a live memory-consumers table (bottom). `/temperature` 301-redirects here; `/api/system` ↔ `/api/temperature` same. |
| `/bandwidth` | Bandwidth | ntopng-style Top Talkers view sourced from RITA's ClickHouse `conn` tables. 4-tile summary, stacked-area chart (top-8 devices + Other), Top Talkers table (click device to filter chart), Top Destinations table (GeoIP/ASN-enriched). |
| `/beacons` | Beacons | Device Hotlist (Total col opens all-severities modal; High/Total/Max Score headers sortable — default Max Score desc; rightmost col "Add to FP" for rows with Total=1, "click counts to add FP" hint otherwise), Investigate, Top Beacons, Suppressed-by-FPs audit card (behind "Show FP" toggle) |
| `/network` | Network | Two-tier layout: **Alerts** (TLS, DNS, New Beacons — feed dashboard tile) above **Investigate** (Exfil, Night, Protocol, Persistent, context-only) |
| `/assets` | Assets | Known LAN devices, FP badges, Add to FP button |
| `/fps` | False Positives | FP registry management UI |
| `/health` | Health | Health check output, display toggle, Clear Slack button, Domain Activity Flagger |
| `/backup` | Backup | USB clone status and trigger |

Health is only accessible via the Dashboard Health tile — it is intentionally not in the main nav.

## Key API endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/display` | GET | Read display flag state |
| `/api/display` | POST | Write display flag (blank/restore) |
| `/api/domain-watch/config` | GET | Read currently-watched domain ('' = off) |
| `/api/domain-watch/config` | POST | `{"domain": "..."}` — set or clear |
| `/api/domain-watch/data` | GET | Last 6h of activity, bucketed by minute |

## Critical patterns

### False positive filtering

Every `build_*` function that returns network intelligence data must apply FP filtering at the dimensions relevant to its panel: **device** always; **domain** where the row has an FQDN or external host; **protocol** where a beacon row with a `svc` field is retained. See memory `feedback_network_intel_fp.md` for the current coverage matrix. Missing the right dimension is how FP-registered rules silently fail to suppress matching rows (gmail / skype / NTP incidents).

This applies to dashboard tile counters as well as page builders. `count_beacon_findings_today` (the "Beaconing Devices" tile) must track `get_beacon_data`'s filter set exactly — device + domain + protocol + safe-dest + `score==0` — or the dashboard count diverges from the `/beacons` Device Hotlist and the user sees two different numbers for the same thing (2026-04-22 incident).

Domain matching uses an apex-aware helper (`_fp_domain_match(q, patterns)`) so that `*.foo.com` also suppresses the bare `foo.com`. See [False Positive Workflow](../investigation/false-positive-workflow.md).

After any webapp write to `false-positives.conf`, call `_invalidate_network_cache()` (all 7 FP routes do). It does **not** null the cache — it signals the warmer to rebuild in the background (see [Network Intel cache warmer (2026-05-15)](#network-intel-cache-warmer-2026-05-15)). The cache is not automatically invalidated by external CLI writes to the FP file.

### Data attributes (not onclick)

Never embed JSON or quoted data in `onclick="..."` HTML attributes. Use `data-*` attributes and access them via `this.dataset.*` in JavaScript. Embedded JSON in onclick attributes breaks with nested quotes.

### Beacon score zero

Skip rows where beacon score == 0 in the Device Hotlist. RITA classifies long-duration persistent connections as `High` with score 0 — these are not beacons and create significant noise.

### Multi-day report dedup

Each `beacon-report-*.txt` bundles the last 3 RITA daily databases (see [Data Pipeline](../architecture/data-pipeline.md)), so a persistent beacon shows up as one CSV row **per day**. `get_beacon_data` and `summarize.sh` collapse rows to one per distinct `(src, dst, fqdn)` before aggregating — highest beacon score wins, most recent day breaks ties — so severity badges, the Device Hotlist, per-device modals and Top Beacons count *distinct beacons*, not beacon-days. `build_new_beacons` was already safe (keyed by `(src, dest)`). Any new report consumer must apply the same dedup. (2026-05-19)

### CSV parsing

Always use `csv.reader`, never `str.split(",")`, in `parse_beacon_report()`. Quoted fields (e.g. protocol keys containing commas) retain their surrounding quotes with naive splitting, breaking field extraction.

### Cache invalidation

`_NETWORK_CACHE` must be busted after **any** write to `false-positives.conf`, whether via the webapp or via the CLI. CLI writes bypass the webapp's normal FP-write code path.

### Network Intel cache warmer (2026-05-15)

`/network` runs 10 Zeek-log builders — **~17s uncached**. `build_network_intel()` TTL-caches the result (5 min), but before this change every cache lapse made the next visitor wait the full 17s (browsers gave up mid-load with `SSL: UNEXPECTED_EOF`). `_compute_network_intel()` now holds the uncached build, and a `_network_cache_warmer` daemon thread (started in `__main__` before `app.run`) rebuilds `_NETWORK_CACHE` every `TTL-60s`, swapping the finished dict in atomically. Requests always hit the ~0.01s cached path. If `/network` feels slow again, confirm the warmer thread is alive (the `bb-graphs` PID should show 2 threads).

**FP edits no longer cold-stall (2026-05-27).** Adding/removing an FP used to set `_NETWORK_CACHE["data"] = None`, so the next *dashboard* load ran the full ~17s synchronous rebuild — a multi-second spinner (diagnosed from the access log: two `/fps/add-domain` POSTs followed by a slow `GET /`). Now all 7 FP routes call `_invalidate_network_cache()`, which `.set()`s a `_NETWORK_REBUILD_REQUEST` Event. The warmer loop is `clear → rebuild → wait(event, timeout=interval)`, so an FP edit wakes it immediately; it rebuilds off to the side and atomically swaps in the fresh FP-filtered result while readers keep getting one-edit-stale data. Nothing blocks. Clearing the event before each rebuild means an edit landing mid-rebuild re-sets it and gets a follow-up rebuild (coalesces rapid successive edits).

### JA4 threat surfaces — exact + FP + fade

The "this device matches a known threat fingerprint" finding shows up on five surfaces that **must stay in lockstep**. All apply the same three rules:

1. **Exact-match only.** `classify_ja4()` returns `source == "ja4db"` for an exact JA4 hash hit; `source == "ja4db-cipher"` for a cipher-portion-only fallback. Cipher-family is **informational only** — it surfaces in tooltip / label text but never as a flagged threat. Cipher hashes are shared with legitimate clients (e.g. `2b729b4bf6f3` matches both IcedID and many ordinary apps), so they're far too broad to act on.
   - **Generic-runtime exclusion (2026-05-15).** Even an exact ja4db hit is downgraded to informational if its ja4db `Library` is a generic language runtime — `_ja4_label_is_threat()` (and `label_is_threat()` in `scripts/ja4-threat-check.py`) returns `False` when the label contains a `_JA4_GENERIC_RUNTIMES` token (currently `golang`). The hash labelled "Sliver Agent / GoLang" is the stock Go `crypto/tls` Client Hello, shared by every Go program — flagging it made any Go-running device a false threat. Specific fingerprints (Cobalt Strike beacon, the Sliver/Havoc *server* JA4S — empty Library) are unaffected.
2. **FP suppression.** Devices whose MAC is in `false-positives.conf` are treated as fully trusted everywhere. The threat marker / alert is suppressed even if a real exact JA4 match exists.
3. **14-day fade** (where history is consulted, currently /assets only). A historical fingerprint that hasn't been `last_seen` within `JA4_THREAT_FADE_DAYS` (14) stops contributing to the device's threat flag. Today's live data is always counted regardless. The history file itself is preserved — only the read-time aggregation fades.

| Surface | Function | Notes |
|---|---|---|
| Slack alert | `scripts/ja4-threat-check.py` | exact + FP MAC skip; detail string must be stable for Lambda dedup |
| Dashboard "Network Intel" count | `network_alert_summary` | filtered ja4 count via underlying builders |
| /network → JA4 Threat Matches | `build_ja4_threat_matches` | exact + FP IP skip |
| /network → JA4 Inventory | `build_ja4_inventory` | FP IP excludes the row entirely; per-hash `threat` flags exact-only |
| /assets THREAT badge | `ja4_summary_for_ip` | exact + FP IP suppression + fade |

If you add a new JA4-threat-bearing UI element, run all three rules through it before shipping. Project memory `project_ja4_alerts.md` carries the same matrix.

### Custom popovers (not native `title=`)

For multi-line tooltips that the user is expected to actually read (e.g. the /assets THREAT badge explaining matched JA4 hashes), use the `.bb-pop` class with a `data-pop="..."` attribute, not the native `title` attribute. Native browser tooltips have a 1-2s delay, drop newlines unreliably, and on some setups don't render at all. Add `tabindex="0"` so keyboard/tap focus shows it too, and keep `title="..."` as an a11y fallback.

The tooltip is rendered into a **body-level `position:fixed` portal** by a script in `base.html` (the `.bb-pop-portal` styles are in `bb.css`). This replaced the original CSS `::after` pseudo-element on 2026-05-15: a pseudo-element cannot escape an ancestor's overflow clipping, so tooltips on badges inside `.table-wrap` (which has `overflow-x:auto`) were silently truncated. The portal is fixed against the viewport and never clipped. Templates are unchanged — the `.bb-pop` + `data-pop=` contract is the same.

## Safe destination filtering

Beacon connections to known-safe destinations are filtered before the hotlist is built. Two lists in `webapp/app.py`:

**`_SAFE_ORGS`** (ASN-based, matched via MaxMind GeoLite2):
- Apple Inc., Microsoft Corporation, Google LLC, Cloudflare Inc., NetActuate Inc.

**`_SAFE_DOMAIN_SUFFIXES`** (domain suffix matching):
- microsoft.com, google.com, apple.com, the .apple TLD, signal.org, netflix.com, amazon.com, fing.io/com, sharepoint.com, monknow.com, azureedge.net, aka.ms, outlook.com, dns.google, and others.

The same filtering runs in `scripts/summarize.sh` using shell functions and the same MaxMind database.

To add a new entry to both simultaneously: just say "add X to the safe list".

## Geo enrichment

MaxMind GeoLite2 databases at `/var/lib/GeoIP/` (ASN + City DBs). Used to annotate bare IP destinations with `(organisation, city, country)`. Updated every Wednesday and Saturday by `geoipupdate.timer` (account 1317713).

## Zeek-side IP enrichment (2026-05-06)

GeoIP only tells you "Amazon, Columbus, US" — not *which* AWS tenant. RITA's daily report joins against same-day `dns_history` only, so any beacon whose dst was last resolved on a prior day surfaces as a bare AWS/Azure IP even though Zeek captured the FQDN earlier.

`enrich_ips_batch(pairs, days=7)` in `webapp/app.py` recovers identity by querying four Zeek log sources across the recent daily ClickHouse DBs, in priority order:

| # | Source | Field | Why this order |
|---|---|---|---|
| 1 | `<db>.ssl` | `argMax(server_name, ts)` | TLS SNI — the client literally said the FQDN. Most authoritative. |
| 2 | `<db>.dns` | `arrayJoin(answers)` matching dst | Historical DNS query that resolved here. Catches stale IPs RITA missed. |
| 3 | `<db>.ssl` | `argMax(server_subject, ts)` (CN extracted) | Cert Subject CN. Works for SNI-less / ESNI flows. |
| 4 | `<db>.http` | `argMax(host, ts)` | HTTP Host header. Plain-HTTP fallback (e.g. OCSP). |

Per-source query is **one** ClickHouse `UNION ALL` across the daily DBs with the candidate dst-IN list pushed down — fast even for hundreds of pairs. Results cached per-process with a 10-min TTL keyed on **dst only** (the IP's identity is the same regardless of which LAN device is asking — refactored 2026-05-06 after a case where one device's STUN dst stayed unenriched because the SNI had been recorded from a different LAN host). Empty results are also cached so unidentifiable IPs don't re-query.

Safety: results that are themselves IP literals (some clients send the IP as TLS SNI) are filtered out — an IP isn't enrichment.

**Wired in:**

| Page | Panel | Server-side hook |
|---|---|---|
| `/network` | New Beacons | `build_new_beacons` → `row.dest_enrich` |
| `/beacons` | Hotlist HB/MB/LB/AB modals | `get_beacon_data` → `entry.enrich_*` |
| `/beacons` | Top Beacons table | same |

The enrichment line renders inline beneath the bare IP: `→ api.knock.app  DNS · 2d`.

**FP form prefill cascade.** When the operator clicks "Add to FP" on an enriched bare-IP row, both fields are derived from the enrichment when present:

- **Pattern**: `*.knock.app` (from `enrich_name`) instead of the bare AWS IP. One FP entry covers the whole service across current and future IPs.
- **Reason**: `api.knock.app` (the `enrich_name` itself) instead of the GeoIP ASN org `Amazon.com, Inc.`. Documents *what* is being suppressed.

Operator can edit either before submitting. If enrichment found nothing, the cascade falls back to the previous behaviour (literal IP for pattern, ASN org for reason).

**Matcher-side requirement.** The FP-domain check (`_fp_domain_hit` in `get_beacon_data`, the equivalent in `build_new_beacons`) must consult the enrichment name as a third match target alongside the row FQDN and the bare dst IP. Without it, the user adds `*.knock.app` to FP and the bare AWS IPs the enrichment identified as Knock stay visible — the prefill makes adding the FP one-click but the matcher has to fire for the suppression to actually happen. Both call sites run a quick pre-pass to gather candidate `(src, dst)` pairs and call `enrich_ips_batch` *before* the FP-suppression decision, so the enrichment is in hand at the right moment.

**Open candidates** (not yet wired): the Investigate panel on `/beacons`, the Suricata page, and any future panel that surfaces bare IPs. The helper is reusable — pass `[(src_ip, dst_ip), …]` and merge the result onto each row before rendering. When wiring, don't forget the matcher-side requirement above — that's the part that bit us when extending to the Hotlist.

## External IP threat-intel (2026-05-13)

Zeek-side enrichment above answers *"what is this IP?"* from our own captured traffic. But some destinations never give Zeek anything to work with — direct-IP connections with no SNI, no DNS resolution, no completed TLS handshake (the 43.175.230.151 / Tencent CDN case). For those, we pull in two external sources daily. Full writeup at [External IP Intel](../investigation/external-ip-intel.md); from the webapp's perspective:

- `load_ip_intel()` / `ip_intel(ip)` in `app.py` (mtime-cached, no restart needed when the timer writes new data) read `/var/lib/beaconbutty/ip-intel-cache.json`.
- `enrich_ips_batch()` attaches an `intel` sub-dict alongside the existing `name/source/when_days` fields. Bare-IP code paths that don't hit `enrich_ips_batch` (Suricata external dsts, slow-cadence rows) call `ip_intel(dst)` directly.
- `templates/_intel_badge.html` Jinja macro + a JS twin `intelBadgeHtml()` in `beacons.html` render a small `TI` badge with a `bb-pop` tooltip. **Mirror-drift hazard**: if the macro logic changes, update both copies — see [Custom popovers (not native title=)](#custom-popovers-not-native-title) and the general drift hazard in [Scripts & Timers](scripts-and-timers.md).
- Badge colour:
    - **red** = AbuseIPDB ≥ 75 OR Shodan vulns non-empty OR Shodan tags ∩ `{tor, vpn, proxy, honeypot, compromised, malware, ics, nuclear}`
    - **yellow** = AbuseIPDB 1-74 OR Shodan ports ≥ 50 OR any other Shodan tag
    - **grey** = data present, nothing flagged

Wired into: `/beacons` (top + 4 hotlist modals + Investigate), `/network` New Beacons, `/suricata` LAN + unresolved + per-alert ext_ip, `/beacons/slow`.

## System page charts (temp + CPU + memory)

The `/system` page stacks two Chart.js charts backed by one `/api/system?days=N` fetch, sharing the Today / 3 Days / 7 Days selector. The top chart (temp + fans) has threshold lines via the `thresholdPlugin`; the bottom chart (CPU % + memory %, memory added 2026-07-12) is fixed Y 0-100 with a live memory-consumers table beneath it.

Key implementation decisions:
- **Always destroy and recreate** the chart on view switch. Chart.js inline plugins only fire `afterDraw` on chart creation — calling `chart.update()` does not re-fire the plugin.
- **Day-divider plugin is parameterised** by the target y-scale id (`makeDayDivPlugin('yTemp' | 'yCpu')`) so both charts share the same midnight-line logic without touching each other.
- **Y-axis scaling (temp)**: p2/p98 percentile bounds calculated from the data, then 20 % manual grace padding applied. This suppresses outlier spikes without hiding the normal operating range. `grace` is ignored when explicit `min`/`max` are set — must be applied manually.
- **Y-axis scaling (CPU)**: fixed 0-100 %, stepSize 25. Stable bounds make day-to-day comparison honest.
- **Multi-day aggregation**: hourly buckets use **maximum** of `temp_c`, `cpu_pct` and `mem_pct`, not average. This preserves spikes which are operationally significant. `top_cpu`/`top_mem` for an hourly bucket come from the record at that hour's CPU/memory peak, so the tooltip explains the peak it shows.
- **Data thinning**: client-side `thinData()` reduces dense today views to 150 points for rendering performance. It always keeps the newest record — uniform sampling can drop the tail, hiding young metrics that only exist there yet.
- **Data source**: `bb-watchdog` samples `temp_c` + `cpu_pct` (from `/proc/stat` delta-between-ticks) + `mem_pct` (100·(1−MemAvailable/MemTotal)) + `top_cpu`/`top_mem` (top-3 consumers as `[name, pct]` pairs, friendly-name grouped; CPU % from per-process jiffy deltas between ticks, NOT `ps`'s cumulative %cpu) + fan states every 60 s and appends to `/var/lib/beaconbutty/watchdog/data/YYYY-MM-DD.json`. Records before 2026-04-24 have no `cpu_pct`; records before 2026-07-12 evening have no `mem_pct`/`top_*` — chart renders null as a gap (`spanGaps: true`), and the memory series draws visible dots while it has <10 points on screen.
- **Tooltip consumers**: hovering the bottom chart shows the top-3 CPU consumers under the CPU value and the top-3 memory users under the Memory value (tooltip `afterLabel` reads `sysData[dataIndex]`).
- **Memory consumers table**: `/api/memory-consumers` snapshots `ps`, groups RSS by friendly name (`_MEM_KNOWN` in `app.py`), and flags any service above its expected ceiling (~30 % over observed steady state) as HIGH. Rendered below the chart with a totals line (available ≥ 1 GiB OK / ≥ 0.5 warn / else high).
- **Legacy URLs**: `/temperature` and `/api/temperature` 301-redirect to `/system` and `/api/system` respectively.

## Suricata page — noise suppression + unified counting (2026-04-24)

Two invariants across every count on `/suricata`:

1. **STREAM/QUIC infrastructure noise is suppressed everywhere.** `filter_infra_noise()` (in `webapp/app.py`) drops any alert whose rule starts with `SURICATA STREAM` or `SURICATA QUIC` — those fire on traffic shape, not threats, and drown out everything meaningful. Applied in `count_alerts_by_priority`, `count_sigs_by_priority`, `build_suricata_data`, and `build_suricata_extras`. Page tagline carries a small note so users aren't surprised. If the raw stream is needed for debug, read `/var/log/suricata/fast.log` directly.
2. **"An alert" = one post-filter fast.log line.** Header tile, dashboard Suricata card, 7-day trend, hourly timeline, category breakdown, and `Show P3 (N)` toggle all report raw line counts. Top Signatures groups by rule with a `Count` column that sums to the tile.

Before 2026-04-24 the page mixed three conventions (tile: distinct sigs; category breakdown: raw with STREAM-only filter; trend: raw with no filter), producing surprises like *"10 P3 in the tile but 170 in the trend for the same day."* Fixed in commit `f4f5f27` (tile alignment) + `c378c8d` (button label).

## Suricata 7-day trend coverage detection

The trend distinguishes "day with zero alerts" (rendered as `0`, dimmed, no bar) from "day with no source data" (rendered as `—`, dim italic "no data" label + tooltip). Coverage = today (live fast.log) ∪ the set of alert-timestamp dates in `week_alerts`. **This was previously computed from archive file mtime, which was wrong**: gzip preserves source-file mtime and rotations happen at ~midnight, so `fast.log.1.gz` rotated at 00:40 today has mtime in today's data but actually holds yesterday's alerts. Fixed in commit `aa51f9c` (2026-04-24).

**Drill-down (2026-04-24)**: each count in the trend is a link that opens a modal listing every alert on that day (time, priority, rule, source → destination). `build_suricata_extras()` returns `trend_details` — a dict keyed by ISO date whose values are per-alert dicts — which the template embeds in a `<script type="application/json">` tag. The modal reads it on click; no extra round-trip.

## Bandwidth page (2026-04-24)

The `/bandwidth` page answers "who is hogging bandwidth?" — ntopng-shaped Top Talkers / Top Destinations, sourced from RITA's existing per-day ClickHouse databases.

**Data source**: `beaconbutty_YYYYMMDD.conn` (one DB per day, RITA v5.1.1 imports hourly). The `conn` table has `src_ip_bytes`, `dst_ip_bytes`, `src_local`, `dst_local` — we filter `src_local=1 AND dst_local=0` for per-LAN-device WAN-bound traffic. IPv4 addresses are stored as `::ffff:a.b.c.d` in the IPv6 column — `IPv6NumToString(src)` plus a Python strip of the prefix handles the presentation.

**ip_bytes, not payload bytes (2026-04-25)**: every byte sum reads `src_ip_bytes` / `dst_ip_bytes` (real IP-layer bytes Zeek observed on the wire), not `src_bytes` / `dst_bytes` (Zeek's TCP-payload estimator). The original implementation used the payload counters and was tripped by a TCP-sequence-wrap artifact: 2026-04-24 and 2026-04-25 each showed a single 32-second flow from a LAN host to `weather.partners.msn.com` reporting `dst_bytes=0x4_FFFF_FFFF` (≈20 GiB) while only ~14 KB had actually crossed the wire. Zeek had inferred a giant gap and credited it as transferred bytes (`missed_bytes=18.6 GB`). Switching to ip_bytes counts only packets actually observed; Network Intelligence's exfil + night-activity scans were migrated symmetrically (commit `f339b5b`). Trade-off: ip_bytes includes IP+TCP/UDP headers (~5 % over payload), which actually matches what `vnstat`/`iftop`/the ISP meter see.

**Query shape**: one `subprocess.run(['clickhouse-client','--query', SQL + ' FORMAT JSONEachRow'])` per section (summary/talkers, timeseries, destinations). No Python CH client needed. Multi-day windows use `UNION ALL` across daily DBs — the per-day databases are independent, so the union approach is cheap for 7-day queries (~hundreds of ms).

**Key implementation choices**:
- **Top-N + Other bucket**: talker query returns every LAN device ordered by total bytes; the top 8 by total become individual series, the rest aggregate into `__other__`. Matches ntopng's standard Top Talkers chart shape.
- **Hour-bucketed `sum` (not max)**: bandwidth is additive, so hourly buckets use `sum(src_ip_bytes + dst_ip_bytes)`. Differs from the System page's max-per-hour choice (that's a gauge; this is a throughput integral).
- **Asset-name resolution via `ip_label(ip, ip_to_host, assets)`** — reuses the same helper the beacon pages use (dnsmasq leases + assets.json). This is where we beat ntopng — ntopng names from DHCP/mDNS are often stale.
- **GeoIP/ASN enrichment on destinations** via the existing MaxMind reader (`_geoip_info`).
- **Click-to-filter**: clicking a device row hides the stacked area and shows just that device as a filled line. Yellow banner shows which device is filtered; "Show all devices" clears it.
- **Click-to-expand Up / Down (2026-04-25)**: each talker's Up and Down byte values are buttons. Click → an inline sub-row drops in beneath that device showing its top external destinations sorted by the chosen direction (IP, ASN/org, country/city, up/down/flows). Backed by `/api/bandwidth/device-destinations?ip=…&direction=up|down&days=…`. Toggle off by clicking the same value, or click the other direction to swap. Open expanders are torn down whenever the talker table re-renders (sort or window change).
- **Sortable talker columns**: client-side re-sort, default Total desc.
- **Summary "Peak Hour"** is computed from the timeseries rather than a separate query (saves a round-trip).

**What's deliberately deferred**:
- nDPI-style application identification ("this was Netflix vs Zoom") — would need bolting nDPI onto Zeek or a second capture.
- Sub-hour resolution — conn.log is flow-terminated and RITA imports hourly, so hour buckets are the natural grain.
- Per-device drilldown chart — the click-to-filter on the main chart covers the common case.

## Manual device-name overrides

`/var/lib/beaconbutty/device-names.json` is a flat `{ip: friendly_name}` map consulted by `ip_label()` **before** dnsmasq leases and `assets.json`. Used for devices that don't advertise a useful DHCP hostname — MDM-managed work machines, things on randomised MACs with a known IP, IoT gear with cryptic model codes.

Reloaded on file mtime change — edit the file, the next page render picks up the new name. No webapp restart. Edit with `sudo jq` or just a text editor; the file is `dm:dm` and mode 664 so the webapp can read it.

Example:

```json
{
  "192.168.50.50": "Work Laptop",
  "192.168.50.60": "Family Laptop"
}
```

Precedence order in `ip_label(ip, ip_to_host, assets)`:
1. `device-names.json` manual override
2. dnsmasq DHCP hostname
3. `assets.json` `hostname` / `mac_vendor`
4. bare IP

The Assets page also consults `device-names.json` as a hostname fallback — if `assets.json` has no hostname for an IP but the overrides file does, the page shows the override name with a small `manual` pill so the source is visible.

Only useful for IP-stable devices. If a device has a randomised MAC and its IP changes, either pin its IP via a dnsmasq reservation (see `scripts/07_router_mode.sh` for examples) or rely on the other paths.

## Suricata page performance

`/var/log/suricata/eve.json` grows to ~200MB by end of day (now on log2ram). Rotated archives land in `/var/lib/suricata/archive/` on NVMe. Optimisations:
- Binary search to find today's byte offset in `eve.json` before reading
- File parsed once per request; result shared across functions
- 15-minute page cache (`_SURICATA_CACHE_TTL = 900`) — repeat loads are instant
- First load: ~3.3 seconds

## Domain Activity Flagger (Health page)

Generic on-demand replacement for the old hardcoded `dnanudge-watch` timer
(see *Incident Log* — `2026-04-16 → 2026-04-22 — dnanudge.com hourly beacon`).

Off until a domain is loaded via the Health page input. When set, the Flask
backend scans the last 6h of Zeek `ssl.log` and `dns.log` (today's daily
archive + `current/`) on demand, filters by case-insensitive substring match
against SNI / DNS query, and buckets matching events by UTC minute.

Per bucket the response includes:
- `count` — unique `(second, source_ip, source_type)` tuples
- `sources` — `[[ip, count], …]` for that minute
- `paired` — `[[hostname, count], …]` of any other DNS query made by the
  same source within ±1s, hostnames the target domain itself excluded.
  **Counts matter** — `shops.myshopify.com (x12)` is causation;
  `time1.google.com (x1)` is coincidence.

UI is a 6-row × 60-column heatmap grid (16 × 20 px cells), with a custom
fast tooltip per cell (the native `title=` attribute had a 1-2s delay), plus
a table of non-zero buckets newest-first. Auto-refreshes every 30 s while a
domain is set. Row labels show date when the window crosses midnight.

Config persists in `/var/lib/beaconbutty/domain-watch.json` (must exist and
be writable by the `dm` user — pre-create owned by `dm` if redeploying from
scratch).

Window is fixed at 6h. Going longer would mean introducing a pre-aggregated
store (ClickHouse); not justified for current investigative use.

## Beacons page — date picker

The date picker on the Beacons page uses a custom dropdown:
- Current week dates listed directly
- Older weeks shown as collapsed rows (`6–12 Apr ›`) that expand on click
- The week containing the currently selected date auto-expands on load
- Grouping logic in `_group_dates_by_week()` in `webapp/app.py`
