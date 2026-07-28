---
tags: [beaconbutty/investigation]
created: 2026-04-16
---

# False Positive Workflow

## What causes false positives

RITA scores connections based on statistical regularity. Many legitimate applications make regular outbound connections that superficially look like beacons:

- **Software update checks** — macOS, Windows, apps checking for updates hourly
- **IoT telemetry** — smart home devices pinging cloud services
- **App heartbeats** — health/sync pings (Dropbox, OneDrive, cloud apps)
- **CDN health checks** — apps verifying connectivity to their CDN
- **Analytics/telemetry** — usage reporting on a regular schedule

These are expected and need to be registered to keep the hotlist clean. The alternative (lowering the score threshold) creates too much noise — see [Alert Tuning](alert-tuning.md).

## Assessing a potential FP

### Step 1: Identify the device

Open the webapp → **Assets** page. Find the source IP. The page shows:
- Hostname (from dnsmasq or Zeek)
- MAC address
- MAC vendor (from IEEE OUI database)
- Whether it's already in the FP registry

If the device has a **randomised MAC** (common on iPhones and modern Android), the vendor will show as the OS vendor (Apple/Google) and the hostname may be generic.

### Step 2: Identify the destination

Open the webapp → **Beacons** page → expand the device entry. For each beacon connection you'll see:
- Destination IP and/or FQDN
- GeoIP annotation: organisation, city, country (from MaxMind GeoLite2)
- Beacon score (0–1)
- Connection count over the period

Also useful:
```bash
# WHOIS lookup
whois <destination-ip>

# Reverse DNS
dig -x <destination-ip> +short

# Zeek SSL log (shows SNI/hostname even for HTTPS)
zcat /var/log/zeek/$(date +%Y-%m-%d)/ssl*.gz | grep <destination-ip>
```

### Step 3: Decide

| Scenario | Action |
|----------|--------|
| Known device + destination matches device purpose | Register as FP |
| Known device + destination is a well-known org | Register as FP (or add org to safe list) |
| Known device + unfamiliar destination | Research destination before deciding |
| Unknown device | Identify device first — check MAC vendor, Zeek hostnames |
| Score ≥ 0.9 + unknown destination + unknown device | Treat as potential incident |

> [!warning]
> Score = 0 with `High` RITA classification means a **long-duration persistent connection**, not a beacon. These appear in some report views but should not be treated as beacons. They are skipped in the Device Hotlist.

## Registering a false positive

### Via webapp

Assets page → find device → click **"Add to FP"** → fill in the pre-populated modal with IP and reason → confirm.

### Via CLI

```bash
beaconbutty-fp.sh add <ip> "<reason>"

# Examples:
beaconbutty-fp.sh add 192.168.50.160 "Air quality monitor — ICMP telemetry to vendor cloud"
beaconbutty-fp.sh add 192.168.50.50  "Smart exercise bike — hourly telemetry"
```

### Via the confirmation modal

The webapp uses a branded confirmation modal (not browser `confirm()`) for all destructive/significant actions. FP additions and removals route through this modal.

## FP registry format

`/var/lib/beaconbutty/false-positives.conf` — **JSON** (v2), four maps:

```json
{
  "version": 2,
  "devices":   {"00:17:88:25:eb:67": "Hue Bridge"},
  "domains":   {"*.example-cdn.com": "App CDN"},
  "protocols": {"3478:udp": "STUN keepalives are universally noisy"},
  "orgs":      {"*ExampleCloud*": {"reason": "Regional app cloud",
                                   "devices": ["aa:bb:cc:dd:ee:ff"]}}
}
```

`devices`, `domains` and `protocols` are always `pattern → reason` strings.
**`orgs` takes two shapes** (2026-07-28): a bare reason string means the ASN is
suppressed LAN-wide, while `{"reason": str, "devices": [mac, ...]}` scopes the
suppression to those source MACs. Both coexist in the same file — any consumer
must handle each. See [Device-scoped org-FPs](#device-scoped-org-fps).

The original one-line-per-entry text format is long gone, and assuming it
lingers has cost real bugs: one consumer still parsed it as whitespace-split
text long after the migration, silently returning an empty set — so its FP
device filter had never worked. Any new consumer must `json.load` and take the
right map. Writes go through `fp.sh` (`save_conf`, atomic tmp+rename) or the
webapp's `_run_fp_script()`.

## Currently registered FPs

| Device | IP | Reason |
|--------|-----|--------|
| Example: air quality monitor | 192.168.50.160 | ICMP telemetry to vendor cloud |

## Domain-pattern matching

FP domain patterns use `fnmatch` glob semantics, with one BeaconButty-specific extension: a pattern starting with `*.` **also matches the bare apex**. So `*.foo.com` matches both `sub.foo.com` and `foo.com` — without that extension, plain `fnmatch` would only match the former (the leading `*.` requires a literal dot).

This matters because DNS-anomaly queries and some beacon destinations hit the apex directly (`thameslinkrailway.com`, `blackeaglesecurityteam.com`), and every FP builder would otherwise leak them through. The apex-aware matcher lives at `_fp_domain_match(q, patterns)` in `webapp/app.py`; every FP-domain call site uses it, and `scripts/summarize.sh` inlines the same logic.

If you add a new `build_*` function that filters by domain, call the shared helper — don't re-invent `any(fnmatch.fnmatch(q, p) for p in patterns)` or the apex case will silently break again.

## DNS entropy filtering

The Network page calculates DNS query entropy per device to detect potential DNS tunnelling. Implementation details:

- Uses the **SLD (second-level domain) label only** — e.g. for `sub.example.com`, uses `example` not `sub.example`
- Skips `.local`, `.internal`, `.lan` queries — mDNS and internal DNS do not indicate tunnelling
- High entropy (long random subdomains) with many unique queries = flag for investigation

## Registry keying: MAC with Zeek-DHCP IP history

The FP `devices` map is keyed by MAC address (migrated from IP-keyed 2026-03-21). `summarize.sh` resolves each FP MAC to every IP it has held in the last 14 days by walking `/var/log/zeek/<date>/dhcp*.log*` plus `current/`, merged with the present dnsmasq lease file. That window matters because a beacon report row carries the IP assigned at Zeek-capture time, which may differ from the MAC's current lease if the device has since renewed.

The Suppressed column in the FP devices table sums across all historical IPs, not just the current one.

**Still brittle**: devices with randomised MACs (iPhones, modern Android, some laptops) need re-adding when the MAC rotates — there is no identifier stable enough to outlast MAC rotation without an active inventory handshake.

## Adding to the safe destination list

If an entire organisation or domain suffix should never appear in beacon results:

In `webapp/app.py`:
- Add ASN org name to `_SAFE_ORGS` (matched via MaxMind GeoLite2)
- Add domain suffix to `_SAFE_DOMAIN_SUFFIXES`

In `scripts/summarize.sh`:
- Add matching patterns to the shell equivalents

Just say "add X to the safe list" — both locations get updated together.

## FP-add UI surface (where each button lives)

The webapp exposes "Add to FP" affordances on several pages, but not every page exposes every dimension — different blast radii belong on different surfaces.  Consolidated rules (2026-05-04):

| Page | Source-device FP | Destination FP | Protocol FP |
|---|---|---|---|
| `/beacons` (Device Hotlist modal) | — | ✓ via "Add to FP" → Domain (default selection); destination IP itself is also a clickable shortcut | ✓ but gated — see below |
| `/beacons` (Device Hotlist row, single-beacon shortcut) | — | ✓ row-level "Add to FP" button when the device has Total=1 — skips the severity-picker modal and opens the FP dialog directly on that one beacon | ✓ same as the modal flow |
| `/beacons/slow` | ✓ at the group level (`FP src`) | ✓ per row (`FP dst`) | — |
| `/network` | — (deliberately removed; too coarse for per-panel signals) | ✓ on New Beacons + Persistent Beacons (`FP dst` only) | — |
| `/assets` | ✓ — global device FP makes sense here | — | — |
| `/fps` | ✓ all three | ✓ all three | ✓ all three |

**Why source-FP isn't on `/network`:** silencing a device's MAC via the global FP registry hides it on every panel and dashboard count, which is rarely what the operator wants when they're investigating a single signal type (e.g. "this device is noisy on TLS Anomalies but I still want to see it on Night Activity").  For genuine global device suppression, `/assets` and `/fps` both make the consequence obvious.

**Pattern is editable on every destination surface (2026-05-07).** All three domain-FP modals (`/beacons`, `/beacons/slow`, `/network`) now show the suggested pattern in an inline editable input — pre-filled with `*.<registrable domain>` from the FQDN (or Zeek-recovered enrichment name on bare-IP rows, or the literal IP as last resort), and the operator can broaden it before submit (e.g. `*.foo.knock.app` → `*.knock.app`, or down to `dnanudge.com` apex).  The previous `window.prompt`-based flow on `/beacons/slow` and `/network` has been retired.  Source-FP on `/beacons/slow` still uses `window.prompt` — there's no domain pattern to generalise on a MAC/IP entry.

**The prefill rule is `*.<registrable domain>`, and it lives in one place (2026-07-24).** Because `*.x.y` also matches the bare apex (above), a single pattern covers the apex and every subdomain — that is what an operator almost always means by "suppress this destination".

Getting there is not "strip the first label". Two ways that goes wrong, both found live:

| Host | Naive rule | Result | Blast radius |
|---|---|---|---|
| `krebsonsecurity.com` | everything after the first dot | `*.com` | every `.com` destination |
| `bbc.co.uk` | strip first label when >2 labels | `*.co.uk` | every `.co.uk` destination |

The first was the `/beacons/slow` rule as shipped; it mis-fired on **every apex row on the page** (`hnrss.org` → `*.org`, `risky.biz` → `*.biz`, `komoot.de` → `*.de`). The second was the `/beacons` and `/network` rule.

The generalisation now lives in **`fp_dst_default(host)` in `webapp/app.py`**, deliberately adjacent to the `_fp_domain_match()` whose semantics it mirrors. It walks back from the end, consults a multi-label public-suffix set (`co.uk`, `com.au`, `co.jp`, …) so second-level registries keep their own label, and returns bare IPs and single-label names literally. `/beacons/slow` is server-rendered so it calls the function directly; `/beacons` and `/network` render rows client-side, so `base.html` exposes `bbFpDstDefault()` — the same algorithm, with **the suffix list injected from `app.py` via a context processor** so the two sides cannot drift.

> If you add a fourth destination surface, call one of those two. Do not re-derive the pattern inline — that is how both variants above got shipped.

**Long hostnames are middle-elided, not end-truncated (2026-07-24).** The identifying part of a hostname is at the end, so `text-overflow: ellipsis` clips precisely the part the operator needs. `shorten_host()` keeps both ends — `69n8gfquor…wuchuyun.com` — preserving the leading gibberish (itself a DGA / CDN-shard signal) alongside the domain that names the owner. The full value stays in the `.bb-pop` popover and in the FP pattern; only the visible text is shortened.

**Reason pre-fill convention:** the destination's GeoIP ASN org (`Amazon.com Inc.`, `Cloudflare Inc.`, etc.).  FP entries are about the destination, not the source — the org documents who owns the FP'd thing.  If GeoIP can't attribute the IP, the field is left empty rather than nudging toward a misleading default.

## Protocol-FP — global, dangerous, gated

Protocol matching is done by `_fp_service_match(svc, fp_protocols)` (module-level in `webapp/app.py`, mirrored in `scripts/summarize.sh`), which every consumer calls. It has no source binding — an entry like `443:tcp:ssl` would silence every HTTPS beacon on every device forever, effectively turning beacon detection off.

**Compound services.** RITA bundles several services into one field, e.g. `80:tcp:http,3478:udp:` (STUN with a TURN 80/tcp fallback). The matcher splits on commas and tests **each component independently**, so a single-component FP entry (`3478:udp`) suppresses the compound row too. A registered FP entry must therefore be **one component** (`port:proto` or `port:proto:name`) — never the whole compound blob. The `/beacons` dialog's Service field is an editable input pre-filled by `_protoDefault()`: a single-service row auto-normalises `3478:udp:` → `3478:udp`; a compound row is shown whole so you trim it to the one component you mean to suppress.

The FP modal on `/beacons` dims the **Protocol** option and shows a prominent red warning unless the row's service is on a narrow safe list. `_isSafeProto()` inspects **every** component (so STUN paired with an incidental HTTP flow is still recognised) and matches either a Zeek service name or a known-safe `port:proto`:

```
names: ntp · mdns · dhcp · dhcpv6 · llmnr · netbios-ns · netbios-dgm · ssdp
ports: 3478:udp · 3478:tcp   (STUN/TURN — Zeek leaves these unlabelled)
```

Clicking the dimmed Protocol option fires a `confirm()` dialog spelling out the consequence; only an explicit OK proceeds.  Safe protocols behave normally — single click, no friction.

Existing FP file has exactly two protocol entries: `123:udp:ntp` and `3478:udp` (STUN, added 2026-05-06). Both fall in the "standard signalling protocol on its standard port" category — see below. Adding anything ending in `:ssl`, `:http`, `:dns`, or a bare `:tcp` is almost certainly a mistake.

## Standard signalling protocols (STUN, NTP, mDNS, DHCP, …)

A class of protocols whose sole job is *signalling* — establishing peer addresses, time sync, name resolution — generate beacon-shaped traffic by design and are universally legitimate when seen on their well-known ports. They can't be domain-FP'd because they deliberately don't surface a domain — clients use hardcoded server lists or multicast.

| Protocol | Port | Used by |
|---|---|---|
| **STUN** | 3478/udp (also 3478/tcp, 5349 TLS) | FaceTime / iMessage / Continuity (Apple), Tailscale derp, Zoom / Teams huddles, Slack calls, Discord, Signal voice, Google Meet, WhatsApp, any WebRTC in-browser |
| **NTP** | 123/udp | Time sync — every device, every OS |
| **mDNS** | 5353/udp | Local service discovery (`.local` names) |
| **DHCP** | 67-68/udp | IP lease management |
| **LLMNR / NetBIOS / SSDP** | 5355, 137-138, 1900 | Legacy Windows / UPnP discovery |
| **SIP** | 5060/udp | VoIP signalling |

### Why STUN looks beacon-shaped

STUN (RFC 5389) is how a device behind NAT figures out its public address so a peer can punch through the NAT to connect directly. The flow:

1. Device sends a tiny UDP packet to a STUN server on port 3478.
2. Server replies "I see you as `<public_ip>:<src_port>`".
3. Device shares that with its peer over a separate signalling channel; both can now connect P2P.

Because chat / video / collaboration apps want to be *ready* for an incoming call, they keep their NAT mapping alive by sending STUN keepalives every ~30s while idle. Result: tiny, regular, anonymous-looking outbound packets to a hardcoded server pool — every C2-detection signal lights up. Typical fingerprint per device per day: ~120 packets, ~16 KB total, hitting Akamai/Linode/Cloudflare IPs (rented STUN infra).

Bare-IP rows on `3478:udp:` from a Mac, an iPhone, or anything with WhatsApp/Zoom installed are all this.

### When to reach for protocol-FP

Symptom: bare-IP rows on a port from the table above, high count, low payload, often spread across many LAN devices, no DNS / SNI / cert / HTTP signal at all.

Action: `beaconbutty-fp.sh add-protocol '<port>:<proto>' '<≤50-char reason>'` and restart `bb-graphs.service`. One entry suppresses the entire class on every device, every destination, forever — which is the right scope for these protocols. The whack-a-mole alternative (FP'ing each STUN/NTP server IP individually) doesn't scale because the provider IPs rotate.

For anything not in the table above, the protocol-FP modal will warn you with a confirmation dialog. Trust the warning — protocol-FP'ing `:ssl` or `:tcp` would effectively disable beacon detection.

## Organisation-FP for no-host destinations

A fourth FP dimension exists alongside device, domain, and protocol: **`orgs`**
— fnmatch patterns against the GeoIP ASN owner string (`dst_org`). Surfaced on
`/beacons/slow`.

### Why it exists

The other three dimensions are useless when a row has **no domain handle at
all**: no SNI, no HTTP Host header, no DNS resolution on the LAN's resolver.
That is the real fingerprint of regional-app cloud traffic — a phone talking
directly to a provider's IPs on proprietary ports. None of the alternatives fit:

- A domain pattern can't suppress a literal IP — `fnmatch('1.13.112.169',
  '*.example.com')` is False, and there's no DNS to bridge them.
- A device-FP is too coarse; it silences the device everywhere.
- A protocol-FP doesn't apply; the ports are proprietary, not standard
  signalling.
- CIDRs don't scale — large providers span thousands of netblocks across
  multiple ASNs.

One org entry, fnmatched against the GeoIP owner, covers all of it.

### Symptom and action

Rows render as dim *"no host · `<org name>`"*. The cell shows two stacked
buttons: **FP ip** (raw dst IP → `/fps/add-domain`, silences just that address)
and **FP org** (`*<first-token>*` → `/fps/add-org`, silences the provider).

The new entry takes effect on the next page load — the slow filter re-applies at
render time — and org-FPs also gate the **detector** at scan time and are
re-checked by the **daily digest** at post time, so an org-FP'd destination can
neither page nor resurface in the morning.

### When NOT to use

- If a row has SNI, HTTP Host, or any DNS resolution, use `FP dst` (domain-FP)
  instead. `FP ip` / `FP org` only appear when the row has no domain handle.
- Don't blanket-FP a major cloud provider — that's what the hyperscaler gate
  covers, and an org-FP would also wipe future no-host investigative signal on
  that provider.
- Don't auto-add an org-FP just because `is_hyperscaler=true` — the operator
  picking the org name consciously is the whole point.

## Device-scoped org-FPs

*Added 2026-07-28.* An org entry may name the source devices it applies to. A
bare reason string still means LAN-wide; `{"reason": ..., "devices": [mac, ...]}`
suppresses the ASN **only** for traffic from those MACs.

### Why

Every org entry on this system was originally LAN-wide, added out of alert
fatigue. LAN-wide is a silent detection hole: a compromised IoT device beaconing
to a given CDN would be suppressed simply because a phone in the house runs an
app that uses the same provider.

It also blocked the fix the noise actually needed. The slow-cadence pager fired
25 times, all false alarms, mostly consumer-CDN edges from a few devices — but
the ASNs involved are large consumer carriers. Suppressing those LAN-wide would
have blinded the detector across the whole network. Scoped to the handful of
devices that legitimately talk to them, they are safe and precise. See
[Slow-Cadence Beacons](slow-cadence-beacons.md#why-the-real-time-pager-was-retired-2026-07-28).

**The rule:** an FP that means *"this is normal for this device"* must carry the
device in the key. Only once suppression is scoped is it safe to be generous
with it.

### Using it

```bash
# Scope to one or more devices (IP or MAC; IPs resolve via leases/ARP)
beaconbutty-fp.sh add-org '*ExampleCloud*' 'Regional app CDN' \
    --device 192.168.50.20,192.168.50.21

# Repeat --device UNIONS the MAC set — it does not replace it
beaconbutty-fp.sh add-org '*ExampleCloud*' 'Regional app CDN' --device 192.168.50.22

# Widen an existing scoped entry back to the whole LAN
beaconbutty-fp.sh add-org '*ExampleCloud*' 'Regional app CDN' --global
```

Both narrowing and widening print a `Note:` line, so the transition is never
silent. In the webapp the **FP org** button opens the modal with a ticked *"Only
for &lt;device&gt;"* checkbox — **scoped is the default**; untick for LAN-wide.

`beaconbutty-fp.sh list` shows an indented scope line per org entry (each scoped
MAC and its current IP, or `LAN-wide`), and the `/fps` Organisations card has a
**Scope** column.

### Matching is case-sensitive, deliberately

MaxMind's ASN owner strings are inconsistently capitalised — one carrier appears
as `Chinanet` and another as `CHINA UNICOM China169 Backbone`. Add both patterns
rather than making the match case-insensitive: case-insensitivity would
retroactively re-interpret every pattern already written, and in particular
would widen a pattern like `*ACE*` to match `Rackspace`.

### Three-way mirror

Org matching is implemented in three places and they must agree:

| Where | Function |
|---|---|
| `scripts/slow-cadence.py` | `fp_orgs()` + `fp_org_match()` — scan time |
| `scripts/slow-cadence-digest.py` | inline matcher in `fp_filter()` — post time |
| `webapp/app.py` | `_fp_org_entries()` + `_fp_org_match()` — render time |

Change all three together, and verify by running the same cases through each
rather than eyeballing that the rewrites look alike. When testing, make sure the
source device in the fixture is **not** caught by any *other* filter — a device
that is itself a device-FP gets dropped a stage earlier and reads as a false
disagreement.
