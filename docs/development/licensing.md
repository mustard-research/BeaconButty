---
tags: [beaconbutty/development]
created: 2026-04-21
updated: 2026-05-04
status: draft
---

# Licensing Analysis: Zeek, Suricata, RITA, ClickHouse & FoxIO JA4+

> [!abstract] TL;DR
> Zeek (BSD-3) and ClickHouse (Apache-2.0) are permissive and unproblematic. Suricata (GPLv2) and RITA (GPLv3) are strong copyleft. **FoxIO JA4+ is the new long pole** (added 2026-05-04 alongside the JA4 fingerprinting work): JA4 itself is BSD, but JA4S/JA4H/JA4X/SSH/etc. are under the FoxIO License 1.1 with patent-pending claims, permissive only for non-monetised internal use. Any monetisation — direct or indirect — needs an OEM licence from FoxIO, including the SaaS and installer-fetches-on-install patterns that work for the GPL components. A closed-source commercial product that bundles all four GPL/BSD components faces real constraints from the GPL pair only; the architecture (separate processes communicating via files, sockets, and SQL — see [Data Pipeline](../architecture/data-pipeline.md)) keeps us on the "aggregation" side rather than "derivative work." Two viable commercial paths for the GPL pieces: ship an installer that fetches GPL components at install time, or deliver as SaaS. Commercial non-GPL licensing is available for Suricata from OISF; **not** available for RITA. ClickHouse adds no copyleft risk but introduces trademark and (if SaaS) ClickHouse Cloud-vs-self-hosted commercial considerations.

> [!warning] Not legal advice
> This is a technical summary of licence obligations, not legal advice. Before commercialising, engage an IP lawyer with open-source licensing experience to review the final architecture, distribution model, and dependency tree. The Suricata + RITA + glue pattern is common in the NDR vendor space; specialist counsel will have seen it before.

## Component licence summary

| Component  | Licence        | Copyleft strength                | Commercial licence available?            |
|------------|----------------|----------------------------------|------------------------------------------|
| Zeek       | BSD 3-Clause   | None (permissive)                | N/A — not needed                         |
| ClickHouse | Apache 2.0     | None (permissive + patent grant) | N/A for the OSS engine; ClickHouse Cloud is a separate paid service |
| Suricata   | GPLv2          | Strong                           | Yes, via OISF consortium (Gold/Platinum) |
| RITA       | GPLv3          | Strong (stricter than v2)        | No known option                          |

Supporting components worth flagging:

| Component                                           | Licence       | Notes                                                                 |
|-----------------------------------------------------|---------------|-----------------------------------------------------------------------|
| dnsmasq                                             | GPLv2         | DHCP/DNS on the appliance ([Network Topology](../architecture/network-topology.md)); same arm's-length pattern as Suricata. Replaceable (Kea, systemd-networkd) if needed. |
| log2ram                                             | GPLv3         | Operational tooling on the appliance ([Log2Ram Usage](../architecture/log2ram-usage.md)); not bundled into a distributable artefact in any obvious commercial topology. |
| Flask + Jinja2                                      | BSD-3 / BSD-3 | Webapp framework ([Webapp](webapp.md)); permissive.                            |
| `clickhouse-connect` / `clickhouse-driver` (Python) | Apache 2.0    | Whichever client we settle on, both are permissive.                   |
| Chart.js                                            | MIT           | Frontend chart rendering; permissive.                                 |
| **FoxIO `zeek/foxio/ja4` plugin** + `ja4plus-mapping.csv` | Mixed: BSD-3 (JA4 only) / **FoxIO License 1.1** (JA4+ — JA4S/JA4H/JA4X/SSH/L/T/D/Scan/TScan)  + patent pending | **Critical for commercialisation.** Internal use today is fine. Any monetised distribution — direct or indirect — needs an OEM licence from FoxIO (`john@foxio.io`). See dedicated section below. |

## Per-component detail

### Zeek — BSD 3-Clause

Zeek is distributed under BSD 3-Clause, which allows free use with essentially no restrictions beyond preserving the copyright notice and disclaimer. Glue code that sits on top of Zeek can remain proprietary. Obligations are limited to including the BSD licence text and copyright notice in our distribution (typically a `NOTICES` file or About dialog).

No meaningful legal risk from Zeek.

### ClickHouse — Apache 2.0

ClickHouse is distributed under the Apache Licence 2.0, a permissive licence with no copyleft propagation. It allows free use, modification, and redistribution — including in closed-source commercial products — provided we:

- Preserve copyright notices and the licence text.
- Include a `NOTICE` file (Apache-2.0 §4(d)) reproducing any upstream `NOTICE` content.
- State significant modifications, if we modify the source.
- Acknowledge the explicit patent grant: by distributing ClickHouse we receive a patent licence from contributors covering the patents they hold in the contributed code; reciprocally, if we sue any contributor over patents reading on ClickHouse, our patent licence terminates. No practical impact unless we plan patent litigation.

**Non-licence considerations specifically for ClickHouse:**

1. **Trademark.** "ClickHouse" is a registered trademark of ClickHouse, Inc. Apache 2.0 explicitly does *not* grant trademark rights (§6). We can ship the binary, but marketing language like "ClickHouse Edition" or "Powered by ClickHouse™" needs care; describing it factually ("uses the ClickHouse columnar database") is fine, branding around it is not. Safe pattern: credit it in technical docs and a `NOTICES` file, keep the product brand independent.
2. **Licence change risk.** Several formerly-Apache database/analytics projects (Elasticsearch → SSPL/ELv2, Redis → RSALv2/SSPL, MongoDB → SSPL, HashiCorp tooling → BUSL) have re-licensed in the last few years to disrupt cloud competitors. ClickHouse, Inc. has so far kept the OSS engine on Apache 2.0 while monetising via ClickHouse Cloud. Pin to a specific version known to be Apache-2.0 and re-audit at every major upgrade — a future re-licence affects only new versions, not what we already shipped, but it would freeze our upgrade path.
3. **ClickHouse Cloud is a separate product.** The managed offering at clickhouse.com/cloud has its own commercial Terms of Service. Nothing about it constrains our use of the OSS engine. If we ever moved BeaconButty's storage to ClickHouse Cloud, that is a vendor-services contract, not a licensing matter.
4. **Bundled third-party code.** The ClickHouse source tree bundles vendored dependencies under various permissive licences (MIT, BSD, Boost, MPL, etc.) and a handful under LGPL. The aggregate `LICENSE` and `contrib/` tree should be reproduced in our `NOTICES` if we redistribute the binary. The standard `clickhouse-server` Debian package handles this for the binary itself.

No meaningful copyleft risk from ClickHouse. Main work item: a clean `NOTICES` file and a sensible trademark posture in marketing copy.

### Suricata — GPLv2

Strong copyleft. The Suricata engine and the bundled HTP library are GPLv2. If our product is considered a *derivative work* of Suricata (typically: dynamically or statically linked against its libraries, or tightly integrated such that the two form a single program), GPLv2 propagates to the whole combined work, which must then be distributed under GPLv2 with source code available.

**Important escape hatch:** OISF offers non-GPL commercial licensing through consortium membership. Gold and Platinum tier members receive a non-GPL Suricata licence that permits inclusion in closed-source commercial products. Priced at the consortium-membership level (not per-seat), so it's a fixed annual cost rather than a per-deployment one.

Worth pricing as a real option if Suricata ends up deeply integrated rather than at arm's length.

### RITA — GPLv3

The hardest case. RITA is licensed GPLv3, which is stricter than v2 in several ways:

- **Anti-Tivoization clause**: if we ship RITA on locked-down hardware/appliances, we must provide the installation information needed for users to install modified versions.
- **Broader patent grant**: distributing RITA grants recipients a patent licence covering any patents we hold that the software practises.
- **"Conveying" language**: broader than GPLv2's "distribution," capturing more forms of delivery.

No commercial/non-GPL licensing option from Active Countermeasures appears to exist. Their commercial offering is a separate product (AC-Hunter) built on similar ideas, not a dual-licensed RITA. The only way to ship RITA in a closed-source product is through an architecture that avoids triggering GPL obligations on our own code.

### FoxIO JA4 / JA4+ — split licence + patent pending

Added 2026-05-04 alongside the JA4 fingerprinting work (see *Upgrade Log* — "JA4 TLS fingerprinting"). FoxIO splits the JA4 ecosystem across two licences and the choice of which we use determines whether commercialisation is open-and-easy or requires a paid OEM agreement.

**The split:**

| Family | Licence | Patent | Commercial use |
|---|---|---|---|
| **JA4** (TLS client only — the field we read as `ssl.log:ja4`) | [BSD-3-Clause](https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE-JA4) | None | Unrestricted. |
| **JA4+** — JA4S, JA4H, JA4X, JA4SSH, JA4L, JA4LS, JA4T, JA4TS, JA4TScan, JA4Scan, JA4D, JA4D6 + future additions | [FoxIO License 1.1](https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE) | Patent pending | Permissive for **internal business** use. Any monetisation (direct or indirect) needs an OEM licence. |

**What BeaconButty consumes from FoxIO:**

- `ja4` field in `ssl.log` — BSD, fine commercially.
- `ja4s` field in `ssl.log` — **JA4+, FoxIO licensed.**
- `ja4plus-mapping.csv` (the threat-intel data at `/var/lib/beaconbutty/ja4db.csv`) — **JA4+, FoxIO licensed.** Contains the Cobalt Strike / Sliver / Havoc / Qakbot / etc. mappings that drive the JA4 Threat Matches panel and the `threat_intel_hit` Slack alerts.
- The Zeek `zeek/foxio/ja4` plugin code itself implements JA4+ algorithms — its use carries the FoxIO licence even though the source is openly published.

**What that means for the four distribution architectures discussed below:**

- **A — single appliance, no JA4+ stripped:** clean BSD island. Lose threat-family detection and cipher-family OS classification. Survives without an OEM.
- **A or B — single appliance with JA4+:** internal-use compliance OK if customer is not paying us for it. **Selling** an appliance that contains JA4+ requires an OEM licence — full stop, even if JA4+ output is internal-only and never surfaces in the UI. The FAQ is explicit about indirect monetisation triggering the requirement.
- **C — SaaS:** running BeaconButty on infrastructure we own and selling access definitionally requires an OEM. SaaS use of JA4+ is the single clearest "yes you need a licence" case in the FoxIO FAQ.
- **D — installer fetches at install time:** does **not** help here. The user-licence is for non-monetised use. If the end product is a paid offering, the act of distributing the installer (even when JA4+ is fetched separately) still triggers the requirement. Different from the GPL pattern.

**Practical commercialisation order:**

1. Email `john@foxio.io` (or the form at <https://www.fox-io.com/>) requesting an OEM licence quote. Lead time and pricing unknown — likely royalty-bearing or per-deployment fees.
2. While waiting / negotiating: build the BSD-only fallback fork. Strip `ja4s` consumption, the threat-match builder + panel, the threat-check timer, the cipher-family classifier, the threat badges across UI. Keep the BSD `ja4` field, the per-device JA4 history, the modal-fingerprint surfacing on Investigate / Inventory / Assets.
3. Decide commercial go-to-market with both options costed: OEM-bearing full-feature vs BSD-only reduced-capability. The threat-family alerting is the most user-visible loss in the BSD-only fork.

Patent claims on JA4+ methods mean re-implementing them ourselves doesn't sidestep the requirement — only the OEM licence resolves both copyright **and** patent in one transaction.

## Derivative-work vs aggregation

The single most important determination for BeaconButty. The FSF's own position:

- **Derivative work**: linking, tight integration into a single program, sharing data structures. GPL propagates.
- **Mere aggregation**: independent programs that happen to be distributed together, communicating at arm's length (files, pipes, sockets, CLI invocation). GPL applies only to the GPL components themselves.

Our integration pattern (see [Data Pipeline](../architecture/data-pipeline.md) and [Services](../architecture/services.md)) favours the aggregation reading:

- Zeek runs as a standalone daemon; we consume its log files.
- Suricata runs as a standalone daemon; we drive it via `suricata.yaml` and consume EVE JSON output.
- RITA is a standalone Go binary; we feed it Zeek logs, and it writes its results into ClickHouse over the network protocol.
- ClickHouse runs as a standalone daemon; we talk to it over its native TCP protocol or HTTP, executing SQL via a permissively-licensed client library. Even if ClickHouse were copyleft (it isn't), SQL-over-socket is squarely on the aggregation side of the FSF's line.
- Our Python glue ([Webapp](webapp.md), [Scripts & Timers](scripts-and-timers.md)) orchestrates separate processes — it does not link to Suricata, RITA, or ClickHouse code.

Under any reasonable reading, this is aggregation. The FSF explicitly considers pipe/file/socket IPC as arm's length.

However: **aggregation does not remove GPL obligations on the GPL components themselves**. If we convey Suricata and RITA binaries as part of our bundle, we still must:

1. Pass on the GPL terms for those components.
2. Provide complete corresponding source (or a written offer to supply it for at least three years under GPLv2; GPLv3 has its own mechanisms).
3. Preserve all copyright notices and licence texts.
4. Not impose any additional restrictions on recipients' rights under the GPL.
5. Not use DRM or technical measures that would prevent recipients from exercising their GPL rights (GPLv3-specific).

Our glue code can stay proprietary. Customers still get full GPL rights over the RITA and Suricata components in our bundle.

## Distribution architectures

### Option A — Installer fetches GPL components at runtime

Distributable contains only our proprietary glue code plus an installer. At install time, the installer downloads Zeek, Suricata, RITA, and ClickHouse from their official upstream sources (the projects' own apt/yum repos or release infrastructure).

Under this model, **we never convey the GPL software**. The user obtains it from the upstream projects directly. Our GPL obligations are effectively none — we're merely pointing at publicly available software. ClickHouse is permissive so this layer is incidental for it; we could equally bundle it with no licence consequences, but pulling it from the upstream `packages.clickhouse.com` repo is operationally simpler (security updates flow through apt) and keeps the installer pattern uniform across components.

Risk: if our installer materially modifies the downloaded GPL software, the modifications would themselves be GPL. Keep the installer to a plain download-and-install pattern; configuration via upstream-supported mechanisms only (config files, env vars, CLI flags). The same caution applies to ClickHouse — modifications would still be Apache-2.0 (no copyleft), but they create a maintenance fork.

This is the cleanest path and worth treating as the default.

### Option B — SaaS / managed service

GPLv2 and GPLv3 are both triggered by *conveying* (distributing) software, not by using it to provide a service. If customers interact with BeaconButty via a web UI or API hosted on our infrastructure, and they never receive GPL binaries from us, GPL obligations are largely inactive. ClickHouse is Apache-2.0 either way, so it imposes no SaaS-specific obligations.

> [!important] Critical SaaS audit gate
> Verify neither Suricata nor RITA — nor *ClickHouse* — has switched to AGPL, SSPL, BUSL, or any network-copyleft / source-available variant. AGPL extends copyleft obligations to network use specifically to close the SaaS gap; SSPL/BUSL are the database-vendor pattern aimed at exactly the SaaS topology we'd be running. A licence audit (and a re-audit on every major version) is required before relying on this.

Current state at time of writing: none of the four primary components has moved off its current licence. ClickHouse is the most plausible future re-licence candidate based on industry pattern, so pin the version in audit pipelines.

For SaaS specifically, two ClickHouse delivery options exist:

- **Self-hosted ClickHouse on our infra**: standard Apache-2.0 use; no extra terms.
- **ClickHouse Cloud as our backing store**: a vendor-services contract, governed by ClickHouse Cloud TOS rather than the OSS licence. A commercial decision (cost, ops burden, data residency) — not a licensing one.

### Option C — Bundle everything, accept GPL distribution obligations

Ship a single tarball/appliance image containing our glue code + Zeek + Suricata + RITA + ClickHouse. Glue code stays proprietary (on aggregation grounds). The GPL components (Suricata, RITA) remain GPL — we provide source for them, licence texts, and comply with GPLv3's installation-information requirement if we ship a locked-down appliance. ClickHouse adds to the `NOTICES` file but no source-distribution obligation.

Feasible but administratively heavier than A or B. Most meaningful for an on-premises appliance product where the operational simplicity for the customer justifies the compliance overhead on our side. The ClickHouse binary is large (~500 MB installed); if image size matters, that alone may push toward Option A.

### Option D — Buy a commercial Suricata licence, architect around RITA

If we buy the OISF commercial licence for Suricata, we remove one GPL constraint entirely. RITA remains GPLv3 — but if we isolate RITA to a separate process boundary and obtain it at install time (Option A pattern, applied only to RITA), we've cleanly separated the concerns. The right fit if Suricata needs deep integration (e.g., embedded as a library) but RITA can stay at arm's length. ClickHouse is irrelevant to this option — its permissive licence means we can integrate it however suits, including embedding via `clickhouse-local` or the (Apache-2.0) embedded library if a future architecture wanted that.

## Recommended path forward

For BeaconButty specifically, assuming the goal is a commercial closed-source product:

1. **Default architecture**: Option A. Python glue orchestrates Zeek, Suricata, RITA, and ClickHouse as separate processes. Installer pulls them from upstream apt repos. Glue code stays proprietary, no GPL propagation, minimal compliance overhead.
2. **If Suricata integration gets tight**: price OISF consortium membership. Gold tier is typically the right entry point for a commercial product.
3. **If going SaaS instead**: confirm AGPL/SSPL/BUSL status of all dependencies (including transitive, and including ClickHouse on every major upgrade) in a licence audit pipeline, re-run at every version bump.
4. **Do not** modify Suricata or RITA source unless prepared to contribute those modifications upstream or release them under GPL. A proprietary fork of either is legally possible but painful. ClickHouse modifications are legally fine (Apache-2.0) but create a maintenance fork.
5. **Do run** a full transitive dependency audit before commercialisation. `pip-licenses` for Python deps, `go-licenses` for RITA's Go dependencies, `licensecheck` for Suricata's and ClickHouse's C/C++ dependencies. A single AGPL or unusual-licensed transitive dep can reshape the picture.
6. **Branding hygiene**: never imply endorsement by Zeek, Suricata, RITA / Active Countermeasures, OISF, or ClickHouse Inc. Factual descriptive use only. Trademark issues bite earlier and harder than licence issues for a small commercial product.
7. **Maintain a `NOTICES` file** in the distributable from day one, even before commercialisation. Adding it later is tedious; adding it as you go is trivial. Should cover Zeek, ClickHouse, all Python deps, Chart.js, plus the GPL components if conveyed under Option C.

## Open questions

- [ ] Does the glue need to link to any Suricata library (e.g., `libsuricata`)? If yes → derivative work territory → OISF commercial licence likely required.
- [ ] Distribution model: download, appliance, or SaaS?
- [ ] Target customers: will any require on-prem deployment? That rules out pure SaaS.
- [ ] Do we ever need to modify RITA's scoring or detection logic? If yes, those modifications are GPLv3 and either stay private (we can't distribute the modified binary without releasing source) or get contributed upstream.
- [ ] Pricing model for us vs OISF Gold membership break-even: at what revenue does commercial Suricata pay for itself?
- [ ] ClickHouse delivery model in a SaaS topology: self-host on our infra, or use ClickHouse Cloud as the backing store? Cost vs ops trade-off, not a licensing one.
- [ ] Are we comfortable pinning to a specific ClickHouse major version with a re-audit gate at every upgrade, in case ClickHouse Inc. follows the Elastic/Redis/MongoDB re-licence pattern?
- [ ] **FoxIO OEM lead time and price** — request quote early; the threat-family alerting is the single most user-visible feature that depends on the JA4+ ecosystem. If quote is unworkable, scope out the BSD-only fork as a parallel build target.

## Related notes

- [System Overview](../architecture/system-overview.md) — design rationale, why ClickHouse
- [Data Pipeline](../architecture/data-pipeline.md) — the IPC boundaries that make aggregation hold
- [Services](../architecture/services.md) — daemon model that keeps each GPL component at arm's length
- *Public Repo* — separate but adjacent: pre-publish checklist for the OSS repo

## References

- Zeek licence: https://github.com/zeek/zeek/blob/master/COPYING
- Suricata licence: https://github.com/OISF/suricata/blob/main/LICENSE
- Suricata GPL FAQ: https://suricata.io/features/open-source/
- OISF consortium membership: https://oisf.net/
- RITA licence: https://github.com/activecm/rita (LICENSE file)
- ClickHouse licence: https://github.com/ClickHouse/ClickHouse/blob/master/LICENSE
- ClickHouse `NOTICE` / vendored deps: https://github.com/ClickHouse/ClickHouse/tree/master/contrib
- ClickHouse trademark policy: https://clickhouse.com/legal/trademark-policy
- ClickHouse Cloud terms: https://clickhouse.com/legal/agreements/terms-of-service
- FSF on aggregation vs derivative works: https://www.gnu.org/licenses/gpl-faq.html#MereAggregation
- Apache 2.0 text: https://www.apache.org/licenses/LICENSE-2.0
- FoxIO License 1.1: https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE
- FoxIO BSD JA4 sub-licence: https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE-JA4
- FoxIO Licensing FAQ: https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md
- FoxIO OEM contact: john@foxio.io · https://www.fox-io.com/
