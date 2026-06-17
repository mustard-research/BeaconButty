##! BeaconButty — site-local Zeek policy
##!
##! Loads exactly the log sources RITA needs for beacon analysis:
##!   conn.log   — the primary input (timing, bytes, duration)
##!   dns.log    — DNS beaconing / DGA detection
##!   ssl.log    — JA3 fingerprints, SNI, certificate subjects
##!   http.log   — HTTP C2 (user-agent, URIs)
##!   ssh.log    — reverse shell over SSH
##!
##! Intentionally excludes high-CPU scripts (SSL cert validation,
##! traceroute) that are too expensive for a Pi under load.

# ── Core protocol analysers ───────────────────────────────────────────────────
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/ssh
@load base/protocols/ftp
@load base/protocols/smtp

# ── File analysis ─────────────────────────────────────────────────────────────
@load base/files/x509        # TLS certificate logging
@load base/files/hash        # MD5/SHA1 of transferred files

# ── Frameworks ────────────────────────────────────────────────────────────────
@load base/frameworks/notice
@load base/frameworks/intel  # Placeholder for future threat feed integration

# ── Useful policy scripts ─────────────────────────────────────────────────────
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/ssl/log-hostcerts-only

# ── zkg-managed packages (JA4 fingerprinting, etc.) ───────────────────────────
@load packages

# ── BeaconButty: minimal ARP logger ───────────────────────────────────────────
# Zeek 8 fires ARP events but does not ship a logging script. arp-log.zeek in
# this directory creates arp.log; the webapp reads it for L2 anomaly detection
# (MAC↔IP changes, gateway impersonation, gratuitous-ARP storms).
@load ./arp-log

# ── Tuning for Raspberry Pi ───────────────────────────────────────────────────
# Increase the connection table expiry delay (default may be low for busy links)
redef table_expire_delay = 10 secs;
