"""
BeaconButty Alert Lambda
Receives alert POSTs from the Pi, deduplicates via DynamoDB, posts to Slack.

Environment variables:
  SLACK_WEBHOOK_URL   — Slack incoming webhook URL
  DYNAMODB_TABLE      — DynamoDB table name (default: beaconbutty-alerts)
  SHARED_SECRET       — Must match X-BeaconButty-Secret header from Pi
  DEDUP_HOURS_HIGH    — Dedup window for high severity (default: 6)
  DEDUP_HOURS_MEDIUM  — Dedup window for medium severity (default: 1)
"""

import json
import os
import time
import urllib.request
import urllib.error
import hashlib
import boto3
from datetime import datetime, timezone

SLACK_WEBHOOK_URL = os.environ["SLACK_WEBHOOK_URL"]
DYNAMODB_TABLE    = os.environ.get("DYNAMODB_TABLE", "beaconbutty-alerts")
SHARED_SECRET     = os.environ["SHARED_SECRET"]
DEDUP_HOURS_HIGH  = int(os.environ.get("DEDUP_HOURS_HIGH", "6"))
DEDUP_HOURS_MEDIUM = int(os.environ.get("DEDUP_HOURS_MEDIUM", "1"))
SOURCE_HOST       = os.environ.get("SOURCE_HOST", "beaconbutty")

ddb = boto3.resource("dynamodb", region_name="eu-west-1")
table = ddb.Table(DYNAMODB_TABLE)

SEVERITY_EMOJI = {
    "high":   "🔴",
    "medium": "🟡",
    "low":    "🟢",
}

ALERT_TYPE_LABELS = {
    "high_score_beacon":    "New High-Score Beacon",
    "persistent_beacon":    "Persistent Beacon",
    "threat_intel_hit":     "Threat Intelligence Hit",
    "suricata_p1_lan":      "P1 Suricata Alert — LAN Device",
    "suricata_p1_repeated": "P1 Suricata Alert — Repeated",
    "new_device":           "New LAN Device",
    "traffic_anomaly":      "Traffic Anomaly",
    "tor_contact":          "Tor Exit Node Contact",
    "service_down":         "Service Down",
    "disk_critical":        "Disk Space Critical",
    "health_check_fail":    "Health Check Failed",
    "teams_relay_anomaly":  "Teams Relay Anomaly (DragonForce pattern)",
    "slow_cadence_beacon":  "Slow-Cadence Beacon",
    "slow_cadence_digest":  "Slow-Cadence Daily Digest",
    "gateway_impersonation": "Gateway Impersonation (ARP)",
    "sustained_high_cpu":   "Sustained High CPU",
    "config_invalid":       "Config File Invalid",
    "config_stray_files":   "Stray Config Files",
}


def lambda_handler(event, context):
    # ── Auth ──────────────────────────────────────────────────────────────────
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    if headers.get("x-beaconbutty-secret") != SHARED_SECRET:
        return {"statusCode": 403, "body": "Forbidden"}

    # ── Parse body ────────────────────────────────────────────────────────────
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return {"statusCode": 400, "body": "Bad JSON"}

    alert_type = body.get("type", "unknown")
    severity   = body.get("severity", "medium").lower()
    device     = body.get("device", "unknown")
    detail     = body.get("detail", "")
    timestamp  = body.get("timestamp", datetime.now(timezone.utc).isoformat())

    # ── Deduplication ─────────────────────────────────────────────────────────
    # Full detail (an 80-char prefix conflated long-FQDN details) and
    # severity (an escalation must page even inside the medium window).
    fingerprint = hashlib.sha256(
        f"{alert_type}:{severity}:{device}:{detail}".encode()
    ).hexdigest()[:32]

    dedup_hours = DEDUP_HOURS_HIGH if severity == "high" else DEDUP_HOURS_MEDIUM
    now_ts  = int(time.time())
    expires = now_ts + (dedup_hours * 3600)

    try:
        resp = table.get_item(Key={"fingerprint": fingerprint})
        item = resp.get("Item")
        # DynamoDB TTL deletion is lazy (can lag by days) — enforce the
        # window ourselves or an expired item over-suppresses.
        if item and int(item.get("expires_at", 0)) > now_ts:
            return {"statusCode": 200, "body": "Deduplicated"}
    except Exception as e:
        print(f"DynamoDB read error: {e}")

    # ── Format Slack message ──────────────────────────────────────────────────
    emoji = SEVERITY_EMOJI.get(severity, "⚪")
    label = ALERT_TYPE_LABELS.get(alert_type, alert_type.replace("_", " ").title())

    # Parse timestamp for display
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        ts_display = dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        ts_display = timestamp

    slack_payload = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} BeaconButty — {label}",
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity*\n{severity.title()}"},
                    {"type": "mrkdwn", "text": f"*Device*\n`{device}`"},
                    {"type": "mrkdwn", "text": f"*Detail*\n{detail}"},
                    {"type": "mrkdwn", "text": f"*Time*\n{ts_display}"},
                ]
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"BeaconButty · {SOURCE_HOST}"}
                ]
            }
        ]
    }

    # ── Post to Slack ─────────────────────────────────────────────────────────
    try:
        req = urllib.request.Request(
            SLACK_WEBHOOK_URL,
            data=json.dumps(slack_payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()
    except urllib.error.HTTPError as e:
        print(f"Slack HTTP error: {e.code} {e.reason}")
        return {"statusCode": 502, "body": f"Slack error: {e.code}"}
    except Exception as e:
        print(f"Slack post error: {e}")
        return {"statusCode": 502, "body": str(e)}

    # Record the dedup fingerprint only AFTER Slack accepted the post — a
    # write before a failed post would swallow every retry/recurrence for
    # the whole dedup window.
    try:
        table.put_item(Item={
            "fingerprint": fingerprint,
            "expires_at":  expires,
            "alert_type":  alert_type,
            "device":      device,
            "created_at":  now_ts,
        })
    except Exception as e:
        print(f"DynamoDB write error: {e}")

    print(f"Alert sent: {alert_type} / {severity} / {device}")
    return {"statusCode": 200, "body": "OK"}
