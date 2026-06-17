# BeaconButty alert Lambda

Tiny AWS Lambda function that fronts the Slack alert pipeline. The
healthcheck and the various detectors POST to API Gateway; this Lambda
dedups on `(type, device, detail)` and forwards new alerts to a Slack
channel webhook.

## Build & deploy

```sh
cd aws/lambda
zip function.zip lambda_function.py
aws lambda update-function-code \
    --function-name beaconbutty-alert \
    --zip-file fileb://function.zip
```

## Environment

Set in the Lambda console (do not commit):

| Variable | Purpose |
|---|---|
| `SLACK_WEBHOOK_URL` | Slack incoming-webhook URL |
| `SHARED_SECRET`     | Bearer token the Pi sends in the `Authorization` header |
| `DEDUP_TTL_HOURS`   | How long to suppress repeat alerts (default 24) |

`SLACK_WEBHOOK_URL` is provisioned per-Slack-workspace; see
`docs/architecture/alert-chain.md` for the wiring diagram.
