# n8n integration (TRG-014)

SCRS and n8n talk in both directions. n8n forwards GitHub events into SCRS
(relay) or asks for assessments (trigger). SCRS pushes signed events back
(outbound webhooks), so workflows never have to poll in a loop. SCRS never
writes to GitHub; commit statuses and PR comments come from n8n using its own,
separately scoped credential.

Importable workflows live next to this file:

| File | What it does |
| --- | --- |
| [`scrs-github-relay.json`](scrs-github-relay.json) | GitHub organization webhook → SCRS `/ingest/github` (relay mode) |
| [`scrs-assessment-completed.json`](scrs-assessment-completed.json) | SCRS `assessment.completed` → verify signature → commit status / alert on `fail` |
| [`scrs-nightly-reconcile.json`](scrs-nightly-reconcile.json) | Nightly `POST /maintenance/rescan` so missed events are re-assessed |

After import, set the credentials and the `SCRS_BASE_URL` value noted in each workflow.

## 1. One-time setup

```bash
BASE=https://scrs.example.com/scrs/v1
# Relay token: provider endpoints only. Restrict it to n8n's egress IP.
curl -sX POST "$BASE/tokens" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"name":"n8n-relay","scopes":["ingest:relay"],"ip_allow_list":["203.0.113.10/32"]}'
# Read token for the completion workflow (fetching findings, report, context).
curl -sX POST "$BASE/tokens" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"name":"n8n-reader","scopes":["read"]}'
# Outbound subscription. The response contains the signing secret once.
curl -sX POST "$BASE/webhooks" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"name":"n8n-main","url":"https://auto-hooks.example.com/webhook/scrs-events","events":["assessment.completed","assessment.failed","integrity.alert","feed.stale","connection.degraded"]}'
curl -sX POST "$BASE/webhooks/$SUBSCRIPTION_ID:test" -H "Authorization: Bearer $ADMIN"   # sends a ping
```

Set `SCRS_RELAY_ENABLED=true` on the API. If n8n runs in the same Docker
network as SCRS and you want plain HTTP to it, add its hostname to
`SCRS_WEBHOOK_PRIVATE_HOSTS`; otherwise subscriptions must use public HTTPS.

## 2. Relay GitHub events into SCRS

GitHub's HMAC covers the exact bytes it sent, so the relay must forward the
**unchanged body** and the `X-GitHub-Event` and `X-GitHub-Delivery` headers:

- **Webhook node:** HTTP method `POST`, Respond `Immediately`, and enable the
  **Raw Body** option so the original bytes are kept as binary.
- **HTTP Request node:** `POST {{SCRS_BASE_URL}}/scrs/v1/ingest/github`, with
  these settings:
  - **Authentication:** Header Auth credential `Authorization: Bearer <relay token>`.
  - **Body:** "n8n Binary File" using the webhook's binary data.
  - **Headers:** `X-GitHub-Event: {{$json.headers["x-github-event"]}}` and
    `X-GitHub-Delivery: {{$json.headers["x-github-delivery"]}}`.

The delivery GUID is the idempotency key, so n8n retries never double-scan.
SCRS answers `202` (queued), `200` (replay, integrity-only event, tag or
out-of-scope repository) or `4xx/5xx` (fix and retry). Pushes and PRs create
assessments; force pushes, deletions, membership and visibility changes, and
campaign-pattern matches create `integrity.alert` events immediately.

Equivalent without n8n: point a second organization webhook straight at
`/scrs/v1/webhooks/github` with `SCRS_GITHUB_WEBHOOK_SECRET`.

## 3. Act on completion events

Every delivery carries these headers:

| Header | Meaning |
| --- | --- |
| `X-SCRS-Event` | Event type, e.g. `assessment.completed` |
| `X-SCRS-Signature` | `sha256=` HMAC-SHA256 of the **exact body** with the subscription secret |
| `Idempotency-Key` | Event id; identical across retries and redeliveries |
| `X-SCRS-Delivery` | Delivery id (differs per subscription) |

Verify before trusting the payload. In a **Code** node placed after a Webhook
node with **Raw Body** enabled:

```javascript
const crypto = require('crypto');
const secret = $env.SCRS_WEBHOOK_SECRET;            // or a credential
const raw = Buffer.from($input.first().binary.data.data, 'base64');
const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(raw).digest('hex');
const given = $input.first().json.headers['x-scrs-signature'] || '';
if (given.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(given), Buffer.from(expected))) {
  throw new Error('Invalid SCRS signature');
}
return [{ json: JSON.parse(raw.toString('utf8')) }];
```

(n8n's Code node needs `NODE_FUNCTION_ALLOW_BUILTIN=crypto` for `require('crypto')`.)

Then branch on `data.assessment.verdict`:

| Verdict | Suggested action |
| --- | --- |
| `fail` | Block promotion: failing commit status, Slack/Telegram alert with `data.links.report` |
| `incomplete` | Neutral status ("partial coverage"); never treat as pass |
| `warn` | Passing status with a warning comment |
| `pass` | Passing status |

For GitHub statuses use `data.assessment.repository`, `data.assessment.commit`
and n8n's own GitHub credential. `GET {links.report}` returns Markdown sized
for a PR comment. For an AI triage agent, create the subscription with
`"profile":"agent","egress_ack":true`: `assessment.completed` then carries the
bounded context document, with `instructions_notice` and `untrusted_paths`
listing every string that came from outside SCRS.

## 4. Reconcile after outages

GitHub and registries do not guarantee delivery. The nightly workflow calls
`POST /scrs/v1/maintenance/rescan` (admin token), which queues the default
branch of every in-scope repository not assessed recently. Alternatively set
`SCRS_RESCAN_INTERVAL_HOURS` and let the worker do it. To re-assess specific
targets from n8n, use `POST /scrs/v1/assessments:batch` with up to 100 items,
each with its own `idempotency_key`; the response reports each item's status.
