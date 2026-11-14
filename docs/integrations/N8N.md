# n8n integration (TRG-014)

SCRS and n8n talk in both directions. n8n forwards GitHub, GitLab and registry
events into SCRS (relay) or asks for assessments (trigger). SCRS pushes signed events back
(outbound webhooks), so workflows never have to poll in a loop. SCRS never
writes to GitHub; commit statuses and PR comments come from n8n using its own,
separately scoped credential.

Importable workflows live next to this file:

| File | What it does |
| --- | --- |
| [`scrs-github-relay.json`](scrs-github-relay.json) | GitHub organization webhook → SCRS `/ingest/github` (relay mode, signature forwarded) |
| [`scrs-gitlab-relay.json`](scrs-gitlab-relay.json) | GitLab group webhook → SCRS `/ingest/gitlab` (relay mode, token forwarded) |
| [`scrs-registry-relay.json`](scrs-registry-relay.json) | Docker Hub webhook or GAR Pub/Sub push → SCRS `/ingest/registry/{provider}` |
| [`scrs-assessment-completed.json`](scrs-assessment-completed.json) | SCRS `assessment.completed` → Header Auth → commit status by verdict |
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
# Outbound subscription. The response contains the signing secret and the
# X-SCRS-Auth header value once.
curl -sX POST "$BASE/webhooks" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"name":"n8n-main","url":"https://auto-hooks.example.com/webhook/scrs-events","events":["assessment.completed","assessment.failed","integrity.alert","feed.stale","connection.degraded"]}'
curl -sX POST "$BASE/webhooks/$SUBSCRIPTION_ID:test" -H "Authorization: Bearer $ADMIN"   # sends a ping
```

Set `SCRS_RELAY_ENABLED=true` on the API. If n8n runs in the same Docker
network as SCRS and you want plain HTTP to it, add its hostname to
`SCRS_WEBHOOK_PRIVATE_HOSTS`; otherwise subscriptions must use public HTTPS.

## 2. Trigger assessments from any workflow (inbound)

`POST /scrs/v1/assessments` is the inbound automation endpoint. Use it when an
event that is not a provider webhook (release request, ticket, chat command,
schedule) should start an assessment:

- **Authentication:** Header Auth credential `Authorization: Bearer <token>`
  with scope `trigger`, created with `ip_allow_list` set to n8n's egress IP.
  `trigger` tokens can read and cancel only the assessments they created.
- **Target:** must be a discovered, in-scope asset on an enabled connection;
  anything else returns `404`, so a workflow cannot point SCRS at arbitrary
  repositories or registries.
- **Idempotency:** send the source event id as `Idempotency-Key`. A retry
  returns `200` with `Idempotent-Replayed: true`; the same key with a different
  body returns `409`.
- **Context:** `trigger.origin`, `event`, `delivery_id`, `actor` and up to 20
  `context` keys travel with the assessment and come back in
  `data.assessment.trigger` of `assessment.completed`.

```json
{"target":{"type":"git","repository":"acme/api","ref":"main"},
 "trigger":{"origin":"n8n","event":"release.requested","delivery_id":"{{$execution.id}}",
            "actor":"release-bot","context":{"ticket":"CHG-1042","environment":"prod"}}}
```

Use `/assessments:batch` for up to 100 targets in one call. For an image, send
`{"type":"image","repository":"docker.io/acme/api","ref":"1.4.2"}`.

## 3. Relay GitHub events into SCRS

GitHub's HMAC covers the exact bytes it sent, so the relay must forward the
**unchanged body** and the `X-GitHub-Event`, `X-GitHub-Delivery` and
`X-Hub-Signature-256` headers. When the signature is forwarded and
`SCRS_GITHUB_WEBHOOK_SECRET` is configured, SCRS verifies it, so neither n8n
nor anything between it and GitHub can alter or forge events. Without the
header or without the secret, the relay token alone is trusted.

- **Webhook node:** HTTP method `POST`, Respond `Immediately`, and enable the
  **Raw Body** option so the original bytes are kept as binary.
- **HTTP Request node:** `POST {{SCRS_BASE_URL}}/scrs/v1/ingest/github`, with
  these settings:
  - **Authentication:** Header Auth credential `Authorization: Bearer <relay token>`.
  - **Body:** "n8n Binary File" using the webhook's binary data.
  - **Headers:** `X-GitHub-Event`, `X-GitHub-Delivery` and
    `X-Hub-Signature-256`, each copied from `{{$json.headers[...]}}`.

The delivery GUID is the idempotency key, so n8n retries never double-scan.
SCRS answers `202` (queued), `200` (replay, integrity-only event, tag or
out-of-scope repository) or `4xx/5xx` (fix and retry). Pushes and PRs create
assessments; force pushes, deletions, membership and visibility changes, and
campaign-pattern matches create `integrity.alert` events immediately.

Equivalent without n8n: point a second organization webhook straight at
`/scrs/v1/webhooks/github` with `SCRS_GITHUB_WEBHOOK_SECRET`.

### GitLab

GitLab group webhooks (Push, Tag push and Merge request events) can call
`/scrs/v1/ingest/gitlab` directly with the "Secret token" set to
`SCRS_GITLAB_WEBHOOK_SECRET`, or go through `scrs-gitlab-relay.json`, which
forwards `X-Gitlab-Event`, `Idempotency-Key`, `X-Gitlab-Event-UUID` and
`X-Gitlab-Token` (verified by SCRS when the secret is configured). GitLab's
`Idempotency-Key` is the idempotency key, since it is stable across retries of
one delivery; the event UUID, which recursive hooks share, is the fallback for
GitLab versions that do not send it. GitLab does not report force
pushes; deletions, branch churn, mass deletions and pattern matches still alert.

### Container registries

`/scrs/v1/ingest/registry/{harbor|dockerhub|gar|oci}` queues an image
assessment per pushed manifest (`ingest:relay` token):

- **Harbor:** project → Webhooks → HTTP, event "Artifact pushed", Auth Header
  `Bearer <relay token>`. Calls SCRS directly, no n8n needed.
- **Docker Hub, GAR:** neither can send an Authorization header. Import
  `scrs-registry-relay.json`, set the n8n variable `SCRS_REGISTRY_PROVIDER`
  (`dockerhub` or `gar`), and point the Docker Hub webhook or the GAR Pub/Sub
  push subscription (topic `gcr`) at the workflow URL.
- **registry:2, Zot, Nexus (`oci`):** configure CNCF Distribution
  notifications with the relay token as an `Authorization` header.

Retried deliveries of the same body replay the same assessments.

## 4. Act on completion events

Every delivery carries these headers:

| Header | Meaning |
| --- | --- |
| `X-SCRS-Event` | Event type, e.g. `assessment.completed` |
| `X-SCRS-Signature` | `sha256=` HMAC-SHA256 of the **exact body** with the subscription secret |
| `Idempotency-Key` | Event id; identical across retries and redeliveries |
| `X-SCRS-Delivery` | Delivery id (differs per subscription) |

| `X-SCRS-Auth` | Static per-subscription value for receivers that can only compare a header |

**In n8n** (no Code node or `NODE_FUNCTION_ALLOW_BUILTIN` needed): set the
Webhook node's **Authentication** to *Header Auth* with a credential named
`X-SCRS-Auth` whose value is `auth_header.value` from the subscription's create
or `rotate-secret` response. n8n then rejects calls without it. The
`scrs-assessment-completed.json` workflow is set up this way.

`X-SCRS-Auth` authenticates the sender. `X-SCRS-Signature` additionally binds
the body; receivers that can compute HMAC (your own services) should verify it:

```javascript
const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
// compare with the X-SCRS-Signature header in constant time
```

Then branch on `body.event.type` and `body.data.assessment.verdict`:

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

## 5. Reconcile after outages

GitHub and registries do not guarantee delivery. The nightly workflow calls
`POST /scrs/v1/maintenance/rescan` (admin token), which queues the default
branch of every in-scope repository not assessed recently. Alternatively set
`SCRS_RESCAN_INTERVAL_HOURS` and let the worker do it. To re-assess specific
targets from n8n, use `POST /scrs/v1/assessments:batch` with up to 100 items,
each with its own `idempotency_key`; the response reports each item's status.
