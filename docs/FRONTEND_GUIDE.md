# Frontend guide

How to build a Web UI on the SCRS API. The contract is `api/openapi.yaml` (served at
`/scrs/v1/docs`, raw YAML at `/scrs/v1/docs/openapi.yaml` while docs are enabled). The
per-endpoint listing is [API_REFERENCE.md](API_REFERENCE.md). This page is the order in
which to call things.

Every path below is relative to `/scrs/v1`.

## 1. Set up the client

- **Generate types.** Feed `openapi.yaml` to `openapi-typescript` or `orval`. Schemas
  carry realistic `example` values, so mock servers (Prism, MSW generators) return
  plausible data without extra work. A contract test checks every example against its
  schema.
- **Base URL.** Same origin through Traefik is simplest. A separate origin needs its exact
  origin in `SCRS_CORS_ORIGINS` (no wildcards); otherwise the browser blocks the call.
  Readable response headers: `Location`, `ETag`, `Retry-After`, `X-Next-Cursor`,
  `X-Request-Id`, `Idempotent-Replayed`.
- **Errors.** Every failure is `{"error": "<message>"}`. Show the message; log
  `X-Request-Id` for support.
- **Rate limit.** 120 requests per token per minute. On `429`, wait `Retry-After` seconds.
  Prefer the aggregate endpoints (section 4) over looping the list endpoints.

## 2. Authentication and roles

Send `Authorization: Bearer <token>`. Tokens have one or more scopes; the UI should hide
what the token cannot do.

| Scope | A user with it can |
| --- | --- |
| `read` | View everything below, including live events and `GET /system/status`. |
| `write` | Also trigger assessments, triage findings, edit assets and owners, request reports, edit QA, SAST and local advisories. |
| `admin` | Also manage tokens, connections, webhooks, retention, waivers (`accepted`, `suppressed`, `false_positive`), LLM providers, integrations, the audit log. |
| `trigger` | Queue assessments and QA runs only (automation, not a person). |
| `qa` | Only the QA screens: read QA profiles, runs, reports and coverage, start or cancel runs. It cannot see assessments, findings or assets, so it suits a QA pipeline or a QA-only back-office role. |

Give a browser session a `read` or `write` token, never `admin`, unless it is the
operator console. `POST /tokens` (admin) returns the secret once; store it only in memory
or a secure cookie handled by your backend. A `401` means sign in again; a `403` means the
token lacks a scope, so do not retry.

Which scope each operation needs is in its `security` field and in its description
("Scope `write`").

## 3. First-run flow (operator console)

1. `GET /system/status` shows what is configured (database, Redis, worker, ClamAV, QA runner).
   Poll it on the settings page; `system.degraded` and `system.recovered` arrive on `/events`.
2. `POST /connections` adds a GitHub, GitLab or registry account. `POST /connections/{id}:test`
   checks the credential. `POST /connections/{id}:webhook` sets the inbound webhook secret.
3. `POST /connections/{id}:discover` (admin) lists repositories or images and answers when the
   inventory is reconciled (`discovered`, `in_scope` counts; `502` if the provider refuses). The connection `scope`
   (include and exclude globs) decides `flags.in_scope`; only in-scope assets are assessed.
4. `GET /assets` lists them (`next_cursor` pagination). `PATCH /assets/{id}` sets owner,
   environment, criticality and exposure. Use `POST /assets` or `POST /assets:import` (up to
   500, per-item results) for something discovery does not list.
5. Optional: `PUT /integrations/dependency-track`, `/llm/providers`, `/webhooks` (outbound).

## 4. Everyday screens

### Dashboard

| Widget | Call |
| --- | --- |
| Totals, open counts by severity and type, expiring waivers | `GET /register/summary` |
| Trend chart (detected and fixed per day) | `GET /register/timeseries?days=30` |
| Worst assets | `GET /register/top-assets` |
| Platform health banner | `GET /system/status` |

These accept the same filters as `GET /register` (asset, status, severity, type), so a
dashboard can be scoped to one asset or team's assets. The timeseries counts detections and
fixes per day, not the number open at the end of that day; label the chart accordingly.

### Assets

- List and detail: `GET /assets`, `GET /assets/{id}`.
- Image and source: `GET /assets/{id}/links` on an image shows the repository it was built from
  (`direction: out`); on a repository it lists the images built from it (`direction: in`). `POST` sets one by
  hand (`repository` path or `to_asset_id`), `DELETE /assets/{id}/links/{to}` removes it. Links also appear by
  themselves when an image carries a source label (`source: oci_label`, a claim by the publisher). An image's
  register entries carry `source_repository`.
- Revision history: `GET /assets/{id}/revisions` (each ref and commit with its newest
  verdict). Pick two and call `GET /assets/{id}/sbom-diff?from=<commit or assessment id>&to=...`
  for added, removed, version-changed and licence-changed packages.
- Last good revision: `GET /assets/{id}/last-known-good?ref=main`.
- Delete: `DELETE /assets/{id}` works only for assets added by hand with no history. A
  `409` message says why; show it. An uploaded asset can be deleted the same way while it has never been assessed.
- Source that is not in a repository: `POST /uploads` (`multipart/form-data`: `name`, `file` as
  `.tar.gz` up to 64 MiB, optional `ref` and `assess=false`). It creates or reuses the asset
  `upload/<name>` (type `uploaded`) and queues an assessment; each distinct archive is a revision
  (`GET /assets/{id}/uploads`, `/revisions`, `/sbom-diff`); an admin removes one with
  `DELETE /assets/{id}/uploads/{upload}` (its past results stay). The response carries `asset`, `upload`
  and `assessment`, or `assessment_error` when the archive was kept but not queued. Show uploaded
  assets without a repository link; there is no connection to open (the built-in one is hidden).

### Run a scan and follow it

1. `POST /assessments` with `{target: {type: "git", repository: "acme/api", ref: "main"}}`.
   It answers `202` with the assessment (`status: queued`). Send an `Idempotency-Key` so a
   double click does not queue two.
2. Wait for completion with live events (below), or poll `GET /assessments/{id}` every few
   seconds until `status` is `succeeded`, `failed` or `cancelled`.
3. Show `verdict` (`fail` > `incomplete` > `warn` > `pass`; a partial scan is never `pass`),
   `stages` (which checks ran, and which were partial or skipped) and `counts`.
4. Detail tabs: `/assessments/{id}/findings`, `/components`, `/files`, `/sbom` and `/mbom`
   (downloads), `/vex`, `/report`.

### Risk register

- `GET /register` lists findings with filters and `cursor` pagination.
- `GET /register/{id}/events` is the finding's history.
- Assignment and discussion: `PUT /register/{id}/assignee` sets or clears who holds an entry.
  SCRS has no user model, so the assignee is a string your UI chooses (email, username or team)
  and filters with `assignee=` or `unassigned=true`; `GET`/`POST /register/{id}/comments` lists
  and adds notes. A comment's `author` is the token's name; send `on_behalf_of` with the signed-in
  person's name, which is stored as claimed. `assignee` and `comment_count` appear on register
  and asset listings, not on an assessment's frozen findings. Only an admin can delete a comment.
- `PATCH /register/{id}` changes status with a reason (8 to 2000 characters). Moving to
  `accepted` needs `admin` and `expires_at` within 90 days. An accepted finding whose waiver
  has expired counts as `open` in the aggregates.
- `GET /register/export?format=csv|json` for a download (50,000 rows at most; JSON sets
  `truncated`) and `GET /register/vex` for one OpenVEX document of the filtered register.
- Finding `type` decides which fields to show: `vulnerability` has `advisory_id` and
  `guidance` (fixed and safe versions); `license`, `sast`, `secret`, `ai_review`, `qa_*` and
  the rest are listed in the `Finding` schema.

### Advisories

- Search: `GET /advisories?q=&origin=&ecosystem=&package=`. One advisory: `GET /advisories/{id}`
  (also `GET /intel/vulnerabilities/{id}`).
- Local advisories (for example an internal package found compromised): `POST /advisories`
  with explicit `versions` or `all_versions: true`. SCRS assigns `x_SCRS-<year>-<n>`.
  `GET /advisories/{id}/affected` shows which stored components match. A local advisory opens
  register entries at once (`register_entries_opened` in the response) and at each later scan; use
  `malicious: true` for a compromised package, which fails the verdict. Withdrawing closes the entries.
- Withdraw with `POST /advisories/{id}:withdraw` (kept and audited).

### Jobs

`GET /jobs` is one newest-first list of everything queued or finished (assessments, QA runs and
generation, AI summaries and reviews, reports, mirrors, Dependency-Track uploads), for a status
page or a "what is stuck" view. Use `status` (`queued`, `running`, `succeeded`, `failed`,
`cancelled`, the same for every kind) and `kind` to filter, and `resource` to open the full
record. `POST /jobs/{id}:cancel` (admin) stops an assessment or QA run. It does not replace
the per-kind endpoints, which carry the results. It lists work, not schedules:
`GET /maintenance/schedule` has those.

### Integrity and incidents

- Integrity entries are register entries of `type=integrity` (filter `GET /register?type=integrity`).
  Their advisory ids tell the source: `SCRS-EVENT-*` from webhooks and the Actions check
  (`AUTHOR-NEW`, `AUTHOR-OFF-HOURS`, `PUSHER-DIFFERS-FROM-AUTHOR`, `RUN-NUMBER-GAP`,
  `ACTIONS-WORKFLOWS-CHANGED`, `FORCE-PUSH` and others), `SCRS-WORKFLOW-CHANGE`, `SCRS-LARGE-NEW-FILE` and
  `SCRS-CI-FILE-GROWTH` from scans. Authors and actors are claims in the event, never verified identities.
- Settings page: `GET`/`PUT /policies/integrity` and `/policies/dependencies` (admin to change, `If-Match`
  required). Every signal starts off.
- Repository page: `GET /assets/{id}/actions` (404 until a check has run) and `POST /assets/{id}/actions:check`
  for "check now". `available: false` with a `reason` means the credential lacks the Actions permission.
  `flags.actions_unused` on the asset marks a repository with Actions off or no workflows.
- Incident response: `POST /incidents` (admin) with `actors` and `since` returns a report (what they touched,
  signals, branches and pull requests, workflow and install-hook changes, last known good and mirrors to restore
  from) and queues fresh scans; `GET /incidents/{id}` shows the report with the live state of those scans.
  The sweep only reads: containment is manual.

### QA screens

QA runs functional (Karate), load (Gatling) and lint checks against a deployed environment. Results never
change a verdict.

- **Profile page** (per repository): `GET`/`PUT /assets/{id}/qa/profile` (`PUT` needs `admin` and `If-Match`).
  Fields to show: `base_url`, `refs`, `auto_run`, `functional`, `lint.tools`, `perf`, `ai_triage` and `gate`.
  Build the linter picker from `GET /qa/runner` (`runner.lint_tools`: only the linters installed on the runner).
  `gate: assessment` (default) tests commits that passed a security assessment; `gate: none` lets QA run on
  its own, so label it clearly ("runs without a security scan").
- **Run list:** `GET /assets/{id}/qa/runs` with `kind` and `status` filters; page with `before` and
  `next_before`. On an assessment page use `GET /assessments/{id}/qa`.
- **Start a run:** `POST /assets/{id}/qa/runs` with `kind` `full`, `functional`, `performance` or `lint`.
  With `gate: none` add `ref` (a branch the profile covers; empty is the default branch). `full` answers
  `{runs: [...]}`; the others answer one run. Show the `409` message (no enabled profile, no assessed commit,
  or a `fail` verdict) and the `400` message (what the profile still lacks).
- **Run detail:** poll `GET /qa/runs/{id}` until `status` is final (`passed`, `failed`, `error`, `cancelled`,
  `skipped`). A run with `assessment_id: null` was not tied to an assessment; `commit` fills in when the worker
  starts it. Then `GET /qa/runs/{id}/scenarios?status=failed`, `/coverage` and `/report` (download).
- **Trend:** `GET /assets/{id}/qa/coverage` is one point per finished functional run.
- **Lint results** are register entries: `GET /register?type=qa_lint` (one per tool, rule and file; `evidence`
  lists the lines). `type=qa_lint_config` means a linter could not run or its result is incomplete, so show it as
  a setup warning rather than a code problem.
- **AI triage** (`ai_triage` on the profile) writes a summary to the asset's chronicle, but only for runs tied
  to an assessment; a run without one answers `409` on `POST /qa/runs/{id}/triage`.
- **Security-only assessment.** `skip_qa: true` on `POST /assessments` keeps QA out of that assessment. Offer it
  as a checkbox on the "Assess now" dialog.

### Reports, licences, SAST, AI

- Ask the chronicle: `GET /assets/{id}/chronicle/search?q=...` returns the nearest chunks of the asset's
  advisories, summaries and reviews with a `score`; show `unindexed_documents` as "N documents not searchable yet"
  and offer admins `POST /knowledge:backfill` (call until `remaining` is 0). `503` means no embedding server.
- Reports: `POST /reports` returns a job; add `params.include_ai_summaries: true` to append each asset's newest
  AI-written summary (always labelled unverified; json, md and pdf only); poll `GET /reports/{id}` until `succeeded`, then
  `GET /reports/{id}/download`. Frameworks come from `GET /reports/frameworks`.
- Licences: `GET /assets/{id}/licenses`, policy at `/policies/license`.
- SAST and reachability: `/sast/settings`, `/assets/{id}/sast`. A vulnerability entry's `evidence.reachability.status` is `reachable`, `imported_only`, `not_reachable`, `unknown` or `unsupported` with a `method` (`call_graph` for Go, `import_graph` for npm and PyPI); never treat `unknown` as safe. QA: `/assets/{id}/qa/*`, runs at `/qa/runs/{id}`.
- AI summaries and code review: `POST /assessments/{id}/summaries`,
  `POST /assets/{id}/ai-reviews`. Both are jobs; poll `GET /summary-jobs/{id}` and
  `GET /ai-reviews/{id}`. They need an enabled provider (`GET /llm/providers`); a hosted
  provider needs the operator's source-code acknowledgement before code review.

## 5. Live updates

`GET /events` is a `text/event-stream`. Browser `EventSource` cannot send an
`Authorization` header, so read it with `fetch` and a streaming reader (for example
`@microsoft/fetch-event-source`).

- It opens with `ready` and sends a heartbeat comment every 20 seconds.
- It ends after 10 minutes with `reconnect`; reconnect right away.
- Events are notices, not payloads: `data` holds ids (`refs`) to fetch. Missed events are not
  replayed, so reload the screen's state when you connect and on `resync`.
- Filter with `?types=assessment.completed,finding.created`.
- A token may hold only a couple of streams at once (`429` beyond that); share one stream across the page rather than one per
  component.

## 6. Conventions that affect UI code

- **Pagination.** `{items, next_cursor}`; pass `cursor` until it is empty. The connection list
  returns its cursor in the `X-Next-Cursor` header. Revisions use `next_before` and `before`.
- **Optimistic concurrency.** Mutable resources return an `ETag`. Send it back in `If-Match`
  on `PATCH` and `PUT`. `428` means you did not send one; `409` means someone else changed it,
  so reload and re-apply the edit.
- **Idempotency.** `POST` triggers accept `Idempotency-Key`. A replay inside 24 hours answers
  `200` with `Idempotent-Replayed: true`.
- **Async work.** Assessments, reports, summaries, reviews and QA runs answer
  quickly with a job or resource in `queued`. Treat `queued` and `running` as in progress.
- **Secrets are never returned.** Connection credentials, provider API keys, webhook secrets
  and token secrets are write-only. Show `has_api_key`, `webhook.configured` and `prefix`.
- **Times.** RFC 3339 UTC. Dates only (`day`) in timeseries.
- **Empty lists, not 404.** A list under an asset or assessment that does not exist (qa runs, mirrors,
  chronicle, revisions, webhook deliveries and similar) answers `200` with empty `items`. A single
  resource, such as `GET /assessments/{id}/findings`, answers `404`. Check the parent when you need to tell them apart.
- **Unknown fields.** Ignore properties you do not know; new ones are added without a version
  change.

## 7. Not available yet

These have no endpoint, so do not design screens that depend on them: comment editing, and finding assignment notifications. See `docs/PRD_PROGRESS_AND_AUDIT.md` for the
full list.

## 8. Finding things in the API docs

The docs page (`/scrs/v1/docs`) opens with every area collapsed. Use the filter box to find an
operation by name or path, or open an area. Each area starts with the flow its screens follow, the
states to show and, where one helps, a recipe:

| Building | Open |
| --- | --- |
| Dashboard and risk screens | **Risk register**, **Assets**, **Assessments**, **Assessment results**, **System** |
| Following any long-running work | **Jobs** (poll one place for assessments, QA, AI work, reports and mirrors) |
| QA screens | **QA setup**, **QA runs**, **QA test generation** |
| Automation and n8n | **Assessments**, **Webhook subscriptions** (including email), **Ingest**, **Jobs** |
| Threat data | **Indicators of compromise**, **YARA rulesets**, **Vulnerability data and VEX**, **Policies** |
| Administration | **Connections**, **Tokens**, **Maintenance**, **Retention**, **Audit and inbound events**, **Incidents** |

Every JSON response carries an example. Responses that have none yet are tracked by the quality
gate in `api/docs_quality_test.go`, which only lets that number go down. The schemas section at the
bottom of the docs page lists every type for client generation. The page is read-only on purpose
(no "Try it out"): call the API from your own client with a token of the narrowest scope.
