# API reference by module

<!-- Generated from api/openapi.yaml by `make api-reference`. Do not edit by hand. -->

Every path is relative to `/scrs/v1`. A token needs **any one** of the scopes in the Access column, and `admin` satisfies every scope. The contract (`GET /scrs/v1/docs`) opens with the conventions, the states to show and worked call sequences, and describes every request, response and field; this page is only the index by module. See [STACK.md](STACK.md) for how the modules connect, [FRONTEND_GUIDE.md](FRONTEND_GUIDE.md) for the order to call things when building screens and [integrations/N8N.md](integrations/N8N.md) for automation.

## System

Health, readiness, metrics, platform status and this documentation.

`GET /system/healthz` and `/system/readyz` are public probes for load balancers. `GET /system/status` (token) rolls up every dependency (database, Redis, storage, scanner, SAST, QA runner) for a status banner; changes arrive as `system.degraded` and `system.recovered` events.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/docs` | public | Swagger UI |
| GET | `/docs/openapi.yaml` | public | OpenAPI document |
| GET | `/system/github-webhooks` | `read` | GitHub webhook delivery check state |
| POST | `/system/github-webhooks:check` | `admin` | Run the GitHub webhook delivery check now |
| GET | `/system/healthz` | public | Liveness probe |
| GET | `/system/metrics` | `read` | Prometheus metrics |
| GET | `/system/readyz` | public | Readiness probe |
| GET | `/system/status` | `read` or `write` | Platform status |

## Tokens

Create, list and revoke API tokens (admin).

A token has one or more scopes (`read`, `write`, `trigger`, `qa`, `ingest:relay`, `admin`), an optional IP allow-list and an optional expiry. The secret is returned once, by `POST /tokens`. Give each integration its own token so the audit log and `requested_by` say who did what.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/tokens` | `admin` | List API tokens |
| POST | `/tokens` | `admin` | Create an API token |
| DELETE | `/tokens/{id}` | `admin` | Revoke an API token |

## Connections

Accounts SCRS reads from: GitHub, GitLab, Docker Hub, Google Artifact Registry, Harbor and any OCI registry (admin).

Set-up order: `POST /connections` (credential is write-only), `POST /connections/{id}:test` to check it, `POST /connections/{id}:discover` to list what it can see, `POST /connections/{id}:webhook` to get the receiver URL and secret for inbound webhooks. The connection `scope` (include and exclude patterns) decides which discovered assets are assessed.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/connections` | `admin` | List connections |
| POST | `/connections` | `admin` | Create a connection |
| DELETE | `/connections/{id}` | `admin` | Disable a connection |
| GET | `/connections/{id}` | `admin` | Get a connection |
| PATCH | `/connections/{id}` | `admin` | Change scope or enable/disable |
| POST | `/connections/{id}:discover` | `admin` | Discover assets |
| POST | `/connections/{id}:rotate-credential` | `admin` | Replace the stored credential |
| POST | `/connections/{id}:test` | `admin` | Test provider access |
| POST | `/connections/{id}:webhook` | `admin` | Set or rotate a connection's webhook secret |

## Assets

The repositories, images and uploaded archives SCRS knows about, with the business context you give them.

Discovery fills the list; `PATCH /assets/{id}` sets owner, environment, criticality, exposure and labels (needs `If-Match`). Add something discovery does not list with `POST /assets`, `POST /assets:import` or `POST /uploads`. Per asset you also find its revisions, SBOM diff, licences, links between an image and its repository, GitHub Actions check, QA and SAST settings, and AI reviews.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/assets` | `read` | List assets |
| POST | `/assets` | `write` | Register an asset by hand |
| DELETE | `/assets/{id}` | `admin` | Delete a manually registered asset |
| GET | `/assets/{id}` | `read` or `write` | Get an asset |
| PATCH | `/assets/{id}` | `write` | Update owner and attributes |
| GET | `/assets/{id}/actions` | `read` or `write` | GitHub Actions inventory of a repository |
| POST | `/assets/{id}/actions:check` | `write` | Read a repository's Actions inventory now |
| GET | `/assets/{id}/last-known-good` | `read` or `write` | Last known good revision |
| GET | `/assets/{id}/links` | `read` or `write` | Image-to-source links of an asset |
| POST | `/assets/{id}/links` | `write` | Link an image to its source |
| DELETE | `/assets/{id}/links/{to}` | `write` | Remove an image-to-source link |
| GET | `/assets/{id}/revisions` | `read` or `write` | Assessed revisions of an asset |
| GET | `/assets/{id}/sbom-diff` | `read` or `write` | Compare the packages of two revisions |
| GET | `/assets/{id}/uploads` | `read` or `write` | Archives uploaded for an asset |
| DELETE | `/assets/{id}/uploads/{upload}` | `admin` | Delete an uploaded archive |
| POST | `/assets:import` | `write` | Register many assets |
| GET | `/owners` | `read` or `write` | List owners |
| POST | `/owners` | `write` | Create an owner |
| PATCH | `/owners/{id}` | `write` | Replace an owner's fields |
| POST | `/uploads` | `write` | Upload a source archive |

## Mirrors

Git history bundles of repository assets, kept so a repository can be restored after an incident. Request one with `POST /assets/{id}/mirrors`, poll it as a job, then download the bundle and check it against `X-Content-SHA256`.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/assets/{id}/mirrors` | `read` or `write` | List git mirrors of an asset |
| POST | `/assets/{id}/mirrors` | `write` | Mirror a repository now |
| GET | `/assets/{id}/mirrors/{mirror}/bundle` | `admin` | Download a git bundle |

## Assessments

Start, follow and list assessments.

`POST /assessments` queues one (answers `202`). Follow it with `GET /assessments/{id}?wait=30` or an `assessment.completed` event. `POST /assessments:batch` starts many with one result each. Set `skip_qa` to keep QA out of an assessment. Results are under **Assessment results**.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/assessments` | `read` or `write` or `trigger` | List assessments |
| POST | `/assessments` | `write` or `trigger` | Trigger an assessment |
| GET | `/assessments/latest` | `read` or `write` or `trigger` | Latest assessment for an asset or commit |
| DELETE | `/assessments/{id}` | `write` or `trigger` | Cancel a queued or running assessment |
| GET | `/assessments/{id}` | `read` or `write` or `trigger` | Get an assessment |
| POST | `/assessments:batch` | `write` or `trigger` | Trigger up to 100 assessments |

## Assessment results

What one assessment found: `findings`, `components` (packages), `files`, the SBOM and MBOM downloads, VEX, a Markdown `report` and the JSON `context` for automation and AI agents.

Open the verdict first (`GET /assessments/{id}`), then the tab the screen needs. `trigger` tokens can read only the assessments they started.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/assessments/{id}/components` | `read` or `write` or `trigger` | Components (packages) of an assessment |
| GET | `/assessments/{id}/context` | `read` or `write` or `trigger` | Context document for automation and AI agents |
| GET | `/assessments/{id}/files` | `read` or `write` or `trigger` | File evidence |
| GET | `/assessments/{id}/findings` | `read` or `write` or `trigger` | Findings of an assessment |
| GET | `/assessments/{id}/mbom` | `read` or `write` or `trigger` | CycloneDX MBOM (manufacturing BOM) |
| GET | `/assessments/{id}/report` | `read` or `write` or `trigger` | Human-readable report |
| GET | `/assessments/{id}/sbom` | `read` or `write` or `trigger` | SBOM (CycloneDX or SPDX) |
| GET | `/assessments/{id}/snapshot` | `admin` | Download the scanned source archive |
| GET | `/assessments/{id}/vex` | `read` or `write` or `trigger` | OpenVEX document |
| GET | `/sboms/{id}/download` | `read` or `write` | Download an SBOM |

## Imports

Record a report from another scanner (Trivy JSON or SARIF) as an assessment, so its findings join the same register. `POST /assessments:import`.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| POST | `/assessments:import` | `write` or `trigger` | Import a Trivy or SARIF report |

## Risk register

One list of findings across all assessments, deduplicated, with their triage lifecycle.

Screens: `GET /register` (filter by asset, status, severity, type, assignee), `GET /register/summary`, `/timeseries` and `/top-assets` for dashboards, `GET /register/export` for a download. Work on an entry: `PATCH /register/{id}` (status with a reason), `PUT /register/{id}/assignee`, `POST /register/{id}/comments`, and read `GET /register/{id}/events` for its history.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/register` | `read` or `write` | List register entries |
| GET | `/register/export` | `read` or `write` | Export register entries |
| GET | `/register/summary` | `read` or `write` | Register totals |
| GET | `/register/timeseries` | `read` or `write` | Findings detected and fixed per day |
| GET | `/register/top-assets` | `read` or `write` | Assets with the most open findings |
| GET | `/register/vex` | `read` or `write` | Register-wide VEX |
| PATCH | `/register/{id}` | `write` | Change a finding's status |
| PUT | `/register/{id}/assignee` | `write` | Assign a register entry |
| GET | `/register/{id}/comments` | `read` or `write` | Comments on a register entry |
| POST | `/register/{id}/comments` | `write` | Comment on a register entry |
| DELETE | `/register/{id}/comments/{comment}` | `admin` | Delete a comment |
| GET | `/register/{id}/events` | `read` or `write` | Finding history |

## Remediation

Guided fix plans for npm (`package-lock.json`) and Maven (`pom.xml`) manifests. `POST /assets/{id}/remediations` queues a plan; read it from `GET /assessments/{id}/remediation`. A plan is advice; SCRS never writes to a repository.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/assessments/{id}/remediation` | `read` or `write` or `trigger` | Remediation plan result |
| GET | `/assessments/{id}/remediations` | `read` or `write` or `trigger` | Automatic plans for an assessment |
| POST | `/assets/{id}/remediations` | `write` | Request a fix plan |
| GET | `/remediation/capabilities` | `read` or `write` | Supported fix-plan ecosystems |

## Ingest

Where GitHub, GitLab and registries send events (push, pull request, image push).

Each connection has its own receiver (`/ingest/<provider>/<connection>`), checked by signature or secret. Automation such as n8n can forward the unchanged body with an `ingest:relay` token instead. These calls queue assessments; a person does not call them.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| POST | `/ingest/github` | signature or secret, or `ingest:relay` | GitHub events (direct or relay) |
| POST | `/ingest/github/{connection}` | signature or secret, or `ingest:relay` | GitHub events for one connection |
| POST | `/ingest/gitlab` | signature or secret, or `ingest:relay` | GitLab events (direct or relay) |
| POST | `/ingest/gitlab/{connection}` | signature or secret, or `ingest:relay` | GitLab events for one connection |
| POST | `/ingest/registry/{provider}` | `ingest:relay` | Registry push events |
| POST | `/ingest/registry/{provider}/{connection}` | signature or secret | Registry push events for one connection |
| POST | `/webhooks/github` | signature or secret | GitHub webhook (direct) |

## Webhook subscriptions

Outbound webhooks: SCRS sends signed events to your URL (admin).

Create one with `POST /webhooks`, choose events and a payload profile, and keep the secret and `X-SCRS-Auth` value shown once. `POST /webhooks/{id}:test` sends a `ping`. The delivery log shows each attempt, and a `dead` delivery can be redelivered.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/schemas/events` | `read` or `write` or `trigger` | List event schemas |
| GET | `/schemas/events/{type}/{version}` | `read` or `write` or `trigger` | Get one event JSON Schema |
| GET | `/webhooks` | `admin` | List subscriptions |
| POST | `/webhooks` | `admin` | Create a subscription |
| DELETE | `/webhooks/{id}` | `admin` | Disable a subscription |
| GET | `/webhooks/{id}` | `admin` | Get a subscription |
| PATCH | `/webhooks/{id}` | `admin` | Update a subscription |
| GET | `/webhooks/{id}/deliveries` | `admin` | Delivery log |
| GET | `/webhooks/{id}/deliveries/{delivery}` | `admin` | Get one delivery |
| POST | `/webhooks/{id}/deliveries/{delivery}:redeliver` | `admin` | Redeliver an event |
| POST | `/webhooks/{id}:rotate-secret` | `admin` | Rotate the signing secret |
| POST | `/webhooks/{id}:test` | `admin` | Send a ping event |

## Threat intelligence

Threat data SCRS matches against what it scans: indicators of compromise (manual, STIX or a TAXII feed), YARA rulesets, advisory and malicious-package feeds, local advisories and imported VEX documents.

Sources and rulesets have a mode: `hunt` records matches without changing a verdict, `alert` gates by severity, `block` fails the verdict on any match. `alert` and `block` need `admin`.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/advisories` | `read` or `write` | Search advisories |
| POST | `/advisories` | `write` | Create a local advisory |
| GET | `/advisories/{id}` | `read` or `write` | Read one advisory |
| GET | `/advisories/{id}/affected` | `read` or `write` | Components a local advisory names |
| POST | `/advisories/{id}:withdraw` | `write` | Withdraw a local advisory |
| GET | `/feeds/indicators` | `admin` | Active indicator bundle |
| PUT | `/feeds/indicators` | `admin` | Import and activate an indicator bundle |
| GET | `/intel/indicator-sources` | `read` or `write` | Indicator sources |
| POST | `/intel/indicator-sources` | `write` | Create an indicator source |
| DELETE | `/intel/indicator-sources/{id}` | `write` | Delete an indicator source |
| GET | `/intel/indicator-sources/{id}` | `read` or `write` | Indicator source |
| PATCH | `/intel/indicator-sources/{id}` | `write` | Change an indicator source |
| GET | `/intel/indicator-sources/{id}/indicators` | `read` or `write` | A source's indicators |
| PUT | `/intel/indicator-sources/{id}/indicators` | `write` | Replace a source's indicators |
| GET | `/intel/indicator-sources/{id}/taxii` | `read` or `write` | TAXII feed settings and poll state |
| PATCH | `/intel/indicator-sources/{id}/taxii` | `admin` | Change a TAXII feed |
| POST | `/intel/indicator-sources/{id}:hunt` | `write` | Retro-hunt with a source |
| POST | `/intel/indicator-sources/{id}:import-csv` | `write` | Import indicators from CSV |
| POST | `/intel/indicator-sources/{id}:import-stix` | `write` | Upload a STIX 2.1 bundle |
| POST | `/intel/indicator-sources/{id}:poll` | `admin` | Poll a TAXII feed now |
| POST | `/intel/indicator-sources/{id}:test` | `admin` | Check a TAXII feed's settings |
| GET | `/intel/vex-documents` | `read` or `write` | List imported VEX documents |
| POST | `/intel/vex-documents` | `write` | Import a VEX document |
| DELETE | `/intel/vex-documents/{id}` | `admin` | Delete a VEX document |
| GET | `/intel/vex-statements` | `read` or `write` | Find vendor statements |
| GET | `/intel/vulnerabilities/{id}` | `read` or `write` | Everything known about a vulnerability |
| GET | `/intel/vulnerability-sources` | `read` or `write` | List vulnerability and advisory sources |
| GET | `/intel/vulnerability-sources/{key}` | `read` or `write` | Get one advisory source |
| PATCH | `/intel/vulnerability-sources/{key}` | `admin` | Enable, disable or reschedule a source |
| POST | `/intel/vulnerability-sources/{key}:sync` | `admin` | Sync an advisory source now |
| GET | `/intel/yara-rulesets` | `read` or `write` | YARA rulesets |
| POST | `/intel/yara-rulesets` | `write` | Create a YARA ruleset |
| DELETE | `/intel/yara-rulesets/{id}` | `write` | Delete a YARA ruleset |
| GET | `/intel/yara-rulesets/{id}` | `read` or `write` | YARA ruleset with its rules |
| PATCH | `/intel/yara-rulesets/{id}` | `write` | Change a YARA ruleset |
| POST | `/intel/yara-rulesets/{id}:hunt` | `write` | Retro-hunt with a ruleset |
| POST | `/intel/yara-rulesets:validate` | `write` | Compile YARA rules without saving |
| GET | `/policies/dependencies` | `read` or `write` | Dependency checks policy |
| PUT | `/policies/dependencies` | `admin` | Change the dependency checks |
| GET | `/policies/integrity` | `read` or `write` | Behavioural and size signals policy |
| PUT | `/policies/integrity` | `admin` | Change the integrity signals |

## Operations

Running the platform (admin): maintenance jobs, the inbound event log, retention of each data class, scheduled work, versions and the audit log.

Retention changes can be previewed with `POST /settings/retention:preview` before they are saved.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/audit` | `admin` | Query the audit log |
| GET | `/events/inbound` | `admin` | Inbound event log |
| GET | `/events/inbound/{id}` | `admin` | Get an inbound event |
| POST | `/events/inbound/{id}:replay` | `admin` | Replay an event's assessment |
| GET | `/incidents` | `read` or `write` | List incidents |
| POST | `/incidents` | `admin` | Sweep what an account touched |
| GET | `/incidents/{id}` | `read` or `write` | Read an incident |
| GET | `/jobs` | `read` or `write` | List background jobs |
| GET | `/jobs/{id}` | `read` or `write` | Read one job |
| POST | `/jobs/{id}:cancel` | `admin` | Cancel a job |
| POST | `/maintenance/rebuild` | `admin` | Re-assess current revisions |
| POST | `/maintenance/redeliver-dead` | `admin` | Requeue all dead deliveries |
| POST | `/maintenance/rescan` | `admin` | Rescan default branches |
| POST | `/maintenance/reset` | `admin` | Reset one scope of data |
| POST | `/maintenance/run` | `admin` | Run maintenance now |
| GET | `/maintenance/schedule` | `admin` | Scheduled jobs and their last runs |
| POST | `/maintenance/update-sensors` | `admin` | Refresh feeds now |
| GET | `/maintenance/versions` | `admin` | Platform versions and update check |
| GET | `/settings/retention` | `admin` | Get the retention policy |
| PUT | `/settings/retention` | `admin` | Set the retention policy |
| POST | `/settings/retention:preview` | `admin` | Preview what a retention change deletes |
| POST | `/settings/retention:purge` | `admin` | Apply the retention policy now |

## E2E QA

Functional (Karate), load (Gatling) and lint QA of a repository against its deployed environment, with API coverage, report-only findings and AI-drafted tests.

**Runs.** A profile (`PUT /assets/{id}/qa/profile`) says where to test and what to run. Runs start two ways: automatically when an assessment finishes (profile `auto_run`), or on request with `POST /assets/{id}/qa/runs`. `kind: full` runs everything the profile configures. A run is a job: poll `GET /qa/runs/{id}`, then read scenarios, coverage and the report. Lint and test failures become `qa_*` entries in the risk register; they never change a verdict.

**With or without a security assessment.** By default a manual run tests a commit that passed an assessment, and a `fail` verdict blocks it. An admin can set the profile `gate` to `none` so QA runs on its own against the head of a ref. To keep QA out of one assessment, send `skip_qa` on `POST /assessments`. A token with only the `qa` scope can start and read QA and nothing else.

**Lint.** The profile's `lint.tools` choose among ruff, mypy, bandit, pylint, phpstan, phpcs, clang-tidy, golangci-lint, eslint, ktlint, swiftlint and dart-analyze. `GET /qa/runner` lists what the runner has installed.

**Runner.** The QA runner is a separate service on its own host, with its own token. An operator can also call it directly (`POST /v1/jobs`) for jobs that are not stored here. The runner does no vulnerability, malware or SBOM work. Details: `docs/QA_TESTING.md`.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/assessments/{id}/qa` | `read` or `write` or `trigger` or `qa` | QA runs of an assessment |
| GET | `/assets/{id}/qa/coverage` | `read` or `write` or `qa` | API coverage history of a repository |
| GET | `/assets/{id}/qa/generations` | `read` or `write` or `qa` | List a repository's test generations |
| POST | `/assets/{id}/qa/generations` | `write` | Draft tests with the profile's LLM |
| DELETE | `/assets/{id}/qa/profile` | `admin` | Remove a repository's QA profile |
| GET | `/assets/{id}/qa/profile` | `read` or `write` or `qa` | Get a repository's QA profile |
| PUT | `/assets/{id}/qa/profile` | `admin` | Create or replace a repository's QA profile |
| GET | `/assets/{id}/qa/runs` | `read` or `write` or `qa` | List a repository's QA runs |
| POST | `/assets/{id}/qa/runs` | `write` or `trigger` or `qa` | Run QA tests now |
| GET | `/assets/{id}/qa/suites` | `read` or `write` or `qa` | List generated test files |
| GET | `/qa/generations/{id}` | `read` or `write` or `trigger` or `qa` | Get a test generation and its files |
| GET | `/qa/generations/{id}/files` | `read` or `write` or `trigger` or `qa` | Download a generation's files |
| GET | `/qa/runner` | `read` or `write` or `trigger` or `qa` | Karate runner status |
| GET | `/qa/runs/{id}` | `read` or `write` or `trigger` or `qa` | Get a QA run |
| GET | `/qa/runs/{id}/coverage` | `read` or `write` or `trigger` or `qa` | API coverage of a QA run |
| GET | `/qa/runs/{id}/report` | `read` or `write` or `trigger` or `qa` | Download a QA run's reports |
| GET | `/qa/runs/{id}/scenarios` | `read` or `write` or `trigger` or `qa` | Scenarios of a QA run |
| GET | `/qa/runs/{id}/triage` | `read` or `write` or `trigger` or `qa` | Triage jobs of a QA run |
| POST | `/qa/runs/{id}/triage` | `write` | Ask a model to triage a finished QA run |
| POST | `/qa/runs/{id}:cancel` | `write` or `trigger` or `qa` | Cancel a QA run |
| GET | `/qa/suites/{id}` | `read` or `write` or `trigger` or `qa` | Get a generated test file |
| POST | `/qa/suites/{id}:approve` | `admin` | Approve a generated test file |
| POST | `/qa/suites/{id}:reject` | `write` | Reject a generated test file |

## Licences

Licence inventory per asset, the policy that decides allow, review or deny by how the software is distributed, category overrides and third-party notices. A policy aid, not legal advice.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/assets/{id}/licenses` | `read` or `write` | Asset licence inventory |
| GET | `/assets/{id}/licenses/notices` | `read` or `write` | Third-party notices file |
| GET | `/licenses/categories` | `read` or `write` | Licence categories |
| PUT | `/licenses/categories` | `admin` | Replace category overrides |
| GET | `/licenses/categories/history` | `read` or `write` | Category override history |
| GET | `/policies/gate` | `read` or `write` | Default gate rules |
| GET | `/policies/license` | `read` or `write` | Active licence policy |
| PUT | `/policies/license` | `admin` | Replace the licence policy |
| POST | `/policies/license:evaluate` | `read` or `write` | Try a licence against the policy |
| GET | `/reports/licenses` | `read` or `write` | Licence report |
| GET | `/schemas/{name}` | `read` or `write` or `trigger` | Policy and pack JSON Schemas |

## Compliance reports

Evidence reports for OWASP Top 10, CWE Top 25, PCI DSS and imported DISA STIG, as JSON, CSV, Markdown or PDF. Evidence for assessors, not certification.

Flow: `GET /reports/frameworks`, then `POST /reports` with a framework and a scope (asset, owner or portfolio); poll `GET /reports/{id}` until `succeeded`, then download it.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| DELETE | `/frameworks/{id}` | `admin` | Delete an uploaded pack |
| GET | `/frameworks/{id}` | `read` or `write` | Get a framework pack |
| GET | `/reports` | `read` or `write` | List evidence reports |
| POST | `/reports` | `write` | Request an evidence report |
| GET | `/reports/frameworks` | `read` or `write` | List framework packs |
| POST | `/reports/frameworks` | `admin` | Upload a framework pack |
| POST | `/reports/frameworks/stig` | `admin` | Import a DISA STIG benchmark |
| GET | `/reports/{id}` | `read` or `write` | Get a report job |
| GET | `/reports/{id}/download` | `read` or `write` | Download a report |

## Integrations

Optional two-way link to OWASP Dependency-Track. SCRS uploads each SBOM and, when enabled, reads back what Dependency-Track found and shares triage decisions. SCRS never depends on it being reachable.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/integrations/dependency-track` | `read` or `write` | Dependency-Track export settings |
| PUT | `/integrations/dependency-track` | `admin` | Configure the Dependency-Track export |
| GET | `/integrations/dependency-track/findings` | `read` or `write` | Dependency-Track findings and their register entries |
| GET | `/integrations/dependency-track/uploads` | `read` or `write` | List SBOM uploads |
| POST | `/integrations/dependency-track/uploads/{id}/retry` | `admin` | Retry a failed upload |
| POST | `/integrations/dependency-track:sync` | `admin` | Read Dependency-Track findings now |
| POST | `/integrations/dependency-track:test` | `admin` | Test the Dependency-Track connection |

## Live events

Server-sent events for a browser UI: short notices that something changed (`GET /events`).

Events carry ids to fetch, not full payloads, and missed events are not replayed: reload the screen when you connect and on `resync`. Webhooks remain the guaranteed delivery path. A browser `EventSource` cannot send an `Authorization` header, so read the stream with `fetch`.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/events` | `read` or `write` | Stream live events |

## SAST

Static analysis of repository source with bundled analyzers (gosec, Bandit, OpenGrep, Bearer), Go call-graph reachability and npm and PyPI import-level reachability. They run in an isolated container without SCRS secrets. Settings apply platform-wide and per asset.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/assets/{id}/sast` | `read` or `write` | Asset SAST settings |
| PUT | `/assets/{id}/sast` | `write` | Replace asset SAST settings |
| GET | `/reachability/capabilities` | `read` or `write` | Reachability capabilities |
| GET | `/sast/analyzers` | `read` or `write` | Bundled analyzers |
| GET | `/sast/rulesets` | `read` or `write` | Custom OpenGrep rulesets |
| POST | `/sast/rulesets` | `write` | Upload a custom ruleset |
| DELETE | `/sast/rulesets/{id}` | `admin` | Delete a ruleset |
| GET | `/sast/rulesets/{id}` | `read` or `write` | Get a ruleset |
| GET | `/sast/settings` | `read` or `write` | Deployment SAST settings |
| PUT | `/sast/settings` | `admin` | Replace deployment SAST settings |

## LLM providers

Model services that draft QA tests, summarise assessments and review code (admin): OpenAI, Anthropic, Gemini, Azure OpenAI, Mistral, Groq, DeepSeek, xAI, OpenRouter, Together, Ollama or any OpenAI-compatible server. `GET /llm/presets` lists known services.

**Where code may go.** Each provider has a read-only `locality`: `local` is a model server you run (its host is in `SCRS_LLM_PRIVATE_HOSTS`), `hosted` is any other. `source_allowed` says whether it may be sent **source code** (AI review, unit-test generation). A `local` provider always may. A `hosted` provider may only after the platform switch `SCRS_LLM_ALLOW_SOURCE_TO_HOSTED=true` is on and an administrator has called `POST /llm/providers/{id}:allow-source` with a `note` that records why; `:revoke-source` withdraws it, and so does changing the provider's `base_url`. Both steps are audited. Summaries and advisories need neither: the model sees only finding IDs, titles, severities, package names and versions, fixed versions and upstream advisory text, never code, evidence, file paths, secrets or AI review entries.

**Declared in the environment.** Providers can be declared at deploy time (`SCRS_LLM_PROVIDERS`, `SCRS_LLM_PROVIDER_<NAME>_*`). They show `managed_by_environment: true`; an administrator can only enable or disable them here.

**Screening and trust.** Every prompt and answer passes a guard that redacts credentials, keys, tokens and the platform's own secrets and removes images, scripts and tracking links from answers. It is a safety net, not a guarantee. Model output is not verified: findings are report-only `ai_review` entries marked `unverified` and never change a verdict.

**Budget.** Model work stops at the assessment's token ceiling (`SCRS_LLM_ASSESSMENT_INPUT_TOKENS`, `SCRS_LLM_ASSESSMENT_OUTPUT_TOKENS`) and says so in `incomplete`. A hosted provider, billed per token, also has a monthly cap across all its work (`SCRS_LLM_MONTHLY_INPUT_TOKENS`, `SCRS_LLM_MONTHLY_OUTPUT_TOKENS`, calendar month UTC); work resumes next month or when you raise it. A self-hosted provider has no cap. An answer cut off at the provider's `max_tokens` does not count as a review of that file.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/llm/presets` | `read` or `write` | List supported LLM provider kinds |
| GET | `/llm/providers` | `read` or `write` | List LLM providers |
| POST | `/llm/providers` | `admin` | Add an LLM provider |
| DELETE | `/llm/providers/{id}` | `admin` | Delete an LLM provider |
| GET | `/llm/providers/{id}` | `read` or `write` | Get an LLM provider |
| PATCH | `/llm/providers/{id}` | `admin` | Change an LLM provider |
| POST | `/llm/providers/{id}:allow-source` | `admin` | Allow source code to go to a hosted provider |
| POST | `/llm/providers/{id}:revoke-source` | `admin` | Withdraw the source-code acknowledgement |
| POST | `/llm/providers/{id}:test` | `admin` | Check an LLM provider |

## Advisories and summaries

A language model writes an **assessment summary** (headline, risk level, priorities, progress since the last summary) and an **advisory** (explanation, recommended action, urgency) for the most important findings of an assessment. Use any provider; the model sees only findings and advisory text, never code (see the data policy in the API overview).

Flow: `POST /assessments/{id}/summaries` with a `provider_id`, poll `GET /summary-jobs/{id}` until `status` is `succeeded` or `failed`, then read the results in the asset's chronicle: `GET /assets/{id}/chronicle`.

**The chronicle** is the history of an asset's written advisories, summaries and reviews, oldest first. A new summary or advisory *supersedes* the one before it: the old one is kept, marked with `superseded_at`, and the new one names it in `supersedes`, so you can follow a risk from first advisory to fix. Every document has `origin: llm` when a model wrote it, and `provenance` (model, provider, prompt version, what the guard removed). Texts are written by a model from the findings and are not verified.

Which findings are described: vulnerabilities (SCRS's own and Dependency-Track's), malicious dependencies, licence, integrity and configuration findings. Not described, only counted: code analysis (SAST), secret detection, AI code review entries, malware, YARA and IOC matches, QA entries.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/assessments/{id}/summaries` | `read` or `write` | List an assessment's summary jobs |
| POST | `/assessments/{id}/summaries` | `write` or `trigger` | Write advisories and a summary for an assessment |
| GET | `/assets/{id}/chronicle` | `read` or `write` | The asset's chronicle of advisories, summaries and reviews |
| GET | `/assets/{id}/chronicle/search` | `read` or `write` | Search the chronicle by meaning |
| POST | `/knowledge:backfill` | `admin` | Index documents that have no vectors |
| GET | `/summary-jobs/{id}` | `read` or `write` | Get a summary job |

## AI review

A language model reads the source of an assessed commit and reports production risks, logic bugs, lint-class problems, security weaknesses and performance problems as report-only register entries of type `ai_review`.

**Source code goes to a provider whose `source_allowed` is true**: a self-hosted model (`locality` `local`), or a hosted provider the platform and an administrator have both opted in (see the data policy in the API overview). Each review records where its source went in `locality`. The review is advisory: entries are marked `unverified`, never change a verdict, and carry the file, lines, category, confidence, a plain explanation and a suggested fix, never code. Each review also writes a summary to the asset's chronicle (`GET /assets/{id}/chronicle`). Flow: `POST /assets/{id}/ai-reviews`, poll `GET /ai-reviews/{id}` until `status` is `succeeded` or `failed`, then list the entries with `GET /register?asset_id=` and look for `type: ai_review`. The QA runner's lint entries (`qa_lint`) are separate, and the review shows the model each file's lint findings as context.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/ai-reviews/{id}` | `read` or `write` | Get an AI code review |
| GET | `/assets/{id}/ai-reviews` | `read` or `write` | List an asset's AI code reviews |
| POST | `/assets/{id}/ai-reviews` | `write` or `trigger` | Review the code with a self-hosted model |

