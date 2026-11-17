# API reference by module

<!-- Generated from api/openapi.yaml by `make api-reference`. Do not edit by hand. -->

Every path is relative to `/scrs/v1`. A token needs **any one** of the scopes in the Access column, and `admin` satisfies every scope. See [STACK.md](STACK.md) for how the modules connect, and the contract (`GET /scrs/v1/docs`) for request and response schemas.

## System

Health, readiness, metrics and these docs.

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

API tokens and their scopes (admin).

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/tokens` | `admin` | List API tokens |
| POST | `/tokens` | `admin` | Create an API token |
| DELETE | `/tokens/{id}` | `admin` | Revoke an API token |

## Connections

Provider connections (GitHub, GitLab, Docker Hub, GAR, Harbor, OCI) and discovery (admin).

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

Discovered repositories and images, their owners and operator attributes.

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

Git history bundles of repository assets for incident restore.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/assets/{id}/mirrors` | `read` or `write` | List git mirrors of an asset |
| POST | `/assets/{id}/mirrors` | `write` | Mirror a repository now |
| GET | `/assets/{id}/mirrors/{mirror}/bundle` | `admin` | Download a git bundle |

## Assessments

Trigger, track and list supply-chain assessments.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/assessments` | `read` or `write` or `trigger` | List assessments |
| POST | `/assessments` | `write` or `trigger` | Trigger an assessment |
| GET | `/assessments/latest` | `read` or `write` or `trigger` | Latest assessment for an asset or commit |
| DELETE | `/assessments/{id}` | `write` or `trigger` | Cancel a queued or running assessment |
| GET | `/assessments/{id}` | `read` or `write` or `trigger` | Get an assessment |
| POST | `/assessments:batch` | `write` or `trigger` | Trigger up to 100 assessments |

## Assessment results

Findings, components, SBOM, reports and machine-readable documents of one assessment.

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

Record external scanner reports (Trivy, SARIF) as assessments.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| POST | `/assessments:import` | `write` or `trigger` | Import a Trivy or SARIF report |

## Risk register

Deduplicated findings across assessments and their triage lifecycle.

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

Guided npm and Maven fix plans. Plans are advice; SCRS never writes to repositories.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/assessments/{id}/remediation` | `read` or `write` or `trigger` | Remediation plan result |
| GET | `/assessments/{id}/remediations` | `read` or `write` or `trigger` | Automatic plans for an assessment |
| POST | `/assets/{id}/remediations` | `write` | Request a fix plan |
| GET | `/remediation/capabilities` | `read` or `write` | Supported fix-plan ecosystems |

## Ingest

Provider and registry events (direct webhooks or relayed through automation such as n8n).

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

Outbound event subscriptions, delivery log and redelivery (admin).

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

Versioned indicator-of-compromise bundles (admin).

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

Maintenance, inbound event log and retention (admin).

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

Karate API, integration, UI and load testing of each assessed repository against its deployed environment, with API coverage, report-only findings and LLM-drafted tests.

**Two ways to use the runner.** (1) Through this API: a successful assessment queues a run, and results, coverage and `qa_*` findings are stored here. (2) Directly, by an operator: the runner is also published on its own hostname (limited to an IP allowlist, `Authorization: Bearer` with the runner token, not an API token) and accepts `POST /v1/jobs` (multipart `spec` and `bundle`), `GET /v1/jobs/{id}`, `GET /v1/jobs/{id}/report`, `DELETE /v1/jobs/{id}` and `GET /v1/info` for standalone functional (Karate API, UI) and performance (Gatling) jobs. Direct jobs use the runner's slots but are not recorded by this API: no run, finding, event or archive. The runner does no vulnerability, malware, SBOM or MBOM work, and has no lint job kind. Contract and examples: `docs/QA_TESTING.md`.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/assessments/{id}/qa` | `read` or `write` or `trigger` | QA runs of an assessment |
| GET | `/assets/{id}/qa/coverage` | `read` or `write` | API coverage history of a repository |
| GET | `/assets/{id}/qa/generations` | `read` or `write` | List a repository's test generations |
| POST | `/assets/{id}/qa/generations` | `write` | Draft tests with the profile's LLM |
| DELETE | `/assets/{id}/qa/profile` | `admin` | Remove a repository's QA profile |
| GET | `/assets/{id}/qa/profile` | `read` or `write` | Get a repository's QA profile |
| PUT | `/assets/{id}/qa/profile` | `admin` | Create or replace a repository's QA profile |
| GET | `/assets/{id}/qa/runs` | `read` or `write` | List a repository's QA runs |
| POST | `/assets/{id}/qa/runs` | `write` or `trigger` | Run QA tests now |
| GET | `/assets/{id}/qa/suites` | `read` or `write` | List generated test files |
| GET | `/qa/generations/{id}` | `read` or `write` or `trigger` | Get a test generation and its files |
| GET | `/qa/generations/{id}/files` | `read` or `write` or `trigger` | Download a generation's files |
| GET | `/qa/runner` | `read` or `write` or `trigger` | Karate runner status |
| GET | `/qa/runs/{id}` | `read` or `write` or `trigger` | Get a QA run |
| GET | `/qa/runs/{id}/coverage` | `read` or `write` or `trigger` | API coverage of a QA run |
| GET | `/qa/runs/{id}/report` | `read` or `write` or `trigger` | Download a QA run's reports |
| GET | `/qa/runs/{id}/scenarios` | `read` or `write` or `trigger` | Scenarios of a QA run |
| POST | `/qa/runs/{id}:cancel` | `write` or `trigger` | Cancel a QA run |
| GET | `/qa/suites/{id}` | `read` or `write` or `trigger` | Get a generated test file |
| POST | `/qa/suites/{id}:approve` | `admin` | Approve a generated test file |
| POST | `/qa/suites/{id}:reject` | `write` | Reject a generated test file |

## Licences

Licence inventory, normalisation, categories and policy by distribution model, third-party notices. A policy aid, not legal advice.

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

OWASP Top 10, CWE Top 25, PCI DSS and imported DISA STIG evidence reports from framework packs, as JSON, CSV, Markdown or PDF. Evidence for assessors, not certification.

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

Optional two-way link to OWASP Dependency-Track. SCRS uploads each SBOM, then (when enabled) reads back what Dependency-Track found, joins it with its own register entries, and shares triage decisions. SCRS never depends on it being reachable.

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

Server-sent events for frontends (OUT-004). Fire-and-forget notices of committed events; webhooks remain the guaranteed delivery path.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/events` | `read` or `write` | Stream live events |

## SAST

Bundled static analyzers (gosec, Bandit, OpenGrep, Bearer) and Go reachability, run in the scrs-sast sandbox without SCRS secrets.

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

Model endpoints (OpenAI, Anthropic, Gemini, Azure OpenAI, Mistral, Groq, DeepSeek, xAI, OpenRouter, Together, Ollama or any OpenAI-compatible server) that draft QA tests and review code (admin).

Each provider has a read-only `locality`: `local` is a model server you run, whose host is listed in `SCRS_LLM_PRIVATE_HOSTS`; `hosted` is any other provider. Both can exist side by side, and either can be declared in the deployment's environment (`managed_by_environment`).

`source_allowed` says whether the provider may be sent **source code** (AI review, unit-test generation). A `local` provider always may. A `hosted` provider may only after the platform switch `SCRS_LLM_ALLOW_SOURCE_TO_HOSTED=true` is on and an administrator has called `POST /llm/providers/{id}:allow-source`; `POST /llm/providers/{id}:revoke-source` withdraws it. Findings and advisory text, the input of advisories and summaries, need neither.

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
| GET | `/summary-jobs/{id}` | `read` or `write` | Get a summary job |

## AI review

A language model reads the source of an assessed commit and reports production risks, logic bugs, lint-class problems, security weaknesses and performance problems as report-only register entries of type `ai_review`.

**Source code goes to a provider whose `source_allowed` is true**: a self-hosted model (`locality` `local`), or a hosted provider the platform and an administrator have both opted in (see the data policy in the API overview). Each review records where its source went in `locality`. The review is advisory: entries are marked `unverified`, never change a verdict, and carry the file, lines, category, confidence, a plain explanation and a suggested fix, never code. Each review also writes a summary to the asset's chronicle (`GET /assets/{id}/chronicle`). Flow: `POST /assets/{id}/ai-reviews`, poll `GET /ai-reviews/{id}` until `status` is `succeeded` or `failed`, then list the entries with `GET /register?asset_id=` and look for `type: ai_review`. The real linters of the QA runner are separate and are not merged into this result yet.

| Method | Path | Access | What it does |
| --- | --- | --- | --- |
| GET | `/ai-reviews/{id}` | `read` or `write` | Get an AI code review |
| GET | `/assets/{id}/ai-reviews` | `read` or `write` | List an asset's AI code reviews |
| POST | `/assets/{id}/ai-reviews` | `write` or `trigger` | Review the code with a self-hosted model |

