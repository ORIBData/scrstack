# E2E QA testing (Karate)

SCRS runs Karate tests for every assessed GitHub or GitLab repository that has a QA profile. Karate covers API tests, integration chains, UI tests (headless Chromium), mocks and load tests (karate-gatling) in one syntax. The tests run against a deployed environment, such as staging or a preview URL, on a **Karate runner** that you host. SCRS stores the results, API coverage and report-only findings next to the security assessment.

Karate (core and karate-cli) is MIT-licensed open source. The runner pins karate-cli 0.1.9 and Karate 2.1.4 and checks both against SHA-256 digests. No Karate Labs account or commercial module is used.

## How it fits the pipeline

```
assessment succeeds ──► QA run queued (profile enabled, auto_run, ref matches)
   │ verdict fail ──► run recorded "skipped": the commit's code never reaches the runner
   ▼
worker: fetch the assessed commit, take <test_path> as suite "repo",
        add approved generated features as suite "generated" (with SCRS's karate-config.js)
   ▼
POST runner /v1/jobs (spec + bundle) ──► runner runs karate-cli per suite, or Gatling
   ▼
worker polls GET /v1/jobs/{id} ──► GET /v1/jobs/{id}/report (SHA-256 checked) ──► S3 qa/<sha256>.tar.gz
   ▼
scenarios, API coverage, qa_* findings, qa.completed / qa.failed events
```

- **Report-only.** QA findings never change an assessment's verdict. They appear in the register and in the assessment's findings, with `counts.qa` on the assessment.
- **Reliable ingest.**
  - Each worker step is short and leased (`qa_runs`), so a crashed worker loses nothing.
  - Submissions are idempotent: the runner job ID is the run ID, and the same content returns the same job.
  - If the runner restarts and forgets a job, SCRS submits it again (at most 5 submission attempts).
  - The runner announces the report digest, and SCRS checks it before storing the report.
  - Runs that outlive their timeout by 30 minutes are ended with an error.
- **Order of work.** Runs move through `queued → submitted → running → passed | failed | error`; `cancelled` and `skipped` are also possible. At most `SCRS_QA_MAX_ACTIVE` runs are on the runner at once.

## Deployment options

- **In the SCRS Dokploy stack** (`deploy/compose.dokploy.yaml`, service `scrs-qa-runner`).
  - The runner is built from its own image (`make release-qa-runner`).
  - SCRS reaches it privately at `http://scrs-qa-runner:8090` on the internal `qa` network.
  - Traefik also publishes it at `https://${SCRS_QA_DOMAIN}`, behind an IP allowlist and the token, so operators can run standalone jobs (see [Standalone operator use](#standalone-operator-use)).
  - This is simplest to run, but the runner shares the host's kernel with SCRS. See
    [DOKPLOY.md](DOKPLOY.md#e2e-qa-karate-additions) for what it can reach and how to check.
- **On a separate VM** (`deploy/compose.qa-runner.yaml`). This gives the strongest isolation;
  set `SCRS_QA_RUNNER_URL` to its https URL and `SCRS_QA_RUNNER_ALLOW_HTTP=false`.

The guidance below applies to both. On the shared host, "dedicated VM" becomes "dedicated
container with no SCRS secrets and no access to SCRS's networks".

## The runner host

The runner executes repository test code. Karate features can run JavaScript, call Java and start processes. Treat the runner host as running untrusted code:

1. **Use a dedicated VM or host with no SCRS credentials.** It holds only `SCRS_QA_RUNNER_TOKEN`, and SCRS calls the runner, never the other way round. The runner needs no route to SCRS's database, Redis, S3 or any internal network.
2. **Allow outbound traffic only to the systems under test**: the profiles' `base_url` hosts, plus package mirrors if your tests need them. Block cloud metadata endpoints (169.254.169.254).
3. **Separate the test user from the runner.** Run the container as in `deploy/compose.qa-runner.yaml`:
   - The supervisor starts as root and holds only `SETUID`, `SETGID`, `CHOWN`, `FOWNER`, `DAC_OVERRIDE` and `KILL`.
   - Every test process runs as uid 10001, so it cannot read the runner's token or environment.
   - The root filesystem is read-only, `no-new-privileges` is set, and job directories live on tmpfs and are deleted after each job.
4. **Protect the API.** Put TLS in front, either a reverse proxy or `SCRS_QA_RUNNER_TLS_CERT` and `SCRS_QA_RUNNER_TLS_KEY`. Bind to a private interface or VPN that only SCRS can reach. Use `SCRS_QA_RUNNER_TOKEN_FILE` to keep the token out of the container configuration.
5. **Rebuild the VM from its image periodically.** Jobs are isolated from each other by user and directory, not by VM.

```bash
# On the QA host
export SCRS_QA_RUNNER_TOKEN=$(openssl rand -hex 32)
docker compose -f deploy/compose.qa-runner.yaml up -d --build
curl -s localhost:8090/healthz

# On SCRS (API and worker)
SCRS_QA_RUNNER_URL=https://qa-runner.internal.example.com
SCRS_QA_RUNNER_TOKEN=<the same token>
```

`GET /scrs/v1/qa/runner` reports whether SCRS can reach the runner, along with the runner's Karate version, Gatling support and queue.

### Runner settings

| Variable | Default | Meaning |
|---|---|---|
| `SCRS_QA_RUNNER_TOKEN` / `_TOKEN_FILE` | required | Bearer token SCRS presents (32+ characters) |
| `SCRS_QA_RUNNER_SLOTS` | 1 (compose: 2) | Jobs run at once |
| `SCRS_QA_RUNNER_MAX_QUEUED` | 20 | Waiting jobs before the runner answers 429 |
| `SCRS_QA_RUNNER_RETENTION_HOURS` | 24 | How long finished reports stay for collection |
| `SCRS_QA_RUNNER_JOB_UID` / `_GID` | 0 (compose: 10001) | User for test processes; 0 runs them as the runner user |
| `SCRS_QA_RUNNER_TLS_CERT` / `_KEY` | unset | Serve HTTPS directly |
| `SCRS_QA_RUNNER_PASS_ENV` | unset | Extra runner variables tests inherit (comma-separated names), such as `HTTPS_PROXY` |
| `SCRS_QA_RUNNER_KARATE`, `_JAVA`, `_PERF_CLASSPATH` | image values | Commands; an empty Gatling classpath disables performance jobs |

### Standalone operator use

The runner is a QA, performance and load service. It is separate from supply-chain scanning and never sees SBOMs, MBOMs, vulnerabilities, malware or integrity results. Operators can use it without SCRS storing anything:

- **Address.** `https://${SCRS_QA_DOMAIN}`, reachable only from `SCRS_QA_RUNNER_ALLOWED_CIDRS`.
- **Credential.** `SCRS_QA_RUNNER_TOKEN` as a bearer token. It is the same token Core and the worker use, not an SCRS API token, so keep it to people who may run test code.
- **Jobs.** The Runner API below, with `kind` `functional` (Karate API, integration and UI) or `performance` (Gatling). Pick a new lower-case UUID for `id`.
- **Results.** Fetch the report from `GET /v1/jobs/{id}/report` and check `X-Content-SHA256`. SCRS creates no run, finding, event or S3 archive for these jobs.
- **Capacity.** Direct jobs share the runner's slots and queue with runs started by SCRS; a full queue answers `429`.
- **Lint.** The runner has no lint job kind. Linting is not part of this service today.

### Runner API (SCRS ↔ runner)

All routes except `/healthz` need `Authorization: Bearer <token>`.

| Route | Purpose |
|---|---|
| `POST /v1/jobs` | Multipart: `spec` (JSON, below) then `bundle` (gzip tar, ≤ 32 MiB). `202` new, `200` same job resubmitted, `409` same ID with different content, `429` queue full, `422` performance job without Gatling |
| `GET /v1/jobs/{id}` | State `queued`, `running`, `passed`, `failed`, `error` or `cancelled`, with exit code, times and report digest |
| `GET /v1/jobs/{id}/report` | Report archive with `X-Content-SHA256` |
| `DELETE /v1/jobs/{id}` | Cancel (kills the process group) and remove |
| `GET /v1/info` | Karate version, Gatling support, slots, queue |

```json
{"id":"<run uuid>","kind":"functional","base_url":"https://api.staging.example.com","env":"staging",
 "threads":2,"timeout_seconds":900,"suites":[{"dir":"repo","tags":["~@ignore"]},{"dir":"generated"}],
 "variables":{"API_TOKEN":"…"}}
```

The runner handles each job as follows:

- **Each suite runs as its own Karate project:**
  `karate run --no-pom -f html,junit:xml,karate:jsonl -w <suite> -g <suite> <suite>`.
- **The environment is fixed.** Tests see `SCRS_BASE_URL`, `SCRS_ENV` and `QA_<NAME>` for each variable. They never see the runner's token or its other settings.
- **Project settings are ignored.** `.karate/` directories (karate-cli project settings) and `karate-pom.json` are dropped.
- **Secrets are redacted** from every text file in the report. That covers the variable values in plain, JSON-escaped and HTML-escaped form, plus credential headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key` and similar) in Karate's request logs.
- **The report archive** holds `result.json`, `console.log` (first 1 MiB and last 7 MiB) and `reports/<suite>/` (Karate HTML, JUnit XML and `karate-json/karate-events.jsonl`), or `gatling/` for load runs. If it would exceed 64 MiB, HTML is dropped first and the result is marked `truncated`.

Pass or fail is decided from the reports, not the exit code:
- karate-cli exits 101 on failures, where the plain jar exits 1.
- A suite that writes no event stream is an `error`.
- Gatling exits 2 when a threshold is breached; that run is `failed`.

## QA profile

There is one profile per repository asset: `PUT /scrs/v1/assets/{id}/qa/profile`. It needs `admin` scope, because the runner calls `base_url` with the profile's secrets.

```json
{
  "base_url": "https://api.staging.example.com",
  "environment": "staging",
  "refs": ["main", "release/*"],
  "test_path": "karate",
  "tags": ["~@ignore"],
  "threads": 2,
  "timeout_seconds": 900,
  "openapi_path": "api/openapi.yaml",
  "variables": {"API_TOKEN": "…"},
  "auth": {"header": "Authorization", "variable": "API_TOKEN", "prefix": "Bearer "},
  "perf": {"features": ["perf/browse.feature"], "users": 20, "ramp_seconds": 30, "duration_seconds": 120,
           "p95_millis": 800, "max_error_percent": 1, "auto_run": false},
  "llm_provider_id": "<uuid>",
  "allow_source_upload": false
}
```

The fields work as follows:

- **`refs`**
  - Accepts globs such as `main`, `release/*` and `pull/*`.
  - Empty means every ref.
  - Pull-request assessments use the ref `pull/<n>`.
  - Note that `base_url` is a deployed environment, so a PR run tests the PR's tests against whatever is deployed.
- **`test_path`** is the repository directory holding the Karate project; its `karate-config.js` sits there too.
- **Secrets** reach tests as `QA_<NAME>` environment variables. For example:
  ```javascript
  function fn() {
    var env = java.lang.System.getenv;
    return { baseUrl: env('SCRS_BASE_URL'), token: env('QA_API_TOKEN') };
  }
  ```
- **`variables`** are write-only. Omitting them keeps the stored set, and `variable_names` lists them.
- **`auth`** applies only to generated features: SCRS's `karate-config.js` for the `generated` suite adds this header to every request.
- **UI tests** use the image's Chromium:
  ```
  * configure driver = { type: 'chrome', headless: true, addOptions: ['--no-sandbox', '--disable-dev-shm-usage'] }
  ```
  The `--no-sandbox` flag is needed because the container has no user namespaces.
- **Mocks**: tests can start Karate mocks with `karate.start('mock.feature')` to stand in for third-party dependencies.
- **`perf`** runs the listed features under load, rather than once:
  - Users ramp up, and each repeats the features for the duration.
  - p95 and error-rate thresholds are Gatling assertions.
  - `auto_run` starts a load run after each passing functional run; `POST .../qa/runs {"kind":"performance"}` starts one on demand.

## Results and findings

| Finding type | Severity | Raised when | Closed when |
|---|---|---|---|
| `qa_failure` | `@severity=critical\|high\|medium\|low` tag on the scenario, otherwise medium | A scenario fails | A later functional run of the ref does not report it |
| `qa_untested` | low | A documented OpenAPI operation got no test traffic | A later run calls it |
| `qa_performance` | medium | A load threshold is breached | A later load run meets it |
| `qa_config` | low | Setup problems: no `.feature` files, OpenAPI document missing or unusable | A later run without the problem |
| `qa_unconfigured` | low | A complete scan finds `openapi.yaml`, `swagger.json` or similar but the repository has no QA profile | A profile exists at the next complete scan |

How coverage is measured:
- **Matching.** Karate's request logs (in the JSON Lines report) show each call's method, URL and response status. SCRS matches each call to the target host against the operation templates. It strips the `base_url` path and the document's server or base paths first, and literal segments beat parameters (`/users/me` matches before `/users/{id}`).
- **Counting.** Deprecated operations are listed but not counted. Called paths that the document does not describe are listed under `unmatched`.
- **Endpoints.** `GET /qa/runs/{id}/coverage` has the per-operation detail, and `GET /assets/{id}/qa/coverage` has the trend.

Other results:
- **Events.** `qa.completed` (passed or failed) and `qa.failed` (error or skipped) carry the run summary and links. New QA findings also emit `finding.created`.

## Test generation with an LLM (bring your own key)

**Providers.** Add a provider with `POST /scrs/v1/llm/providers` (admin), check it with `POST /llm/providers/{id}:test`, then set `llm_provider_id` on the profile. Supported kinds:

| Kind | Protocol | Default inference URL |
|---|---|---|
| `openai` | Chat Completions (`max_completion_tokens`) | `https://api.openai.com/v1` |
| `azure_openai` | Chat Completions, `api-key` header | your resource, such as `https://<name>.openai.azure.com/openai/v1` |
| `anthropic` | Messages API | `https://api.anthropic.com/v1` |
| `gemini` | generateContent | `https://generativelanguage.googleapis.com/v1beta` |
| `mistral`, `groq`, `deepseek`, `xai`, `openrouter`, `together` | Chat Completions | each provider's public endpoint |
| `ollama` | Chat Completions, key optional | `http://localhost:11434/v1` |
| `openai_compatible` | Chat Completions | your URL: vLLM, LiteLLM, Portkey, or a gateway in front of Bedrock or Vertex |

How the provider connection is handled:
- **Keys** are sealed with `SCRS_MASTER_KEY` and never returned.
- **Network.**
  - Calls pass the same network guard as webhooks: public addresses only, no redirects.
  - Self-hosted endpoints (and plain http) need their host in `SCRS_LLM_PRIVATE_HOSTS`.
- **Retries.** Rate limits and server errors are retried twice, honouring `Retry-After`.

**What generation sends.** `POST /assets/{id}/qa/generations` works at the latest successful assessment:

- **`kind: api` (Phase 2).**
  - Sends the OpenAPI operations, eight per request, with operations untested by the last run first.
  - Includes their definitions and referenced schemas, and asks for Karate features.
  - `max_operations` defaults to 30; `operations` picks specific ones.
- **`kind: unit` (Phase 3).**
  - Sends source files that have no tests, one per request, with one existing test as a style sample.
  - Covers Go (`go test`), TypeScript and JavaScript (Jest, Vitest or Mocha from `package.json`), Python (pytest), Java and Kotlin (JUnit 5).
  - `max_files` defaults to 5.
  - It needs `allow_source_upload: true` on the profile, because source code leaves your network.

**Reviewing drafts.** Model output is untrusted, since the spec and the source can carry prompt injection. So every generated file is a draft and passes static checks before anyone can approve it.

- **API features must:**
  - start with `Feature:`, have a `Background:` with exactly `* url baseUrl`, and have at least one scenario;
  - use only request, assert and variable keywords (`url`, `path`, `param`, `header`, `request`, `method`, `status`, `match`, `assert`, `def` and similar);
  - use no `call`, `read`, `eval`, `karate.exec`, `karate.fork`, `karate.write`, `Java.type`, `java.*`, drivers or absolute URLs.
- **Failures.** Files that fail are stored `rejected` with their problems, and cannot be approved.
- **Approval.**
  - `POST /qa/suites/{id}:approve` (admin) makes an API feature part of every later functional run, as the `generated` suite. An admin can trial drafts first with `{"include_drafts": true}` on a manual run.
  - Unit tests are never run by SCRS. Download them with `GET /qa/generations/{id}/files` (a tar with `MANIFEST.json`) and commit them, and your CI runs them.
- **Usage.** Each generation records input and output tokens.

## API summary

| Route | Scope |
|---|---|
| `GET/PUT/DELETE /assets/{id}/qa/profile` | read / admin / admin |
| `GET/POST /assets/{id}/qa/runs` | read / write or trigger (`include_drafts` admin) |
| `GET /assets/{id}/qa/coverage`, `/qa/suites`, `/qa/generations` | read |
| `POST /assets/{id}/qa/generations` | write |
| `GET /assessments/{id}/qa` | read |
| `GET /qa/runs/{id}`, `/scenarios`, `/coverage`, `/report` | read |
| `POST /qa/runs/{id}:cancel` | write or trigger |
| `GET /qa/generations/{id}`, `/files`; `GET /qa/suites/{id}` | read |
| `POST /qa/suites/{id}:approve` / `:reject` | admin / write |
| `GET /qa/runner` | read |
| `GET /llm/presets`, `GET /llm/providers[/{id}]` | read |
| `POST/PATCH/DELETE /llm/providers[/{id}]`, `POST /llm/providers/{id}:test` | admin |

The full contract, with schemas and examples, is in `api/openapi.yaml` (tags *E2E QA* and *LLM providers*).

## SCRS settings

| Variable | Service | Meaning |
|---|---|---|
| `SCRS_QA_RUNNER_URL`, `SCRS_QA_RUNNER_TOKEN` | API, worker | The runner. Unset keeps QA runs queued |
| `SCRS_QA_RUNNER_ALLOW_HTTP` | API, worker | Allow `http://` for a runner on a private network |
| `SCRS_QA_RUNNER_CA_FILE` | API, worker | PEM trusted for a privately issued runner certificate |
| `SCRS_QA_MAX_ACTIVE` | worker | Runs on the runner at once (default 4) |
| `SCRS_QA_GENERATION_ENABLED` | worker | `false` stops test generation and AI code review |
| `SCRS_LLM_PRIVATE_HOSTS` | API, worker | Self-hosted model hosts allowed private addresses and http |

## Verification

All of the following were run against real software:

- **`make qa-runner-test`** uses the pinned Karate 2.1.4 jar and checks:
  - a passing and a failing scenario against a mock that requires a bearer token from `QA_API_TOKEN`;
  - JSON Lines parsing and coverage calls;
  - redaction of the token from every report file;
  - cancellation of a running process group;
  - idempotent and conflicting resubmission.
- **`make qa-runner-image-test`** builds the image and runs it with the compose hardening (read-only root, dropped capabilities, test user 10001). In that container it ran:
  - an API scenario;
  - a headless-Chromium UI scenario;
  - a karate-gatling load run with thresholds.
- **`TestPostgresQAPipeline`** (in `make database-test`) drives the whole flow against PostgreSQL and a runner using a scripted Karate stand-in:
  - an assessment queues a run, and the runner drops the repository's `.karate` folder;
  - findings and coverage are recorded, and events are emitted;
  - an LLM generation produces one accepted and one rejected feature;
  - the approved feature runs as the generated suite and closes `qa_untested`;
  - a unit-test draft is produced;
  - cancellation removes the runner job;
  - a malware verdict skips QA.
- **`TestPostgresQAAndLLMProviderAPI`** covers the HTTP contract: scopes, sealed keys and variables, `If-Match`, and the provider check against a fake model.
- **Fixtures.** The Karate and Gatling fixtures in `internal/qa/testdata` are real 2.1.4 and Gatling 3.16 output.

Not yet verified: generation against each hosted provider with real keys. The request and response shapes follow each provider's published API and are tested against fakes. Run `POST /llm/providers/{id}:test` after adding a provider.
