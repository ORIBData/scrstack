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

## QA with or without a security assessment

QA is part of an assessment by default and can also run on its own. SCRS (API and worker) is the single orchestrator in both cases: the same endpoints, the same runner, the same register entries.

| You want | Do this |
|---|---|
| Security assessment **with** QA (default) | `POST /assessments`. When the asset has an enabled, `auto_run` QA profile, its functional and lint runs are queued as the assessment finishes. A `fail` verdict records them as `skipped`. |
| Security assessment **without** QA | `POST /assessments` with `"skip_qa": true`. |
| QA **without** a security assessment | Set `"gate": "none"` in the asset's QA profile (admin), then `POST /assets/{id}/qa/runs` with `{"kind": "full", "ref": "main"}`. No assessment is needed. |
| QA of an assessed commit | `POST /assets/{id}/qa/runs` with `{"kind": "full"}` or `"assessment_id"`, on a profile with the default `"gate": "assessment"`. |

- **Run kinds.** `kind` is `functional`, `performance`, `lint` or `full`. `full` queues every run the profile configures: functional (with a `base_url` and `functional` on), performance (unless it already follows a passing functional run) and lint (with lint settings). The answer lists the runs and uses the first run's ID as `job_id`.
- **What the gate controls.** With `gate: assessment` (the default) a manual run tests the latest successful git assessment, or the one named, and refuses a `fail` verdict. With `gate: none` and no `assessment_id`, the worker resolves `ref` (the default branch when empty; it must match the profile's `refs`) to a commit when the run starts and records that commit on the run. Runs have `assessment_id: null` then, and their entries appear in the register like any other QA entry.
- **Trust.** The repository's Karate features and linter configuration run on the QA runner (see *Lint* for the trust notes). With `gate: assessment` the security scan has looked at that commit first; with `gate: none` it has not. Set `gate: none` only for repositories you control, and keep the runner on an isolated network, as the deployment options describe. Only an `admin` token can save a profile, so an automation key cannot switch the gate.
- **AI triage needs an assessment.** Triage texts, their token budget and the chronicle are filed under an assessment. A run with no assessment keeps its report and register entries, and `POST /qa/runs/{id}/triage` answers `409`; automatic triage skips it.
- **A key for QA only.** Create a token with the `qa` scope (`POST /tokens`, admin). It can read QA profiles, runs, reports, coverage and generated tests, and start or cancel runs. It cannot start or read assessments, findings or SBOMs, list assets, run AI reviews or generation, or change any setting. The router test checks this for every operation in the contract. Give it an IP allow-list and an expiry. The token's name is stored as the run's `requested_by`.
- **The runner token is a different secret.** `SCRS_QA_RUNNER_TOKEN` is how SCRS authenticates to the runner. Callers never hold it.

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
| `SCRS_QA_RUNNER_LINT_<TOOL>` | the tool's name | Executable of each linter ; a linter that is not found is not offered, and a runner with none refuses lint jobs (`422`) |
| `SCRS_QA_RUNNER_LINT_DEPS` | `false` | Fetch a project's dependencies before linting (needs network access to package hosts) |
| `SCRS_QA_RUNNER_ESLINT_FALLBACK` | `/opt/eslint/eslint.config.mjs` | ESLint config for repositories that have none |

### Standalone operator use

The runner is a QA, performance and load service. It is separate from supply-chain scanning and never sees SBOMs, MBOMs, vulnerabilities, malware or integrity results. Operators can use it without SCRS storing anything:

- **Address.** `https://${SCRS_QA_DOMAIN}`, reachable only from `SCRS_QA_RUNNER_ALLOWED_CIDRS`.
- **Credential.** `SCRS_QA_RUNNER_TOKEN` as a bearer token. It is the same token Core and the worker use, not an SCRS API token, so keep it to people who may run test code.
- **Jobs.** The Runner API below, with `kind` `functional` (Karate API, integration and UI), `performance` (Gatling) or `lint` (linters over a source tree). Pick a new lower-case UUID for `id`.
- **Results.** Fetch the report from `GET /v1/jobs/{id}/report` and check `X-Content-SHA256`. SCRS creates no run, finding, event or S3 archive for these jobs.
- **Capacity.** Direct jobs share the runner's slots and queue with runs started by SCRS; a full queue answers `429`.
- **Lint.** `kind` `lint` runs linters over a source tree (see [Lint](#lint)); the bundle holds the source under `src/` and the spec names the tools instead of suites.

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
| `qa_lint` | the worst severity in the group (see [Lint](#lint) for each tool) | A linter reports a rule in a file. One entry covers every occurrence of one rule of one tool in one file, so it does not churn when lines move | A later lint run in which every requested linter ran and that does not report it |
| `qa_lint_config` | low | A requested linter is not installed on the runner, could not produce a result, the source has no files for the profile's linters, or the run hit a limit | A later run without the problem |
| `qa_unconfigured` | low | A complete scan finds `openapi.yaml`, `swagger.json` or similar but the repository has no QA profile | A profile exists at the next complete scan |

How coverage is measured:
- **Matching.** Karate's request logs (in the JSON Lines report) show each call's method, URL and response status. SCRS matches each call to the target host against the operation templates. It strips the `base_url` path and the document's server or base paths first, and literal segments beat parameters (`/users/me` matches before `/users/{id}`).
- **Counting.** Deprecated operations are listed but not counted. Called paths that the document does not describe are listed under `unmatched`.
- **Endpoints.** `GET /qa/runs/{id}/coverage` has the per-operation detail, and `GET /assets/{id}/qa/coverage` has the trend.

Other results:
- **Events.** `qa.completed` (passed or failed) and `qa.failed` (error or skipped) carry the run summary and links. New QA findings also emit `finding.created`.

## Lint

A profile with `lint: {"tools": [...]}` adds a **lint run** after each successful assessment of a matching ref (with `auto_run`), and `POST /assets/{id}/qa/runs {"kind":"lint"}` starts one on demand. Entries are report-only: they never change a verdict.

| Tool | Language | Reads | Severity |
|---|---|---|---|
| `ruff` | Python style and errors | `ruff.toml`, `pyproject.toml` | medium for rules that usually mean a runtime error (`F82x`, `F63x`, `F7xx`, `E9xx`, `PLE`), high for a syntax error, otherwise low |
| `mypy` | Python types | `mypy.ini`, `pyproject.toml`, `setup.cfg` | high for a syntax error, otherwise medium (type errors) |
| `bandit` | Python security | `pyproject.toml` (`[tool.bandit]`) | bandit's own severity (high, medium, low), with the CWE in the message; a file bandit could not parse is a medium `not-scanned` issue |
| `pylint` | Python code quality | `.pylintrc`, `pyproject.toml`, `setup.cfg` | high for a syntax error or fatal, medium for an error, low for warnings, refactor hints and conventions |
| `phpstan` | PHP static analysis | `phpstan.neon`, `phpstan.neon.dist`, `composer.json` | high for a parse error, otherwise medium |
| `phpcs` | PHP code style | `phpcs.xml`, `.phpcs.xml`, `phpcs.xml.dist` | low (a coding standard), medium for a file phpcs could not read |
| `clang-tidy` | C and C++ | `.clang-tidy` | medium for the static analyzer, `bugprone-*`, `cert-*` and compile errors, otherwise low |
| `golangci-lint` | Go | `.golangci.yml`, `go.mod` | medium for `govet`, `staticcheck`, `errcheck`, `gosec`, `ineffassign`, `typecheck` and similar, otherwise low |
| `eslint` | JavaScript, TypeScript | `eslint.config.*` | high for a parse failure, medium for an error, low for a warning |
| `ktlint` | Kotlin | `.editorconfig` | low |
| `swiftlint` | Swift | `.swiftlint.yml` | medium for an error, low for a warning |
| `dart-analyze` | Dart, Flutter | `analysis_options.yaml`, `pubspec.yaml` | high for a compile-time error, medium for a warning, low for a hint or lint |

**A profile that only lints** sets `functional: false` and needs no `base_url`: SCRS then queues no Karate run after an assessment, so there is no "no tests" `qa_config` entry. A profile with `functional` true (the default) or `perf` still needs a `base_url`.

How it runs:
- **Bundle.** The worker downloads the assessed commit and sends only the files the requested linters read (their sources plus their configuration, `go.mod`, `package.json` and lockfile, `pubspec.yaml`), never `node_modules`, `Pods`, `.dart_tool` or `.git`. Files over 2 MiB are left out. The limits are 20000 files, 96 MiB, and 32 MiB compressed; a source tree over them is linted in part, and a `qa_lint_config` entry says how many files were left out.
- **Command lines are fixed.** The runner runs each tool with its own arguments, as the job user (uid 10001), and writes the report to a file it chooses. A repository can configure rules (`ruff.toml`, `.golangci.yml`, an ESLint config, `.editorconfig`, `.swiftlint.yml`, `analysis_options.yaml`) but cannot change how the tool is run. Linter configurations can run repository code (an ESLint config is JavaScript), so lint jobs follow the same host rules as the rest of this page.
- **Projects in a monorepo.** Go is linted per module (every directory with a `go.mod`, up to 20, never `vendor` or `testdata`), ESLint per directory holding an `eslint.config.*` (the outer one covers nested ones), and Dart per package (`pubspec.yaml`). Paths in the results are relative to the repository. A repository with no ESLint config is linted with the runner's own (ESLint's recommended rules for JavaScript and TypeScript, Node and browser globals); one with a config always uses its own.
- **Dependencies.** Without them a linter can resolve only the standard library. With `SCRS_QA_RUNNER_LINT_DEPS=true` the runner fetches a project's dependencies first: `go mod download` (unless `vendor/` exists), `npm ci --ignore-scripts` (only with a `package-lock.json`), `dart pub get`, and `composer install --no-scripts --no-plugins` (only with a `composer.lock`, so only the pinned versions, and not if `vendor/` is committed) for each Composer project, which PHPStan then uses. Composer ignores platform requirements (PHP version and extensions), because the runner's PHP is not the application's. The Python and C/C++ tools never install dependencies. That needs outbound access to the package hosts (Go proxy, npm registry, pub.dev, Packagist and the hosts of the packages), so it is off by default; leave it off and vendor Go modules and commit lockfiles if the runner has no network. When a fetch fails, the tool still runs and a `qa_lint_config` entry says its result may be incomplete.
- **A silent or broken tool is not a clean one.** A tool that is not installed, cannot start, exits with a failure code or writes an unreadable report is an `error` (or `unavailable`) in `report.lint.tools` and gets a `qa_lint_config` entry. An entry is closed by absence only when every requested linter ran completely and the issue list was not cut at 5000 issues.
- **SwiftLint on Linux** is the release's static build, which needs no Swift toolchain. It skips the few rules that need SourceKit (it says so on stderr, kept in `console.log`), and it cannot compile iOS code, so rules that need type information do not run. Treat its results as a style and common-mistake check.
- **Python tools overlap on purpose.** ruff is fast and covers style and obvious errors; mypy checks types; bandit looks for security problems (shell calls, weak hashes, hard-coded passwords); pylint is slower and stricter. The same line can appear under several tools, each as its own entry. The repository's dependencies are never installed for them, so mypy runs with `--ignore-missing-imports` (a call into an untyped or missing package is not checked) and pylint has `import-error` and `no-name-in-module` off. Without the packages the checks that need them are weaker. pylint is noisy on a repository that has no `.pylintrc` (docstring and naming rules): set the rules in the repository, or request only the tools you want in `lint.tools`. A mypy or pylint configuration can load plugins, which run repository code, like an ESLint config.
- **PHP.** PHPStan uses the repository's `phpstan.neon` (paths and level); without one it analyses the source at level 5, without `vendor/`. phpcs uses the repository's `phpcs.xml`; without one it applies PSR-12. Without dependencies PHPStan cannot see classes from Composer packages and reports them as unknown (`class.notFound`); turn on the dependency step below to resolve them. The runner loads the `vendor/autoload.php` of every Composer project it finds, also when the repository commits its `vendor/`.
- **C and C++ (best effort).** clang-tidy needs the compiler flags of a build, which the runner does not have (a committed `compile_commands.json` points at another machine). The runner compiles each `.c`, `.cc`, `.cpp` and `.cxx` file on its own, with every directory that holds a header on the include path, in batches of 25 files (up to 3000 files). Project headers resolve, and the static analyzer finds leaks, null dereferences and similar. A third-party or generated header does not resolve: clang-tidy stops at that include, those sources are only partly analysed, and the tool's note says how many includes were not found, so its entries are never closed by absence. A repository's `.clang-tidy` is used; without one the runner applies `clang-analyzer-*` and `bugprone-*`. Defines and language standards from the build (`-D`, `-std`) are not known.
- **ktlint** reports style rules from `.editorconfig` (the standard rule set); it does not check Gradle or Android lint.
- **AI code review.** A review of the same assessment shows the model each file's lint findings next to the static-analysis findings, so it builds on them instead of repeating them.
- **Results.** The run's `summary.lint` has the issue count, files, and counts by tool and severity. `qa.completed` and `finding.created` carry the run and new entries.

**Images.** The slim `base` image (`--target base`) ships `ruff` only. The default build, the full image that `make release-qa-runner` publishes, adds the rest, every download checked against a pinned SHA-256 (ESLint from a lockfile with integrity hashes, installed without scripts; mypy, bandit and pylint from `deploy/karate-runner/lint/requirements.txt`, which pins every file by hash and installs from wheels only):

```bash
make qa-runner-lint-image            # the full runner, every linter (the default build of the Dockerfile)
make release-qa-runner               # publishes that same full image for the Dokploy stack
# or: docker build -f deploy/karate-runner/Dockerfile --target base -t <tag> .   (slim, ruff only)
```

It adds Python with mypy, bandit and pylint, PHP with PHPStan, phpcs and Composer (pinned phars), clang-tidy with the C and C++ headers (Debian package), the Go toolchain with golangci-lint, Node with ESLint, ktlint, SwiftLint and the Dart SDK; the image is about 2 GB larger than the runner. `GET /qa/runner` lists the linters it finds (`lint_tools`). Set `SCRS_QA_RUNNER_LINT_<TOOL>` (`RUFF`, `MYPY`, `BANDIT`, `PYLINT`, `PHPSTAN`, `PHPCS`, `CLANG_TIDY`, `GOLANGCI_LINT`, `ESLINT`, `KTLINT`, `SWIFTLINT`, `DART_ANALYZE` with `dart` as the executable) to use another executable. To check a runner, point `SCRS_TEST_RUNNER_URL` and `SCRS_TEST_RUNNER_TOKEN` at it and run `go test ./internal/qarunner -run TestRealRunnerLint -v`; with dependency installs on, add `SCRS_TEST_DEPS_DIR` and run `TestRealRunnerLintDeps`.

## AI triage of QA results

SCRS can ask a model to turn a finished run into something an engineer can act on. For each run it writes:
- **A run summary** in the asset's chronicle (kind `qa_summary`): a headline, a risk level for shipping the commit, what failed and what it probably means, and up to eight priorities. It supersedes the previous one.
- **An advisory per important entry** (up to 15), stored against the register entry: what went wrong, the most likely cause, whether the application, the test or the linter configuration is the likelier thing to change, the concrete steps to fix it, and an urgency.

What the model is shown: the entry's title and severity, the feature, scenario and tag, the first 700 characters of the failure text, the load threshold and its measured value, and for lint the tool, rule, file, number of occurrences and up to five messages. It is never shown source code, request or response bodies or the profile's variables. Everything goes through the same guard as other model calls (credentials, secrets and exfiltration markup are removed; answers are validated, links are removed, and an advisory for an entry that was not sent is dropped).

Because file paths, test names and failure text can carry sensitive data (a failing assertion may echo what the target returned), a triage follows the **source-code rule** of AI code review: the provider must be self-hosted, or hosted with `SCRS_LLM_ALLOW_SOURCE_TO_HOSTED=true` and an acknowledgement. It is checked when queued and again when the job runs.

How to use it:
- **Automatically.** Set `llm_provider_id` and `ai_triage: true` on the profile. After each finished run with entries to describe, SCRS queues a triage. It is off by default, because `llm_provider_id` may have been set for test generation only.
- **On request.** `POST /qa/runs/{id}/triage` (optionally with `provider_id`) answers `202` with a `job_id`; poll `GET /summary-jobs/{id}`. `GET /qa/runs/{id}/triage` lists the run's jobs.
- **Limits.** The assessment's token budget and the provider's monthly cap apply, and a cut-off answer is never stored as complete. Texts are marked as written by a model and not verified, and never change a verdict or an entry's status.

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
| `GET/POST /assets/{id}/qa/runs` | read or qa / write, trigger or qa (`include_drafts` admin) |
| `GET /assets/{id}/qa/coverage`, `/qa/suites`, `/qa/generations` | read or qa |
| `POST /assets/{id}/qa/generations` | write |
| `GET /assessments/{id}/qa` | read, trigger or qa |
| `GET /qa/runs/{id}`, `/scenarios`, `/coverage`, `/report` | read, trigger or qa |
| `POST /qa/runs/{id}:cancel` | write, trigger or qa |
| `GET /qa/generations/{id}`, `/files`; `GET /qa/suites/{id}` | read, trigger or qa |
| `POST /qa/suites/{id}:approve` / `:reject` | admin / write |
| `GET /qa/runner` | read, trigger or qa |
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
