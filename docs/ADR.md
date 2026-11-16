# Architecture decision records

These records cover the PRD's ADR list (section 8.9) and the decisions taken while building SCRS. Each gives the decision, why it was taken, its consequences, and where the evidence is.

**Statuses:**
- **Accepted:** decided and built.
- **Superseded:** the PRD's proposal was replaced by what is described here.
- **Proposed:** not built yet.

| ID | Decision | Status |
| --- | --- | --- |
| ADR-001 | Go module, Go 1.27 | Accepted |
| ADR-002 | One repository, fork of the ClamAV REST project; separate images per trust boundary | Accepted (amended) |
| ADR-003 | Single binary with role sub-commands | Accepted |
| ADR-004 | PostgreSQL is the job system of record *and* the dispatcher | Superseded |
| ADR-005 | OSV-Scanner as a pinned CLI subprocess | Accepted |
| ADR-006 | YARA-X CLI subprocess for rulesets | Accepted |
| ADR-007 | ClamAV as a shared sidecar over INSTREAM | Accepted |
| ADR-008 | Contract-first OpenAPI 3.1 with contract tests, hand-written handlers | Accepted (amended) |
| ADR-009 | In-house STIX 2.1 pattern parser | Accepted |
| ADR-010 | No CVSS calculator: keep every vector and source-supplied score | Accepted |
| ADR-011 | API tokens stored as SHA-256 of 256-bit random secrets | Accepted |
| ADR-012 | S3 through minio-go with custom endpoint and path style | Accepted |
| ADR-013 | Additive idempotent DDL under a migration lock | Superseded |
| ADR-014 | `log/slog` JSON logs | Accepted |
| ADR-015 | AES-256-GCM secrets under `SCRS_MASTER_KEY`, bound to their owner | Accepted |
| ADR-016 | Fixed intervals and PostgreSQL locks; no cron library | Accepted |
| ADR-017 | go-containerregistry for image pulls by digest | Accepted |
| ADR-018 | SAST analyzers as sandboxed external processes in their own image | Accepted |
| ADR-019 | Provider connections in encrypted rows; environment seeds the first | Accepted |
| ADR-020 | OSV schema as the single advisory format | Accepted (amended) |
| ADR-021 | E2E QA on an operator-hosted Karate runner, called by SCRS | Accepted |
| ADR-022 | One LLM adapter over three wire protocols | Accepted |
| ADR-023 | Inbound webhook secrets belong to connections | Accepted |
| ADR-024 | Report-only gates for hunt, QA and vendor statements | Accepted |
| ADR-025 | Licence data: declared, then detected, then deps.dev metadata | Accepted |
| ADR-026 | SCRS generates its SBOMs from its own component model | Accepted |
| ADR-027 | Framework packs as versioned data with recorded mapping sources | Accepted |
| ADR-028 | Go reachability with govulncheck on SCRS's own advisory feed | Accepted |
| ADR-029 | Internal-use analyzer licences (Bearer, OpenGrep rules) | Accepted |
| ADR-030 | Live events from PostgreSQL NOTIFY, not Redis Pub/Sub | Accepted |
| ADR-031 | STIG by owner-uploaded XCCDF with an SCRS starter mapping | Accepted |
| ADR-032 | PDF reports from a built-in, deterministic writer | Accepted |
| ADR-033 | Dependency-Track export through a transactional upload queue | Accepted |

## ADR-001 Go module

**Decision:** one Go module, `github.com/ORIBData/scrstack`, at the Go version in `go.mod` (1.27).

**Why:** the PRD's floor came from `cyclonedx-go`. The current toolchain also gives `net/http` method and wildcard routing, `log/slog` and `min`/`max`.

**Consequences:** `make test` runs the whole module with the race detector.

## ADR-002 Repository and images

**Decision:** SCRS lives in the fork of the ClamAV REST project, and the legacy scanner keeps working (`docs/DOKPLOY.md`). The PRD proposed two images. There are four trust boundaries:
- the SCRS image (`deploy/Dockerfile.scrs`: API, worker, scanner, feed-sync, egress proxies);
- the official ClamAV image;
- the Karate runner image (`deploy/karate-runner/Dockerfile`), which runs repository test code and holds no SCRS secrets;
- the SAST image (`deploy/Dockerfile.sast`), which reads repository code with bundled analyzers, has no network except Go module downloads, and holds no SCRS secrets (ADR-018).

**Consequences:** three images are released (`make release`, `make release-qa-runner`, `make release-sast`). See ADR-021 and ADR-018.

## ADR-003 Single binary with role sub-commands

**Decision:** `scrs api`, `worker`, `scanner`, `feed-sync`, `egress-proxy`, `yara-install`, `sast`, `init` and the maintenance commands come from one binary; the SAST image runs the same binary in its `sast` role. The Karate runner is a separate small binary (`cmd/scrs-qa-runner`) because it ships in another image.

**Consequences:** each Compose service selects its role. Isolation comes from the container settings, not from the binary.

## ADR-004 Job dispatch (superseded)

**PRD proposal:** PostgreSQL as the record and Redis Streams as dispatch, with an outbox and a reconciler.

**Decision:** PostgreSQL does both, with no Redis stream:
- jobs are claimed with `FOR UPDATE SKIP LOCKED` and leases;
- retries back off;
- one running assessment per asset;
- the same lease pattern serves mirrors, TAXII polls, QA runs, generations and advisory syncs.

Redis is used only for per-token rate limiting.

**Why:** one store means no dual-write and nothing to reconcile, and a crashed worker's lease simply expires. Concurrent claims and lease expiry are exercised in `make database-test`. No production-scale throughput figure is recorded yet.

**Consequences:** queue depth is a SQL count, exposed in `/system/metrics`. If dispatch ever needs to scale out, ADR-004 can be revisited.

## ADR-005 OSV-Scanner integration

**Decision:** run the pinned `osv-scanner` CLI (v2.7.1, built from `tools/osv` into the scanner image) offline against the local OSV mirror.

**Why:**
- Its library API is unstable between minor versions.
- The CLI gives process isolation and a deadline per scan.
- Upgrades are one pinned version.

**Evidence:** `make scanner-test` runs the pinned binary against adversarial offline fixtures. Spike S1 in `docs/SPIKES.md` records the outcome.

## ADR-006 YARA engine

**Decision:** two engines:
- The starter rules run inside ClamAV, which supports a YARA subset with no modules. A canary proves they are loaded.
- Team and third-party rulesets run with the YARA-X CLI (`yr`, static, no cgo) as a subprocess, with the `pe`, `elf`, `math`, `hash` and `dotnet` modules.

**Why:** YARA-X is the maintained engine and avoids cgo. The subprocess has deadlines and memory bounds.

**Evidence:** `internal/scanner/yarax_test.go`; spike S7.

## ADR-007 ClamAV sidecar

**Decision:** one ClamAV daemon per deployment, on the internal scanning network. The scanner streams each file over `INSTREAM`, never a path on the daemon's filesystem. Signatures update in the ClamAV container, and stale signatures raise a posture finding.

**Evidence:** `make malware-test` (EICAR and clean file).

## ADR-008 OpenAPI contract

**Decision:** `api/openapi.yaml` (OpenAPI 3.1) is the contract, served at `/scrs/v1/docs`. Handlers are hand-written on `net/http`; no code generation or request-validation middleware.

**Why:** generated routers would fight the shared authorization, rate-limit and error conventions.

**Consequences:** `internal/httpapi/contract_test.go` fails the build when:
- a documented operation is not routed;
- a routed method is undocumented;
- an operation lacks an id, tag, summary, description or responses.

## ADR-009 STIX parsing

**Decision:** an in-house lexer, parser and evaluator for STIX 2.1 patterns (`internal/intelligence/stix.go`).
- It turns comparisons on file hashes, file names, domains, IPv4, IPv6 and URLs into indicators.
- It expands to disjunctive normal form.
- Every pattern it cannot match at rest is reported with a reason.

**Why:** no maintained Go library parses patterns.

**Evidence:** `internal/intelligence/stix_test.go`.

## ADR-010 CVSS

**Decision:** SCRS does not compute CVSS scores. It keeps every vector and the base score and severity each source supplies (OSV, NVD, CNA and ADP containers) as `severity_sources`. Finding severity comes from the OSV record.

**Why:** sources already publish base scores. Recomputing them (and environmental scores) adds a library dependency and a disagreement surface without new information.

**Consequences:** environmental scoring is not offered. Revisit if policy needs it.

## ADR-011 API tokens

**Decision:** 256-bit random tokens. Only their SHA-256 is stored, and each is checked in PostgreSQL on every request, so revocation takes effect at once. Tokens can be scoped, expiring and IP-restricted.

## ADR-012 S3 client

**Decision:** `minio-go` with custom endpoints and path-style addressing. Objects are content-addressed by SHA-256 and verified on read.

## ADR-013 Migrations (superseded)

**PRD proposal:** versioned SQL files run by `scrs migrate`.

**Decision:** every schema statement is additive and idempotent (`CREATE ... IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`). They are applied by `scrs init` (the `scrs-storage-init` service) under a PostgreSQL advisory lock, and no destructive DDL is ever run.

**Why:** forward-only, re-runnable and safe for rolling restarts, with no migration state to repair.

**Consequences:** renames and drops need a two-release plan. `make database-test` bootstraps twice to prove idempotency.

## ADR-014 Logging

**Decision:** `log/slog` JSON to stdout, with request IDs, and no secrets or tokens in logs. Access logs record the path, never query strings.

## ADR-015 Secrets at rest

**Decision:** AES-256-GCM under `SCRS_MASTER_KEY`, with additional data that binds each ciphertext to its owner:
- connections (`name:provider`);
- connection webhook secrets (`connection-webhook:<id>`);
- webhook subscriptions;
- TAXII credentials (`taxii:<source>`);
- LLM keys (`llm:<provider>`);
- QA variables (`qa:<asset>`).

Connection rows carry a key id (`v1`) for future rotation.

**Consequences:** losing the master key makes every stored secret unreadable. Key rotation tooling is not built yet.

## ADR-016 Scheduling

**Decision:** each worker loop runs on a fixed interval (`SCRS_*_SECONDS`, `SCRS_*_HOURS`). One replica is chosen per pass by a transaction advisory lock or a row lease; no cron library is used.

**Consequences:** the `scheduler_runs` table records each job's last run, status and next run (`GET /maintenance/schedule`).

## ADR-017 Registry client

**Decision:** `go-containerregistry` pulls images by digest from Docker Hub, GAR, Harbor and any OCI registry, and streams them to the scanner within a size cap.

**Evidence:** `internal/scanner/image_test.go`.

## ADR-018 SAST analyzers

**Decision:** gosec, Bandit, OpenGrep and Bearer run as child processes behind one Go interface (`internal/sast`) in a separate image, `scrs-sast`, never linked into SCRS. The image runs the `scrs sast` role and serves only the worker and the API over the internal `sast` network.

**Why a separate image:**
- the analyzers need a Python runtime, a Go toolchain and two native binaries, which would grow the scanner image;
- SAST gets its own sandbox and budget.

OpenGrep was added to the PRD's set because it is the only bundled analyzer for Kotlin and Swift, and it widens the JavaScript and TypeScript rules.

**Consequences:**
- A third image is released (`make release-sast`).
- Results are normalised into `sast` entries, which gate only when new.
- Inline suppressions are recorded, not lost, and a suppression added for an open entry is an integrity signal.

**Evidence:** `internal/sast` tests, `TestPostgresSASTAndReachabilityPipeline`, `make sast-image-test` and spike S10.

## ADR-028 Go reachability

**Decision:** `govulncheck` (call graph) runs in `scrs-sast` against a vulnerability database the service builds from the OSV Go archive `scrs-feed-sync` keeps. It does not use OSV-Scanner's call analysis, which gives a yes/no answer without traces. Module sources come through `scrs-sast-egress` (go-modules profile).

**Why:** traces (file and line), the import-only level, and no extra advisory source to sync.

**Consequences:**
- Failed, skipped and unsupported analyses are `unknown` or `unsupported`, never `not_reachable`.
- Scores move by configured weights.
- Nothing is closed for being unreachable.
- Standard-library entries are `unknown`, because they would describe the analyzer's toolchain.

## ADR-029 Internal-use analyzer licences

**Decision:** the owner accepted Bearer's Elastic License 2.0 and the OpenGrep community rules' Commons Clause for internal use (PRD Q22, 2026-11-15). Both are recorded as `redistributable: false`.

**Consequences:** any SCRS build distributed outside CreditChek, or offered as a service, must remove them (`SCRS_SAST_ANALYZERS=gosec,bandit` at minimum, and the image's bundled rules).

## ADR-019 Provider connections

**Decision:** connections (credentials, scope, webhook secret) are encrypted rows managed through the API. The environment only seeds the first GitHub connection.

## ADR-020 Advisory format (amended)

**Decision:** matching runs only on OSV records, offline. NVD and CVE Program records are converted to OSV-schema records with `origin` `nvd` or `cve5`, and the original is stored verbatim (`advisory_records`). They enrich findings, adding severity sources and CWEs, but do not create matches. Aliases come from the OSV records.

**Amendment:** there is no separate alias-graph table yet; findings carry OSV aliases.

**Amendment (2026-11-15):** CPE matching (VUL-007) would be the first matcher outside OSV. It is deferred: SCRS has no inventory of software without a package URL (OSV-Scanner drops it, and image binaries are not identified), and the NVD sync stores no CPE applicability. Spike S14 decides it.

## ADR-021 E2E QA runner

**Decision:** Karate tests run on an operator-hosted runner (`scrs-qa-runner`). SCRS pushes jobs to it and polls, and the runner never calls SCRS. The runner:
- holds no SCRS secrets;
- runs tests as a separate user with six capabilities;
- drops `.karate/` and `karate-pom.json`;
- redacts secrets from reports.

It can run in the Dokploy stack on an internal network or on its own VM. Keploy was evaluated and rejected because it needs root and eBPF and records traffic.

**Amendment (2026-11-16):** The runner is a QA, performance and load service only. It never handles SBOMs, MBOMs, vulnerabilities, malware or integrity data. Traefik publishes it for operators who run standalone jobs; those jobs are not recorded by SCRS. Lint is not a job kind.

**Evidence:** `make qa-runner-test`, `make qa-runner-image-test`, `TestPostgresQAPipeline`.

## ADR-022 LLM adapter

**Decision:** one client (`internal/llm`) over three wire protocols:
- OpenAI chat completions, which covers OpenAI, Azure OpenAI, Mistral, Groq, DeepSeek, xAI, OpenRouter, Together, Ollama and compatible gateways;
- the Anthropic Messages API;
- Gemini generateContent.

Each has a per-provider key and inference URL, uses the netguard dialer and is retried with backoff. Model output is untrusted: generated tests pass static checks and need approval before they run.

## ADR-023 Per-connection webhook secrets

**Decision:** inbound provider and registry webhooks are verified with the connection's own secret at `/ingest/<provider>/<connection>`, and resolve only to that connection's assets. Outbound subscriptions can be scoped to connections. The shared environment secrets remain only for legacy receivers.

## ADR-024 Report-only gates

**Decision:** these never change an assessment's verdict:
- `hunt` indicator sources and rulesets;
- E2E QA findings (`qa_*`);
- vendor (VEX) statements.

They are shown and counted. Promotion to enforcement (`alert`, `block`) is an explicit admin action.

## ADR-025 Licence data

**Decision:** each component's licence comes from the first of:
- **declared** data the scan already reads: npm lockfiles and installed manifests, Python metadata, Composer locks, and the Alpine and Debian package databases;
- **detected** licence files next to the package, matched with `google/licensecheck`;
- **metadata** from deps.dev, fetched once per package version through the netguard dialer and cached in PostgreSQL.

Expressions are normalised to SPDX. Categories ship as editable, versioned data. The policy evaluates category by distribution model.

**Why:** declared data is authoritative and free, detection covers vendored code and image layers, and deps.dev covers registries whose lockfiles carry no licence (Go, Maven, PyPI requirements). A failed lookup stays *unresolved* rather than "unknown", so an outage never manufactures licence entries.

**Consequences:** the licence gate is report-only until an admin makes the policy enforcing after counsel review (PRD Q24). Pub, SwiftPM and CocoaPods have no metadata source and report "no licence found" unless a licence file is present.

## ADR-026 SBOM generation

**Decision:** the worker generates the stored CycloneDX 1.6 document from SCRS's component model with `cyclonedx-go`. SPDX 2.3 JSON is generated from the same model on export. The scanner no longer runs OSV-Scanner's CycloneDX output.

**Why:**
- OSV-Scanner's CycloneDX drops OS packages it cannot give a package URL; the Debian images in the Trivy parity run produced documents with no components.
- A single model makes CycloneDX and SPDX list the same packages (AT-26) and carry licences.
- It also saves a second OSV-Scanner run per scan.

**Evidence:** `internal/sbom` validates both formats against the official schemas.

## ADR-027 Framework packs

**Decision:** compliance mappings are JSON data packs embedded in the release (`internal/compliance/packs`). Each records the source of its mapping:
- MITRE CWE views for OWASP 2021 and the CWE Top 25;
- OWASP's own 2025 category pages, because MITRE has only the release candidate.

Finding types without a CWE (vulnerable and malicious dependencies, integrity, secrets, misconfiguration) map through `type_categories`. Admins can upload `cwe_mapping` packs; PCI DSS views are code-defined evidence.

**Consequences:** reports state the pack version and source, count unmapped findings, and never compute a compliance verdict.

## ADR-030 Live events

**Decision:** `GET /events` streams server-sent events (OUT-004).
- Every emitted event is also announced with `pg_notify` inside the transaction that records it.
- Each API instance listens on one dedicated PostgreSQL connection and fans notices out to its streams.
- The PRD named Redis Pub/Sub for this.

**Why:**
- A NOTIFY is delivered only after commit and never for a rolled-back change, so a stream cannot announce an assessment that does not exist.
- Events are emitted inside transactions in both the API and the worker. Publishing to Redis after commit would mean changing every emitting call site.

**Consequences:**
- Delivery is fire-and-forget. Clients reload state on connect and on `resync`; webhooks remain the guaranteed path.
- Notices carry ids only, within NOTIFY's 8000-byte limit.
- Transactions that notify serialise briefly at commit, which is negligible at SCRS's event rate.
- Streams are bounded per instance and per token, end after 10 minutes, and drop slow readers.
- The schema-specific channel requires a direct PostgreSQL connection: a transaction-pooling proxy would break LISTEN.

## ADR-031 STIG

**Decision:** CMP-004 targets the DISA Application Security and Development STIG (answering PRD Q23).
- An admin uploads DISA's XCCDF benchmark, and every rule becomes a category keyed by its STIG id.
- SCRS ships a starter mapping of CWEs and finding types for the rules its scans can evidence. Admins edit the resulting pack.

**Why:** SCRS bundles no DISA content, and STIG ids stay stable across releases. Starter entries missing from a release are reported, not silently ignored.

**Consequences:** reports give each rule an evidence value (open findings, no open findings, not evidenced) and never a checklist status such as "Not a Finding".

## ADR-032 PDF reports

**Decision:** PDF is rendered in-process by a small writer in `internal/compliance` (PDF 1.4, standard Helvetica, Flate-compressed pages). It does not use a third-party library or a headless browser.

**Why:**
- No new dependency or container, and no network or file access.
- No timestamps, so reports stay content-addressed: the same report gives the same SHA-256.

**Consequences:** plain tabular layout, and Latin-1 text only (other characters print as `?`).

## ADR-033 Dependency-Track export

**Decision:**
- When the export is enabled, `Complete` inserts a `dtrack_uploads` row in its own transaction (an outbox).
- The worker leases uploads with `SKIP LOCKED` and pushes them with `PUT /api/v1/bom` through the netguard dialer, without following redirects.
- 429, 5xx and network errors retry with exponential backoff, at most 12 attempts. Other 4xx answers fail at once.
- The API key is sealed with the master key and is write-only.

**Why:** a crash between completion and upload cannot lose a push, and Dependency-Track being down never affects an assessment (section 15).

**Consequences:** uploads are visible and retryable through the API, and finished rows are pruned after 90 days.

**Amendment (2026-11-16):**
- `uploaded` only means Dependency-Track accepted the BOM, which it processes afterwards. The worker checks the event token (`GET /api/v1/event/token/{token}`), then the project's `lastBomImport` (`GET /api/v1/project/lookup`), and records `processing` as `processed`, `unconfirmed` or `failed`.
- `:test` reads the key's team permissions (`GET /api/v1/team/self`) and requires `BOM_UPLOAD` and `PROJECT_CREATION_UPLOAD`. The earlier probe (`GET /api/v1/event/token/{random}`) only proved the key was valid.
- A permanent upload failure, or an import that did not happen, emits `dependency_track.upload_failed`, and `GET /system/status` reports a `dependency_track` component.
