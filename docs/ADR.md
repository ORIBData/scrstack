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
| ADR-018 | SAST analyzers as sandboxed external processes | Proposed (M9) |
| ADR-019 | Provider connections in encrypted rows; environment seeds the first | Accepted |
| ADR-020 | OSV schema as the single advisory format | Accepted (amended) |
| ADR-021 | E2E QA on an operator-hosted Karate runner, called by SCRS | Accepted |
| ADR-022 | One LLM adapter over three wire protocols | Accepted |
| ADR-023 | Inbound webhook secrets belong to connections | Accepted |
| ADR-024 | Report-only gates for hunt, QA and vendor statements | Accepted |

## ADR-001 Go module

**Decision:** one Go module, `github.com/ORIBData/scrstack`, at the Go version in `go.mod` (1.27).

**Why:** the PRD's floor came from `cyclonedx-go`. The current toolchain also gives `net/http` method and wildcard routing, `log/slog` and `min`/`max`.

**Consequences:** `make test` runs the whole module with the race detector.

## ADR-002 Repository and images

**Decision:** SCRS lives in the fork of the ClamAV REST project, and the legacy scanner keeps working (`docs/DOKPLOY.md`). The PRD proposed two images. There are three trust boundaries:
- the SCRS image (`deploy/Dockerfile.scrs`: API, worker, scanner, feed-sync, egress proxy);
- the official ClamAV image;
- the Karate runner image (`deploy/karate-runner/Dockerfile`), which runs repository test code and holds no SCRS secrets.

**Consequences:** two images are released (`make release`, `make release-qa-runner`). See ADR-021.

## ADR-003 Single binary with role sub-commands

**Decision:** `scrs api`, `worker`, `scanner`, `feed-sync`, `egress-proxy`, `yara-install`, `init` and the maintenance commands come from one binary. The Karate runner is a separate small binary (`cmd/scrs-qa-runner`) because it ships in another image.

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

## ADR-018 SAST analyzers (proposed, M9)

**Decision to build:** gosec, Bandit and Bearer as sandboxed external processes behind a Go interface, in a scanner image, never linked into SCRS.

**Status:** not built. SARIF import covers external SAST tools meanwhile.

## ADR-019 Provider connections

**Decision:** connections (credentials, scope, webhook secret) are encrypted rows managed through the API. The environment only seeds the first GitHub connection.

## ADR-020 Advisory format (amended)

**Decision:** matching runs only on OSV records, offline. NVD and CVE Program records are converted to OSV-schema records with `origin` `nvd` or `cve5`, and the original is stored verbatim (`advisory_records`). They enrich findings, adding severity sources and CWEs, but do not create matches. Aliases come from the OSV records.

**Amendment:** there is no separate alias-graph table yet; findings carry OSV aliases.

## ADR-021 E2E QA runner

**Decision:** Karate tests run on an operator-hosted runner (`scrs-qa-runner`). SCRS pushes jobs to it and polls, and the runner never calls SCRS. The runner:
- holds no SCRS secrets;
- runs tests as a separate user with six capabilities;
- drops `.karate/` and `karate-pom.json`;
- redacts secrets from reports.

It can run in the Dokploy stack on an internal network or on its own VM. Keploy was evaluated and rejected because it needs root and eBPF and records traffic.

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
