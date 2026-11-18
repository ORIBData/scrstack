# SCRS production gate status — 2026-11-12

> **Historical record (2026-11-12).** The milestone status below is out of date: M2–M7 have since been delivered. Current status and remaining work are in the README roadmap and [PRODUCTION_READINESS_AUDIT.md](PRODUCTION_READINESS_AUDIT.md).

**Latest implementation status:** see [PRD expansion audit](PRD_EXPANSION_AUDIT.md).
It supersedes this report for malware, IOC, workflow ingress, retention and active
automatic remediation. The evidence below records the earlier baseline.

Production sign-off remains withheld. This report supersedes the remaining-gate
list in the earlier AUDIT_2026-11-12.md. It reflects repository implementation and
local evidence, not a live VPS assessment.

## Pipeline delivery update

The repository now includes durable PostgreSQL assessment jobs, immutable GitHub
archive acquisition, an isolated offline OSV-Scanner 2.7.1 worker path, CycloneDX
SBOMs in content-addressed S3 storage, findings and immutable assessment snapshots,
waiver expiry and audit history, plus opt-in advice-only npm remediation jobs.
See [implementation, operating limits and acceptance gaps](ASSESSMENT_PIPELINE.md).

New regression cases cover actor-scoped idempotency, per-asset serialization, lease
expiry/cancellation, revision fencing, historical findings, incomplete scans preserving
previous findings, remediation admission/result persistence and trigger-only authorization.
`make scanner-test` builds the same locked upstream graph as the image and confirms a
synthetic vulnerable package is detected despite repository suppressions and gitignore.

This remains a partial M2/M7 implementation. Malware/IOC/integrity stages are explicitly
skipped and force incomplete verdicts. Guided remediation defaults off pending actual
provider-backed acceptance. No full production sign-off is issued.

The historical zero-finding image results below apply only to the smaller baseline
API image. The new image includes OSV and has 209 indexed packages. Its first Scout
scan reports CVE-2025-15558 against Docker CLI 29.7.1. This is assessed as not applicable:
[Docker's own advisory](https://github.com/docker/cli/security/advisories/GHSA-p436-gjf2-799p)
limits impact to Windows CLI plugin-manager binaries and says the fix is in 29.2.0.
Our runtime is Linux, with a later version. Raw SARIF remains retained without silent
suppression, and `make image-audit` still exits nonzero for that raw finding.
Go vulnerability analysis of the locked OSV command reports no vulnerabilities.

## Foundation baseline evidence (before the pipeline extension)

| Area | Implementation and verification |
| --- | --- |
| Authentication | PostgreSQL stores only token hashes; serialized bootstrap creation/rotation; managed token create/list/revoke; scope enforcement; expiry and CIDR constraints; no positive auth cache that could retain revoked access. |
| Request controls | Atomic Redis sliding-window limits (120/min/token), fail-closed Redis/store behavior, exact CORS origins, configurable docs authentication, explicit trusted proxy ranges. |
| Connection lifecycle | PATCH scope/enabled, credential rotation, DELETE as disable. Inventory and audit remain; scan eligibility is withdrawn until successful rediscovery. Monotonic revision locking rejects stale provider results even when timestamps are equal. Provider identity cannot change under an existing name. |
| Audit | Connection changes include authenticated actor IDs; token creation/revocation and bootstrap rotation are audited transactionally. |
| Performance | API connection pagination; batched asset writes; pooled readiness clients and nonblocking concurrent health polling. |
| Persistence | Concurrent migration/bootstrap tests; reconciliation rollback and stale-call tests; actual PostgreSQL dump/restore verifying credential decryption, revoked tokens, and retained disabled inventory. |
| Legacy scanner boundary | Separate required service token, bounded request concurrency/body size, server timeouts; host filesystem scan routes return 410; malformed multipart no longer panics. 18 container fixture tests passed, including EICAR detection, size errors, protocols and retired path routes. The legacy scanner is not the SCRS assessment pipeline. |
| Runtime dependencies | Updated x/net, x/crypto, compress and transitives. API runtime is a nonroot static binary plus CA certificates, with no shell/libc/package manager. Go vulnerability check reports no vulnerabilities. |
| Image assessment | Initial API image: 11 findings across six packages. Rebuilt API image: zero reported findings, 30 indexed packages; CycloneDX SBOM and SARIF retained by image ID under artifacts/. This is time-bound scan evidence, not a guarantee of absence of defects. |
| Deployment | Dokploy labels select host and `/scrs/v1/*`, HTTPS resolver, redirect and shared proxy network. No host port or prefix stripping; admin database URL only reaches init. Rendered Compose assertions passed. |
| Release/CI | Registry-neutral dated source-hash tags; SBOM/provenance requested on push; inherited upstream automatic publisher archived; SCRS CI performs QA without publishing. |

## QA evidence

- `make qa`: focused Go race tests, repository-wide go vet, API path/contract checks,
  legacy security unit regressions and 10 Python tooling/deployment tests passed.
- `make database-test`: PostgreSQL reconciliation/concurrency, token/lifecycle,
  Redis rate-window and dump/restore integration tests passed using disposable stores.
- `make storage-integration`: nonroot minimal API image initialized PostgreSQL/S3,
  checked Redis/S3, authenticated connection creation, and repeated initialization.
- AMD64 API image cross-build passed; ARM64 API integration passed.
- ClamAV disposable container fixture suite: 18 passed.
- `govulncheck@v1.9.0 ./...`: no vulnerabilities found after dependency updates.
- Docker Scout assessment and CycloneDX generation passed on the rebuilt local API
  image. Exact image identifiers and findings are retained in artifacts/*/image.json.
- GitHub-hosted CI has been configured but not executed remotely. No release push,
  signature, production database mutation or VPS deployment was performed.

## Architecture decisions and remaining limits

AUTH-004's proposed positive Redis auth cache is deliberately not implemented:
PostgreSQL is consulted on every request, preventing stale-cache acceptance after
revocation. This costs a lookup plus a throttled last-used update; production load
and capacity targets still need measurement. Redis is used for admission control.
Bootstrap rotation must be coordinated across replicas with identical env settings.

DELETE connection is a reversible disable, not a physical purge. Its assets stay
in the risk history. This protects evidence and avoids deletion cascades. Explicit
retention/purge policy remains part of the unimplemented product modules.

The basic schema remains maintained through serialized idempotent DDL with a version
record. A complete migration/rollback lifecycle and broader observability/owner model
are not yet delivered. Provider network calls are bounded but synchronous; a durable
assessment queue now exists in PostgreSQL; complete provider capability/backoff/event contracts remain absent. Provider payload and
response/error OpenAPI schemas also need fuller typing and contract acceptance.

## Product milestone status (reconciled 2026-11-16)

Earlier versions of this table lagged the code. It now follows the delivery records in
[PRODUCTION_READINESS_AUDIT.md](PRODUCTION_READINESS_AUDIT.md) and the contract.

| PRD milestone | Status |
| --- | --- |
| M0 Foundations/spikes | Delivered: ADR-001 to ADR-033 ([ADR.md](ADR.md)) and spikes S1 to S13 ([SPIKES.md](SPIKES.md)). Measurements left: OSV and ClamAV throughput, mobile sample repositories, NVD volumes. |
| M1 Platform core | Delivered: auth and bootstrap token, scoped tokens, owners, audit log, health, readiness, `/system/status`, metrics, request ids. |
| M2 Repository scan MVP | Delivered for GitHub and GitLab: archive acquisition, durable jobs, recursive inventory, CycloneDX SBOM and MBOM, offline OSV, register, direct and relay ingest, integrity events. Needs acceptance with real accounts. |
| M3 Malware/malicious dependencies | Delivered: ClamAV, starter YARA, IOC matching, OSV `MAL-` records. YARA is limited to ClamAV's subset (no modules). |
| M4 Threat feeds | Delivered: indicator sources, STIX, CSV and TAXII, vulnerability-source registry, NVD and CVE Program, KEV and EPSS, vendor VEX. Needs live NVD and TAXII acceptance. |
| M5 Retention/maintenance/outbound | Delivered: retention classes, maintenance, signed webhooks and schemas, mirrors, last known good, agent payloads. |
| M6 Images/registries | Delivered: Docker Hub, GAR, Harbor and OCI adapters, layer-level scanning, registry push events, Trivy parity run ([TRIVY_PARITY.md](TRIVY_PARITY.md)). |
| M7 Remediation/hardening | Delivered as advice-only plans for npm (`package-lock.json`) and Maven (`pom.xml`) with isolated egress; no repository writes. Provider acceptance remains. |
| M8 Licences/compliance | Delivered 2026-11-14 ([LICENSES_AND_COMPLIANCE.md](LICENSES_AND_COMPLIANCE.md)); STIG and PDF reports added in P2. |
| M9 SAST/reachability | Delivered 2026-11-15 ([SAST.md](SAST.md)). Import-level reachability for npm and PyPI delivered 2026-11-17; call graphs beyond Go remain P2. |
| E2E QA (Karate) and LLM test generation | Delivered ([QA_TESTING.md](QA_TESTING.md)). Scope decision 2026-11-16: the runner is a QA, performance and load service with an operator route for standalone jobs, separate from supply-chain risk. Lint job kind delivered 2026-11-17: `kind` `lint` runs ruff, mypy, bandit, pylint, PHPStan, phpcs, clang-tidy, golangci-lint, ESLint, ktlint, SwiftLint and `dart analyze` over the assessed commit's source (ruff in the runner image, the rest in the lint image, `make qa-runner-lint-image`), per Go module, ESLint project and Dart package, with `qa_lint` and `qa_lint_config` entries, a profile `lint` setting, and lint-only profiles (`functional: false`, no `base_url`). Verified against the real pinned binaries in the built image (all twelve tools, with and without dependency installs for Go, ESLint, Dart and Composer; Python tools run without the repository's packages); not verified on your host, on real repositories or at scale. Mobile coverage is style-level: SwiftLint's static build skips SourceKit rules, ktlint checks style only, and there is no Android lint or Xcode build. |
| P2 | Delivered 2026-11-15: Dependency-Track export (ADR-033), live events (ADR-030), ASD STIG import (ADR-031), PDF reports (ADR-032), outbound licence compatibility. CPE matching (VUL-007) deferred to spike S14. |
| AI advisories, summaries and chronicle | Delivered 2026-11-16: allowlisted findings-and-advisory-text prompts, summary and per-finding advisories with provenance and supersession, self-hosted embeddings, compose services for `scrs-embed` and the model host ([MODEL_HOST.md](MODEL_HOST.md)). Delivered later the same day: summaries in JSON, Markdown and PDF reports (`params.include_ai_summaries`), `GET /assets/{id}/chronicle/search` and `POST /knowledge:backfill`. Linters are not built. |
| AI code review | Delivered 2026-11-16 on a self-hosted model: guarded model calls, `ai_review` entries, per-assessment token budget and ledger ([LLM_KNOWLEDGE.md](LLM_KNOWLEDGE.md)). Lint entries are shown to the review as per-file context. AI triage of QA results delivered 2026-11-17 (`POST /qa/runs/{id}/triage`, profile `ai_triage`): a run summary and per-entry advisories for failures, load breaches and lint entries, source-rule gated like code review. |
| Dependency-Track link | Delivered 2026-11-16: processing checks, permission-aware `:test`, `dependency_track` status and `dependency_track.upload_failed`, findings read-back as one entry per vulnerability, shared triage, provider-qualified project names ([DEPENDENCY_TRACK_AUDIT.md](DEPENDENCY_TRACK_AUDIT.md)). |
| Platform status | Delivered 2026-11-16: `GET /system/status`, `system.degraded` and `system.recovered` events, a deeper QA runner `/healthz`, scopes on every operation checked against the router, and [STACK.md](STACK.md) with the generated [API_REFERENCE.md](API_REFERENCE.md). |

## Open PRD requirements (audited 2026-11-16)

Rows say what is delivered and what is not. Earlier rows described gaps; the audit searched the
contract, routes and source for each; it does not prove absence of every partial behaviour.
None blocks the delivered modules above, and the PRD marks most as P1 or P2.

| Area | Requirement | Gap |
| --- | --- | --- |
| Assets | AST-001, ING-006 | Delivered (phase 1): `POST /assets`, `POST /assets:import` (up to 500, per-item results), `DELETE /assets/{id}` (manual assets with no history only) and `GET /assets/{id}/revisions`. Manual assets live under an existing connection and are never marked inaccessible by discovery. Delivered (phase 1b): the `uploaded` asset type and `POST /uploads` (multipart `.tar.gz`, 64 MiB at most). An upload belongs to a built-in `scrs-uploads` connection (provider `upload`, hidden from `GET /connections` and not editable); the archive is kept under `uploads/` in object storage, its SHA-256 prefix is the revision, and the worker scans it like a repository snapshot. Uploads are deleted with `DELETE /assets/{id}/uploads/{upload}` (admin), an uploaded asset with `DELETE /assets/{id}` while it has no history, and the `uploaded_archives` retention class removes archives a newer upload with the same label replaced. Not built: QA runs and remediation for uploads. |
| Register | RR-008, RR-010, RR-012, RR-014 | Delivered (RR-008): `PUT /register/{id}/assignee` (free-text identifier, no user model), `GET` and `POST /register/{id}/comments`, `DELETE /register/{id}/comments/{comment}` (admin), `assignee` and `unassigned` filters on the list and every aggregate, an `assignee` column in the CSV export, and `assigned` and `comment.*` entries in the history. Delivered 2026-11-17: the outbound `finding.assigned` event (finding, asset, new and previous assignee, caller), sent when an assignee changes or is cleared, scoped to the asset's connection. Not built: comment editing, user accounts or in-app notifications. Delivered earlier: `GET /register` filters (asset, status, severity, type), `/register/summary`, `/register/timeseries`, `/register/top-assets`, `/register/export` (CSV or JSON, 50000 rows at most) and `/register/vex` (one OpenVEX document for the filtered register). Triage and waivers go through `PATCH /register/{id}`. |
| SBOM | SBM-005 | Component changes are recorded per assessment (`change` on findings and components); delivered (phase 2): `GET /assets/{id}/sbom-diff?from=&to=` compares two revisions (added, removed, version-changed and licence-changed packages). |
| Advisories | OSV-008 | Delivered: `POST /advisories` (local `x_SCRS-<year>-<n>` OSV records with exact versions, semantic-version `ranges` for npm, Go, crates.io, NuGet, Hex and Pub, or `all_versions`), `GET /advisories` search, `GET /advisories/{id}`, `POST /advisories/{id}:withdraw` and `GET /advisories/{id}/affected`. A local advisory opens register entries from the stored inventories at creation and at every later assessment (`malicious: true` raises `malicious_dependency` entries that fail the gate), and withdrawing it closes them. Limits: ranges for PyPI, Maven, Debian, RubyGems and other ecosystems are refused (list their versions); matching is by ecosystem, name and version, with no CPE. |
| Malicious dependencies | MAL-004, MAL-005, MAL-006 | Delivered: `introduced_by` on entries about a dependency that is new since the previous scan of the ref (the trigger's claimed actor, the commit and the assessment; kept for the entry's life and in `malicious_dependency.reported`), and `GET`/`PUT /policies/dependencies` with `min_release_age_days` (publish dates from deps.dev, cached) and `typosquat` (a curated npm and PyPI list, one edit or separator away). Both are off by default, produce `suspicious_dependency` entries of severity medium that never change a verdict, and report a partial `dependency_policy` stage when they could not cover every package. Limits: the popular-package list is a seed of about 260 names, not a ranking; `introduced_by` names the claimed pusher, not a verified commit author (a git archive carries no author); neither check looks at image layers beyond the ecosystems deps.dev covers. |
| Integrity | INT-003, INT-012, INT-014, INT-015, INT-018 | Delivered: `GET`/`PUT /policies/integrity` (all off by default) with new-author, off-hours and pusher-differs signals from push webhooks, and large-new-file and CI-file-growth entries from scans; `GET /assets/{id}/actions` and `POST /assets/{id}/actions:check` (Actions inventory, `actions_unused`, workflow-list changes and run-number gaps; scheduled with `SCRS_ACTIONS_SWEEP_INTERVAL_HOURS`); `POST /incidents`, `GET /incidents` and `GET /incidents/{id}`. Not built: signed-to-unsigned commit detection (INT-003, a push payload carries no signature data), a binary-versus-text test for the large-file check (the inventory has sizes only), and the optional GitHub sweep of events older than retention (INT-013). Author identity and actors are claims from the event. Force-push, branch-churn, mass-deletion, visibility and membership rules existed already. |
| Connections | CON-012 | Delivered: `GET`/`POST /assets/{id}/links` and `DELETE /assets/{id}/links/{to}` (kind `built_from`; image to GitHub, GitLab or uploaded source), plus automatic links from the image's `org.opencontainers.image.source` label at each image assessment, and `source_repository` on an image's register entries. A label link is dropped when the label stops naming the repository; a manual link never is. Limits: only `built_from` (no `deployed_from`); the label is the publisher's claim; a label links only when it names exactly one known repository, and a self-hosted GitLab is recognised only by a host name starting with `gitlab`. |
| Remediation | REM-002 | Delivered: guided remediation runs in a separate sandbox container (`scrs-remediator`, the scanner image in the `remediation` role) with its own token, no SCRS secrets, a private network shared only with the worker and the egress proxy, a disposable `noexec` tmpfs, CPU, memory, process and time limits, and no package-manager scripts. Still advice only. Not verified on a real host: the limits are Compose settings, and `osv-scanner fix` runs as the container user (it can read that container's own environment, which holds only the sandbox token). |
| Operations | | Delivered: `GET /jobs`, `GET /jobs/{id}` and `POST /jobs/{id}:cancel`, one normalised view over assessments, QA runs and generation, AI summaries and reviews, reports, mirrors and Dependency-Track uploads (each keeps its own table and endpoints). Only assessments and QA runs can be cancelled. Delivered 2026-11-17: every long operation that is a job (assessments, QA runs and generations, AI summaries and reviews, reports, mirrors) answers with `job_id` and `status_url` beside its `Location`, so one poll loop on `GET /jobs/{id}` serves them all. Not built: progress percentages, and scheduled maintenance jobs in the list (they stay in `GET /maintenance/schedule`). |
| Vulnerability matching | VUL-007 | Not built (spike S14). CPE matching is for software with no package URL (binaries in images), and the pipeline has no such components: the scanner reads package managers' databases and lockfiles, which all carry purls, and nothing detects loose binaries. CPE matching needs that detection first, or a CycloneDX import that carries `cpe` for components, plus a CPE dictionary and NVD applicability matching. |
| Reachability | REA-005, REA-012 | Delivered (REA-005): import-level reachability for npm and PyPI (`imported_only`, method `import_graph`, up to five places), `unknown` otherwise and never `not_reachable`; `GET /reachability/capabilities` lists it. Not built: call-graph analysis beyond Go (REA-012 spike S12 for Java/Kotlin, Python and C#) and taint traces across a library boundary (REA-010). A dynamic or computed import is missed, and a PyPI distribution whose module name differs is matched only by a short table. |

## Before declaring the PRD complete

1. Decide for each open row whether it is in version 1 or is formally descoped in an ADR; the PRD still lists
   them. ADR-035 (Proposed 2026-11-17) makes that call with recommendations; it is Accepted when the product owner agrees. Nothing here changes the stack's connections or scopes.
2. Complete the external acceptance list below.

## External release acceptance still required

The ordered procedure, with `make deployment-acceptance`, `make pipeline-acceptance` and an evidence table, is in [STAGING_ACCEPTANCE.md](STAGING_ACCEPTANCE.md).

1. Configure a real domain/DNS and Dokploy's existing ACME resolver; deploy the exact
   published image digest; verify public TLS/redirects, `/scrs/v1/docs`, readiness,
   authorization, restart recovery and certificate renewal settings.
2. Validate intended GitHub organizations/OAuth approvals and registry credentials,
   inventory coverage, expiry and provider rate limits with representative accounts.
3. Publish and sign the release manifest under the operator's trusted identity;
   verify signatures and retained attestations for each deployed platform.
4. Perform hosted PostgreSQL and S3 disaster-recovery acceptance, load/fault testing,
   and recovery-time/recovery-point measurements for the completed product.

The operator confirmed they will select the domain and configure Dokploy/Let's Encrypt.
No concrete staging URL or VPS access is available for live acceptance yet.

## Historical foundation API image evidence

| Platform | Local immutable image ID | Docker Scout findings |
| --- | --- | --- |
| ARM64 | `sha256:33a7833be6e11e4c52c77afdc65a0dfcd47871c190b2b82a30ff972d8afa483f` | 0 |
| AMD64 | `sha256:53c3ce234d2b52635f4bb33bdce31c8e626e34ed5b0b5b6f46bc0d03606acba5` | 0 |

These are local image IDs, not published registry manifest digests. SBOM and
SARIF artifacts are in the corresponding `artifacts/<image-id>/` directories.

## Pipeline engineering and QA assessment

| Concern | Review outcome and evidence |
| --- | --- |
| Business logic | Admission requires a discovered permitted asset; ambiguous connection matches return 422. Partial scans never pass or close old findings. Duplicate findings do not inflate counts. Candidate fixed versions are limited to the affected package. |
| Architecture | PostgreSQL transaction owns admission, audit and idempotency; no database-to-Redis dual-write. Worker, offline scanner and feed downloader have distinct credential/network boundaries. Additional roles use one release image. See the queue ADR rationale in ASSESSMENT_PIPELINE.md. |
| Concurrency | Per-asset unique running index, FIFO claim ordering across retry backoff, expiring leases, three-attempt limit and configuration-revision fencing. Cancellation and stale completion tests pass against PostgreSQL. |
| Authorization | Trigger-only users see their own jobs; read cannot enqueue/cancel; remediation requires write; suppression/acceptance requires admin. Cross-token tests and trigger-to-remediation bypass tests pass. |
| Security | Fixed GitHub origins, no credential forwarding to archive redirects, bounded archive extraction rejecting traversal/links/special files, trusted scanner config overriding repository suppressions, no inherited secrets in analyzer commands. Redirect and real upstream suppression regression tests pass. |
| Performance | Queue cap, bounded result sizes, paginated reads, batched component/finding writes, history/admission indexes and assessment pool capped at eight connections. Large feed/repository memory and throughput still need deployed measurements. |
| Data loss | Cancellation preserves history; findings and audit commit atomically; S3 artifacts are hash-addressed and read-verified. Disposable MinIO round-trip and tamper rejection passed. No production purge is implemented. Unreferenced objects may remain after failed publication. |
| Remediation | Parent asset/manifest/commit admission and result persistence tested. No provider writes. Actual upstream fix execution through deployed egress remains unverified and disabled by default. |
| QA | Final local `make qa`, expanded `make database-test`, `make scanner-test`, and image/storage integration passed. One scanner rebuild initially failed due local disk exhaustion and passed on repeat after concurrent build jobs ended. No live data-store tests or provider writes occurred. |
| Production failure paths | Stale feeds reject scans; parser warnings and unsupported/oversized inputs fail closed; worker failure retains incomplete verdict. Metrics/alert delivery, fleet scheduling, provider rate-limit recovery and real VPS fault/load testing remain open. |

The default Go test target skips service-backed fixtures when their explicit test
variables are absent. The dedicated database/scanner targets were run to exercise
those cases. A passing default test run alone is not sufficient evidence for them.

## Final pipeline image evidence

| Platform | Local immutable image ID | Raw Scout findings |
| --- | --- | --- |
| ARM64 | `sha256:7539e736348f18e2539303a0a0bace345f092d519513b540ac6b9607c82bc74a` | 1 (CVE-2025-15558; applicability assessment above) |
| AMD64 | `sha256:9a093cdeb2e9c8ef34b9e0a345e553b1aa361825e30ba4e1f956309629c2626a` | 1 (same advisory) |

Both images built and executed the OSV version command with network disabled,
read-only root and all capabilities dropped (AMD64 through local emulation).
SBOM/SARIF and image metadata are retained under `artifacts/<image-id>/`. These
are local working-tree builds, not published or signed release manifests.
The raw image-audit gate remains nonzero; no finding was suppressed automatically.
