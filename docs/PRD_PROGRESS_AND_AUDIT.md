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
| M9 SAST/reachability | Delivered 2026-11-15 ([SAST.md](SAST.md)). Reachability beyond Go remains P2. |
| E2E QA (Karate) and LLM test generation | Delivered ([QA_TESTING.md](QA_TESTING.md)). Scope decision 2026-11-16: the runner is a QA, performance and load service with an operator route for standalone jobs, separate from supply-chain risk. A lint job kind is not implemented. |
| P2 | Delivered 2026-11-15: Dependency-Track export (ADR-033), live events (ADR-030), ASD STIG import (ADR-031), PDF reports (ADR-032), outbound licence compatibility. CPE matching (VUL-007) deferred to spike S14. |
| Platform status | Delivered 2026-11-16: `GET /system/status`, `system.degraded` and `system.recovered` events, a deeper QA runner `/healthz`, scopes on every operation checked against the router, and [STACK.md](STACK.md) with the generated [API_REFERENCE.md](API_REFERENCE.md). |

## Open PRD requirements (audited 2026-11-16)

These requirements have no implementation in the contract or code. The audit searched the
contract, routes and source for each; it does not prove absence of every partial behaviour.
None blocks the delivered modules above, and the PRD marks most as P1 or P2.

| Area | Requirement | Gap |
| --- | --- | --- |
| Assets | AST-001, ING-006 | No `uploaded` asset type or `POST /uploads`; assets come from connection discovery. No `POST /assets`, `DELETE /assets/{id}`, `POST /assets:import` or `GET /assets/{id}/revisions`. |
| Register | RR-008, RR-010, RR-012, RR-014 | No finding comments or assignment endpoints; no register export (CSV or VEX download), summary, timeseries or top-assets aggregates. Triage and waivers go through `PATCH /register/{id}`; VEX is per assessment. |
| SBOM | SBM-005 | Component changes are recorded per assessment (`change` on findings and components); there is no `sbom-diff` endpoint between two revisions. |
| Advisories | OSV-008 | No API to create local `x_SCRS-*` advisories, and no advisory search; `GET /intel/vulnerabilities/{id}` reads one. |
| Malicious dependencies | MAL-004, MAL-005, MAL-006 | No `introduced_by` tagging, minimum-release-age policy (P2) or typosquat heuristic (P2). |
| Integrity | INT-003, INT-012, INT-014, INT-015, INT-018 | No behavioural author signals, large-addition heuristic, Actions inventory, run-number gap detection or incident sweep (`/incidents`, P2). Force-push, branch-churn, mass-deletion, visibility and membership rules exist. |
| Connections | CON-012 | No image-to-source link (`built_from`). |
| Remediation | REM-002 | Isolated egress and no repository writes, but not the full sandbox worker profile. |
| Operations | | No `/jobs` inspection endpoint; scheduled jobs appear in `GET /maintenance/schedule`. |
| Vulnerability matching | VUL-007 | CPE matching, spike S14. |
| Reachability | REA-005, REA-012 | Ecosystems beyond Go. |

## Before declaring the PRD complete

1. Decide for each open row whether it is in version 1 or is formally descoped in an ADR; the PRD still lists
   them. Nothing here changes the stack's connections or scopes.
2. Complete the external acceptance list below.

## External release acceptance still required

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
