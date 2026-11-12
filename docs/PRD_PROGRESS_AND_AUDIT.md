# SCRS production gate status — 2026-11-12

Production sign-off remains withheld. This report supersedes the remaining-gate
list in the earlier AUDIT_2026-11-12.md. It reflects repository implementation and
local evidence, not a live VPS assessment.

## Blockers addressed in this implementation pass

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
assessment queue and complete provider capability/backoff/event contracts are absent. Provider payload and
response/error OpenAPI schemas also need fuller typing and contract acceptance.

## Product requirements still blocking full sign-off

| PRD milestone | Current status |
| --- | --- |
| M0 Foundations/spikes | Partial; required spike/ADR acceptance is incomplete. |
| M1 Platform core | Authentication/lifecycle substantially extended; owners, observability and broader migration/acceptance work remain. |
| M2 Repository scan MVP | Not delivered: immutable fetch, authenticated ingestion/trigger, durable assessments/jobs, recursive inventory, CycloneDX generation for assessed assets, offline OSV matching, findings register and integrity events. |
| M3 Malware/malicious dependencies | Legacy ClamAV verified separately; SCRS orchestration, YARA, malicious-package matching and gates are absent. |
| M4 Threat feeds | Not implemented. |
| M5 Retention/maintenance/outbound | Not implemented. Developer image cleanup is not product retention. |
| M6 Images/registries | Docker Hub/GAR discovery only; digest pull/assessment/layer attribution and remaining adapters absent. |
| M7 Remediation/hardening | Hardening advanced; remediation workflows are absent. |
| M8 Licences/compliance | Not implemented. |
| M9 SAST/reachability | Not implemented. |

These are engineering deliverables, not items that can be closed through deployment
configuration or documentation. The repository is not a complete supply-chain scanner.

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

## Final local API image evidence

| Platform | Local immutable image ID | Docker Scout findings |
| --- | --- | --- |
| ARM64 | `sha256:33a7833be6e11e4c52c77afdc65a0dfcd47871c190b2b82a30ff972d8afa483f` | 0 |
| AMD64 | `sha256:53c3ce234d2b52635f4bb33bdce31c8e626e34ed5b0b5b6f46bc0d03606acba5` | 0 |

These are local image IDs, not published registry manifest digests. SBOM and
SARIF artifacts are in the corresponding `artifacts/<image-id>/` directories.
