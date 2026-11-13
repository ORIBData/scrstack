# Production-readiness audit: Dokploy/Traefik deployment (2026-11-12)

Scope: SCRS service code (`cmd/scrs`, `internal/*`, `api/`), the Dokploy Compose
deployment and its runtime dependencies. Business logic, performance, security,
authorization, race conditions, data loss and lint were reviewed. The legacy
root scanner (`clamrest.go`, root `docker-compose*.yml`) is not part of the
Dokploy deployment and was not re-audited. This supersedes the "remaining
gates" lists in the earlier audits only where stated below.

**Disposition:** the defects that would break a first deployment or mislead a CI
gate are fixed and verified locally. Live VPS acceptance (`make
deployment-acceptance` against the real domain) has not been run and is still
required.

## Fixed findings

| Severity | Area | Finding | Fix | Evidence |
| --- | --- | --- | --- | --- |
| Critical | Deployment | The live OSV npm archive holds 231,736 records (mostly `MAL-` reports), but feed validation capped archives at 200,000 entries. With the default `SCRS_OSV_ECOSYSTEMS=npm,Go`, feed sync always failed, so the scanner never became healthy, the worker never started, and no assessment could run. | Cap raised to 1,000,000; the existing per-entry (2 MiB) and total (2 GiB) expansion limits still bound it. | `TestRealFeedArchiveValidates` passes against the downloaded live npm `all.zip` (373 MiB uncompressed, 6.7 s). |
| High | Business logic | Verdict `incomplete` overrode `fail`. Every assessment is currently partial (integrity is partial by design), so malware, malicious-dependency, IOC and critical hits were all reported as `incomplete`. A CI gate blocking on `fail` would never block. | `fail` now outranks `incomplete` (TRG-006, MAL-007). Integrity entries gate as `fail` (PRD Q19 default). | `TestVerdictGate`; DB test asserts a critical in a partial scan is `fail`. |
| High | Business logic | Waivers had no effect on the gate: an admin-approved `accepted` finding (or `suppressed`/`false_positive`) still failed every later assessment. | The verdict excludes unexpired waivers and reports them as `counts.waived`. Waived malicious content stays at least `warn` (MAL-007). Snapshots keep raw detections. | `TestVerdictGate`; DB regression `waivedRun`. |
| High | Business logic | Findings never closed as `fixed`. Closure required a fully `complete` scan, which cannot currently happen. It also required that no commit be pinned, which excluded every GitHub webhook push, the primary trigger path. Upgraded dependencies therefore stayed `open` forever. | Closure now runs per finding type, only when that type's producing stages completed, and only for the ref's current head (`ref_moved=false`). Webhook pushes qualify. Integrity entries are not auto-closed while that stage is partial. | `TestClosableTypesRequireProducingStages`; DB regression closes `TEST-002` on a webhook-style scan and leaves the waived entry intact. |
| High | Correctness | SCA failed as "incomplete coverage" whenever scanner stderr contained "error" or "warning". OSV-Scanner echoes every scanned lockfile path to stderr, so a repository with e.g. `packages/error-pages/package-lock.json` never got SCA coverage. | Known progress lines (`Scanning dir …`, `Scanned … file and found N packages`) are excluded before the check. Genuine error and warning lines still fail closed. | Real OSV binary run: old check fails, new check passes; `TestScannerProgressPathsAreNotProblems`. |
| Medium | Performance/cost | A persistent feed failure re-downloaded ~230 MiB every minute (~330 GB/day of egress on the VPS). | Exponential backoff, 1 min doubling to 1 h, reset on success; the error cause is now logged. | Code review; `go vet`/staticcheck clean. |
| Medium | Deployment | Scanner healthcheck `start_period` was 120 s, but the first deploy must download and validate the OSV feeds. On a slow link Compose would mark the scanner unhealthy, and the worker's `depends_on` would abort the Dokploy deploy. | `start_period: 15m` with `start_interval: 10s`, so a fast sync still becomes healthy quickly. | `docker compose config` renders both values. |
| Medium | Operability | Worker, scanner and feed-sync logged failures with no cause ("assessment failed"), so production incidents could not be diagnosed. | Errors are logged with their sanitized cause; stored assessment errors stay generic. | Code review. |
| Medium | Security (lint SA1019) | GAR credentials were parsed with the deprecated `google.CredentialsFromJSON`, which accepts any credential type, including external-account configs that fetch from arbitrary URLs. | `CredentialsFromJSONWithType(…, google.ServiceAccount, …)`. | staticcheck clean. |
| Low | Integrations | GitHub tag pushes returned 400, so GitHub showed failed deliveries for every release tag. | Non-branch refs are acknowledged with 200 `ignored_non_branch_ref`; OpenAPI updated. | `TestWebhookSignatureAndEventValidation` case added. |
| Low | Security | With a trusted proxy and no `X-Forwarded-For`, the client IP became invalid, so IP-restricted tokens were rejected. | The peer address is used when the header is absent. | `TestClientIPTrustBoundary` case added. |
| Low | Browser clients | CORS omitted `PUT` (retention, indicators) and the `Idempotency-Key`/`If-Match` headers, and exposed no response headers (`Location`, `ETag`, cursors). | Methods, allowed headers and exposed headers completed. | Existing CORS test passes. |
| Low | Correctness | The connection list used the page before checking the store error. | Error checked first. | Code review. |
| Lint | Tests | Dead assignment in `store_test.go` (SA4006). | Removed. | staticcheck clean. |

## Reviewed and found sound

- **Authorization:** every management route passes `protect` with explicit scopes.
  Trigger tokens see only their own assessments. Read tokens cannot enqueue, cancel or
  triage. Waivers and suppressions need admin. The webhook route uses only HMAC over
  the exact body plus delivery-ID replay protection. Revocation is checked in
  PostgreSQL on every request (no positive cache).
- **Races:** lock ordering is connection → asset in discovery, change, admission and
  completion, so these paths cannot deadlock. Admission and claim use advisory locks
  plus `SKIP LOCKED`. A partial unique index allows one running job per asset. Leases
  and configuration revisions fence stale workers. Cancel during a run is rejected
  at publication.
- **Data loss:** there are no hard-delete endpoints. Connection DELETE disables the
  connection and keeps its inventory and history. Retention purges only raw inbound
  events older than the policy (default: keep forever), in batches of 1,000, with
  revision-checked, audited policy changes. Queued/running jobs' events are protected.
  S3 artifacts are content-addressed and hash-verified on read.
- **Archive handling:** traversal, links, special files, duplicate paths, multiple
  roots and expansion limits are rejected. Scanner subprocesses inherit no credentials.
  The scanner network is internal-only. Remediation egress is allow-listed to
  npm/deps.dev and to public IPs only.
- **Capacity:** measured OSV-Scanner peak RSS with the full npm feed is ~520 MiB per
  pass (~6 s), within the scanner's 2 GiB limit.

## Remaining risks (not fixed; decide before relying on them)

1. **Clean repositories read `incomplete`, never `pass`.** The integrity stage is
   partial by design and independent YARA is absent. Gate CI on `verdict == "fail"`
   and treat `incomplete` as "no known blocker, partial coverage".
2. **No scheduled maintenance.** Retention purge is manual
   (`POST /settings/retention:purge`). `audit_log`, `finding_events` and expired
   `assessment_idempotency` rows grow without bound. This is acceptable at low
   volume; add a scheduler before heavy webhook traffic.
3. **Observability.** The API has no access log or metrics. Use Traefik access logs.
   The API healthcheck uses `/readyz`, so while PostgreSQL, Redis or S3 is down
   Traefik drops the router and clients see 404, not 503.
4. **Throughput.** One worker and one scanner slot are validated. ClamAV opens one
   connection per file inside a 90 s content budget, so large repositories may report
   malware coverage as `partial`.
5. **Third-party image CVEs.** The ClamAV image's 84 raw Scout findings (earlier
   audit) remain unassessed.
6. **PRD gaps** (unchanged): image/digest assessment, YARA, full integrity, outbound
   webhooks, licences, SAST, and gating on *new* criticals only (all criticals gate today).

## Verification run for this audit

- `make test lint contract-check qa`: all Go packages with the race detector, gofmt,
  `go vet`, OpenAPI contract checks and 12 Python deployment/tooling tests passed.
- `staticcheck` (all non-style checks): clean.
- `make database-test`: disposable PostgreSQL 16, Redis 7 and MinIO, including the new
  closure/waiver regression, passed.
- Real `osv-scanner` fixture suite (`SCRS_TEST_OSV_BINARY`): passed.
- Live npm OSV archive: validated by `validateFeed`; real scan memory measured.
- `make storage-integration`: the production image built from `deploy/Dockerfile.scrs`
  bootstrapped disposable PostgreSQL/Redis/MinIO and served authenticated requests; passed.

## Dokploy deployment checklist

1. `make image-reference`, then `make release` and copy the concrete `SCRS_IMAGE` tag.
2. In Dokploy, create a Compose service from `deploy/compose.dokploy.yaml`. Set every
   variable in `.env.example`, with unique random values for `SCRS_MASTER_KEY`
   (`openssl rand -base64 32`), `SCRS_BOOTSTRAP_API_TOKEN` and `SCRS_SCANNER_API_TOKEN`
   (`openssl rand -hex 32` each). Store the master key outside the VPS: a database
   backup is useless without it.
3. Match `SCRS_TRAEFIK_NETWORK`, the entrypoints and `SCRS_CERT_RESOLVER` to Dokploy's
   Traefik. Do **not** also add a domain for this service in Dokploy's Domains UI.
4. Allow outbound HTTPS from the VPS to `osv-vulnerabilities.storage.googleapis.com`,
   `api.github.com`, `codeload.github.com`, the ClamAV mirrors and (for remediation)
   `registry.npmjs.org`/`api.deps.dev`.
5. The first deploy can take several minutes while feeds download. The worker starts
   once `scrs-scanner` is healthy. ClamAV downloads signatures on first start; until
   then malware coverage reads `partial`.
6. Set `SCRS_PUBLIC_BASE_URL` and run `make deployment-acceptance`.

## Update 2026-11-13: outbound webhooks, relay and M1–M7 completion

**Delivered:**
- **Outbound webhooks.** Signed delivery from a transactional outbox, with retries, dead-letter and redelivery. Summary, full and agent profiles; SSRF-safe dialing.
- **n8n relay ingestion.** GitHub `pull_request` assessments and integrity alerts (INT-001/002/008/009/010/011).
- **M1:** owners and asset attributes, metrics, request IDs, access logs.
- **M2:** batch trigger, latest-by-commit, long-poll, filters, last-known-good, diffs and new-versus-existing gating.
- **M3:** YARA (via ClamAV, proven by canary), campaign indicator types, KEV/EPSS.
- **M5:** scheduler, maintenance actions, inbound-event log with replay, delivery-log retention, source snapshots, n8n reference workflows.
- **M6:** Docker Hub/GAR images by digest.
- **M7:** Maven remediation, OpenVEX, load testing.

**Defects found and fixed while building:**

| Severity | Finding | Fix |
| --- | --- | --- |
| High | PR assessments passed the `pull/<n>` label to GitHub as a ref to resolve; every PR scan would have failed. | PR scans pin only the head commit. Worker regression test. |
| High | Integrity change records (workflow changes, provider events) would have auto-closed as `fixed` once the integrity stage completed. | Excluded from absence-based closure; they stay open until reviewed. |
| High | Every non-hash indicator was matched as a domain, so new indicator types would have counted as coverage without matching anything. | One matcher per type; event-only patterns no longer count as content coverage. |
| Medium | SSRF checks treated carrier-grade NAT (100.64.0.0/10) and other special ranges as public, in both webhook delivery and the remediation egress proxy. | Shared non-public range list in both. |
| Medium | First deploy: a scratch-image container mounting ClamAV's empty volume first would leave it root-owned and unwritable. | The installer starts after ClamAV and retries until writable. Verified in a live Compose run. |
| Medium | `docker/cli` v28.2.2 (GO-2026-4610) arrived with the registry library. | Upgraded to v29.2.0. `docker/distribution` (GO-2026-6778, no fix) remains, unreachable from SCRS code. |
| Low | Streaming an image through the scanner's 30 s read timeout would have cut large images off. | Scanner read/write timeouts 5 and 9 minutes; image jobs get a 9-minute deadline inside the 10-minute lease. |

**Verification (2026-11-13):**
- `make qa`, `scanner-test`, `database-test`, `malware-test`, `image-scan-test` and `storage-integration` all pass.
- staticcheck (all non-style checks) is clean; govulncheck reports no reachable vulnerabilities.
- **Live checks:**
  - real OSV-Scanner with the real npm and Alpine feeds;
  - a local registry pull by digest, with 15 packages and 42 advisories matched;
  - live CISA KEV/EPSS (Log4Shell flagged as known-exploited);
  - live Maven and npm remediation through the egress proxy;
  - the n8n workflows import into n8n 1.97.1.
- **Load:** 480 concurrent admissions with p95 89 ms; 240 jobs completed exactly once across 6 workers, including 22 crash recoveries via lease expiry, with one outbox event per completion.
- **Full `compose.dokploy.yaml` stack run locally**, covering every service, the YARA volume handoff and API port 7000.

**Remaining risks:**
- Image layers get no malware, YARA, IOC or integrity analysis, so image verdicts are `incomplete` unless they `fail`.
- YARA runs in ClamAV's YARA subset (no modules).
- Git-bundle history mirroring, Harbor/OCI/GitLab adapters, registry push events, Trivy/SARIF import, licences, SAST and reachability are not built.
- Webhook receivers must verify `X-SCRS-Signature`.
- Live Traefik/TLS acceptance on the VPS is still pending.

## 2026-11-14 update: closing the remaining gaps

**Delivered**
- **Image layers:** every layer file goes through ClamAV, YARA and IOC matching, including files later layers delete. Image verdicts can now reach `pass`. Default feeds add Maven, PyPI, Alpine and Debian.
- **Providers:** GitLab (groups and subgroups, archive snapshots, webhooks with branch-churn and mass-deletion alerts), Harbor, and generic OCI registries (catalog or explicit repositories).
- **Registry push events:** Harbor, Docker Hub, GAR Pub/Sub and CNCF Distribution. Assessments are pinned to the pushed digest, and retried deliveries replay the same assessments.
- **Trivy and SARIF import:** imports join the register and the gate. Trivy secret values are discarded. Closure is scoped to the same tool, and imports never act as baseline or last-known-good.
- **Git-history mirrors:** native smart-HTTP fetch with pack checksum verification, streamed to S3 with a SHA-256 hash, then pruned. Bundles restore with `git clone`.
- **Relay and n8n:** relayed GitHub and GitLab events verify a forwarded provider signature. Outbound webhooks add `X-SCRS-Auth`, so n8n needs no Code node or `crypto` builtin.
- **OpenAPI 0.3.0:** 74 operations across 14 tags, each with a summary, description, scope and typed errors; validated by Redocly. Contract tests fail if a route is undocumented or a documented operation is not routed.

**Defects found and fixed while building**
- The registry ingest returned `202` for a fully replayed delivery.
- Imported assessments were rejected because the SBOM rule did not exempt them.
- The completion n8n workflow set a passing commit status for every non-completion event, for example `integrity.alert`.
- Callers could inject the internal `import` marker into a normal trigger; it is now stripped.

**Verification**
- Passing: `make qa`, `database-test` (including new GitLab, registry, import and mirror end-to-end tests, plus a worker mirror test), `scanner-test`, `malware-test` and `storage-integration` (multipart bundle round trip).
- `image-scan-test` now uses real ClamAV: 90 Alpine layer files scanned, YARA canary detected, 15 packages and 43 advisories.
- Mirror restore tested against a real `git http-backend`.
- Rebuilt Compose stack smoke-tested live.
- govulncheck: 0 reachable vulnerabilities.

**Remaining**
- YARA is limited to ClamAV's subset (no modules).
- Ubuntu OSV feed exceeds the 512 MiB cap.
- No licence/SPDX policy, built-in SAST or reachability.
- GitLab does not report force pushes.
- Live Traefik/TLS acceptance on the VPS is still pending.
- Decisions kept: existing criticals warn rather than pass; metrics use a `read` token; `pass` needs an active IOC bundle.

## 2026-11-14 addendum: SBOM/MBOM and inbound automation

- **Renamed:** the product is now the Software Supply Chain Risk Stack (README, PRD title, OpenAPI 0.4.0, image labels).
- **New: CycloneDX 1.6 MBOM per assessment** (`/assessments/{id}/mbom`). It records the produced commit or image digest, the build definitions and pinned inputs with SHA-256, the verifying tools, and a link to the SBOM. It validates against the CycloneDX 1.6 schema (`cyclonedx-cli`). It records declared inputs, not observed build provenance.
- **Validated: inbound automation.** `POST /assessments` is the inbound automation endpoint, alongside signed outbound webhooks. Added bounded `trigger.context` (20 keys, 256-character printable values), echoed in `assessment.completed`.
- **New end-to-end test** of the n8n round trip:
  - Rejects a missing token, a token from the wrong network, and the wrong scope (`ingest:relay`).
  - Rejects undiscovered or excluded assets (`404`) and malformed context (`400`).
  - Accepts the request (`202` with `Location`); a retry replays (`200`, `Idempotent-Replayed`) and a changed body under the same key conflicts (`409`).
  - Logs the inbound event, then delivers the context back in the `assessment.completed` payload.
