# Assessment pipeline implementation and operating limits

This delivery provides a repository SCA pipeline, not full PRD production sign-off.
All URLs use `/scrs/v1`. Swagger includes the new assessment, register and remediation
routes. Database migration `2026111204` is additive and runs through `scrs init`.

## Workflow

1. An administrator creates a GitHub connection and discovers its permitted assets.
2. A `write` or `trigger` token posts an assessment. Repository URLs are not accepted;
   the repository must resolve to a discovered, accessible asset on an enabled
   connection. Specify `connection` when multiple connections cover that repository.
3. PostgreSQL commits the job, normalized inbound request, audit event and optional
   actor-scoped 24-hour idempotency record in one transaction, then the API returns 202.
4. A worker leases a job, resolves a GitHub commit, downloads its archive, and binds
   retries to that immutable commit. API credentials never follow the codeload redirect.
5. An isolated scanner extracts bounded regular files, runs pinned OSV-Scanner 2.7.1
   offline, and returns component inventory, findings and a CycloneDX 1.6 SBOM.
6. The worker writes the content-addressed SBOM to S3 before committing database
   results. Completion validates its lease, current connection configuration revision
   and asset eligibility again. Cancelled or stale workers cannot publish findings.
7. Read results through `/assessments/{id}`, `/components`, `/findings`, `/sbom`, and
   `/report`. The register at `/register` retains findings across assessments.

Example body for `POST /scrs/v1/assessments`:

```json
{"connection":"github-primary","target":{"type":"git","repository":"example/api","ref":"main"},"trigger":{"origin":"ci","delivery_id":"build-123"}}
```

Use a bearer token and preferably `Idempotency-Key`. A matching replay returns 200;
reuse for a different normalized request returns 409. Trigger-only callers can read
and cancel only their own jobs. Read scope cannot enqueue or cancel jobs. Write/admin
can operate across the deployment's assets. This is a single security-domain deployment,
not a multi-tenant authorization model.

## Queue and failure semantics

PostgreSQL is the durable job authority, deliberately replacing the PRD's proposed
Redis Streams job transport. This avoids a database/queue dual-write gap. Redis still
provides API admission control. Short transaction advisory locks serialize admission
and claims; a partial unique index permits only one running job per asset. Admission
caps queued plus running jobs at 500. Claims use `FOR UPDATE SKIP LOCKED`.

A job has a ten-minute lease and a five-minute worker deadline; scanner execution has
a four-minute deadline. Crashed leases are reclaimed, with a maximum of three attempts.
Provider/network/parser failures remain incomplete. Cancellation revokes publication
rights immediately; the running scanner may finish its bounded attempt before cleanup.
Only one worker and one scanner replica are currently validated. Multiple workers can
claim different assets, but scanner contention consumes retry attempts; do not scale
workers until pool-aware scheduling and load acceptance have been completed.

Finding identity includes asset, ref, advisory, type, component PURL and manifest path.
Duplicate detections do not inflate counts. Assessment snapshots remain immutable when
register statuses change. Accepted risk requires admin and a future expiry of at most
90 days; expired acceptance reads as open. Manual `fixed` is not allowed. Absence only
closes findings after a complete current-ref assessment; partial results retain history.

S3 success followed by a database failure can leave an unreferenced immutable object.
This is intentional to avoid a database reference to a missing artifact. No garbage
collection or destructive retention action is enabled. A production retention feature
must reference-check objects and preserve audit/history before deletion.

## Deployment and resource boundaries

The same image supplies API, worker, scanner, feed-sync and egress-proxy roles. Hosted
PostgreSQL, Redis and S3 remain external. Dokploy exposes only the API through its
existing Traefik labels. Scanner has only the internal scanning network, read-only feeds,
a bounded noexec temporary filesystem, no shell/package manager, and no provider,
database or S3 credentials. Worker holds provider/storage credentials and never executes
repository code. Repository scanner policy and gitignore cannot suppress detections.
Archive links, special files, traversal, duplicate files and oversized expansion fail.

Set the distinct random `SCRS_SCANNER_API_TOKEN` in Dokploy. `.env` has a generated local
value; `.env.example` has a placeholder. Do not reuse the public API token. Configure
`SCRS_OSV_ECOSYSTEMS` for all intended inventories (default `npm,Go`). Fresh OSV feeds
are downloaded from the fixed public OSV origin into an atomic snapshot every six hours;
failed synchronization retries after one minute. Feeds older than 24 hours make scanner
health fail. Initial feed download must complete before the worker starts.
Feeds are a rebuildable local Docker volume, not the authoritative evidence store.

The scanner is limited to 2 GiB RAM and two CPUs; feed-sync to 512 MiB. These are limits,
not measured capacity guarantees. Real large repositories/ecosystem databases need VPS
load testing. Download cap is 64 MiB compressed; extraction cap is 256 MiB total, 32 MiB
per file and 10,000 files. Unsupported/oversized inputs fail rather than pass silently.

## Guided remediation

`SCRS_REMEDIATION_ENABLED=false` is the default. `/remediation/capabilities` exposes
runtime enablement. The implemented adapter accepts only npm `package-lock.json` with
`in-place` strategy. A write token posts to `/assets/{id}/remediations` with
`assessment_id`, `manifest` and optional `strategy`. The manifest must occur in that
asset's successful prior inventory. The job pins the prior commit and rechecks scope.
Read advice at `/assessments/{job_id}/remediation`.

OSV fix operates on a disposable archive, with no inherited credentials. Its only
configured egress is a CONNECT proxy restricted to public IPs for deps.dev and the
public npm registry on port 443. Plans go to content-addressed S3 storage. No commit,
PR or repository write occurs. Plan completion is never a security pass; proposed
changes need review and a fresh assessment. Maven and other strategies are unavailable.
The provider-backed fix path and deployed egress controls have not passed acceptance;
leave this feature disabled until those tests are completed.

## Remaining product gates

- Direct/relay webhook authentication, batch triggers and outbound delivery/outbox.
- Full OSV advisory JSONB mirror and provenance, KEV/EPSS, NVD/CVE/VEX and custom feeds.
- Integrated ClamAV/YARA, IOC rules, integrity baselines/events and malicious response.
- OCI image/digest fetching, layer attribution, registry event adapters and PR assessment.
- Owners, maintenance/retention previews, metrics/alerts and full contextual reports.
- Licensing/SPDX/compliance, SAST analyzers and reachability.
- Real GitHub/private-repository acceptance; hosted backup/restore and failure/load tests;
  exact published image, signature, Dokploy domain/TLS and deployed restart recovery.

Consequently successful execution currently returns `incomplete`: malware, IOC and
integrity coverage is explicitly skipped. Do not interpret it as a clean repository.

## Verification

`make qa`, `make database-test`, `make scanner-test`, and `make storage-integration`
exercise code/race checks, real disposable PostgreSQL/Redis, actual offline OSV matching
against a synthetic advisory (including repository suppression attempts), and image
bootstrap against disposable PostgreSQL/Redis/MinIO. Database cases cover concurrent
idempotency, per-asset serialization, lease expiry, duplicate completion, cancellation,
status history, remediation admission/result persistence, and incomplete-scan preservation. Disposable MinIO checks artifact round-trip, key restrictions and corruption rejection.
Worker integration uses synthetic acquisition and scanner HTTP responses; it does not
prove real provider acquisition. No live hosted stores are mutated by these targets.

Upstream contracts: [OSV offline mode](https://google.github.io/osv-scanner/usage/offline-mode/),
[OSV configuration override](https://google.github.io/osv-scanner/configuration/),
[guided remediation](https://github.com/google/osv-scanner/blob/v2.7.1/docs/guided-remediation.md),
and [GitHub repository contents/archive API](https://docs.github.com/en/rest/repos/contents).
