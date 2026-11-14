# Assessment pipeline implementation and operating limits

This delivery provides a repository SCA pipeline, not full PRD production sign-off.
All URLs use `/scrs/v1`. Swagger includes the new assessment, register and remediation
routes. Database migration `2026111204` is additive and runs through `scrs init`.

## Workflow

1. An administrator creates a GitHub, GitLab or registry connection and discovers its permitted assets.
2. A `write` or `trigger` token posts an assessment. Repository URLs are not accepted;
   the repository must resolve to a discovered, accessible asset on an enabled
   connection. Specify `connection` when multiple connections cover that repository.
3. PostgreSQL commits the job, normalized inbound request, audit event and optional
   actor-scoped 24-hour idempotency record in one transaction, then the API returns 202.
4. A worker leases a job, resolves a GitHub or GitLab commit, downloads its archive, and
   binds retries to that immutable commit. API credentials never follow a redirect.
   Image jobs resolve the tag to a platform manifest digest and stream the image.
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
90 days; expired acceptance reads as open. Manual `fixed` is not allowed. Absence
closes a finding only when the scan covered the ref's current head (`ref_moved` false,
including webhook pushes that name both commit and ref) and every stage that produces
that finding type completed (for example inventory, SBOM and vulnerability matching for
`vulnerability`). Types whose producing stage was partial or skipped retain history;
integrity entries therefore stay open until reviewed while that stage remains partial.

S3 success followed by a database failure can leave an unreferenced immutable object.
This is intentional to avoid a database reference to a missing artifact. S3 garbage collection is not enabled. Raw webhook-event retention is available separately and defaults to keep forever. A production retention feature
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

`SCRS_REMEDIATION_ENABLED=true` is now configured in dotenv and Compose. `/remediation/capabilities` exposes
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
The actual upstream command passed synthetic empty-plan and vulnerable-lodash tests
through the allowlisted proxy with public deps.dev data. Automatic plans are scheduled
through a transactional outbox for supported npm manifests after assessments complete.
`GET /assessments/{id}/remediations` shows child job and dispatch state. Disabled or
changed provider scope blocks dispatch. Unsupported ecosystems remain unsupported.
Deployed egress isolation and representative private-provider acceptance are still open.

## SBOM and MBOM

Every successful assessment has two CycloneDX 1.6 documents:

- **SBOM** (`/assessments/{id}/sbom`): the component inventory from OSV-Scanner,
  stored content-addressed in S3 and hash-checked on download.
- **MBOM** (`/assessments/{id}/mbom`): a Manufacturing Bill of Materials
  generated on request from the register. `metadata.component` is the produced
  artifact (`pkg:github`/`pkg:gitlab` at the commit, or `pkg:oci` at the image
  digest and platform). `components` are the build definitions and pinned
  inputs observed in that revision with their SHA-256: CI workflows (GitHub,
  GitLab, CircleCI, Jenkins, Azure, Bitbucket), Dockerfiles and Compose files,
  Makefiles, Gradle/Maven, `package.json`, and Go, npm, Yarn, pnpm, Python,
  Cargo and Bundler lockfiles. `formulation` ties them to a build workflow;
  `metadata.tools` and `scrs:stage:*` properties record what verified it;
  `externalReferences` links the SBOM. It validates against the CycloneDX 1.6
  schema.

The MBOM describes declared build inputs. SCRS does not watch the CI run, so it
is not build provenance; pair it with SLSA attestations where your pipeline
produces them. Image MBOMs list only flagged layer files, because image file
inventories are not retained.

## Container images

Image assessments (Docker Hub, GAR, Harbor, OCI) stream a docker-save archive
from the registry to the scanner (capped by `SCRS_MAX_IMAGE_BYTES`). Two
analyses run concurrently:

- **Packages:** OSV-Scanner inventories OS packages (Alpine, Debian feeds) and
  language packages, with a CycloneDX SBOM and vulnerability/MAL matching. An
  image whose OS feed is not in `SCRS_OSV_ECOSYSTEMS` reports `inventory`
  failed. Ubuntu's feed exceeds the 512 MiB cap and is unsupported.
- **Layer content:** every regular file of every layer goes through ClamAV
  (with the SCRS YARA rules) and the IOC matchers, including files deleted by a
  later layer: they are still in the blobs every pull downloads. Identical
  content is scanned once. Files over 25 MiB are hashed but not scanned
  (`malware: partial`). The scan stops at 200 000 files or 4 minutes and reports
  partial coverage. Only flagged files are listed under `/files`.
- **YARA-X rulesets:** enabled team and third-party rulesets run on every
  distinct repository file and image layer file up to 128 MiB (stage
  `yara_x`). The stage is `skipped` with no rulesets; when it runs, `partial`
  or `failed` makes the verdict `incomplete`. See
  [THREAT_INTELLIGENCE.md](THREAT_INTELLIGENCE.md).

Repository workflow rules (workflow changes, install hooks, root helper scripts)
do not apply to images; `integrity` says so in its detail.

## Imported reports

`POST /assessments:import` records a Trivy JSON or SARIF 2.1.0 report against a
discovered asset revision (`target.commit` required). The assessment has one
stage, `import`, and no SBOM. Findings join the register (`misconfiguration`,
`secret` and `code` types are import-only) and gate like SCRS findings. Imported
findings are closed only by a later import of the same tool for the same ref
sent with `replace_previous: true`, which declares the report the tool's full
result; a partial run (secrets only, say) must leave it `false`. SCRS's own
scans never close imported findings, because tools name the same issue
differently (CVE versus GHSA ids). Imports never close SCRS findings, never
serve as a baseline for SCRS scans and never count as last-known-good. Trivy secret matches are discarded; only rule, file and line
are kept.

## Git history mirrors

`POST /assets/{id}/mirrors` queues a git bundle of every branch and tag of a
GitHub or GitLab asset. The worker speaks git's smart HTTP protocol directly
(no git binary), verifies the pack checksum, and streams the bundle through a
SHA-256 hash into S3 (`mirrors/<id>.bundle`, at most `SCRS_MIRROR_MAX_BYTES`).
With `SCRS_MIRROR_INTERVAL_HOURS`, assets labelled `mirror=true` are mirrored
on schedule. A bundle is marked `pruned` and its object deleted only when it
is beyond the newest `SCRS_MIRROR_KEEP` and older than `SCRS_MIRROR_MIN_AGE_DAYS`
(default 30). The newest bundle taken before the asset's earliest open integrity
finding is never pruned, so repeated mirroring of a compromised repository cannot
replace every clean backup. Restore: download with an
admin token, compare with `X-Content-SHA256`, then `git clone <file>.bundle`.
SHA-256 object-format repositories are not supported.

## Remaining product gates

- Licensing/SPDX/compliance policy, built-in SAST and reachability analysis (SARIF import covers external SAST tools).
- The built-in starter rules run inside ClamAV, which supports a subset of YARA (no modules). Rules needing modules belong in a YARA-X ruleset (`/intel/yara-rulesets`).
- Real private-repository and registry acceptance on the target VPS; hosted backup/restore drills.

Consequently, successful execution can still return `incomplete`, for example
when no IOC bundle is active or ClamAV signatures are stale. Do not interpret
incomplete as a clean result.

Verdict precedence is `fail` > `incomplete` > `warn` > `pass`. Malware, malicious
dependencies and IOC matches fail whether new or existing; a new critical
vulnerability and a new high or critical integrity entry fail. "New" means absent
from the previous successful scan of the same ref, or of the base branch for a
pull request. An existing critical, a new high, a new medium integrity entry or an
existing serious one warns. `fail` is reported even when coverage is partial, so a
CI gate must block on `fail` and must not treat `incomplete` as `pass`. Register
triage applies to the gate: unexpired `accepted`, `suppressed` and `false_positive`
entries do not gate (counted under `counts.waived`), except that waived malicious
content still yields at least `warn` (MAL-007). Assessment snapshots keep raw detections.

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


## Content inspection, inbound events and bounded retention

The file pass runs before dependency analysis, with a 90-second budget. SCA then has
a two-minute budget. Missing manifests or OSV failures retain file detections rather
than discard them. The internal scanner accepts bounded multipart archive plus the
active IOC bundle, supplied by the trusted worker. `GET /assessments/{id}/files`
returns path, SHA256, size and malware status; source content is never persisted.
ClamAV streams regular files up to 25 MiB via INSTREAM. Errors, engine limits,
oversize files and stale/unavailable signature dates make coverage partial.
Signature versions older than 26 hours produce posture findings. See the upstream
[ClamD protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html).

Indicators live in indicator sources (`/intel/indicator-sources`), each with its own
mode (`hunt`, `alert` or `block`), severity and minimum confidence; see
[Threat intelligence](THREAT_INTELLIGENCE.md#indicator-sources). Each scan receives the
unexpired indicators of every enabled source. `PUT /feeds/indicators` still activates an
immutable version of up to 10,000 indicators, keeps prior versions and audit history,
and feeds the block-mode `bundle` source. Text matching (domains, IPv4, URLs, content
patterns) is capped at 1 MiB per file; skipped text means partial coverage. STIX upload
and TAXII polling are being built. Workflow `toJSON(secrets)` matches are critical; changes to workflow
file hashes compared with the prior assessment raise high-severity integrity entries.
This is a change baseline, not a last-known-good declaration.

`POST /webhooks/github` verifies GitHub's HMAC-SHA256 against the exact raw body,
requires a delivery UUID and only admits pushes for discovered in-scope repositories.
Raw JSON, job and replay record commit atomically. Delivery replay is protected for
24 hours; unsupported events are explicit 422 responses. Deleted branches are ignored.
Set `SCRS_GITHUB_WEBHOOK_SECRET` to the same random 32+ character value in GitHub;
blank disables ingress. Body and concurrent-handler limits apply before parsing.

Raw ingress retention is managed by admin-only `/settings/retention`, `:preview` and
`:purge`. Set `inbound_event_days` (zero keeps forever), using the policy ETag in
`If-Match` on updates and purge. Preview counts eligible rows and stored JSON bytes.
Purge removes at most 1000 old events and excludes queued/running assessment events.
It never deletes assessments, findings, audit history or S3 artifacts. Scheduled purge,
per-class PRD retention defaults and artifact garbage collection remain open.
