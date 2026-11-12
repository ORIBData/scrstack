# PRD expansion audit — 2026-11-12

Status: implementation increment validated locally; **full production sign-off withheld**.
This report updates the earlier pipeline-only assessment. It does not declare all PRD
milestones complete, and no live Dokploy acceptance has been claimed.

## Delivered and assessed

| Module | Change and QA evidence |
| --- | --- |
| Malware | ClamAV INSTREAM scans extracted regular files; file hashes/status persist in PostgreSQL. Limits/errors remain partial, signature age is checked, stale signatures produce posture findings. Real clean-file/EICAR and version metadata tests passed. Parser fixtures cover malformed replies and size-limit responses. Separate YARA remains missing. |
| IOC feeds | Admin-only immutable version import to JSONB, atomic activation/history/audit, SHA256/domain matching and expiry exclusion. Worker supplies the active snapshot through bounded multipart input. Validation and duplicate-version rollback tests passed. Wider types/remote feed ingestion remain missing. |
| Integrity | Workflow secret serialization detection and workflow-file change comparison against the prior assessment. Raw source excluded from findings. Full provider metadata, branch/PR history, run-gap detection and last-known-good rules remain missing. |
| Remediation | Enabled in dotenv/Compose. Automatic supported npm plans are emitted through a durable database outbox. Explicit plan API remains. Real upstream no-change and vulnerable-lodash plans passed using public metadata through the restricted proxy. No repository writes. Outbox repeat dispatch, parent scope and persistence tested. Maven/other strategies remain missing. |
| Inbound workflows | Direct signed GitHub push route with exact-body HMAC, bounded concurrency/body, scope checks, immutable commit, durable raw events and replay protection. Signature/replay/raw-persistence tests passed. Relay/other events/outbound notifications remain missing. |
| Retention | Raw-event policy with ETag concurrency, preview and bounded audited purge; default keeps forever. Pending events and assessed evidence are protected. Disposable PostgreSQL tests verify stale-policy rejection, preview/purge counts and retained findings. Other classes and scheduler remain missing. |
| Deployment | Public HTTPS acceptance reads deployment dotenv; optional node port binds localhost only. No domain was guessed and no deployment was attempted. Image bootstrap passed with disposable hosted-style stores. |

## Engineering and architecture findings addressed

- File detections were previously blocked by SCA failure/no supported manifest. They
  now run first and persist even without an SBOM; missing SCA coverage cannot pass.
- File inspection and SCA have separate deadlines inside the existing scanner deadline;
  one failing engine cannot silently assert the other engine's coverage.
- Expired IOC entries cannot match; immutable bundle versions cannot be overwritten;
  failed duplicate imports roll back activation changes.
- Automatic remediation admission uses an outbox in the assessment transaction and
  checks prior child jobs after a dispatch crash. Scope is checked again on admission
  and result publication. Unsupported manifests are never fabricated as successful plans.
- The signed webhook route has no bearer-token bypass: it uses a separate provider
  HMAC secret, verifies the exact bytes, rejects unknown events and preserves raw input.
- Retention does not use cascades or delete object storage. Policy updates and purge
  use revision checks and transactionally record audit evidence.
- Positive malware/IOC matches retain explicit findings even when the overall verdict
  is incomplete. Users must not equate incomplete with pass.

## Remaining production gates

Image/digest acquisition and layer assessment; independent YARA; full integrity and
threat-intelligence feed coverage; outbound webhook delivery; complete retention classes
and scheduled maintenance; licensing/SPDX/compliance; SAST/reachability; broader guided
remediation strategies; production metrics, load/fault recovery and real-provider
acceptance are still outstanding engineering work.

The staging URL will be supplied as `SCRS_PUBLIC_BASE_URL` in deployment dotenv.
Traefik terminates external TLS; SCRS serves HTTP internally. Run
`make deployment-acceptance` after deployment. That read-only check does not establish
certificate renewal, disaster recovery or load resilience.

## Third-party malware image review

The initial official Alpine 1.5.4 image reported 17 findings, including libc/XML
issues. The selected official Debian 1.5.4 variant supports native ARM64 and AMD64,
runs with its unprivileged entrypoint and dropped capabilities, and passed EICAR tests.
Its raw Docker Scout scan reports **84 findings across 17 packages**, including eight
high-severity findings (Kerberos/XML), with no fixed version reported in that scan.
This is **not** a vulnerability clearance; applicability/upstream remediation remains
a production gate. No findings are silently waived. The selected image is configurable
with `SCRS_CLAMAV_IMAGE` for a reviewed replacement.

`SCRS_CLAMAV_MEMORY` defaults to a 4 GiB limit for signature reload headroom, following
[ClamAV's container guidance](https://docs.clamav.net/manual/Installing/Docker.html).
This is not a RAM reservation, but VPS capacity must cover concurrent scanner/engine
usage. External PostgreSQL/Redis/S3 do not eliminate this scan-engine memory cost.

## Local verification record

- `make qa`: Go race tests, vet, contract checks and 12 Python tooling/config tests passed.
- `make database-test`: PostgreSQL/Redis/MinIO tests passed, including automatic plans,
  immutable IOC imports, signed webhook replay/raw event persistence and retention safeguards.
- Real pinned OSV fixtures passed for SCA and guided remediation. The vulnerable-package
  fixture used synthetic advisory data and public package metadata; no private source or
  provider credentials were sent.
- `make malware-test`: the native unprivileged Debian service detected EICAR, accepted
  clean content and returned parsable signature metadata.
- `make storage-integration`: new schema and application image initialized disposable
  PostgreSQL/Redis/MinIO and served authenticated API requests successfully.
- ARM64 and AMD64 SCRS builds passed. Raw application image scans retain the previously
  assessed Docker CLI CVE-2025-15558 finding; audit commands therefore return nonzero.
- ClamAV raw SARIF/SBOM are retained at
  `artifacts/7fd6e2ead9f528ad4460929ded361ed5c7491788be9d0501d372cdac45b090f0/`.
  Its 84 findings are not suppressed or claimed resolved.

No release push, VPS change, private-provider mutation or production data purge occurred.
