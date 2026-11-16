# Dependency-Track integration audit (2026-11-16)

Scope: how SCRS Core (assets, assessments, register) integrates with a self-hosted OWASP Dependency-Track (DT) that runs Trivy and the crowd-sourced vulnerability sources. Compared against the DT API contract published at `https://dt-api.creditchek.net/api/openapi.json` (DT 4.14.6, 153 paths, `X-Api-Key` or Bearer auth).

**How this was checked.** Code read: `internal/dtrack`, `internal/assessments/dtrack.go`, `internal/worker/dtrack.go`, `internal/httpapi/dtrack.go`. DT side: the public OpenAPI document and the unauthenticated `GET /api/version`. No API key was used and no authenticated call was made, so nothing below was observed against your data. Statements about DT behaviour that the contract does not state are marked *to confirm*.

## What exists

SCRS has a **one-way, outbound** adapter: SCRS to DT.

| Part | Behaviour |
| --- | --- |
| Trigger | A succeeded assessment with an SBOM queues a `dtrack_uploads` row in the same transaction (outbox). Imports and remediation runs are skipped. |
| Upload | `PUT /api/v1/bom` with `autoCreate`, optional `parentUUID`, base64 CycloneDX 1.6 JSON. Project name is the asset locator, version is the ref, else the commit, else `latest`. |
| Delivery | Leased, exponential backoff, 12 attempts (about two days). 401, 403, 4xx are permanent; 429, 5xx and network errors retry. |
| Credentials | API key sealed with the master key (AAD-bound), write-only. Only https to public hosts, or named private hosts. No redirects. |
| Operator API | `GET/PUT /integrations/dependency-track`, `:test`, `GET /uploads`, `POST /uploads/{id}/retry`. |
| Contract match | `PUT /v1/bom` and `GET /version` match the DT contract. |

These parts are sound. The gaps are below.

## Findings

| # | Severity | Finding |
| --- | --- | --- |
| F1 | High | **No DT to SCRS direction.** SCRS never reads a finding, metric or analysis from DT. Everything DT adds (NVD, GitHub advisories, OSS Index, OSV, Snyk, Trivy analyzer) stays in DT. The register shows SCRS's own findings only, so the adapter is not bidirectional. |
| F2 | High | **Fixed 2026-11-16.** **`uploaded` did not mean processed.** DT accepts the BOM and processes it asynchronously. SCRS stores the returned token but nothing polls it. A BOM DT later rejects, or a failed analysis, shows as `uploaded`. |
| F3 | High | **Fixed 2026-11-16.** **`:test` did not check permissions.** `Check` calls `GET /v1/event/token/{random}`. The contract lists only `200` and `401` for it, so any valid key passes, with or without `BOM_UPLOAD` and `PROJECT_CREATION_UPLOAD`. A key without them passes the test, then fails the first upload with 403 and the upload becomes permanently `failed`. The unit test fake returns 403 on that route, which real DT does not, so the test hides the defect. |
| F4 | Medium | **Triage is not shared.** SCRS statuses (`open`, `triaged`, `in_progress`, `accepted`, `suppressed`, `false_positive`, `fixed`) and waivers have no link to DT analysis (`NOT_SET`, `IN_TRIAGE`, `EXPLOITABLE`, `FALSE_POSITIVE`, `NOT_AFFECTED`, `RESOLVED`, plus justification, response and suppression). A finding suppressed in one tool reappears in the other. |
| F5 | Medium | **Project identity and sprawl.** Name is the bare locator (a GitHub and a GitLab repository with the same path collide). Version falls back to the commit, so a commit-only target creates a new DT project version per commit, never cleaned up. No `isLatest`, `projectTags` or classifier is sent, so DT cannot separate branches, environments or asset types. |
| F6 | Medium | **No duplicate control between engines.** The same CVE can arrive from SCRS (OSV-based), from DT (several sources) and from a CI Trivy import (`assessments:import`, `format: trivy`), with different severities. No key (vulnerability alias plus package URL) joins them. |
| F7 | Medium | **Fixed 2026-11-16.** **DT was not in `/system/status`.** Reachability, version, queue depth and failed uploads are not visible to a frontend, and a permanent upload failure raises no event. |
| F8 | Info | **SAST and DAST have no DT path.** DT is a component-analysis tool and does not ingest SAST or DAST results. SCRS's SAST (Go) and SARIF import stay in SCRS. SCRS has **no DAST module** (the QA runner is Karate functional and load testing, not DAST). Neither can be wired to DT. |
| F9 | Info | **MBOM is not pushed.** DT has no MBOM concept; nothing to fix unless you want it stored as a separate project. |
| F10 | Info | **Trivy is configured only inside DT.** DT calls a Trivy server using its own `scanner.trivy.*` settings, which need `SYSTEM_CONFIGURATION` to read. SCRS cannot see or enforce them and should not hold that permission. |

## Your four coverage areas

| Area | Today | Gap |
| --- | --- | --- |
| Packages and SBOM | Pushed as CycloneDX; DT analyses with every source you enabled | Results never come back (F1, F2) |
| Repository advisories | DT mirrors GitHub advisories; SCRS has its own OSV feed | No reconciliation (F6) |
| SAST | Built into SCRS; SARIF import | DT cannot take it (F8) |
| DAST | Not in SCRS | Not in DT either (F8) |

## DT endpoints a bidirectional adapter would use

All are in the contract you linked. Permissions are the ones DT documents per operation.

| Need | DT call | DT permission |
| --- | --- | --- |
| Permission self-check (F3) | `GET /v1/team/self` (returns `permissions`) | none beyond a valid key |
| Find the project | `GET /v1/project/lookup?name=&version=` | `VIEW_PORTFOLIO` |
| Processing finished (F2) | `GET /v1/event/token/{token}` (`/v1/bom/token` is deprecated) | valid key |
| Confirm import and analysis | `Project.lastBomImport`, `lastVulnerabilityAnalysis`, `metrics` | `VIEW_PORTFOLIO` |
| Read findings (F1) | `GET /v1/finding/project/{uuid}` (`suppressed`, `source`; also SARIF) | `VIEW_VULNERABILITY` |
| Re-run analysis | `POST /v1/finding/project/{uuid}/analyze` | `VIEW_VULNERABILITY` |
| Triage write-back (F4) | `PUT /v1/analysis` | `VULNERABILITY_ANALYSIS` |
| VEX export or import | `GET /v1/vex/cyclonedx/project/{uuid}`, `PUT /v1/vex` | per operation |
| Portfolio numbers for a dashboard | `GET /v1/metrics/portfolio/current`, `/project/{uuid}/current` | `VIEW_PORTFOLIO` |

Each finding carries `attribution.analyzerIdentity` (for example the Trivy or OSV analyzer). That field is how SCRS can show which source found a vulnerability, and how it can confirm Trivy is active without reading DT's settings (F10).

## Status of the fixes (2026-11-16)

- **F3:** `:test` reads `GET /v1/team/self` and requires `BOM_UPLOAD` and `PROJECT_CREATION_UPLOAD`. It returns `permissions`, `missing_permissions` and `required_permissions`. The unit-test fake now follows the real contract.
- **F2:** after an upload is accepted, the worker checks `GET /v1/event/token/{token}` and then `GET /v1/project/lookup`, and records `processing` as `processed`, `unconfirmed` or `failed`. A BOM counts as imported when the project's `lastBomImport` is newer than the upload (with two minutes allowed for clock differences). `unconfirmed` is what a key without `VIEW_PORTFOLIO` gets. *To confirm against a live DT:* that `lastBomImport` behaves this way on 4.14.6.
- **F7:** `GET /system/status` has a `dependency_track` component and a `dependency_track.upload_failed` event covers rejected uploads and failed imports.
- **Open:** F1, F4, F5, F6.

## Recommended order

1. **Fix F3 and F2** (small, no new data model): check `GET /v1/team/self` for `BOM_UPLOAD` and `PROJECT_CREATION_UPLOAD` in `:test`; poll the event token after upload and record `processed` or `processing_failed`; correct the unit-test fake.
2. **F7:** add a `dependency_track` component to `/system/status` and a `dependency_track.upload_failed` event.
3. **F5:** name projects `<provider>/<locator>`, send `isLatest` for default-branch scans and `projectTags` (`scrs`, asset type), and skip commit-only versions or give them a short retention.
4. **F1 and F6:** a read-only pull of DT findings per project into the register as a separate source (`dependency-track`), joined to SCRS findings by vulnerability alias plus package URL, with the analyzer shown. Read-only first; triage write-back (F4) after the mapping is agreed.

## API key for the adapter

Use one DT team dedicated to SCRS. Grant `BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD`, `VIEW_PORTFOLIO` and `VIEW_VULNERABILITY`. Add `VULNERABILITY_ANALYSIS` only when write-back is built. Do not grant `SYSTEM_CONFIGURATION` or `ACCESS_MANAGEMENT`. If DT portfolio access control is on, the team also needs access to the projects it creates (*to confirm*). `dt-api.creditchek.net` is public https, so `SCRS_DTRACK_PRIVATE_HOSTS` stays empty.

## Not verified

- Any call with your automation key, including whether the key has the permissions above.
- That DT 4.14.6 accepts CycloneDX 1.6 from SCRS (expected, but not proved without an upload).
- Whether Trivy and the other analyzers are enabled in your DT.
- Whether DT's webhook notifications (BOM processed, new vulnerability) can carry an authentication header. Until that is confirmed, polling is the baseline and DT notifications are optional.
