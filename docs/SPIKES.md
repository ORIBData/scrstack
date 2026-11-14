# Spike results (PRD section 8.10)

The PRD planned spikes S1–S13 before M2. Most questions were answered while building, by tests that run against the real tools. This record states each answer, the evidence, and what is still unmeasured.

**Evidence levels:**
- **Verified:** a repeatable test or command exercises it.
- **Observed:** checked once by hand or from upstream documentation.
- **Open:** not answered yet.

| ID | Question | Outcome | Level |
| --- | --- | --- | --- |
| S1 | OSV-Scanner as a library or CLI; offline throughput | CLI, pinned v2.7.1, offline against a local mirror (ADR-005) | Verified (choice); throughput Open |
| S2 | Where `MAL-` records come from | Inside the OSV per-ecosystem dumps (OpenSSF malicious-packages is an OSV source), so one download serves both | Observed |
| S3 | Mobile ecosystem coverage | npm, Go, Maven, PyPI, Pub and SwiftURL are synced by default; CocoaPods has no OSV ecosystem | Observed; per-ecosystem sample repos Open |
| S4 | ClamAV REST versus INSTREAM; memory; throughput | INSTREAM over the internal network (ADR-007); 4 GiB memory limit for signature reloads | Verified (path); throughput Open |
| S5 | Remediation sandbox: scripts disabled, egress restricted | Scripts off; allow-listed egress proxy to npm and deps.dev; no repository writes | Verified |
| S6 | Image scanning path and layer attribution | Pull by digest, unpack layers in the scanner, inventory with OSV-Scanner, content-scan every layer file including whiteouts | Verified; Trivy parity in `docs/TRIVY_PARITY.md` |
| S7 | YARA engine | YARA-X CLI for rulesets; ClamAV YARA subset for starter rules (ADR-006) | Verified |
| S8 | Archive by commit, fork PR head, relay body integrity | Archives by immutable commit with redirects refused; PR scans pin the head commit; relay signatures over the exact body are verified | Verified (archive, relay); fork PR head Observed |
| S9 | NVD full-sync volume; NVD, CVE and OSV overlap; licence detector | Targeted sync instead of a full mirror; detector deferred to M8 | Partly verified; volumes Open |
| S10 | SAST sandboxing | Not started (M9) | Open |
| S11 | Zennoxa Shield evaluation | Not started (M9) | Open |
| S12 | Reachability beyond Go | Not started (M9) | Open |
| S13 | GitLab, Docker Hub and GAR adapters | `:test` and `:discover` for every provider | Verified |

## S1 OSV-Scanner integration

**Outcome:** the CLI, pinned to v2.7.1 and built from `tools/osv`, runs offline against the OSV mirror that `scrs-feed-sync` keeps (refreshed every six hours, rejected when older than 24 hours).

**Evidence:**
- `make scanner-test` runs the pinned binary against adversarial fixtures: suppression files are ignored, and malformed and oversized input fails closed.
- The image parity run (S6) scans real images through the production scanner.

**Open:** a measured 500-component throughput figure, and the mirror's size per ecosystem. Size is reported by the feed status (`GET /intel/vulnerability-sources`) but not yet recorded here.

## S2 Malicious-package records

**Outcome:** OSV's per-ecosystem dumps include the OpenSSF malicious-packages records (`MAL-` ids), so no separate repository sync is needed. They match in the same OSV-Scanner pass, and findings are typed `malicious_dependency`. `malicious_dependency.reported` fires when one is first seen.

**Evidence:** `TestPostgresEventsAdvisorySyncAndObjectRetention` covers the event. A live `MAL-` match against the real dump has not been recorded as a test.

## S3 Mobile ecosystems

**Outcome:**
- The default `SCRS_OSV_ECOSYSTEMS` is `npm,Go,Maven,PyPI,Pub,SwiftURL,RubyGems,Alpine,Debian`.
- Gradle projects resolve as Maven where OSV-Scanner reads the lockfiles.
- Flutter is covered through `Pub`, SwiftPM through `SwiftURL`.
- CocoaPods has no OSV ecosystem, so Podfiles produce inventory but no advisory matches.

**Open:** the coverage table against sample mobile repositories.

## S4 ClamAV

**Outcome:** `INSTREAM` over the internal scanning network, never host paths. Several files stream in parallel. `SCRS_CLAMAV_MEMORY` defaults to 4 GiB of headroom for signature reloads.

**Evidence:** `make malware-test` (EICAR detected, clean file accepted, signature metadata parsed).

**Open:** throughput on a 10,000-file repository.

## S5 Remediation sandbox

**Outcome:** plans are generated in the scanner with package-manager scripts disabled. All egress goes through `scrs-egress-proxy`, which allows only public npm and deps.dev addresses. Plans are advice; SCRS never writes to repositories.

**Evidence:** `internal/scanner/remediation_test.go` (empty plan, vulnerable npm package, Maven), plus the proxy's private-address refusal.

## S6 Images and layer attribution

**Outcome:**
- Images are resolved to a platform manifest digest and pulled by digest, within a size cap.
- Each layer is unpacked in the scanner.
- OSV-Scanner inventories OS and language packages.
- ClamAV, YARA and IOC rules inspect every layer file, including files a later layer deleted.

**Evidence:** `internal/scanner/image_test.go`; the parity run against Trivy is in [TRIVY_PARITY.md](TRIVY_PARITY.md).

## S7 YARA engine

**Outcome:** see ADR-006. The YARA-X CLI `yr` 1.22.0 runs rulesets with modules; combined STIX-derived rulesets compile there.

**Evidence:** `internal/scanner/yarax_test.go`, plus checks against the real `yr` in the scanner image.

## S8 Fetch and relay

**Outcome:**
- Archives are fetched by immutable commit and redirects are refused, so credentials never follow them.
- PR assessments pin the head commit and never resolve `pull/<n>` as a ref.
- Relay mode verifies a forwarded provider signature over the exact body, now against the connection's own webhook secret (ADR-023).
- Archives were chosen over clones; mirrors use git bundles.

**Evidence:** connection and ingest Postgres tests; `TestPostgresConnectionWebhooksAndScopedSubscriptions`.

**Observed only:** fetching a fork's PR head by commit with a GitHub App token.

## S9 Vulnerability data

**Outcome:**
- Instead of a full NVD mirror, the worker syncs only CVEs that open register entries reference. It reads the NVD's modified-CVE window and refreshes only records it already holds.
- Pacing follows the NVD's published limits: 6 s without a key, 0.7 s with `SCRS_NVD_API_KEY`.
- The CVE Program's CNA records are fetched the same way.
- Both are stored as OSV-shaped records next to OSV data (ADR-020).

**Evidence:** `internal/advisory` tests and `TestPostgresEventsAdvisorySyncAndObjectRetention`, against NVD 2.0 and CVE JSON 5 shaped servers.

**Open:**
- Full-sync volume and time; not needed for the targeted design.
- Measured NVD, CVE and OSV conflict rates on 1,000 CVEs.
- The licence-detector choice (M8).

## S10–S12 SAST, Shield, reachability

Not started; they belong to M9 and will be recorded here when done.

## S13 Provider adapters

**Outcome:** GitHub (App, fine-grained PAT, OAuth), GitLab (groups and subgroups, gitlab.com or self-managed), Docker Hub, GAR, Harbor and generic OCI connections all support `:test` and `:discover`. Each connection's inbound webhooks are verified with its own secret.

**Evidence:** `internal/connections` tests; `TestPostgresGitLabRegistryImportAndMirrors`.

**Observed only:** GAR Workload Identity from a non-Google host. Real-account acceptance is part of release acceptance.
