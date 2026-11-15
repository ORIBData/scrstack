# Licences, SBOM exports, safe versions and compliance reports (M8)

M8 covers:
- licences (LIC-001 to LIC-009);
- SPDX export and the export surface (SBM-010, SBM-011);
- safe versions (VUL-008);
- compliance evidence reports (CMP-001 to CMP-006).

Licence results are a **policy aid, not legal advice**. Compliance reports are **evidence for an assessor, not a certification**, and carry no compliance verdict.

## Licences

### Where licence data comes from (LIC-001)

Each component carries `license` with an SPDX expression and a `source`:

| Source | From | Ecosystems |
| --- | --- | --- |
| `declared` | Lockfiles, manifests and OS package databases read during the content walk | npm `package-lock.json` (v2 and v3) and installed `package.json`; PyPI `METADATA` and `PKG-INFO` (`License-Expression`, licence classifiers, short `License`); Composer `composer.lock` and `installed.json`; Alpine `lib/apk/db/installed`; Debian machine-readable `usr/share/doc/<pkg>/copyright` |
| `detected` | Licence file text, matched with `github.com/google/licensecheck`, with a `confidence` (share of the file matching licence texts; used at 0.5 or more) | `LICENSE`/`COPYING` files in `node_modules/<pkg>`, `*.dist-info`, `vendor/<module>`, the Go module cache, and free-form Debian copyright files |
| `metadata` | deps.dev API v3, fetched once per package version and cached in PostgreSQL (30 days; 7 for unknown packages) | npm, Go, Maven, PyPI, crates.io, NuGet, RubyGems |
| `none` | Nothing found anywhere; evaluated as `NOASSERTION` (category `unknown`) | Pub, SwiftPM, CocoaPods and other ecosystems without registry metadata |

How sources combine:
- A recognised declared licence wins. Otherwise a detected licence is used, then declared text SCRS could not identify.
- Debian components are source packages, so the copyright files of every binary package built from a source are combined with AND.
- The repository's own root `LICENSE` is reported in the `license` stage detail. It is not treated as a component.

**When a lookup fails** (deps.dev unreachable, or over `SCRS_DEPSDEV_MAX_LOOKUPS`):
- The component stays *unresolved*: no licence entry, and the `license` stage is `partial`.
- An outage never turns into "no licence found".
- Under an enforcing policy, unresolved components make the assessment `incomplete`.

### Normalisation and categories (LIC-002, LIC-003)

**Normalisation:**
- Text becomes an SPDX expression (`AND`, `OR`, `WITH`, parentheses).
- Deprecated ids are modernised (`GPL-2.0+` becomes `GPL-2.0-or-later`; `GPL-2.0-with-classpath-exception` becomes `GPL-2.0-only WITH Classpath-exception-2.0`).
- Common names, Python classifiers and Debian short names are mapped.
- Lists from npm `licenses` and Python classifiers are alternatives (OR). Debian file stanzas are combined (AND).
- Text SCRS cannot identify becomes `LicenseRef-scrs-<hash>` (category `unknown`). The original text is kept in `refs`.

**Categories:**
- The mapping ships in `internal/license/data/categories.json`. It covers all 740 ids of the SPDX License List 3.29.0, plus SCRS's own refs such as `LicenseRef-scrs-proprietary` (npm `UNLICENSED`) and `LicenseRef-scrs-bsd-unversioned`.
- There are nine categories: `permissive`, `public_domain`, `weak_copyleft`, `strong_copyleft`, `network_copyleft`, `source_available_restricted`, `non_commercial`, `proprietary` and `unknown`.
- A linking or runtime exception (Classpath, GCC runtime, LLVM and others) turns strong copyleft into weak copyleft.
- Admins override categories with `PUT /licenses/categories`. Overrides are versioned (`GET /licenses/categories/history`) and audited (`license_categories.updated`). Shipped mapping updates still apply to every id not overridden.

### Policy and distribution (LIC-004, LIC-005)

Every asset has a `distribution`: `internal`, `saas` (the default) or `distributed`. Admins set it with `PATCH /assets/{id}`. Mark mobile apps `distributed` and internal tooling `internal`. The licence inventory hints when an asset with Flutter or Swift packages is not marked `distributed`.

`corporate-default` applies until an admin stores a policy:

| Category | internal | saas | distributed |
| --- | --- | --- | --- |
| permissive, public domain | allow | allow | allow |
| weak copyleft | allow | allow | review |
| strong copyleft | allow | allow | review |
| network copyleft (AGPL, OSL) | review | **deny** | review |
| source-available restricted (SSPL, BUSL, Elastic) | review | **deny** | review |
| non-commercial | deny | deny | deny |
| proprietary, unknown | review | review | review |

**Policy documents** (`PUT /policies/license`, schema at `GET /schemas/license-policy`, `If-Match` revision):
- Rules match by licence id, category or package URL prefix. They can be narrowed by path glob, dependency scope (`dev` from the lockfile's dependency groups, or `runtime`), assets and distributions.
- Rules apply in order and the first match decides. Otherwise the matrix decides, then `default`.
- `AND` takes the strictest result and `OR` the most lenient.

`POST /policies/license:evaluate` is a dry run for counsel: it normalises the text and returns the decision with its basis (`rule:<n>`, `matrix:<category>/<distribution>` or `default`).

### Entries, gate and waivers (LIC-006, LIC-008)

**Entries:** a review or deny result becomes a `license` register entry, with advisory id `SCRS-LICENSE:<expression>` and severity `high` for deny and `medium` for review (configurable). It records the policy, its revision, the decision and the licence evidence.

**Gate:**

| Policy | deny | review |
| --- | --- | --- |
| `enforcing: false` (default, until counsel review, PRD Q24) | warn | does not gate |
| `enforcing: true` | **fail**, new or existing | warn |

**Waivers** use the standard register flow (`PATCH /register/{id}` with `accepted` and `expires_at`). They are audited in the entry's history and shown in inventories and reports.

**Closure:** entries close when a complete scan of the ref (with `inventory` and `license` stages `ok`) no longer produces them.

### Inventory, reports and notices (LIC-007, LIC-009)

- `GET /assets/{id}/licenses?ref=` is the newest assessed revision's components with expression, category, source, confidence, current policy result and basis, and the entry's status and waiver.
- `GET /reports/licenses?format=json|csv|md&asset_id=` is one asset or every assessed asset. In CSV, cells that start with a formula character are prefixed with `'`.
- `GET /assets/{id}/licenses/notices` is a THIRD-PARTY-NOTICES text file with each component's licence, the copyright lines SCRS recorded and links to the SPDX licence texts. Development dependencies are left out unless `include_dev=true`.

## SBOM generation and export (SBM-001, SBM-010, SBM-011)

**SCRS now generates the stored SBOM itself** from its component model (CycloneDX 1.6, via `cyclonedx-go`), with licences, dependency groups and every path a package was found at. Before M8 it stored OSV-Scanner's CycloneDX output, which leaves out OS packages it cannot give a package URL. On `debian:bookworm-slim` that document had no components at all.

`GET /assessments/{id}/sbom?format=` and `GET /sboms/{id}/download?format=` (where `id` is the SBOM's SHA-256 or the assessment id) serve:

| Format | Document |
| --- | --- |
| `cyclonedx-json` (default) | The stored document, checked against `sbom_sha256` (`ETag`) |
| `cyclonedx-xml` | The same document as XML |
| `spdx-json` | SPDX 2.3, generated from the same components |

SPDX documents carry:
- `licenseDeclared` (declared sources only) and `licenseConcluded`;
- package URLs, and `DEPENDS_ON` and `DEV_DEPENDENCY_OF` relationships;
- `hasExtractedLicensingInfos` for every LicenseRef.

Both formats list one entry per package URL, so their counts agree. Documents name the SCRS version and generation time, also in `X-SCRS-Version` and `X-SCRS-Generated-At`. Tests validate both against the official CycloneDX 1.6 and SPDX 2.3 JSON schemas (AT-26).

## Safe versions (VUL-008)

**Index:** `scrs-feed-sync` writes `index.json` (package name to advisory records) next to each ecosystem archive.

**What the scanner returns:** for every package with a vulnerability entry, every advisory the local mirror holds for it.

**What the worker adds** to each vulnerability entry's `guidance`:

| Field | Meaning |
| --- | --- |
| `fixed_versions` | Fixes named by the matched advisories |
| `safe_versions` | Ascending, at most ten: candidates above the installed version that **no** known advisory for the package affects, judged with each ecosystem's version ordering (osv-scalibr `semantic`) |
| `smallest_safe_upgrade`, `latest_safe` | The lowest safe version and, when a full version list was available, the highest |
| `safe_basis` | How many advisories were checked, whether the full mirror set was used, and whether candidates came from the registry's versions or only advisory fixes |

Candidates are the deps.dev version list (deprecated versions and pre-releases left out, unless the installed version is a pre-release), or else the advisories' fixed versions. A fix that a later advisory affects is not safe. For example, 4.17.21 fixes one lodash advisory but another affects it, so the answer is 4.18.1.

## Compliance evidence reports (CMP-001 to CMP-006)

### Framework packs (CMP-001, CMP-005)

| Pack | Source of the mapping |
| --- | --- |
| `owasp-top10-2021` | MITRE CWE view 1344, CWE List 5.0 (2026-10-28) |
| `owasp-top10-2025` | OWASP Top 10:2025 category pages, "List of Mapped CWEs" (MITRE has only the release candidate as view 1450) |
| `cwe-top25-2025`, `cwe-top25-2024` | MITRE CWE views 1435 and 1430, in rank order |
| `pci-dss-4.0.1` | SCRS evidence views for requirements 6.3.1, 6.3.2 and 6.3.3 |

**How findings map to categories:**
- A finding counts in every category whose CWEs it carries.
- Some finding types have no CWE of their own. They map through `type_categories`:

  | Finding type | OWASP 2021 | OWASP 2025 |
  | --- | --- | --- |
  | Vulnerable dependency | A06 | A03 |
  | Malicious dependency | A08 | A03 |
  | Integrity change | A08 | A08 |
  | Secret | A07 | A07 |
  | Misconfiguration | A05 | A02 |

- Reports show which mapping was used.

**Where CWEs come from:**
- OSV `cwe_ids`;
- NVD and CVE Program records for the entry's CVE aliases;
- Trivy `CweIDs`;
- SARIF rule tags and properties, such as CodeQL's `external/cwe/cwe-079`.

**Custom packs:** admins upload `cwe_mapping` packs with `POST /reports/frameworks` (schema at `GET /schemas/framework-pack`) and read or delete them at `/frameworks/{id}`. Shipped ids are reserved.

### Reports (CMP-002, CMP-003, CMP-006)

`POST /reports` takes these fields:
- `framework`;
- `scope`: `asset`, `owner` or `portfolio`;
- a window of `since` to `until`, at most 366 days (default the last 90);
- `format`: `json`, `csv` or `md`;
- `params`: `sbom_max_age_days` (default 30), `sla_critical_days` (30) and `sla_high_days` (90).

The worker builds the report (`SCRS_REPORT_POLL_SECONDS`). Poll `GET /reports/{id}` and fetch `GET /reports/{id}/download`. The file is integrity-checked; its digest is in `ETag` and `X-SCRS-Report-SHA256`.

Every report records:
- the data time, SCRS version, scope and window;
- the freshness of every advisory source;
- assets lacking a recent SBOM, as gaps;
- dismissed findings and excluded finding types (licence, malware, indicator and QA entries).

**Content by kind:**

| Kind | Content |
| --- | --- |
| CWE mapping | Per category: open findings by severity, opened and closed in the window, a weekly trend and the CWEs seen; `unmapped` counts findings without a CWE and with CWEs outside the pack |
| PCI DSS 6.3.1 | Open findings ranked by severity per asset, with known-exploited counts |
| PCI DSS 6.3.2 | SBOM coverage and gaps |
| PCI DSS 6.3.3 | Critical and high vulnerabilities open past their patch window, fixed within or after it, and the median days to fix |

**Retention:** files are stored under `reports/` in S3 in the `reports` retention class.

## Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `SCRS_DEPSDEV_ENABLED` | true | deps.dev licence metadata and version lists |
| `SCRS_DEPSDEV_URL`, `SCRS_DEPSDEV_PRIVATE_HOSTS` | public API | A mirror and its private hostnames |
| `SCRS_DEPSDEV_MAX_LOOKUPS` | 2000 | Licence lookups per assessment |
| `SCRS_REPORT_POLL_SECONDS` | 30 | Report build interval (0 disables) |
| `SCRS_RETENTION_DEFAULT_REPORTS_DAYS` | empty | Retention default for report files |

## Verification

| Test | Covers |
| --- | --- |
| `internal/license` | Normalisation cases, categories and overrides, corporate-default (AT-25 decisions), rules, the policy schema, detection and every manifest parser |
| `internal/sbom` | CycloneDX 1.6 and SPDX 2.3 validated against the official schemas, equal counts, licences and XML (AT-26) |
| `internal/versions` | OSV range evaluation in npm, PyPI and Debian ordering, and the safe-version cases including a fix that a later advisory affects |
| `internal/compliance` | Shipped packs, pack validation, category, unmapped, gap and PCI computations, and rendering without a verdict |
| `make scanner-test` | Declared licences and the package index with the real OSV-Scanner |
| `TestPostgresLicencesSafeVersionsSBOMAndReports` | The worker end to end: deps.dev metadata and cache, entries and verdicts report-only and enforcing, waiver (AT-25), safe versions, generated SBOM against SPDX (AT-26), OWASP 2025 and PCI reports (AT-30) |
| `TestPostgresLicenceAndComplianceAPI` | Every new endpoint through the real router, with scopes, `If-Match`, formats, downloads and audit records |

**Not yet tried:** real deps.dev at volume, and counsel review of `corporate-default` (PRD Q24).
