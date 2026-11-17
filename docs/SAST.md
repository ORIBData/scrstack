# SAST analyzers and reachability (M9)

SCRS bundles open-source static analyzers and a Go reachability tool (ADR-018). It runs them in a separate sandbox, `scrs-sast`, and records their results in the risk register. It writes no analysis engine or rule set of its own; teams can add rules (below).

## Analyzers

| Analyzer | Version | Languages | Licence | Distribution |
| --- | --- | --- | --- | --- |
| gosec | 2.30.0 | Go | Apache-2.0 | Free to redistribute |
| Bandit | 1.9.4 | Python | Apache-2.0 | Free to redistribute |
| OpenGrep | 2.0.0 | JavaScript, TypeScript, Java, Kotlin, Swift, Scala, PHP, Ruby, C#, C, Rust, Bash, Dockerfile | Engine LGPL-2.1; **rules LGPL-2.1 with Commons Clause** | Internal use only |
| Bearer | 2.1.3 | JavaScript/TypeScript, Java, PHP, Ruby | **Elastic License 2.0** (engine and rules) | Internal use only |
| govulncheck | 1.9.0 | Go reachability | BSD-3-Clause | Free to redistribute |

**Licences (SAST-010):**
- You accepted Bearer's Elastic License 2.0 and the OpenGrep rules' Commons Clause for internal use at CreditChek.
- Both are marked `redistributable: false` in `GET /sast/analyzers`. They must be removed from any SCRS build that leaves CreditChek, or offered as a service.

**Bundled rules:**
- **OpenGrep:** 632 rules from the community rules at commit `f1d2b562` (archived November 2025), for the languages above.
  - The Python and Go rules are left out: Bandit and gosec cover them, and they would double the entries.
- **Bearer:** rules v0.48.4 for JavaScript, Java, PHP and Ruby. Its Go and Python rules repeat gosec and Bandit, so they are not bundled.
- **Pinning:** every binary and rule archive in the image is pinned by SHA-256 or `go.sum` (`deploy/Dockerfile.sast`, `tools/sast`, `deploy/sast/requirements.txt`).

**Coverage gaps:**
- **Dart/Flutter:** no bundled analyzer.
- **Swift:** four rules only.
- Detected languages without an analyzer are named in the `sast` stage detail. Add custom OpenGrep rules to cover them.

## How a scan runs

1. **Check whether it applies.** For a repository assessment where SAST or reachability is enabled for the asset, the worker sends the source archive to `scrs-sast`.
2. **Pick analyzers.** The service detects languages from extensions (SAST-002) and runs each applicable, enabled analyzer as a child process:
   - with no network, no proxy and no credentials;
   - with git configuration ignored;
   - with `CGO_ENABLED=0` and `GOPROXY=off`;
   - under its budget (`SCRS_SAST_TIMEOUT`, default 10 minutes).
3. **Analyzers never run project code.** None runs build, install, generate or cgo steps. The hostile sample (a cgo preamble, `go:generate`, and a `setup.py` that writes a file and calls out) creates nothing (AT-28).
4. **Inline suppressions are run, then recorded.** Analyzers run with `nosec`, `nosemgrep` and `bearer:disable` ignored. SCRS reads the flagged line itself and records `suppressed_in_code` instead of losing the finding (SAST-007).
5. **Results are normalised** (SAST-005) to:
   - tool, rule, CWE ids, severity and confidence;
   - path and lines;
   - message;
   - data-flow steps (SARIF `codeFlows`; steps inside dependencies are tagged `third_party`, REA-010);
   - a SHA-256 of the surrounding code.

   No code snippet is stored.
6. **One finding reported by two tools** (same file, line and CWE) is linked through `also_reported_by`.

**Isolation (SAST-004):**
- `scrs-sast` is read-only, runs as a non-root user and drops all capabilities.
- It works in tmpfs, with memory, CPU and process limits.
- It sits only on the internal `sast` network, and holds no SCRS secrets except its own bearer token.
- Its one route out is `scrs-sast-egress`, which allows only `proxy.golang.org` and `sum.golang.org` for Go module downloads.

## Register entries and the gate (SAST-005 to SAST-007)

**Identity:**
- Each finding is a `sast` entry with advisory id `<tool>:<rule>`.
- Its identity uses the code hash, not the line, so a line shift keeps one entry.
- Adding a suppression comment keeps the identity too, because suppression markers are removed before hashing.

**Gate:**

| Entry | Verdict effect |
| --- | --- |
| New critical | fail |
| New high | warn |
| Existing | none |
| Suppressed in code | none (counted as `suppressed_in_code`) |
| A failed analyzer or a breached budget | the assessment is `incomplete`, never `pass` (SAST-011) |

**Suppressions added in code:** an entry that was open in the baseline but is now silenced by an inline comment raises an integrity entry, `SCRS-SAST-SUPPRESSION-ADDED` (medium). It stays open until someone reviews it (AT-27).

**Closure:** an entry closes when a complete SAST run of the ref no longer reports it, and only if *its own* analyzer ran with full coverage. An analyzer deselected for the asset, skipped, partial or failed did not look, so its entries stay open.

**Disabled rules and excludes:** an open entry hidden by a disabled rule or an excluded path becomes `suppressed`, with a `suppressed_by_configuration` event naming the filter. It is never marked `fixed`, because the code did not change. It is reopened if the filter is removed and the analyzer reports it again.

**Coverage gaps count:** gosec reports Go packages it could not load (type errors, missing modules, cgo). Its run is then `partial` and the assessment `incomplete`. To keep dependencies loadable, gosec downloads modules through the same go-modules proxy as reachability.

## Reachability (REA-001 to REA-007)

`govulncheck` runs against a database built from the OSV Go feed that `scrs-feed-sync` already keeps, for up to ten Go modules per repository. Every vulnerability entry then gets `evidence.reachability`:

| Status | Meaning |
| --- | --- |
| `reachable` | The project's code calls the vulnerable function. `trace` gives file and line from the caller to the symbol. |
| `imported_only` | Go: the vulnerable package is imported but not called. npm and PyPI: the repository's own source imports the package (`method: import_graph`; `trace` lists up to five places). |
| `not_reachable` | The module is required but the vulnerable package is not imported. |
| `unknown` | The analysis failed or was skipped, there is no verdict for the advisory, or the entry is from the Go standard library (analysed against the analyzer's toolchain, not your Go version). For npm and PyPI: the repository's own source does not import the package, which says nothing about whether a dependency of it is reached. |
| `unsupported` | Ecosystems other than Go, npm and PyPI, and npm or PyPI entries of a repository with no JavaScript, TypeScript or Python source: no verified open-source call-graph analyzer exists (spike S12). |

**Import-level fallback (REA-005).** For npm and PyPI the SAST service reads the imports of the repository's own JavaScript, TypeScript and Python files (`require`, `import`, dynamic `import()`, `export ... from`, Python `import` and `from ... import`; dependency and build directories are skipped). A package is matched by name; a PyPI distribution is also matched to its module names (its own name with `-` as `_`, and a short table such as `beautifulsoup4` to `bs4`). It never reports `not_reachable`, and it moves no score. It is a reading of text, not a call graph: a dynamic or computed import is missed.

**Safety rules:**
- A failed or skipped analysis is never `not_reachable` (REA-003).
- **Scores:** reachable adds 10 and not reachable subtracts 15 (`SCRS_REACHABILITY_WEIGHTS`). Known-exploited entries keep at least 45.
- Nothing is closed because it is unreachable (REA-004).
- Private Go modules cannot be downloaded through the proxy, so their advisories are `unknown`.
- Rust call analysis compiles code, so it is not offered (REA-006).

## Settings and rules

| Setting | Where | Default |
| --- | --- | --- |
| SAST on or off | `SCRS_SAST_ENABLED`; per asset with `PUT /assets/{id}/sast` (`enabled`) | off |
| Reachability on or off | `SCRS_REACHABILITY_ENABLED`; per asset (`reachability`) | off |
| Analyzers allowed in the deployment | `SCRS_SAST_ANALYZERS` | all four |
| Analyzers for one asset | `analyzers` | all allowed |
| Disabled rules (`tool:rule`, globs) and excluded paths (globs) | `PUT /sast/settings` (admin) plus per asset | none |
| Custom OpenGrep rules | `POST /sast/rulesets` (write; compiled offline by the service first, with a strict scan of an empty directory); `DELETE` (admin) | none |

All changes need `If-Match` and are audited.

**API:**
- `GET /sast/analyzers` lists versions, licences, rule counts and enabled state (SAST-009).
- `GET /reachability/capabilities` lists what is supported (REA-007).

## Deployment

`scrs-sast` is a third image (`make release-sast`, `deploy/Dockerfile.sast`) in the same Dokploy stack. Set:
- `SCRS_SAST_IMAGE`;
- `SCRS_SAST_API_TOKEN` (32 or more random characters, shared by the API, worker and service).

The service is not published through Traefik. See [DOKPLOY.md](DOKPLOY.md).

## Verification

| Check | Covers |
| --- | --- |
| `internal/sast` unit tests | Parsers fed the real outputs of the pinned tools, govulncheck classification, workspace and suppression identity, correlation, budgets and selection |
| `internal/worker` | Reachability mapping and scores, entry mapping and stage status |
| `TestPostgresSASTAndReachabilityPipeline` | New against existing entries, the suppression-added integrity entry, closure, a failed analyzer leaving the assessment incomplete, settings, rulesets and audit records |
| `make sast-image-test` | Starts the real image on an internal-only network with the go-modules proxy, and runs AT-27, AT-28 and AT-29. The canary check runs from the host, not inside the container under test |

**Spike results (2026-11-15):**
- Every analyzer ran offline.
- A full four-tool scan of the samples takes a few seconds.
- govulncheck called the sample's vulnerable function `reachable`, and the import-only sample `not_reachable`, matching OSV-Scanner's own call analysis.
