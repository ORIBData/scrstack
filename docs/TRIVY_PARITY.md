# Image scanning compared with Trivy

This records the M6 parity check (spike S6). It compares the production SCRS scanner's `/scan-image` output with Trivy on three public images. Both used the same image archives and feeds from the same day.

## Setup

| | SCRS | Trivy |
| --- | --- | --- |
| Version | `scrs` scanner image built from `lionel.dev` on 2026-11-14 (OSV-Scanner v2.7.1) | 0.67.2, `trivy image --input <archive> --format json` |
| Data | OSV mirror for Alpine, Debian and PyPI, fetched 2026-11-14 20:49 UTC, plus KEV and EPSS | Trivy DB v2, updated 2026-11-14 19:00 UTC |
| Container | read-only, all capabilities dropped, 2 GiB tmpfs, offline | default |

**Images** (pulled by digest, saved with `docker save`):

| Image | Digest | Platform |
| --- | --- | --- |
| `alpine:3.18.4` | `sha256:eece025e432126ce23f223450a0326fbebde39cdf496a85d8c016293fc851978` | linux/arm64 |
| `debian:bookworm-slim` | `sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc` | linux/arm64 |
| `python:3.12-slim` (Debian 13) | `sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b` | linux/amd64 |

## How the results are compared

The two tools name OS packages differently:
- **Trivy** lists binary packages, such as `libc6` and `libssl3`.
- **SCRS** names a component by its source package, such as `glibc` and `openssl`. Each finding still carries the binary package in its purl (`pkg:deb/debian/libc6@…?source=glibc`).

Two comparisons are therefore made:
- **By binary package:** the advisory's CVE id and the purl's package name, against Trivy's `VulnerabilityID` and `PkgName`. This is the register's granularity, since a finding's fingerprint includes its purl.
- **By source package:** for packages, against Trivy's `SrcName`.

Distro advisory ids (`DEBIAN-CVE-…`, `ALPINE-CVE-…`) and aliases are reduced to their CVE id.

## Results

**Packages** (by source package):

| Image | SCRS | Trivy (binary) | Trivy (source) | Names in both |
| --- | --- | --- | --- | --- |
| alpine | 10 | 15 | 10 | 10 |
| debian | 65 | 88 | 63 | 63 |
| python | 64 | 88 | 62 | 62 |

Every source package Trivy found, SCRS found too. SCRS's two extra rows are the same source at two versions; for example, `util-linux` appears both with and without its epoch.

**Vulnerabilities** (by binary package):

| Image | SCRS | Trivy | Both | Only SCRS | Only Trivy |
| --- | --- | --- | --- | --- | --- |
| alpine | 38 | 38 | 38 | 0 | 0 |
| debian | 224 | 224 | 219 | 5 | 5 |
| python | 216 | 215 | 210 | 6 | 5 |

The raw SCRS finding count for python is 234. The difference from 216 is advisories that pip matches under both a `PYSEC` id and a `GHSA` id, which reduce to the same CVE.

## Differences

**Only in Trivy:** Debian's `TEMP-…` placeholders for issues that have no CVE yet:
- `TEMP-0290435-0B57B5` (tar);
- `TEMP-0517018-A83CE6` (sysvinit-utils);
- `TEMP-0628843-DBAD28` (login, passwd);
- `TEMP-0841856-B18BAF` (bash).

These come from the Debian security tracker, which Trivy reads directly. Debian's OSV export publishes only CVE records, so these placeholders cannot reach SCRS. All of them have tracker urgency "unimportant" and no fix.

**Only in SCRS:** Debian OSV records that Trivy's database does not list for these releases:
- `CVE-2025-8941` in pam (all four binary packages, both images);
- `CVE-2026-95209` in gnutls28 (bookworm), urgency "unimportant";
- `CVE-2026-119586` and `CVE-2026-39113` in sqlite3 (trixie), both "not yet assigned".

In each case, the OSV record marks the release as affected from version 0 with no fix. Trivy's Debian data is built from the tracker's per-release status, and these entries are open or not yet triaged there. Both tools follow their own data source correctly.

## Bug found and fixed

On `debian:bookworm-slim`, the first run marked inventory as **failed** ("image scanner reported incomplete coverage") even though it had already found its 224 findings.

**Cause:**
- When writing the CycloneDX SBOM, OSV-Scanner prints `Failed to parse package URL: unable to determine purl type of libgpg-error@1.46-1 (Debian:12)` for some source packages.
- SCRS treats any stderr line containing "error" as a coverage problem.
- The package name `libgpg-error` contains "error", so that line tripped the check.

**Follow-up (M8):** the same notices showed that OSV-Scanner's CycloneDX output had no components for these Debian images. SCRS now generates the SBOM from its own component model and no longer runs OSV-Scanner's CycloneDX writer (ADR-026).

**Fix:** `internal/scanner/scanner.go` now treats that notice as benign, like the progress lines that echo repository paths. A real error on the next line still marks coverage partial. `TestScannerProgressPathsAreNotProblems` covers both cases.

## Conclusion

- **OS packages and language packages** in these images match Trivy in full, and vulnerability matches agree on 97% or more of entries.
- **The remaining differences** come from the data sources (Debian tracker placeholders compared with Debian's OSV export), not from matching.
- **Ubuntu images** were not compared, because the Ubuntu OSV archive is too large for the default mirror (see `docs/PRODUCTION_READINESS_AUDIT.md`). Use a Trivy import for Ubuntu-based images.

**To repeat the run:**
1. Save each image with `docker save`.
2. Post the archive to the scanner's `/scan-image`.
3. Run `trivy image --input` on the same archive.
4. Compare the two JSON reports as described above.
