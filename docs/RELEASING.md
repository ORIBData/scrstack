# SCRS image releases

Set `.env` to a full image repository and the release tag template:

```dotenv
SCRS_IMAGE=organization/repository:scrs_YYYY_MM_DD_v{shortSHA256}
```

An organization alone is not a Docker Hub image repository. For Google Artifact
Registry use `REGION-docker.pkg.dev/PROJECT/REPOSITORY/IMAGE` before the colon.
Do not leave `{Container_Registry_Organization_Name}` in a deployment value.

```sh
make image-reference
make image
make release                                   # linux/amd64 (the staging VPS)
make release PLATFORMS=linux/amd64,linux/arm64 # multi-architecture, when needed
make clean-dry-run
make clean
```

Make resolves the UTC date and the first 12 hexadecimal characters of SHA-256
across sorted Git-listed source file paths and contents, including nonignored
new files and working-tree edits. Dotenv files are excluded. This is a source
fingerprint, not the image digest or Git commit ID. Pin the published manifest
digest for immutable deployments. A rebuild of unchanged source on the same
day uses the same tag; registries can enforce immutability if required.

`SCRS_IMAGE` on the Make command line overrides `.env`. `VERSION=scrs_...`
can explicitly override the tag; legacy `DOCKERHUB_REPO=namespace/name` remains
supported. `make image-reference` prints the concrete reference. Copy that
reference into Dokploy's `SCRS_IMAGE`; Compose does not expand the template.

Releases build `linux/amd64` by default (`PLATFORMS` adds `linux/arm64`). Each
release creates a temporary Buildx `docker-container` builder, because the
default `docker` driver cannot attach the SBOM and provenance attestations, and
removes it on exit together with the temporary login. From an Apple Silicon Mac
the amd64 image builds under emulation, so the Rust YARA-X stage takes much
longer than a native build.

**Docker Build Cloud.** Set `SCRS_BUILD_CLOUD=ORG/BUILDER` (for example
`oribdata/creditchek-stg-ci`) in `.env`, or on the make command line, to build
on that cloud builder:
- Builds run on native amd64 and arm64 machines, so there is no emulation.
- The release creates a temporary reference to the builder and removes it on exit. The cloud builder itself is untouched.
- Build Cloud signs in with the release's Docker Hub login, so the image must be on Docker Hub and the username must belong to the builder's organisation.
- The build context is uploaded to Docker's builders. `.dockerignore` keeps `.env`, `.git`, `bin` and `artifacts` out of it.
- Builds use the organisation's Build Cloud minutes.

Docker Hub releases prompt for a username and PAT. GAR releases select the
`oauth2accesstoken` username and prompt for a fresh access token (obtain one
with `gcloud auth print-access-token`). The GAR repository must already exist
and the identity needs push permissions. See [Google's authentication guide](https://docs.cloud.google.com/artifact-registry/docs/docker/authentication).
Credentials are supplied through stdin and retained only in a temporary Docker
configuration, removed on exit. The current Docker engine endpoint is preserved.
No provider asset credentials from the SCRS database are used to publish SCRS.

Cleanup accepts either registry path, limits repository matching to `scrs_`
tags, preserves the newest local project image and images used by containers,
and never deletes registry images or storage volumes. Build cache is not pruned.

`make image-audit` scans the resolved local image with Docker Scout and generates
CycloneDX SBOM and SARIF evidence under `artifacts/<immutable-image-id>/`. It fails
when findings are reported. These artifacts are ignored by Git and should be
retained with release evidence. Release builds request BuildKit SBOM and provenance
attestations. Attestations do not replace an identity signature: registry publishing,
signing the published manifest digest, and verifying that signature are separate
release acceptance steps not executed by the local QA workflow.

The inherited upstream workflow that automatically pushed `clamav-rest` images has
been archived. SCRS CI builds/tests the API without publishing; release remains an
explicit operator action through Make.

## Karate runner image

The E2E QA runner is a second image built from `deploy/karate-runner/Dockerfile`
(karate-cli 0.1.9, Karate 2.1.4 and karate-gatling, all pinned and checksum-verified;
headless Chromium; Java 21). It follows the same tag rules:

```sh
make qa-runner-image                       # local build
make qa-runner-image-test                  # API, UI and load runs in a hardened container
make qa-runner-image-reference             # print the resolved tag
make release-qa-runner
```

`release-qa-runner` and `release-sast` read `SCRS_QA_RUNNER_IMAGE` and
`SCRS_SAST_IMAGE` from `.env`, as `release` reads `SCRS_IMAGE`; a value on the
make command line wins. `make sast-image-reference` and
`make qa-runner-image-reference` print the resolved tags for Dokploy. Tags must
begin `scrs_`. When the three images share one repository, give each its own
prefix so their tags never collide:

```dotenv
SCRS_IMAGE=organization/repository:scrs_YYYY_MM_DD_v{shortSHA256}
SCRS_SAST_IMAGE=organization/repository:scrs_sast_YYYY_MM_DD_v{shortSHA256}
SCRS_QA_RUNNER_IMAGE=organization/repository:scrs_qa_runner_YYYY_MM_DD_v{shortSHA256}
```

`make clean` then keeps only the newest local `scrs_*` image of that repository,
so rebuild the other two locally if needed; registry images are never deleted.

Set the resolved reference as `SCRS_QA_RUNNER_IMAGE` in Dokploy. Bump
`KARATE_VERSION`, `KARATE_SHA256` and the karate-cli digests in the Dockerfile
together, from `https://karate.sh/manifest.json`.
