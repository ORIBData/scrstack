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
make release PLATFORMS=linux/amd64,linux/arm64
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
