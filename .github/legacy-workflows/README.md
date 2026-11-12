# Archived upstream workflows

These upstream ClamAV workflows are preserved for reference and are not executed
by GitHub Actions. Their automatic publisher targeted `DOCKER_USER/clamav-rest`
and semantic-version tags, which do not match the SCRS release contract.

SCRS uses `.github/workflows/ci.yaml` for validation and `make release` for the
operator-selected Docker Hub or GAR repository, with interactive credentials.
No registry credentials are required by SCRS pull-request CI.
