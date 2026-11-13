# SCRS foundation and deployment

The foundation is the part every SCRS module builds on: the API process, the
versioned OpenAPI contract and Swagger UI, storage bootstrap and migrations,
API tokens, and native provider connections with asset discovery. The
assessment pipeline (durable jobs, worker, isolated scanner, findings register)
runs on top of it and is described in
[ASSESSMENT_PIPELINE.md](ASSESSMENT_PIPELINE.md). An unimplemented route
returns 404 and is not listed in OpenAPI. The base ClamAV REST binary and its
root Compose files remain available to internal callers but are not part of
`compose.dokploy.yaml`; the pipeline uses its own private ClamAV daemon.

## URL contract

The public root is `/scrs/v1`. Each module owns one top-level segment:

- `/scrs/v1/system/healthz`, `/scrs/v1/system/readyz`: liveness and readiness
- `/scrs/v1/docs`, `/scrs/v1/docs/openapi.yaml`: Swagger UI and contract
- `/scrs/v1/tokens`: API token management
- `/scrs/v1/connections`, `/scrs/v1/assets`: provider accounts and discovered assets
- `/scrs/v1/assessments`, `/scrs/v1/register`: assessments and the risk register
- `/scrs/v1/webhooks/github`, `/scrs/v1/feeds/indicators`, `/scrs/v1/settings/retention`,
  `/scrs/v1/remediation/capabilities`: ingestion, indicators, retention, remediation

New modules follow `/scrs/v1/{module_name}/*`. This path rule supersedes
the `/api/v1` and root-level examples in the draft PRD. The OpenAPI `servers`
value and every implemented path must match the actual Go handler. Traefik
forwards the full path without stripping `/scrs/v1`.

## Local work

```sh
make build
make test
make lint
make contract-check
make image VERSION=dev
make clean-dry-run
make clean
make storage-integration
```

Copy `.env.example` to `.env`, replace every placeholder, run `chmod 600 .env`,
then run:

```sh
make storage-init
make storage-check
python3 scripts/run_with_env.py bin/scrs api
```

Open `http://localhost:7000/scrs/v1/docs`. Running assessments locally also
needs `bin/scrs feed-sync`, `bin/scrs scanner` and `bin/scrs worker`. Outside
containers, point them at local paths: `SCRS_FEED_ROOT` and
`SCRS_OSV_DB=<feed root>/current`, a writable `SCRS_WORK_ROOT`,
`SCRS_OSV_BINARY=bin/osv-scanner` (built by `make scanner-test`) and
`SCRS_SCANNER_URL=http://127.0.0.1:8081/scan`. The Dokploy Compose file wires
all of this together. Swagger UI
assets are pinned and bundled in the API image, so the page does not depend on
a CDN. The API checks storage once at startup. The readiness route also checks
PostgreSQL, Redis and S3, caching the result for ten seconds. `healthz` only
reports that the process is running. The Compose healthcheck uses `readyz`.

`scrs init` runs storage bootstrap and all schema migrations. Provider
connections are created later through the authenticated REST API; see
[PROVIDERS.md](PROVIDERS.md).
`storage bootstrap` creates the named database only when
`SCRS_DATABASE_ADMIN_URL` is supplied and its role has `CREATEDB`; otherwise
the database must already exist. The application role must already exist and
be able to log in. On a self-hosted PostgreSQL server, create that role with
an administrator account before bootstrap, for example:

```sql
CREATE ROLE scrs_app LOGIN PASSWORD '<your-strong-password>';
```

Bootstrap creates the `scrs` schema, a migration table and the SCRS tables in
that database. It creates the named S3 bucket if absent and the S3 credential
has `CreateBucket`. It does not create a Redis server. The job queue lives in
PostgreSQL; Redis holds only short-lived per-token rate-limit keys. S3 prefixes
(`sbom/`, `remediation/`) are virtual and appear with the first artifact. The check
exercises PostgreSQL, a temporary Redis stream and cache key, and a temporary
S3 object. In a versioned bucket, the probe removes its exact object version;
the credential therefore needs `DeleteObjectVersion`. Missing permissions
produce a failing exit code. Bootstrap is idempotent and does not remove
existing data.

## Docker Hub release

```sh
make release VERSION=scrs_staging DOCKERHUB_REPO=oribdata/zerorate-stg PLATFORMS=linux/amd64
```

The target prompts for a Docker Hub username and PAT in the terminal. If
`DOCKERHUB_REPO` is omitted, it also asks for the repository. The login user
may differ from the repository namespace if that account has push permission.
It captures the active Docker engine endpoint before using a temporary Docker
config for registry credentials, then publishes **one tag**, for example
`oribdata/zerorate-stg:scrs_staging`. This repository also holds other services,
so use an SCRS-specific tag to avoid overwriting another service's staging tag.
The default `PLATFORMS` includes both native
`linux/amd64` and `linux/arm64`; the example above builds only AMD64. The PAT
is not placed in a file in this repository or passed as a Docker build argument. The temporary login is
removed when the command ends. `make release` requires an explicit non-`dev`
tag and a configured `docker buildx` builder.

`make clean-dry-run` previews local SCRS image tags to remove. `make clean`
removes older local SCRS images, retains the newest image by creation time,
and skips images used by any local container. It recognizes local `IMAGE_NAME`
tags, SCRS-labelled images, and `DOCKERHUB_REPO` tags (or the repository in
`.env`'s `SCRS_IMAGE` when the variable is omitted). For example, run
`make clean-dry-run DOCKERHUB_REPO=oribdata/zerorate-stg` before
`make clean DOCKERHUB_REPO=oribdata/zerorate-stg`. In a shared repository it
selects only tags beginning `scrs_` unless the image carries SCRS's own label.
Set `SCRS_REPO_TAG_PREFIX` explicitly if your SCRS tags use another prefix.
It does not prune other
projects, volumes or build cache, and it does not remove remote Docker Hub
images.

## Dokploy Compose

Set all values from `.env.example` in the Dokploy Compose environment and use
`deploy/compose.dokploy.yaml`. A one-shot `scrs-storage-init` service bootstraps
storage before the API starts. `SCRS_BOOTSTRAP_API_TOKEN` is the initial admin
token; use it to create narrower managed tokens and to add each GitHub
organization, Docker Hub namespace or GAR project through the REST API after
deployment. See [PROVIDERS.md](PROVIDERS.md).
Routing comes from the Traefik labels in the Compose file (host
`SCRS_DOMAIN`, paths `/scrs/v1/*`, container port 7000, HTTPS via
`SCRS_CERT_RESOLVER`). Do **not** also add a domain in Dokploy's **Domains**
settings; that creates a second router. Preview the generated Compose
configuration before deploying. No host port is published by this Compose
file. Do not configure a `StripPrefix` middleware. If you supplied
`SCRS_DATABASE_ADMIN_URL` to create the database, remove it from Dokploy after
the first successful bootstrap; the long-running API never receives it.

The stack runs the API, the one-shot bootstrap, the worker, the isolated
scanner, a private ClamAV daemon, OSV feed synchronization and the remediation
egress proxy, all except ClamAV from the same SCRS image. PostgreSQL, Redis and
S3 are external endpoints configured by URL. A scheduler for periodic
maintenance is not implemented yet. [DOKPLOY.md](DOKPLOY.md) is the full
deployment contract.
