# SCRS foundation and deployment

This slice ships the SCRS API process, a versioned OpenAPI contract,
Swagger UI, storage bootstrap and native provider discovery. It persists
discovered assets, but does **not** yet implement assessments, jobs or scanner
orchestration. An unimplemented
route returns 404; it is not listed in OpenAPI. The existing ClamAV REST binary
and Compose file remain available for their current callers and are not exposed
by `compose.dokploy.yaml`.

## URL contract

The public root is `/scrs/v1`. Operational routes live under `system`,
documentation under `docs`, and provider management under `connections`:

- `/scrs/v1/system/healthz`
- `/scrs/v1/system/readyz`
- `/scrs/v1/docs`
- `/scrs/v1/docs/openapi.yaml`
- `/scrs/v1/connections`
- `/scrs/v1/assets`

Future routes follow `/scrs/v1/{module_name}/*`, for example
`/scrs/v1/assessments/{id}`. This path rule supersedes
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

Open `http://localhost:8080/scrs/v1/docs`. Swagger UI
assets are pinned and bundled in the API image, so the page does not depend on
a CDN. The API checks storage once at startup. The readiness route also checks
PostgreSQL, Redis and S3, caching the result for ten seconds. `healthz` only
reports that the process is running. The Compose healthcheck uses `readyz`.

`scrs init` runs storage bootstrap. Provider connections are created later
through the authenticated REST API; see [PROVIDERS.md](PROVIDERS.md).
`storage bootstrap` creates the named database only when
`SCRS_DATABASE_ADMIN_URL` is supplied and its role has `CREATEDB`; otherwise
the database must already exist. The application role must already exist and
be able to log in. On a self-hosted PostgreSQL server, create that role with
an administrator account before bootstrap, for example:

```sql
CREATE ROLE scrs_app LOGIN PASSWORD '<your-strong-password>';
```

Bootstrap creates the `scrs` schema and a migration table in that database.
It creates the named S3 bucket if absent and the S3
credential has `CreateBucket`. It does not create a Redis server or write any
application stream; Redis keys are created when work is queued. S3 prefixes
are virtual and are created by future object writes. The check
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
storage before the API starts. The API uses `SCRS_BOOTSTRAP_API_TOKEN` to
authorize connection management. Add each GitHub organization, Docker Hub
namespace or GAR project through the REST API after deployment. See
[PROVIDERS.md](PROVIDERS.md).
In Dokploy's **Domains** settings, select
`scrs-api`, port `8080`, and your HTTPS hostname. Dokploy attaches the selected
service to Traefik and provides the routing labels. Preview the generated
Compose configuration before deploying. No host port is published by this
Compose file. Do not configure a `StripPrefix` middleware. If you supplied
`SCRS_DATABASE_ADMIN_URL` to create the database, remove it from Dokploy after
the first successful bootstrap; the long-running API never receives it.

Only the API and one-shot bootstrap container are included at this stage;
PostgreSQL, Redis and S3 are external endpoints configured by URL. The later
platform Compose file will add the worker, scheduler and private ClamAV service
after their contracts and persistence behavior are implemented.
