# Dokploy deployment contract

Use `deploy/compose.dokploy.yaml` with concrete published `SCRS_IMAGE` and
`SCRS_QA_RUNNER_IMAGE` references (see [RELEASING.md](RELEASING.md)). Run
`make image-reference` before building/releasing, then copy the resolved value
into Dokploy. The date/hash placeholders are a Make template, not Compose syntax.

Set the following for each environment:

```dotenv
SCRS_DOMAIN=your-staging-domain.example
SCRS_ROUTER_NAME=scrs-staging
SCRS_TRAEFIK_NETWORK=dokploy-network
SCRS_HTTP_ENTRYPOINT=web
SCRS_HTTPS_ENTRYPOINT=websecure
SCRS_CERT_RESOLVER=letsencrypt
SCRS_SWAGGER_DOCS_ENABLE=true
SCRS_DOCS_PUBLIC=true
SCRS_CORS_ORIGINS=
SCRS_TRUSTED_PROXY_CIDRS=
```

Use a different domain and unique router name for production on the same VPS.
The hostname has no scheme, path, port or wildcard. DNS must resolve to the VPS.
Match the network, entrypoints and resolver to your existing Traefik configuration.

The Compose labels expose only `/scrs/v1` and `/scrs/v1/*` on the selected host,
redirect HTTP to HTTPS, enable TLS with the named ACME resolver, and send traffic
to port 7000 without stripping the path. Swagger UI is at `/scrs/v1/docs`; its
contract is `/scrs/v1/docs/openapi.yaml`. No application port is published on the
host. The init service is explicitly hidden from Traefik and receives the optional
PostgreSQL bootstrap administrator URL; the API does not receive that URL.

Dokploy's existing Traefik must configure the Let's Encrypt resolver, ACME account
email, reachable challenge ports/DNS credentials and persistent certificate storage.
Traefik owns issuance and renewal. Labels select an existing resolver; they do not
create it. Do not also configure a second router through Dokploy's Domains UI for
this service. See [Dokploy's label example](https://docs.dokploy.com/docs/core/docker-compose/example)
and [Traefik TLS routing](https://doc.traefik.io/traefik/reference/routing-configuration/http/tls/overview/).

Two settings control the docs:
- `SCRS_SWAGGER_DOCS_ENABLE=false` removes the Swagger UI, its assets and the
  OpenAPI document altogether. Every `/scrs/v1/docs` path then returns the same
  404 as an unknown route, with or without a token, so a production host does
  not reveal its API contract. The default is `true`; any other value stops the
  API at start-up.
- `SCRS_DOCS_PUBLIC` applies only while the docs are enabled.

Keep public docs enabled for normal browser access. If `SCRS_DOCS_PUBLIC=false`,
the docs document and all assets require bearer authentication; an authenticated
client/proxy must supply headers before the Swagger page can load. API management
routes always require authentication regardless of the docs setting.

`SCRS_TRUSTED_PROXY_CIDRS` is an explicit comma-separated list of trusted proxy
peer networks. Leave it empty to ignore forwarded IP headers. For per-token client
IP restrictions behind Traefik, configure its exact peer IP range and ensure other
untrusted containers cannot join that trusted range. Never trust a default route.
The API walks X-Forwarded-For from right to left and stops at the first untrusted
hop. `SCRS_CORS_ORIGINS` accepts exact browser origins; empty disables cross-origin
browser access. Wildcards are not allowed.

Before accepting the deployment, verify public HTTPS trust, HTTP redirect,
readiness, unauthenticated API denial, authenticated access, private registry pull,
restart recovery and certificate renewal configuration on the actual VPS. These
checks have not been performed against a live SCRS domain in this workspace.

## Token lifecycle and recovery

Set a random bootstrap token of 32–512 non-whitespace characters and the same
value on every API replica. Startup stores only its SHA-256 hash. Changing it and
restarting replaces the stored value globally; old replicas with a stale env value
must not be restarted later. Changing deployment settings must be coordinated.

Admin tokens can create/list/revoke `/scrs/v1/tokens`. Token creation returns the
secret once. Connection management requires admin; asset listing requires read or
admin. Narrow `trigger` and `ingest:relay` scopes grant no management access; their
product endpoints are not yet implemented. Revocation is checked in PostgreSQL
on every request. Redis enforces 120 admitted requests per token per sliding minute;
Redis outages fail closed. Token IP lists accept CIDRs and token expiry is optional.
The bootstrap token cannot be revoked through the API; rotate it via the environment.

Back up PostgreSQL with a provider-supported consistent snapshot or `pg_dump -Fc`.
Store `SCRS_MASTER_KEY` separately in secure recovery storage: a database backup
cannot recover encrypted provider credentials without the same key. Do not rotate
that key by simply replacing the env value. Restore into a separate empty database,
validate decryption, token revocation and asset state, then perform a controlled
cutover. `make database-test` exercises a real dump/restore of synthetic records.
Hosted database failover, S3 object/version recovery and full recovery-time targets
still require environment-specific acceptance.

## Legacy scanner compatibility

The root `docker-compose*.yml` examples are internal legacy scanner examples,
not SCRS API deployments. They now build this repository's protected scanner and
bind ports to loopback. Supply a separate `SCRS_SCANNER_API_TOKEN` of at least 32
characters to use streaming scan routes. `/scanFile` and `/scanPath` are retired
with HTTP 410; clients must upload content. The SCRS API image contains none of
these legacy routes. Older upstream Kubernetes manifests/documentation are not a
supported SCRS production deployment and must not be deployed as this product.

## Assessment services

The Compose file now also starts worker, offline scanner, OSV feed synchronization
and a restricted remediation egress proxy using the same SCRS image. Set a distinct
random `SCRS_SCANNER_API_TOKEN`; set `SCRS_OSV_ECOSYSTEMS` to the required package
ecosystems. `SCRS_REMEDIATION_ENABLED=true` enables the validated npm advice path. Only the
API joins Traefik's external network. Feed download must complete before scanner
readiness allows the worker to start. PostgreSQL, Redis and evidence S3 stay external.
The rebuildable feed cache is a local Docker volume. Review scanner resource limits
and [pipeline operating constraints](ASSESSMENT_PIPELINE.md) before deploying.

Guided remediation (REM-002) runs in its own container, `scrs-remediator`: the scanner image
in the `remediation` role, answering only `/remediate` with `SCRS_REMEDIATION_API_TOKEN` (a
third random token, different from the scanner's). It holds no database, storage, provider or
scanner credentials, shares one internal network (`remediation`) only with the worker and the
egress proxy, works in a 256 MiB `noexec` tmpfs, and is limited to 1 CPU, `SCRS_REMEDIATION_MEMORY`
(default 1g), 128 processes and the request's 4-minute timeout. The scanner itself no longer
serves `/remediate` (`SCRS_SCANNER_ROLE=scan`). Existing deployments must add
`SCRS_REMEDIATION_API_TOKEN` before updating the stack.

## External HTTPS acceptance and optional HTTP node port

Set `SCRS_PUBLIC_BASE_URL=https://your-domain` (or the same URL with `/scrs/v1`)
in the deployment dotenv. `make deployment-acceptance` uses that value to verify
TLS, public health/readiness, unauthorized rejection, authorized assessment reads,
Swagger/OpenAPI and active remediation capabilities. It uses
`SCRS_ACCEPTANCE_API_TOKEN` (read scope) or falls back to the bootstrap token.
Credentials are not printed and cross-origin redirects are rejected.
`make pipeline-acceptance` goes further: it uploads a small archive with a write-scoped
`SCRS_ACCEPTANCE_WRITE_TOKEN` and follows the assessment through the worker, scanner and storage.
The full ordered checklist, with what to record, is [STAGING_ACCEPTANCE.md](STAGING_ACCEPTANCE.md).

The API listens on HTTP port 7000 inside Docker (`SCRS_HTTP_ADDR=:7000`). Traefik terminates external HTTPS
and preserves `/scrs/v1/*`. A published host port is unnecessary for that routing.
If an HTTP node port is needed for local VPS diagnostics, add
`deploy/compose.nodeport.yaml`; it binds `SCRS_HTTP_NODE_PORT` (default 7000) to **127.0.0.1**
only and forwards it to the container's port 7000, e.g. `curl http://127.0.0.1:7000/scrs/v1/system/readyz`.
Probes: `/system/healthz` and `/system/readyz` are public and answer only `ok` or `unavailable` (load balancers).
A frontend status page should call `GET /system/status` with a `read` token. It reports `api`, `postgres`, `redis`,
`s3`, `worker` (heartbeat), `scanner`, `feeds`, `sast`, `qa_runner` and `dependency_track` (only while the Dependency-Track link is on) as `ok`, `degraded`, `down` or `not_configured`,
and always answers `200`, so read its `status` field. The QA runner's own `/healthz` returns 503 with the names of
failed prerequisites (`karate`, `work_dir`, `java`, `gatling_classpath`), which makes Docker mark it unhealthy.

Each API instance also watches that status every 30 seconds. A status that holds for three checks (about 90 seconds,
starting two minutes after boot, so a redeploy stays quiet) is announced once across instances as a `system.degraded`
event (lists the failing components) or, when it returns to `ok`, `system.recovered` (with the duration). Subscribe a
webhook to them (`events: ["system.degraded","system.recovered"]`) or receive them on `GET /events`. Announcements
are stored in PostgreSQL, so an outage of PostgreSQL itself cannot be announced: the live stream drops and clients
should treat a reconnect as a reason to call `GET /system/status`.
Keep external consumers on the HTTPS domain. Certificate renewal remains owned by
Dokploy/Traefik and needs operational verification separately.

Remediation is now enabled by default in Compose and dotenv. Supported npm manifests
produce automatic advice jobs after assessment completion; inspect
`GET /scrs/v1/assessments/{id}/remediations`. Source repositories are never modified.
The ClamAV service uses the pinned official 1.5.4 Debian image with native AMD64/ARM64 support, running as
its unprivileged user with capabilities dropped. `SCRS_CLAMAV_MEMORY` defaults to 4 GiB
to allow signature-reload headroom; this is a memory limit, not a reservation. ClamAV exposes no host port and stores only signature data in
its volume. Freshclam needs outbound access for signature updates. Stale signatures
make malware coverage partial and create a posture finding. YARA remains separate
and is not implemented by loading rules into ClamAV.

## 2026-11-13 release additions

**New service.** `scrs-yara-rules` runs once per deploy as the ClamAV image's
`clamav` user (uid 1000). It waits until ClamAV has populated its signature
volume, writes the embedded YARA ruleset as `scrs.yar`, then sends clamd a
`RELOAD`. Assessments prove the rules are live with a canary; if the
installer failed, the `yara` stage reads `skipped` and verdicts stay
`incomplete`. Check `docker logs <project>-scrs-yara-rules-1` after deploy.

**Outbound access** now also needed: `www.cisa.gov` (KEV) and
`epss.empiricalsecurity.com` (EPSS) from `scrs-feed-sync`; for Maven
remediation, `repo.maven.apache.org` and `repo1.maven.org` through the egress
proxy; and your n8n or other webhook receivers from `scrs-worker`. KEV/EPSS
outages never block scanning; the previous copy is carried forward.

**Settings** (all optional; see `.env.example`):

| Variable | Service | Purpose |
| --- | --- | --- |
| `SCRS_RELAY_ENABLED` | API | Accept n8n relay deliveries (bearer `ingest:relay` token) on the GitHub, GitLab and shared registry receivers. Per-connection registry receivers do not need it |
| `SCRS_PUBLIC_BASE_URL` | API, worker | Absolute links in webhook payloads; deployment acceptance |
| `SCRS_WEBHOOK_PRIVATE_HOSTS` | API, worker | Hostnames allowed as http or private-address webhook targets |
| `SCRS_TAXII_PRIVATE_HOSTS` | API, worker | TAXII server hostnames allowed to resolve to private addresses, such as an OpenCTI on the same network |
| `SCRS_EVENT_MAX_BYTES`, `SCRS_EVENT_FIELD_MAX`, `SCRS_EVENT_REDACT` | API, worker | Context-document limits and JSON Pointer redaction |
| `SCRS_MASS_DELETION_FILES` | API | Mass-deletion alert threshold (default 50 files) |
| `SCRS_MAX_IMAGE_BYTES`, `SCRS_SCANNER_MEMORY` | worker, scanner | Image size cap (400 MiB) and scanner memory (3 GiB) |
| `SCRS_SNAPSHOT_ARCHIVES` | worker | Store each fetched source archive in S3 for restore |
| `SCRS_RESCAN_INTERVAL_HOURS` | worker | Scheduled default-branch rescans; 0 disables |

**Image assessment** requires the image's OS ecosystems in
`SCRS_OSV_ECOSYSTEMS`. The default is now `npm,Go,Maven,PyPI,Pub,SwiftURL,RubyGems,Alpine,Debian`
(about 380 MB on the first sync, which the scanner healthcheck allows up to
15 minutes for). Pub, SwiftURL and RubyGems cover Flutter, Swift Package
Manager and fastlane lockfiles; without a lockfile's feed the whole package
stage fails and the verdict is `incomplete`. Ubuntu is not supported offline:
its archive is 815 MB and expands to 8.1 GiB (2026-11-14), beyond the 512 MiB
download, 2 GiB expansion and 2 MiB per-record caps. Import a Trivy report for
Ubuntu-based images instead. OSV publishes no CocoaPods feed and OSV-Scanner
does not read `Podfile.lock`, so CocoaPods dependencies have no vulnerability
coverage.

**Monitoring.** Scrape `https://<domain>/scrs/v1/system/metrics` with a
`read` token (Prometheus `authorization` credentials). Queue depth, oldest
queued age, verdict totals, duration quantiles and undelivered webhooks come
from PostgreSQL, so one scrape target covers the API and worker. Alert on
`scrs_store_up == 0`, a growing `scrs_assessment_oldest_queued_seconds`, and
`scrs_webhook_deliveries{status="dead"} > 0`.

**Verified locally on 2026-11-13.** This Compose file (port 7000) ran
end to end with disposable PostgreSQL, Redis and MinIO:
- storage initialized;
- the YARA installer wrote into ClamAV's volume and the live clamd matched the canary;
- feed sync delivered OSV, KEV and EPSS;
- the scanner health gate released the worker;
- the API answered over the proxy network;
- the worker's dispatcher attempted outbound delivery and scheduled a retry.

Live Traefik/TLS on the VPS remains to be accepted with `make deployment-acceptance`.

## 2026-11-14 release additions

Migration `2026111401` runs through `scrs-storage-init`: it widens the
connection provider check and adds the `asset_mirrors` table. It is additive.

**New capabilities:** GitLab, Harbor and generic OCI connections; GitLab
webhooks (`/scrs/v1/ingest/gitlab`); registry push events
(`/scrs/v1/ingest/registry/{harbor,dockerhub,gar,oci}`); Trivy and SARIF import
(`/scrs/v1/assessments:import`); ClamAV, YARA and IOC inspection of every image
layer; git-history mirrors; and an `X-SCRS-Auth` header on outbound webhooks
for n8n Header Auth.

| Variable | Service | Purpose |
| --- | --- | --- |
| `SCRS_GITLAB_WEBHOOK_SECRET` | API | Legacy: shared GitLab secret for the shared `/ingest/gitlab` receiver. Connections now have their own secrets (`POST /connections/{id}:webhook`) |
| `SCRS_YARA_BINARY` | API, scanner | YARA-X CLI used to validate and run YARA rulesets (default `/usr/local/bin/yr`, shipped in the image) |
| `SCRS_GITHUB_HOOK_CHECK_MINUTES` | worker | GitHub webhook delivery check interval (default 5; 0 disables). GitHub never retries a failed delivery, so the worker reads SCRS's webhook delivery log, requests redelivery of missed events and reports hook misconfiguration at `GET /system/github-webhooks` |
| `SCRS_TAXII_POLL_SECONDS` | worker | How often the worker checks for due TAXII feeds (default 60; 0 disables polling). Each feed has its own `interval_minutes` |
| `SCRS_GITHUB_HOOK_URL` | worker | Legacy default hook URL for the delivery check; set `hook_url` per connection instead. By default the check matches the connection's receiver `/scrs/v1/ingest/github/<connection>` or the shared paths is checked |
| `SCRS_MIRRORS_ENABLED` | worker | Run the mirror queue (default `true`) |
| `SCRS_MIRROR_INTERVAL_HOURS` | worker | Mirror assets labelled `mirror=true` on this interval; 0 = on demand only |
| `SCRS_MIRROR_MAX_BYTES` | worker | Largest bundle (default 2 GiB) |
| `SCRS_MIRROR_KEEP` | worker | Bundles kept per asset (default 7) |
| `SCRS_MIRROR_MIN_AGE_DAYS` | worker | Bundles younger than this are never pruned (default 30). A bundle is deleted only when beyond `SCRS_MIRROR_KEEP` and older than this; the newest bundle taken before an open integrity finding is always kept |

**Outbound access** from `scrs-worker` now also includes your GitLab origin,
`github.com` (git smart HTTP for mirrors) and every connected registry.

**Large transfers.** Imports may upload 16 MiB within 60 seconds and bundle
downloads stream for up to 30 minutes. If Traefik's entrypoint read or write
timeouts are lower, raise them for the SCRS router.

**Verified locally on 2026-11-13.** This Compose file was rebuilt and run from
the `deploy/Dockerfile.scrs` image. The migration applied, and the GitLab,
Harbor and GitHub connections were accepted. A GitLab push queued an
assessment. A Harbor push queued a digest-pinned image assessment. A Trivy
import completed with its verdict. A mirror request reached github.com and was
recorded as failed with a clear `HTTP 401`, because the test used a synthetic
token.

## E2E QA (Karate) additions

Tables `llm_providers`, `qa_profiles`, `qa_runs`, `qa_scenarios`, `qa_generations`
and `qa_suites` are created by `scrs-storage-init`. All changes are additive.

**Two images, one stack.** The repository builds two images:
- **SCRS:** `deploy/Dockerfile.scrs`, published with `make release`.
- **The Karate runner:** `deploy/karate-runner/Dockerfile`, published with
  `make release-qa-runner SCRS_QA_RUNNER_IMAGE=registry/namespace/scrs-qa-runner:scrs_YYYY_MM_DD_v{shortSHA256}`.
  It builds for amd64 and arm64.

`deploy/compose.dokploy.yaml` deploys both in the same Dokploy stack:

| Service | Image | Private address | Public URL (Traefik, TLS) |
| --- | --- | --- | --- |
| `scrs-api` | `SCRS_IMAGE` | `http://scrs-api:7000` | `https://${SCRS_DOMAIN}/scrs/v1` |
| `scrs-qa-runner` | `SCRS_QA_RUNNER_IMAGE` | `http://scrs-qa-runner:8090` | `https://${SCRS_QA_DOMAIN}`, limited to `SCRS_QA_RUNNER_ALLOWED_CIDRS` |

How the two services connect:
- **Private path.** The API and worker reach the runner over the stack's internal
  `qa` network (`SCRS_QA_RUNNER_URL=http://scrs-qa-runner:8090`). QA traffic never
  leaves the host or passes through Traefik.
- **Public router.** Traefik gives the runner its own router (`SCRS_QA_ROUTER_NAME`),
  certificate and hostname, with an http→https redirect. Every call also needs the
  runner's bearer token.
- **Operator route.** The public router exists for operators who run standalone QA,
  performance and load jobs on the runner. These jobs are independent of SCRS
  assessments and of supply-chain checks, and SCRS does not record them. See
  [QA_TESTING.md](QA_TESTING.md#standalone-operator-use).
- **Allowlist.** The default `SCRS_QA_RUNNER_ALLOWED_CIDRS=127.0.0.1/32` lets nobody
  in from outside. Add the CIDRs of the operators and tools that should call the runner directly.
- **Ports.** Each service has its own container port (7000 and 8090), and both are
  published on 443 by hostname. Neither binds a host port.
- **DNS.** Create a record for `SCRS_QA_DOMAIN` pointing at the VPS.

| Variable | Service | Purpose |
| --- | --- | --- |
| `SCRS_QA_RUNNER_IMAGE` | runner | Published runner image reference |
| `SCRS_QA_RUNNER_TOKEN` | API, worker, runner | Shared bearer token (32+ characters) |
| `SCRS_QA_DOMAIN`, `SCRS_QA_ROUTER_NAME` | runner | Runner hostname and Traefik router name (default `scrs-qa`) |
| `SCRS_QA_RUNNER_ALLOWED_CIDRS` | runner | Client CIDRs allowed through Traefik (default `127.0.0.1/32`, nobody) |
| `SCRS_QA_RUNNER_SLOTS`, `SCRS_QA_RUNNER_MEMORY`, `SCRS_QA_RUNNER_WORK_SIZE` | runner | Parallel jobs (default 1), memory limit (3g) and job tmpfs (2g) |
| `SCRS_QA_RUNNER_URL`, `SCRS_QA_RUNNER_ALLOW_HTTP` | API, worker | Default to the private runner; set an https URL and `false` for a runner on another host |
| `SCRS_QA_RUNNER_CA_FILE` | API, worker | PEM file trusted for a privately issued runner certificate |
| `SCRS_QA_MAX_ACTIVE` | worker | Runs on the runner at once (default 4) |
| `SCRS_QA_GENERATION_ENABLED` | worker | `false` disables LLM test generation and AI code review |
| `SCRS_LLM_PRIVATE_HOSTS` | API, worker | Your own model servers (Ollama, vLLM). Besides allowing private addresses and http, this list marks a provider `local`, which may always be sent source code. A hosted provider needs the two opt-ins instead. |
| `SCRS_LLM_PROVIDERS`, `SCRS_LLM_PROVIDER_HOSTED_*`, `SCRS_LLM_PROVIDER_LOCAL_*` | API | Providers declared in the environment (names `hosted` and `local`; settings are `KIND`, `MODEL`, `BASE_URL`, `API_KEY`, `MAX_TOKENS`, `TEMPERATURE`, `ALLOW_SOURCE`). They exist when the API starts; the environment owns them. See [LLM_KNOWLEDGE.md](LLM_KNOWLEDGE.md#providers-from-the-environment) |
| `SCRS_LLM_ALLOW_SOURCE_TO_HOSTED` | API, worker | `true` lets an acknowledged hosted provider receive source code (default `false`). Set it on both |
| `SCRS_LLM_MONTHLY_INPUT_TOKENS`, `SCRS_LLM_MONTHLY_OUTPUT_TOKENS` | worker | Monthly token cap per hosted provider (defaults 20000000 and 4000000; `0` removes a cap) |
| `SCRS_LLM_ASSESSMENT_INPUT_TOKENS`, `SCRS_LLM_ASSESSMENT_OUTPUT_TOKENS` | worker | Token ceiling for the model work of one assessment (defaults 300000 and 60000) |
| `SCRS_LLM_TIMEOUT_SECONDS` | API, worker | One model call's time limit (default 360; 900 for a CPU model) |
| `SCRS_AI_REVIEW_MAX_FILE_BYTES` | worker | Largest source file sent for AI code review (default 49152) |
| `SCRS_EMBED_API_KEY` | `scrs-embed`, worker | Required. Key for the embedding service |
| `SCRS_EMBED_URL`, `SCRS_EMBED_MODEL`, `SCRS_EMBED_DIM`, `SCRS_EMBED_MAX_CHARS`, `SCRS_EMBED_PRIVATE_HOSTS` | worker | The self-hosted embedding service (defaults: `scrs-embed`, bge-small, 384, 1500). Empty URL turns embedding off. See [MODEL_HOST.md](MODEL_HOST.md) |
| `SCRS_EMBED_MEMORY`, `SCRS_EMBED_CPUS` | `scrs-embed` | Resource limits (defaults 2g, 2) |
| `SCRS_LLM_PRIVATE_HOSTS` | API, worker | Self-hosted model hosts (Ollama, vLLM) allowed to resolve privately and use http |

**Runner isolation in the shared stack.** The runner executes repository test code on
the same host as SCRS.
- **What protects SCRS:**
  - The runner has no SCRS secrets, and its tests run as uid 10001 without the runner token.
  - The container keeps six capabilities and a read-only root filesystem.
  - It is not on the stack's `default` network.
- **What it can still reach:**
  - It joins `dokploy-network`, because Traefik routes to it there and that network
    gives it internet access to your staging URLs. So it can also reach every other
    container attached to `dokploy-network`.
  - It can reach the host's published ports.
- **Actions:**
  - Keep databases and admin services off `dokploy-network`, or protect them with credentials.
  - Block cloud metadata (`169.254.169.254`) for the runner on the host firewall.
- **Check from inside the runner** that it cannot reach your database or Redis:
  `docker exec <runner> curl -m 3 telnet://<db-host>:5432` should fail.

For a hard boundary, run `deploy/compose.qa-runner.yaml` on a separate VM instead, and
point `SCRS_QA_RUNNER_URL` at its https URL. No other change is needed.

**Outbound access** from `scrs-worker` also includes the inference URLs of the LLM
providers you add, such as `api.openai.com`, `api.anthropic.com` and
`generativelanguage.googleapis.com`. The API calls a provider too when an admin runs
`POST /llm/providers/{id}:test`. Report archives are stored in the existing bucket
under `qa/`. See [QA_TESTING.md](QA_TESTING.md).

## Advisory sources, retention and maintenance additions

Tables `vulnerability_sources`, `advisory_records`, `vex_documents`,
`vendor_statements`, `scheduler_runs` and `retention_classes`, plus
`assets.legal_hold`, are created by `scrs-storage-init`. All changes are additive.

| Variable | Service | Purpose |
| --- | --- | --- |
| `SCRS_ADVISORY_SYNC_SECONDS` | worker | How often due NVD and CVE Program syncs are checked (default 60; 0 disables) |
| `SCRS_NVD_API_KEY` | worker | Optional NVD API key: one request per 0.7 s instead of 6 s |
| `SCRS_DTRACK_PUSH_SECONDS` | worker | How often queued Dependency-Track uploads are pushed (default 30; 0 disables). The export itself is enabled with `PUT /integrations/dependency-track` |
| `SCRS_DTRACK_PRIVATE_HOSTS` | API, worker | Dependency-Track hostnames allowed to resolve to private addresses and use http (a server on the same network) |
| `SCRS_EVENTS_MAX_STREAMS` | API | Live event streams (`GET /events`) per API instance (default 200) |
| `SCRS_EVENTS_STREAMS_PER_TOKEN` | API | Live event streams per API token (default 5) |
| `SCRS_NVD_API_URL`, `SCRS_CVE_API_URL` | worker | Override the NVD and CVE Services URLs (mirrors, tests) |
| `SCRS_RETENTION_DEFAULT_<CLASS>_DAYS` | API, worker | Retention default for a class the policy leaves not set (0 or empty keeps forever; `AUDIT_LOG` at least 365) |
| `SCRS_RELEASE_FEED_URL` | API | Optional https JSON release feed for `GET /maintenance/versions` |
| `SCRS_VERSION` | API | Optional version label for `GET /maintenance/versions` |

**Outbound access** from `scrs-worker` also includes
`services.nvd.nist.gov` and `cveawg.mitre.org`.

## SAST analyzers and reachability (M9)

`scrs-sast` is a third image (`make release-sast SCRS_SAST_IMAGE=...`) in the same stack:
- It sits on the internal `sast` network with the API and worker.
- Its one route out is `scrs-sast-egress` (`SCRS_EGRESS_PROFILE=go-modules`: `proxy.golang.org` and `sum.golang.org` only).
- It mounts `scrs-feeds` read-only for the Go advisory archive.
- It is not published through Traefik.

Tables `sast_settings`, `asset_sast_settings` and `sast_rulesets` are created by `scrs-storage-init`.

| Variable | Service | Purpose |
| --- | --- | --- |
| `SCRS_SAST_IMAGE` | stack | Published scrs-sast image reference |
| `SCRS_SAST_API_TOKEN` | API, worker, scrs-sast | Shared bearer token (32 or more random characters) |
| `SCRS_SAST_URL` | API, worker | Default `http://scrs-sast:8083` |
| `SCRS_SAST_ENABLED`, `SCRS_REACHABILITY_ENABLED` | API, worker | Deployment defaults (false); assets override them with `PUT /assets/{id}/sast` |
| `SCRS_SAST_ANALYZERS` | scrs-sast | Analyzers allowed (default `gosec,bandit,opengrep,bearer`) |
| `SCRS_SAST_TIMEOUT` | worker | Per-analyzer budget (default `10m`); a breach makes the assessment incomplete |
| `SCRS_REACHABILITY_WEIGHTS` | worker | Score change for reachable and not reachable (default `10,-15`) |
| `SCRS_SAST_SLOTS`, `SCRS_SAST_MEMORY`, `SCRS_SAST_WORK_SIZE` | scrs-sast | Concurrent analyses (1), memory (4g), tmpfs work area (4g) |

**Outbound access** from `scrs-sast-egress`: `proxy.golang.org` and `sum.golang.org`. See [SAST.md](SAST.md).

## Licences, SBOM exports and compliance reports (M8)

Tables `policies`, `license_category_versions`, `package_metadata`,
`package_versions`, `reports` and `framework_packs`, plus `assets.distribution`
(default `saas`), are created by `scrs-storage-init`. All changes are additive.
`scrs-feed-sync` now also writes a package index (`index.json`) next to each
ecosystem archive; scans of snapshots synced before it fall back to matched
advisories for safe versions.

| Variable | Service | Purpose |
| --- | --- | --- |
| `SCRS_ACTIONS_SWEEP_INTERVAL_HOURS` | worker | Reads each in-scope GitHub repository's Actions inventory (enabled, workflow list, run-number gaps) this often, 25 repositories per 15 minutes; 0 or unset is off. Needs the read-only Actions permission on the connection's credential; without it the repository shows `available: false` |
| `SCRS_DEPSDEV_ENABLED` | worker | Licence metadata and version lists from deps.dev (default true; false evaluates packages without a declared or detected licence as "no licence found") |
| `SCRS_DEPSDEV_URL`, `SCRS_DEPSDEV_PRIVATE_HOSTS` | worker | A deps.dev API mirror and its hostnames allowed to resolve to private addresses |
| `SCRS_DEPSDEV_MAX_LOOKUPS` | worker | Licence lookups per assessment (default 2000); the rest are left unresolved and retried next time |
| `SCRS_REPORT_POLL_SECONDS` | worker | How often queued compliance reports are built (default 30; 0 disables) |
| `SCRS_RETENTION_DEFAULT_REPORTS_DAYS` | API, worker | Retention default for compliance report files |

**Outbound access** from `scrs-worker` also includes `api.deps.dev`. Report files are
stored in the existing bucket under `reports/`. See [LICENSES_AND_COMPLIANCE.md](LICENSES_AND_COMPLIANCE.md).
