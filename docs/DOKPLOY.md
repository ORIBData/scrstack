# Dokploy deployment contract

Use `deploy/compose.dokploy.yaml` with a concrete published `SCRS_IMAGE`. Run
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

## External HTTPS acceptance and optional HTTP node port

Set `SCRS_PUBLIC_BASE_URL=https://your-domain` (or the same URL with `/scrs/v1`)
in the deployment dotenv. `make deployment-acceptance` uses that value to verify
TLS, public health/readiness, unauthorized rejection, authorized assessment reads,
Swagger/OpenAPI and active remediation capabilities. It uses
`SCRS_ACCEPTANCE_API_TOKEN` (read scope) or falls back to the bootstrap token.
Credentials are not printed and cross-origin redirects are rejected.

The API listens on HTTP port 7000 inside Docker (`SCRS_HTTP_ADDR=:7000`). Traefik terminates external HTTPS
and preserves `/scrs/v1/*`. A published host port is unnecessary for that routing.
If an HTTP node port is needed for local VPS diagnostics, add
`deploy/compose.nodeport.yaml`; it binds `SCRS_HTTP_NODE_PORT` (default 7000) to **127.0.0.1**
only and forwards it to the container's port 7000, e.g. `curl http://127.0.0.1:7000/scrs/v1/system/readyz`.
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
| `SCRS_RELAY_ENABLED` | API | Accept n8n relay deliveries on `/scrs/v1/ingest/github` |
| `SCRS_PUBLIC_BASE_URL` | API, worker | Absolute links in webhook payloads; deployment acceptance |
| `SCRS_WEBHOOK_PRIVATE_HOSTS` | API, worker | Hostnames allowed as http or private-address webhook targets |
| `SCRS_EVENT_MAX_BYTES`, `SCRS_EVENT_FIELD_MAX`, `SCRS_EVENT_REDACT` | API, worker | Context-document limits and JSON Pointer redaction |
| `SCRS_MASS_DELETION_FILES` | API | Mass-deletion alert threshold (default 50 files) |
| `SCRS_MAX_IMAGE_BYTES`, `SCRS_SCANNER_MEMORY` | worker, scanner | Image size cap (400 MiB) and scanner memory (3 GiB) |
| `SCRS_SNAPSHOT_ARCHIVES` | worker | Store each fetched source archive in S3 for restore |
| `SCRS_RESCAN_INTERVAL_HOURS` | worker | Scheduled default-branch rescans; 0 disables |

**Image assessment** requires the image's OS ecosystems in
`SCRS_OSV_ECOSYSTEMS`, for example `npm,Go,Maven,Alpine,Debian`. Each adds to
the first feed download, which the scanner healthcheck now allows up to
15 minutes for.

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
