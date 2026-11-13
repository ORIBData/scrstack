# Native provider connections

Build and deploy one generic SCRS image. After deployment, create any number
of GitHub, GitLab, Docker Hub, Google Artifact Registry (GAR), Harbor and
generic OCI registry connections through the authenticated REST API
(`POST /scrs/v1/connections`, documented in Swagger UI at `/scrs/v1/docs`). Each connection has its own name, provider config,
credential and scope. The Docker Hub PAT used by `make release` is separate
from provider connection credentials.

`scrs init` sets up storage. The Dokploy Compose file supplies no provider
credentials. Nonsecret connection config and scope are PostgreSQL `jsonb`;
credentials are AES-256-GCM ciphertext in a separate `bytea` column and are
never returned by the API. Keep `SCRS_MASTER_KEY` stable across deployments.

## REST workflow

Use `Authorization: Bearer <SCRS_BOOTSTRAP_API_TOKEN>` for the connection API.
Keep this token on the server or a backend-for-frontend, never in browser code.

1. `POST /scrs/v1/connections` creates a connection and returns its ID.
2. `POST /scrs/v1/connections/{id}:test` checks the credential and counts visible resources.
3. `POST /scrs/v1/connections/{id}:discover` stores visible resources and scope flags.
4. `GET /scrs/v1/connections` or `GET /scrs/v1/connections/{id}` returns nonsecret configuration and status.
5. `GET /scrs/v1/assets?limit=100` returns discovered assets and their `in_scope` flags. Follow `next_cursor` until it is empty.

Example fine-grained GitHub PAT request body:

```json
{
  "provider": "github",
  "name": "github-creditchek",
  "config": {"organization": "CreditChek", "auth_type": "fine_grained_pat"},
  "scope": {"include": ["CreditChek/api", "CreditChek/web-*"], "exclude": []},
  "credential": {"token": "REPLACE_WITH_ISSUED_TOKEN"}
}
```

Use another unique name for each organization or registry account. Creation
never overwrites an existing name. Current REST support covers creation,
listing, lookup, testing and discovery. Scope edits, credential rotation,
deletion, managed API tokens and live resource pagination remain to be built.

For other providers, use the same request shape:

| Provider | `config` | `credential` | Example scope include |
| --- | --- | --- | --- |
| GitHub App | `{"organization":"CreditChek","auth_type":"github_app","app_id":"123","installation_id":456}` | `{"private_key_pem":"<PEM text>","webhook_secret":"<secret>"}` | `CreditChek/*` |
| GitHub OAuth App | `{"organization":"CreditChek","auth_type":"oauth_app_token"}` | `{"token":"<issued user token>"}` | `CreditChek/api` |
| Docker Hub | `{"namespace":"myteam","identifier":"myteam"}` | `{"token":"<read-only token>"}` | `docker.io/myteam/*` |
| GAR | `{"project":"my-project","location":"europe-west2"}` | `{"service_account_json":{...the complete Google key object...}}` | `europe-west2-docker.pkg.dev/my-project/**` |

## Scope and discovery

For each connection, set `scope.include` to exact locators or globs. An empty
include list means no assets are in scope. `scope.exclude` always wins. Discovery records
accessible resources, including out-of-scope ones, as assets with
`flags.discovered=true` and an `in_scope` flag. It never scans them in this
foundation slice. Call `:discover` after `:test`; startup does not discover
provider resources. The private CLI supports `scrs connections discover all`
for reconciliation.

Discovery is bounded to 100 pages per list and 10,000 resources per connection.
It fails rather than silently reporting a partial inventory at those limits.
Periodic reconciliation and scan jobs are later milestones.

## GitHub organization

Set `config.auth_type` to one of three modes:

| Mode | Credential | GitHub organization control |
| --- | --- | --- |
| `github_app` | App ID, installation ID, PEM private key | Organization installs the App on all or selected repositories. |
| `fine_grained_pat` | Already-issued fine-grained PAT in `credential.token` | Organization PAT policy may restrict or require owner approval. Choose the organization as resource owner and grant selected repositories. |
| `oauth_app_token` | Already-issued OAuth App user token in `credential.token` | Under **Third-party application access policy**, an owner must approve the OAuth App when restrictions are enabled. The user must also have repository access. |

For `github_app`, grant read access to repository metadata and contents,
install it on the organization, then choose all or selected repositories. Send
the PEM key as `credential.private_key_pem`. SCRS signs an RS256 App JWT,
exchanges it for an installation token, then pages through the installation's
repositories. The App installation is an outer access boundary.

For `fine_grained_pat`, select **Metadata: read** (implicit for fine-grained
PATs) and **Contents: read** for future source scanning. For `oauth_app_token`,
authorize an OAuth App with `repo` scope when private repositories are needed.
The adapter calls `/user/repos`, then checks both `full_name` and `owner.login`
against `config.organization`. SCRS scope can narrow the resulting list.
The `:test` endpoint checks access; a zero count can also mean
the token lacks organization or repository approval, so compare the inventory
with GitHub before treating coverage as complete. A policy denial reported as
HTTP 403 fails the test. SCRS cannot approve a token or OAuth App on behalf of
the organization.

The OAuth mode currently accepts an already-issued user token; browser consent,
authorization-code exchange, refresh and revocation handling are not yet built.
Fine-grained PAT rotation is also operator-managed. The optional webhook secret
is currently stored only for GitHub App mode. Webhook HMAC verification and
event ingestion are not yet implemented.

Sources: [App JWT](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app),
[installation tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation),
[repository listing](https://docs.github.com/en/rest/apps/installations),
[user repository listing](https://docs.github.com/en/rest/repos/repos#list-repositories-for-the-authenticated-user),
[fine-grained PAT organization policy](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization),
[OAuth App organization approval](https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/approving-oauth-apps-for-your-organization),
[webhook validation](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries).

## Docker Hub

Set `config.namespace` to the user or organization namespace.
`config.identifier` is the username for a personal access token or the
organization name for an organization access token. Supply a **read-only** token
in `credential.token`. SCRS exchanges it at `/v2/auth/token`, then calls
the namespace-scoped repository list endpoint. Organization tokens need the
`Repository List` scope to see private repositories; without it, Docker Hub can
return HTTP 200 while silently omitting private repositories. Verify scope and
inventory before relying on coverage.

Sources: [Docker Hub token authentication](https://docs.docker.com/reference/api/hub/latest/),
[namespace repository listing](https://docs.docker.com/reference/api/hub/latest/operations/listNamespaceRepositories/),
[token scopes](https://docs.docker.com/security/access-tokens/reference/).

## Google Artifact Registry

Set `config.project` and `config.location`. Grant the service account
`roles/artifactregistry.reader` for the project or repository, then put its
JSON key object in `credential.service_account_json`. The adapter
accepts only `type=service_account` with Google's official OAuth token URI,
gets a read-only OAuth token, lists GAR repositories, then lists Docker images
inside each Docker-format repository. Unique image repository paths become
container-image assets.

Google recommends Workload Identity Federation for external workloads where
an identity provider is available. This first native GAR adapter supports
service-account JSON only; the external-account credential flow needs a
separate, verified implementation and a secure credential-file mount in
Dokploy. Do not paste an untrusted external-account JSON into the service-key
credential field.

Sources: [GAR repository listing](https://docs.cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories/list),
[GAR reader role](https://docs.cloud.google.com/artifact-registry/docs/repositories/list-repos),
[Workload Identity Federation](https://docs.cloud.google.com/iam/docs/workload-identity-federation).

## GitLab

`config.group` is the top-level group or a subgroup path (`acme/platform`);
discovery includes every non-archived project in subgroups and records them as
`gitlab_repo` assets (`acme/platform/api`). `config.base_url` defaults to
`https://gitlab.com`; self-managed instances need an HTTPS origin and may
include a path prefix. Put a group or project access token with `read_api` and
`read_repository` in `credential.token`.

Assessments fetch `repository/archive.tar.gz` for the resolved commit from the
same origin with redirects refused. Webhooks: point the group webhook at
`/scrs/v1/ingest/gitlab` with the secret token `SCRS_GITLAB_WEBHOOK_SECRET`,
or relay through n8n. When GitHub and GitLab both hold the same path, pass
`"provider": "gitlab"` in the assessment target.

```json
{"provider":"gitlab","name":"gitlab-platform","config":{"group":"acme/platform"},
 "scope":{"include":["acme/platform/**"]},"credential":{"token":"glpat-..."}}
```

## Harbor

Set `config.url` (HTTPS), `config.project` and `config.username` (a robot
account such as `robot$scrs`), and put the robot secret in
`credential.token`. Give the robot `list repository` and `pull artifact`
permissions only. Discovery uses Harbor's v2 API; image pulls use the same
robot account. For push events, add a project webhook "Artifact pushed"
pointing at `/scrs/v1/ingest/registry/harbor` with Auth Header
`Bearer <ingest:relay token>`.

## Generic OCI registry

For GHCR, Quay, ECR-compatible proxies, registry:2, Zot, Nexus and others:
`config.registry` is the host (with port if needed). List the image
repositories to cover in `config.repositories`, or omit it to use the
registry catalog (`/v2/_catalog`) filtered by `config.namespace`; GHCR and
some others offer no catalog. For private registries set `config.username` and
`credential.token`; omit both for anonymous public pulls (`credential: {}`).
Registries must serve HTTPS.

```json
{"provider":"oci","name":"ghcr-acme","config":{"registry":"ghcr.io","username":"acme-bot",
 "repositories":["acme/api","acme/worker"]},"scope":{"include":["ghcr.io/acme/*"]},
 "credential":{"token":"ghp_... (read:packages)"}}
```

## Security and current boundaries

- No provider credential is returned by the API or stored in JSONB.
- Credentials supplied through the REST API pass through the API process and
  are encrypted before storage. Use HTTPS and keep the admin token server-side.
- The same repository or image may appear under more than one connection.
  Assessment triggers then return `422`; pass `connection` (name or id).
- Admin-supplied base URLs (GitLab, Harbor, OCI registry) may point at private
  networks by design, for self-hosted installs. Only admins create connections.
- Discovery alone does not scan. Assessments, webhooks, imports and mirrors use
  these connections; see `ASSESSMENT_PIPELINE.md`.
