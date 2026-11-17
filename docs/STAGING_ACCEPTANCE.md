# Staging acceptance runbook

What to run, in order, on the Dokploy VPS before calling a build ready, and what to
write down. It covers the four items under "External release acceptance still required"
in [PRD_PROGRESS_AND_AUDIT.md](PRD_PROGRESS_AND_AUDIT.md). Nothing here has been run against
a real VPS yet; the two scripts are tested only against fakes.

Rules for the whole run: never paste a token, `SCRS_MASTER_KEY` or a provider credential
into a ticket or chat; keep them in the Dokploy environment or a password manager. Run
commands that use live credentials yourself (in a terminal, or with `! <command>` inside
a Claude Code session) rather than asking an assistant to.

## 0. Prepare

1. Choose the domain and point DNS at the VPS. Confirm Dokploy's Traefik has the Let's Encrypt
   resolver named in `SCRS_CERT_RESOLVER`, reachable challenge ports and persistent ACME storage
   ([DOKPLOY.md](DOKPLOY.md)).
2. Publish the images (`make release`, [RELEASING.md](RELEASING.md)) and put the exact
   digests in `SCRS_IMAGE`, `SCRS_QA_RUNNER_IMAGE` and the SAST image variable. Do not deploy
   a tag.
3. Fill the environment from `.env.example`. Set `SCRS_PUBLIC_BASE_URL`. Leave
   `SCRS_SWAGGER_DOCS_ENABLE=true` while the frontend team works.
4. Deploy. When the stack is up, create two tokens with the bootstrap token
   (`POST /tokens`, the secret is shown once): `acceptance-read` (scope `read`) and
   `acceptance-write` (scope `write`). Put them in `.env` as `SCRS_ACCEPTANCE_API_TOKEN` and
   `SCRS_ACCEPTANCE_WRITE_TOKEN`, then revoke both when acceptance is done.

## 1. HTTPS and routing (read-only)

```
make deployment-acceptance
```

Passes when TLS verifies, `/system/healthz` and `/readyz` answer, unauthenticated calls
get 401, the docs and `openapi.yaml` load (or 404 when disabled), and remediation is enabled.
Also check by hand: `http://` redirects to `https://`, and the certificate's issuer is
Let's Encrypt (`openssl s_client -connect <domain>:443 -servername <domain> </dev/null | openssl x509 -noout -issuer -dates`).

Record: date, domain, image digests, script output.

## 2. The pipeline end to end (writes one asset)

```
make pipeline-acceptance
```

Uploads a tiny npm project with `lodash@4.17.11` as `upload/scrs-acceptance` and follows the
assessment through the worker, scanner, object storage and database. It fails when the
platform is `down`, an upload is refused, the assessment does not finish within
`SCRS_ACCEPTANCE_TIMEOUT` seconds (default 300) or ends `failed`, a core stage
(`resolve`, `fetch`, `inventory`, `sbom`) is not `ok`, or the SBOM, job list, revision list
or register summary is unreadable. It warns, without failing, for a component that is not
`ok` (`feeds`, `sast`, `qa_runner`, `dependency_track`), a malware, YARA, IOC or integrity
stage that is partial, and when no vulnerability is found for lodash, which usually means the
OSV mirror has not synced yet (`GET /intel/vulnerability-sources`).

A clean `verdict` is not expected: lodash 4.17.11 has known vulnerabilities, and a
repository with partial coverage reads `incomplete`, never `pass`.

Record: the output, the assessment id, the stages and their durations.

## 3. Feeds

1. `GET /intel/vulnerability-sources`: each enabled source has a recent `last_success_at`.
   First sync of OSV, NVD and CVE Program can take a long time; wait for it before judging.
2. `GET /system/status`: `feeds` is `ok`. A source stale beyond its limit shows as `degraded` and raises
   `feed.stale`.
3. Re-run `make pipeline-acceptance`; the lodash warning should now be gone.
4. If TAXII or STIX sources are used, add one real source and confirm a poll (`POST /intel/indicator-sources/{id}:poll`).

Record: source, last success, row counts you can see, any rate-limit errors.

## 4. Providers and real data

Use a real organisation and the narrowest credentials ([PROVIDERS.md](PROVIDERS.md)).

1. `POST /connections` with the provider, scope globs and credential; then `POST /connections/{id}:test`
   and `:discover`. Compare `discovered` and `in_scope` with what you expect; check that an
   excluded repository is not in scope.
2. Trigger one assessment on a real repository (`POST /assessments`) and read the findings,
   SBOM and `GET /assessments/{id}/report`.
3. Set the connection webhook (`POST /connections/{id}:webhook`), configure the provider to call
   `/ingest/<provider>/<connection>`, push a commit and confirm an assessment queues.
4. Registries: assess one image by tag and by digest.
5. Note the credential's expiry date and the provider's rate-limit headers or errors seen.

Record: provider, scope, counts, any 4xx or rate-limit responses, credential expiry.

## 5. Restart recovery

1. Start an upload assessment (`make pipeline-acceptance` in one terminal).
2. In Dokploy, restart the worker container while it runs. The assessment must reach `succeeded`
   after its lease expires (the lease is 5 to 10 minutes) or be re-queued; it must not stay `running` forever.
3. Restart the API, then Redis, then the scanner one at a time. After each, `GET /system/status`
   returns to `ok` within about two minutes and a new assessment succeeds.
4. Stop Redis: authenticated calls fail closed with 503 (by design), `/system/healthz` still answers.

Record: what you restarted, time to `ok`, anything that needed manual action.

## 6. Certificate renewal

Traefik owns issuance and renewal. Record the certificate's `notAfter` now, confirm the ACME
storage is on a persistent volume, and set a reminder for 30 days before expiry to check that it
renewed. A real renewal cannot be forced; a staging CA or a short-lived test domain is the only way to see one early.

## 7. Backup and disaster recovery

1. Take a PostgreSQL backup (`pg_dump -Fc` or the provider's snapshot) and note the time it takes.
2. Restore it into a separate, empty database. Start a throwaway SCRS pointed at it with the **same**
   `SCRS_MASTER_KEY` and the same S3 bucket (read-only credentials if you can). Confirm: a token works, connections
   decrypt (`POST /connections/{id}:test`), assets and the register match, an SBOM downloads, and
   `GET /assets/{id}/uploads` lists the acceptance archive.
3. Confirm S3 has versioning or provider-side recovery for the bucket, and that `uploads/`, `sbom/` and
   `snapshots/` objects survive a deleted-object test in a scratch bucket.
4. Record recovery point (age of the newest restored row) and recovery time (start of restore to a working API).

Record: backup size and duration, restore duration, RPO, RTO, who holds `SCRS_MASTER_KEY` offline.

## 8. Load and faults

Within the rate limit of 120 requests per token per minute:

1. Reads: 20 requests per second for five minutes against `GET /register/summary` and `GET /jobs`
   (use several tokens, since each is capped at 120 per minute). Watch latency and `GET /system/status`.
2. Writes: upload 20 different archives in a loop (change a byte per archive). The worker and scanner
   take one at a time; `GET /jobs?status=queued` should drain, and a full queue answers 429 with `Retry-After`.
3. Faults: stop the scanner (assessments retry, `scanner` is `down`), stop MinIO (`s3` is `down`, new
   assessments cannot finish), stop ClamAV (malware stage `partial`, verdict `incomplete`). Each recovers when the service returns.

Record: request rate, p95 latency, queue drain time, which faults recovered by themselves.

## 9. Settings to decide for staging

Off by default and worth a deliberate choice:

| Setting | Where | Note |
| --- | --- | --- |
| Retention days per class | `PUT /settings/retention` | Includes `uploaded_archives`; nothing is purged until days are set. Preview first with `:preview`. |
| Dependency checks | `PUT /policies/dependencies` | `min_release_age_days` calls deps.dev; `typosquat` has false positives. Both informational. |
| Licence policy | `PUT /policies/license` | Keep report-only until counsel reviews. |
| Hosted LLM providers | `/llm/providers`, `SCRS_LLM_ALLOW_SOURCE_TO_HOSTED` | Source code goes to a hosted provider only after the platform switch and a per-provider acknowledgement. |
| Dependency-Track link | `PUT /integrations/dependency-track` | The API key is stored through the API, never in the environment. |
| Outbound webhooks | `POST /webhooks` | Subscribe `system.degraded` and `system.recovered` so an outage is announced. |

## 10. Evidence table

Fill one row per item; keep it with the release notes.

| Item | Date | Who | Result | Evidence (output, ids, screenshots) |
| --- | --- | --- | --- | --- |
| HTTPS and routing | | | | |
| Pipeline end to end | | | | |
| Feeds | | | | |
| Providers and real data | | | | |
| Restart recovery | | | | |
| Certificate renewal | | | | |
| Backup and restore (RPO, RTO) | | | | |
| Load and faults | | | | |
| Release manifest signed and verified | | | | |

## Known limits to carry into staging

- Clean repositories read `incomplete`, not `pass`; gate CI on `fail`.
- Uploaded source can only be assessed as a whole archive of at most 64 MiB.
- Local advisories do not create register entries yet; hosted LLM review and Dependency-Track depend on settings above.
- Everything under "Open PRD requirements" in [PRD_PROGRESS_AND_AUDIT.md](PRD_PROGRESS_AND_AUDIT.md) is still open.
