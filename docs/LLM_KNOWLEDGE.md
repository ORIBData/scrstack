# LLM guardrails and knowledge layer

The objective: use a language model to enrich SCRS's technical output (advisories, summaries, reports, QA and code review) while keeping credentials and source out of the provider's hands, keeping embeddings and memory in your own infrastructure, and keeping everything traceable per asset and assessment.

This document records what was validated, what was decided, what is built, and what is next. Audit findings are in [LLM_RAG_AUDIT.md](LLM_RAG_AUDIT.md).

## Validated facts

| Claim | Finding | Source |
| --- | --- | --- |
| A custom extension can run on any standard PostgreSQL over a normal connection | **No.** `CREATE EXTENSION` needs the extension's control file in the server's extension directory, and a superuser unless the extension is marked trusted. A native extension needs files on the database host; managed PostgreSQL services allow only the extensions they ship. | [PostgreSQL: CREATE EXTENSION](https://www.postgresql.org/docs/current/sql-createextension.html) |
| pgvector is the standard vector extension | Yes. It is installed on the server (package or build), then `CREATE EXTENSION vector` per database. Major managed services offer it (secondary source; confirm for your provider). HNSW indexes support up to 2,000 dimensions for `vector`. | [pgvector on PGXN](https://pgxn.org/dist/vector/), [Neon docs](https://neon.com/docs/extensions/pgvector.md), [Bytebase](https://www.bytebase.com/blog/pgvector/) |
| A self-hosted embedding server can speak one standard API | Yes. Hugging Face Text Embeddings Inference exposes the OpenAI embeddings API and has a CPU image; Ollama exposes `/v1/embeddings` (marked experimental). | [TEI quick tour](https://huggingface.co/docs/text-embeddings-inference/quick_tour), [Ollama OpenAI compatibility](https://docs.ollama.com/api/openai-compatibility) |
| Truncated model output must be detected | OpenAI's structured-output guarantee holds only if the response is not cut off (`finish_reason` is `length`). SCRS already reads the stop reason for all three protocols. | [OpenAI: structured outputs](https://openai.com/index/introducing-structured-outputs-in-the-api/) |
| Risks to design against | OWASP Top 10 for LLM Applications 2025 lists prompt injection (LLM01), sensitive information disclosure (LLM02), system prompt leakage (LLM07) and vector and embedding weaknesses (LLM08). A 2026 edition exists; check it for current numbering. | [OWASP GenAI Security Project](https://genai.owasp.org/2024/11/17/owasp-reveals-2025-top-10-risks-for-llms-new-sponsorship-program/) |
| Model context and output limits | **Not verified.** OpenAI's current model limits could not be retrieved, so no limit is assumed. Budgets are configurable and truncation is detected. | n/a |

## Decisions

- **Vector store: a portable connector, not a native extension.** Because a native extension cannot be layered over a plain connection, the knowledge layer needs nothing beyond standard PostgreSQL. Vectors are stored as bytes and searched exactly by cosine similarity after the database filters by asset, kind and embedding model. This works on any PostgreSQL, including managed servers. If your server has pgvector, a second backend can use it for HNSW; check with `SELECT name, default_version FROM pg_available_extensions WHERE name = 'vector';`. The portable store is exact and comfortable for the corpus of an asset (thousands to tens of thousands of chunks); the cap is `MaxCandidates` (default 50,000, newest first), and a search says when it was cut.
- **What may leave the platform: findings and advisory text only.** Prompts for the new enrichment work are built from typed, allowlisted fields (identifiers, titles, severities, package names and versions, advisory text), never from evidence, file contents or source. Everything is also screened by the guard.
- **Embeddings are self-hosted.** The embedding client talks only to an endpoint you run, through the same network guard as other outbound calls. No text is sent to a provider for embedding.
- **History is kept in PostgreSQL, outside retention.** Knowledge documents carry no foreign keys to assets, assessments or findings, so the retention jobs that prune closed findings do not delete the chronicle.

## Decision: where source code may go (amended 2026-11-16)

The first decision was a self-hosted code model only. A fixed monthly host (about $140 for a 16 GB machine) is a poor fit for staging and early production next to a pay-per-token provider, so the platform now supports both and lets you choose. The default is unchanged: **source code goes nowhere but your own model server until you opt in.**

"Self-hosted" is still a rule the code checks: a provider is `local` when its host is listed in `SCRS_LLM_PRIVATE_HOSTS`; anything else is `hosted`. What each may be sent:

| | Findings and advisory text (summaries, advisories) | Source code (AI code review, unit-test generation) |
| --- | --- | --- |
| `local` | Yes | Yes, always |
| `hosted` | Yes | Only after **both** opt-ins below |

The two opt-ins for a hosted provider:
1. **Platform switch:** `SCRS_LLM_ALLOW_SOURCE_TO_HOSTED=true` on the API and the worker. Off by default.
2. **Acknowledgement of that provider:** `POST /llm/providers/{id}:allow-source` with a `note` (why this provider may see source, for example the agreement that covers it), or `SCRS_LLM_PROVIDER_<NAME>_ALLOW_SOURCE=true` for a provider declared in the environment (recorded as acknowledged by `environment`). It is audited (`llm_provider.source_allowed`), shown on the provider (`source_ack_by`, `source_ack_at`, `source_ack_note`) and withdrawn automatically when the provider's `kind` or `base_url` changes, or by `POST /llm/providers/{id}:revoke-source`.

`GET /llm/providers` reports the outcome as `source_allowed`. It is checked when a review or unit-test generation is requested and again in the worker, so withdrawing the acknowledgement, or switching the platform switch off, stops a queued job before any source is fetched. Each review records where its source went (`locality`).

What stays on for every provider: the guard (secrets are redacted from every prompt and answer), the directory skip list, the file-size cap and the token budgets. Before opting in, prefer a provider with zero-retention terms; the guard is a safety net, not a guarantee, and source code is more sensitive than findings.

API-test generation sends only the OpenAPI document and is unchanged. The advisory and summary allowlist never includes code, whichever provider is used.

## Providers from the environment

A hosted and a self-hosted provider can be declared in the container's environment and exist when the API starts, with no API call. `SCRS_LLM_PROVIDERS` lists names; each name `N` (upper-cased, `-` as `_`) is described by `SCRS_LLM_PROVIDER_N_KIND`, `_MODEL`, `_BASE_URL`, `_API_KEY`, `_MAX_TOKENS`, `_TEMPERATURE` and `_ALLOW_SOURCE`. The Dokploy compose file passes the names `hosted` and `local`:

```
SCRS_LLM_PROVIDERS=hosted,local
SCRS_LLM_PROVIDER_HOSTED_KIND=openai
SCRS_LLM_PROVIDER_HOSTED_MODEL=<model>
SCRS_LLM_PROVIDER_HOSTED_API_KEY=<key>
SCRS_LLM_PROVIDER_LOCAL_KIND=openai_compatible
SCRS_LLM_PROVIDER_LOCAL_BASE_URL=https://model.example.com/v1
SCRS_LLM_PROVIDER_LOCAL_MODEL=qwen2.5-coder-7b
SCRS_LLM_PROVIDER_LOCAL_API_KEY=<SCRS_MODEL_API_KEY>
SCRS_LLM_PRIVATE_HOSTS=model.example.com
```

- It is idempotent: a restart that changes nothing writes nothing; a changed declaration (model, URL, key) updates the provider and bumps its revision.
- Keys are sealed with `SCRS_MASTER_KEY` like any provider key and never logged. A bad declaration is logged without its values and skipped; the API still starts.
- The environment owns these providers (`managed_by_environment: true`): the API changes only `enabled` (an administrator's switch is kept across restarts) and refuses delete. A provider an administrator made through the API with the same name is never overwritten (an error is logged).
- Other names need their variables added to the compose file's API service (it cannot pass a wildcard).

## Cost control for hosted providers

A pay-per-token bill needs a ceiling. Besides the per-assessment budget, every **hosted** provider has a monthly cap across all its work (summaries, advisories, code review and test generation): `SCRS_LLM_MONTHLY_INPUT_TOKENS` (default 20,000,000) and `SCRS_LLM_MONTHLY_OUTPUT_TOKENS` (default 4,000,000), per calendar month in UTC, `0` to remove a cap. The defaults are a safety ceiling, not a forecast: set them from what you intend to spend. When a cap is reached, work stops with a message that names it (`incomplete` or `error`) and resumes next month or when you raise it. A self-hosted provider has no cap. Usage comes from the `llm_usage` ledger by provider name; test generation checks the cap once per run and adds what it used afterwards. Money is not computed: token prices differ by provider and change, so convert with your provider's current price list.

## Built

**Guard** (`internal/llm/guard`, always on inside `internal/llm.Client`):
- Screens every prompt before it is sent and every answer before it is returned. It cannot be switched off.
- Detects private keys, AWS, GitHub, GitLab, Slack, OpenAI, Anthropic, Google, Stripe, npm, SendGrid, Twilio, SCRS and Dependency-Track tokens, JWTs, bearer tokens, URLs with credentials, secret-looking assignments (`password=…`), and long high-entropy strings (leaving digests, UUIDs and lockfile hashes alone).
- Redacts the exact value of every secret this process holds (environment variables with names such as KEY, SECRET, TOKEN, PASSWORD, DATABASE_URL, plus the provider key in use, and their base64 forms).
- On output, also removes images, scripts and other dangerous markup, links with query strings or fragments, and invisible and bidirectional control characters.
- Reports counts by kind in the response (`redactions.input` and `redactions.output`), never values.
- `Untrusted` and `DataRule` wrap repository and advisory text as data in a prompt.
- Limits: it is pattern-based. It is strong for known formats and your own secrets and weaker for an arbitrary string, which is why prompts are built from allowlisted fields first. It cannot prove that no secret is present and it cannot stop prompt injection; it removes the channels injection would use to send data out.

**Client:** structured output (`response_format` with a strict JSON Schema) for OpenAI and Azure OpenAI; truncation reported for all providers.

**Embeddings** (`internal/embed`): OpenAI-compatible client for a self-hosted server; screens text, batches, retries transient errors, checks the dimension, normalises vectors, refuses empty or over-long text instead of truncating it silently. Settings: `SCRS_EMBED_URL`, `SCRS_EMBED_MODEL`, `SCRS_EMBED_DIM`, `SCRS_EMBED_API_KEY`.

**Knowledge store** (`internal/knowledge`, tables created by `scrs-storage-init`):
- `knowledge_documents` (advisories, summaries, chronicles, QA summaries, code reviews, reports) with kind, asset, assessment, finding, ref, provenance (model, prompt version, input hash, redaction counts) and a supersession chain; `knowledge_chunks` with the embedding model, dimension and vector.
- `AddDocument`, `AddChunks`, `Search` (exact cosine, scoped by asset, kind, finding and model), `Chronicle` (an asset's documents oldest first, with what replaced what), and `Split`.
- All text is screened again before it is stored.
- `llm_usage` ledger and `Reserve`: a ceiling per assessment on input and output tokens (`SCRS_LLM_ASSESSMENT_INPUT_TOKENS`, default 300,000; `SCRS_LLM_ASSESSMENT_OUTPUT_TOKENS`, default 60,000). It limits spend; it is not the size of one answer. An answer cut off at the provider's `max_tokens` is reported as truncated and must never be stored as complete.

**AI code review** (`internal/review`, `ai_reviews`, worker job):
- Files are chosen and ranked, sent one per call with line numbers and wrapped as untrusted data, and answered in a JSON schema that is validated (unknown categories and out-of-range lines are dropped).
- Results are report-only `ai_review` register entries marked `unverified`, closed when a later review of the same files no longer reports them, with their history in the finding events.
- Each call is checked against the assessment's token budget and recorded in the `llm_usage` ledger (with what the guard removed). A cut-off answer is never counted as a review of that file.
- Each review writes a summary document (titles, files and lines, never code) to the asset's chronicle in the knowledge store.
- API: `POST` and `GET /assets/{id}/ai-reviews`, `GET /ai-reviews/{id}`; documented in the OpenAPI contract with the data policy.

**Advisories and summaries** (`internal/summarize`, `ai_summaries`, worker job):
- The model is shown only the allowlist (`summarize.Finding`): identifiers, titles, severities, package, versions, fixed versions and upstream advisory text, with untrusted text wrapped as data. Findings of the types SAST, secret, AI review, malware, YARA, IOC, QA and posture are counted and never described, so any provider may be used.
- One summary call and advisories a few findings to a call, each with a JSON schema; answers are validated (finding IDs must be ones that were sent, links are removed, lengths bounded). A cut-off answer is retried smaller, never stored as complete.
- Results are chronicle documents (`origin: llm`, with provenance) that supersede the previous summary of the asset or the previous advisory of the same finding; the previous summary is given to the model so it can describe progress.
- When `scrs-embed` is configured, each text is split into chunks of about 1,000 characters, embedded by the self-hosted model and stored in `knowledge_chunks`; if embedding is unavailable the document is stored without vectors.
- API: `POST` and `GET /assessments/{id}/summaries`, `GET /summary-jobs/{id}`, `GET /assets/{id}/chronicle`.

**Deployment:** `scrs-embed` (TEI CPU) in the main stack and `compose.model-host.yaml` for the second machine; see [MODEL_HOST.md](MODEL_HOST.md).

**Chronicle search and backfill.** `GET /assets/{id}/chronicle/search?q=` embeds the question with the same self-hosted server (so the API container joins the internal `embed` network and holds `SCRS_EMBED_*`), compares it with the asset's stored chunks by cosine similarity and returns the nearest chunks with their document and score; `unindexed_documents` says how many documents have no vectors yet. `POST /knowledge:backfill` (admin) embeds those, `limit` documents per call, until `remaining` is 0. Both answer 503 without an embedding server.

**Summaries in reports.** A report requested with `params.include_ai_summaries: true` adds each asset's newest assessment summary to the json, Markdown and PDF output under an "AI-written summaries (unverified)" heading with a notice; it changes no count, mapping or gap, and csv is unchanged.

Real linters run in the QA runner as a lint job kind ([QA_TESTING.md](QA_TESTING.md#lint)), and the review shows the model a file's lint findings next to its static-analysis findings. Not yet built: automatic backfill on a schedule. QA test generation gets the guard automatically because it uses the client.

## Next

1. **Orchestrator:** a worker job per completed assessment that builds allowlisted prompts, checks the budget, calls the model, validates the answer against a JSON Schema, screens it, stores it with provenance and embeds it. A truncated answer is split and retried (map-reduce over findings) instead of kept.
2. **Advisory enrichment and report text:** per-finding advisories and per-assessment and per-asset summaries stored first, then rendered into the PDF so reports stay deterministic.
3. **API:** read the chronicle and search per asset; trigger or regenerate; scopes and OpenAPI as for the rest of the contract.
4. **Session memory:** conversation state for an analyst asking questions about an asset, stored in PostgreSQL with the same screening and retention, and retrieval from the knowledge store.
6. ~~Real linters in the QA runner~~ Delivered 2026-11-17 (lint job kind with ruff in the image; mypy, bandit, pylint, PHPStan, phpcs, clang-tidy, golangci-lint, ESLint, ktlint, SwiftLint and dart analyze in the lint image), with AI triage of QA results ([QA_TESTING.md](QA_TESTING.md#ai-triage-of-qa-results)).
   - The AI review is already stored as `ai_review` entries; the merge adds linter results beside them under one asset view.
7. **pgvector backend**, if your server has it.

**Static analysis in the review.** Each file's prompt now lists what the static analyzers (gosec, Bandit, OpenGrep, Bearer) already reported for it in the assessment under review (up to 15 notes, most severe first, skipping lines suppressed in code), inside an untrusted-data block, with the instruction not to repeat them and to look for what they missed. They are the linters this stack has; running dedicated linters (ESLint, Ruff, golangci-lint) in the QA runner remains unbuilt.

## Data policy, screening and budgets (API reference)

This is the full text behind the short **LLM providers**, **Advisories and summaries** and **AI review** sections of the API contract.

**Where code may go.** Each provider has a read-only `locality`: `local` is a model server you run (its host is in `SCRS_LLM_PRIVATE_HOSTS`), `hosted` is any other. `source_allowed` says whether it may be sent **source code** (AI review, unit-test generation). A `local` provider always may. A `hosted` provider may only after the platform switch `SCRS_LLM_ALLOW_SOURCE_TO_HOSTED=true` is on and an administrator has called `POST /llm/providers/{id}:allow-source` with a `note` that records why; `:revoke-source` withdraws it, and so does changing the provider's `base_url`. Both steps are audited. Summaries and advisories need neither: the model sees only finding IDs, titles, severities, package names and versions, fixed versions and upstream advisory text, never code, evidence, file paths, secrets or AI review entries.

**Declared in the environment.** Providers can be declared at deploy time (`SCRS_LLM_PROVIDERS`, `SCRS_LLM_PROVIDER_<NAME>_*`). They show `managed_by_environment: true`; an administrator can only enable or disable them through the API.

**Screening and trust.** Every prompt and answer passes a guard that redacts credentials, keys, tokens and the platform's own secrets and removes images, scripts and tracking links from answers. It is a safety net, not a guarantee. Model output is not verified: findings are report-only `ai_review` entries marked `unverified` and never change a verdict.

**Budget.** Model work stops at the assessment's token ceiling (`SCRS_LLM_ASSESSMENT_INPUT_TOKENS`, `SCRS_LLM_ASSESSMENT_OUTPUT_TOKENS`) and says so in `incomplete`. A hosted provider, billed per token, also has a monthly cap across all its work (`SCRS_LLM_MONTHLY_INPUT_TOKENS`, `SCRS_LLM_MONTHLY_OUTPUT_TOKENS`, calendar month UTC); work resumes next month or when you raise it. A self-hosted provider has no cap. An answer cut off at the provider's `max_tokens` does not count as a review of that file.

**The chronicle.** `GET /assets/{id}/chronicle` is the history of an asset's written advisories, summaries and reviews, oldest first. A new summary or advisory supersedes the one before it: the old one is kept, marked with `superseded_at`, and the new one names it in `supersedes`. Every document has `origin: llm` when a model wrote it and a `provenance` (model, provider, prompt version, what the guard removed).

**What is described.** Vulnerabilities (SCRS's own and Dependency-Track's), malicious dependencies, licence, integrity and configuration findings. Not described, only counted: code analysis (SAST), secret detection, AI code review entries, malware, YARA and IOC matches, QA entries.
