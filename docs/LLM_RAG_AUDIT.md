# LLM and RAG audit (2026-11-16)

Scope: the LLM inference integration, and what the platform needs around it to enhance advisories, produce per-assessment and per-asset reports, add QA (performance, lint) and production-risk analysis, and keep a persisted, searchable history of risks as they are treated and reassessed.

## Corrections and progress (2026-11-16)

The first version of this audit had two errors, corrected here, and several gaps have since been closed.

- **Truncation:** the client already reports truncated answers for all three protocols (`Response.Truncated`), and QA generation reads it. L2 is only about structured output.
- **Consent:** QA profiles already carry `allow_source_upload` (default false) for unit-test generation. There is still no consent or budget for sending findings and advisory text, which is the new use.
- **L1, L2 closed in part:** structured output (strict JSON Schema) for OpenAI and Azure OpenAI is in the client. A self-hosted embedding client exists (`internal/embed`); there is no provider embedding call by design.
- **L3 closed:** an always-on guard in the client screens every prompt and answer for credentials and the process's own secrets.
- **L4 closed in part:** a usage ledger and per-assessment budget exist; nothing calls them yet.
- **P4 closed in part:** a portable vector store on standard PostgreSQL exists, with no extension needed.
- **P5, P7, P8 closed in part:** `knowledge_documents` and `knowledge_chunks` keep provenance, the supersession chain and the embedding model and dimension, outside retention.
- **P3 closed in part:** AI code review runs on a self-hosted model (your decision) and stores `ai_review` entries; real linters in the QA runner are still to do.
- **P1 closed:** advisory enrichment and assessment summaries exist (allowlisted prompts, chronicle, provenance).
- **P6 closed in part:** model text is stored as plain text with a notice, links are removed, and the guard screens output; rendering into reports is still to do.
- **Open:** P2 (per-assessment and per-asset report text in the PDF), P6 rendering (advisory enrichment, report text, lint and code review, the rendering rules for model text). See [LLM_KNOWLEDGE.md](LLM_KNOWLEDGE.md).

## What was audited

**The module described as newly added is not in this repository.** The working tree has only the Dependency-Track changes, there is no other local branch (`lionel.dev`, `master`), no stash, and no ignored or untracked LLM files. The only LLM code is `internal/llm`, the ADR-022 adapter, which pre-dates this request. This audit covers that adapter and the platform around it. If your module lives on another machine or branch, push it and the audit should be repeated against it: findings L1 to L4 may already be solved there.

## What exists

| Part | State |
| --- | --- |
| `internal/llm` | One client over three wire protocols (OpenAI chat completions and compatible gateways, Anthropic Messages, Gemini). Per-provider key (sealed) and URL, netguard dialer, retries with backoff, token counts returned. OpenAI is a preset. |
| Use | Only E2E QA test generation (`worker/qagen.go`: Karate API tests, unit tests) and an admin connectivity check. Output is untrusted: static checks and approval before anything runs. |
| Persistence | `llm_providers`, `qa_generations` (with `input_tokens` and `output_tokens`), `qa_suites`. |
| Advisory data | `advisory_records` (OSV, NVD, CVE.org records as JSON) and, on each finding, a fixed `guidance` object with aliases, fixed versions and a template sentence. |
| Reports | Deterministic framework evidence reports (OWASP Top 10, CWE, PCI DSS, STIG) as JSON, CSV, Markdown or built-in PDF (ADR-032: the same inputs always give the same bytes). Scopes: `portfolio`, `asset`, `owner`. |
| History | `finding_events` (detected, status changes, fixed, corroborated), `assessment_findings` snapshots, each assessment's `diff`, `qa_runs`, VEX. |
| QA | Karate functional and Gatling performance runs. |

## Gaps

### In the adapter (L)

| # | Severity | Gap |
| --- | --- | --- |
| L1 | High | **No embeddings.** `Request` is a system and a user message and the client has one method, `Complete`. There is no `/embeddings` call. OpenAI offers one; Anthropic does not, so a RAG corpus needs an embedding provider that may differ from the chat provider. |
| L2 | Medium | **Free text only.** No JSON schema or structured output, no tool calling, no streaming. Advisory and bug-risk output needs a validated shape, or it cannot be stored, ranked or rendered reliably. |
| L3 | High | **No content filter before the prompt.** QA generation sends repository source files to the provider. The only filter is a directory skip list (`node_modules`, `testdata`, `generated` and similar). Nothing removes secrets, keys or `.env` content from file text. This is a live data-exposure risk in the feature that exists today. |
| L4 | Medium | **No egress consent or budget.** Sending code or findings to a hosted model is a data-sharing decision. Webhook subscriptions record an `egress_ack`; LLM providers have no such flag. Token counts exist only per QA generation: no ledger by purpose, no cap, no cost. |

### In the platform (P)

| # | Severity | Gap |
| --- | --- | --- |
| P1 | High | **Advisory enhancement does not exist.** `guidance` is a template and `advisory_records` is raw upstream data. Nothing summarises, explains for this codebase or recommends a fix, and there is no table to keep generated advisories, their inputs or the model that wrote them. |
| P2 | High | **No per-assessment report, and no narrative.** Reports are framework evidence by scope. An assessment-level report and any model-written summary are missing. Adding model text to the PDF writer would break its byte-for-byte determinism unless the text is stored first, versioned, and the report built from the stored text. |
| P3 | Medium | **No lint and no production-risk analysis.** QA runs functional and performance only (no lint job kind). Nothing reads code for "what can break in production" (unhandled errors, missing timeouts, retries without limits, race conditions). SAST is rule-based. This would be a new, report-only analysis of unverified model output. |
| P4 | High | **No vector store.** No `pgvector`, no `CREATE EXTENSION` anywhere, no embeddings table. PostgreSQL is external to the stack, so whether the extension can be installed depends on your server. The tests use `postgres:16-alpine`, which does not include it. |
| P5 | Medium | **The history is raw, not a chronicle.** The events are good source material, but nothing joins them per vulnerability into a readable timeline (found, advised, triaged, fixed, reappeared). With a retention class for closed findings set, `closed_findings` deletes them together with their history. It is off by default (`SCRS_RETENTION_DEFAULT_CLOSED_FINDINGS_DAYS` empty), so the corpus must keep its own copy, with its own retention. |
| P6 | Medium | **Untrusted text reaches the model.** Code, comments, READMEs and upstream advisory text can carry instructions. Today the output is guarded by static checks and approval; model-written advisories shown to people or printed in PDFs have no equivalent, and nothing marks them as AI-generated or checks links and markup. |
| P7 | Medium | **No provenance.** A stored generation needs the model, a prompt version, an input hash and the source ids (finding, advisory, assessment), so a statement can be traced and regenerated. `qa_generations` records provider and model only. |
| P8 | Low | **Embedding lifecycle.** Vectors need the model name, dimension and a version, and a way to re-embed when the model changes. |

## Fix now

These are the gaps that make an LLM feature unsafe or unusable if built on top of the current state. Do them before anything else:

1. **L3, filter secrets from prompts.** Reuse the scanner's secret detection (`internal/scanner/content.go`) on every file and finding text before it is sent; drop the file when a secret is found. Add a test that a planted key never reaches the fake provider. This also protects the QA generation that exists today.
2. **L4, provider consent and a usage ledger.** An `egress_ack` on each provider (required to send repository content), and one `llm_usage` table (purpose, provider, model, input and output tokens, time) with a daily cap per purpose. A model failure must never fail an assessment; reuse the leased queue pattern of `qa_generations`.
3. **L1 and L2, extend the client:** an `Embed` call and JSON-schema output for OpenAI-compatible providers, with the response validated before storage.
4. **P4, decide the vector store** (decision below), then add the embeddings table with model, dimension and version.
5. **P7 and P6, a `generated_advisories` table** (finding or advisory id, assessment id, model, prompt version, input hash, text, status) with output always labelled AI-generated and rendered as plain text.

Then build, in this order: **P1** advisory enhancement, **P2** per-assessment and per-asset report text stored before rendering, **P5** the per-vulnerability chronicle and its retention, **P3** production-risk analysis and a lint job kind.

## Decisions needed

- **Vector store.** Install `pgvector` on your PostgreSQL (a `CREATE EXTENSION vector` in `scrs-storage-init`, which already has the admin URL), or store embeddings as arrays and compare in the application. The extension is the right answer beyond a few thousand rows; arrays need no server change. This audit assumes pgvector.
- **What may leave the platform.** Findings and advisory text, or also repository source? The second is what L3 protects; it needs your explicit approval per provider.
- **Embedding provider.** OpenAI embeddings, or a self-hosted model (Ollama, vLLM) reachable through `SCRS_LLM_PRIVATE_HOSTS`.
- **Lint and production-risk analysis.** Model-reviewed code (report-only, unverified), real linters run by the QA runner, or both. They need different work: the first is a prompt and a schema, the second is a new runner job kind.
