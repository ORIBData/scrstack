# Model providers, self-hosted embeddings and the model host

## Choose where the model runs

The adapter supports a hosted provider (pay per token) and a self-hosted model server side by side. Pick per purpose:

| | Hosted OpenAI-compatible provider | Self-hosted model host (`compose.model-host.yaml`) |
| --- | --- | --- |
| Cost | Per token; no idle cost. Capped monthly by `SCRS_LLM_MONTHLY_*` | A fixed monthly machine (about $140 for 16 GB, as you priced it) |
| Speed and quality | Fast; frontier-class models | A 4-bit 7B on CPU takes minutes per file and reviews code more shallowly |
| Summaries and advisories | Yes (findings and advisory text only) | Yes |
| Code review, unit tests (source code) | Only after the two opt-ins (`SCRS_LLM_ALLOW_SOURCE_TO_HOSTED=true` and `POST /llm/providers/{id}:allow-source`) | Always allowed |
| Where data goes | To the provider | Stays on your hardware |

**Staging and early production:** use a hosted provider and no second machine. **Customers whose source must not leave their hardware:** deploy the model host and register it as a `local` provider. You can run both at once (`SCRS_LLM_PROVIDERS=hosted,local`) and pick per request with `provider_id`. Embeddings (`scrs-embed`) stay on the SCRS machine in both cases, so no text goes to a provider for embedding.

### A hosted provider, from the environment

On the SCRS stack (API service), set:

| Variable | Value |
| --- | --- |
| `SCRS_LLM_PROVIDERS` | `hosted` (or `hosted,local`) |
| `SCRS_LLM_PROVIDER_HOSTED_KIND` | `openai`, `anthropic`, `gemini`, `mistral`, `groq`, `deepseek`, `xai`, `openrouter`, `together`, `azure_openai` or `openai_compatible` |
| `SCRS_LLM_PROVIDER_HOSTED_MODEL` | The provider's model or deployment name |
| `SCRS_LLM_PROVIDER_HOSTED_BASE_URL` | Only for a gateway, regional endpoint or Azure resource; the kind has a default |
| `SCRS_LLM_PROVIDER_HOSTED_API_KEY` | The provider's key (sealed in the database at start; never logged) |
| `SCRS_LLM_PROVIDER_HOSTED_MAX_TOKENS` | Largest answer (default 8192). Raise it for code review so answers are not cut off |
| `SCRS_LLM_MONTHLY_INPUT_TOKENS`, `SCRS_LLM_MONTHLY_OUTPUT_TOKENS` | Monthly cap for this provider (worker; defaults 20,000,000 and 4,000,000; `0` removes a cap) |

Redeploy; the provider exists when the API starts (`GET /llm/providers`, `managed_by_environment: true`). Check it with `POST /llm/providers/{id}:test`. To let it review code, set `SCRS_LLM_ALLOW_SOURCE_TO_HOSTED=true` on the API **and** the worker, then acknowledge it: `POST /llm/providers/{id}:allow-source` with `{"note":"<why, for example the agreement that covers it>"}`. `source_allowed` turns true. Prefer a provider with zero-retention terms. Rotate its key by changing `SCRS_LLM_PROVIDER_HOSTED_API_KEY` and redeploying.

Token prices change and differ by provider, so SCRS caps tokens, not money: convert the cap with your provider's current price list.

### The model host, from the environment

After section 2, declare it too: `SCRS_LLM_PROVIDER_LOCAL_KIND=openai_compatible`, `SCRS_LLM_PROVIDER_LOCAL_BASE_URL=https://model.example.com/v1`, `SCRS_LLM_PROVIDER_LOCAL_MODEL=qwen2.5-coder-7b`, `SCRS_LLM_PROVIDER_LOCAL_API_KEY=<SCRS_MODEL_API_KEY>`, add the name to `SCRS_LLM_PROVIDERS`, and put `model.example.com` in `SCRS_LLM_PRIVATE_HOSTS` (API and worker). It shows `locality: local` and `source_allowed: true` with no further step.

## Services

SCRS uses two optional self-hosted services:

| Service | Where | Purpose | Image |
| --- | --- | --- | --- |
| `scrs-embed` | the SCRS stack (`deploy/compose.dokploy.yaml`) | Text embeddings for the chronicle's search | Hugging Face Text Embeddings Inference, CPU |
| `scrs-model` | a second machine (`deploy/compose.model-host.yaml`), optional | Reads source code for AI code review and unit-test generation when the code must stay on your hardware | llama.cpp server |

What was checked and what was not: both images exist and are pinned by digest; their flags and environment variables were confirmed with `--help` on the pinned images; both model repositories exist, are ungated and licensed Apache-2.0 (Qwen2.5-Coder-7B-Instruct-GGUF) and MIT (bge-small-en-v1.5); both compose files render with `docker compose config`. **They were not run end to end here**, so the first start on your machines is the real test.

## 1. Embeddings on the SCRS machine

`scrs-embed` runs `BAAI/bge-small-en-v1.5` (33M parameters, 384 dimensions, a 512-token window) on CPU, limited to 2 GB and 2 cores. It is on an internal network: only the worker reaches it, with an API key.

1. In Dokploy, set `SCRS_EMBED_API_KEY` (`openssl rand -hex 32`). The other settings have working defaults: `SCRS_EMBED_URL=http://scrs-embed:80/v1`, `SCRS_EMBED_MODEL=BAAI/bge-small-en-v1.5`, `SCRS_EMBED_DIM=384`, `SCRS_EMBED_MAX_CHARS=1500`, `SCRS_EMBED_PRIVATE_HOSTS=scrs-embed`.
2. Deploy. The first start downloads the model (about 130 MB) into the `scrs-embed-models` volume; that is why the service is also on the `embed-fetch` network. Wait for the service to be healthy.
3. Check it from inside the container (Dokploy terminal):
   ```bash
   curl -s -H "Authorization: Bearer $API_KEY" -H 'Content-Type: application/json' \
     -d '{"model":"x","input":["hello"]}' http://127.0.0.1:80/v1/embeddings | head -c 200
   ```
   You should see `"embedding":[` with 384 numbers.
4. Once the model is cached, remove `embed-fetch` from the service's `networks` and redeploy, so the service has no route out.

Notes:
- `AUTO_TRUNCATE` is off. A text longer than the model's window is an error, not silently cut. SCRS keeps chunks to 1,000 characters (limit 1,500), inside the 512-token window.
- Do not use `nomic-embed-text` with this TEI version: a published benchmark reports TEI 1.9 cannot load it.
- If `SCRS_EMBED_URL` is empty the worker skips embedding; documents are still stored and can be indexed later.

## 2. The model host (second machine)

### What it is and why llama.cpp

A 16 GB CPU machine runs a 4-bit 7B code model through llama.cpp's OpenAI-compatible server. This replaces vLLM for this machine, for facts you can check:
- vLLM's CPU build serves a 7B model in bf16, about 14 GB of weights, more than a 16 GB machine can spare. Its CPU image needs AVX-512 (an AVX2 fallback is "not recommended" in its documentation), and GGUF is not supported on x86 CPU.
- llama.cpp runs the 4-bit GGUF (about 5 GB) on ordinary AVX2 CPUs.
- vLLM's `--api-key` protects only the `/v1` routes, and its own security page says not to rely on it alone. The compose file routes only `/v1` for the same reason.

Use vLLM when the machine has a GPU. Then serve the model with `vllm serve <model> --api-key "$KEY"`, keep the same Traefik labels (only `PathPrefix(/v1)`, with the IP allowlist), and add the host to `SCRS_LLM_PRIVATE_HOSTS` exactly as below.

### Protection

1. TLS: Traefik issues and renews a Let's Encrypt certificate; plain http redirects to https.
2. Routing: only `/v1`. The server's other endpoints (`/props`, `/slots`, `/metrics`, `/health`) are never routed, and the slots endpoint is also switched off in the server.
3. Source address: an IP allowlist admits only the SCRS machine (`SCRS_MODEL_ALLOWED_CIDRS`). The default admits nobody. If Dokploy's Traefik sits behind another proxy (a CDN), the client address Traefik sees is the proxy's; use that proxy's address range or Traefik's `ipstrategy` settings, and rely on the key meanwhile.
4. API key: the server requires `SCRS_MODEL_API_KEY` as a bearer token. The server accepts several keys separated by commas, so you can rotate without downtime (see Operations).
5. Limits: Traefik rate-limits each client (`SCRS_MODEL_RATE_PER_SECOND`, default 5, burst `SCRS_MODEL_RATE_BURST`, default 10) and caps the request body (`SCRS_MODEL_MAX_BODY_BYTES`, default 4 MiB) before the server sees it.

### Set up

1. Machine: 16 GB RAM, 4 or more cores (8 is better), about 10 GB of disk for the model, Dokploy with Traefik and a `letsencrypt` certificate resolver, and a DNS record for the model's hostname pointing at it.
2. In Dokploy, create a Compose application from `deploy/compose.model-host.yaml` with this environment:
   | Variable | Value |
   | --- | --- |
   | `SCRS_MODEL_DOMAIN` | The hostname, such as `model.example.com` |
   | `SCRS_MODEL_API_KEY` | `openssl rand -hex 32` |
   | `SCRS_MODEL_ALLOWED_CIDRS` | The SCRS machine's public IP, such as `203.0.113.10/32` |
   | `SCRS_MODEL_THREADS` | Physical cores minus one or two (default 6) |
   | `SCRS_MODEL_CTX` | Context in tokens (default 32768; about 2 GB of memory) |
   | `SCRS_MODEL_HF_REPO` | Default `Qwen/Qwen2.5-Coder-7B-Instruct-GGUF:Q4_K_M` |
   | `SCRS_MODEL_MEMORY` | Container limit (default `11g`) |
   | `SCRS_MODEL_RATE_PER_SECOND`, `SCRS_MODEL_RATE_BURST`, `SCRS_MODEL_MAX_BODY_BYTES` | Traefik limits (defaults 5, 10, 4194304) |
   | `SCRS_TRAEFIK_NETWORK`, `SCRS_CERT_RESOLVER`, `SCRS_HTTPS_ENTRYPOINT`, `SCRS_HTTP_ENTRYPOINT` | Only if your Dokploy differs from the defaults (`dokploy-network`, `letsencrypt`, `websecure`, `web`) |
3. Deploy. The first start downloads about 5 GB and the health check allows 15 minutes.
4. Check it from the SCRS machine (an allowed address), which does not print the key:
   ```bash
   SCRS_MODEL_DOMAIN=model.example.com SCRS_MODEL_API_KEY=... SCRS_MODEL_NAME=qwen2.5-coder-7b \
     bash scripts/check_model_host.sh --chat
   ```
   It checks the certificate, the http redirect, that the key is required and accepted, that `/props`, `/slots`, `/metrics`, `/health` and `/` are not routed, and (with `--chat`) one small completion and how long it took. From any other address you should get `403` (allowlist). If the certificate check fails, wait for Traefik to issue it (the DNS record must point at the machine and ports 80 and 443 must be open) and check Traefik's logs.
5. On the SCRS stack:
   1. Add the hostname to `SCRS_LLM_PRIVATE_HOSTS` (API and worker). This declares the machine as yours, so it is `local` and always may receive source code. Never add a hosted provider's hostname.
   2. For a CPU model, set `SCRS_LLM_TIMEOUT_SECONDS=900` and lower `SCRS_AI_REVIEW_MAX_FILE_BYTES` (for example `24576`) so a file fits the context and the time limit. Redeploy.
   3. Register it, either from the environment (see "The model host, from the environment" above) or with `POST /llm/providers` with `{"name":"model-host","kind":"openai_compatible","base_url":"https://model.example.com/v1","model":"qwen2.5-coder-7b","max_tokens":4096,"api_key":"<SCRS_MODEL_API_KEY>"}`. The response must show `"locality":"local"`. `POST /llm/providers/{id}:test` checks the connection.
6. Run a review: `POST /assets/{id}/ai-reviews` with that `provider_id`.

### Expectations on CPU (estimates, not measurements)

- One request at a time (`LLAMA_ARG_N_PARALLEL=1`): parallel slots only slow each other down on CPU.
- A few thousand tokens in and a few hundred out takes minutes per file on 8 cores with a 7B model. Treat review as a nightly batch of `max_files` 5 to 10, not an interactive feature.
- Quality: a 7B model catches obvious lint and some logic errors; its production-risk reasoning is shallower than a frontier model's. Entries are marked unverified for that reason.
- Measure before relying on it: time one review and adjust `SCRS_MODEL_THREADS`, `max_files` and `SCRS_AI_REVIEW_MAX_FILE_BYTES`.

### Operations

- Upgrade: change the image digest in the compose file after testing; the model stays in the `scrs-model-cache` volume.
- Rotate the key without downtime: set `SCRS_MODEL_API_KEY` to `old,new` and redeploy the model host; change SCRS to the new key (`SCRS_LLM_PROVIDER_LOCAL_API_KEY`, or `PATCH /llm/providers/{id}` with `api_key`) and redeploy; then set `SCRS_MODEL_API_KEY` to `new` and redeploy. `scripts/check_model_host.sh` uses the first key in the list.
- Long requests: a CPU model sends nothing until it finishes, which can take minutes. The server's own timeout is 900 seconds here. If your Traefik entrypoint sets `respondingTimeouts`, make sure they are longer than that (not verified against your Dokploy's Traefik configuration).
- Logs show request timing; the server does not log prompts by default.
