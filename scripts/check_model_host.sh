#!/usr/bin/env bash
# Checks a deployed model host (deploy/compose.model-host.yaml) from the machine
# that should be allowed to use it: TLS, the http redirect, the API key, and
# that nothing but /v1 is reachable. Reads SCRS_MODEL_DOMAIN and
# SCRS_MODEL_API_KEY from the environment; the key is never printed or put on a
# command line. Add --chat to send one small completion (uses the model).
set -uo pipefail
: "${SCRS_MODEL_DOMAIN:?Set SCRS_MODEL_DOMAIN to the DNS name of the model host}"
: "${SCRS_MODEL_API_KEY:?Set SCRS_MODEL_API_KEY to the key the server requires}"
key="${SCRS_MODEL_API_KEY%%,*}"
base="https://${SCRS_MODEL_DOMAIN}"
dir="$(mktemp -d)"
trap 'rm -rf "$dir"' EXIT
chmod 700 "$dir"
(umask 077; printf 'Authorization: Bearer %s\n' "$key" > "$dir/auth")
failed=0
check() { # description, expected status, curl args...
  local description="$1" want="$2" got
  shift 2
  got="$(curl -sS -o "$dir/body" -w '%{http_code}' --max-time 30 "$@" 2>"$dir/err")" || got="error"
  if [[ "$got" == "$want" ]]; then
    printf 'ok    %s (%s)\n' "$description" "$got"
  else
    printf 'FAIL  %s: got %s, want %s %s\n' "$description" "$got" "$want" "$(head -c 200 "$dir/err")"
    failed=1
  fi
}
check "TLS certificate is valid (no -k)" 401 "$base/v1/models"
check "plain http redirects to https" 308 --max-redirs 0 "http://${SCRS_MODEL_DOMAIN}/v1/models"
check "the API key is required" 401 "$base/v1/models"
check "the API key is accepted" 200 -H "@$dir/auth" "$base/v1/models"
if [[ -n "${SCRS_MODEL_NAME:-}" ]] && ! grep -q "$SCRS_MODEL_NAME" "$dir/body" 2>/dev/null; then
  # $dir/body now holds the last response (the key check), which lists the model.
  printf 'FAIL  the model list does not mention %s\n' "$SCRS_MODEL_NAME"; failed=1
fi
for path in /props /slots /metrics /health /; do
  check "$path is not routed" 404 -H "@$dir/auth" "$base$path"
done
if [[ "${1:-}" == "--chat" ]]; then
  model="${SCRS_MODEL_NAME:-qwen2.5-coder-7b}"
  started=$(date +%s)
  check "a small completion works" 200 --max-time 600 -H "@$dir/auth" -H 'Content-Type: application/json' \
    -d "{\"model\":\"$model\",\"max_tokens\":8,\"messages\":[{\"role\":\"user\",\"content\":\"Reply with OK.\"}]}" "$base/v1/chat/completions"
  printf 'info  completion took %ss\n' "$(( $(date +%s) - started ))"
fi
if [[ "$failed" -ne 0 ]]; then echo 'Model host checks failed'; exit 1; fi
echo 'Model host checks passed'
