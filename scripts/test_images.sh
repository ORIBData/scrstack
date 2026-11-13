#!/usr/bin/env bash
# M6 acceptance: local registry, real Alpine image, real OSV Alpine feed, pinned scanner.
set -euo pipefail
: "${DOCKER:=docker}"
: "${GO:=go}"
registry="scrs-registry-qa-$$"
work=$(mktemp -d)
trap '"$DOCKER" rm -f "$registry" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
"$DOCKER" run --rm -d --name "$registry" -p 127.0.0.1::5000 registry:2.8.3 >/dev/null
address=$("$DOCKER" port "$registry" 5000/tcp)
port=${address##*:}
for attempt in {1..30}; do curl -fsS "http://127.0.0.1:$port/v2/" >/dev/null 2>&1 && break; sleep 1; done
"$DOCKER" pull -q --platform linux/amd64 alpine:3.19.1 >/dev/null
# Docker Desktop's daemon cannot reach the host loopback; the test pushes the saved image.
"$DOCKER" save alpine:3.19.1 -o "$work/alpine.tar"
curl -fsS -o "$work/alpine.zip" https://osv-vulnerabilities.storage.googleapis.com/Alpine/all.zip
mkdir -p bin
(cd tools/osv && "$GO" build -trimpath -o ../../bin/osv-scanner github.com/google/osv-scanner/v2/cmd/osv-scanner)
SCRS_TEST_REGISTRY="localhost:$port" SCRS_TEST_IMAGE_TAR="$work/alpine.tar" SCRS_TEST_ALPINE_FEED="$work/alpine.zip" SCRS_TEST_OSV_BINARY="$PWD/bin/osv-scanner" \
  "$GO" test -race -count=1 -v ./internal/scanner -run TestLiveImageArchiveAndScan
