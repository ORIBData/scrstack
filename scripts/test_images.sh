#!/usr/bin/env bash
# M6 acceptance: local registry, real Alpine image, real OSV Alpine feed, pinned scanner.
set -euo pipefail
: "${DOCKER:=docker}"
: "${GO:=go}"
registry="scrs-registry-qa-$$"
clamav="scrs-image-clamav-qa-$$"
work=$(mktemp -d)
trap '"$DOCKER" rm -f "$registry" "$clamav" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
# Real ClamAV with the SCRS YARA rules for layer malware coverage.
"$DOCKER" run --rm -d --name "$clamav" --memory=2g --cpus=2 --user clamav --entrypoint /init-unprivileged --cap-drop ALL --security-opt no-new-privileges:true -e CLAMAV_NO_FRESHCLAMD=true -v "$PWD/internal/scanner/rules/scrs.yar:/var/lib/clamav/scrs.yar:ro" -p 127.0.0.1::3310 clamav/clamav:1.5.4-debian13-slim@sha256:76a9c3b63764b78178dc68fa7efcceca0cde2c8c9d4f925a8e697cb4511f8fdc >/dev/null
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
for attempt in {1..60}; do "$DOCKER" exec "$clamav" clamdscan --ping=1 >/dev/null 2>&1 && break; sleep 2; done
clamd=$("$DOCKER" port "$clamav" 3310/tcp)
SCRS_TEST_CLAMD_ADDRESS="$clamd" SCRS_TEST_REGISTRY="localhost:$port" SCRS_TEST_IMAGE_TAR="$work/alpine.tar" SCRS_TEST_ALPINE_FEED="$work/alpine.zip" SCRS_TEST_OSV_BINARY="$PWD/bin/osv-scanner" \
  "$GO" test -race -count=1 -v ./internal/scanner -run TestLiveImageArchiveAndScan
