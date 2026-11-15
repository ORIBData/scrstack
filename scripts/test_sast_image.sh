#!/usr/bin/env bash
# M9 acceptance against the real scrs-sast image (AT-27 to AT-29, S10, S12):
# the analyzers run on an internal-only network; only Go module downloads
# leave it, through the go-modules egress proxy.
set -euo pipefail
DOCKER="${DOCKER:-docker}"
GO="${GO:-go}"
SAST_IMAGE="${SAST_IMAGE:-scrs-sast:dev}"
SCRS_IMAGE="${SCRS_IMAGE_LOCAL:-scrs:dev}"
run_id="scrs-sast-test-$$"
token="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
work="$(mktemp -d)"
cleanup() {
  "$DOCKER" rm -f "$run_id-sast" "$run_id-proxy" "$run_id-client" >/dev/null 2>&1 || true
  "$DOCKER" network rm "$run_id-internal" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

mkdir -p "$work/feed/osv-scalibr/Go" "$work/sast-tmp"
# The analyzer container's /tmp is a host directory, so the canary check below
# observes from outside the box under test (a compromised container could hide
# files from a check it runs on itself).
chmod 1777 "$work/sast-tmp"
curl -fsSL -o "$work/feed/osv-scalibr/Go/all.zip" https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip
"$DOCKER" network create --internal "$run_id-internal" >/dev/null
"$DOCKER" run -d --name "$run_id-proxy" --read-only --cap-drop ALL -e SCRS_EGRESS_PROFILE=go-modules "$SCRS_IMAGE" egress-proxy >/dev/null
"$DOCKER" network connect --alias sast-egress "$run_id-internal" "$run_id-proxy"
"$DOCKER" run -d --name "$run_id-sast" --network "$run_id-internal" --network-alias scrs-sast \
  --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 512 --memory 4g \
  --tmpfs /work:size=3g,mode=1777,exec -v "$work/sast-tmp:/tmp" \
  -v "$work/feed:/feeds/current:ro" \
  -e SCRS_SAST_API_TOKEN="$token" -e SCRS_SAST_GO_PROXY=http://sast-egress:8082 \
  "$SAST_IMAGE" sast >/dev/null
CGO_ENABLED=0 GOOS=linux GOARCH="$("$GO" env GOARCH)" "$GO" test -c -o "$work/sast.test" ./internal/sast
for _ in $(seq 1 30); do
  "$DOCKER" exec "$run_id-sast" scrs sast-healthcheck >/dev/null 2>&1 && break
  sleep 2
done
"$DOCKER" run --name "$run_id-client" --network "$run_id-internal" --read-only \
  -v "$work/sast.test:/sast.test:ro" -v "$PWD/internal/sast/testdata:/testdata:ro" -w / \
  -e SCRS_TEST_SAST_URL=http://scrs-sast:8083 -e SCRS_TEST_SAST_TOKEN="$token" \
  --tmpfs /tmp:size=64m,mode=1777 --entrypoint sh "$SAST_IMAGE" -c 'mkdir -p /tmp/t && cd /tmp/t && ln -s /testdata testdata && /sast.test -test.run TestSASTImageAcceptance -test.v -test.count=1'
# AT-28: nothing in the hostile repository ran. Checked from the host: the
# container's /tmp, and every file it added to its image layer (docker diff).
if find "$work/sast-tmp" -name 'canary-*' | grep -q . || "$DOCKER" diff "$run_id-sast" | grep -q canary; then
  echo "hostile repository canary created" >&2
  exit 1
fi
echo "AT-28: no canary created (checked from the host); the analyzer network is internal-only"
