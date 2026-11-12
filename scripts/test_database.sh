#!/usr/bin/env bash
set -euo pipefail
: "${DOCKER:=docker}"
: "${GO:=go}"
test_container="scrs-db-qa-$$"
test_redis="scrs-redis-qa-$$"
trap '"$DOCKER" rm -f "$test_container" "$test_redis" >/dev/null 2>&1 || true' EXIT
"$DOCKER" run --rm -d --name "$test_container" -e POSTGRES_PASSWORD=synthetic-test-password -p 127.0.0.1::5432 postgres:16-alpine >/dev/null
"$DOCKER" run --rm -d --name "$test_redis" -p 127.0.0.1::6379 redis:7-alpine >/dev/null
ready=false
for attempt in {1..30}; do
 if "$DOCKER" exec "$test_container" pg_isready -U postgres >/dev/null 2>&1; then ready=true; break; fi
 sleep 1
done
if [[ "$ready" != true ]]; then echo 'Disposable PostgreSQL failed to become ready' >&2; exit 1; fi
test_address=$("$DOCKER" port "$test_container" 5432/tcp)
test_redis_address=$("$DOCKER" port "$test_redis" 6379/tcp)
SCRS_TEST_PG_CONTAINER="$test_container" SCRS_TEST_REDIS_URL="redis://${test_redis_address}/0" SCRS_TEST_DATABASE_URL="postgres://postgres:synthetic-test-password@${test_address}/postgres?sslmode=disable" "$GO" test -race ./internal/connections ./internal/httpapi -run TestPostgres -count=1
