SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: database-test
database-test:
	DOCKER=$(DOCKER) GO=$(GO) bash scripts/test_database.sh

GO ?= go
DOCKER ?= docker
VERSION ?=
SCRS_IMAGE ?=
SCRS_SAST_IMAGE ?=
SCRS_QA_RUNNER_IMAGE ?=
IMAGE_NAME ?= scrs
PLATFORMS ?= linux/amd64,linux/arm64
DOCKERHUB_REPO ?=
SCRS_REPO_TAG_PREFIX ?= scrs_

.PHONY: help build test lint contract-check image clean clean-dry-run storage-check storage-bootstrap storage-init connections-list connections-test connections-discover storage-integration release

help:
	@echo 'build           Build the SCRS API binary locally'
	@echo 'test            Run Go tests and the race detector'
	@echo 'scanner-test    Run pinned upstream OSV against adversarial offline fixtures'
	@echo 'sast-image-test Build scrs-sast and run AT-27 to AT-29 on an internal-only network'
	@echo 'lint            Format check and go vet'
	@echo 'contract-check  Validate the published OpenAPI route paths'
	@echo 'image           Build a local SCRS API image'
	@echo 'image-reference Print the resolved SCRS_IMAGE release tag'
	@echo 'sast-image-reference, qa-runner-image-reference  Print the resolved SCRS_SAST_IMAGE and SCRS_QA_RUNNER_IMAGE tags'
	@echo 'image-audit     Generate SBOM and vulnerability evidence for a local image'
	@echo 'database-test   Exercise concurrency, tokens, lifecycle and PostgreSQL restore'
	@echo 'legacy-integration  Test the internal legacy scanner with ClamAV fixtures'
	@echo 'qa              Run local tests, lint, contracts and tooling checks'
	@echo 'qa-runner-image Build the Karate runner image (E2E QA)'
	@echo 'qa-runner-test  Test the runner with the pinned Karate jar (needs Java 21)'
	@echo 'qa-runner-image-test  Test API, UI and load runs in a hardened runner container'
	@echo 'release-qa-runner  Push SCRS_QA_RUNNER_IMAGE (Karate runner, from .env) for the Dokploy stack'
	@echo 'clean           Remove older local SCRS images; keep newest and container-used images'
	@echo 'clean-dry-run   Preview which local SCRS image tags would be removed'
	@echo 'storage-check   Test the configured PostgreSQL, Redis and S3 stores'
	@echo 'storage-bootstrap  Create missing SCRS database/schema/bucket when permitted'
	@echo 'storage-init   Bootstrap storage and seed configured provider connections'
	@echo 'connections-list  List nonsecret connection configuration'
	@echo 'connections-test  Test one provider connection (CONNECTION=github-primary)'
	@echo 'connections-discover  Discover one or all connections (CONNECTION=all)'
	@echo 'storage-integration  Test bootstrap and connection checks with disposable Docker services'
	@echo 'release         Push SCRS_IMAGE using interactive registry credentials'

build:
	@mkdir -p bin
	$(GO) build -trimpath -o bin/scrs ./cmd/scrs

test:
	$(GO) test -race ./cmd/... ./internal/... ./api/...

lint:
	@test -z "$$(find cmd/scrs internal api -name '*.go' -print0 | xargs -0 gofmt -l)" || { echo 'Go files needed formatting'; exit 1; }
	$(GO) vet ./...

contract-check:
	$(GO) test ./internal/httpapi/... ./api/...

image:
	@SCRS_IMAGE="$(SCRS_IMAGE)" VERSION="$(VERSION)" DOCKERHUB_REPO="$(DOCKERHUB_REPO)" python3 scripts/image_reference.py bash -c '"$$0" build -f deploy/Dockerfile.scrs -t "$$SCRS_IMAGE" .' "$(DOCKER)"

clean:
	SCRS_IMAGE="$(SCRS_IMAGE)" DOCKER=$(DOCKER) python3 scripts/clean_images.py --image-name "$(IMAGE_NAME)" --repository "$(DOCKERHUB_REPO)" --repository-tag-prefix "$(SCRS_REPO_TAG_PREFIX)"

clean-dry-run:
	SCRS_IMAGE="$(SCRS_IMAGE)" DOCKER=$(DOCKER) python3 scripts/clean_images.py --image-name "$(IMAGE_NAME)" --repository "$(DOCKERHUB_REPO)" --repository-tag-prefix "$(SCRS_REPO_TAG_PREFIX)" --dry-run

storage-check: build
	@python3 scripts/run_with_env.py bin/scrs storage check

storage-bootstrap: build
	@python3 scripts/run_with_env.py bin/scrs storage bootstrap

storage-init: build
	@python3 scripts/run_with_env.py bin/scrs init

connections-list: build
	@python3 scripts/run_with_env.py bin/scrs connections list

connections-test: build
	@python3 scripts/run_with_env.py bin/scrs connections test "$(or $(CONNECTION),github-primary)"

connections-discover: build
	@python3 scripts/run_with_env.py bin/scrs connections discover "$(or $(CONNECTION),all)"

storage-integration:
	@$(DOCKER) build -f deploy/Dockerfile.scrs -t scrs:storage-test .
	@set -e; \
	  compose='$(DOCKER) compose -p scrs-storage-qa -f tests/integration/storage.compose.yaml'; \
	  trap "$$compose down -v" EXIT; \
	  $$compose up -d postgres redis minio api; \
	  $$compose run --rm storage-bootstrap; \
	  $$compose run --rm --no-deps storage-check; \
	  $$compose run --rm connections-create; \
	  $$compose run --rm --no-deps connections-list; \
	  $$compose run --rm --no-deps storage-bootstrap

release:
	@DOCKER="$(DOCKER)" VERSION="$(VERSION)" SCRS_IMAGE="$(SCRS_IMAGE)" PLATFORMS="$(PLATFORMS)" DOCKERHUB_REPO="$(DOCKERHUB_REPO)" python3 scripts/image_reference.py bash scripts/release.sh

.PHONY: image-reference sast-image-reference qa-runner-image-reference
image-reference:
	@SCRS_IMAGE="$(SCRS_IMAGE)" VERSION="$(VERSION)" DOCKERHUB_REPO="$(DOCKERHUB_REPO)" python3 scripts/image_reference.py

sast-image-reference:
	@SCRS_IMAGE_KEY=SCRS_SAST_IMAGE SCRS_IMAGE="$(SCRS_SAST_IMAGE)" VERSION="$(VERSION)" DOCKERHUB_REPO= python3 scripts/image_reference.py

qa-runner-image-reference:
	@SCRS_IMAGE_KEY=SCRS_QA_RUNNER_IMAGE SCRS_IMAGE="$(SCRS_QA_RUNNER_IMAGE)" VERSION="$(VERSION)" DOCKERHUB_REPO= python3 scripts/image_reference.py

.PHONY: image-audit qa
image-audit:
	@DOCKER="$(DOCKER)" SCRS_IMAGE="$(SCRS_IMAGE)" VERSION="$(VERSION)" DOCKERHUB_REPO="$(DOCKERHUB_REPO)" python3 scripts/image_reference.py python3 scripts/audit_image.py

qa: test lint contract-check
	$(GO) test -race . -run 'TestLegacySecurity|TestMalformedMultipart'
	python3 -m unittest discover -s tests -p '*_test.py'

# E2E QA: the Karate runner image (built from deploy/karate-runner), and the
# runner tests against the pinned Karate jar and a running runner container.
QA_RUNNER_IMAGE ?= scrs-qa-runner:local
KARATE_JAR_URL := https://github.com/karatelabs/karate/releases/download/v2.1.4/karate-2.1.4.jar
KARATE_JAR_SHA256 := 1f743f4acc56526b39bd88c84bfe4491c46d5e94f4ab5a38c437c9400dbc2488

.PHONY: qa-runner-image qa-runner-test qa-runner-image-test release-qa-runner
qa-runner-image:
	$(DOCKER) build -f deploy/karate-runner/Dockerfile -t $(QA_RUNNER_IMAGE) .

# Publishes the runner image the Dokploy stack deploys as scrs-qa-runner.
# SCRS_QA_RUNNER_IMAGE (from .env, or on the command line) is a template like
# registry/namespace/scrs-qa-runner:scrs_YYYY_MM_DD_v{shortSHA256}.
release-qa-runner:
	@DOCKER="$(DOCKER)" VERSION="$(VERSION)" SCRS_IMAGE_KEY=SCRS_QA_RUNNER_IMAGE SCRS_IMAGE="$(SCRS_QA_RUNNER_IMAGE)" SCRS_DOCKERFILE=deploy/karate-runner/Dockerfile PLATFORMS="$(PLATFORMS)" DOCKERHUB_REPO= python3 scripts/image_reference.py bash scripts/release.sh

# SCRS_SAST_IMAGE comes from .env, or the command line, like SCRS_IMAGE.
release-sast:
	@DOCKER="$(DOCKER)" VERSION="$(VERSION)" SCRS_IMAGE_KEY=SCRS_SAST_IMAGE SCRS_IMAGE="$(SCRS_SAST_IMAGE)" SCRS_DOCKERFILE=deploy/Dockerfile.sast PLATFORMS="$(PLATFORMS)" DOCKERHUB_REPO= python3 scripts/image_reference.py bash scripts/release.sh

qa-runner-test:
	@mkdir -p bin
	@test -f bin/karate-2.1.4.jar || curl -fsSL -o bin/karate-2.1.4.jar $(KARATE_JAR_URL)
	@echo "$(KARATE_JAR_SHA256)  bin/karate-2.1.4.jar" | shasum -a 256 -c -
	SCRS_TEST_KARATE_JAR=$(CURDIR)/bin/karate-2.1.4.jar $(GO) test -race -count=1 -run 'TestRealKarate|TestRunner' ./internal/qarunner/

qa-runner-image-test: qa-runner-image
	@name=scrs-qa-runner-test-$$$$; token=$$(openssl rand -hex 24); \
	trap '$(DOCKER) rm -f '"$$name"' >/dev/null 2>&1' EXIT; \
	$(DOCKER) run -d --name $$name -e SCRS_QA_RUNNER_TOKEN=$$token -e SCRS_QA_RUNNER_JOB_UID=10001 -e SCRS_QA_RUNNER_JOB_GID=10001 \
	  --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE --cap-add KILL \
	  --security-opt no-new-privileges:true --read-only --tmpfs /work:size=2g,mode=0711 --tmpfs /tmp:size=512m,mode=1777 \
	  --shm-size 1g --add-host host.docker.internal:host-gateway -p 127.0.0.1::8090 $(QA_RUNNER_IMAGE) >/dev/null; \
	sleep 3; port=$$($(DOCKER) port $$name 8090/tcp | head -1); \
	SCRS_TEST_RUNNER_URL=http://$$port SCRS_TEST_RUNNER_TOKEN=$$token SCRS_TEST_RUNNER_HOST=host.docker.internal \
	  $(GO) test -count=1 -run TestRunnerImage -v ./internal/qarunner/

.PHONY: legacy-integration
legacy-integration:
	$(DOCKER) build -f Dockerfile.test -t scrs:legacy-test .
	$(DOCKER) run --rm --memory=2g --cpus=2 scrs:legacy-test

# Build the exact dependency graph used in the shipped scanner, then run a real
# offline scan against synthetic advisories. Does not use .env or live stores.
.PHONY: sast-image sast-image-test release-sast
sast-image:
	$(DOCKER) build -f deploy/Dockerfile.sast -t scrs-sast:dev .

sast-image-test: sast-image
	$(DOCKER) build -f deploy/Dockerfile.scrs -t scrs:dev .
	DOCKER=$(DOCKER) GO=$(GO) bash scripts/test_sast_image.sh

.PHONY: scanner-test
scanner-test:
	@mkdir -p bin
	cd tools/osv && $(GO) build -trimpath -o ../../bin/osv-scanner github.com/google/osv-scanner/v2/cmd/osv-scanner
	SCRS_TEST_OSV_BINARY="$(CURDIR)/bin/osv-scanner" $(GO) test -race -count=1 ./internal/scanner

.PHONY: deployment-acceptance
deployment-acceptance:
	@python3 scripts/run_with_env.py python3 scripts/deployment_acceptance.py

.PHONY: malware-test
malware-test:
	DOCKER=$(DOCKER) GO=$(GO) bash scripts/test_malware.sh

.PHONY: remediation-live-test
remediation-live-test: scanner-test
	SCRS_TEST_OSV_BINARY="$(CURDIR)/bin/osv-scanner" SCRS_TEST_LIVE_REMEDIATION=1 $(GO) test -race -count=1 ./internal/scanner -run TestUpstreamRemediation

.PHONY: image-scan-test
image-scan-test:
	DOCKER=$(DOCKER) GO=$(GO) bash scripts/test_images.sh
