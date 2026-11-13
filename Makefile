SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: database-test
database-test:
	DOCKER=$(DOCKER) GO=$(GO) bash scripts/test_database.sh

GO ?= go
DOCKER ?= docker
VERSION ?=
SCRS_IMAGE ?=
IMAGE_NAME ?= scrs
PLATFORMS ?= linux/amd64,linux/arm64
DOCKERHUB_REPO ?=
SCRS_REPO_TAG_PREFIX ?= scrs_

.PHONY: help build test lint contract-check image clean clean-dry-run storage-check storage-bootstrap storage-init connections-list connections-test connections-discover storage-integration release

help:
	@echo 'build           Build the SCRS API binary locally'
	@echo 'test            Run Go tests and the race detector'
	@echo 'scanner-test    Run pinned upstream OSV against adversarial offline fixtures'
	@echo 'lint            Format check and go vet'
	@echo 'contract-check  Validate the published OpenAPI route paths'
	@echo 'image           Build a local SCRS API image'
	@echo 'image-reference Print the resolved SCRS_IMAGE release tag'
	@echo 'image-audit     Generate SBOM and vulnerability evidence for a local image'
	@echo 'database-test   Exercise concurrency, tokens, lifecycle and PostgreSQL restore'
	@echo 'legacy-integration  Test the internal legacy scanner with ClamAV fixtures'
	@echo 'qa              Run local tests, lint, contracts and tooling checks'
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
	$(GO) test -race ./cmd/scrs/... ./internal/... ./api/...

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

.PHONY: image-reference
image-reference:
	@SCRS_IMAGE="$(SCRS_IMAGE)" VERSION="$(VERSION)" DOCKERHUB_REPO="$(DOCKERHUB_REPO)" python3 scripts/image_reference.py

.PHONY: image-audit qa
image-audit:
	@DOCKER="$(DOCKER)" SCRS_IMAGE="$(SCRS_IMAGE)" VERSION="$(VERSION)" DOCKERHUB_REPO="$(DOCKERHUB_REPO)" python3 scripts/image_reference.py python3 scripts/audit_image.py

qa: test lint contract-check
	$(GO) test -race . -run 'TestLegacySecurity|TestMalformedMultipart'
	python3 -m unittest discover -s tests -p '*_test.py'

.PHONY: legacy-integration
legacy-integration:
	$(DOCKER) build -f Dockerfile.test -t scrs:legacy-test .
	$(DOCKER) run --rm --memory=2g --cpus=2 scrs:legacy-test

# Build the exact dependency graph used in the shipped scanner, then run a real
# offline scan against synthetic advisories. Does not use .env or live stores.
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
