SHELL := /bin/bash
.DEFAULT_GOAL := help

GO ?= go
DOCKER ?= docker
VERSION ?= dev
IMAGE_NAME ?= scrs
PLATFORMS ?= linux/amd64,linux/arm64
DOCKERHUB_REPO ?=
SCRS_REPO_TAG_PREFIX ?= scrs_

.PHONY: help build test lint contract-check image clean clean-dry-run storage-check storage-bootstrap storage-init connections-list connections-test connections-discover storage-integration release

help:
	@echo 'build           Build the SCRS API binary locally'
	@echo 'test            Run Go tests and the race detector'
	@echo 'lint            Format check and go vet'
	@echo 'contract-check  Validate the published OpenAPI route paths'
	@echo 'image           Build a local SCRS API image'
	@echo 'clean           Remove older local SCRS images; keep newest and container-used images'
	@echo 'clean-dry-run   Preview which local SCRS image tags would be removed'
	@echo 'storage-check   Test the configured PostgreSQL, Redis and S3 stores'
	@echo 'storage-bootstrap  Create missing SCRS database/schema/bucket when permitted'
	@echo 'storage-init   Bootstrap storage and seed configured provider connections'
	@echo 'connections-list  List nonsecret connection configuration'
	@echo 'connections-test  Test one provider connection (CONNECTION=github-primary)'
	@echo 'connections-discover  Discover one or all connections (CONNECTION=all)'
	@echo 'storage-integration  Test bootstrap and connection checks with disposable Docker services'
	@echo 'release         Push DOCKERHUB_REPO=namespace/name:VERSION using an interactive Docker Hub login'

build:
	@mkdir -p bin
	$(GO) build -trimpath -o bin/scrs ./cmd/scrs

test:
	$(GO) test -race ./cmd/scrs/... ./internal/... ./api/...

lint:
	@test -z "$$(find cmd/scrs internal api -name '*.go' -print0 | xargs -0 gofmt -l)" || { echo 'Go files needed formatting'; exit 1; }
	$(GO) vet ./cmd/scrs/... ./internal/... ./api/...

contract-check:
	$(GO) test ./internal/httpapi/... ./api/...

image:
	$(DOCKER) build -f deploy/Dockerfile.scrs -t $(IMAGE_NAME):$(VERSION) .

clean:
	DOCKER=$(DOCKER) python3 scripts/clean_images.py --image-name "$(IMAGE_NAME)" --repository "$(DOCKERHUB_REPO)" --repository-tag-prefix "$(SCRS_REPO_TAG_PREFIX)"

clean-dry-run:
	DOCKER=$(DOCKER) python3 scripts/clean_images.py --image-name "$(IMAGE_NAME)" --repository "$(DOCKERHUB_REPO)" --repository-tag-prefix "$(SCRS_REPO_TAG_PREFIX)" --dry-run

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
	@$(MAKE) image VERSION=storage-test
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
	DOCKER=$(DOCKER) VERSION=$(VERSION) PLATFORMS=$(PLATFORMS) DOCKERHUB_REPO=$(DOCKERHUB_REPO) SCRS_REPO_TAG_PREFIX=$(SCRS_REPO_TAG_PREFIX) ./scripts/release.sh
