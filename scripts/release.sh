#!/usr/bin/env bash
set -euo pipefail

: "${DOCKER:=docker}"
: "${VERSION:=}"
: "${PLATFORMS:=linux/amd64}"
: "${DOCKERHUB_REPO:=}"
: "${SCRS_REPO_TAG_PREFIX:=scrs_}"
# SCRS_BUILD_CLOUD selects a Docker Build Cloud builder (ORG/BUILDER): native
# amd64 and arm64 builders instead of local emulation. Read from the
# environment, else from .env (read as text, never evaluated).
: "${SCRS_BUILD_CLOUD:=}"
if [[ -z "$SCRS_BUILD_CLOUD" && -f .env ]]; then
  SCRS_BUILD_CLOUD=$(sed -n 's/^SCRS_BUILD_CLOUD=//p' .env | tail -n 1 | tr -d '"'"'"' \r')
fi
if [[ -n "$SCRS_BUILD_CLOUD" && ! "$SCRS_BUILD_CLOUD" =~ ^[a-z0-9][a-z0-9_-]*/[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo 'SCRS_BUILD_CLOUD must be ORG/BUILDER, for example oribdata/creditchek-stg-ci' >&2
  exit 2
fi

export SCRS_IMAGE
SCRS_IMAGE=$(python3 "$(dirname "$0")/image_reference.py") || exit 2
if [[ ! "$PLATFORMS" =~ ^linux/(amd64|arm64)(,linux/(amd64|arm64))?$ ]] || [[ "$PLATFORMS" == 'linux/amd64,linux/amd64' || "$PLATFORMS" == 'linux/arm64,linux/arm64' ]]; then
  echo 'PLATFORMS must be linux/amd64, linux/arm64, or both' >&2
  exit 2
fi
registry=docker.io
if [[ "${SCRS_IMAGE%%/*}" == *.* || "${SCRS_IMAGE%%/*}" == *:* ]]; then
  registry=${SCRS_IMAGE%%/*}
fi
if [[ -n "$SCRS_BUILD_CLOUD" && "$registry" != docker.io ]]; then
  echo 'SCRS_BUILD_CLOUD needs a Docker Hub image: Build Cloud signs in with the Docker Hub login' >&2
  exit 2
fi
if [[ ! -t 0 ]]; then
  echo 'Release needs an interactive terminal for Docker Hub credentials' >&2
  exit 2
fi

# Read the active endpoint before isolating registry credentials: a fresh
# DOCKER_CONFIG has no saved Docker Desktop context or Buildx builder.
if [[ -z "${DOCKER_HOST:-}" ]]; then
  docker_endpoint=$("$DOCKER" context inspect --format '{{.Endpoints.docker.Host}}')
  if [[ -z "$docker_endpoint" ]]; then
    echo 'Active Docker context has no engine endpoint' >&2
    exit 1
  fi
  export DOCKER_HOST="$docker_endpoint"
fi
unset DOCKER_CONTEXT

if [[ "$registry" == *-docker.pkg.dev ]]; then
  registry_username=oauth2accesstoken
else
  read -r -p "Registry username ($registry): " registry_username
  [[ -n "$registry_username" ]] || { echo 'Username is required' >&2; exit 2; }
fi
docker_config_dir=$(mktemp -d)
# The isolated config has no Buildx builder, and the default "docker" driver
# cannot attach SBOM and provenance attestations. Each release creates its own
# builder (docker-container, or a reference to the Build Cloud builder) and
# removes it, and the login, on exit. Removing a cloud reference leaves the
# cloud builder itself untouched.
builder="scrs-release-$$"
cleanup() {
  unset dockerhub_pat
  "$DOCKER" buildx rm --force "$builder" >/dev/null 2>&1 || true
  rm -rf -- "$docker_config_dir"
}
trap cleanup EXIT
export DOCKER_CONFIG="$docker_config_dir"
if ! "$DOCKER" info >/dev/null; then
  echo 'Docker engine is unavailable through the active context endpoint' >&2
  exit 1
fi

read -r -s -p "Registry PAT or access token ($registry): " dockerhub_pat
echo
if [[ -z "$dockerhub_pat" ]]; then
  echo 'Docker Hub PAT cannot be empty' >&2
  exit 2
fi

printf '%s' "$dockerhub_pat" | "$DOCKER" login "$registry" --username "$registry_username" --password-stdin
unset dockerhub_pat

image="$SCRS_IMAGE"
echo "Publishing ${image} for ${PLATFORMS}"
# SCRS_DOCKERFILE selects the image: SCRS (default), scrs-sast or the Karate runner.
dockerfile=${SCRS_DOCKERFILE:-deploy/Dockerfile.scrs}
case "$dockerfile" in
  deploy/Dockerfile.scrs|deploy/Dockerfile.sast|deploy/karate-runner/Dockerfile) ;;
  *) echo 'SCRS_DOCKERFILE must be deploy/Dockerfile.scrs, deploy/Dockerfile.sast or deploy/karate-runner/Dockerfile' >&2; exit 2 ;;
esac
if [[ -n "$SCRS_BUILD_CLOUD" ]]; then
  # The Docker Hub login above must belong to a member of the Build Cloud
  # organisation. The context is uploaded to Docker's builders; .dockerignore
  # keeps .env, .git and local artifacts out of it.
  echo "Building on Docker Build Cloud builder ${SCRS_BUILD_CLOUD}"
  "$DOCKER" buildx create --name "$builder" --driver cloud "$SCRS_BUILD_CLOUD" >/dev/null
else
  "$DOCKER" buildx create --name "$builder" --driver docker-container --bootstrap >/dev/null
fi
"$DOCKER" buildx build --builder "$builder" --platform "$PLATFORMS" -f "$dockerfile" -t "$image" --sbom=true --provenance=mode=max --push .
echo "Published ${image}"
