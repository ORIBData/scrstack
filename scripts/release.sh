#!/usr/bin/env bash
set -euo pipefail

: "${DOCKER:=docker}"
: "${VERSION:=}"
: "${PLATFORMS:=linux/amd64,linux/arm64}"
: "${DOCKERHUB_REPO:=}"
: "${SCRS_REPO_TAG_PREFIX:=scrs_}"

export SCRS_IMAGE
SCRS_IMAGE=$(python3 "$(dirname "$0")/image_reference.py") || exit 2
if [[ ! "$PLATFORMS" =~ ^linux/(amd64|arm64)(,linux/(amd64|arm64))?$ ]] || [[ "$PLATFORMS" == 'linux/amd64,linux/amd64' || "$PLATFORMS" == 'linux/arm64,linux/arm64' ]]; then
  echo 'PLATFORMS must be linux/amd64, linux/arm64, or both' >&2
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

registry=docker.io
if [[ "${SCRS_IMAGE%%/*}" == *.* || "${SCRS_IMAGE%%/*}" == *:* ]]; then
  registry=${SCRS_IMAGE%%/*}
fi
if [[ "$registry" == *-docker.pkg.dev ]]; then
  registry_username=oauth2accesstoken
else
  read -r -p "Registry username ($registry): " registry_username
  [[ -n "$registry_username" ]] || { echo 'Username is required' >&2; exit 2; }
fi
docker_config_dir=$(mktemp -d)
trap 'unset dockerhub_pat; rm -rf -- "$docker_config_dir"' EXIT
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
"$DOCKER" buildx build --platform "$PLATFORMS" -f deploy/Dockerfile.scrs -t "$image" --sbom=true --provenance=mode=max --push .
echo "Published ${image}"
