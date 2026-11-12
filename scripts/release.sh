#!/usr/bin/env bash
set -euo pipefail

: "${DOCKER:=docker}"
: "${VERSION:=dev}"
: "${PLATFORMS:=linux/amd64,linux/arm64}"
: "${DOCKERHUB_REPO:=}"
: "${SCRS_REPO_TAG_PREFIX:=scrs_}"

if [[ ! "$VERSION" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
  echo 'VERSION must be a valid, nonempty Docker tag' >&2
  exit 2
fi
if [[ "$VERSION" == "dev" || "$VERSION" == "latest" ]]; then
  echo 'Set VERSION to an immutable release tag, for example v0.1.0' >&2
  exit 2
fi
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

read -r -p 'Docker Hub username: ' dockerhub_username
if [[ ! "$dockerhub_username" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
  echo 'Invalid Docker Hub username' >&2
  exit 2
fi
if [[ -z "$DOCKERHUB_REPO" ]]; then
  read -r -p 'Docker Hub repository (namespace/name): ' DOCKERHUB_REPO
fi
if [[ ! "$DOCKERHUB_REPO" =~ ^[a-z0-9][a-z0-9_-]*/[a-z0-9]+([._-][a-z0-9]+)*$ ]]; then
  echo 'DOCKERHUB_REPO must be a Docker Hub namespace/repository, such as oribdata/zerorate-stg' >&2
  exit 2
fi
if [[ -f .env ]]; then
  while IFS= read -r env_line; do
    if [[ "$env_line" == SCRS_IMAGE=* ]]; then
      configured_image=${env_line#SCRS_IMAGE=}
      configured_image=${configured_image#\"}; configured_image=${configured_image%\"}
      configured_image=${configured_image#\'}; configured_image=${configured_image%\'}
      configured_repo=${configured_image%:*}
      configured_tag=${configured_image##*:}
      if [[ "$configured_repo" == "$DOCKERHUB_REPO" && "$configured_tag" == "$SCRS_REPO_TAG_PREFIX"* && "$VERSION" != "$SCRS_REPO_TAG_PREFIX"* ]]; then
        echo "The configured Docker Hub repository is shared; use a tag beginning ${SCRS_REPO_TAG_PREFIX} (for example ${SCRS_REPO_TAG_PREFIX}${VERSION})" >&2
        exit 2
      fi
      break
    fi
  done < .env
fi

docker_config_dir=$(mktemp -d)
trap 'unset dockerhub_pat; rm -rf -- "$docker_config_dir"' EXIT
export DOCKER_CONFIG="$docker_config_dir"
if ! "$DOCKER" info >/dev/null; then
  echo 'Docker engine is unavailable through the active context endpoint' >&2
  exit 1
fi

read -r -s -p 'Docker Hub PAT: ' dockerhub_pat
echo
if [[ -z "$dockerhub_pat" ]]; then
  echo 'Docker Hub PAT cannot be empty' >&2
  exit 2
fi

printf '%s' "$dockerhub_pat" | "$DOCKER" login --username "$dockerhub_username" --password-stdin
unset dockerhub_pat

image="${DOCKERHUB_REPO}:${VERSION}"
echo "Publishing ${image} for ${PLATFORMS}"
"$DOCKER" buildx build --platform "$PLATFORMS" -f deploy/Dockerfile.scrs -t "$image" --push .
echo "Published ${image}"
