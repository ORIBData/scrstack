#!/usr/bin/env python3
"""Remove older local SCRS images, leaving the newest and container-used IDs."""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from image_reference import configured_image, valid_repository


def docker(*args):
    return subprocess.check_output([os.environ.get("DOCKER", "docker"), *args], text=True)


def configured_repository():
    """Read only the image reference; never load the entire dotenv as shell."""
    image = configured_image()
    return image.rsplit(":", 1)[0] if ":" in image.rsplit("/", 1)[-1] else image



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image-name", default="scrs")
    parser.add_argument("--repository", default="")
    parser.add_argument("--repository-tag-prefix", default="scrs_")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if not args.image_name or "/" in args.image_name or ":" in args.image_name:
        parser.error("--image-name must be a local repository name")
    repository = args.repository or configured_repository()
    if repository and not valid_repository(repository):
        parser.error("--repository must be a full registry repository")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", args.repository_tag_prefix):
        parser.error("--repository-tag-prefix must be a nonempty Docker tag prefix")

    ids = set(docker("image", "ls", "--all", "--no-trunc", "--filter", "label=io.scrs.project=scrstack", "--format", "{{.ID}}").splitlines())
    ids.update(docker("image", "ls", "--all", "--no-trunc", "--filter", f"reference={args.image_name}:*", "--format", "{{.ID}}").splitlines())
    if repository:
        ids.update(docker("image", "ls", "--all", "--no-trunc", "--filter", f"reference={repository}:{args.repository_tag_prefix}*", "--format", "{{.ID}}").splitlines())
    if not ids:
        print("No local SCRS images found")
        return 0
    images = json.loads(docker("image", "inspect", *sorted(ids)))
    images.sort(key=lambda image: (image["Created"], image["Id"]), reverse=True)
    newest = images[0]["Id"]
    containers = docker("container", "ls", "--all", "--no-trunc", "--format", "{{.ID}}").splitlines()
    used = set()
    if containers:
        used = {item["Image"] for item in json.loads(docker("container", "inspect", *containers))}
    print(f"Keeping newest SCRS image {newest[:19]}")
    failures = 0
    for image in images[1:]:
        image_id = image["Id"]
        if image_id in used:
            print(f"Keeping container-used image {image_id[:19]}")
            continue
        labelled = image.get("Config", {}).get("Labels", {}).get("io.scrs.project") == "scrstack"
        tags = image.get("RepoTags") or []
        project_prefixes = [args.image_name + ":"]
        if repository:
            project_prefixes.append(repository + ":" + args.repository_tag_prefix)
        refs = tags if labelled else [tag for tag in tags if tag.startswith(tuple(project_prefixes))]
        if not refs and labelled:
            refs = [image_id]
        for ref in refs:
            print(f"{'Would remove' if args.dry_run else 'Removing'} {ref}")
            if not args.dry_run:
                result = subprocess.run([os.environ.get("DOCKER", "docker"), "image", "rm", ref], check=False)
                if result.returncode:
                    failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"Docker image cleanup failed: {exc}", file=sys.stderr)
        sys.exit(1)
