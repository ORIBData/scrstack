#!/usr/bin/env python3
"""Resolve SCRS image templates without evaluating dotenv as shell code."""
import datetime
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys


def configured_image():
    if os.environ.get('SCRS_IMAGE'):
        return os.environ['SCRS_IMAGE']
    path = Path('.env')
    if path.exists():
        for line in path.read_text().splitlines():
            if line.startswith('SCRS_IMAGE='):
                return line.split('=', 1)[1].strip().strip('\"\'')
    return ''


def valid_repository(value):
    return bool(re.fullmatch(r'[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+', value))


def source_digest():
    names = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard']).split(b'\0')
    digest = hashlib.sha256()
    for raw in sorted(set(names)):
        if not raw:
            continue
        path = Path(os.fsdecode(raw))
        if path.name.startswith('.env') or not path.is_file():
            continue
        content = path.read_bytes()
        digest.update(raw + b'\0' + str(len(content)).encode() + b'\0' + content)
    return digest.hexdigest()[:12]


def resolve():
    reference = configured_image()
    repository = os.environ.get('DOCKERHUB_REPO', '')
    version = os.environ.get('VERSION', '')
    if repository:
        reference = repository + ':' + (version or 'scrs_YYYY_MM_DD_v{shortSHA256}')
    elif version and reference:
        reference = reference.rsplit(':', 1)[0] + ':' + version
    if not reference:
        raise ValueError('Set SCRS_IMAGE to registry/namespace/image:scrs_YYYY_MM_DD_v{shortSHA256}')
    reference = reference.replace('YYYY_MM_DD', datetime.datetime.now(datetime.timezone.utc).strftime('%Y_%m_%d'))
    if '{shortSHA256}' in reference:
        reference = reference.replace('{shortSHA256}', source_digest())
    repository, separator, tag = reference.rpartition(':')
    if not separator or not valid_repository(repository) or not re.fullmatch(r'scrs_[A-Za-z0-9_.-]{1,122}', tag):
        raise ValueError('SCRS_IMAGE needs a full repository and a tag; use a tag beginning scrs_')
    return reference


if __name__ == '__main__':
    try:
        reference = resolve()
        if len(sys.argv) == 1:
            print(reference)
        else:
            env = os.environ.copy()
            env['SCRS_IMAGE'] = reference
            os.execvpe(sys.argv[1], sys.argv[1:], env)
    except ValueError as exc:
        sys.exit(str(exc))
