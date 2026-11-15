#!/usr/bin/env python3
"""Resolve SCRS image templates without evaluating dotenv as shell code."""
import datetime
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys


def image_key():
    """The .env key holding the image to resolve: SCRS_IMAGE, or SCRS_SAST_IMAGE
    and SCRS_QA_RUNNER_IMAGE for the other release targets."""
    key = os.environ.get('SCRS_IMAGE_KEY') or 'SCRS_IMAGE'
    if key not in ('SCRS_IMAGE', 'SCRS_SAST_IMAGE', 'SCRS_QA_RUNNER_IMAGE'):
        raise ValueError('SCRS_IMAGE_KEY must be SCRS_IMAGE, SCRS_SAST_IMAGE or SCRS_QA_RUNNER_IMAGE')
    return key


def configured_image():
    """SCRS_IMAGE from the environment (Make passes the command-line or
    environment value of the selected key), else the selected key in .env."""
    if os.environ.get('SCRS_IMAGE'):
        return os.environ['SCRS_IMAGE']
    key = image_key()
    path = Path('.env')
    if path.exists():
        for line in path.read_text().splitlines():
            if line.startswith(key + '='):
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
    key = image_key()
    if not reference:
        raise ValueError(f'Set {key} (in .env or on the make command line) to registry/namespace/image:scrs_YYYY_MM_DD_v{{shortSHA256}}')
    reference = reference.replace('YYYY_MM_DD', datetime.datetime.now(datetime.timezone.utc).strftime('%Y_%m_%d'))
    if '{shortSHA256}' in reference:
        reference = reference.replace('{shortSHA256}', source_digest())
    repository, separator, tag = reference.rpartition(':')
    if not separator or not valid_repository(repository) or not re.fullmatch(r'scrs_[A-Za-z0-9_.-]{1,122}', tag):
        raise ValueError(f'{key} needs a full repository and a tag; use a tag beginning scrs_ (for example registry/namespace/image:scrs_sast_YYYY_MM_DD_v{{shortSHA256}})')
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
