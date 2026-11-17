#!/usr/bin/env python3
"""End-to-end pipeline acceptance for a deployed SCRS; never prints credentials.

Unlike deployment_acceptance.py this writes: it uploads a tiny source archive
as the asset `upload/scrs-acceptance` and follows the assessment through the
real worker, scanner, ClamAV, object storage and database. It needs a token
with the `write` scope (SCRS_ACCEPTANCE_WRITE_TOKEN) and leaves one asset
behind; every run adds one revision to it.

Set SCRS_PUBLIC_BASE_URL (https only). SCRS_ACCEPTANCE_TIMEOUT is the seconds
to wait for the assessment (default 300).
"""
import gzip
import io
import json
import os
import ssl
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ASSET_NAME = 'scrs-acceptance'
# Stages a deployment cannot do without; others report WARN because a feed
# that has not synced yet or an optional scanner must not fail the run.
REQUIRED_STAGES = ('resolve', 'fetch', 'inventory', 'sbom')
FINISHED = ('succeeded', 'failed', 'cancelled')


class Result:
    def __init__(self):
        self.failures = 0
        self.warnings = 0

    def passed(self, message):
        print('PASS ' + message)

    def warn(self, message):
        self.warnings += 1
        print('WARN ' + message)

    def fail(self, message):
        self.failures += 1
        print('FAIL ' + message)


def archive(run_id):
    """A source tree with one known-vulnerable npm dependency (lodash 4.17.11)."""
    files = {
        'package.json': json.dumps({'name': 'scrs-acceptance', 'version': '1.0.0', 'description': run_id, 'dependencies': {'lodash': '4.17.11'}}),
        'package-lock.json': json.dumps({
            'name': 'scrs-acceptance', 'version': '1.0.0', 'lockfileVersion': 3, 'requires': True,
            'packages': {
                '': {'name': 'scrs-acceptance', 'version': '1.0.0', 'dependencies': {'lodash': '4.17.11'}},
                'node_modules/lodash': {'version': '4.17.11', 'resolved': 'https://registry.npmjs.org/lodash/-/lodash-4.17.11.tgz'},
            },
        }),
    }
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode='wb', mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w') as tar:
            for name, text in sorted(files.items()):
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size, info.mtime, info.mode = len(data), 0, 0o644
                tar.addfile(info, io.BytesIO(data))
    return out.getvalue()


def multipart(fields, filename, data):
    boundary = uuid.uuid4().hex
    parts = []
    for key, value in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode())
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\nContent-Type: application/gzip\r\n\r\n'.encode() + data + b'\r\n')
    parts.append(f'--{boundary}--\r\n'.encode())
    return b''.join(parts), 'multipart/form-data; boundary=' + boundary


def run(call, result, timeout=300, sleep=time.sleep, clock=time.monotonic):
    """Runs the checks through call(method, path, body=None, headers=None) -> (status, parsed body or bytes)."""
    status, body = call('GET', '/system/status')
    if status != 200 or not isinstance(body, dict):
        result.fail(f'/system/status: HTTP {status}')
    else:
        overall = body.get('status')
        (result.passed if overall == 'ok' else result.fail if overall == 'down' else result.warn)(f'platform status is {overall}')
        for name, component in sorted(body.get('components', {}).items()):
            state = component.get('status')
            if state not in ('ok', 'not_configured'):
                (result.fail if name in ('postgres', 'redis', 's3', 'worker', 'scanner') else result.warn)(f'component {name} is {state}: {component.get("detail", "")}')
    run_id = uuid.uuid4().hex
    payload, content_type = multipart({'name': ASSET_NAME, 'ref': 'acceptance'}, 'acceptance.tar.gz', archive(run_id))
    status, body = call('POST', '/uploads', payload, {'Content-Type': content_type, 'Idempotency-Key': 'acceptance-' + run_id})
    if status not in (200, 201) or not isinstance(body, dict) or not body.get('assessment'):
        result.fail(f'POST /uploads: HTTP {status} {body.get("error", "") if isinstance(body, dict) else ""}'.strip())
        return
    asset, upload, assessment = body['asset']['id'], body['upload'], body['assessment']['id']
    result.passed(f'archive of {upload["size"]} bytes stored as revision {upload["commit"][:12]}; assessment queued')
    deadline = clock() + timeout
    current = body['assessment']
    while current.get('status') not in FINISHED:
        if clock() > deadline:
            result.fail(f'assessment {assessment} still {current.get("status")} after {timeout} s: check the worker and scanner logs and GET /jobs')
            return
        status, polled = call('GET', f'/assessments/{assessment}?wait=30')
        if status != 200 or not isinstance(polled, dict):
            result.fail(f'GET /assessments/{assessment}: HTTP {status}')
            return
        current = polled
        if current.get('status') not in FINISHED:
            sleep(2)
    if current['status'] != 'succeeded':
        result.fail(f'assessment ended {current["status"]}: {current.get("error", "")}')
        return
    result.passed(f'assessment succeeded with verdict {current.get("verdict")}')
    stages = {s['name']: s for s in current.get('stages', [])}
    for name in REQUIRED_STAGES:
        stage = stages.get(name)
        if stage and stage.get('status') == 'ok':
            result.passed(f'stage {name} ok')
        else:
            result.fail(f'stage {name} is {stage.get("status") if stage else "missing"}: {stage.get("detail", "") if stage else ""}'.strip())
    for name, stage in sorted(stages.items()):
        if name not in REQUIRED_STAGES and stage.get('status') not in ('ok', 'skipped'):
            result.warn(f'stage {name} is {stage.get("status")}: {stage.get("detail", "")}')
    status, findings = call('GET', f'/assessments/{assessment}/findings')
    vulnerabilities = [f for f in findings.get('items', []) if f.get('type') == 'vulnerability'] if status == 200 and isinstance(findings, dict) else []
    if vulnerabilities:
        result.passed(f'{len(vulnerabilities)} vulnerability entries for lodash 4.17.11 (the OSV mirror is populated)')
    else:
        result.warn('no vulnerability found for lodash 4.17.11: the OSV mirror may not have synced yet (GET /intel/vulnerability-sources)')
    status, sbom = call('GET', f'/assessments/{assessment}/sbom')
    if status == 200 and isinstance(sbom, dict) and sbom.get('bomFormat') == 'CycloneDX' and 'lodash' in json.dumps(sbom):
        result.passed('CycloneDX SBOM stored and readable')
    else:
        result.fail(f'GET /assessments/{assessment}/sbom: HTTP {status} or not a CycloneDX document naming lodash')
    status, jobs = call('GET', f'/jobs?kind=assessment&asset_id={asset}&limit=5')
    if status == 200 and isinstance(jobs, dict) and any(j.get('id') == assessment and j.get('status') == 'succeeded' for j in jobs.get('items', [])):
        result.passed('the job list shows the assessment as succeeded')
    else:
        result.fail(f'GET /jobs does not list assessment {assessment} as succeeded (HTTP {status})')
    status, revisions = call('GET', f'/assets/{asset}/revisions')
    if status == 200 and isinstance(revisions, dict) and any(r.get('commit') == upload['commit'] for r in revisions.get('items', [])):
        result.passed('the revision list names the uploaded archive')
    else:
        result.fail(f'GET /assets/{asset}/revisions does not list revision {upload["commit"][:12]} (HTTP {status})')
    status, summary = call('GET', '/register/summary')
    if status == 200 and isinstance(summary, dict) and 'total' in summary:
        result.passed(f'register summary readable ({summary["total"]} entries)')
    else:
        result.fail(f'GET /register/summary: HTTP {status}')


def main():
    raw = os.environ.get('SCRS_PUBLIC_BASE_URL', '').rstrip('/')
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/scrs/v1'):
        raise ValueError('Set SCRS_PUBLIC_BASE_URL to https://your-domain or https://your-domain/scrs/v1')
    base = raw if parsed.path else raw + '/scrs/v1'
    token = os.environ.get('SCRS_ACCEPTANCE_WRITE_TOKEN')
    if not token:
        raise ValueError('Set SCRS_ACCEPTANCE_WRITE_TOKEN to a token with the write scope')
    try:
        timeout = int(os.environ.get('SCRS_ACCEPTANCE_TIMEOUT', '300'))
    except ValueError:
        raise ValueError('SCRS_ACCEPTANCE_TIMEOUT must be a number of seconds') from None
    if not 10 <= timeout <= 3600:
        raise ValueError('SCRS_ACCEPTANCE_TIMEOUT must be between 10 and 3600')
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def call(method, path, body=None, headers=None):
        request = urllib.request.Request(base + path, data=body, method=method, headers={'Accept': 'application/json', 'Authorization': 'Bearer ' + token, **(headers or {})})
        try:
            response = opener.open(request, timeout=60)
        except urllib.error.HTTPError as exc:
            response = exc
        except (urllib.error.URLError, OSError):
            raise ValueError(f'{method} {path}: connection or TLS verification failed') from None
        with response:
            data = response.read((32 << 20) + 1)
            if len(data) > 32 << 20:
                raise ValueError(f'{method} {path}: response too large')
            try:
                return response.code, json.loads(data)
            except ValueError:
                return response.code, data

    result = Result()
    run(call, result, timeout)
    print(f'{result.failures} failed, {result.warnings} warnings')
    if result.failures == 0:
        print('Pipeline acceptance passed. Restart recovery, certificate renewal, load and disaster recovery still need their own evidence (docs/STAGING_ACCEPTANCE.md).')
    return 1 if result.failures else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except ValueError as exc:
        sys.exit(f'Acceptance failed: {exc}')
