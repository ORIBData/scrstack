#!/usr/bin/env python3
"""Read-only HTTPS acceptance for the deployed SCRS API; never prints credentials."""
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def main():
    raw = os.environ.get('SCRS_PUBLIC_BASE_URL', '').rstrip('/')
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/scrs/v1'):
        raise ValueError('Set SCRS_PUBLIC_BASE_URL to https://your-domain or https://your-domain/scrs/v1')
    base = raw if parsed.path else raw + '/scrs/v1'
    token = os.environ.get('SCRS_ACCEPTANCE_API_TOKEN') or os.environ.get('SCRS_BOOTSTRAP_API_TOKEN')
    if not token:
        raise ValueError('Set SCRS_ACCEPTANCE_API_TOKEN to a read-scoped token (or provide the bootstrap token)')
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    def check(path, expected, authenticated=False, validate=None):
        headers = {'Accept': 'application/json'}
        if authenticated:
            headers['Authorization'] = 'Bearer ' + token
        req = urllib.request.Request(base + path, headers=headers)
        try:
            response = opener.open(req, timeout=15)
        except urllib.error.HTTPError as exc:
            response = exc
        except (urllib.error.URLError, OSError):
            raise ValueError(f'{path}: connection or TLS verification failed') from None
        with response:
            body = response.read((4 << 20) + 1)
            if response.code != expected or len(body) > 4 << 20:
                raise ValueError(f'{path}: expected HTTP {expected}, received {response.code}')
            if validate and not validate(body):
                raise ValueError(f'{path}: unexpected response contract')
        print(f'PASS {path}: HTTP {expected}')
    check('/system/healthz', 200)
    check('/system/readyz', 200)
    check('/assessments', 401)
    check('/assessments', 200, True, lambda b: isinstance(json.loads(b).get('items'), list))
    private_docs = os.environ.get('SCRS_DOCS_PUBLIC', 'true').lower() == 'false'
    check('/docs', 200, private_docs)
    check('/docs/openapi.yaml', 200, private_docs, lambda b: b'url: /scrs/v1' in b and b'/assessments:' in b)
    check('/remediation/capabilities', 200, True, lambda b: json.loads(b).get('enabled') is True)
    print('HTTPS API acceptance passed. Certificate renewal, restart recovery, load and disaster recovery require separate operational evidence.')

if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        sys.exit(f'Acceptance failed: {exc}')
