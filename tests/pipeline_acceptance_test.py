import importlib.util
import io
import json
import os
import pathlib
import tarfile
import unittest
from unittest.mock import patch

path = pathlib.Path(__file__).resolve().parents[1] / 'scripts/pipeline_acceptance.py'
spec = importlib.util.spec_from_file_location('pipeline_acceptance', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

HEALTHY = {'status': 'ok', 'components': {name: {'status': 'ok'} for name in ('postgres', 'redis', 's3', 'worker', 'scanner')}}
ASSESSMENT = '5d1a7c34-82f0-4e0b-b6c1-7a9e2f3d4b10'
ASSET = '0b6f1c1e-3d52-4a6e-9f4a-1d2c3b4a5e60'
COMMIT = 'a' * 40


def server(status='succeeded', stages=None, vulnerabilities=1, sbom=True, platform=HEALTHY):
    stages = stages if stages is not None else [{'name': n, 'status': 'ok'} for n in ('resolve', 'fetch', 'inventory', 'sbom', 'match_vuln')]
    seen = []

    def call(method, path, body=None, headers=None):
        seen.append((method, path))
        if path == '/system/status':
            return 200, platform
        if path == '/uploads':
            assert method == 'POST' and b'name="name"' in body and headers['Content-Type'].startswith('multipart/form-data')
            return 201, {'asset': {'id': ASSET}, 'upload': {'size': 100, 'commit': COMMIT}, 'assessment': {'id': ASSESSMENT, 'status': 'queued'}}
        if path.startswith(f'/assessments/{ASSESSMENT}?wait'):
            return 200, {'id': ASSESSMENT, 'status': status, 'verdict': 'warn', 'stages': stages, 'error': 'boom' if status == 'failed' else ''}
        if path.endswith('/findings'):
            return 200, {'items': [{'type': 'vulnerability'}] * vulnerabilities}
        if path.endswith('/sbom'):
            return (200, {'bomFormat': 'CycloneDX', 'components': [{'name': 'lodash'}]}) if sbom else (404, {})
        if path.startswith('/jobs'):
            return 200, {'items': [{'id': ASSESSMENT, 'status': status}]}
        if path.endswith('/revisions'):
            return 200, {'items': [{'commit': COMMIT}]}
        if path == '/register/summary':
            return 200, {'total': 3}
        return 404, {}
    return call, seen


class PipelineAcceptanceTest(unittest.TestCase):
    def run_checks(self, **kwargs):
        call, seen = server(**kwargs)
        result = module.Result()
        with patch('builtins.print'):
            module.run(call, result, timeout=10, sleep=lambda s: None)
        return result, seen

    def test_archive_is_a_gzip_tar_with_the_vulnerable_lockfile(self):
        data = module.archive('run')
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
            names = tar.getnames()
            lock = json.load(tar.extractfile('package-lock.json'))
        self.assertEqual(names, ['package-lock.json', 'package.json'])
        self.assertEqual(lock['packages']['node_modules/lodash']['version'], '4.17.11')
        self.assertNotEqual(module.archive('run'), module.archive('another'), 'each run is a new revision')

    def test_healthy_deployment_passes(self):
        result, seen = self.run_checks()
        self.assertEqual((result.failures, result.warnings), (0, 0))
        self.assertIn(('GET', '/register/summary'), seen)

    def test_an_empty_osv_mirror_warns_without_failing(self):
        result, _ = self.run_checks(vulnerabilities=0)
        self.assertEqual((result.failures, result.warnings), (0, 1))

    def test_a_missing_required_stage_fails(self):
        stages = [{'name': n, 'status': 'ok'} for n in ('resolve', 'fetch', 'inventory')]
        result, _ = self.run_checks(stages=stages)
        self.assertEqual(result.failures, 1)

    def test_a_partial_optional_stage_warns(self):
        stages = [{'name': n, 'status': 'ok'} for n in ('resolve', 'fetch', 'inventory', 'sbom')] + [{'name': 'malware', 'status': 'partial', 'detail': 'ClamAV down'}]
        result, _ = self.run_checks(stages=stages)
        self.assertEqual((result.failures, result.warnings), (0, 1))  # the partial malware stage

    def test_a_failed_assessment_fails(self):
        result, _ = self.run_checks(status='failed')
        self.assertEqual(result.failures, 1)

    def test_a_down_component_fails(self):
        broken = {'status': 'down', 'components': {'redis': {'status': 'down', 'detail': 'unreachable'}}}
        result, _ = self.run_checks(platform=broken)
        self.assertEqual(result.failures, 2)

    def test_a_stuck_assessment_times_out(self):
        call, _ = server()
        ticks = iter(range(0, 1000, 5))

        def stuck(method, path, body=None, headers=None):
            status, payload = call(method, path, body, headers)
            if path.startswith(f'/assessments/{ASSESSMENT}?wait'):
                payload = dict(payload, status='running')
            return status, payload
        result = module.Result()
        with patch('builtins.print'):
            module.run(stuck, result, timeout=20, sleep=lambda s: None, clock=lambda: next(ticks))
        self.assertEqual(result.failures, 1)

    def test_the_script_refuses_insecure_urls_and_missing_tokens(self):
        for url in ['', 'http://example.com', 'https://user:pw@example.com', 'https://example.com/other']:
            with self.subTest(url=url), patch.dict(os.environ, {'SCRS_PUBLIC_BASE_URL': url}, clear=True):
                with self.assertRaises(ValueError):
                    module.main()
        with patch.dict(os.environ, {'SCRS_PUBLIC_BASE_URL': 'https://example.com'}, clear=True):
            with self.assertRaisesRegex(ValueError, 'SCRS_ACCEPTANCE_WRITE_TOKEN'):
                module.main()
        with patch.dict(os.environ, {'SCRS_PUBLIC_BASE_URL': 'https://example.com', 'SCRS_ACCEPTANCE_WRITE_TOKEN': 'x', 'SCRS_ACCEPTANCE_TIMEOUT': '1'}, clear=True):
            with self.assertRaisesRegex(ValueError, 'between 10 and 3600'):
                module.main()


if __name__ == '__main__':
    unittest.main()
