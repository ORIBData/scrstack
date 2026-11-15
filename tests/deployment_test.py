import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class DeploymentTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which('docker'), 'Docker Compose CLI required')
    def test_traefik_labels_and_secret_boundaries(self):
        values = {
            'SCRS_IMAGE': 'example/scrs:scrs_2026_11_12_v123456abcdef',
            'SCRS_DOMAIN': 'scrs.staging.example.com',
            'SCRS_ROUTER_NAME': 'scrs-staging',
            'SCRS_DATABASE_URL': 'postgres://synthetic:synthetic@db/scrs',
            'SCRS_DATABASE_ADMIN_URL': 'postgres://bootstrap:synthetic@db/postgres',
            'SCRS_REDIS_QUEUE_URL': 'redis://redis/0',
            'SCRS_S3_ENDPOINT': 'https://s3.example.com',
            'SCRS_S3_REGION': 'test-region', 'SCRS_S3_BUCKET': 'test-bucket',
            'SCRS_S3_ACCESS_KEY': 'synthetic', 'SCRS_S3_SECRET_KEY': 'synthetic',
            'SCRS_SCANNER_API_TOKEN': 'synthetic-scanner-token-at-least-32-characters',
            'SCRS_MASTER_KEY': 'synthetic', 'SCRS_BOOTSTRAP_API_TOKEN': 'synthetic-token',
            'SCRS_QA_RUNNER_IMAGE': 'example/scrs-qa-runner:scrs_2026_11_14_v123456abcdef',
            'SCRS_QA_RUNNER_TOKEN': 'synthetic-runner-token-at-least-32-characters',
            'SCRS_QA_DOMAIN': 'qa-runner.staging.example.com',
            'SCRS_QA_ROUTER_NAME': 'scrs-qa-staging',
            'SCRS_SAST_IMAGE': 'example/scrs-sast:scrs_2026_11_15_v123456abcdef',
            'SCRS_SAST_API_TOKEN': 'synthetic-sast-token-at-least-32-characters',
        }
        with tempfile.NamedTemporaryFile(mode='w') as env:
            env.write('\n'.join(f'{key}={value}' for key,value in values.items())); env.flush()
            result = subprocess.run(['docker','compose','--env-file',env.name,'-f',str(ROOT/'deploy/compose.dokploy.yaml'),'config','--format','json'],env={'PATH':os.environ['PATH'],'HOME':os.environ['HOME']},capture_output=True,text=True,check=True)
        config=json.loads(result.stdout)
        api=config['services']['scrs-api']; labels=api['labels']
        self.assertNotIn('ports',api)
        self.assertNotIn('SCRS_DATABASE_ADMIN_URL',api['environment'])
        self.assertIn('proxy',api['networks'])
        self.assertEqual(labels['traefik.http.routers.scrs-staging.tls.certresolver'],'letsencrypt')
        self.assertIn('PathPrefix(`/scrs/v1/`)',labels['traefik.http.routers.scrs-staging.rule'])
        self.assertIn('Host(`scrs.staging.example.com`)',labels['traefik.http.routers.scrs-staging.rule'])
        self.assertEqual(labels['traefik.http.middlewares.scrs-staging-https.redirectscheme.scheme'],'https')
        self.assertFalse(any('stripprefix' in key.lower() for key in labels))
        self.assertEqual(config['services']['scrs-storage-init']['labels']['traefik.enable'],'false')

        scanner=config['services']['scrs-scanner']
        self.assertEqual(set(scanner['networks']), {'scanning'})
        self.assertTrue(config['networks']['scanning']['internal'])
        for service in ['scrs-scanner', 'scrs-feed-sync', 'scrs-egress-proxy', 'scrs-clamav']:
            env=config['services'][service].get('environment', {})
            self.assertFalse(set(env) & {'SCRS_MASTER_KEY', 'SCRS_DATABASE_URL', 'SCRS_S3_SECRET_KEY', 'SCRS_BOOTSTRAP_API_TOKEN'})
            self.assertNotIn('ports', config['services'][service])
        self.assertEqual(scanner['environment']['SCRS_REMEDIATION_ENABLED'], 'true')

        # The Karate runner: its own router and hostname, private qa network
        # shared with the API and worker, and no SCRS secrets.
        runner=config['services']['scrs-qa-runner']; rl=runner['labels']
        self.assertEqual(runner['image'], 'example/scrs-qa-runner:scrs_2026_11_14_v123456abcdef')
        self.assertEqual(set(runner['networks']), {'qa', 'proxy'})
        self.assertTrue(config['networks']['qa']['internal'])
        self.assertIn('qa', config['services']['scrs-worker']['networks'])
        self.assertIn('qa', api['networks'])
        self.assertNotIn('ports', runner)
        self.assertEqual(rl['traefik.http.routers.scrs-qa-staging.rule'], 'Host(`qa-runner.staging.example.com`)')
        self.assertEqual(rl['traefik.http.services.scrs-qa-staging.loadbalancer.server.port'], '8090')
        self.assertEqual(rl['traefik.http.routers.scrs-qa-staging.middlewares'], 'scrs-qa-staging-allow')
        self.assertEqual(rl['traefik.http.middlewares.scrs-qa-staging-allow.ipallowlist.sourcerange'], '127.0.0.1/32')
        self.assertFalse(set(runner['environment']) & {'SCRS_MASTER_KEY', 'SCRS_DATABASE_URL', 'SCRS_S3_SECRET_KEY', 'SCRS_BOOTSTRAP_API_TOKEN', 'SCRS_SCANNER_API_TOKEN'})
        self.assertEqual(runner['environment']['SCRS_QA_RUNNER_JOB_UID'], '10001')
        self.assertEqual(runner['cap_drop'], ['ALL'])
        self.assertTrue(runner['read_only'])
        self.assertEqual(config['services']['scrs-worker']['environment']['SCRS_QA_RUNNER_URL'], 'http://scrs-qa-runner:8090')
        self.assertEqual(config['services']['scrs-worker']['environment']['SCRS_QA_RUNNER_TOKEN'], runner['environment']['SCRS_QA_RUNNER_TOKEN'])

        # The SAST analyzers: internal sast network only, out only through the
        # go-modules egress proxy, no SCRS secrets, never published.
        sast=config['services']['scrs-sast']
        self.assertEqual(sast['image'], 'example/scrs-sast:scrs_2026_11_15_v123456abcdef')
        self.assertEqual(set(sast['networks']), {'sast'})
        self.assertTrue(config['networks']['sast']['internal'])
        self.assertNotIn('ports', sast)
        self.assertEqual(sast['labels']['traefik.enable'], 'false')
        self.assertEqual(sast['cap_drop'], ['ALL'])
        self.assertTrue(sast['read_only'])
        self.assertFalse(set(sast['environment']) & {'SCRS_MASTER_KEY', 'SCRS_DATABASE_URL', 'SCRS_S3_SECRET_KEY', 'SCRS_BOOTSTRAP_API_TOKEN', 'SCRS_SCANNER_API_TOKEN', 'SCRS_QA_RUNNER_TOKEN'})
        self.assertEqual(sast['environment']['SCRS_SAST_GO_PROXY'], 'http://scrs-sast-egress:8082')
        egress=config['services']['scrs-sast-egress']
        self.assertEqual(egress['environment']['SCRS_EGRESS_PROFILE'], 'go-modules')
        self.assertEqual(set(egress['networks']), {'default', 'sast'})
        self.assertIn('sast', config['services']['scrs-worker']['networks'])
        self.assertIn('sast', api['networks'])
        self.assertEqual(config['services']['scrs-worker']['environment']['SCRS_SAST_API_TOKEN'], sast['environment']['SCRS_SAST_API_TOKEN'])
        self.assertEqual(config['services']['scrs-worker']['environment']['SCRS_SAST_ENABLED'], 'false')
