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
