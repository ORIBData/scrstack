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
            'SCRS_EMBED_API_KEY': 'synthetic-embed-key-at-least-32-characters',
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

        # Self-hosted embeddings: internal only, pinned by digest, holding none
        # of the platform's secrets, and no text can leave to a hosted provider
        # because the worker reaches it over the internal network only.
        embed = config['services']['scrs-embed']
        self.assertIn('@sha256:', embed['image'])
        self.assertEqual(set(embed['networks']), {'embed', 'embed-fetch'})
        self.assertTrue(config['networks']['embed']['internal'])
        self.assertNotIn('proxy', embed['networks'])
        self.assertEqual(embed['labels']['traefik.enable'], 'false')
        self.assertFalse(set(embed['environment']) & {'SCRS_MASTER_KEY', 'SCRS_DATABASE_URL', 'SCRS_S3_SECRET_KEY', 'SCRS_BOOTSTRAP_API_TOKEN', 'SCRS_SCANNER_API_TOKEN', 'SCRS_QA_RUNNER_TOKEN', 'SCRS_SAST_API_TOKEN'})
        self.assertEqual(embed['environment']['AUTO_TRUNCATE'], 'false')
        self.assertIn('embed', config['services']['scrs-worker']['networks'])
        self.assertNotIn('embed', api['networks'])
        self.assertEqual(config['services']['scrs-worker']['environment']['SCRS_EMBED_API_KEY'], embed['environment']['API_KEY'])
        # LLM providers declared in the environment: the API holds the declarations
        # and the sealing key; source code to a hosted provider is off by default
        # in both services, and hosted spend has a monthly ceiling.
        api_env = config['services']['scrs-api']['environment']
        worker_env = config['services']['scrs-worker']['environment']
        for name in ('HOSTED', 'LOCAL'):
            for field in ('KIND', 'MODEL', 'BASE_URL', 'API_KEY', 'MAX_TOKENS', 'TEMPERATURE', 'ALLOW_SOURCE'):
                self.assertIn(f'SCRS_LLM_PROVIDER_{name}_{field}', api_env)
                self.assertNotIn(f'SCRS_LLM_PROVIDER_{name}_{field}', worker_env, 'the worker reads providers from the database; it needs no provider key in its environment')
        self.assertEqual(api_env['SCRS_LLM_ALLOW_SOURCE_TO_HOSTED'], 'false')
        self.assertEqual(worker_env['SCRS_LLM_ALLOW_SOURCE_TO_HOSTED'], 'false')
        self.assertEqual(worker_env['SCRS_LLM_MONTHLY_INPUT_TOKENS'], '20000000')
        self.assertEqual(worker_env['SCRS_LLM_MONTHLY_OUTPUT_TOKENS'], '4000000')
        self.assertEqual(config['services']['scrs-worker']['environment']['SCRS_EMBED_URL'], 'http://scrs-embed:80/v1')
        self.assertEqual(config['services']['scrs-worker']['environment']['SCRS_EMBED_MAX_CHARS'], '1500')

    @unittest.skipUnless(shutil.which('docker'), 'Docker Compose CLI required')
    def test_model_host_exposes_only_v1_behind_allowlist_and_key(self):
        values = {'SCRS_MODEL_DOMAIN': 'model.staging.example.com', 'SCRS_MODEL_API_KEY': 'synthetic-model-key-at-least-32-characters'}
        with tempfile.NamedTemporaryFile(mode='w') as env:
            env.write('\n'.join(f'{key}={value}' for key,value in values.items())); env.flush()
            result = subprocess.run(['docker','compose','--env-file',env.name,'-f',str(ROOT/'deploy/compose.model-host.yaml'),'config','--format','json'],env={'PATH':os.environ['PATH'],'HOME':os.environ['HOME']},capture_output=True,text=True,check=True)
        model = json.loads(result.stdout)['services']['scrs-model']
        labels = model['labels']
        # Only /v1 is routed: the server's other endpoints are never exposed.
        self.assertEqual(labels['traefik.http.routers.scrs-model.rule'], 'Host(`model.staging.example.com`) && PathPrefix(`/v1`)')
        self.assertEqual(labels['traefik.http.routers.scrs-model.tls.certresolver'], 'letsencrypt')
        # The allowlist admits nobody until the SCRS machine is named.
        self.assertEqual(labels['traefik.http.middlewares.scrs-model-allow.ipallowlist.sourcerange'], '127.0.0.1/32')
        self.assertEqual(labels['traefik.http.routers.scrs-model-http.middlewares'], 'scrs-model-https')
        # Rate limit and a body cap sit in front of the server, after the allowlist.
        self.assertEqual(labels['traefik.http.routers.scrs-model.middlewares'], 'scrs-model-allow,scrs-model-limit,scrs-model-body')
        self.assertEqual(labels['traefik.http.middlewares.scrs-model-limit.ratelimit.average'], '5')
        self.assertEqual(labels['traefik.http.middlewares.scrs-model-body.buffering.maxrequestbodybytes'], '4194304')
        self.assertEqual(model['environment']['LLAMA_ARG_ENDPOINT_SLOTS'], '0')
        self.assertEqual(model['environment']['LLAMA_API_KEY'], values['SCRS_MODEL_API_KEY'])
        self.assertIn('@sha256:', model['image'])
        self.assertEqual(model['environment']['LLAMA_ARG_N_PARALLEL'], '1')
        self.assertNotIn('ports', model)
        self.assertIn('--no-webui', model['command'])
        # No platform secret belongs on this machine.
        self.assertFalse(set(model['environment']) & {'SCRS_MASTER_KEY', 'SCRS_DATABASE_URL', 'SCRS_S3_SECRET_KEY', 'SCRS_BOOTSTRAP_API_TOKEN'})
        # The key is required: the file does not render without it.
        with tempfile.NamedTemporaryFile(mode='w') as env:
            env.write('SCRS_MODEL_DOMAIN=model.staging.example.com\n'); env.flush()
            missing = subprocess.run(['docker','compose','--env-file',env.name,'-f',str(ROOT/'deploy/compose.model-host.yaml'),'config','-q'],env={'PATH':os.environ['PATH'],'HOME':os.environ['HOME']},capture_output=True,text=True)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn('SCRS_MODEL_API_KEY', missing.stderr)
