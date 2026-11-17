import json
import os
import pathlib
import pty
import select
import subprocess
import tempfile
import time
import unittest


RELEASE = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "release.sh"


class ReleaseTest(unittest.TestCase):
    def test_shared_repository_rejects_generic_staging_tag(self):
        with tempfile.TemporaryDirectory() as directory:
            pathlib.Path(directory, ".env").write_text("SCRS_IMAGE=oribdata/zerorate-stg:scrs_v123\n")
            fake_docker = pathlib.Path(directory, "docker")
            fake_docker.write_text("#!/bin/sh\nif [ \"$1\" = context ]; then echo unix:///tmp/synthetic.sock; exit 0; fi\nexit 99\n")
            fake_docker.chmod(0o700)
            master, slave = pty.openpty()
            env = os.environ.copy()
            env.update(DOCKER=str(fake_docker), DOCKERHUB_REPO="oribdata/zerorate-stg", VERSION="staging")
            env.pop("DOCKER_HOST", None)
            process = subprocess.Popen(["bash", str(RELEASE)], stdin=slave, stdout=slave, stderr=slave, env=env, cwd=directory)
            os.close(slave)
            os.write(master, b"orishane\n")
            output = bytearray()
            deadline = time.monotonic() + 5
            while process.poll() is None and time.monotonic() < deadline:
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        output.extend(os.read(master, 4096))
                    except OSError:
                        break
            if process.poll() is None:
                process.kill()
            status = process.wait(timeout=2)
            os.close(master)
            self.assertEqual(status, 2, output.decode(errors="replace"))
            self.assertIn("use a tag beginning scrs_", output.decode(errors="replace"))

    def test_uses_explicit_repo_and_preserves_engine_with_isolated_login(self):
        self.check_registry_release(False)

    def test_gar_login_and_repository(self):
        self.check_registry_release(True)

    def test_build_cloud_builder_from_dotenv(self):
        self.check_registry_release(False, cloud="oribdata/creditchek-stg-ci")

    def test_build_cloud_rejects_non_docker_hub_and_bad_names(self):
        for dotenv, extra in (
            ("SCRS_BUILD_CLOUD=oribdata/creditchek-stg-ci\n", {"DOCKERHUB_REPO": "", "SCRS_IMAGE": "europe-west2-docker.pkg.dev/p/r/scrs:scrs_staging"}),
            ("SCRS_BUILD_CLOUD=not a builder; rm -rf /\n", {}),
        ):
            with tempfile.TemporaryDirectory() as directory:
                pathlib.Path(directory, ".env").write_text(dotenv)
                fake_docker = pathlib.Path(directory, "docker")
                fake_docker.write_text("#!/bin/sh\nif [ \"$1\" = context ]; then echo unix:///tmp/synthetic.sock; exit 0; fi\nexit 99\n")
                fake_docker.chmod(0o700)
                env = os.environ.copy()
                env.update(DOCKER=str(fake_docker), DOCKERHUB_REPO="oribdata/zerorate-stg", VERSION="scrs_staging", SCRS_IMAGE="", SCRS_BUILD_CLOUD="")
                env.update(extra)
                env.pop("DOCKER_HOST", None)
                result = subprocess.run(["bash", str(RELEASE)], stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, cwd=directory, timeout=10)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("SCRS_BUILD_CLOUD", result.stderr)

    def check_registry_release(self, gar, cloud=""):
        with tempfile.TemporaryDirectory() as directory:
            fake_docker = pathlib.Path(directory, "docker")
            log = pathlib.Path(directory, "calls.jsonl")
            fake_docker.write_text("""#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
if args[:2] == ['context', 'inspect']:
    print('unix:///tmp/synthetic-docker.sock')
    sys.exit(0)
if args == ['info']:
    assert os.environ.get('DOCKER_HOST') == 'unix:///tmp/synthetic-docker.sock'
    assert pathlib.Path(os.environ['DOCKER_CONFIG']).is_dir()
if args[:1] == ['login']:
    assert sys.stdin.read() == 'synthetic-pat'
    if os.environ.get('GAR_TEST'):
        assert args[1:4] == ['europe-west2-docker.pkg.dev', '--username', 'oauth2accesstoken']
    print('Login Succeeded')
if args[:2] == ['buildx', 'create']:
    if os.environ.get('CLOUD_TEST'):
        assert args[args.index('--driver')+1:args.index('--driver')+3] == ['cloud', os.environ['CLOUD_TEST']]
    else:
        assert args[args.index('--driver')+1] == 'docker-container'
    # The login the cloud builder uses lives in the isolated config.
    assert pathlib.Path(os.environ['DOCKER_CONFIG']).is_dir()
if args[:2] == ['buildx', 'build']:
    assert os.environ.get('DOCKER_HOST') == 'unix:///tmp/synthetic-docker.sock'
    assert args[args.index('--builder')+1].startswith('scrs-release-')
    assert '--sbom=true' in args
    assert '--push' in args
    assert args[args.index('-t')+1] == os.environ['EXPECTED_IMAGE']
    assert args[args.index('--platform')+1] == 'linux/amd64'
with open(os.environ['RELEASE_TEST_LOG'], 'a') as output:
    output.write(json.dumps({'args': args, 'config': os.environ.get('DOCKER_CONFIG')})+'\\n')
""")
            fake_docker.chmod(0o700)
            master, slave = pty.openpty()
            env = os.environ.copy()
            env.update(DOCKER=str(fake_docker), DOCKERHUB_REPO="oribdata/zerorate-stg", VERSION="scrs_staging", PLATFORMS="linux/amd64", RELEASE_TEST_LOG=str(log))
            env.pop("DOCKER_HOST", None)
            env.pop("DOCKER_CONTEXT", None)
            env["EXPECTED_IMAGE"] = "oribdata/zerorate-stg:scrs_staging"
            env["SCRS_IMAGE"] = ""
            # Hermetic: the release reads SCRS_BUILD_CLOUD from .env in its
            # working directory, so run it in the temporary directory.
            env["SCRS_BUILD_CLOUD"] = ""
            if cloud:
                pathlib.Path(directory, ".env").write_text("SCRS_BUILD_CLOUD=" + cloud + "\n")
                env["CLOUD_TEST"] = cloud
            if gar:
                env.update(GAR_TEST="1", DOCKERHUB_REPO="", SCRS_IMAGE="europe-west2-docker.pkg.dev/project/repository/scrs:scrs_staging")
                env["EXPECTED_IMAGE"] = env["SCRS_IMAGE"]
            process = subprocess.Popen(["bash", str(RELEASE)], stdin=slave, stdout=slave, stderr=slave, env=env, cwd=directory)
            os.close(slave)
            os.write(master, b"synthetic-pat\n" if gar else b"orishane\nsynthetic-pat\n")
            output = bytearray()
            deadline = time.monotonic() + 10
            while process.poll() is None and time.monotonic() < deadline:
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        output.extend(os.read(master, 4096))
                    except OSError:
                        break
            if process.poll() is None:
                process.kill()
            status = process.wait(timeout=2)
            os.close(master)
            self.assertEqual(status, 0, output.decode(errors="replace"))
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual([call["args"][:2] for call in calls], [["info"], ["login", calls[1]["args"][1]], ["buildx", "create"], ["buildx", "build"], ["buildx", "rm"]])
            # The temporary builder is removed with the login, after the push.
            self.assertEqual(calls[2]["args"][calls[2]["args"].index("--name")+1], calls[4]["args"][-1])
            self.assertFalse(pathlib.Path(calls[-1]["config"]).exists(), "temporary login config was not removed")


if __name__ == "__main__":
    unittest.main()
