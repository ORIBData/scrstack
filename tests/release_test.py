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
    print('Login Succeeded')
if args[:2] == ['buildx', 'build']:
    assert os.environ.get('DOCKER_HOST') == 'unix:///tmp/synthetic-docker.sock'
    assert '--push' in args
    assert args[args.index('-t')+1] == 'oribdata/zerorate-stg:scrs_staging'
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
            process = subprocess.Popen(["bash", str(RELEASE)], stdin=slave, stdout=slave, stderr=slave, env=env, cwd=RELEASE.parent.parent)
            os.close(slave)
            os.write(master, b"orishane\nsynthetic-pat\n")
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
            self.assertEqual([call["args"][0] for call in calls], ["info", "login", "buildx"])
            self.assertFalse(pathlib.Path(calls[-1]["config"]).exists(), "temporary login config was not removed")


if __name__ == "__main__":
    unittest.main()
