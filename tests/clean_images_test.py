import contextlib
import io
import json
import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import clean_images


class CleanImagesTest(unittest.TestCase):
    def test_keeps_newest_and_container_used_images(self):
        images = [
            {"Id": "sha256:new", "Created": "2026-11-12T12:00:00Z", "RepoTags": ["scrs:new"], "Config": {"Labels": {"io.scrs.project": "scrstack"}}},
            {"Id": "sha256:used", "Created": "2026-11-11T12:00:00Z", "RepoTags": ["scrs:used"], "Config": {"Labels": {"io.scrs.project": "scrstack"}}},
            {"Id": "sha256:old", "Created": "2026-11-10T12:00:00Z", "RepoTags": ["scrs:old", "unrelated:shared"], "Config": {"Labels": {}}},
        ]

        def fake_docker(*args):
            if args[:2] == ("image", "ls"):
                return "sha256:new\nsha256:used\nsha256:old\n"
            if args[:2] == ("image", "inspect"):
                return json.dumps(images)
            if args[:2] == ("container", "ls"):
                return "container-id\n"
            if args[:2] == ("container", "inspect"):
                return json.dumps([{"Image": "sha256:used"}])
            raise AssertionError(args)

        with mock.patch.object(clean_images, "docker", side_effect=fake_docker), mock.patch.object(clean_images.subprocess, "run") as remove, mock.patch.object(sys, "argv", ["clean_images.py", "--image-name", "scrs"]), contextlib.redirect_stdout(io.StringIO()):
            remove.return_value.returncode = 0
            self.assertEqual(clean_images.main(), 0)
        remove.assert_called_once()
        self.assertEqual(remove.call_args.args[0][-2:], ["rm", "scrs:old"])

    def test_includes_docker_hub_repository_without_project_label(self):
        images = [
            {"Id": "sha256:new", "Created": "2026-11-12T12:00:00Z", "RepoTags": ["scrs:latest"], "Config": {"Labels": {"io.scrs.project": "scrstack"}}},
            {"Id": "sha256:old", "Created": "2026-11-10T12:00:00Z", "RepoTags": ["oribdata/zerorate-stg:scrs_old", "unrelated:shared"], "Config": {"Labels": {}}},
        ]
        calls = []

        def fake_docker(*args):
            calls.append(args)
            if args[:2] == ("image", "ls"):
                return "sha256:new\nsha256:old\n"
            if args[:2] == ("image", "inspect"):
                return json.dumps(images)
            if args[:2] == ("container", "ls"):
                return ""
            raise AssertionError(args)

        with mock.patch.object(clean_images, "docker", side_effect=fake_docker), mock.patch.object(clean_images.subprocess, "run") as remove, mock.patch.object(sys, "argv", ["clean_images.py", "--repository", "oribdata/zerorate-stg"]), contextlib.redirect_stdout(io.StringIO()):
            remove.return_value.returncode = 0
            self.assertEqual(clean_images.main(), 0)
        self.assertTrue(any("reference=oribdata/zerorate-stg:scrs_*" in call for call in calls))
        remove.assert_called_once()
        self.assertEqual(remove.call_args.args[0][-2:], ["rm", "oribdata/zerorate-stg:scrs_old"])


if __name__ == "__main__":
    unittest.main()
