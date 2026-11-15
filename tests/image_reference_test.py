import os
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import image_reference as image

class ImageReferenceTest(unittest.TestCase):
    def test_templates_for_both_registries(self):
        for repo in ("example/scrs", "europe-west2-docker.pkg.dev/project/repository/scrs"):
            with patch.dict("os.environ", {"SCRS_IMAGE": repo + ":scrs_YYYY_MM_DD_v{shortSHA256}", "VERSION": "", "DOCKERHUB_REPO": ""}), patch.object(image, "source_digest", return_value="123456abcdef"):
                self.assertRegex(image.resolve(), "^" + repo + r":scrs_\d{4}_\d{2}_\d{2}_v123456abcdef$")
    def test_rejects_placeholder_and_unscoped_tag(self):
        for ref in ("{Container_Registry_Organization_Name}:scrs_test", "example/scrs:latest", "example/scrs:bad;command"):
            with patch.dict("os.environ", {"SCRS_IMAGE": ref, "VERSION": "", "DOCKERHUB_REPO": ""}):
                with self.assertRaises(ValueError):
                    image.resolve()
    def test_each_release_target_reads_its_own_dotenv_key(self):
        dotenv = (
            "SCRS_IMAGE=example/stg:scrs_YYYY_MM_DD_v{shortSHA256}\n"
            "SCRS_SAST_IMAGE=example/stg:scrs_sast_YYYY_MM_DD_v{shortSHA256}\n"
            "SCRS_QA_RUNNER_IMAGE='example/stg:scrs_qa_runner_YYYY_MM_DD_v{shortSHA256}'\n"
        )
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as directory:
            pathlib.Path(directory, ".env").write_text(dotenv)
            os.chdir(directory)
            try:
                for key, prefix in (("", "scrs_"), ("SCRS_IMAGE", "scrs_"), ("SCRS_SAST_IMAGE", "scrs_sast_"), ("SCRS_QA_RUNNER_IMAGE", "scrs_qa_runner_")):
                    with patch.dict("os.environ", {"SCRS_IMAGE": "", "SCRS_IMAGE_KEY": key, "VERSION": "", "DOCKERHUB_REPO": ""}), patch.object(image, "source_digest", return_value="123456abcdef"):
                        self.assertRegex(image.resolve(), "^example/stg:" + prefix + r"\d{4}_\d{2}_\d{2}_v123456abcdef$")
                # A value from the make command line or environment wins over .env.
                with patch.dict("os.environ", {"SCRS_IMAGE": "example/other:scrs_cli", "SCRS_IMAGE_KEY": "SCRS_SAST_IMAGE", "VERSION": "", "DOCKERHUB_REPO": ""}):
                    self.assertEqual(image.resolve(), "example/other:scrs_cli")
                with patch.dict("os.environ", {"SCRS_IMAGE": "", "SCRS_IMAGE_KEY": "PATH", "VERSION": "", "DOCKERHUB_REPO": ""}):
                    with self.assertRaises(ValueError):
                        image.resolve()
                pathlib.Path(directory, ".env").write_text("SCRS_SAST_IMAGE=example/stg:scrs-sast_v1\n")
                with patch.dict("os.environ", {"SCRS_IMAGE": "", "SCRS_IMAGE_KEY": "SCRS_SAST_IMAGE", "VERSION": "", "DOCKERHUB_REPO": ""}):
                    with self.assertRaisesRegex(ValueError, "^SCRS_SAST_IMAGE needs"):
                        image.resolve()
                pathlib.Path(directory, ".env").write_text("")
                with patch.dict("os.environ", {"SCRS_IMAGE": "", "SCRS_IMAGE_KEY": "SCRS_QA_RUNNER_IMAGE", "VERSION": "", "DOCKERHUB_REPO": ""}):
                    with self.assertRaisesRegex(ValueError, "^Set SCRS_QA_RUNNER_IMAGE"):
                        image.resolve()
            finally:
                os.chdir(cwd)
