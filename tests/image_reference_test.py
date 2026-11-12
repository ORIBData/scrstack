import pathlib
import sys
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
