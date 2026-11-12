import importlib.util
import os
import pathlib
import unittest
from unittest.mock import patch

path=pathlib.Path(__file__).resolve().parents[1]/'scripts/deployment_acceptance.py'
spec=importlib.util.spec_from_file_location('acceptance',path)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class AcceptanceTest(unittest.TestCase):
    def test_rejects_insecure_or_credentialled_public_url(self):
        for url in ['', 'http://example.com', 'https://user:password@example.com', 'https://example.com/other', 'https://example.com?token=secret']:
            with self.subTest(url=url), patch.dict(os.environ, {'SCRS_PUBLIC_BASE_URL':url}, clear=True):
                with self.assertRaises(ValueError):
                    module.main()
    def test_requires_token_before_network(self):
        with patch.dict(os.environ, {'SCRS_PUBLIC_BASE_URL':'https://example.com/scrs/v1'}, clear=True):
            with self.assertRaisesRegex(ValueError, 'SCRS_ACCEPTANCE_API_TOKEN'):
                module.main()
