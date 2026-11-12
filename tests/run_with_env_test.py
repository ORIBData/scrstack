import pathlib
import subprocess
import sys
import tempfile
import unittest


LOADER = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "run_with_env.py"


class RunWithEnvTest(unittest.TestCase):
    def test_preserves_ampersand_without_shell_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            pathlib.Path(directory, ".env").write_text("SCRS_DATABASE_URL=postgres://example/db?sslmode=require&application_name=scrs\n")
            code = "import os; print(os.environ['SCRS_DATABASE_URL'])"
            result = subprocess.run([sys.executable, str(LOADER), sys.executable, "-c", code], cwd=directory, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "postgres://example/db?sslmode=require&application_name=scrs")

    def test_does_not_pass_admin_url_to_api(self):
        with tempfile.TemporaryDirectory() as directory:
            pathlib.Path(directory, ".env").write_text("SCRS_DATABASE_ADMIN_URL=synthetic-secret\n")
            fake_scrs = pathlib.Path(directory, "scrs")
            fake_scrs.write_text("#!/usr/bin/env python3\nimport os\nprint('present' if 'SCRS_DATABASE_ADMIN_URL' in os.environ else 'absent')\n")
            fake_scrs.chmod(0o700)
            result = subprocess.run([sys.executable, str(LOADER), str(fake_scrs), "api"], cwd=directory, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "absent")


if __name__ == "__main__":
    unittest.main()
