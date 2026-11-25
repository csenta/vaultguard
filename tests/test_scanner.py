import unittest
from vaultguard.core.models import SecretType
from vaultguard.core.scanner import SecretScanner
import os
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestSecretScanner(unittest.TestCase):
    def setUp(self):
        self.sample_dir = os.path.join(_ROOT, "examples", "sample_repo")

    def test_scan_directory(self):
        files_scanned, secrets = SecretScanner.scan_path(self.sample_dir)
        self.assertEqual(files_scanned, 4)
        self.assertGreaterEqual(len(secrets), 5)

        secret_types = [s.secret_type for s in secrets]
        self.assertIn(SecretType.AWS_ACCESS_KEY, secret_types)
        self.assertIn(SecretType.GITHUB_TOKEN, secret_types)
        self.assertIn(SecretType.OPENAI_API_KEY, secret_types)
        self.assertIn(SecretType.STRIPE_SECRET_KEY, secret_types)
        self.assertIn(SecretType.SLACK_WEBHOOK, secret_types)
        self.assertIn(SecretType.DATABASE_DSN, secret_types)

    def test_safe_file_ignored(self):
        safe_file = f"{self.sample_dir}/safe.py"
        secrets = SecretScanner.scan_file(safe_file)
        self.assertEqual(len(secrets), 0)


if __name__ == "__main__":
    unittest.main()
