import unittest
from vaultguard.core.models import LeakedSecret, SecretType
from vaultguard.engines.git_purger import GitPurger
from vaultguard.engines.remediation import RemediationEngine


class TestRemediation(unittest.TestCase):
    def test_remediation_plan_and_git_purger(self):
        secret = LeakedSecret(
            id="sec_test",
            secret_type=SecretType.AWS_ACCESS_KEY,
            raw_value="AKIA1234567890ABCDEF",
            masked_value="AKIA****CDEF",
            file_path="config.py",
            line_number=5,
            line_content="AWS_ACCESS_KEY = 'AKIA1234567890ABCDEF'",
            entropy=3.5,
            provider="AWS",
        )
        plan = RemediationEngine.generate_plan(secret)
        self.assertEqual(plan.provider, "AWS")
        self.assertEqual(plan.env_variable_name, "AWS_ACCESS_KEY_ID")
        self.assertGreater(len(plan.rotation_steps), 3)

        # Test purge script generation
        purge_script = GitPurger.generate_purge_script([secret])
        self.assertIn("git-filter-repo", purge_script)
        self.assertIn("AKIA1234567890ABCDEF==>REDACTED_BY_VAULTGUARD", purge_script)


if __name__ == "__main__":
    unittest.main()
