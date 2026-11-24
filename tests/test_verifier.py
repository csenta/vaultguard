import unittest
from vaultguard.core.models import LeakedSecret, SecretType, VerificationStatus
from vaultguard.engines.verifier import CredentialVerifier


class TestVerifier(unittest.TestCase):
    def test_simulated_verification(self):
        verifier = CredentialVerifier(simulation_mode=True)

        active_secret = LeakedSecret(
            id="s1",
            secret_type=SecretType.GITHUB_TOKEN,
            raw_value="ghp_active_token_1234567890",
            masked_value="ghp_***890",
            file_path="app.py",
            line_number=10,
            line_content="token = '...'",
            entropy=4.2,
        )
        status_active = verifier.verify_secret(active_secret)
        self.assertEqual(status_active, VerificationStatus.SIMULATED_ACTIVE)

        revoked_secret = LeakedSecret(
            id="s2",
            secret_type=SecretType.GITHUB_TOKEN,
            raw_value="ghp_revoked_token_9876543210",
            masked_value="ghp_***210",
            file_path="app.py",
            line_number=12,
            line_content="token = '...'",
            entropy=4.2,
        )
        status_revoked = verifier.verify_secret(revoked_secret)
        self.assertEqual(status_revoked, VerificationStatus.SIMULATED_REVOKED)


if __name__ == "__main__":
    unittest.main()
