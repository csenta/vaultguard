import unittest
from vaultguard.core.entropy import is_likely_placeholder, shannon_entropy, validate_entropy_threshold


class TestEntropy(unittest.TestCase):
    def test_shannon_entropy(self):
        # Repetitive string has low entropy
        self.assertLess(shannon_entropy("aaaaaaaaaaaa"), 0.1)

        # High randomness string has high entropy
        high_entropy_str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        self.assertGreater(shannon_entropy(high_entropy_str), 3.5)

    def test_placeholder_filtering(self):
        self.assertTrue(is_likely_placeholder("YOUR_API_KEY_HERE"))
        self.assertTrue(is_likely_placeholder("AKIAEXAMPLEKEY12345"))
        self.assertTrue(is_likely_placeholder("insert_here"))
        self.assertTrue(is_likely_placeholder("dummy_token_123456"))

        # Real-looking token
        self.assertFalse(is_likely_placeholder("ghp_9842uiohfasd89y213h41klhasdf98"))

    def test_threshold_validation(self):
        self.assertFalse(validate_entropy_threshold("AKIAEXAMPLEKEY12345", min_entropy=2.8))
        self.assertTrue(validate_entropy_threshold("AKIA1234567890ABCDEF", min_entropy=2.8))


if __name__ == "__main__":
    unittest.main()
