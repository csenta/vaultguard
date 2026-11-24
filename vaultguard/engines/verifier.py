"""
Safe Read-Only Credential Verification Engine for VaultGuard.
Determines whether leaked API keys and tokens are actively valid or already revoked.
"""

import json
import urllib.error
import urllib.request
from vaultguard.core.models import LeakedSecret, SecretType, VerificationStatus


class CredentialVerifier:
    """Verifies validity of discovered credentials using safe, read-only identity probes."""

    def __init__(self, simulation_mode: bool = False):
        self.simulation_mode = simulation_mode

    def verify_secret(self, secret: LeakedSecret) -> VerificationStatus:
        if self.simulation_mode:
            # Deterministic simulation for test suites and air-gapped CI
            if "revoked" in secret.raw_value.lower() or "old" in secret.raw_value.lower():
                secret.verification_status = VerificationStatus.SIMULATED_REVOKED
            else:
                secret.verification_status = VerificationStatus.SIMULATED_ACTIVE
            return secret.verification_status

        try:
            if secret.secret_type == SecretType.GITHUB_TOKEN:
                return self._verify_github(secret)
            elif secret.secret_type == SecretType.STRIPE_SECRET_KEY:
                return self._verify_stripe(secret)
            elif secret.secret_type == SecretType.SLACK_BOT_TOKEN:
                return self._verify_slack(secret)
            elif secret.secret_type == SecretType.OPENAI_API_KEY:
                return self._verify_openai(secret)
        except Exception:
            pass

        secret.verification_status = VerificationStatus.UNVERIFIED
        return secret.verification_status

    def _verify_github(self, secret: LeakedSecret) -> VerificationStatus:
        req = urllib.request.Request(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {secret.raw_value}",
                "User-Agent": "VaultGuard-Verifier/1.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=4) as resp:
                if resp.status == 200:
                    secret.verification_status = VerificationStatus.ACTIVE
                    return VerificationStatus.ACTIVE
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                secret.verification_status = VerificationStatus.REVOKED
                return VerificationStatus.REVOKED
            elif e.code == 429:
                secret.verification_status = VerificationStatus.RATE_LIMITED
                return VerificationStatus.RATE_LIMITED
        return VerificationStatus.UNVERIFIED

    def _verify_stripe(self, secret: LeakedSecret) -> VerificationStatus:
        req = urllib.request.Request(
            "https://api.stripe.com/v1/balance",
            headers={"Authorization": f"Bearer {secret.raw_value}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=4) as resp:
                if resp.status == 200:
                    secret.verification_status = VerificationStatus.ACTIVE
                    return VerificationStatus.ACTIVE
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                secret.verification_status = VerificationStatus.REVOKED
                return VerificationStatus.REVOKED
        return VerificationStatus.UNVERIFIED

    def _verify_slack(self, secret: LeakedSecret) -> VerificationStatus:
        req = urllib.request.Request(
            "https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {secret.raw_value}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = json.loads(resp.read().decode())
                if data.get("ok"):
                    secret.verification_status = VerificationStatus.ACTIVE
                    return VerificationStatus.ACTIVE
                elif data.get("error") in ("invalid_auth", "account_inactive", "token_revoked"):
                    secret.verification_status = VerificationStatus.REVOKED
                    return VerificationStatus.REVOKED
        except Exception:
            pass
        return VerificationStatus.UNVERIFIED

    def _verify_openai(self, secret: LeakedSecret) -> VerificationStatus:
        req = urllib.request.Request(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {secret.raw_value}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=4) as resp:
                if resp.status == 200:
                    secret.verification_status = VerificationStatus.ACTIVE
                    return VerificationStatus.ACTIVE
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                secret.verification_status = VerificationStatus.REVOKED
                return VerificationStatus.REVOKED
        return VerificationStatus.UNVERIFIED
