"""
Automated Remediation Playbook and Environment Template Generator for VaultGuard.
"""

from vaultguard.core.models import LeakedSecret, RemediationPlan, SecretType

ENV_NAME_MAPPING = {
    SecretType.AWS_ACCESS_KEY: ("AWS_ACCESS_KEY_ID", "AKIAXXXXXXXXXXXXXXXX"),
    SecretType.AWS_SECRET_KEY: ("AWS_SECRET_ACCESS_KEY", "your_aws_secret_access_key_here"),
    SecretType.GITHUB_TOKEN: ("GITHUB_TOKEN", "ghp_your_github_personal_access_token_here"),
    SecretType.OPENAI_API_KEY: ("OPENAI_API_KEY", "sk-proj-your_openai_api_key_here"),
    SecretType.STRIPE_SECRET_KEY: ("STRIPE_SECRET_KEY", "sk_live_your_stripe_secret_key_here"),
    SecretType.SLACK_BOT_TOKEN: ("SLACK_BOT_TOKEN", "xoxb-your_slack_bot_token_here"),
    SecretType.SLACK_WEBHOOK: ("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T00/B00/XXXX"),
    SecretType.GCP_API_KEY: ("GCP_API_KEY", "AIzayour_google_cloud_api_key_here"),
    SecretType.DATABASE_DSN: ("DATABASE_URL", "postgresql://user:password@localhost:5432/dbname"),
    SecretType.PRIVATE_KEY: ("PRIVATE_KEY_PATH", "./certs/server.key"),
}

ROTATION_PLAYBOOKS = {
    "AWS": [
        "1. Log in to AWS IAM Console (or run 'aws iam create-access-key --user-name <user>').",
        "2. Create a new access key and securely store it in your Secrets Manager or vault.",
        "3. Update application environment variables with the new key.",
        "4. Set the old compromised access key state to 'Inactive' in IAM Console.",
        "5. Verify application telemetry and CloudTrail logs for unexpected access attempts.",
        "6. Permanently delete the old access key in IAM.",
    ],
    "GitHub": [
        "1. Navigate to GitHub Settings -> Developer settings -> Personal access tokens.",
        "2. Select the compromised token and click 'Revoke'.",
        "3. Generate a new fine-grained Personal Access Token with minimal required scopes and an expiration date.",
        "4. Update GitHub Actions secrets or local .env with the new token.",
    ],
    "OpenAI": [
        "1. Open the OpenAI Platform Dashboard at platform.openai.com/api-keys.",
        "2. Locate the compromised key and click the trash icon to revoke it immediately.",
        "3. Create a new secret key, assign it a clear name, and copy the value.",
        "4. Update server environment variables with the replacement key.",
    ],
    "Stripe": [
        "1. Go to Stripe Dashboard -> Developers -> API keys.",
        "2. Locate the compromised Secret key and click 'Roll key...'.",
        "3. Choose an expiration window for the old key (e.g. immediate or 24h grace period).",
        "4. Deploy the new key to your payment backend environment.",
    ],
    "Slack": [
        "1. Go to api.slack.com/apps and select your Slack App.",
        "2. Navigate to OAuth & Permissions -> Tokens for Your Workspace and revoke the bot token.",
        "3. Reinstall the app to workspace to generate a fresh token.",
        "4. Update your notification service configuration.",
    ],
    "Database": [
        "1. Connect to database administrator console.",
        "2. Execute: ALTER USER <username> WITH PASSWORD '<new_secure_random_password>';",
        "3. Update application DATABASE_URL connection strings across all deployment environments.",
        "4. Terminate any active untrusted database sessions: SELECT pg_terminate_backend(pid)...",
    ],
}


class RemediationEngine:
    """Generates actionable rotation playbooks, .env templates, and purge recipes."""

    @staticmethod
    def generate_plan(secret: LeakedSecret) -> RemediationPlan:
        env_var, env_val = ENV_NAME_MAPPING.get(secret.secret_type, ("SECRET_KEY", "your_secret_here"))
        playbook = ROTATION_PLAYBOOKS.get(secret.provider, [
            "1. Revoke the compromised credential immediately in the service provider portal.",
            "2. Generate a new credential with least-privilege permissions.",
            "3. Store the new credential in an isolated secret store (e.g. HashiCorp Vault, AWS Secrets Manager).",
            "4. Verify all services authenticate properly with the updated credential.",
        ])

        env_example = f"{env_var}={env_val}"
        purge_cmd = f"git-filter-repo --replace-text <(echo '{secret.raw_value}==>REDACTED_BY_VAULTGUARD')"

        return RemediationPlan(
            secret_id=secret.id,
            provider=secret.provider,
            secret_type=secret.secret_type.value,
            file_path=secret.file_path,
            line_number=secret.line_number,
            rotation_steps=playbook,
            env_variable_name=env_var,
            env_example_line=env_example,
            git_purge_command=purge_cmd,
        )
