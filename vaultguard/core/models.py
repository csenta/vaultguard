"""
Data Models for VaultGuard.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class SecretType(str, Enum):
    AWS_ACCESS_KEY = "AWS_ACCESS_KEY"
    AWS_SECRET_KEY = "AWS_SECRET_KEY"
    GITHUB_TOKEN = "GITHUB_TOKEN"
    OPENAI_API_KEY = "OPENAI_API_KEY"
    SLACK_WEBHOOK = "SLACK_WEBHOOK"
    SLACK_BOT_TOKEN = "SLACK_BOT_TOKEN"
    STRIPE_SECRET_KEY = "STRIPE_SECRET_KEY"
    GCP_API_KEY = "GCP_API_KEY"
    DATABASE_DSN = "DATABASE_DSN"
    PRIVATE_KEY = "PRIVATE_KEY"
    GENERIC_SECRET = "GENERIC_SECRET"


class VerificationStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    SIMULATED_ACTIVE = "SIMULATED_ACTIVE"
    SIMULATED_REVOKED = "SIMULATED_REVOKED"
    RATE_LIMITED = "RATE_LIMITED"


def mask_secret(value: str) -> str:
    """Masks secret preserving beginning and end for safe display and logging."""
    if len(value) <= 8:
        return "********"
    if len(value) <= 16:
        return value[:3] + "*" * (len(value) - 6) + value[-3:]
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


@dataclass
class LeakedSecret:
    id: str
    secret_type: SecretType
    raw_value: str
    masked_value: str
    file_path: str
    line_number: int
    line_content: str
    entropy: float
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    severity: str = "HIGH"  # CRITICAL, HIGH, MEDIUM
    provider: str = "Generic"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RemediationPlan:
    secret_id: str
    provider: str
    secret_type: str
    file_path: str
    line_number: int
    rotation_steps: list[str]
    env_variable_name: str
    env_example_line: str
    git_purge_command: str


@dataclass
class VaultGuardReport:
    target_path: str
    files_scanned: int
    secrets: list[LeakedSecret] = field(default_factory=list)
    remediations: list[RemediationPlan] = field(default_factory=list)
    risk_score: int = 0  # 0 to 100
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_path": self.target_path,
            "files_scanned": self.files_scanned,
            "total_secrets_found": len(self.secrets),
            "risk_score": self.risk_score,
            "timestamp": self.timestamp,
            "secrets": [
                {
                    "id": s.id,
                    "type": s.secret_type.value,
                    "provider": s.provider,
                    "masked": s.masked_value,
                    "file": s.file_path,
                    "line": s.line_number,
                    "entropy": round(s.entropy, 2),
                    "status": s.verification_status.value,
                    "severity": s.severity,
                }
                for s in self.secrets
            ],
            "remediations": [
                {
                    "secret_id": r.secret_id,
                    "provider": r.provider,
                    "file": r.file_path,
                    "env_var": r.env_variable_name,
                    "rotation_steps": r.rotation_steps,
                    "git_purge_command": r.git_purge_command,
                }
                for r in self.remediations
            ],
        }
