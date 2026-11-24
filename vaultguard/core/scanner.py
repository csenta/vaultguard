"""
High-Precision Multi-Pattern Secret Scanner for VaultGuard.
"""

import os
import re
import uuid

from vaultguard.core.entropy import shannon_entropy, validate_entropy_threshold
from vaultguard.core.models import LeakedSecret, SecretType, mask_secret

# High-precision regular expression signatures
SECRET_PATTERNS = [
    {
        "type": SecretType.AWS_ACCESS_KEY,
        "provider": "AWS",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "min_entropy": 2.8,
    },
    {
        "type": SecretType.AWS_SECRET_KEY,
        "provider": "AWS",
        "severity": "CRITICAL",
        "pattern": re.compile(r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "min_entropy": 4.0,
    },
    {
        "type": SecretType.GITHUB_TOKEN,
        "provider": "GitHub",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b"),
        "min_entropy": 3.8,
    },
    {
        "type": SecretType.OPENAI_API_KEY,
        "provider": "OpenAI",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b(sk-[a-zA-Z0-9]{32,}|sk-proj-[a-zA-Z0-9-_]{40,})\b"),
        "min_entropy": 3.8,
    },
    {
        "type": SecretType.STRIPE_SECRET_KEY,
        "provider": "Stripe",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b"),
        "min_entropy": 3.5,
    },
    {
        "type": SecretType.SLACK_BOT_TOKEN,
        "provider": "Slack",
        "severity": "HIGH",
        "pattern": re.compile(r"\b(xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b"),
        "min_entropy": 3.0,
    },
    {
        "type": SecretType.SLACK_WEBHOOK,
        "provider": "Slack",
        "severity": "HIGH",
        "pattern": re.compile(r"(https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8,12}\/B[0-9A-Z]{8,12}\/[0-9A-Za-z]{24})"),
        "min_entropy": 3.2,
    },
    {
        "type": SecretType.GCP_API_KEY,
        "provider": "Google Cloud",
        "severity": "HIGH",
        "pattern": re.compile(r"\b(AIza[0-9A-Za-z-_]{35})\b"),
        "min_entropy": 3.5,
    },
    {
        "type": SecretType.DATABASE_DSN,
        "provider": "Database",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b((?:postgres|postgresql|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@[^\s\/]+(?:\/[^\s\?]+)?)\b"),
        "min_entropy": 3.0,
    },
    {
        "type": SecretType.PRIVATE_KEY,
        "provider": "Crypto",
        "severity": "CRITICAL",
        "pattern": re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"),
        "min_entropy": 2.0,
    },
]

IGNORED_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", "dist", "build"}
IGNORED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz", ".lock"}


class SecretScanner:
    """Scans directories and files for hardcoded secrets with entropy verification."""

    @staticmethod
    def scan_path(target_path: str) -> tuple[int, list[LeakedSecret]]:
        if os.path.isfile(target_path):
            secrets = SecretScanner.scan_file(target_path)
            return 1, secrets

        files_scanned = 0
        all_secrets: list[LeakedSecret] = []

        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
            for f in files:
                ext = os.path.splitext(f)[-1].lower()
                if ext in IGNORED_EXTENSIONS:
                    continue
                full_path = os.path.join(root, f)
                files_scanned += 1
                file_secrets = SecretScanner.scan_file(full_path)
                all_secrets.extend(file_secrets)

        return files_scanned, all_secrets

    @staticmethod
    def scan_file(file_path: str) -> list[LeakedSecret]:
        secrets: list[LeakedSecret] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return []

        for line_idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") and "example" in stripped.lower():
                continue

            for rule in SECRET_PATTERNS:
                matches = rule["pattern"].findall(line)
                for raw_match in matches:
                    candidate = raw_match.strip()
                    ent = shannon_entropy(candidate)

                    # Entropy check
                    if not validate_entropy_threshold(candidate, rule["min_entropy"]):
                        continue

                    masked = mask_secret(candidate)
                    secrets.append(
                        LeakedSecret(
                            id=f"sec_{uuid.uuid4().hex[:8]}",
                            secret_type=rule["type"],
                            raw_value=candidate,
                            masked_value=masked,
                            file_path=file_path,
                            line_number=line_idx,
                            line_content=stripped[:120],
                            entropy=ent,
                            severity=rule["severity"],
                            provider=rule["provider"],
                        )
                    )

        return secrets
