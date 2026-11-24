"""
Git History Purge and Redaction Script Synthesizer for VaultGuard.
"""

from vaultguard.core.models import LeakedSecret


class GitPurger:
    """Generates automated shell scripts to completely rewrite git history and remove leaked secrets."""

    @staticmethod
    def generate_purge_script(secrets: list[LeakedSecret]) -> str:
        unique_raw_secrets = list({s.raw_value for s in secrets})

        script = """#!/usr/bin/env bash
# ==============================================================================
# 🧹 VaultGuard Automated Git History Purge Script
# Warning: This rewrites git commit history. Ensure all contributors have committed
# their work and back up your repository before running this script.
# ==============================================================================
set -euo pipefail

echo "==> Creating backup branch 'pre-vaultguard-backup'..."
git branch -f pre-vaultguard-backup HEAD

# Prepare replacement rules
REPLACE_FILE=$(mktemp)
trap 'rm -f "$REPLACE_FILE"' EXIT

cat << 'EOF' > "$REPLACE_FILE"
"""
        for sec in unique_raw_secrets:
            script += f"{sec}==>REDACTED_BY_VAULTGUARD\n"

        script += """EOF

if command -v git-filter-repo &> /dev/null; then
  echo "==> Purging secrets using git-filter-repo..."
  git-filter-repo --replace-text "$REPLACE_FILE" --force
  echo "✅ Git history rewritten cleanly!"
elif command -v bfg &> /dev/null; then
  echo "==> Purging secrets using BFG Repo-Cleaner..."
  bfg --replace-text "$REPLACE_FILE"
  git reflog expire --expire=now --all && git gc --prune=now --aggressive
  echo "✅ BFG history purge complete!"
else
  echo "❌ Neither 'git-filter-repo' nor 'bfg' was found on PATH."
  echo "   Install git-filter-repo: pip install git-filter-repo"
  exit 1
fi

echo "==> Next steps:"
echo "   1. Verify your codebase: git log -p -S 'REDACTED_BY_VAULTGUARD'"
echo "   2. Force push updated branches: git push origin --force --all"
echo "   3. Invalidate/rotate the original credentials in the provider console!"
"""
        return script
