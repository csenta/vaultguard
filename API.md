# VaultGuard API Reference

## Python Library Usage

```python
from vaultguard.core.scanner import SecretScanner
from vaultguard.engines.verifier import CredentialVerifier
from vaultguard.engines.remediation import RemediationEngine
from vaultguard.engines.git_purger import GitPurger
from vaultguard.reporters.cli_reporter import CLIReporter

# 1. Scan codebase for hardcoded credentials
files_scanned, secrets = SecretScanner.scan_path("src/")

# 2. Verify active vs revoked status
verifier = CredentialVerifier(simulation_mode=False)
for s in secrets:
    status = verifier.verify_secret(s)
    print(f"Token: {s.masked_value} | Status: {status.value}")

# 3. Generate remediation plans
plans = [RemediationEngine.generate_plan(s) for s in secrets]

# 4. Generate git purge script
purge_script = GitPurger.generate_purge_script(secrets)
```
