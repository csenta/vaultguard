# Security Policy

## Security Model

VaultGuard scans for sensitive secrets in software repositories and configurations.

### Safe by Design
- **Masked Reporting**: Secret values are masked in console output and reports, preventing accidental visual exposure.
- **Read-Only Verification**: Verification requests call non-destructive endpoints (e.g. `/user`, `/models`, `GetCallerIdentity`) and do not perform billable, administrative, or state-modifying actions.
- **Air-Gapped CI Compatible**: Supports `--simulate` mode to execute verification deterministically without network egress.

## Reporting a Vulnerability

If you identify a security defect in VaultGuard:
1. Do not open public GitHub issues.
2. Submit details to the repository maintainers through private GitHub security advisories.
