"""
Console Summary Reporter for VaultGuard.
"""

from vaultguard.core.models import VaultGuardReport


class CLIReporter:
    """Renders formatted terminal output for secret detection and remediation audits."""

    @staticmethod
    def print_summary(report: VaultGuardReport):
        print("\n" + "=" * 80)
        print("🔐 [VAULTGUARD] SECRET LEAKAGE & REMEDIATION AUDIT REPORT")
        print("=" * 80)
        print(f"  Target Scanned:          {report.target_path}")
        print(f"  Files Analyzed:          {report.files_scanned}")
        print(f"  Total Secrets Found:     {len(report.secrets)}")

        score_color = "🟢" if report.risk_score < 30 else ("🟡" if report.risk_score < 70 else "🔴")
        print(f"  Credential Risk Score:   {score_color} {report.risk_score}/100")
        print("-" * 80)

        if not report.secrets:
            print("  ✅ No exposed secrets or hardcoded API keys detected!")
        else:
            for idx, s in enumerate(report.secrets, 1):
                badge = {
                    "CRITICAL": "💥 CRITICAL",
                    "HIGH": "🚨 HIGH    ",
                    "MEDIUM": "⚠️  MEDIUM  ",
                }.get(s.severity, s.severity)
                status_badge = {
                    "ACTIVE": "🔴 ACTIVE KEY!",
                    "REVOKED": "🟢 REVOKED",
                    "SIMULATED_ACTIVE": "🔴 SIMULATED ACTIVE",
                    "SIMULATED_REVOKED": "🟢 SIMULATED REVOKED",
                    "UNVERIFIED": "⚪ UNVERIFIED",
                    "RATE_LIMITED": "🟡 RATE LIMITED",
                }.get(s.verification_status.value, s.verification_status.value)

                print(f"[{idx:02d}] {badge} | {status_badge:<18} | {s.provider} ({s.secret_type.value})")
                print(f"     Masked Token:  {s.masked_value} (Entropy: {s.entropy:.2f} bits)")
                print(f"     Location:      {s.file_path}:{s.line_number}")
                print(f"     Snippet:       {s.line_content}")
                print()

        if report.remediations:
            print("🔧 SUGGESTED REMEDIATION & ROTATION PLAYBOOKS:")
            for idx, r in enumerate(report.remediations, 1):
                print(f"  [{idx:02d}] Replace in {r.file_path}:{r.line_number} with env variable '{r.env_variable_name}'")
                print(f"       Example: {r.env_example_line}")

        print("\n" + "=" * 80 + "\n")
