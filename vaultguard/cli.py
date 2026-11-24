"""
Unified Command-Line Interface for VaultGuard.
"""

import argparse
import json
import os
import sys

from vaultguard.core.models import VaultGuardReport
from vaultguard.core.scanner import SecretScanner
from vaultguard.engines.git_purger import GitPurger
from vaultguard.engines.remediation import RemediationEngine
from vaultguard.engines.verifier import CredentialVerifier
from vaultguard.reporters.cli_reporter import CLIReporter
from vaultguard.reporters.html_reporter import HTMLReporter


def compute_risk_score(secrets) -> int:
    score = 0
    for s in secrets:
        if s.severity == "CRITICAL":
            score += 25
        elif s.severity == "HIGH":
            score += 15
        else:
            score += 8
        if "ACTIVE" in s.verification_status.value:
            score += 20
    return min(100, score)


def run_vaultguard_scan(path: str, verify: bool = False, simulate: bool = False) -> VaultGuardReport:
    files_scanned, secrets = SecretScanner.scan_path(path)

    # Verification
    if verify or simulate:
        verifier = CredentialVerifier(simulation_mode=simulate)
        for s in secrets:
            verifier.verify_secret(s)

    # Remediation
    remediations = [RemediationEngine.generate_plan(s) for s in secrets]
    risk_score = compute_risk_score(secrets)

    return VaultGuardReport(
        target_path=path,
        files_scanned=files_scanned,
        secrets=secrets,
        remediations=remediations,
        risk_score=risk_score,
    )


def handle_scan(args: argparse.Namespace) -> int:
    try:
        report = run_vaultguard_scan(args.path, verify=args.verify, simulate=args.simulate)
    except Exception as e:
        print(f"[ERROR] Scan failed on {args.path}: {e}")
        return 1

    # 1. Terminal output
    CLIReporter.print_summary(report)

    # 2. JSON export
    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"📄 JSON report saved to {args.output_json}")

    # 3. HTML export
    if args.output_html:
        html = HTMLReporter.generate(report)
        with open(args.output_html, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"📊 Interactive HTML report saved to {args.output_html}")

    # 4. CI quality gate
    if args.fail_on_active:
        has_active = any("ACTIVE" in s.verification_status.value for s in report.secrets)
        if has_active:
            print("❌ CI Gate Failed: Active valid credentials detected in source code!")
            return 2

    if args.fail_on_severity:
        threshold = args.fail_on_severity.upper()
        severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        thresh_val = severity_order.get(threshold, 3)

        violates = any(severity_order.get(s.severity, 0) >= thresh_val for s in report.secrets)
        if violates:
            print(f"❌ CI Gate Failed: Found secrets matching or exceeding severity '{threshold}'!")
            return 2

    return 0


def handle_purge(args: argparse.Namespace) -> int:
    try:
        _, secrets = SecretScanner.scan_path(args.path)
    except Exception as e:
        print(f"[ERROR] Scan for purge failed: {e}")
        return 1

    if not secrets:
        print("✅ No secrets detected. Git purge script not required.")
        return 0

    script = GitPurger.generate_purge_script(secrets)
    out_file = args.output or "purge_git_history.sh"
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(script)
    os.chmod(out_file, 0o755)

    print(f"🧹 Automated git history purge script generated: {out_file}")
    print(f"   Contains purge rules for {len(secrets)} leaked credentials.")
    return 0


def handle_remediate(args: argparse.Namespace) -> int:
    try:
        _, secrets = SecretScanner.scan_path(args.path)
    except Exception as e:
        print(f"[ERROR] Remediation failed: {e}")
        return 1

    if not secrets:
        print("✅ No secrets detected requiring remediation.")
        return 0

    plans = [RemediationEngine.generate_plan(s) for s in secrets]

    # Generate .env.example
    env_lines = sorted(list({p.env_example_line for p in plans}))
    env_content = "\n".join(env_lines) + "\n"

    if args.output_env:
        with open(args.output_env, "w", encoding="utf-8") as f:
            f.write(env_content)
        print(f"📄 Generated .env template written to {args.output_env}")
    else:
        print("\n🔧 Recommended .env Configuration:")
        print(env_content)

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="vaultguard",
        description="VaultGuard: Autonomous Secret & API Key Leakage Remediator with Proof-of-Revocation & Live Key Verification",
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan repository for hardcoded secrets")
    p_scan.add_argument("--path", "-p", required=True, help="Target file or directory path")
    p_scan.add_argument("--verify", action="store_true", help="Perform live non-destructive verification with provider APIs")
    p_scan.add_argument("--simulate", action="store_true", help="Perform deterministic simulated verification")
    p_scan.add_argument("--output-json", default="", help="Path to write JSON report")
    p_scan.add_argument("--output-html", default="", help="Path to write interactive HTML dashboard")
    p_scan.add_argument("--fail-on-active", action="store_true", help="Exit code 2 if any secret is actively valid")
    p_scan.add_argument(
        "--fail-on-severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="Exit code 2 if secrets >= severity threshold",
    )

    # purge
    p_purge = subparsers.add_parser("purge", help="Generate automated git history purge script")
    p_purge.add_argument("--path", "-p", required=True, help="Target repository directory path")
    p_purge.add_argument("--output", "-o", default="purge_git_history.sh", help="Output shell script filename")

    # remediate
    p_remedy = subparsers.add_parser("remediate", help="Generate .env template and rotation playbooks")
    p_remedy.add_argument("--path", "-p", required=True, help="Target repository directory path")
    p_remedy.add_argument("--output-env", default="", help="Path to write .env.example file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "scan":
        return handle_scan(args)
    elif args.command == "purge":
        return handle_purge(args)
    elif args.command == "remediate":
        return handle_remediate(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
