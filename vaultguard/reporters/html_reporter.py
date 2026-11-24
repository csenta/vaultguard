"""
Standalone Interactive HTML5 Dashboard Generator for VaultGuard.
"""

import json
from vaultguard.core.models import VaultGuardReport


class HTMLReporter:
    """Generates standalone visual security audit dashboard with dark mode styling."""

    @staticmethod
    def generate(report: VaultGuardReport, title: str = "VaultGuard Secret Leakage Audit") -> str:
        report_json = json.dumps(report.to_dict())

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <style>
    :root {{
      --bg: #0b0f19;
      --card-bg: #151c2c;
      --border: #232f48;
      --text: #f1f5f9;
      --text-muted: #8e9db7;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #f59e0b;
      --success: #10b981;
      --accent: #6366f1;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}
    body {{ background: var(--bg); color: var(--text); padding: 2rem; }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
    h1 {{ font-size: 1.8rem; font-weight: 700; color: #a5b4fc; display: flex; align-items: center; gap: 0.5rem; }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
    .stat-card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }}
    .stat-title {{ color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    .stat-val {{ font-size: 2rem; font-weight: 700; margin-top: 0.4rem; }}
    .risk-score {{ color: {("#ef4444" if report.risk_score >= 70 else ("#f59e0b" if report.risk_score >= 30 else "#10b981"))}; }}
    .section {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; }}
    .section-title {{ font-size: 1.2rem; font-weight: 600; margin-bottom: 1rem; color: #fff; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
    th, td {{ padding: 0.85rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
    th {{ color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }}
    tr:hover {{ background: rgba(255, 255, 255, 0.02); }}
    .badge {{ display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; }}
    .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
    .badge-high {{ background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }}
    .badge-active {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
    .badge-revoked {{ background: rgba(16, 185, 129, 0.2); color: var(--success); border: 1px solid var(--success); }}
    .badge-unverified {{ background: rgba(142, 157, 183, 0.2); color: var(--text-muted); }}
    code {{ font-family: monospace; background: rgba(0, 0, 0, 0.3); padding: 0.2rem 0.4rem; border-radius: 4px; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>🔐 VaultGuard Secret Intelligence</h1>
        <p style="color: var(--text-muted); margin-top: 0.25rem;">Autonomous Secret Leakage Remediator & Proof-of-Revocation Platform</p>
      </div>
      <div style="font-size: 0.85rem; color: var(--text-muted);">
        Target: <strong>{report.target_path}</strong> | {report.timestamp}
      </div>
    </header>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-title">Risk Index</div>
        <div class="stat-val risk-score">{report.risk_score} / 100</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Files Scanned</div>
        <div class="stat-val">{report.files_scanned}</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Leaked Secrets</div>
        <div class="stat-val" style="color: {("#ef4444" if report.secrets else "#10b981")};">{len(report.secrets)}</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Remediation Plans</div>
        <div class="stat-val" style="color: var(--accent);">{len(report.remediations)}</div>
      </div>
    </div>

    <!-- Secrets Table -->
    <div class="section">
      <div class="section-title">
        <span>Exposed Credentials & Active Status ({len(report.secrets)})</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Provider & Type</th>
            <th>Status</th>
            <th>Masked Secret</th>
            <th>Location</th>
            <th>Entropy</th>
          </tr>
        </thead>
        <tbody>
"""

        for s in report.secrets:
            b_class = f"badge-{s.severity.lower()}"
            st_class = "badge-active" if "ACTIVE" in s.verification_status.value else ("badge-revoked" if "REVOKED" in s.verification_status.value else "badge-unverified")
            html += f"""          <tr>
            <td><span class="badge {b_class}">{s.severity}</span></td>
            <td><strong>{s.provider}</strong> <br><code>{s.secret_type.value}</code></td>
            <td><span class="badge {st_class}">{s.verification_status.value}</span></td>
            <td><code>{s.masked_value}</code></td>
            <td>{s.file_path}:{s.line_number}</td>
            <td>{s.entropy:.2f} bits</td>
          </tr>
"""

        if not report.secrets:
            html += "<tr><td colspan='6' style='text-align: center; color: var(--success);'>✅ No hardcoded secrets detected!</td></tr>"

        html += f"""        </tbody>
      </table>
    </div>

    <!-- Remediation Section -->
    <div class="section">
      <div class="section-title">
        <span>Remediation & Rotation Playbooks</span>
      </div>
      <ul>
"""
        for r in report.remediations:
            html += f"""        <li style="margin-bottom: 1.25rem;">
          <strong>{r.provider} ({r.secret_type})</strong> at <code>{r.file_path}:{r.line_number}</code>
          <div style="margin-top: 0.35rem; color: #38bdf8; font-family: monospace; font-size: 0.85rem;">Extract to env: {r.env_example_line}</div>
          <ol style="margin-left: 1.5rem; margin-top: 0.35rem; font-size: 0.85rem; color: var(--text-muted);">
"""
            for step in r.rotation_steps:
                html += f"            <li>{step}</li>\n"
            html += "          </ol>\n        </li>\n"

        if not report.remediations:
            html += "<p style='color: var(--text-muted);'>No remediation required.</p>"

        html += f"""      </ul>
    </div>

  </div>
  <script>
    const reportData = {report_json};
    console.log("VaultGuard Report Loaded:", reportData);
  </script>
</body>
</html>"""
        return html
