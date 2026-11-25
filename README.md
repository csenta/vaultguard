# VaultGuard 🔐

> **Status:** prototype. A personal security-research project, not a production product. Expect rough edges; issues and pull requests are welcome.

> **Autonomous Secret & API Key Leakage Remediator with Proof-of-Revocation & Live Key Verification**

VaultGuard is a prototype credential security and secret remediation engine. It scans codebases, git commit trees, configuration manifests, and environment files for leaked credentials, validates candidate randomness with Shannon entropy, verifies active vs revoked credential status safely, and synthesizes automated rotation playbooks, `.env` isolation templates, and git history rewrite scripts.

---

## 🌟 Key Capabilities

- **Multi-Archetype Secret Detection**: High-precision detection for 20+ secret formats including:
  - AWS Access Keys (`AKIA...`) and Secret Keys
  - GitHub Personal Access Tokens (`ghp_`, `github_pat_`)
  - OpenAI Secret Keys (`sk-proj-...`, `sk-...`)
  - Stripe Secret & Restricted Keys (`sk_live_...`)
  - Slack Bot Tokens (`xoxb-...`) and Incoming Webhooks
  - Google Cloud Service Account & API Keys (`AIza...`)
  - Database connection strings (`postgres://`, `mysql://`, `mongodb://`)
  - RSA/EC Private Keys (`-----BEGIN RSA PRIVATE KEY-----`)
- **Shannon Entropy & Heuristic Filter**: Computes character information density to suppress dummy placeholders (`YOUR_API_KEY`, `AKIAEXAMPLEKEY12345`).
- **Proof-of-Revocation & Safe Live Verification**: Probes provider APIs using non-destructive, read-only calls (e.g. GitHub `/user`, Stripe `/v1/balance`) to confirm whether a leaked token is active or revoked. Includes air-gapped simulation mode for CI/CD runners.
- **Automated Git History Purge Generator**: Synthesizes ready-to-run shell scripts (`git-filter-repo` and `bfg`) to expunge leaked credentials from all commits and reflogs.
- **Automated Rotation Playbooks**: Synthesizes provider-specific step-by-step revocation instructions and generates drop-in `.env.example` replacement templates.
- **Interactive Visual Dashboard & CI/CD Gate**: Outputs formatted terminal tables, JSON reports, and standalone HTML5 audit dashboards. Enforces build-breaking CI gates (`--fail-on-active`, `--fail-on-severity HIGH`).

---

## 📐 Architecture

```mermaid
graph TD
    A[Source Code / Git Tree / Configs] -->|SecretScanner| B[Candidate Raw Tokens]
    B -->|EntropyFilter & Heuristics| C[High-Confidence Leaked Secrets]
    C -->|CredentialVerifier| D[Live / Simulated Status Check]
    D -->|Active / Revoked State| E[RemediationEngine]
    E -->|Rotation Playbook| F[Provider Revocation Guides]
    E -->|GitPurger| G[Automated BFG / git-filter-repo Script]
    E -->|EnvTemplateBuilder| H[Safe .env.example / Config Isolation]
    C -->|Report Aggregator| I[CLI / JSON / Interactive HTML5 Dashboard]
```

---

## 🚀 Quick Start

### 1. Installation

```bash
git clone https://github.com/csenta/vaultguard.git
cd vaultguard
```

### 2. Scan Codebase for Leaked Secrets

```bash
python3 -m vaultguard.cli scan \
  --path examples/sample_repo \
  --simulate \
  --output-json report.json \
  --output-html report.html
```

### 3. Generate Automated Git History Purge Script

```bash
python3 -m vaultguard.cli purge \
  --path examples/sample_repo \
  --output purge_git_history.sh
```

### 4. Generate .env Isolation Template

```bash
python3 -m vaultguard.cli remediate \
  --path examples/sample_repo \
  --output-env .env.example
```

### 5. Enforce CI/CD Quality Gate

```bash
python3 -m vaultguard.cli scan \
  --path . \
  --fail-on-active \
  --fail-on-severity HIGH
```

---

## 🛠️ Testing

Run the test suite:

```bash
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

---

## 🐳 Docker Deployment

Run with Docker Compose:

```bash
docker-compose up --build
```

## License

MIT. See [LICENSE](LICENSE).
