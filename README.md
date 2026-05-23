# Aegis-SSDLC — Secure Software Development Lifecycle Agentic Toolchain

Aegis-SSDLC is a modular, agentic security orchestration suite designed to embed automated DevSecOps scanners and custom, specialized security subagents directly into your development workflow. 

It provides automated Static Application Security Testing (SAST), Software Bill of Materials (SBOM) generation, supply chain CVE audits, and 6 purpose-built security subagents to automate security planning, secure coding, peer review, and secure git release management.

---

## 📂 Repository Architecture

```text
agentic-ssdlc/
├── .gitignore               # Strict security filters (prevents credential exposure)
├── LICENSE                  # BSD 3-Clause open source license
├── README.md                # This setup & orchestration documentation
├── config.json.template     # Custom configuration template 
├── install.sh               # Smart, interactive shell installation script
├── bin/                     # Advanced dynamic scanning runners
│   ├── aegis-sast.py        # Orchestrates Semgrep, Trivy, Gosec, and Govulncheck
│   └── aegis-sbom.py        # Orchestrates Syft and Trivy SBOM vulnerability audits
├── templates/               # Standardized markdown report schemas
│   ├── sast_report.md
│   ├── sbom_report.md
│   ├── security_review.md
│   └── threat_model.md
└── agents/                  # Portable custom security subagent JSON templates
    ├── ssdlc_planner.json   # Secure Architect and STRIDE Threat Modeler
    ├── ssdlc_coder.json     # Secure Software Developer
    ├── ssdlc_reviewer.json  # Manual Security Peer Reviewer
    ├── ssdlc_sast.json      # Automated Static Analysis Specialist
    ├── ssdlc_sbom.json      # Supply Chain & SBOM Compliance Auditor
    └── ssdlc_git.json       # Git Release Engineer & Commit Security Gatekeeper
```

---

## 🛠️ Prerequisite Tools

For full engine coverage, the following utilities should be installed on your host system:

| Security Engine | Purpose | Default Scanner Package | Installation Command |
|---|---|---|---|
| **Semgrep** | SAST Code Auditing | `semgrep` | `pip install semgrep` or system package |
| **Trivy** | Secrets & SBOM CVEs | `trivy` | [Trivy Setup Guide](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) |
| **Syft** | SBOM Inventory Generation | `syft` | `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin` |
| **Gosec** | Go Language SAST (Optional) | `gosec` | `go install github.com/securego/gosec/v2/cmd/gosec@latest` |
| **Govulncheck** | Go Dependency CVEs (Optional) | `govulncheck` | `go install golang.org/x/vuln/cmd/govulncheck@latest` |

---

## 🚀 Installation & Parameterization

Clone this repository and execute the smart installer. The installer dynamically:
1. Detects your environment and custom pathways.
2. Checks for both required and optional system dependencies.
3. Parameterizes agent instructions (`agents/*.json`) and tool configurations, substituting local home directory structures (`{{AEGIS_DIR}}` and `{{HOME_DIR}}`).
4. Offers to **automatically inject and register** the custom subagents directly into your active Antigravity CLI brain session!

```bash
cd agentic-ssdlc
chmod +x install.sh
./install.sh
```

---


## 🤖 Custom Security Agents Overview

When imported, you can invoke these specialized agents inside your Antigravity conversation workspace:

### 1. `ssdlc_planner` (Secure Architect & Threat Modeler)
- **Prompt Directive**: Analyzes feature scopes, diagrams trust boundaries with Mermaid, details STRIDE vulnerabilities, and publishes concrete security requirements checklists.

### 2. `ssdlc_coder` (Secure Software Developer)
- **Prompt Directive**: Satisfies threat requirements checklists using defensive coding techniques (strict input validation, parameter binding, environment-based credentials loading, secure error suppression).

### 3. `ssdlc_reviewer` (Manual Security Peer Reviewer)
- **Prompt Directive**: Independent line-by-line reviewer checking diffs for OWASP Top 10 weaknesses and ensuring STRIDE requirements are validated before merging.

### 4. `ssdlc_sast` (Automated Static Analysis Specialist)
- **Prompt Directive**: Runs the automated `aegis-sast.py` runner to audit custom codebase rules, triages findings, and ensures the codebase compiles cleanly.

### 5. `ssdlc_sbom` (Supply Chain Auditor)
- **Prompt Directive**: Runs `aegis-sbom.py` to compile an inventory CycloneDX SBOM and verify that dependencies contain zero open blocking CVEs.

### 6. `ssdlc_git` (Release Engineer & Gatekeeper)
- **Prompt Directive**: Manages feature branches, stages commits safely, verifies that SAST and SBOM verdicts have passed, and pushes signed commits.

---

## ⚖️ License
Licensed under the [BSD 3-Clause License](LICENSE).
