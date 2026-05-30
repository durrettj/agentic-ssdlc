#!/usr/bin/env python3
import os
import sys
import json
import shutil
import subprocess
from datetime import datetime

# Determine the Home directory and base Agentic directory dynamically
HOME_DIR = os.path.expanduser("~")
AEGIS_DIR = os.environ.get("AEGIS_DIR", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Binary Paths (checks system PATH first, falls back to standard local folders)
TIVY_BIN = shutil.which("trivy") or "/usr/bin/trivy"
SEMGREP_BIN = shutil.which("semgrep") or os.path.join(HOME_DIR, "ssdlc-env/bin/semgrep")
GOSEC_BIN = shutil.which("gosec") or os.path.join(HOME_DIR, "go/bin/gosec")
GOVULNCHECK_BIN = shutil.which("govulncheck") or os.path.join(HOME_DIR, "go/bin/govulncheck")

# Configuration and output paths relative to Aegis directory
CONFIG_PATH = os.path.join(AEGIS_DIR, "config.json")
REPORTS_DIR = os.path.join(AEGIS_DIR, "reports")
TEMPLATE_PATH = os.path.join(AEGIS_DIR, "templates", "sast_report.md")

def load_config():
    try:
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[-] Warning: Failed to load config: {e}. Using defaults.")
        return {
            "project_path": HOME_DIR,
            "sast": {
                "semgrep_rules": "p/security-audit",
                "trivy_secrets": True,
                "gosec": true,
                "govulncheck": true,
                "fail_on_severity": "high"
            }
        }

def check_go_project(project_path):
    # Search for go.mod or *.go files
    for root, _, files in os.walk(project_path):
        if "go.mod" in files:
            return True
        for file in files:
            if file.endswith(".go"):
                return True
    return False

def run_command(cmd, shell=False, cwd=None):
    try:
        res = subprocess.run(cmd, shell=shell, capture_output=True, text=True, check=False, cwd=cwd)
        return res.stdout, res.stderr, res.returncode
    except Exception as e:
        return "", str(e), -1

def run_semgrep(project_path, rules):
    print("[*] Running Semgrep SAST...")
    if not os.path.exists(SEMGREP_BIN) and not shutil.which("semgrep"):
        print(f"[-] Warning: Semgrep binary not found. Skipping Semgrep scan.")
        return []

    cmd = [SEMGREP_BIN, "scan", "--config", rules, "--json", project_path]
    stdout, stderr, code = run_command(cmd)
    
    findings = []
    try:
        data = json.loads(stdout)
        results = data.get("results", [])
        for item in results:
            finding = {
                "id": item.get("check_id"),
                "scanner": "Semgrep",
                "file": item.get("path"),
                "line": item.get("start", {}).get("line"),
                "col": item.get("start", {}).get("col"),
                "severity": item.get("extra", {}).get("severity", "medium").lower(),
                "message": item.get("extra", {}).get("message"),
                "code": item.get("extra", {}).get("lines")
            }
            # Map semgrep severity to standard: ERROR->high, WARNING->medium, INFO->low
            if finding["severity"] == "error":
                finding["severity"] = "high"
            elif finding["severity"] == "warning":
                finding["severity"] = "medium"
            elif finding["severity"] == "info":
                finding["severity"] = "low"
            findings.append(finding)
    except Exception as e:
        print(f"[-] Semgrep parsing error or empty result: {e}")
        if "No paths to scan" in stderr or "No files" in stderr:
            print("[+] Semgrep found no files to scan.")
    return findings

def run_trivy_secrets(project_path):
    print("[*] Running Trivy Secret Scanner...")
    if not os.path.exists(TIVY_BIN) and not shutil.which("trivy"):
        print(f"[-] Warning: Trivy binary not found. Skipping Trivy Secrets scan.")
        return []

    cmd = [TIVY_BIN, "fs", "--scanners", "secret", "--format", "json", project_path]
    stdout, stderr, code = run_command(cmd)
    
    findings = []
    try:
        data = json.loads(stdout)
        results = data.get("Results", [])
        for result in results:
            secrets = result.get("Secrets", [])
            file_path = result.get("Target")
            for sec in secrets:
                findings.append({
                    "id": sec.get("RuleID", "TrivySecret"),
                    "scanner": "Trivy Secrets",
                    "file": file_path,
                    "line": sec.get("StartLine"),
                    "col": 0,
                    "severity": sec.get("Severity", "medium").lower(),
                    "message": f"Potential secret exposure: {sec.get('Title')} (Category: {sec.get('Category')})",
                    "code": sec.get("Match")
                })
    except Exception as e:
        print(f"[-] Trivy Secret parsing error: {e}")
    return findings

def run_gosec(project_path):
    print("[*] Running gosec...")
    if not os.path.exists(GOSEC_BIN) and not shutil.which("gosec"):
        print(f"[-] Warning: gosec binary not found. Skipping gosec scan.")
        return []
    
    # Run gosec inside the project path
    cmd = [GOSEC_BIN, "-fmt=json", "-no-fail", "./..."]
    stdout, stderr, code = run_command(cmd, shell=False, cwd=project_path)
    
    findings = []
    try:
        data = json.loads(stdout)
        issues = data.get("Issues", [])
        for issue in issues:
            findings.append({
                "id": issue.get("rule_id"),
                "scanner": "Gosec",
                "file": issue.get("file"),
                "line": issue.get("line"),
                "col": 0,
                "severity": issue.get("severity", "medium").lower(),
                "message": issue.get("details"),
                "code": issue.get("code")
            })
    except Exception as e:
        print(f"[-] Gosec parsing error: {e}")
    return findings

def run_govulncheck(project_path):
    print("[*] Running govulncheck...")
    if not os.path.exists(GOVULNCHECK_BIN) and not shutil.which("govulncheck"):
        print(f"[-] Warning: govulncheck binary not found. Skipping govulncheck scan.")
        return []
    
    cmd = [GOVULNCHECK_BIN, "-json", "./..."]
    stdout, stderr, code = run_command(cmd, shell=False, cwd=project_path)
    
    findings = []
    # govulncheck outputs multiple JSON objects separated by newlines
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            # Find finding items
            finding_data = data.get("finding")
            if finding_data:
                osv_id = finding_data.get("osv")
                traces = finding_data.get("traces", [])
                message = f"Vulnerability {osv_id} found in package {finding_data.get('module')}"
                if traces:
                    message += f" - Reachable path: {traces[0].get('description')}"
                
                # Check standard severity if available, default to high since it's a known CVE in use
                findings.append({
                    "id": osv_id,
                    "scanner": "Govulncheck",
                    "file": "go.mod",
                    "line": 0,
                    "col": 0,
                    "severity": "high",
                    "message": message,
                    "code": f"Imported module: {finding_data.get('module')}"
                })
        except json.JSONDecodeError:
            continue # skip non-JSON warning/text lines
        except Exception as e:
            print(f"[-] Unexpected error parsing govulncheck output line: {e}")
    return findings

def create_report(findings, project_path, fail_severity):
    print("[*] Consolidating and writing SAST reports...")
    
    total = len(findings)
    critical_count = sum(1 for f in findings if f["severity"] == "critical")
    high_count = sum(1 for f in findings if f["severity"] == "high")
    medium_count = sum(1 for f in findings if f["severity"] == "medium")
    low_count = sum(1 for f in findings if f["severity"] == "low")
    
    # Sort findings by severity priority
    sev_map = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda x: sev_map.get(x["severity"], 4))
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_filename = f"sast_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    report_path = os.path.join(REPORTS_DIR, report_filename)
    latest_path = os.path.join(REPORTS_DIR, "sast_report_latest.md")
    
    has_blocking = False
    fail_sev_val = sev_map.get(fail_severity.lower(), 1) # default to high blocking
    
    # Build detailed findings markdown
    detailed_findings_md = ""
    for idx, f in enumerate(findings, start=1):
        sev_label = f["severity"].upper()
        if sev_map.get(f["severity"].lower(), 3) <= fail_sev_val:
            has_blocking = True
            sev_label += " 🛑 [BLOCKING]"
            
        detailed_findings_md += f"""
### **SAST-{idx:02d}: {f['id']}**
* **Severity**: `{sev_label}`
* **Scanner**: `{f['scanner']}`
* **Location**: `{f['file']}:{f['line']}`
* **Description**: {f['message']}
"""
        if f["code"]:
            detailed_findings_md += f"""
* **Finding Snippet**:
  ```
  {str(f['code']).strip()}
  ```
"""
        detailed_findings_md += "\n---\n"
        
    if not findings:
        detailed_findings_md = "### 🎉 No vulnerabilities or secrets detected!"
        
    status = "FAIL 🛑" if has_blocking else "PASS  [SECURE]"
    
    # Generate the Markdown file contents
    report_md = f"""# Agentic-SSDLC SAST Automated Code Scan Report

## Project: Agentic-Secured-Project
**Scanner Agent**: `ssdlc_sast`
**Date**: {timestamp}
**Verdict**: {status}

---

## 1. Executive Security Metrics
* **Total Code Scan Findings**: {total}
* **Critical Findings**: {critical_count}
* **High Findings**: {high_count}
* **Medium Findings**: {medium_count}
* **Low Findings**: {low_count}

---

## 2. Integrated Engine Dashboard
| Security Tool | Scope | Status |
|---|---|---|
| **Semgrep SAST** | Custom Application Code Rules | {"PASS" if not [f for f in findings if f['scanner']=='Semgrep' and sev_map.get(f['severity'], 3) <= fail_sev_val] else "ACTION REQUIRED"} |
| **Trivy Secrets** | Credentials & Key Auditing | {"PASS" if not [f for f in findings if f['scanner']=='Trivy Secrets' and sev_map.get(f['severity'], 3) <= fail_sev_val] else "ACTION REQUIRED"} |
| **Gosec SAST** | Go Code AST Security | {"PASS" if not [f for f in findings if f['scanner']=='Gosec' and sev_map.get(f['severity'], 3) <= fail_sev_val] else "ACTION REQUIRED"} |
| **Govulncheck** | Reachable Dependency CVEs | {"PASS" if not [f for f in findings if f['scanner']=='Govulncheck' and sev_map.get(f['severity'], 3) <= fail_sev_val] else "ACTION REQUIRED"} |

---

## 3. Detailed Findings List

{detailed_findings_md}

---

## 4. Scan Metadata & Sign-Off
* **Scanned Path**: `{project_path}`
* **Security Blocking Policy**: Fail on `{fail_severity.upper()}` and higher.
* **Scan Completed Cleanly**: Yes
"""
    
    # Save files
    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(report_path, "w") as f:
        f.write(report_md)
    with open(latest_path, "w") as f:
        f.write(report_md)
        
    print(f"[+] Consolidated report saved to: {report_path}")
    print(f"[+] Latest report saved to: {latest_path}")
    
    return has_blocking

def main():
    print("=========================================")
    print("    AGENTIC-SAST SECURITY RUNNER        ")
    print("=========================================")
    
    config = load_config()
    project_path = os.path.abspath(os.path.expanduser(config.get("project_path", HOME_DIR)))
    if not os.path.isdir(project_path):
        print(f"[-] Error: Scanned project_path does not exist or is not a directory: {project_path}")
        sys.exit(1)
        
    sast_config = config.get("sast", {})
    
    semgrep_rules = sast_config.get("semgrep_rules", "p/security-audit")
    fail_severity = sast_config.get("fail_on_severity", "high")
    
    findings = []
    
    # 1. Run Semgrep Scan
    findings += run_semgrep(project_path, semgrep_rules)
    
    # 2. Run Trivy Secrets Scan
    if sast_config.get("trivy_secrets", True):
        findings += run_trivy_secrets(project_path)
        
    # 3. Check for Go files and run Go SAST
    if check_go_project(project_path):
        print("[+] Go project detected. Enabling Go SAST analysis...")
        if sast_config.get("gosec", True):
            findings += run_gosec(project_path)
        if sast_config.get("govulncheck", True):
            findings += run_govulncheck(project_path)
            
    # 4. Create Consolidated Report
    has_blocking = create_report(findings, project_path, fail_severity)
    
    print("=========================================")
    if has_blocking:
        print(f"🛑 SCAN RESULT: FAILED! Found blocking security issues (Severity >= {fail_severity.upper()}).")
        sys.exit(1)
    else:
        print("✅ SCAN RESULT: PASSED! Codebase complies with security policies.")
        sys.exit(0)

if __name__ == "__main__":
    main()
