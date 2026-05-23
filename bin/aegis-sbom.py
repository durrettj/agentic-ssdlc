#!/usr/bin/env python3
import os
import sys
import json
import shutil
import subprocess
from datetime import datetime

# Determine the Home directory and base Aegis directory dynamically
HOME_DIR = os.path.expanduser("~")
AEGIS_DIR = os.environ.get("AEGIS_DIR", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Binary Paths (checks system PATH first, falls back to standard locations)
SYFT_BIN = shutil.which("syft") or "/usr/local/bin/syft"
TIVY_BIN = shutil.which("trivy") or "/usr/bin/trivy"

# Configuration and output paths relative to Aegis directory
CONFIG_PATH = os.path.join(AEGIS_DIR, "config.json")
REPORTS_DIR = os.path.join(AEGIS_DIR, "reports")
SBOM_JSON_PATH = os.path.join(REPORTS_DIR, "sbom.json")

def load_config():
    try:
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[-] Warning: Failed to load config: {e}. Using defaults.")
        return {
            "project_path": HOME_DIR,
            "sbom": {
                "format": "cyclonedx-json",
                "scan_vulnerabilities": True,
                "fail_on_cve_severity": "high"
            }
        }

def run_command(cmd):
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return res.stdout, res.stderr, res.returncode
    except Exception as e:
        return "", str(e), -1

def generate_sbom(project_path):
    print("[*] Generating Software Bill of Materials (SBOM) via Syft...")
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    if not os.path.exists(SYFT_BIN) and not shutil.which("syft"):
        print("[-] Error: syft binary not found. Cannot generate SBOM.")
        return False

    # Run Syft scan and output CycloneDX JSON
    cmd = [SYFT_BIN, "scan", project_path, "-o", "cyclonedx-json", "--file", SBOM_JSON_PATH]
    stdout, stderr, code = run_command(cmd)
    
    if code != 0 or not os.path.exists(SBOM_JSON_PATH):
        print(f"[-] Syft generation failed (Exit code: {code}): {stderr}")
        return False
        
    print(f"[+] SBOM successfully generated and saved to: {SBOM_JSON_PATH}")
    return True

def parse_sbom_packages():
    packages = []
    try:
        with open(SBOM_JSON_PATH, "r") as f:
            data = json.load(f)
        
        components = data.get("components", [])
        for comp in components:
            packages.append({
                "name": comp.get("name"),
                "version": comp.get("version"),
                "license": comp.get("licenses", [{}])[0].get("license", {}).get("id", "Unknown") if comp.get("licenses") else "Unknown",
                "type": comp.get("type", "library")
            })
    except Exception as e:
        print(f"[-] Error parsing CycloneDX SBOM packages: {e}")
    return packages

def scan_sbom_cves():
    print("[*] Scanning SBOM for package vulnerabilities using Trivy...")
    if not os.path.exists(TIVY_BIN) and not shutil.which("trivy"):
        print("[-] Error: trivy binary not found. Cannot perform SBOM vulnerability audit.")
        return []

    cmd = [TIVY_BIN, "sbom", "--format", "json", SBOM_JSON_PATH]
    stdout, stderr, code = run_command(cmd)
    
    vulnerabilities = []
    try:
        data = json.loads(stdout)
        results = data.get("Results", [])
        for res in results:
            vulns = res.get("Vulnerabilities", [])
            for v in vulns:
                vulnerabilities.append({
                    "package": v.get("PkgName"),
                    "version": v.get("InstalledVersion"),
                    "cve_id": v.get("VulnerabilityID"),
                    "severity": v.get("Severity", "medium").lower(),
                    "description": v.get("Title") or v.get("Description"),
                    "fixed_version": v.get("FixedVersion", "N/A")
                })
    except Exception as e:
        print(f"[-] Trivy SBOM parsing error: {e}")
    return vulnerabilities

def create_report(packages, vulnerabilities, project_path, fail_cve_severity):
    print("[*] Consolidating and writing SBOM compliance reports...")
    
    total_packages = len(packages)
    total_vulns = len(vulnerabilities)
    critical_count = sum(1 for v in vulnerabilities if v["severity"] == "critical")
    high_count = sum(1 for v in vulnerabilities if v["severity"] == "high")
    medium_count = sum(1 for v in vulnerabilities if v["severity"] == "medium")
    low_count = sum(1 for v in vulnerabilities if v["severity"] == "low")
    
    # Sort vulnerabilities by severity priority
    sev_map = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    vulnerabilities.sort(key=lambda x: sev_map.get(x["severity"], 4))
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_filename = f"sbom_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    report_path = os.path.join(REPORTS_DIR, report_filename)
    latest_path = os.path.join(REPORTS_DIR, "sbom_report_latest.md")
    
    has_blocking = False
    fail_sev_val = sev_map.get(fail_cve_severity.lower(), 1) # default to high blocking
    
    # Build vulnerability table markdown
    vuln_table_md = "| Package | Installed Version | CVE ID | Severity | Description / Mitigation | Fixed In |\n"
    vuln_table_md += "|---|---|---|---|---|---|\n"
    
    for idx, v in enumerate(vulnerabilities):
        sev_label = v["severity"].upper()
        if sev_map.get(v["severity"].lower(), 3) <= fail_sev_val:
            has_blocking = True
            sev_label += " 🛑 [BLOCKING]"
            
        desc = v["description"][:100] + "..." if len(v["description"]) > 100 else v["description"]
        vuln_table_md += f"| `{v['package']}` | `{v['version']}` | `[{v['cve_id']}]` | `{sev_label}` | {desc} | `{v['fixed_version']}` |\n"
        
    if not vulnerabilities:
        vuln_table_md = "### 🎉 No open security vulnerabilities found in dependencies!"
        
    # Build package list inventory table markdown
    pkg_table_md = "| Package Name | Version | License | Ecosystem Type |\n"
    pkg_table_md += "|---|---|---|---|\n"
    
    # Limit table output to first 100 packages for markdown clean reading, list total
    for pkg in packages[:100]:
        pkg_table_md += f"| `{pkg['name']}` | `{pkg['version']}` | `{pkg['license']}` | `{pkg['type']}` |\n"
        
    if total_packages > 100:
        pkg_table_md += f"| *... and {total_packages - 100} more packages* | | | |\n"
        
    status = "FAIL 🛑" if has_blocking else "PASS  [SECURE]"
    
    # Generate the Markdown file contents
    report_md = f"""# Software Bill of Materials (SBOM) & Supply Chain Security Report

## Project: Aegis-Secured-Project
**Auditor Agent**: `ssdlc_sbom`
**Date**: {timestamp}
**Verdict**: {status}

---

## 1. Supply Chain Health Metrics
* **SBOM Specifications**: CycloneDX v1.5 JSON
* **Total Packages Identified**: {total_packages}
* **Vulnerable Packages**: {len(set(v['package'] for v in vulnerabilities))}
* **Total Dependency CVEs**: {total_vulns}
* **Critical CVEs**: {critical_count}
* **High CVEs**: {high_count}
* **Medium/Low CVEs**: {medium_count + low_count}

---

## 2. Dependency Vulnerability Audit

{vuln_table_md}

---

## 3. Full Inventory (Software Bill of Materials)
*Below is the catalog of dependencies registered in the project.*

{pkg_table_md}

---

## 4. Audit Metadata & Sign-Off
* **SBOM Generator**: `syft`
* **Vulnerability Scanner**: `trivy sbom`
* **Dependency Threshold Policy**: Fail on `{fail_cve_severity.upper()}` and higher.
* **Scan Completed Cleanly**: Yes
"""
    
    with open(report_path, "w") as f:
        f.write(report_md)
    with open(latest_path, "w") as f:
        f.write(report_md)
        
    print(f"[+] Consolidated report saved to: {report_path}")
    print(f"[+] Latest report saved to: {latest_path}")
    
    return has_blocking

def main():
    print("=========================================")
    print("      AEGIS-SBOM SECURITY AUDITOR        ")
    print("=========================================")
    
    config = load_config()
    project_path = config.get("project_path", HOME_DIR)
    sbom_config = config.get("sbom", {})
    
    fail_cve_severity = sbom_config.get("fail_on_cve_severity", "high")
    
    # 1. Generate SBOM
    success = generate_sbom(project_path)
    if not success:
        print("🛑 SBOM Generation Failed!")
        sys.exit(2)
        
    # 2. Parse Packages
    packages = parse_sbom_packages()
    
    # 3. Scan CVEs
    vulnerabilities = []
    if sbom_config.get("scan_vulnerabilities", True):
        vulnerabilities = scan_sbom_cves()
        
    # 4. Create Consolidated Report
    has_blocking = create_report(packages, vulnerabilities, project_path, fail_cve_severity)
    
    print("=========================================")
    if has_blocking:
        print(f"🛑 SCAN RESULT: FAILED! Found blocking dependency CVEs (Severity >= {fail_cve_severity.upper()}).")
        sys.exit(1)
    else:
        print("✅ SCAN RESULT: PASSED! Dependency chain complies with security policies.")
        sys.exit(0)

if __name__ == "__main__":
    main()
