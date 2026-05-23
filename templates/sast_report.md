# Static Application Security Testing (SAST) Report

## Project: Aegis-Secured-Project
**Scanner Agent**: `ssdlc_sast` (Agent)
**Date**: [Insert Timestamp]
**Status**: `[PASS / FAIL]`

---

## 1. Executive Security Metrics
* **Total Scans Executed**: [Count]
* **Total Findings**: [Count]
* **Critical Findings**: [Count]
* **High Findings**: [Count]
* **Medium Findings**: [Count]
* **Low Findings**: [Count]

---

## 2. Scan Summary
| Scanner Engine | Status | Issues Found |
|---|---|---|
| **Semgrep SAST** | [Pass/Fail] | [Count] |
| **Trivy Secret Scanner** | [Pass/Fail] | [Count] |
| **Go Security (gosec)** | [Pass/Fail] | [Count] |
| **Go Vulnerability (govulncheck)** | [Pass/Fail] | [Count] |

---

## 3. Detailed Findings List

### **[ID] [Vulnerability Name / Rule ID]**
* **Severity**: `[Critical / High / Medium / Low]`
* **Scanner**: `[Semgrep / Trivy / gosec / govulncheck]`
* **Location**: `[file_path:line_number]`
* **Finding Snippet**:
  ```[language]
  [vulnerable code snippet]
  ```
* **Vulnerability Description**:
  [Explain the vulnerability and why it was flagged]
* **Remediation Strategy**:
  [Explain how to fix it]

---

## 4. Scan Metadata & Sign-Off
* **Scanned Path**: `/home/jed`
* **Vulnerability Threshold Blocking Policy**: Fail on `[High / Critical]`
* **Scanner Engine Command**: `[Exact CLI command run]`
