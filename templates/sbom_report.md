# Software Bill of Materials (SBOM) & Supply Chain Security Report

## Project: Agentic-Secured-Project
**Auditor Agent**: `ssdlc_sbom` (Agent)
**Date**: [Insert Timestamp]
**Status**: `[PASS / FAIL]`

---

## 1. Supply Chain Health Metrics
* **SBOM Specifications**: CycloneDX v1.5 JSON
* **Total Packages Identified**: [Count]
* **Vulnerable Packages**: [Count]
* **Critical CVEs**: [Count]
* **High CVEs**: [Count]
* **Medium/Low CVEs**: [Count]

---

## 2. Dependency Vulnerability Audit
| Package | Version | CVE ID | Severity | Description / Mitigation |
|---|---|---|---|---|
| `[pkg-name]` | `[v.v.v]` | `[CVE-YYYY-XXXX]` | `[Critical/High]` | `[Description and upgrade path]` |

---

## 3. Full Inventory (Software Bill of Materials)
*Here is the complete catalog of direct and transitive dependencies registered in the project.*

| Package Name | Version | License | Ecosystem / Type |
|---|---|---|---|
| `[example-pkg]` | `[v1.0.0]` | `[MIT]` | `[Go / pip / npm]` |

---

## 4. Audit Metadata & Sign-Off
* **SBOM Generator**: `syft`
* **Vulnerability Scanner**: `trivy sbom`
* **Compliance Threshold**: Fail on `[High / Critical]` CVEs
