# NVD CVE 2025 Dataset Processing Report

**Processing Date:** 2025-08-05 18:19:33

## Processing Summary

- **Total CVEs Processed:** 20,814
- **Successful Conversions:** 20,814
- **Training Examples Generated:** 60,893
- **CVE Database Entries:** 20,814
- **Skipped Entries:** 0

## Vulnerability Categories

- **Injection:** 6,686 vulnerabilities
- **Other Vulnerability:** 4,855 vulnerabilities
- **Authorization:** 2,013 vulnerabilities
- **Buffer Overflow:** 1,657 vulnerabilities
- **Remote Code Execution:** 1,085 vulnerabilities
- **Denial of Service:** 904 vulnerabilities
- **Input Validation:** 897 vulnerabilities
- **Authentication:** 818 vulnerabilities
- **Information Disclosure:** 523 vulnerabilities
- **Memory Management:** 457 vulnerabilities
- **Cross-Site Scripting:** 434 vulnerabilities
- **Privilege Escalation:** 201 vulnerabilities
- **Race Condition:** 91 vulnerabilities
- **Cryptographic:** 79 vulnerabilities
- **Directory Traversal:** 75 vulnerabilities
- **Command Injection:** 20 vulnerabilities
- **SQL Injection:** 19 vulnerabilities

## Severity Distribution

- **MEDIUM:** 10,357 vulnerabilities
- **HIGH:** 6,551 vulnerabilities
- **CRITICAL:** 1,718 vulnerabilities
- **UNKNOWN:** 1,543 vulnerabilities
- **LOW:** 639 vulnerabilities
- **NONE:** 6 vulnerabilities

## Generated Files

- `complete_nvd_cve_training_dataset.json` - Comprehensive training data
- `complete_nvd_cve_database.json` - CVE database for lookups
- `nvd_processing_statistics.json` - Detailed statistics
- `nvd_processing_report.md` - This report

## Usage Instructions

1. **Training Data:** Use `complete_nvd_cve_training_dataset.json` for LLM training
2. **CVE Database:** Use `complete_nvd_cve_database.json` for CVE lookups
3. **Integration:** Update your backend to load these new datasets

