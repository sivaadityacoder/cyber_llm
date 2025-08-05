#!/usr/bin/env python3
"""
Complete NVD CVE 2025 Dataset Processor
Processes the entire nvdcve-2.0-2025.json dataset (20,814+ CVEs) 
for comprehensive cybersecurity LLM training.
"""

import json
import re
from datetime import datetime
from typing import Dict, List, Any
import argparse
import logging
from pathlib import Path

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ComprehensiveCVEProcessor:
    def __init__(self, input_file: str, output_dir: str = "data"):
        self.input_file = input_file
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Statistics
        self.total_processed = 0
        self.successful_conversions = 0
        self.skipped_entries = 0
        
        # Training data storage
        self.training_data = []
        self.cve_database = []
        self.vulnerability_categories = {}
        self.severity_distribution = {}
        
    def extract_severity(self, cve_data: Dict) -> tuple:
        """Extract CVSS score and severity from CVE data"""
        try:
            # Try different CVSS versions
            metrics = cve_data.get('metrics', {})
            
            # CVSS v4.0
            if 'cvssMetricV40' in metrics:
                metric = metrics['cvssMetricV40'][0]['cvssData']
                return metric.get('baseScore', 0), metric.get('baseSeverity', 'UNKNOWN')
            
            # CVSS v3.1
            elif 'cvssMetricV31' in metrics:
                metric = metrics['cvssMetricV31'][0]['cvssData']
                return metric.get('baseScore', 0), metric.get('baseSeverity', 'UNKNOWN')
            
            # CVSS v3.0
            elif 'cvssMetricV30' in metrics:
                metric = metrics['cvssMetricV30'][0]['cvssData']
                return metric.get('baseScore', 0), metric.get('baseSeverity', 'UNKNOWN')
            
            # CVSS v2.0
            elif 'cvssMetricV2' in metrics:
                metric = metrics['cvssMetricV2'][0]['cvssData']
                return metric.get('baseScore', 0), metric.get('baseSeverity', 'UNKNOWN')
            
            return 0, 'UNKNOWN'
        except (KeyError, IndexError, TypeError):
            return 0, 'UNKNOWN'
    
    def extract_attack_vector(self, cve_data: Dict) -> str:
        """Extract attack vector information"""
        try:
            metrics = cve_data.get('metrics', {})
            for version in ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30']:
                if version in metrics:
                    return metrics[version][0]['cvssData'].get('attackVector', 'UNKNOWN')
            return 'UNKNOWN'
        except (KeyError, IndexError, TypeError):
            return 'UNKNOWN'
    
    def extract_cwe_info(self, cve_data: Dict) -> List[str]:
        """Extract CWE (Common Weakness Enumeration) information"""
        cwes = []
        try:
            weaknesses = cve_data.get('weaknesses', [])
            for weakness in weaknesses:
                for desc in weakness.get('description', []):
                    cwe_id = desc.get('value', '')
                    if cwe_id.startswith('CWE-'):
                        cwes.append(cwe_id)
            return cwes
        except (KeyError, TypeError):
            return []
    
    def categorize_vulnerability(self, description: str, cwes: List[str]) -> str:
        """Categorize vulnerability based on description and CWEs"""
        desc_lower = description.lower()
        
        # CWE-based categorization
        cwe_categories = {
            'Injection': ['CWE-89', 'CWE-79', 'CWE-77', 'CWE-78', 'CWE-91', 'CWE-564'],
            'Authentication': ['CWE-287', 'CWE-306', 'CWE-798', 'CWE-521', 'CWE-620'],
            'Authorization': ['CWE-285', 'CWE-862', 'CWE-863', 'CWE-269', 'CWE-284'],
            'Buffer Overflow': ['CWE-120', 'CWE-119', 'CWE-121', 'CWE-122', 'CWE-787'],
            'Information Disclosure': ['CWE-200', 'CWE-209', 'CWE-215', 'CWE-532', 'CWE-538'],
            'Cryptographic': ['CWE-327', 'CWE-328', 'CWE-330', 'CWE-331', 'CWE-347'],
            'Input Validation': ['CWE-20', 'CWE-74', 'CWE-129', 'CWE-190', 'CWE-22'],
            'Race Condition': ['CWE-362', 'CWE-367', 'CWE-364', 'CWE-366', 'CWE-368'],
            'Memory Management': ['CWE-401', 'CWE-402', 'CWE-404', 'CWE-415', 'CWE-416']
        }
        
        for category, cwe_list in cwe_categories.items():
            if any(cwe in cwes for cwe in cwe_list):
                return category
        
        # Description-based categorization
        if any(term in desc_lower for term in ['sql injection', 'sqli', 'sql inject']):
            return 'SQL Injection'
        elif any(term in desc_lower for term in ['cross-site scripting', 'xss']):
            return 'Cross-Site Scripting'
        elif any(term in desc_lower for term in ['buffer overflow', 'buffer overrun']):
            return 'Buffer Overflow'
        elif any(term in desc_lower for term in ['denial of service', 'dos', 'crash']):
            return 'Denial of Service'
        elif any(term in desc_lower for term in ['remote code execution', 'rce', 'code execution']):
            return 'Remote Code Execution'
        elif any(term in desc_lower for term in ['privilege escalation', 'elevation']):
            return 'Privilege Escalation'
        elif any(term in desc_lower for term in ['information disclosure', 'information leak']):
            return 'Information Disclosure'
        elif any(term in desc_lower for term in ['authentication', 'login', 'credential']):
            return 'Authentication'
        elif any(term in desc_lower for term in ['directory traversal', 'path traversal']):
            return 'Directory Traversal'
        elif any(term in desc_lower for term in ['command injection', 'shell injection']):
            return 'Command Injection'
        else:
            return 'Other Vulnerability'
    
    def create_training_examples(self, cve_data: Dict) -> List[Dict]:
        """Create comprehensive training examples from CVE data"""
        examples = []
        
        cve_id = cve_data.get('id', 'UNKNOWN')
        descriptions = cve_data.get('descriptions', [])
        
        # Get English description
        main_description = ""
        for desc in descriptions:
            if desc.get('lang') == 'en':
                main_description = desc.get('value', '')
                break
        
        if not main_description:
            return examples
        
        # Extract metadata
        score, severity = self.extract_severity(cve_data)
        attack_vector = self.extract_attack_vector(cve_data)
        cwes = self.extract_cwe_info(cve_data)
        category = self.categorize_vulnerability(main_description, cwes)
        
        # Update statistics
        self.vulnerability_categories[category] = self.vulnerability_categories.get(category, 0) + 1
        self.severity_distribution[severity] = self.severity_distribution.get(severity, 0) + 1
        
        # Training Example 1: CVE Analysis
        examples.append({
            "instruction": f"Analyze CVE {cve_id} and provide a comprehensive security assessment.",
            "input": f"CVE ID: {cve_id}\nDescription: {main_description}",
            "response": f"""**CVE Analysis: {cve_id}**

**Vulnerability Description:**
{main_description}

**Technical Assessment:**
- **CVSS Score:** {score}/10.0
- **Severity Level:** {severity}
- **Attack Vector:** {attack_vector}
- **Category:** {category}
- **CWE References:** {', '.join(cwes) if cwes else 'Not specified'}

**Risk Impact:**
This vulnerability poses a {severity.lower()} risk to affected systems. The attack can be initiated via {attack_vector.lower()} vector, potentially leading to {category.lower()} issues.

**Mitigation Recommendations:**
1. Apply security patches immediately when available
2. Implement input validation and sanitization
3. Use defense-in-depth security strategies
4. Monitor systems for suspicious activities
5. Conduct regular security assessments

**Detection Methods:**
- Monitor for unusual {category.lower()} patterns
- Implement security logging and alerting
- Use vulnerability scanners regularly
- Conduct penetration testing"""
        })
        
        # Training Example 2: Vulnerability Type Explanation
        examples.append({
            "instruction": f"Explain {category} vulnerabilities and how to prevent them.",
            "input": f"I need to understand {category} vulnerabilities. Can you explain them?",
            "response": f"""**Understanding {category} Vulnerabilities**

**Definition:**
{category} vulnerabilities are security weaknesses that allow attackers to compromise system security through {category.lower()} techniques.

**Common Attack Methods:**
Based on CVE data analysis, {category.lower()} attacks typically involve:
- Exploiting input validation weaknesses
- Bypassing security controls
- Leveraging system misconfigurations

**Real-World Example:**
{cve_id} demonstrates a typical {category.lower()} vulnerability where:
{main_description[:200]}...

**Prevention Strategies:**
1. **Input Validation:** Implement strict input validation and sanitization
2. **Security Controls:** Deploy appropriate security controls and monitoring
3. **Code Review:** Conduct thorough security code reviews
4. **Testing:** Perform regular security testing and vulnerability assessments
5. **Updates:** Keep systems and software updated

**Detection Techniques:**
- Static code analysis tools
- Dynamic application security testing
- Runtime application self-protection (RASP)
- Security information and event management (SIEM)"""
        })
        
        # Training Example 3: CVSS Score Explanation
        if score > 0:
            examples.append({
                "instruction": f"Explain the CVSS score {score} and its security implications.",
                "input": f"What does a CVSS score of {score} mean for cybersecurity?",
                "response": f"""**CVSS Score Analysis: {score}/10.0**

**Severity Classification:** {severity}

**Risk Level Interpretation:**
- **Score Range:** {score} falls in the {severity.lower()} risk category
- **Business Impact:** This score indicates {severity.lower()} potential impact on confidentiality, integrity, and availability
- **Urgency:** {self.get_urgency_level(severity)} priority for remediation

**Technical Factors Contributing to Score:**
- **Attack Vector:** {attack_vector} - determines how the vulnerability can be exploited
- **Attack Complexity:** Complexity of the attack required
- **Privileges Required:** Level of access needed to exploit
- **User Interaction:** Whether user interaction is required

**Remediation Priority:**
{self.get_remediation_guidance(severity, score)}

**Real-World Context:**
CVE {cve_id} exemplifies a {severity.lower()} severity vulnerability that requires appropriate security measures and response protocols."""
            })
        
        return examples
    
    def get_urgency_level(self, severity: str) -> str:
        """Get urgency level based on severity"""
        urgency_map = {
            'CRITICAL': 'Immediate',
            'HIGH': 'High',
            'MEDIUM': 'Medium',
            'LOW': 'Low',
            'UNKNOWN': 'Assessment Required'
        }
        return urgency_map.get(severity, 'Assessment Required')
    
    def get_remediation_guidance(self, severity: str, score: float) -> str:
        """Get remediation guidance based on severity and score"""
        if severity == 'CRITICAL' or score >= 9.0:
            return "Immediate action required. Patch within 24-48 hours. Consider emergency change procedures."
        elif severity == 'HIGH' or score >= 7.0:
            return "High priority patching required within 7 days. Implement compensating controls if patching is delayed."
        elif severity == 'MEDIUM' or score >= 4.0:
            return "Medium priority patching within 30 days. Monitor for exploit activity and implement additional security measures."
        elif severity == 'LOW' or score >= 0.1:
            return "Low priority patching during next maintenance window. Document and track for future remediation."
        else:
            return "Assess risk based on environment-specific factors and implement appropriate controls."
    
    def process_dataset(self):
        """Process the entire CVE dataset"""
        logger.info(f"Starting processing of {self.input_file}")
        
        try:
            with open(self.input_file, 'r', encoding='utf-8') as f:
                logger.info("Loading JSON data (this may take a few minutes for large files)...")
                data = json.load(f)
            
            vulnerabilities = data.get('vulnerabilities', [])
            total_cves = len(vulnerabilities)
            
            logger.info(f"Found {total_cves} CVE entries to process")
            
            # Process in batches for memory efficiency
            batch_size = 100
            for i in range(0, total_cves, batch_size):
                batch = vulnerabilities[i:i + batch_size]
                logger.info(f"Processing batch {i//batch_size + 1}/{(total_cves + batch_size - 1)//batch_size} ({i+1}-{min(i+batch_size, total_cves)})")
                
                for vuln_entry in batch:
                    self.total_processed += 1
                    
                    try:
                        cve_data = vuln_entry.get('cve', {})
                        
                        # Create training examples
                        examples = self.create_training_examples(cve_data)
                        
                        if examples:
                            self.training_data.extend(examples)
                            self.successful_conversions += 1
                            
                            # Create simplified CVE database entry
                            cve_id = cve_data.get('id', 'UNKNOWN')
                            descriptions = cve_data.get('descriptions', [])
                            main_desc = ""
                            for desc in descriptions:
                                if desc.get('lang') == 'en':
                                    main_desc = desc.get('value', '')
                                    break
                            
                            score, severity = self.extract_severity(cve_data)
                            cwes = self.extract_cwe_info(cve_data)
                            category = self.categorize_vulnerability(main_desc, cwes)
                            
                            self.cve_database.append({
                                "cve_id": cve_id,
                                "title": f"{category} vulnerability in {cve_id}",
                                "description": main_desc,
                                "severity": severity,
                                "cvss_score": score,
                                "category": category,
                                "cwes": cwes,
                                "published": cve_data.get('published', ''),
                                "lastModified": cve_data.get('lastModified', '')
                            })
                        else:
                            self.skipped_entries += 1
                            
                    except Exception as e:
                        logger.warning(f"Error processing CVE entry: {e}")
                        self.skipped_entries += 1
                        continue
                
                # Progress update
                progress = (i + batch_size) / total_cves * 100
                logger.info(f"Progress: {progress:.1f}% - Generated {len(self.training_data)} training examples")
        
        except Exception as e:
            logger.error(f"Error processing dataset: {e}")
            raise
    
    def save_results(self):
        """Save all processed data to files"""
        logger.info("Saving processed data...")
        
        # Save comprehensive training dataset
        training_file = self.output_dir / "complete_nvd_cve_training_dataset.json"
        with open(training_file, 'w', encoding='utf-8') as f:
            json.dump(self.training_data, f, indent=2, ensure_ascii=False)
        logger.info(f"Saved {len(self.training_data)} training examples to {training_file}")
        
        # Save CVE database
        cve_db_file = self.output_dir / "complete_nvd_cve_database.json"
        with open(cve_db_file, 'w', encoding='utf-8') as f:
            json.dump(self.cve_database, f, indent=2, ensure_ascii=False)
        logger.info(f"Saved {len(self.cve_database)} CVE entries to {cve_db_file}")
        
        # Save statistics
        stats = {
            "processing_summary": {
                "total_cves_processed": self.total_processed,
                "successful_conversions": self.successful_conversions,
                "skipped_entries": self.skipped_entries,
                "training_examples_generated": len(self.training_data),
                "cve_database_entries": len(self.cve_database)
            },
            "vulnerability_categories": self.vulnerability_categories,
            "severity_distribution": self.severity_distribution,
            "processing_timestamp": datetime.now().isoformat()
        }
        
        stats_file = self.output_dir / "nvd_processing_statistics.json"
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
        logger.info(f"Saved processing statistics to {stats_file}")
        
        # Create summary report
        self.create_summary_report()
    
    def create_summary_report(self):
        """Create a human-readable summary report"""
        report_file = self.output_dir / "nvd_processing_report.md"
        
        with open(report_file, 'w') as f:
            f.write("# NVD CVE 2025 Dataset Processing Report\n\n")
            f.write(f"**Processing Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## Processing Summary\n\n")
            f.write(f"- **Total CVEs Processed:** {self.total_processed:,}\n")
            f.write(f"- **Successful Conversions:** {self.successful_conversions:,}\n")
            f.write(f"- **Training Examples Generated:** {len(self.training_data):,}\n")
            f.write(f"- **CVE Database Entries:** {len(self.cve_database):,}\n")
            f.write(f"- **Skipped Entries:** {self.skipped_entries:,}\n\n")
            
            f.write("## Vulnerability Categories\n\n")
            for category, count in sorted(self.vulnerability_categories.items(), key=lambda x: x[1], reverse=True):
                f.write(f"- **{category}:** {count:,} vulnerabilities\n")
            f.write("\n")
            
            f.write("## Severity Distribution\n\n")
            for severity, count in sorted(self.severity_distribution.items(), key=lambda x: x[1], reverse=True):
                f.write(f"- **{severity}:** {count:,} vulnerabilities\n")
            f.write("\n")
            
            f.write("## Generated Files\n\n")
            f.write("- `complete_nvd_cve_training_dataset.json` - Comprehensive training data\n")
            f.write("- `complete_nvd_cve_database.json` - CVE database for lookups\n")
            f.write("- `nvd_processing_statistics.json` - Detailed statistics\n")
            f.write("- `nvd_processing_report.md` - This report\n\n")
            
            f.write("## Usage Instructions\n\n")
            f.write("1. **Training Data:** Use `complete_nvd_cve_training_dataset.json` for LLM training\n")
            f.write("2. **CVE Database:** Use `complete_nvd_cve_database.json` for CVE lookups\n")
            f.write("3. **Integration:** Update your backend to load these new datasets\n\n")
        
        logger.info(f"Created summary report: {report_file}")

def main():
    parser = argparse.ArgumentParser(description="Process complete NVD CVE 2025 dataset for LLM training")
    parser.add_argument("--input", default="nvdcve-2.0-2025.json", help="Input CVE JSON file")
    parser.add_argument("--output-dir", default=".", help="Output directory for processed files")
    
    args = parser.parse_args()
    
    processor = ComprehensiveCVEProcessor(args.input, args.output_dir)
    
    try:
        processor.process_dataset()
        processor.save_results()
        
        logger.info("🎉 Complete NVD CVE dataset processing finished successfully!")
        logger.info(f"Generated {len(processor.training_data):,} training examples from {processor.total_processed:,} CVEs")
        
    except Exception as e:
        logger.error(f"Processing failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
