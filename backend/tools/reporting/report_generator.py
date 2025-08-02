"""
Security assessment report generator.
"""

import os
import logging
from typing import Dict, List, Any
from datetime import datetime
from pathlib import Path
import json

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate security assessment reports in various formats."""
    
    def __init__(self):
        self.reports_dir = Path("./reports")
        self.reports_dir.mkdir(exist_ok=True)
    
    async def generate(self, report_id: str, scan_results: Dict[str, Any], format: str = "pdf") -> str:
        """Generate security report."""
        try:
            if format.lower() == "pdf":
                return await self._generate_pdf_report(report_id, scan_results)
            elif format.lower() == "html":
                return await self._generate_html_report(report_id, scan_results)
            elif format.lower() == "json":
                return await self._generate_json_report(report_id, scan_results)
            elif format.lower() == "markdown":
                return await self._generate_markdown_report(report_id, scan_results)
            else:
                raise ValueError(f"Unsupported format: {format}")
                
        except Exception as e:
            logger.error(f"Report generation error: {e}")
            raise
    
    async def _generate_pdf_report(self, report_id: str, scan_results: Dict[str, Any]) -> str:
        """Generate PDF report."""
        try:
            # For demonstration, create a simple text report
            # In production, use reportlab or similar for proper PDF generation
            
            report_path = self.reports_dir / f"{report_id}.pdf"
            content = self._generate_report_content(scan_results)
            
            # Mock PDF generation
            with open(report_path, "w") as f:
                f.write("PDF Report Placeholder\\n")
                f.write("=" * 50 + "\\n")
                f.write(content)
                f.write("\\n\\nNote: Install reportlab for proper PDF generation")
            
            logger.info(f"PDF report generated: {report_path}")
            return str(report_path)
            
        except Exception as e:
            logger.error(f"PDF generation error: {e}")
            raise
    
    async def _generate_html_report(self, report_id: str, scan_results: Dict[str, Any]) -> str:
        """Generate HTML report."""
        report_path = self.reports_dir / f"{report_id}.html"
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {report_id}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            line-height: 1.6;
            color: #333;
        }}
        .header {{
            background: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .section {{
            margin-bottom: 30px;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }}
        .vulnerability {{
            background: #f8f9fa;
            border-left: 4px solid #dc3545;
            padding: 10px;
            margin: 10px 0;
        }}
        .severity-critical {{ border-left-color: #dc3545; }}
        .severity-high {{ border-left-color: #fd7e14; }}
        .severity-medium {{ border-left-color: #ffc107; }}
        .severity-low {{ border-left-color: #28a745; }}
        .severity-info {{ border-left-color: #17a2b8; }}
        .recommendations {{
            background: #e3f2fd;
            padding: 15px;
            border-radius: 5px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p>Report ID: {report_id}</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p>This security assessment identified potential vulnerabilities and security issues in the target system.</p>
        {self._generate_summary_html(scan_results)}
    </div>
    
    <div class="section">
        <h2>Scan Results</h2>
        {self._generate_scan_results_html(scan_results)}
    </div>
    
    <div class="section">
        <h2>Vulnerabilities</h2>
        {self._generate_vulnerabilities_html(scan_results)}
    </div>
    
    <div class="section recommendations">
        <h2>Recommendations</h2>
        {self._generate_recommendations_html(scan_results)}
    </div>
    
    <div class="section">
        <h2>Technical Details</h2>
        <p>This report was generated using the Cyber LLM ethical hacking assistant.</p>
        <p>For questions or clarifications, please contact the security team.</p>
    </div>
</body>
</html>"""
        
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {report_path}")
        return str(report_path)
    
    async def _generate_json_report(self, report_id: str, scan_results: Dict[str, Any]) -> str:
        """Generate JSON report."""
        report_path = self.reports_dir / f"{report_id}.json"
        
        report_data = {
            "report_id": report_id,
            "generated_at": datetime.now().isoformat(),
            "report_type": "security_assessment",
            "scan_results": scan_results,
            "metadata": {
                "tool": "Cyber LLM",
                "version": "1.0.0",
                "format": "json"
            }
        }
        
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, default=str)
        
        logger.info(f"JSON report generated: {report_path}")
        return str(report_path)
    
    async def _generate_markdown_report(self, report_id: str, scan_results: Dict[str, Any]) -> str:
        """Generate Markdown report."""
        report_path = self.reports_dir / f"{report_id}.md"
        
        markdown_content = f"""# Security Assessment Report

**Report ID:** {report_id}  
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Tool:** Cyber LLM Ethical Hacking Assistant

## Executive Summary

This security assessment report contains findings from automated scanning and analysis.

{self._generate_summary_markdown(scan_results)}

## Scan Results

{self._generate_scan_results_markdown(scan_results)}

## Vulnerabilities Found

{self._generate_vulnerabilities_markdown(scan_results)}

## Recommendations

{self._generate_recommendations_markdown(scan_results)}

## Technical Notes

- This report was generated automatically
- Manual verification of findings is recommended
- Follow responsible disclosure practices
- Only test on authorized systems

---
*Generated by Cyber LLM - Ethical Hacking AI Assistant*
"""
        
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(markdown_content)
        
        logger.info(f"Markdown report generated: {report_path}")
        return str(report_path)
    
    def _generate_report_content(self, scan_results: Dict[str, Any]) -> str:
        """Generate basic report content."""
        content = f"""
SECURITY ASSESSMENT REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

EXECUTIVE SUMMARY
=================
Target: {scan_results.get('target', 'Unknown')}
Scan Type: {scan_results.get('scan_type', 'General')}
Total Findings: {scan_results.get('total_findings', 0)}

VULNERABILITY BREAKDOWN
======================
"""
        
        severity_breakdown = scan_results.get('severity_breakdown', {})
        for severity, count in severity_breakdown.items():
            content += f"{severity.upper()}: {count}\\n"
        
        content += "\\nRECOMMENDATIONS\\n"
        content += "================\\n"
        
        recommendations = scan_results.get('recommendations', [])
        for i, rec in enumerate(recommendations, 1):
            content += f"{i}. {rec}\\n"
        
        return content
    
    def _generate_summary_html(self, scan_results: Dict[str, Any]) -> str:
        """Generate HTML summary section."""
        severity_breakdown = scan_results.get('severity_breakdown', {})
        total_findings = sum(severity_breakdown.values())
        
        html = f"""
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Target</td><td>{scan_results.get('target', 'Unknown')}</td></tr>
            <tr><td>Total Findings</td><td>{total_findings}</td></tr>
        </table>
        
        <h3>Severity Breakdown</h3>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
        """
        
        for severity, count in severity_breakdown.items():
            html += f"<tr><td class='severity-{severity}'>{severity.title()}</td><td>{count}</td></tr>"
        
        html += "</table>"
        return html
    
    def _generate_scan_results_html(self, scan_results: Dict[str, Any]) -> str:
        """Generate HTML scan results section."""
        return f"<pre>{json.dumps(scan_results, indent=2, default=str)}</pre>"
    
    def _generate_vulnerabilities_html(self, scan_results: Dict[str, Any]) -> str:
        """Generate HTML vulnerabilities section."""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        html = ""
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            html += f"""
            <div class="vulnerability severity-{severity}">
                <h4>{vuln.get('name', 'Unknown Vulnerability')}</h4>
                <p><strong>Severity:</strong> {severity.title()}</p>
                <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
                <p><strong>Location:</strong> {vuln.get('matched_at', 'Unknown')}</p>
            </div>
            """
        
        return html or "<p>No vulnerabilities found.</p>"
    
    def _generate_recommendations_html(self, scan_results: Dict[str, Any]) -> str:
        """Generate HTML recommendations section."""
        recommendations = scan_results.get('recommendations', [])
        html = "<ul>"
        
        for rec in recommendations:
            html += f"<li>{rec}</li>"
        
        html += "</ul>"
        return html
    
    def _generate_summary_markdown(self, scan_results: Dict[str, Any]) -> str:
        """Generate Markdown summary section."""
        severity_breakdown = scan_results.get('severity_breakdown', {})
        
        markdown = f"""
| Metric | Value |
|--------|-------|
| Target | {scan_results.get('target', 'Unknown')} |
| Total Findings | {sum(severity_breakdown.values())} |

### Severity Breakdown

| Severity | Count |
|----------|-------|
"""
        
        for severity, count in severity_breakdown.items():
            markdown += f"| {severity.title()} | {count} |\\n"
        
        return markdown
    
    def _generate_scan_results_markdown(self, scan_results: Dict[str, Any]) -> str:
        """Generate Markdown scan results section."""
        return f"```json\\n{json.dumps(scan_results, indent=2, default=str)}\\n```"
    
    def _generate_vulnerabilities_markdown(self, scan_results: Dict[str, Any]) -> str:
        """Generate Markdown vulnerabilities section."""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        markdown = ""
        
        for i, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get('severity', 'unknown')
            markdown += f"""
### {i}. {vuln.get('name', 'Unknown Vulnerability')}

- **Severity:** {severity.title()}
- **Description:** {vuln.get('description', 'No description available')}
- **Location:** {vuln.get('matched_at', 'Unknown')}

"""
        
        return markdown or "No vulnerabilities found."
    
    def _generate_recommendations_markdown(self, scan_results: Dict[str, Any]) -> str:
        """Generate Markdown recommendations section."""
        recommendations = scan_results.get('recommendations', [])
        markdown = ""
        
        for i, rec in enumerate(recommendations, 1):
            markdown += f"{i}. {rec}\\n"
        
        return markdown