"""
Nuclei scanner integration for vulnerability scanning.
"""

import asyncio
import subprocess
import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

from backend.config import settings

logger = logging.getLogger(__name__)


class NucleiScanner:
    """Nuclei vulnerability scanner integration."""
    
    def __init__(self):
        self.nuclei_path = settings.nuclei_path
        self.timeout = settings.tools_timeout
        
    def is_available(self) -> bool:
        """Check if Nuclei is available."""
        try:
            result = subprocess.run(
                [self.nuclei_path, "-version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False
    
    async def scan(self, target: str, templates: List[str] = None) -> str:
        """Execute Nuclei vulnerability scan."""
        try:
            if not self.is_available():
                return self._mock_nuclei_output(target, templates)
            
            # Build command
            cmd = await self._build_command(target, templates or [])
            
            # Execute scan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout
                )
                
                if process.returncode != 0:
                    error_msg = stderr.decode() if stderr else "Unknown error"
                    logger.warning(f"Nuclei scan warning: {error_msg}")
                    # Nuclei might return non-zero even on successful scans
                
                return stdout.decode()
                
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return "Scan timeout: Operation took too long"
                
        except Exception as e:
            logger.error(f"Nuclei scan error: {e}")
            return self._mock_nuclei_output(target, templates)
    
    async def _build_command(self, target: str, templates: List[str]) -> List[str]:
        """Build Nuclei command."""
        cmd = [self.nuclei_path]
        
        # Target
        cmd.extend(["-u", target])
        
        # Templates
        if templates:
            template_str = ",".join(templates)
            cmd.extend(["-t", template_str])
        else:
            # Use default templates
            cmd.extend(["-t", "technologies/,vulnerabilities/,exposures/"])
        
        # Output format
        cmd.extend(["-json", "-silent"])
        
        # Rate limiting
        cmd.extend(["-rl", "10"])  # 10 requests per second
        
        # Timeout
        cmd.extend(["-timeout", "10"])
        
        return cmd
    
    def _mock_nuclei_output(self, target: str, templates: List[str] = None) -> str:
        """Generate mock Nuclei output for demonstration."""
        mock_results = [
            {
                "template": "technologies/apache-detect",
                "template-url": "https://github.com/projectdiscovery/nuclei-templates/blob/main/technologies/apache-detect.yaml",
                "template-id": "apache-detect",
                "info": {
                    "name": "Apache HTTP Server",
                    "author": ["geeknik"],
                    "tags": ["tech", "apache"],
                    "description": "Apache HTTP Server detection",
                    "severity": "info"
                },
                "type": "http",
                "host": target,
                "matched-at": f"http://{target}",
                "extracted-results": ["Apache/2.4.41 (Ubuntu)"],
                "timestamp": "2024-01-01T00:00:00Z"
            },
            {
                "template": "exposures/configs/apache-status-server-info-disclosure",
                "template-url": "https://github.com/projectdiscovery/nuclei-templates/blob/main/exposures/configs/apache-status-server-info-disclosure.yaml",
                "template-id": "apache-status-server-info-disclosure",
                "info": {
                    "name": "Apache Status Server Info Disclosure",
                    "author": ["pdteam"],
                    "tags": ["exposure", "config", "apache"],
                    "description": "Apache server status page is publicly accessible",
                    "severity": "medium"
                },
                "type": "http",
                "host": target,
                "matched-at": f"http://{target}/server-status",
                "timestamp": "2024-01-01T00:00:00Z"
            }
        ]
        
        # Format as JSON lines
        output_lines = []
        for result in mock_results:
            if not templates or any(tmpl in result["template"] for tmpl in templates):
                output_lines.append(json.dumps(result))
        
        output = "\n".join(output_lines)
        output += f"\n\n# Note: This is demonstration output. Install Nuclei for real scanning.\n"
        output += f"# Target: {target}\n"
        output += f"# Templates: {templates or 'default'}\n"
        
        return output
    
    def parse_json_output(self, json_output: str) -> List[Dict[str, Any]]:
        """Parse Nuclei JSON output."""
        results = []
        
        try:
            lines = json_output.strip().split('\n')
            for line in lines:
                line = line.strip()
                if line and line.startswith('{'):
                    try:
                        result = json.loads(line)
                        results.append(result)
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            logger.error(f"Error parsing Nuclei output: {e}")
        
        return results
    
    def generate_vulnerability_report(self, scan_results: str, target: str) -> Dict[str, Any]:
        """Generate vulnerability report from scan results."""
        parsed_results = self.parse_json_output(scan_results)
        
        # Categorize findings by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        vulnerabilities = []
        
        for result in parsed_results:
            severity = result.get("info", {}).get("severity", "info")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            vulnerabilities.append({
                "template_id": result.get("template-id", "unknown"),
                "name": result.get("info", {}).get("name", "Unknown"),
                "severity": severity,
                "description": result.get("info", {}).get("description", ""),
                "tags": result.get("info", {}).get("tags", []),
                "matched_at": result.get("matched-at", ""),
                "timestamp": result.get("timestamp", "")
            })
        
        return {
            "target": target,
            "scan_timestamp": "2024-01-01T00:00:00Z",
            "total_findings": len(vulnerabilities),
            "severity_breakdown": severity_counts,
            "vulnerabilities": vulnerabilities,
            "recommendations": self._generate_recommendations(vulnerabilities)
        }
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        # Check for specific vulnerability patterns
        has_info_disclosure = any("disclosure" in vuln.get("name", "").lower() for vuln in vulnerabilities)
        has_config_exposure = any("config" in vuln.get("tags", []) for vuln in vulnerabilities)
        has_apache = any("apache" in vuln.get("tags", []) for vuln in vulnerabilities)
        
        if has_info_disclosure:
            recommendations.append("Review and restrict access to sensitive information endpoints")
        
        if has_config_exposure:
            recommendations.append("Secure configuration files and disable debug modes in production")
        
        if has_apache:
            recommendations.append("Update Apache server to the latest version and review security configuration")
        
        # General recommendations
        recommendations.extend([
            "Implement proper access controls and authentication mechanisms",
            "Regular security scanning and vulnerability assessments",
            "Keep all software components updated with latest security patches",
            "Implement Web Application Firewall (WAF) for additional protection"
        ])
        
        return recommendations
    
    def list_template_categories(self) -> List[str]:
        """List available Nuclei template categories."""
        return [
            "cves/",
            "vulnerabilities/",
            "technologies/",
            "exposures/",
            "misconfiguration/",
            "takeovers/",
            "file/",
            "network/",
            "dns/",
            "fuzzing/"
        ]
    
    def get_templates_by_severity(self, severity: str) -> List[str]:
        """Get templates filtered by severity level."""
        severity_templates = {
            "critical": ["cves/", "vulnerabilities/"],
            "high": ["vulnerabilities/", "exposures/"],
            "medium": ["misconfiguration/", "exposures/"],
            "low": ["technologies/", "file/"],
            "info": ["technologies/", "dns/"]
        }
        
        return severity_templates.get(severity.lower(), [])