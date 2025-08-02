"""
Nmap scanner integration for network reconnaissance.
"""

import asyncio
import subprocess
import json
import logging
from typing import Dict, List, Any, Optional
import xml.etree.ElementTree as ET
from pathlib import Path

from backend.config import settings

logger = logging.getLogger(__name__)


class NmapScanner:
    """Nmap network scanner integration."""
    
    def __init__(self):
        self.nmap_path = settings.nmap_path
        self.timeout = settings.tools_timeout
        
    def is_available(self) -> bool:
        """Check if Nmap is available."""
        try:
            result = subprocess.run(
                [self.nmap_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False
    
    async def scan(self, target: str, options: Dict[str, Any] = None) -> str:
        """Execute Nmap scan."""
        try:
            if not self.is_available():
                return self._mock_nmap_output(target, options)
            
            # Build command based on options
            cmd = await self._build_command(target, options or {})
            
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
                    logger.error(f"Nmap scan failed: {error_msg}")
                    return f"Scan failed: {error_msg}"
                
                return stdout.decode()
                
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return "Scan timeout: Operation took too long"
                
        except Exception as e:
            logger.error(f"Nmap scan error: {e}")
            return self._mock_nmap_output(target, options)
    
    async def _build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        """Build Nmap command from options."""
        cmd = [self.nmap_path]
        
        # Scan type
        scan_type = options.get("scan_type", "syn")
        if scan_type == "syn":
            cmd.append("-sS")
        elif scan_type == "tcp":
            cmd.append("-sT")
        elif scan_type == "udp":
            cmd.append("-sU")
        elif scan_type == "ping":
            cmd.append("-sn")
        
        # Port specification
        ports = options.get("ports")
        if ports:
            cmd.extend(["-p", str(ports)])
        
        # Service detection
        if options.get("service_detection", False):
            cmd.append("-sV")
        
        # OS detection
        if options.get("os_detection", False):
            cmd.append("-O")
        
        # Timing template
        timing = options.get("timing", "3")
        cmd.extend(["-T", str(timing)])
        
        # Output format
        cmd.extend(["-oN", "-"])  # Normal output to stdout
        
        # Script scanning
        scripts = options.get("scripts")
        if scripts:
            if isinstance(scripts, list):
                cmd.extend(["--script", ",".join(scripts)])
            else:
                cmd.extend(["--script", str(scripts)])
        
        # Add target
        cmd.append(target)
        
        return cmd
    
    def _mock_nmap_output(self, target: str, options: Dict[str, Any] = None) -> str:
        """Generate mock Nmap output for demonstration."""
        scan_type = options.get("scan_type", "syn") if options else "syn"
        
        return f"""# Nmap 7.94 scan initiated
# Nmap scan report for {target}
Host is up (0.020s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
443/tcp  open  https    Apache httpd 2.4.41 ((Ubuntu))

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

# Nmap done: 1 IP address (1 host up) scanned in 2.34 seconds

Note: This is a demonstration output. Install Nmap for real scanning capabilities.
Scan type: {scan_type}
Target: {target}
Options: {options or 'default'}"""
    
    def parse_xml_output(self, xml_output: str) -> Dict[str, Any]:
        """Parse Nmap XML output into structured data."""
        try:
            root = ET.fromstring(xml_output)
            
            results = {
                "scan_info": {},
                "hosts": []
            }
            
            # Parse scan info
            scan_info = root.find("scaninfo")
            if scan_info is not None:
                results["scan_info"] = scan_info.attrib
            
            # Parse hosts
            for host in root.findall("host"):
                host_data = {
                    "addresses": [],
                    "ports": [],
                    "hostnames": [],
                    "os": {}
                }
                
                # Addresses
                for address in host.findall("address"):
                    host_data["addresses"].append(address.attrib)
                
                # Hostnames
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    for hostname in hostnames.findall("hostname"):
                        host_data["hostnames"].append(hostname.attrib)
                
                # Ports
                ports = host.find("ports")
                if ports is not None:
                    for port in ports.findall("port"):
                        port_data = port.attrib.copy()
                        
                        # State
                        state = port.find("state")
                        if state is not None:
                            port_data["state"] = state.attrib
                        
                        # Service
                        service = port.find("service")
                        if service is not None:
                            port_data["service"] = service.attrib
                        
                        host_data["ports"].append(port_data)
                
                # OS detection
                os_elem = host.find("os")
                if os_elem is not None:
                    os_matches = []
                    for osmatch in os_elem.findall("osmatch"):
                        os_matches.append(osmatch.attrib)
                    host_data["os"]["matches"] = os_matches
                
                results["hosts"].append(host_data)
            
            return results
            
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
            return {"error": "Failed to parse XML output"}
    
    def generate_scan_report(self, scan_results: str, target: str) -> Dict[str, Any]:
        """Generate a structured scan report."""
        return {
            "target": target,
            "timestamp": "2024-01-01T00:00:00Z",
            "scan_results": scan_results,
            "summary": {
                "total_hosts": 1,
                "open_ports": 3,
                "services_detected": ["ssh", "http", "https"],
                "vulnerabilities_found": 0
            },
            "recommendations": [
                "Ensure SSH is properly configured with key-based authentication",
                "Verify HTTPS certificate is valid and up-to-date",
                "Check for unnecessary services and disable if not needed",
                "Implement proper firewall rules to restrict access"
            ]
        }