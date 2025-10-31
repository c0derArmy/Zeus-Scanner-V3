#!/usr/bin/env python3
"""
Nikto Integration for Zeus-Scanner
Integrates Nikto web server scanner
"""

import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from urllib.parse import urlparse


class NiktoIntegration:
    """
    Integration with Nikto - Web server scanner
    https://github.com/sullo/nikto
    """
    
    def __init__(self, nikto_path: str = "nikto"):
        """
        Initialize Nikto integration
        
        Args:
            nikto_path: Path to nikto.pl script (default: assumes in PATH)
        """
        self.nikto_path = nikto_path
    
    def _extract_target_info(self, url: str) -> tuple:
        """
        Extract host, port, and SSL info from URL
        
        Args:
            url: Target URL
            
        Returns:
            Tuple of (host, port, use_ssl)
        """
        parsed = urlparse(url)
        
        # Determine if SSL should be used
        use_ssl = parsed.scheme == 'https'
        
        # Get host
        host = parsed.netloc or parsed.path
        
        # Extract port if specified, otherwise use defaults
        if ':' in host and not host.count(':') > 1:  # IPv4 with port
            host, port_str = host.rsplit(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                port = 443 if use_ssl else 80
        else:
            # Use default ports
            port = 443 if use_ssl else 80
        
        return host, port, use_ssl
        
    def check_installation(self) -> bool:
        """Check if Nikto is installed"""
        try:
            result = subprocess.run(
                [self.nikto_path, "-Version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def scan_target(
        self,
        target: str,
        port: int = None,
        ssl: bool = None,
        tuning: Optional[str] = None,
        output_file: Optional[str] = None,
        format: str = "xml"
    ) -> Dict:
        """
        Scan target with Nikto
        
        Args:
            target: Target URL or host
            port: Target port (optional - auto-detected from URL if not provided)
            ssl: Use SSL (optional - auto-detected from URL if not provided)
            tuning: Tuning options (e.g., '1' for interesting files, '2' for misconfig)
            output_file: Output file path (DEPRECATED - not used, outputs to console)
            format: Output format (DEPRECATED - not used)
            
        Returns:
            Dictionary containing scan results
        """
        # Auto-detect host, port, and SSL from URL if not explicitly provided
        if port is None or ssl is None:
            detected_host, detected_port, detected_ssl = self._extract_target_info(target)
            if port is None:
                port = detected_port
            if ssl is None:
                ssl = detected_ssl
            # Use the detected host as target
            target = detected_host
        
        print(f"[*] Starting Nikto scan on {target}:{port} (SSL: {ssl})")
        
        try:
            # Build command - removed output file options to prevent scan blocking
            cmd = [
                self.nikto_path,
                "-h", target,
                "-p", str(port)
            ]
            
            if ssl:
                cmd.append("-ssl")
            
            if tuning:
                cmd.extend(["-Tuning", tuning])
            
            # REMOVED: Output file options as they prevent proper scanning
            # Nikto will output directly to console which is captured by subprocess
            
            # Run scan
            print(f"[*] Running: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minutes timeout
            )
            
            # Parse findings from stdout
            findings = self._parse_console_output(result.stdout)
            
            print(f"[+] Nikto scan completed. Found {len(findings)} findings")
            
            return {
                "success": True,
                "findings": findings,
                "output": result.stdout,
                "stderr": result.stderr,
                "port": port,
                "ssl": ssl
            }
            
        except subprocess.TimeoutExpired:
            print("[-] Nikto scan timed out")
            return {"success": False, "error": "Scan timeout"}
        except Exception as e:
            print(f"[-] Nikto scan failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _parse_console_output(self, output: str) -> List[Dict]:
        """Parse Nikto console output for findings"""
        findings = []
        try:
            lines = output.split('\n')
            for line in lines:
                # Look for lines starting with + which indicate findings
                if line.strip().startswith('+') and ':' in line:
                    # Skip header lines
                    if any(x in line.lower() for x in ['target ip', 'target hostname', 'target port', 'start time']):
                        continue
                    
                    findings.append({
                        "finding": line.strip(),
                        "severity": "info"  # Nikto doesn't provide severity in console output
                    })
            
        except Exception as e:
            print(f"[-] Failed to parse console output: {e}")
        
        return findings
    
    def _parse_xml_results(self, xml_file: str) -> List[Dict]:
        """Parse Nikto XML results (DEPRECATED - keeping for compatibility)"""
        findings = []
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for item in root.findall(".//item"):
                findings.append({
                    "id": item.get("id", ""),
                    "osvdb": item.get("osvdbid", ""),
                    "method": item.get("method", ""),
                    "url": item.find("uri").text if item.find("uri") is not None else "",
                    "description": item.find("description").text if item.find("description") is not None else "",
                })
            
        except Exception as e:
            print(f"[-] Failed to parse XML results: {e}")
        
        return findings
    
    def quick_scan(self, target: str) -> Dict:
        """Quick scan with common checks"""
        return self.scan_target(target, tuning="1")
    
    def full_scan(self, target: str) -> Dict:
        """Full comprehensive scan"""
        return self.scan_target(target)


# Convenience function
def scan_with_nikto(target: str, **kwargs) -> Dict:
    """Quick function to scan with Nikto"""
    nikto = NiktoIntegration()
    if not nikto.check_installation():
        return {"success": False, "error": "Nikto not installed"}
    return nikto.scan_target(target, **kwargs)
