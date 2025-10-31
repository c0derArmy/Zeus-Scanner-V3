#!/usr/bin/env python3
"""
Nuclei Integration for Zeus-Scanner
Integrates ProjectDiscovery's Nuclei vulnerability scanner
"""

import os
import json
import subprocess
import tempfile
from typing import Dict, List, Optional


class NucleiIntegration:
    """
    Integration with Nuclei - Fast and customizable vulnerability scanner
    https://github.com/projectdiscovery/nuclei
    """
    
    def __init__(self, nuclei_path: str = "nuclei", templates_dir: Optional[str] = None):
        """
        Initialize Nuclei integration
        
        Args:
            nuclei_path: Path to nuclei binary (default: assumes in PATH)
            templates_dir: Custom templates directory
        """
        self.nuclei_path = nuclei_path
        self.templates_dir = templates_dir or os.path.expanduser("~/nuclei-templates")
        self.results = []
        
    def check_installation(self) -> bool:
        """Check if Nuclei is installed"""
        try:
            result = subprocess.run(
                [self.nuclei_path, "-version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def update_templates(self) -> bool:
        """Update Nuclei templates"""
        try:
            print("[*] Updating Nuclei templates...")
            result = subprocess.run(
                [self.nuclei_path, "-update-templates"],
                capture_output=True,
                text=True,
                timeout=300
            )
            if result.returncode == 0:
                print("[+] Nuclei templates updated successfully")
                return True
            return False
        except Exception as e:
            print(f"[-] Failed to update templates: {e}")
            return False
    
    def scan_target(
        self,
        target: str,
        severity: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        templates: Optional[List[str]] = None,
        rate_limit: int = 150,
        concurrency: int = 25
    ) -> Dict:
        """
        Scan target with Nuclei
        
        Args:
            target: Target URL or domain
            severity: Filter by severity (critical, high, medium, low, info)
            tags: Filter by tags (e.g., xss, sqli, lfi)
            templates: Specific template paths
            rate_limit: Rate limit for requests per second
            concurrency: Number of concurrent templates
            
        Returns:
            Dictionary containing scan results
        """
        print(f"[*] Starting Nuclei scan on {target}")
        
        # Create temporary file for JSON output
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp:
            output_file = tmp.name
        
        try:
            # Build command
            cmd = [
                self.nuclei_path,
                "-u", target
            ]
            
            # Add severity filter
            if severity:
                for sev in severity:
                    cmd.extend(["-severity", sev])
            
            # Add tags filter
            if tags:
                cmd.extend(["-tags", ",".join(tags)])
            
            # Add specific templates
            if templates:
                for template in templates:
                    cmd.extend(["-t", template])
            
            # Run scan
            print(f"[*] Running: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            # Parse results
            results = self._parse_results(output_file)
            
            # Clean up
            os.unlink(output_file)
            
            print(f"[+] Nuclei scan completed. Found {len(results)} vulnerabilities")
            return {
                "success": True,
                "vulnerabilities": results,
                "total": len(results)
            }
            
        except subprocess.TimeoutExpired:
            print("[-] Nuclei scan timed out")
            return {"success": False, "error": "Scan timeout"}
        except Exception as e:
            print(f"[-] Nuclei scan failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _parse_results(self, output_file: str) -> List[Dict]:
        """Parse Nuclei JSON output"""
        results = []
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            vuln = json.loads(line)
                            results.append({
                                "template": vuln.get("template-id", "unknown"),
                                "name": vuln.get("info", {}).get("name", "Unknown"),
                                "severity": vuln.get("info", {}).get("severity", "info"),
                                "matched_at": vuln.get("matched-at", ""),
                                "description": vuln.get("info", {}).get("description", ""),
                                "tags": vuln.get("info", {}).get("tags", []),
                                "reference": vuln.get("info", {}).get("reference", []),
                                "type": vuln.get("type", ""),
                                "curl_command": vuln.get("curl-command", "")
                            })
                        except json.JSONDecodeError:
                            continue
        except FileNotFoundError:
            pass
        return results
    
    def scan_with_custom_templates(self, target: str, template_paths: List[str]) -> Dict:
        """Scan with custom Nuclei templates"""
        return self.scan_target(target, templates=template_paths)
    
    def quick_scan(self, target: str) -> Dict:
        """Quick scan with high/critical severity only"""
        return self.scan_target(target, severity=["high", "critical"])
    
    def comprehensive_scan(self, target: str) -> Dict:
        """Comprehensive scan with all templates"""
        return self.scan_target(target)


# Convenience functions
def scan_with_nuclei(target: str, **kwargs) -> Dict:
    """Quick function to scan with Nuclei"""
    nuclei = NucleiIntegration()
    if not nuclei.check_installation():
        return {"success": False, "error": "Nuclei not installed"}
    return nuclei.scan_target(target, **kwargs)
