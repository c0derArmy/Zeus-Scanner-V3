#!/usr/bin/env python3
"""
Wapiti Integration for Zeus-Scanner
Integrates Wapiti web application vulnerability scanner
"""

import subprocess
import json
from typing import Dict, List, Optional


class WapitiIntegration:
    """
    Integration with Wapiti - Web application vulnerability scanner
    https://github.com/wapiti-scanner/wapiti
    """
    
    def __init__(self, wapiti_path: str = "wapiti"):
        """
        Initialize Wapiti integration
        
        Args:
            wapiti_path: Path to wapiti binary (default: assumes in PATH)
        """
        self.wapiti_path = wapiti_path
        
    def check_installation(self) -> bool:
        """Check if Wapiti is installed"""
        try:
            result = subprocess.run(
                [self.wapiti_path, "--version"],
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
        modules: Optional[List[str]] = None,
        scope: str = "page",
        level: int = 1,
        format: str = "json",
        output_file: Optional[str] = None
    ) -> Dict:
        """
        Scan target with Wapiti
        
        Args:
            target: Target URL
            modules: List of modules to use (xss, sqli, exec, file, etc.)
            scope: Scan scope (page, folder, domain, url, punk)
            level: Attack level (1 or 2)
            format: Output format (json, html, txt, xml)
            output_file: Output file path
            
        Returns:
            Dictionary containing scan results
        """
        print(f"[*] Starting Wapiti scan on {target}")
        
        try:
            # Build command
            cmd = [
                self.wapiti_path,
                "-u", target,
                "--scope", scope,
                "--level", str(level),
                "-f", format
            ]
            
            if modules:
                cmd.extend(["-m", ",".join(modules)])
            
            if output_file:
                cmd.extend(["-o", output_file])
            
            # Run scan
            print(f"[*] Running: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minutes timeout
            )
            
            if result.returncode == 0:
                print(f"[+] Wapiti scan completed successfully")
                vulnerabilities = []
                
                # Parse JSON output if available
                if output_file and format == "json":
                    vulnerabilities = self._parse_json_results(output_file)
                
                return {
                    "success": True,
                    "vulnerabilities": vulnerabilities,
                    "output_file": output_file
                }
            else:
                print(f"[-] Wapiti scan failed")
                return {
                    "success": False,
                    "error": result.stderr
                }
            
        except subprocess.TimeoutExpired:
            print("[-] Wapiti scan timed out")
            return {"success": False, "error": "Scan timeout"}
        except Exception as e:
            print(f"[-] Wapiti scan failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _parse_json_results(self, json_file: str) -> List[Dict]:
        """Parse Wapiti JSON results"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
                vulnerabilities = []
                
                for vuln_type, vulns in data.get("vulnerabilities", {}).items():
                    for vuln in vulns:
                        vulnerabilities.append({
                            "type": vuln_type,
                            "url": vuln.get("url", ""),
                            "method": vuln.get("method", ""),
                            "parameter": vuln.get("parameter", ""),
                            "info": vuln.get("info", ""),
                            "level": vuln.get("level", "")
                        })
                
                return vulnerabilities
        except Exception as e:
            print(f"[-] Failed to parse JSON results: {e}")
            return []
    
    def quick_scan(self, target: str) -> Dict:
        """Quick XSS and SQLi scan"""
        return self.scan_target(target, modules=["xss", "sqli"], level=1)
    
    def comprehensive_scan(self, target: str, output_file: str) -> Dict:
        """Comprehensive scan with all modules"""
        return self.scan_target(
            target,
            level=2,
            scope="domain",
            output_file=output_file
        )


# Convenience function
def scan_with_wapiti(target: str, **kwargs) -> Dict:
    """Quick function to scan with Wapiti"""
    wapiti = WapitiIntegration()
    if not wapiti.check_installation():
        return {"success": False, "error": "Wapiti not installed"}
    return wapiti.scan_target(target, **kwargs)
