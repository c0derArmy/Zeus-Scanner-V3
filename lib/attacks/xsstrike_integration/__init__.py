"""
XSStrike Integration for Zeus-Scanner
Fetches XSS vulnerabilities and associated CVEs using XSStrike tool
"""

import subprocess
import json
import os
import tempfile
import re
from typing import Dict, List, Optional, Tuple

from lib.core.settings import logger, set_color


class XSStrikeIntegration:
    def __init__(self, target_url: str, proxy: Optional[str] = None, 
                 timeout: int = 300, verbose: bool = False):
        self.target_url = target_url
        self.proxy = proxy
        self.timeout = timeout
        self.verbose = verbose
        self.xsstrike_path = self._find_xsstrike()
        
    def _find_xsstrike(self) -> Optional[str]:
        paths = [
            "/usr/bin/xsstrike",
            os.path.expanduser("~/XSStrike"),
            "/usr/local/bin/XSStrike",
            "/opt/XSStrike",
            os.path.join(os.getcwd(), "XSStrike"),
        ]
        for path in paths:
            if os.path.exists(path):
                return path
        
        result = subprocess.run(
            ["which", "xsstrike.py"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return os.path.dirname(result.stdout.strip())
        return None
    
    def is_installed(self) -> bool:
        return self.xsstrike_path is not None
    
    def scan(self, mode: str = "crawl") -> Dict:
        if not self.is_installed():
            return {
                'success': False,
                'error': 'XSStrike not found. Install: git clone https://github.com/s0md3v/XSStrike.git',
                'vulnerabilities': [],
                'cves': []
            }
        
        logger.info(set_color(f"Running XSStrike scan on: {self.target_url}", level=25))
        
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            output_file = f.name
        
        try:
            cmd = [
                "python3", 
                os.path.join(self.xsstrike_path, "xsstrike.py"),
                "-u", self.target_url,
                "--json"
            ]
            
            if mode == "aggressive":
                cmd.append("--aggressive")
            elif mode == "fuzz":
                cmd.append("--fuzzer")
            
            if self.proxy:
                cmd.extend(["--proxy", self.proxy])
            
            if self.verbose:
                cmd.append("-v")
            
            cmd.extend(["--timeout", str(self.timeout)])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            vulnerabilities = self._parse_output(result.stdout, result.stderr)
            
            cve_info = self._extract_cve_from_findings(vulnerabilities)
            
            return {
                'success': True,
                'url': self.target_url,
                'vulnerabilities': vulnerabilities,
                'cves': cve_info,
                'raw_output': result.stdout,
                'error_output': result.stderr
            }
            
        except subprocess.TimeoutExpired:
            logger.warning(set_color("XSStrike scan timed out", level=30))
            return {
                'success': False,
                'error': 'Scan timed out',
                'vulnerabilities': [],
                'cves': []
            }
        except Exception as e:
            logger.error(set_color(f"XSStrike error: {str(e)}", level=40))
            return {
                'success': False,
                'error': str(e),
                'vulnerabilities': [],
                'cves': []
            }
        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def _parse_output(self, stdout: str, stderr: str) -> List[Dict]:
        vulnerabilities = []
        
        lines = stdout.split('\n')
        for line in lines:
            if 'XSS' in line.upper() or 'vulnerable' in line.lower():
                vuln = self._extract_vulnerability(line)
                if vuln:
                    vulnerabilities.append(vuln)
        
        if not vulnerabilities and stderr:
            for line in stderr.split('\n'):
                if 'XSS' in line.upper() or 'vulnerable' in line.lower():
                    vuln = self._extract_vulnerability(line)
                    if vuln:
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _extract_vulnerability(self, line: str) -> Optional[Dict]:
        patterns = [
            r'(?P<param>\w+).*?(?P<payload><[^>]+>.*?)[\s|$]',
            r'Parameter.*?:\s*(?P<param>\w+)',
            r'Payload.*?:\s*(?P<payload><[^>]+>)',
            r'(?P<param>[\w_]+).*?=\s*(?P<payload><[^>]+>)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line, re.I)
            if match:
                return {
                    'param': match.group('param') if 'param' in match.groupdict() else 'unknown',
                    'payload': match.group('payload') if 'payload' in match.groupdict() else line.strip(),
                    'type': 'XSS',
                    'source': 'XSStrike'
                }
        
        return None
    
    def _extract_cve_from_findings(self, vulnerabilities: List[Dict]) -> List[Dict]:
        cve_list = []
        
        for vuln in vulnerabilities:
            payload = vuln.get('payload', '')
            
            cve_patterns = [
                r'CVE-\d{4}-\d{4,}',
                r'CVE\d{4}\d{4,}',
            ]
            
            for pattern in cve_patterns:
                matches = re.findall(pattern, payload, re.I)
                for match in matches:
                    cve_id = match.upper()
                    if not cve_id.startswith('CVE-'):
                        cve_id = f"CVE-{cve_id}"
                    cve_list.append({
                        'cve_id': cve_id,
                        'related_to': 'XSS',
                        'payload': payload
                    })
        
        return cve_list
    
    def crawl_and_scan(self, depth: int = 2) -> Dict:
        if not self.is_installed():
            return {
                'success': False,
                'error': 'XSStrike not found',
                'vulnerabilities': [],
                'cves': []
            }
        
        logger.info(set_color(f"Crawling and scanning: {self.target_url}", level=25))
        
        try:
            cmd = [
                "python3",
                os.path.join(self.xsstrike_path, "xsstrike.py"),
                "-u", self.target_url,
                "--crawl",
                "--depth", str(depth)
            ]
            
            if self.proxy:
                cmd.extend(["--proxy", self.proxy])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout * 2
            )
            
            vulnerabilities = self._parse_output(result.stdout, result.stderr)
            cve_info = self._extract_cve_from_findings(vulnerabilities)
            
            return {
                'success': True,
                'url': self.target_url,
                'vulnerabilities': vulnerabilities,
                'cves': cve_info,
                'raw_output': result.stdout
            }
            
        except Exception as e:
            logger.error(set_color(f"Crawl scan error: {str(e)}", level=40))
            return {
                'success': False,
                'error': str(e),
                'vulnerabilities': [],
                'cves': []
            }


def run_xsstrike_scan(url: str, **kwargs) -> Dict:
    verbose = kwargs.get("verbose", False)
    proxy = kwargs.get("proxy", None)
    mode = kwargs.get("mode", "crawl")
    
    if verbose:
        logger.info(set_color(f"Starting XSStrike scan on: {url}", level=25))
    
    scanner = XSStrikeIntegration(
        target_url=url,
        proxy=proxy,
        verbose=verbose
    )
    
    if not scanner.is_installed():
        logger.error(set_color(
            "XSStrike not installed. Install with: git clone https://github.com/s0md3v/XSStrike.git",
            level=40
        ))
        return {
            'success': False,
            'error': 'XSStrike not installed'
        }
    
    if mode == "crawl":
        result = scanner.crawl_and_scan()
    else:
        result = scanner.scan(mode=mode)
    
    if result['success'] and result['vulnerabilities']:
        logger.warning(set_color(
            f"Found {len(result['vulnerabilities'])} XSS vulnerabilities",
            level=35
        ))
        
        if result['cves']:
            logger.warning(set_color(
                f"Found {len(result['cves'])} related CVEs",
                level=35
            ))
    else:
        logger.info(set_color(
            f"No XSS vulnerabilities detected on {url}",
            level=25
        ))
    
    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python xsstrike_integration.py <url>")
        sys.exit(1)
    result = run_xsstrike_scan(sys.argv[1], verbose=True)
    print(json.dumps(result, indent=2))
