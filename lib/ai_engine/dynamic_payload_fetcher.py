#!/usr/bin/env python3

"""
Dynamic Payload Fetcher - Pulls latest vulnerability data from online sources
Fetches real-time exploits, payloads, and CVE data from multiple platforms
"""

import requests
import json
import re
import base64
import time
from urllib.parse import urljoin, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
import logging

class DynamicPayloadFetcher:
    """
    Fetches the latest vulnerability data, exploits, and payloads from online sources
    """
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.timeout = 30
        self.max_workers = 10
        
        # Online sources for vulnerability data
        self.sources = {
            'exploit_db': {
                'base_url': 'https://www.exploit-db.com',
                'search_url': 'https://www.exploit-db.com/search',
                'api_url': 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv'
            },
            'github_repos': [
                'https://api.github.com/repos/danielmiessler/SecLists/contents',
                'https://api.github.com/repos/swisskyrepo/PayloadsAllTheThings/contents',
                'https://api.github.com/repos/payloadbox/sql-injection-payload-list/contents',
                'https://api.github.com/repos/payloadbox/xss-payload-list/contents',
                'https://api.github.com/repos/payloadbox/command-injection-payload-list/contents',
                'https://api.github.com/repos/payloadbox/directory-payload-list/contents',
                'https://api.github.com/repos/1N3/IntruderPayloads/contents',
                'https://api.github.com/repos/fuzzdb-project/fuzzdb/contents',
                'https://api.github.com/repos/Bo0oM/fuzz.txt/contents',
                'https://api.github.com/repos/tennc/webshell/contents',
                'https://api.github.com/repos/xl7dev/WebShell/contents',
                'https://api.github.com/repos/JohnTroony/php-webshells/contents',
                'https://api.github.com/repos/WhiteWinterWolf/wwwolf-php-webshell/contents',
                'https://api.github.com/repos/epinna/weevely3/contents',
                'https://api.github.com/repos/wireghoul/graudit/contents',
                'https://api.github.com/repos/GainSec/PayloadBox/contents'
            ],
            'nuclei_templates': [
                'https://api.github.com/repos/projectdiscovery/nuclei-templates/contents',
                'https://api.github.com/repos/geeknik/the-nuclei-templates/contents',
                'https://api.github.com/repos/harsh-bothra/learn365/contents',
                'https://api.github.com/repos/pikpikcu/nuclei-templates/contents',
                'https://api.github.com/repos/optiv/CVE-2021-44228-Scanner/contents',
                'https://api.github.com/repos/projectdiscovery/fuzzing-templates/contents'
            ],
            'cve_sources': [
                'https://cve.mitre.org/data/downloads/allitems.xml',
                'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz',
                'https://api.github.com/repos/CVEProject/cvelist/contents/cves',
                'https://raw.githubusercontent.com/trickest/cve/main/cves.json'
            ],
            'payload_databases': [
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/quick-SQLi.txt',
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt',
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/command-injection-commix.txt',
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt',
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt',
                'https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/MySQL%20Injection.md',
                'https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/README.md',
                'https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/README.md',
                'https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/README.md',
                'https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/exploit/Mysql/mysql.txt',
                'https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt',
                'https://raw.githubusercontent.com/payloadbox/command-injection-payload-list/master/Intruder/command-injection-payload-list.txt',
                'https://raw.githubusercontent.com/1N3/IntruderPayloads/master/FuzzLists/SQLi.txt',
                'https://raw.githubusercontent.com/1N3/IntruderPayloads/master/FuzzLists/XSS.txt',
                'https://raw.githubusercontent.com/1N3/IntruderPayloads/master/FuzzLists/LFI.txt',
                'https://raw.githubusercontent.com/1N3/IntruderPayloads/master/FuzzLists/RFI.txt'
            ]
        }
        
        self.fetched_data = {
            'sql_injection': set(),
            'xss': set(),
            'lfi_rfi': set(),
            'command_injection': set(),
            'nuclei_templates': [],
            'cve_data': [],
            'exploits': [],
            'webshells': [],
            'bypass_techniques': set(),
            'waf_bypasses': set()
        }
    
    def fetch_all_payloads(self):
        """Fetch payloads from all sources concurrently"""
        print("[*] Starting dynamic payload fetching from online sources...")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            # Fetch from payload databases
            for url in self.sources['payload_databases']:
                futures.append(executor.submit(self._fetch_payload_list, url))
            
            # Fetch GitHub repositories
            for repo_url in self.sources['github_repos']:
                futures.append(executor.submit(self._fetch_github_repo, repo_url))
            
            # Fetch Nuclei templates
            for template_url in self.sources['nuclei_templates']:
                futures.append(executor.submit(self._fetch_nuclei_templates, template_url))
            
            # Fetch CVE data
            for cve_url in self.sources['cve_sources']:
                futures.append(executor.submit(self._fetch_cve_data, cve_url))
            
            # Fetch Exploit-DB data
            futures.append(executor.submit(self._fetch_exploit_db))
            
            # Process completed futures
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=self.timeout)
                    if result:
                        print(f"[+] Successfully fetched data: {result.get('source', 'Unknown')}")
                except Exception as e:
                    print(f"[-] Error fetching data: {e}")
        
        print(f"[+] Fetching complete! Collected:")
        print(f"    - SQL Injection payloads: {len(self.fetched_data['sql_injection'])}")
        print(f"    - XSS payloads: {len(self.fetched_data['xss'])}")
        print(f"    - LFI/RFI payloads: {len(self.fetched_data['lfi_rfi'])}")
        print(f"    - Command Injection payloads: {len(self.fetched_data['command_injection'])}")
        print(f"    - Nuclei templates: {len(self.fetched_data['nuclei_templates'])}")
        print(f"    - CVE entries: {len(self.fetched_data['cve_data'])}")
        print(f"    - Exploits: {len(self.fetched_data['exploits'])}")
        print(f"    - Webshells: {len(self.fetched_data['webshells'])}")
        
        return self.fetched_data
    
    def _fetch_payload_list(self, url: str) -> Dict[str, Any]:
        """Fetch payloads from a direct URL"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                content = response.text
                payloads = [line.strip() for line in content.split('\n') if line.strip()]
                
                # Categorize payloads based on URL or content
                if any(keyword in url.lower() for keyword in ['sqli', 'sql']):
                    self.fetched_data['sql_injection'].update(payloads)
                elif 'xss' in url.lower():
                    self.fetched_data['xss'].update(payloads)
                elif any(keyword in url.lower() for keyword in ['lfi', 'rfi', 'file']):
                    self.fetched_data['lfi_rfi'].update(payloads)
                elif 'command' in url.lower():
                    self.fetched_data['command_injection'].update(payloads)
                else:
                    # Auto-detect payload type
                    self._categorize_payloads(payloads)
                
                return {'source': url, 'count': len(payloads)}
        except Exception as e:
            print(f"[-] Error fetching {url}: {e}")
        return None
    
    def _fetch_github_repo(self, repo_url: str) -> Dict[str, Any]:
        """Fetch files from GitHub repository"""
        try:
            response = self.session.get(repo_url, timeout=self.timeout)
            if response.status_code == 200:
                files = response.json()
                payload_count = 0
                
                for file_info in files:
                    if file_info['type'] == 'file' and any(ext in file_info['name'].lower() 
                                                         for ext in ['.txt', '.md', '.json', '.yaml', '.yml']):
                        file_content = self._fetch_github_file_content(file_info['download_url'])
                        if file_content:
                            payloads = self._extract_payloads_from_content(file_content, file_info['name'])
                            payload_count += len(payloads)
                
                return {'source': repo_url, 'count': payload_count}
        except Exception as e:
            print(f"[-] Error fetching GitHub repo {repo_url}: {e}")
        return None
    
    def _fetch_github_file_content(self, download_url: str) -> Optional[str]:
        """Fetch content of a GitHub file"""
        try:
            response = self.session.get(download_url, timeout=self.timeout)
            if response.status_code == 200:
                return response.text
        except Exception as e:
            print(f"[-] Error fetching file content: {e}")
        return None
    
    def _fetch_nuclei_templates(self, template_url: str) -> Dict[str, Any]:
        """Fetch Nuclei templates from GitHub"""
        try:
            response = self.session.get(template_url, timeout=self.timeout)
            if response.status_code == 200:
                files = response.json()
                template_count = 0
                
                for file_info in files:
                    if (file_info['type'] == 'file' and 
                        file_info['name'].endswith('.yaml') or file_info['name'].endswith('.yml')):
                        template_content = self._fetch_github_file_content(file_info['download_url'])
                        if template_content:
                            template_data = self._parse_nuclei_template(template_content, file_info['name'])
                            if template_data:
                                self.fetched_data['nuclei_templates'].append(template_data)
                                template_count += 1
                
                return {'source': template_url, 'count': template_count}
        except Exception as e:
            print(f"[-] Error fetching Nuclei templates: {e}")
        return None
    
    def _fetch_cve_data(self, cve_url: str) -> Dict[str, Any]:
        """Fetch CVE data from various sources"""
        try:
            if 'mitre.org' in cve_url:
                # Handle MITRE CVE XML
                response = self.session.get(cve_url, timeout=self.timeout * 2)
                if response.status_code == 200:
                    cve_count = self._parse_mitre_cve_xml(response.text)
                    return {'source': cve_url, 'count': cve_count}
            
            elif 'nvd.nist.gov' in cve_url:
                # Handle NVD JSON feed (compressed)
                import gzip
                response = self.session.get(cve_url, timeout=self.timeout * 2)
                if response.status_code == 200:
                    decompressed = gzip.decompress(response.content)
                    cve_data = json.loads(decompressed.decode('utf-8'))
                    cve_count = len(cve_data.get('CVE_Items', []))
                    self._process_nvd_cve_data(cve_data)
                    return {'source': cve_url, 'count': cve_count}
            
            elif 'github.com' in cve_url and 'cvelist' in cve_url:
                # Handle GitHub CVE list
                response = self.session.get(cve_url, timeout=self.timeout)
                if response.status_code == 200:
                    cve_dirs = response.json()
                    cve_count = len(cve_dirs)
                    return {'source': cve_url, 'count': cve_count}
            
            elif 'trickest' in cve_url:
                # Handle Trickest CVE JSON
                response = self.session.get(cve_url, timeout=self.timeout)
                if response.status_code == 200:
                    cve_data = response.json()
                    cve_count = len(cve_data)
                    self.fetched_data['cve_data'].extend(cve_data)
                    return {'source': cve_url, 'count': cve_count}
            
        except Exception as e:
            print(f"[-] Error fetching CVE data from {cve_url}: {e}")
        return None
    
    def _fetch_exploit_db(self) -> Dict[str, Any]:
        """Fetch exploits from Exploit Database"""
        try:
            # Fetch the CSV file with exploit information
            response = self.session.get(self.sources['exploit_db']['api_url'], timeout=self.timeout)
            if response.status_code == 200:
                lines = response.text.split('\n')
                exploit_count = 0
                
                for line in lines[1:]:  # Skip header
                    if line.strip():
                        parts = line.split(',')
                        if len(parts) >= 3:
                            exploit_data = {
                                'id': parts[0],
                                'file': parts[1],
                                'description': parts[2] if len(parts) > 2 else '',
                                'date': parts[3] if len(parts) > 3 else '',
                                'author': parts[4] if len(parts) > 4 else '',
                                'type': parts[5] if len(parts) > 5 else '',
                                'platform': parts[6] if len(parts) > 6 else ''
                            }
                            self.fetched_data['exploits'].append(exploit_data)
                            exploit_count += 1
                
                return {'source': 'Exploit-DB', 'count': exploit_count}
        except Exception as e:
            print(f"[-] Error fetching Exploit-DB: {e}")
        return None
    
    def _extract_payloads_from_content(self, content: str, filename: str) -> List[str]:
        """Extract payloads from file content based on filename and content analysis"""
        payloads = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            # Detect payload type and add to appropriate category
            if any(keyword in filename.lower() for keyword in ['sql', 'sqli']):
                if any(sql_keyword in line.lower() for sql_keyword in ['select', 'union', 'order by', 'group by', 'having', 'where', 'insert', 'update', 'delete', 'drop', 'create', 'alter']):
                    self.fetched_data['sql_injection'].add(line)
                    payloads.append(line)
            
            elif 'xss' in filename.lower():
                if any(xss_keyword in line.lower() for xss_keyword in ['<script', 'alert(', 'confirm(', 'prompt(', 'javascript:', 'onerror', 'onload', 'onclick']):
                    self.fetched_data['xss'].add(line)
                    payloads.append(line)
            
            elif any(keyword in filename.lower() for keyword in ['lfi', 'rfi', 'file', 'inclusion']):
                if any(lfi_keyword in line for lfi_keyword in ['../', '..\\', '/etc/', 'C:\\', 'php://', 'data://', 'file://']):
                    self.fetched_data['lfi_rfi'].add(line)
                    payloads.append(line)
            
            elif any(keyword in filename.lower() for keyword in ['command', 'cmd', 'injection']):
                if any(cmd_keyword in line for cmd_keyword in ['|', '&', ';', '`', '$(']):
                    self.fetched_data['command_injection'].add(line)
                    payloads.append(line)
            
            elif any(keyword in filename.lower() for keyword in ['shell', 'webshell', 'backdoor']):
                self.fetched_data['webshells'].append({
                    'filename': filename,
                    'content': line if len(line) < 1000 else line[:1000] + '...'
                })
                payloads.append(line)
        
        return payloads
    
    def _categorize_payloads(self, payloads: List[str]):
        """Auto-categorize payloads based on content analysis"""
        for payload in payloads:
            payload_lower = payload.lower()
            
            # SQL Injection detection
            if any(keyword in payload_lower for keyword in [
                'select', 'union', 'order by', 'group by', 'having', 'where',
                'insert', 'update', 'delete', 'drop', 'create', 'alter',
                'information_schema', 'mysql', 'mssql', 'oracle', 'postgresql',
                'waitfor', 'sleep(', 'benchmark(', 'pg_sleep', 'dbms_pipe'
            ]):
                self.fetched_data['sql_injection'].add(payload)
            
            # XSS detection
            elif any(keyword in payload_lower for keyword in [
                '<script', 'alert(', 'confirm(', 'prompt(', 'javascript:',
                'onerror', 'onload', 'onclick', 'onmouseover', 'onfocus',
                'document.', 'window.', 'eval(', 'settimeout', 'setinterval'
            ]):
                self.fetched_data['xss'].add(payload)
            
            # LFI/RFI detection
            elif any(keyword in payload for keyword in [
                '../', '..\\', '/etc/', 'C:\\', 'php://', 'data://', 'file://',
                'expect://', 'zip://', 'compress.', '/proc/', '/var/log/'
            ]):
                self.fetched_data['lfi_rfi'].add(payload)
            
            # Command Injection detection
            elif any(keyword in payload for keyword in [
                '|', '&', ';', '`', '$(', 'whoami', 'id;', 'uname',
                'cat /etc/', 'type C:\\', 'net user', 'ps aux', 'netstat'
            ]):
                self.fetched_data['command_injection'].add(payload)
            
            # WAF Bypass techniques
            elif any(keyword in payload_lower for keyword in [
                'bypass', 'waf', 'filter', 'encode', 'obfuscate',
                '%2e%2e', '%252e', 'unicode', 'utf-8', 'double'
            ]):
                self.fetched_data['waf_bypasses'].add(payload)
    
    def _parse_nuclei_template(self, content: str, filename: str) -> Optional[Dict[str, Any]]:
        """Parse Nuclei template YAML content"""
        try:
            import yaml
            template_data = yaml.safe_load(content)
            
            if isinstance(template_data, dict):
                return {
                    'filename': filename,
                    'id': template_data.get('id', ''),
                    'name': template_data.get('info', {}).get('name', ''),
                    'author': template_data.get('info', {}).get('author', ''),
                    'severity': template_data.get('info', {}).get('severity', ''),
                    'description': template_data.get('info', {}).get('description', ''),
                    'tags': template_data.get('info', {}).get('tags', []),
                    'requests': template_data.get('requests', []),
                    'http': template_data.get('http', []),
                    'network': template_data.get('network', []),
                    'dns': template_data.get('dns', [])
                }
        except Exception as e:
            print(f"[-] Error parsing Nuclei template {filename}: {e}")
        return None
    
    def _parse_mitre_cve_xml(self, xml_content: str) -> int:
        """Parse MITRE CVE XML data"""
        try:
            root = ET.fromstring(xml_content)
            cve_count = 0
            
            for item in root.findall('.//{http://cve.mitre.org/cveformat_20/}item'):
                cve_data = {
                    'id': item.get('name', ''),
                    'description': '',
                    'references': [],
                    'phase': item.get('phase', ''),
                    'votes': item.get('votes', '')
                }
                
                # Extract description
                desc_elem = item.find('.//{http://cve.mitre.org/cveformat_20/}desc')
                if desc_elem is not None:
                    cve_data['description'] = desc_elem.text or ''
                
                # Extract references
                for ref in item.findall('.//{http://cve.mitre.org/cveformat_20/}ref'):
                    ref_url = ref.get('url', '')
                    if ref_url:
                        cve_data['references'].append(ref_url)
                
                self.fetched_data['cve_data'].append(cve_data)
                cve_count += 1
            
            return cve_count
        except Exception as e:
            print(f"[-] Error parsing MITRE CVE XML: {e}")
        return 0
    
    def _process_nvd_cve_data(self, cve_data: Dict[str, Any]):
        """Process NVD CVE JSON data"""
        try:
            for cve_item in cve_data.get('CVE_Items', []):
                cve = cve_item.get('cve', {})
                impact = cve_item.get('impact', {})
                
                cve_entry = {
                    'id': cve.get('CVE_data_meta', {}).get('ID', ''),
                    'description': '',
                    'cvss_score': 0.0,
                    'severity': '',
                    'published_date': cve_item.get('publishedDate', ''),
                    'modified_date': cve_item.get('lastModifiedDate', ''),
                    'references': []
                }
                
                # Extract description
                descriptions = cve.get('description', {}).get('description_data', [])
                if descriptions:
                    cve_entry['description'] = descriptions[0].get('value', '')
                
                # Extract CVSS score
                cvss_v3 = impact.get('baseMetricV3', {}).get('cvssV3', {})
                if cvss_v3:
                    cve_entry['cvss_score'] = cvss_v3.get('baseScore', 0.0)
                    cve_entry['severity'] = cvss_v3.get('baseSeverity', '')
                
                # Extract references
                references = cve.get('references', {}).get('reference_data', [])
                for ref in references:
                    cve_entry['references'].append(ref.get('url', ''))
                
                self.fetched_data['cve_data'].append(cve_entry)
        
        except Exception as e:
            print(f"[-] Error processing NVD CVE data: {e}")
    
    def get_latest_payloads_by_type(self, payload_type: str) -> List[str]:
        """Get the latest payloads for a specific type"""
        return list(self.fetched_data.get(payload_type, set()))
    
    def get_nuclei_templates_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """Get Nuclei templates filtered by severity"""
        return [t for t in self.fetched_data['nuclei_templates'] 
                if t.get('severity', '').lower() == severity.lower()]
    
    def get_cve_by_score(self, min_score: float) -> List[Dict[str, Any]]:
        """Get CVEs with CVSS score above threshold"""
        return [cve for cve in self.fetched_data['cve_data'] 
                if cve.get('cvss_score', 0.0) >= min_score]
    
    def search_exploits(self, keyword: str) -> List[Dict[str, Any]]:
        """Search for exploits containing keyword"""
        keyword_lower = keyword.lower()
        return [exp for exp in self.fetched_data['exploits'] 
                if keyword_lower in exp.get('description', '').lower() or 
                   keyword_lower in exp.get('type', '').lower()]
    
    def export_to_files(self, output_dir: str = './fetched_payloads'):
        """Export fetched data to files"""
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        # Export payload lists
        for payload_type, payloads in self.fetched_data.items():
            if isinstance(payloads, set) and payloads:
                filename = os.path.join(output_dir, f"{payload_type}_payloads.txt")
                with open(filename, 'w', encoding='utf-8') as f:
                    for payload in sorted(payloads):
                        f.write(f"{payload}\n")
                print(f"[+] Exported {len(payloads)} {payload_type} payloads to {filename}")
        
        # Export structured data as JSON
        structured_data = {
            'nuclei_templates': self.fetched_data['nuclei_templates'],
            'cve_data': self.fetched_data['cve_data'],
            'exploits': self.fetched_data['exploits'],
            'webshells': self.fetched_data['webshells']
        }
        
        json_filename = os.path.join(output_dir, "structured_data.json")
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(structured_data, f, indent=2, ensure_ascii=False)
        print(f"[+] Exported structured data to {json_filename}")


if __name__ == "__main__":
    fetcher = DynamicPayloadFetcher()
    fetcher.fetch_all_payloads()
    fetcher.export_to_files()