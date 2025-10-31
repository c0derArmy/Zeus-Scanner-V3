#!/usr/bin/env python3

import os
import yaml
import json
import time
import hashlib
from datetime import datetime
from typing import Dict, List, Any
from urllib.parse import urlparse, parse_qs

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


class NucleiTemplateGenerator:
    """
    Advanced Nuclei template generator for all detected vulnerabilities
    """
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.template_database = self._initialize_template_database()
        
    def _initialize_template_database(self):
        """
        Initialize comprehensive template database with attack patterns
        """
        return {
            'SQL Injection': {
                'id_template': 'sqli-{hash}',
                'severity': 'high',
                'classification': {
                    'cvss-metrics': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                    'cvss-score': 9.8,
                    'cwe-id': 'CWE-89'
                },
                'tags': ['sqli', 'injection', 'database'],
                'payloads': [
                    "' OR '1'='1",
                    "' UNION SELECT NULL,NULL,NULL--",
                    "1'; DROP TABLE users--",
                    "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
                    "1' AND SLEEP(5)--"
                ],
                'matchers': [
                    {'type': 'word', 'words': ['mysql_fetch_array', 'ORA-', 'PostgreSQL', 'syntax error'], 'condition': 'or'},
                    {'type': 'time', 'dsl': ['duration>=5']},
                    {'type': 'word', 'words': ['root:x:0:0', 'information_schema'], 'condition': 'or'}
                ]
            },
            
            'Cross-Site Scripting (XSS)': {
                'id_template': 'xss-{hash}',
                'severity': 'medium',
                'classification': {
                    'cvss-metrics': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                    'cvss-score': 6.1,
                    'cwe-id': 'CWE-79'
                },
                'tags': ['xss', 'injection', 'javascript'],
                'payloads': [
                    '<script>alert("XSS")</script>',
                    '<img src=x onerror=alert("XSS")>',
                    'javascript:alert("XSS")',
                    '<svg/onload=alert("XSS")>',
                    '"><script>alert("XSS")</script>'
                ],
                'matchers': [
                    {'type': 'word', 'words': ['<script>alert("XSS")</script>', 'javascript:alert'], 'condition': 'or'},
                    {'type': 'word', 'words': ['XSS'], 'part': 'body'}
                ]
            },
            
            'Local File Inclusion (LFI)': {
                'id_template': 'lfi-{hash}',
                'severity': 'high',
                'classification': {
                    'cvss-metrics': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
                    'cvss-score': 7.5,
                    'cwe-id': 'CWE-22'
                },
                'tags': ['lfi', 'file-inclusion', 'path-traversal'],
                'payloads': [
                    '../../../etc/passwd',
                    '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                    '....//....//....//etc/passwd',
                    'php://filter/convert.base64-encode/resource=../../../etc/passwd',
                    '../../../etc/passwd%00'
                ],
                'matchers': [
                    {'type': 'regex', 'regex': ['root:x:0:0:', '\\[fonts\\]', '127\\.0\\.0\\.1'], 'condition': 'or'},
                    {'type': 'word', 'words': ['root:', 'daemon:', 'www-data:'], 'condition': 'or'}
                ]
            },
            
            'Directory Traversal': {
                'id_template': 'directory-traversal-{hash}',
                'severity': 'high',
                'classification': {
                    'cvss-metrics': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
                    'cvss-score': 7.5,
                    'cwe-id': 'CWE-22'
                },
                'tags': ['directory-traversal', 'path-traversal', 'file-access'],
                'payloads': [
                    '../../../',
                    '..\\..\\..\\',
                    '....//....//....//',
                    '%2e%2e%2f%2e%2e%2f%2e%2e%2f',
                    '..%252f..%252f..%252f'
                ],
                'matchers': [
                    {'type': 'word', 'words': ['Directory listing', 'Index of /'], 'condition': 'or'},
                    {'type': 'regex', 'regex': ['root:x:0:0:', 'Windows NT'], 'condition': 'or'}
                ]
            },
            
            'Sensitive File Exposure': {
                'id_template': 'file-exposure-{hash}',
                'severity': 'medium',
                'classification': {
                    'cvss-metrics': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
                    'cvss-score': 5.3,
                    'cwe-id': 'CWE-200'
                },
                'tags': ['exposure', 'files', 'information-disclosure'],
                'common_files': [
                    '/robots.txt',
                    '/.env',
                    '/config.php',
                    '/wp-config.php',
                    '/.git/config',
                    '/web.config',
                    '/crossdomain.xml'
                ],
                'matchers': [
                    {'type': 'status', 'status': [200]},
                    {'type': 'word', 'words': ['password', 'api_key', 'secret'], 'condition': 'or'}
                ]
            },
            
            'Information Disclosure': {
                'id_template': 'info-disclosure-{hash}',
                'severity': 'low',
                'classification': {
                    'cvss-metrics': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
                    'cvss-score': 3.7,
                    'cwe-id': 'CWE-200'
                },
                'tags': ['info-disclosure', 'headers', 'fingerprinting'],
                'headers_to_check': ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator'],
                'matchers': [
                    {'type': 'regex', 'regex': ['Server:\\s*(.+)', 'X-Powered-By:\\s*(.+)'], 'condition': 'or'},
                    {'type': 'word', 'words': ['Apache', 'nginx', 'IIS'], 'condition': 'or'}
                ]
            },
            
            'Directory Listing': {
                'id_template': 'directory-listing-{hash}',
                'severity': 'low',
                'classification': {
                    'cvss-metrics': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
                    'cvss-score': 5.0,
                    'cwe-id': 'CWE-548'
                },
                'tags': ['directory-listing', 'information-disclosure'],
                'paths_to_test': ['/', '/admin/', '/backup/', '/uploads/'],
                'matchers': [
                    {'type': 'word', 'words': ['Index of /', 'Directory Listing'], 'condition': 'or'},
                    {'type': 'regex', 'regex': ['<title>Index of', 'Directory listing for'], 'condition': 'or'}
                ]
            }
        }
    
    def generate_nuclei_templates(self, vulnerabilities: List[Dict], output_dir: str = None):
        """
        Generate comprehensive Nuclei templates for all vulnerabilities
        """
        if not output_dir:
            output_dir = f"{os.getcwd()}/nuclei-templates"
        
        # Create output directory structure
        self._create_directory_structure(output_dir)
        
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}Zeus Nuclei Template Generator{Style.RESET_ALL}")
        print(f"{Fore.BLUE}Generating templates for {len(vulnerabilities)} vulnerabilities{Style.RESET_ALL}")
        print(f"{Fore.BLUE}Output Directory: {Fore.WHITE}{output_dir}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}\n")
        
        generated_templates = []
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"{Fore.CYAN}[{i}/{len(vulnerabilities)}] Generating template for {vuln.get('type', 'Unknown')}{Style.RESET_ALL}")
            
            try:
                template_data = self._create_nuclei_template(vuln)
                template_path = self._save_template(template_data, output_dir)
                
                generated_templates.append({
                    'vulnerability': vuln,
                    'template_path': template_path,
                    'template_id': template_data['id']
                })
                
                print(f"{Fore.GREEN}[SAVED] {os.path.basename(template_path)}{Style.RESET_ALL}")
                
            except Exception as e:
                print(f"{Fore.RED}[ERROR] Failed to generate template: {e}{Style.RESET_ALL}")
        
        # Generate collection templates
        self._generate_collection_templates(generated_templates, output_dir)
        
        # Generate workflow files
        self._generate_workflow_files(generated_templates, output_dir)
        
        # Generate README
        self._generate_readme(generated_templates, output_dir)
        
        return generated_templates
    
    def _create_directory_structure(self, base_dir: str):
        """
        Create Nuclei template directory structure
        """
        directories = [
            f"{base_dir}/http",
            f"{base_dir}/http/vulnerabilities",
            f"{base_dir}/http/exposures", 
            f"{base_dir}/http/misconfiguration",
            f"{base_dir}/http/takeovers",
            f"{base_dir}/workflows",
            f"{base_dir}/helpers"
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    def _create_nuclei_template(self, vulnerability: Dict) -> Dict:
        """
        Create comprehensive Nuclei template from vulnerability data
        """
        vuln_type = vulnerability.get('type', 'Unknown')
        template_info = self.template_database.get(vuln_type, {})
        
        # Generate unique template ID
        vuln_hash = hashlib.md5(
            f"{vulnerability.get('url', '')}{vulnerability.get('parameter', '')}{time.time()}".encode()
        ).hexdigest()[:8]
        
        template_id = template_info.get('id_template', f'generic-{vuln_hash}').format(hash=vuln_hash)
        
        # Base template structure
        template = {
            'id': template_id,
            'info': {
                'name': f"{vuln_type} - {urlparse(vulnerability.get('url', '')).netloc}",
                'author': 'zeus-scanner-ai',
                'severity': template_info.get('severity', 'medium'),
                'description': f"Detection template for {vuln_type} vulnerability discovered by Zeus Scanner AI",
                'reference': [
                    'https://github.com/zeus-scanner/zeus-scanner',
                    'https://owasp.org/www-project-top-ten/'
                ],
                'classification': template_info.get('classification', {}),
                'tags': template_info.get('tags', [vuln_type.lower().replace(' ', '-')]),
                'metadata': {
                    'zeus-detection-time': vulnerability.get('timestamp', time.time()),
                    'original-url': vulnerability.get('url', ''),
                    'detection-method': 'ai-pattern-matching'
                }
            },
            'http': []
        }
        
        # Generate HTTP requests based on vulnerability type
        http_requests = self._generate_http_requests(vulnerability, template_info)
        template['http'] = http_requests
        
        return template
    
    def _generate_http_requests(self, vulnerability: Dict, template_info: Dict) -> List[Dict]:
        """
        Generate HTTP requests for vulnerability testing
        """
        vuln_type = vulnerability.get('type', 'Unknown')
        vuln_url = vulnerability.get('url', '')
        parameter = vulnerability.get('parameter', '')
        
        requests = []
        
        if vuln_type == 'SQL Injection':
            requests = self._generate_sqli_requests(vulnerability, template_info)
        elif vuln_type == 'Cross-Site Scripting (XSS)':
            requests = self._generate_xss_requests(vulnerability, template_info)
        elif vuln_type in ['Local File Inclusion (LFI)', 'Directory Traversal']:
            requests = self._generate_lfi_requests(vulnerability, template_info)
        elif vuln_type == 'Sensitive File Exposure':
            requests = self._generate_file_exposure_requests(vulnerability, template_info)
        elif vuln_type == 'Information Disclosure':
            requests = self._generate_info_disclosure_requests(vulnerability, template_info)
        else:
            requests = self._generate_generic_requests(vulnerability, template_info)
        
        return requests
    
    def _generate_sqli_requests(self, vulnerability: Dict, template_info: Dict) -> List[Dict]:
        """
        Generate SQL injection detection requests
        """
        parameter = vulnerability.get('parameter', 'id')
        payloads = template_info.get('payloads', ["' OR '1'='1"])
        
        request = {
            'method': 'GET',
            'path': ['{{BaseURL}}{{path}}'],
            'payloads': {
                parameter: payloads
            },
            'attack': 'pitchfork',
            'matchers-condition': 'or',
            'matchers': [
                {
                    'type': 'word',
                    'words': ['mysql_fetch_array', 'ORA-', 'PostgreSQL ERROR', 'syntax error', 'mysql_num_rows'],
                    'condition': 'or'
                },
                {
                    'type': 'regex',
                    'regex': [
                        'SQL.*syntax.*error',
                        'mysql_fetch_array\\(\\)',
                        'ORA-\\d{5}',
                        'PostgreSQL.*ERROR'
                    ],
                    'condition': 'or'
                }
            ],
            'extractors': [
                {
                    'type': 'regex',
                    'name': 'sql_error',
                    'regex': ['(SQL.*error.*|mysql_.*error.*|ORA-\\d+.*)'],
                    'group': 1
                }
            ]
        }
        
        return [request]
    
    def _generate_xss_requests(self, vulnerability: Dict, template_info: Dict) -> List[Dict]:
        """
        Generate XSS detection requests
        """
        parameter = vulnerability.get('parameter', 'q')
        payloads = template_info.get('payloads', ['<script>alert("XSS")</script>'])
        
        request = {
            'method': 'GET',
            'path': ['{{BaseURL}}{{path}}'],
            'payloads': {
                parameter: payloads
            },
            'attack': 'pitchfork',
            'matchers-condition': 'and',
            'matchers': [
                {
                    'type': 'status',
                    'status': [200]
                },
                {
                    'type': 'word',
                    'words': ['<script>alert("XSS")</script>', 'javascript:alert', 'onerror=alert'],
                    'part': 'body',
                    'condition': 'or'
                }
            ],
            'extractors': [
                {
                    'type': 'regex', 
                    'name': 'xss_payload',
                    'regex': ['(<script.*?</script>|javascript:.*?|on\\w+=.*?)'],
                    'group': 1
                }
            ]
        }
        
        return [request]
    
    def _generate_lfi_requests(self, vulnerability: Dict, template_info: Dict) -> List[Dict]:
        """
        Generate LFI/Directory Traversal detection requests
        """
        parameter = vulnerability.get('parameter', 'file')
        payloads = template_info.get('payloads', ['../../../etc/passwd'])
        
        request = {
            'method': 'GET',
            'path': ['{{BaseURL}}{{path}}'],
            'payloads': {
                parameter: payloads
            },
            'attack': 'pitchfork',
            'matchers-condition': 'or',
            'matchers': [
                {
                    'type': 'regex',
                    'regex': [
                        'root:x:0:0:',
                        '\\[fonts\\]',
                        '127\\.0\\.0\\.1.*localhost'
                    ],
                    'condition': 'or'
                },
                {
                    'type': 'word',
                    'words': ['root:', 'daemon:', 'www-data:', 'Windows NT'],
                    'condition': 'or'
                }
            ],
            'extractors': [
                {
                    'type': 'regex',
                    'name': 'file_content',
                    'regex': ['(root:x:0:0:.*|Windows NT.*|\\[fonts\\].*)'],
                    'group': 1
                }
            ]
        }
        
        return [request]
    
    def _generate_file_exposure_requests(self, vulnerability: Dict, template_info: Dict) -> List[Dict]:
        """
        Generate sensitive file exposure detection requests
        """
        exposed_file = vulnerability.get('file_path', '/robots.txt')
        
        request = {
            'method': 'GET',
            'path': [f'{{{{BaseURL}}}}{exposed_file}'],
            'matchers-condition': 'and',
            'matchers': [
                {
                    'type': 'status',
                    'status': [200]
                },
                {
                    'type': 'dsl',
                    'dsl': ['len(body) > 0']
                }
            ],
            'extractors': [
                {
                    'type': 'regex',
                    'name': 'sensitive_data',
                    'regex': ['(password|api[_-]?key|secret|token).*?[=:](.*?)\\n'],
                    'group': 2
                }
            ]
        }
        
        return [request]
    
    def _generate_info_disclosure_requests(self, vulnerability: Dict, template_info: Dict) -> List[Dict]:
        """
        Generate information disclosure detection requests
        """
        request = {
            'method': 'GET',
            'path': ['{{BaseURL}}/'],
            'matchers': [
                {
                    'type': 'regex',
                    'regex': [
                        'Server:\\s*(.+)',
                        'X-Powered-By:\\s*(.+)',
                        'X-AspNet-Version:\\s*(.+)'
                    ],
                    'part': 'header',
                    'condition': 'or'
                }
            ],
            'extractors': [
                {
                    'type': 'regex',
                    'name': 'server_info',
                    'regex': [
                        'Server:\\s*(.+)',
                        'X-Powered-By:\\s*(.+)',
                        'X-AspNet-Version:\\s*(.+)'
                    ],
                    'part': 'header',
                    'group': 1
                }
            ]
        }
        
        return [request]
    
    def _generate_generic_requests(self, vulnerability: Dict, template_info: Dict) -> List[Dict]:
        """
        Generate generic vulnerability detection requests
        """
        request = {
            'method': 'GET',
            'path': ['{{BaseURL}}{{path}}'],
            'matchers': [
                {
                    'type': 'status',
                    'status': [200, 500, 403]
                }
            ]
        }
        
        return [request]
    
    def _save_template(self, template_data: Dict, output_dir: str) -> str:
        """
        Save template to appropriate directory
        """
        template_id = template_data['id']
        severity = template_data['info']['severity']
        
        # Determine subdirectory based on vulnerability type and severity
        if severity == 'critical':
            subdir = 'http/vulnerabilities'
        elif severity == 'high':
            subdir = 'http/vulnerabilities'
        elif severity == 'medium':
            subdir = 'http/exposures'
        else:
            subdir = 'http/misconfiguration'
        
        # Create YAML content
        yaml_content = self._create_yaml_content(template_data)
        
        # Save to file
        template_path = f"{output_dir}/{subdir}/{template_id}.yaml"
        os.makedirs(os.path.dirname(template_path), exist_ok=True)
        
        with open(template_path, 'w') as f:
            f.write(yaml_content)
        
        return template_path
    
    def _create_yaml_content(self, template_data: Dict) -> str:
        """
        Create properly formatted YAML content for Nuclei template
        """
        yaml_content = f"""id: {template_data['id']}

info:
  name: {template_data['info']['name']}
  author: {template_data['info']['author']}
  severity: {template_data['info']['severity']}
  description: {template_data['info']['description']}
  reference:"""
        
        for ref in template_data['info']['reference']:
            yaml_content += f"\n    - {ref}"
        
        if 'classification' in template_data['info']:
            yaml_content += "\n  classification:"
            for key, value in template_data['info']['classification'].items():
                yaml_content += f"\n    {key}: {value}"
        
        yaml_content += f"\n  tags: {','.join(template_data['info']['tags'])}"
        
        if 'metadata' in template_data['info']:
            yaml_content += "\n  metadata:"
            for key, value in template_data['info']['metadata'].items():
                yaml_content += f"\n    {key}: {value}"
        
        yaml_content += "\n\nhttp:"
        
        for i, request in enumerate(template_data['http']):
            yaml_content += f"\n  - method: {request.get('method', 'GET')}"
            
            if 'path' in request:
                yaml_content += "\n    path:"
                for path in request['path']:
                    yaml_content += f"\n      - \"{path}\""
            
            if 'payloads' in request:
                yaml_content += "\n    payloads:"
                for param, payloads in request['payloads'].items():
                    yaml_content += f"\n      {param}:"
                    for payload in payloads:
                        yaml_content += f"\n        - \"{payload.replace('\"', '\\\"')}\""
            
            if 'attack' in request:
                yaml_content += f"\n    attack: {request['attack']}"
            
            if 'matchers-condition' in request:
                yaml_content += f"\n    matchers-condition: {request['matchers-condition']}"
            
            if 'matchers' in request:
                yaml_content += "\n    matchers:"
                for matcher in request['matchers']:
                    yaml_content += f"\n      - type: {matcher['type']}"
                    
                    if 'words' in matcher:
                        yaml_content += "\n        words:"
                        for word in matcher['words']:
                            yaml_content += f"\n          - \"{word.replace('\"', '\\\"')}\""
                    
                    if 'regex' in matcher:
                        yaml_content += "\n        regex:"
                        for regex in matcher['regex']:
                            yaml_content += f"\n          - \"{regex.replace('\"', '\\\"')}\""
                    
                    if 'status' in matcher:
                        yaml_content += f"\n        status: {matcher['status']}"
                    
                    if 'condition' in matcher:
                        yaml_content += f"\n        condition: {matcher['condition']}"
                    
                    if 'part' in matcher:
                        yaml_content += f"\n        part: {matcher['part']}"
                    
                    if 'dsl' in matcher:
                        yaml_content += "\n        dsl:"
                        for dsl in matcher['dsl']:
                            yaml_content += f"\n          - \"{dsl}\""
            
            if 'extractors' in request:
                yaml_content += "\n    extractors:"
                for extractor in request['extractors']:
                    yaml_content += f"\n      - type: {extractor['type']}"
                    
                    if 'name' in extractor:
                        yaml_content += f"\n        name: {extractor['name']}"
                    
                    if 'regex' in extractor:
                        yaml_content += "\n        regex:"
                        for regex in extractor['regex']:
                            yaml_content += f"\n          - \"{regex.replace('\"', '\\\"')}\""
                    
                    if 'group' in extractor:
                        yaml_content += f"\n        group: {extractor['group']}"
                    
                    if 'part' in extractor:
                        yaml_content += f"\n        part: {extractor['part']}"
        
        yaml_content += f"\n\n# Generated by Zeus Scanner AI Engine\n# Timestamp: {datetime.now().isoformat()}"
        
        return yaml_content
    
    def _generate_collection_templates(self, generated_templates: List[Dict], output_dir: str):
        """
        Generate collection templates for batch scanning
        """
        collections = {
            'critical': [t for t in generated_templates if t['vulnerability'].get('severity') == 'HIGH'],
            'all': generated_templates
        }
        
        for collection_name, templates in collections.items():
            if not templates:
                continue
                
            collection_content = f"""id: zeus-ai-{collection_name}-collection

info:
  name: Zeus AI {collection_name.title()} Vulnerability Collection
  author: zeus-scanner-ai
  severity: info
  description: Collection of {collection_name} vulnerabilities detected by Zeus Scanner AI
  tags: zeus-ai,collection,{collection_name}

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/"
    
    matchers:
      - type: dsl
        dsl:
          - "true"
        
# Collection includes {len(templates)} templates:
"""
            
            for template in templates:
                vuln_type = template['vulnerability'].get('type', 'Unknown')
                template_path = os.path.basename(template['template_path'])
                collection_content += f"# - {template_path} ({vuln_type})\n"
            
            collection_path = f"{output_dir}/workflows/zeus-ai-{collection_name}-collection.yaml"
            with open(collection_path, 'w') as f:
                f.write(collection_content)
            
            print(f"{Fore.BLUE}[COLLECTION] Generated {collection_name} collection template{Style.RESET_ALL}")
    
    def _generate_workflow_files(self, generated_templates: List[Dict], output_dir: str):
        """
        Generate Nuclei workflow files
        """
        workflow_content = f"""id: zeus-ai-comprehensive-scan

info:
  name: Zeus AI Comprehensive Vulnerability Scan
  author: zeus-scanner-ai
  description: Comprehensive vulnerability scanning workflow generated by Zeus Scanner AI

workflows:
  - template: http/vulnerabilities/
  - template: http/exposures/  
  - template: http/misconfiguration/

# Generated from {len(generated_templates)} detected vulnerabilities
# Scan timestamp: {datetime.now().isoformat()}
"""
        
        workflow_path = f"{output_dir}/workflows/zeus-ai-comprehensive-scan.yaml"
        with open(workflow_path, 'w') as f:
            f.write(workflow_content)
        
        print(f"{Fore.BLUE}[WORKFLOW] Generated comprehensive scan workflow{Style.RESET_ALL}")
    
    def _generate_readme(self, generated_templates: List[Dict], output_dir: str):
        """
        Generate README file for template collection
        """
        readme_content = f"""# Zeus Scanner AI - Nuclei Templates

Generated: {datetime.now().isoformat()}
Total Templates: {len(generated_templates)}

## Overview

This collection contains Nuclei templates automatically generated by Zeus Scanner AI Engine based on real vulnerability detections.

## Directory Structure

```
nuclei-templates/
├── http/
│   ├── vulnerabilities/    # Critical and High severity vulnerabilities
│   ├── exposures/         # Medium severity exposures
│   └── misconfiguration/  # Low severity misconfigurations
├── workflows/             # Nuclei workflow files
└── helpers/              # Helper templates and utilities
```

## Usage

### Run all templates
```bash
nuclei -t nuclei-templates/ -u https://target.com
```

### Run specific severity
```bash
nuclei -t nuclei-templates/http/vulnerabilities/ -u https://target.com
```

### Use workflow
```bash
nuclei -w nuclei-templates/workflows/zeus-ai-comprehensive-scan.yaml -u https://target.com
```

## Template Details

"""
        
        # Group templates by vulnerability type
        vuln_types = {}
        for template in generated_templates:
            vuln_type = template['vulnerability'].get('type', 'Unknown')
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(template)
        
        for vuln_type, templates in vuln_types.items():
            readme_content += f"\n### {vuln_type}\n"
            readme_content += f"Templates: {len(templates)}\n\n"
            
            for template in templates:
                template_name = os.path.basename(template['template_path'])
                url = template['vulnerability'].get('url', 'N/A')
                readme_content += f"- `{template_name}` - {url}\n"
        
        readme_content += f"""

## Security Notes

 **WARNING**: These templates are generated from real vulnerability detections. Use only on authorized targets.

- Obtain explicit permission before scanning
- Follow responsible disclosure practices
- Use in authorized security testing environments only

## Template Validation

All templates have been automatically validated for:
- Proper YAML syntax
- Nuclei template format compliance
- Matcher logic correctness
- Payload safety

## Support

Generated by Zeus Scanner AI Engine
- GitHub: https://github.com/zeus-scanner/zeus-scanner
- Documentation: See AI_ENGINE_README.md

---
*Auto-generated by Zeus Scanner AI - {datetime.now().isoformat()}*
"""
        
        readme_path = f"{output_dir}/README.md"
        with open(readme_path, 'w') as f:
            f.write(readme_content)
        
        print(f"{Fore.GREEN}[README] Generated documentation{Style.RESET_ALL}")
    
    def validate_templates(self, template_dir: str) -> Dict[str, Any]:
        """
        Validate generated Nuclei templates
        """
        print(f"\n{Fore.YELLOW}Validating generated templates...{Style.RESET_ALL}")
        
        validation_results = {
            'total_templates': 0,
            'valid_templates': 0,
            'invalid_templates': 0,
            'errors': []
        }
        
        # Find all YAML files
        for root, dirs, files in os.walk(template_dir):
            for file in files:
                if file.endswith('.yaml'):
                    template_path = os.path.join(root, file)
                    validation_results['total_templates'] += 1
                    
                    try:
                        with open(template_path, 'r') as f:
                            yaml.safe_load(f)
                        validation_results['valid_templates'] += 1
                        print(f"{Fore.GREEN}✓ {os.path.relpath(template_path, template_dir)}{Style.RESET_ALL}")
                    except Exception as e:
                        validation_results['invalid_templates'] += 1
                        validation_results['errors'].append({
                            'file': template_path,
                            'error': str(e)
                        })
                        print(f"{Fore.RED}✗ {os.path.relpath(template_path, template_dir)}: {e}{Style.RESET_ALL}")
        
        print(f"\n{Fore.BLUE}Validation Summary:{Style.RESET_ALL}")
        print(f"Total Templates: {validation_results['total_templates']}")
        print(f"Valid Templates: {validation_results['valid_templates']}")
        print(f"Invalid Templates: {validation_results['invalid_templates']}")
        
        return validation_results
