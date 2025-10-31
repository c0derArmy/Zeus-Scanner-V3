#!/usr/bin/env python3

import json
import time
import math
from datetime import datetime
from typing import Dict, List, Any, Tuple

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

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


class RiskAssessor:
    """
    AI-powered risk assessment engine for vulnerability management
    """
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.cvss_base_scores = self._initialize_cvss_scores()
        self.industry_risk_weights = self._initialize_industry_weights()
        self.exploit_complexity_factors = self._initialize_complexity_factors()
        
    def _initialize_cvss_scores(self):
        """
        Initialize CVSS base scores for different vulnerability types
        """
        return {
            'SQL Injection': {
                'base_score': 9.0,
                'attack_vector': 'Network',
                'attack_complexity': 'Low',
                'privileges_required': 'None',
                'user_interaction': 'None',
                'scope': 'Changed',
                'confidentiality': 'High',
                'integrity': 'High',
                'availability': 'High'
            },
            'Cross-Site Scripting (XSS)': {
                'base_score': 6.1,
                'attack_vector': 'Network',
                'attack_complexity': 'Low',
                'privileges_required': 'None',
                'user_interaction': 'Required',
                'scope': 'Changed',
                'confidentiality': 'Low',
                'integrity': 'Low',
                'availability': 'None'
            },
            'Local File Inclusion (LFI)': {
                'base_score': 7.5,
                'attack_vector': 'Network',
                'attack_complexity': 'Low',
                'privileges_required': 'None',
                'user_interaction': 'None',
                'scope': 'Unchanged',
                'confidentiality': 'High',
                'integrity': 'None',
                'availability': 'None'
            },
            'Directory Traversal': {
                'base_score': 7.5,
                'attack_vector': 'Network',
                'attack_complexity': 'Low',
                'privileges_required': 'None',
                'user_interaction': 'None',
                'scope': 'Unchanged',
                'confidentiality': 'High',
                'integrity': 'None',
                'availability': 'None'
            },
            'Sensitive File Exposure': {
                'base_score': 5.3,
                'attack_vector': 'Network',
                'attack_complexity': 'Low',
                'privileges_required': 'None',
                'user_interaction': 'None',
                'scope': 'Unchanged',
                'confidentiality': 'Low',
                'integrity': 'None',
                'availability': 'None'
            },
            'Information Disclosure': {
                'base_score': 3.7,
                'attack_vector': 'Network',
                'attack_complexity': 'Low',
                'privileges_required': 'None',
                'user_interaction': 'None',
                'scope': 'Unchanged',
                'confidentiality': 'Low',
                'integrity': 'None',
                'availability': 'None'
            },
            'Directory Listing': {
                'base_score': 5.0,
                'attack_vector': 'Network',
                'attack_complexity': 'Low',
                'privileges_required': 'None',
                'user_interaction': 'None',
                'scope': 'Unchanged',
                'confidentiality': 'Low',
                'integrity': 'None',
                'availability': 'None'
            }
        }
    
    def _initialize_industry_weights(self):
        """
        Initialize industry-specific risk weights
        """
        return {
            'financial': {
                'data_confidentiality': 1.5,
                'regulatory_compliance': 1.8,
                'availability_impact': 1.3,
                'reputation_risk': 1.6
            },
            'healthcare': {
                'data_confidentiality': 1.8,
                'regulatory_compliance': 2.0,
                'availability_impact': 1.7,
                'reputation_risk': 1.4
            },
            'government': {
                'data_confidentiality': 1.9,
                'regulatory_compliance': 1.6,
                'availability_impact': 1.5,
                'reputation_risk': 1.8
            },
            'retail': {
                'data_confidentiality': 1.3,
                'regulatory_compliance': 1.2,
                'availability_impact': 1.6,
                'reputation_risk': 1.4
            },
            'technology': {
                'data_confidentiality': 1.4,
                'regulatory_compliance': 1.1,
                'availability_impact': 1.4,
                'reputation_risk': 1.3
            },
            'default': {
                'data_confidentiality': 1.0,
                'regulatory_compliance': 1.0,
                'availability_impact': 1.0,
                'reputation_risk': 1.0
            }
        }
    
    def _initialize_complexity_factors(self):
        """
        Initialize exploit complexity factors
        """
        return {
            'SQL Injection': {
                'detection_difficulty': 0.2,  # Easy to detect
                'exploitation_skill_level': 0.3,  # Medium skill required
                'tool_availability': 0.1,  # Many tools available
                'payload_complexity': 0.4  # Can be complex
            },
            'Cross-Site Scripting (XSS)': {
                'detection_difficulty': 0.1,  # Very easy to detect
                'exploitation_skill_level': 0.2,  # Low skill required
                'tool_availability': 0.1,  # Many tools available
                'payload_complexity': 0.3  # Moderate complexity
            },
            'Local File Inclusion (LFI)': {
                'detection_difficulty': 0.3,  # Moderate detection difficulty
                'exploitation_skill_level': 0.4,  # Medium-high skill
                'tool_availability': 0.2,  # Some tools available
                'payload_complexity': 0.5  # Can be complex
            },
            'Directory Traversal': {
                'detection_difficulty': 0.2,  # Easy to detect
                'exploitation_skill_level': 0.2,  # Low skill required
                'tool_availability': 0.1,  # Many tools available
                'payload_complexity': 0.2  # Simple payloads
            },
            'Information Disclosure': {
                'detection_difficulty': 0.1,  # Very easy to detect
                'exploitation_skill_level': 0.1,  # Very low skill
                'tool_availability': 0.05,  # Automated scanners
                'payload_complexity': 0.1  # No complex payloads
            }
        }

    def assess_vulnerability_risk(self, vulnerability: Dict[str, Any], 
                                context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Perform comprehensive risk assessment for a single vulnerability
        """
        vuln_type = vulnerability.get('type', 'Unknown')
        
        print(f"{Fore.BLUE}[RISK] Assessing risk for {vuln_type}{Style.RESET_ALL}")
        
        # Calculate base risk score
        base_risk = self._calculate_base_risk(vulnerability)
        
        # Calculate contextual risk factors
        contextual_risk = self._calculate_contextual_risk(vulnerability, context or {})
        
        # Calculate exploitability score
        exploitability = self._calculate_exploitability(vulnerability)
        
        # Calculate business impact
        business_impact = self._calculate_business_impact(vulnerability, context or {})
        
        # Calculate likelihood of exploitation
        likelihood = self._calculate_likelihood(vulnerability, context or {})
        
        # Calculate overall risk score
        overall_risk = self._calculate_overall_risk(
            base_risk, contextual_risk, exploitability, business_impact, likelihood
        )
        
        # Determine risk level and priority
        risk_level, priority = self._determine_risk_level_and_priority(overall_risk)
        
        assessment = {
            'vulnerability_id': self._generate_vulnerability_id(vulnerability),
            'vulnerability_type': vuln_type,
            'assessment_timestamp': time.time(),
            'assessment_date': datetime.now().isoformat(),
            'scores': {
                'base_risk': base_risk,
                'contextual_risk': contextual_risk,
                'exploitability': exploitability,
                'business_impact': business_impact,
                'likelihood': likelihood,
                'overall_risk': overall_risk
            },
            'risk_level': risk_level,
            'priority': priority,
            'cvss_info': self._get_cvss_info(vulnerability),
            'threat_intelligence': self._gather_threat_intelligence(vulnerability),
            'remediation_urgency': self._calculate_remediation_urgency(overall_risk, context or {}),
            'compensating_controls': self._suggest_compensating_controls(vulnerability),
            'risk_acceptance_criteria': self._generate_risk_acceptance_criteria(overall_risk)
        }
        
        return assessment

    def _calculate_base_risk(self, vulnerability: Dict[str, Any]) -> float:
        """
        Calculate base risk score using CVSS-like methodology
        """
        vuln_type = vulnerability.get('type', 'Unknown')
        severity = vulnerability.get('severity', 'MEDIUM')
        
        # Get CVSS base score
        cvss_info = self.cvss_base_scores.get(vuln_type, {})
        base_score = cvss_info.get('base_score', 5.0)
        
        # Adjust based on reported severity
        severity_multipliers = {'HIGH': 1.2, 'MEDIUM': 1.0, 'LOW': 0.7}
        adjusted_score = base_score * severity_multipliers.get(severity, 1.0)
        
        # Normalize to 0-10 scale
        return min(10.0, max(0.0, adjusted_score))

    def _calculate_contextual_risk(self, vulnerability: Dict[str, Any], 
                                 context: Dict[str, Any]) -> float:
        """
        Calculate contextual risk factors
        """
        contextual_score = 5.0  # Base contextual score
        
        # URL-based context
        url = vulnerability.get('url', '').lower()
        
        # Administrative interfaces increase risk
        if any(keyword in url for keyword in ['admin', 'manage', 'control', 'dashboard']):
            contextual_score += 2.0
        
        # API endpoints
        if any(keyword in url for keyword in ['api', 'rest', 'graphql', 'json']):
            contextual_score += 1.5
        
        # Authentication-related endpoints
        if any(keyword in url for keyword in ['login', 'auth', 'session', 'token']):
            contextual_score += 1.8
        
        # Database-related endpoints
        if any(keyword in url for keyword in ['db', 'database', 'sql', 'query']):
            contextual_score += 2.2
        
        # File handling endpoints
        if any(keyword in url for keyword in ['file', 'upload', 'download', 'document']):
            contextual_score += 1.5
        
        # Parameter context
        parameter = vulnerability.get('parameter', '')
        if parameter:
            contextual_score += 0.5  # Parameterized vulnerabilities are generally more exploitable
            
            # High-risk parameters
            if any(keyword in parameter.lower() for keyword in ['id', 'user', 'admin', 'file', 'path']):
                contextual_score += 1.0
        
        # Environment context from provided context
        environment = context.get('environment', 'production')
        env_multipliers = {
            'production': 1.0,
            'staging': 0.8,
            'development': 0.6,
            'testing': 0.4
        }
        contextual_score *= env_multipliers.get(environment, 1.0)
        
        # Public vs internal
        exposure = context.get('exposure', 'public')
        if exposure == 'internal':
            contextual_score *= 0.7
        elif exposure == 'public':
            contextual_score *= 1.0
        
        return min(10.0, max(0.0, contextual_score))

    def _calculate_exploitability(self, vulnerability: Dict[str, Any]) -> float:
        """
        Calculate exploitability score based on complexity factors
        """
        vuln_type = vulnerability.get('type', 'Unknown')
        
        # Get complexity factors
        factors = self.exploit_complexity_factors.get(vuln_type, {
            'detection_difficulty': 0.5,
            'exploitation_skill_level': 0.5,
            'tool_availability': 0.5,
            'payload_complexity': 0.5
        })
        
        # Calculate exploitability (lower complexity = higher exploitability)
        exploitability = 10.0
        
        # Reduce score based on complexity factors
        exploitability -= factors.get('detection_difficulty', 0.5) * 2
        exploitability -= factors.get('exploitation_skill_level', 0.5) * 3
        exploitability -= factors.get('tool_availability', 0.5) * 2
        exploitability -= factors.get('payload_complexity', 0.5) * 2
        
        # Check if vulnerability has been successfully detected (indicates lower complexity)
        if vulnerability.get('payload') or vulnerability.get('pattern_matched'):
            exploitability += 1.0
        
        # Authentication requirements
        if 'auth' in str(vulnerability).lower():
            exploitability -= 1.5
        
        return min(10.0, max(0.0, exploitability))

    def _calculate_business_impact(self, vulnerability: Dict[str, Any], 
                                 context: Dict[str, Any]) -> float:
        """
        Calculate potential business impact
        """
        vuln_type = vulnerability.get('type', 'Unknown')
        base_impact = 5.0
        
        # Impact based on vulnerability type
        impact_scores = {
            'SQL Injection': 9.0,  # High data exposure risk
            'Local File Inclusion (LFI)': 8.0,  # System file access
            'Directory Traversal': 7.0,  # File system access
            'Cross-Site Scripting (XSS)': 6.0,  # User account compromise
            'Sensitive File Exposure': 7.0,  # Information disclosure
            'Directory Listing': 4.0,  # Information disclosure
            'Information Disclosure': 3.0  # Minor information leak
        }
        
        base_impact = impact_scores.get(vuln_type, 5.0)
        
        # Industry-specific adjustments
        industry = context.get('industry', 'default')
        industry_weights = self.industry_risk_weights.get(industry, self.industry_risk_weights['default'])
        
        # Apply industry-specific multipliers
        if 'SQL' in vuln_type or 'File' in vuln_type:
            base_impact *= industry_weights['data_confidentiality']
        
        if context.get('regulated_environment', False):
            base_impact *= industry_weights['regulatory_compliance']
        
        if context.get('high_availability_requirement', False):
            base_impact *= industry_weights['availability_impact']
        
        if context.get('public_facing', True):
            base_impact *= industry_weights['reputation_risk']
        
        # Data sensitivity
        data_classification = context.get('data_classification', 'internal')
        classification_multipliers = {
            'public': 0.5,
            'internal': 1.0,
            'confidential': 1.5,
            'restricted': 2.0
        }
        base_impact *= classification_multipliers.get(data_classification, 1.0)
        
        return min(10.0, max(0.0, base_impact))

    def _calculate_likelihood(self, vulnerability: Dict[str, Any], 
                            context: Dict[str, Any]) -> float:
        """
        Calculate likelihood of exploitation
        """
        base_likelihood = 5.0
        
        # Vulnerability type likelihood
        type_likelihoods = {
            'SQL Injection': 8.0,  # Commonly targeted
            'Cross-Site Scripting (XSS)': 7.0,  # Common attack
            'Local File Inclusion (LFI)': 6.0,  # Moderate targeting
            'Directory Traversal': 6.0,  # Moderate targeting
            'Sensitive File Exposure': 5.0,  # Opportunistic
            'Information Disclosure': 4.0,  # Low priority
            'Directory Listing': 3.0  # Low priority
        }
        
        vuln_type = vulnerability.get('type', 'Unknown')
        base_likelihood = type_likelihoods.get(vuln_type, 5.0)
        
        # Exposure factors
        if context.get('internet_facing', True):
            base_likelihood += 2.0
        
        if context.get('popular_target', False):
            base_likelihood += 1.5
        
        # Security controls
        security_controls = context.get('security_controls', {})
        
        if security_controls.get('waf_enabled', False):
            base_likelihood -= 1.5
        
        if security_controls.get('ids_enabled', False):
            base_likelihood -= 1.0
        
        if security_controls.get('monitoring_enabled', False):
            base_likelihood -= 0.5
        
        # Threat landscape
        threat_level = context.get('threat_landscape', 'medium')
        threat_multipliers = {'low': 0.7, 'medium': 1.0, 'high': 1.3, 'critical': 1.5}
        base_likelihood *= threat_multipliers.get(threat_level, 1.0)
        
        return min(10.0, max(0.0, base_likelihood))

    def _calculate_overall_risk(self, base_risk: float, contextual_risk: float, 
                              exploitability: float, business_impact: float, 
                              likelihood: float) -> float:
        """
        Calculate overall risk score using weighted algorithm
        """
        # Weights for different risk components
        weights = {
            'base_risk': 0.25,
            'contextual_risk': 0.15,
            'exploitability': 0.20,
            'business_impact': 0.25,
            'likelihood': 0.15
        }
        
        # Calculate weighted score
        overall_risk = (
            base_risk * weights['base_risk'] +
            contextual_risk * weights['contextual_risk'] +
            exploitability * weights['exploitability'] +
            business_impact * weights['business_impact'] +
            likelihood * weights['likelihood']
        )
        
        # Apply risk amplification for high-impact, high-likelihood scenarios
        if business_impact >= 7.0 and likelihood >= 7.0:
            overall_risk *= 1.2
        
        # Apply risk reduction for low-exploitability scenarios
        if exploitability <= 3.0:
            overall_risk *= 0.8
        
        return min(10.0, max(0.0, overall_risk))

    def _determine_risk_level_and_priority(self, overall_risk: float) -> Tuple[str, int]:
        """
        Determine risk level and remediation priority
        """
        if overall_risk >= 9.0:
            return 'CRITICAL', 1
        elif overall_risk >= 7.0:
            return 'HIGH', 2
        elif overall_risk >= 5.0:
            return 'MEDIUM', 3
        elif overall_risk >= 3.0:
            return 'LOW', 4
        else:
            return 'INFORMATIONAL', 5

    def _get_cvss_info(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get CVSS information for the vulnerability
        """
        vuln_type = vulnerability.get('type', 'Unknown')
        return self.cvss_base_scores.get(vuln_type, {
            'base_score': 5.0,
            'attack_vector': 'Network',
            'attack_complexity': 'Low',
            'privileges_required': 'None',
            'user_interaction': 'None',
            'scope': 'Unchanged',
            'confidentiality': 'Low',
            'integrity': 'Low',
            'availability': 'Low'
        })

    def _gather_threat_intelligence(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gather threat intelligence data for the vulnerability
        """
        vuln_type = vulnerability.get('type', 'Unknown')
        
        # Simulated threat intelligence data
        threat_intel = {
            'active_campaigns': False,
            'exploit_kits': [],
            'cve_references': [],
            'attack_frequency': 'medium',
            'geographic_distribution': 'global',
            'target_industries': [],
            'malware_families': []
        }
        
        if 'SQL' in vuln_type:
            threat_intel.update({
                'active_campaigns': True,
                'exploit_kits': ['SQLMap', 'Havij', 'SQLNinja'],
                'attack_frequency': 'high',
                'target_industries': ['finance', 'healthcare', 'retail'],
                'malware_families': ['Carbanak', 'FIN7']
            })
        
        elif 'XSS' in vuln_type:
            threat_intel.update({
                'active_campaigns': True,
                'exploit_kits': ['BeEF', 'XSS Hunter', 'BrowserHawk'],
                'attack_frequency': 'high',
                'target_industries': ['social_media', 'e_commerce', 'banking']
            })
        
        elif 'LFI' in vuln_type or 'Directory Traversal' in vuln_type:
            threat_intel.update({
                'active_campaigns': True,
                'exploit_kits': ['Fimap', 'LFISuite'],
                'attack_frequency': 'medium',
                'target_industries': ['web_hosting', 'cms_providers']
            })
        
        return threat_intel

    def _calculate_remediation_urgency(self, overall_risk: float, 
                                     context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate remediation urgency based on risk and context
        """
        base_urgency = overall_risk
        
        # Adjust for business factors
        if context.get('business_critical', False):
            base_urgency += 1.0
        
        if context.get('compliance_requirement', False):
            base_urgency += 1.5
        
        if context.get('public_disclosure_risk', False):
            base_urgency += 2.0
        
        # Determine SLA
        if base_urgency >= 9.0:
            sla_hours = 4  # Immediate
            urgency_level = 'EMERGENCY'
        elif base_urgency >= 7.0:
            sla_hours = 24  # Within 1 day
            urgency_level = 'HIGH'
        elif base_urgency >= 5.0:
            sla_hours = 72  # Within 3 days
            urgency_level = 'MEDIUM'
        elif base_urgency >= 3.0:
            sla_hours = 168  # Within 1 week
            urgency_level = 'LOW'
        else:
            sla_hours = 720  # Within 30 days
            urgency_level = 'INFORMATIONAL'
        
        return {
            'urgency_score': min(10.0, base_urgency),
            'urgency_level': urgency_level,
            'sla_hours': sla_hours,
            'recommended_timeline': self._calculate_recommended_timeline(sla_hours),
            'escalation_required': base_urgency >= 8.0
        }

    def _calculate_recommended_timeline(self, sla_hours: int) -> Dict[str, str]:
        """
        Calculate recommended remediation timeline
        """
        if sla_hours <= 4:
            return {
                'immediate_action': '15 minutes',
                'containment': '1 hour',
                'remediation': '4 hours',
                'verification': '6 hours'
            }
        elif sla_hours <= 24:
            return {
                'immediate_action': '1 hour',
                'containment': '4 hours',
                'remediation': '24 hours',
                'verification': '36 hours'
            }
        elif sla_hours <= 72:
            return {
                'immediate_action': '4 hours',
                'containment': '12 hours',
                'remediation': '72 hours',
                'verification': '96 hours'
            }
        else:
            return {
                'immediate_action': '24 hours',
                'containment': '48 hours',
                'remediation': f'{sla_hours} hours',
                'verification': f'{sla_hours + 24} hours'
            }

    def _suggest_compensating_controls(self, vulnerability: Dict[str, Any]) -> List[str]:
        """
        Suggest compensating controls while remediation is in progress
        """
        vuln_type = vulnerability.get('type', 'Unknown')
        controls = []
        
        if 'SQL' in vuln_type:
            controls.extend([
                'Deploy Web Application Firewall (WAF) with SQL injection rules',
                'Implement database activity monitoring',
                'Apply principle of least privilege to database accounts',
                'Enable database query logging and monitoring',
                'Implement input validation at network perimeter'
            ])
        
        elif 'XSS' in vuln_type:
            controls.extend([
                'Deploy Content Security Policy (CSP) headers',
                'Implement XSS filtering at WAF level',
                'Enable HTTPOnly and Secure cookie flags',
                'Implement session timeout controls',
                'Monitor for suspicious JavaScript execution'
            ])
        
        elif 'LFI' in vuln_type or 'Directory Traversal' in vuln_type:
            controls.extend([
                'Implement file access monitoring',
                'Apply strict file system permissions',
                'Deploy file integrity monitoring (FIM)',
                'Implement network segmentation',
                'Monitor for unusual file access patterns'
            ])
        
        elif 'Information Disclosure' in vuln_type:
            controls.extend([
                'Implement proper HTTP headers (Server, X-Powered-By)',
                'Configure web server to hide version information',
                'Deploy network monitoring for data exfiltration',
                'Implement access logging and monitoring'
            ])
        
        # Universal controls
        controls.extend([
            'Increase security monitoring and alerting',
            'Implement network intrusion detection',
            'Deploy endpoint detection and response (EDR)',
            'Conduct additional security awareness training',
            'Implement incident response procedures'
        ])
        
        return controls

    def _generate_risk_acceptance_criteria(self, overall_risk: float) -> Dict[str, Any]:
        """
        Generate risk acceptance criteria for management decisions
        """
        if overall_risk >= 7.0:
            acceptance_level = 'NOT_RECOMMENDED'
            approval_required = 'C-Level Executive'
            documentation_required = [
                'Detailed risk analysis',
                'Business justification',
                'Compensating controls implementation plan',
                'Incident response plan',
                'Insurance coverage verification',
                'Regular risk review schedule'
            ]
        elif overall_risk >= 5.0:
            acceptance_level = 'CONDITIONAL'
            approval_required = 'Senior Management'
            documentation_required = [
                'Risk analysis summary',
                'Business justification',
                'Compensating controls',
                'Monitoring plan',
                'Review schedule'
            ]
        elif overall_risk >= 3.0:
            acceptance_level = 'ACCEPTABLE'
            approval_required = 'Department Manager'
            documentation_required = [
                'Risk assessment summary',
                'Basic monitoring plan'
            ]
        else:
            acceptance_level = 'ACCEPTABLE'
            approval_required = 'Security Team'
            documentation_required = [
                'Risk assessment record'
            ]
        
        return {
            'acceptance_level': acceptance_level,
            'approval_required': approval_required,
            'documentation_required': documentation_required,
            'insurance_implications': overall_risk >= 7.0,
            'regulatory_considerations': overall_risk >= 6.0,
            'recommended_review_frequency': '30 days' if overall_risk >= 7.0 else '90 days' if overall_risk >= 5.0 else '180 days'
        }

    def _generate_vulnerability_id(self, vulnerability: Dict[str, Any]) -> str:
        """
        Generate a unique vulnerability ID
        """
        import hashlib
        
        # Create unique identifier based on vulnerability characteristics
        identifier_string = f"{vulnerability.get('type', '')}-{vulnerability.get('url', '')}-{vulnerability.get('parameter', '')}-{vulnerability.get('timestamp', '')}"
        
        # Generate hash
        hash_object = hashlib.md5(identifier_string.encode())
        return f"ZEUS-{hash_object.hexdigest()[:8].upper()}"

    def assess_portfolio_risk(self, vulnerabilities: List[Dict[str, Any]], 
                            context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Assess risk across a portfolio of vulnerabilities
        """
        print(f"\n{Fore.MAGENTA}Zeus Risk Assessor - Portfolio Analysis{Style.RESET_ALL}")
        print(f"{Fore.BLUE}Analyzing risk for {len(vulnerabilities)} vulnerabilities...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}\n")
        
        if not vulnerabilities:
            return {'error': 'No vulnerabilities provided for assessment'}
        
        individual_assessments = []
        context = context or {}
        
        # Assess each vulnerability
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"{Fore.CYAN}[{i}/{len(vulnerabilities)}] Assessing {vuln.get('type', 'Unknown')}{Style.RESET_ALL}")
            assessment = self.assess_vulnerability_risk(vuln, context)
            individual_assessments.append(assessment)
        
        # Calculate portfolio metrics
        risk_scores = [a['scores']['overall_risk'] for a in individual_assessments]
        
        portfolio_assessment = {
            'portfolio_summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'assessment_timestamp': time.time(),
                'assessment_date': datetime.now().isoformat(),
                'context': context
            },
            'risk_metrics': {
                'average_risk_score': float(np.mean(risk_scores)) if NUMPY_AVAILABLE else sum(risk_scores) / len(risk_scores),
                'maximum_risk_score': float(max(risk_scores)),
                'minimum_risk_score': float(min(risk_scores)),
                'risk_variance': float(np.var(risk_scores)) if NUMPY_AVAILABLE else 0.0,
                'total_risk_exposure': sum(risk_scores)
            },
            'risk_distribution': {
                'critical': len([s for s in risk_scores if s >= 9.0]),
                'high': len([s for s in risk_scores if 7.0 <= s < 9.0]),
                'medium': len([s for s in risk_scores if 5.0 <= s < 7.0]),
                'low': len([s for s in risk_scores if 3.0 <= s < 5.0]),
                'informational': len([s for s in risk_scores if s < 3.0])
            },
            'priority_queue': sorted(individual_assessments, 
                                   key=lambda x: x['scores']['overall_risk'], 
                                   reverse=True)[:10],  # Top 10 highest risk
            'remediation_timeline': self._calculate_portfolio_remediation_timeline(individual_assessments),
            'resource_requirements': self._calculate_resource_requirements(individual_assessments),
            'compliance_impact': self._assess_compliance_impact(individual_assessments, context),
            'individual_assessments': individual_assessments
        }
        
        return portfolio_assessment

    def _calculate_portfolio_remediation_timeline(self, assessments: List[Dict]) -> Dict[str, Any]:
        """
        Calculate overall remediation timeline for the portfolio
        """
        urgency_levels = [a['remediation_urgency']['urgency_level'] for a in assessments]
        sla_hours = [a['remediation_urgency']['sla_hours'] for a in assessments]
        
        critical_count = urgency_levels.count('EMERGENCY')
        high_count = urgency_levels.count('HIGH')
        
        return {
            'immediate_attention_required': critical_count + high_count,
            'shortest_sla': min(sla_hours) if sla_hours else 720,
            'estimated_total_effort_hours': sum(sla_hours) * 0.3,  # Assume 30% of SLA time for actual work
            'recommended_team_size': max(2, (critical_count + high_count) // 3),
            'parallel_remediation_possible': len([a for a in assessments if a['scores']['overall_risk'] < 7.0])
        }

    def _calculate_resource_requirements(self, assessments: List[Dict]) -> Dict[str, Any]:
        """
        Calculate resource requirements for remediation
        """
        skill_requirements = set()
        tool_requirements = set()
        
        for assessment in assessments:
            vuln_type = assessment['vulnerability_type']
            
            if 'SQL' in vuln_type:
                skill_requirements.update(['Database Security', 'Secure Coding', 'WAF Configuration'])
                tool_requirements.update(['Static Code Analysis', 'Database Activity Monitor', 'WAF'])
            
            elif 'XSS' in vuln_type:
                skill_requirements.update(['Web Security', 'Secure Coding', 'CSP Implementation'])
                tool_requirements.update(['Static Code Analysis', 'Dynamic Testing', 'CSP Tools'])
            
            elif 'LFI' in vuln_type or 'Directory Traversal' in vuln_type:
                skill_requirements.update(['File System Security', 'Secure Coding'])
                tool_requirements.update(['File Integrity Monitoring', 'Static Code Analysis'])
        
        return {
            'required_skills': list(skill_requirements),
            'required_tools': list(tool_requirements),
            'estimated_budget': len(assessments) * 1000,  # Rough estimate per vulnerability
            'external_expertise_needed': len([a for a in assessments if a['scores']['overall_risk'] >= 8.0]) > 5
        }

    def _assess_compliance_impact(self, assessments: List[Dict], 
                                context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess compliance impact of the vulnerability portfolio
        """
        high_risk_count = len([a for a in assessments if a['risk_level'] in ['CRITICAL', 'HIGH']])
        
        compliance_frameworks = context.get('compliance_frameworks', [])
        
        impact_assessment = {
            'frameworks_affected': compliance_frameworks,
            'violation_risk': 'HIGH' if high_risk_count > 5 else 'MEDIUM' if high_risk_count > 2 else 'LOW',
            'reporting_required': high_risk_count > 0 and any(fw in compliance_frameworks for fw in ['PCI-DSS', 'HIPAA', 'SOX']),
            'audit_implications': high_risk_count > 3,
            'certification_impact': high_risk_count > 10,
            'estimated_fine_exposure': high_risk_count * 50000 if 'GDPR' in compliance_frameworks else 0
        }
        
        return impact_assessment