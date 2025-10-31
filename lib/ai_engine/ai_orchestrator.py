#!/usr/bin/env python3

import os
import json
import time
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

from .vulnerability_detector import VulnerabilityDetector
from .ai_analyzer import AIAnalyzer
from .poc_generator import PoCGenerator
from .risk_assessor import RiskAssessor
from .cve_detector import CVEDetector
from .template_generator import NucleiTemplateGenerator
from .enhanced_ai_engine import EnhancedAIEngine

import lib.core.settings
import lib.core.common


class AIOrchestrator:
    """
    Main AI orchestrator for Zeus Scanner - coordinates all AI components
    """
    
    def __init__(self, target_url, verbose=False, user_agent=None, proxy=None, context=None):
        self.target_url = target_url
        self.verbose = verbose
        self.user_agent = user_agent
        self.proxy = proxy
        self.context = context or {}
        
        # Initialize AI components
        self.vulnerability_detector = VulnerabilityDetector(
            target_url, verbose, user_agent, proxy
        )
        self.ai_analyzer = AIAnalyzer(verbose)
        self.poc_generator = PoCGenerator(verbose)
        self.risk_assessor = RiskAssessor(verbose)
        self.cve_detector = CVEDetector(verbose, user_agent, proxy)
        self.template_generator = NucleiTemplateGenerator(verbose)
        
        # Initialize Enhanced AI Engine with massive knowledge base
        print(f"{Fore.CYAN}[*] Initializing Enhanced AI Engine with massive vulnerability database...{Style.RESET_ALL}")
        self.enhanced_ai = EnhancedAIEngine()
        print(f"{Fore.GREEN}[+] Enhanced AI Engine loaded with comprehensive knowledge base!{Style.RESET_ALL}")
        
        # Display knowledge base statistics
        stats = self.enhanced_ai.get_vulnerability_stats()
        print(f"{Fore.CYAN}[*] Knowledge Base Statistics:{Style.RESET_ALL}")
        print(f"    SQL Injection patterns: {stats['static_knowledge_base']['sql_patterns']}")
        print(f"    XSS patterns: {stats['static_knowledge_base']['xss_patterns']}")
        print(f"    LFI/RFI patterns: {stats['static_knowledge_base']['lfi_patterns']}")
        print(f"    Command Injection patterns: {stats['static_knowledge_base']['command_patterns']}")
        print(f"    Dynamic SQL payloads: {stats['dynamic_payloads']['sql_injection']}")
        print(f"    Dynamic XSS payloads: {stats['dynamic_payloads']['xss']}")
        print(f"    CVE entries: {stats['cve_entries']}")
        print(f"    Available exploits: {stats['exploits']}")
        print(f"    Nuclei templates: {stats['nuclei_templates']}")
        
        self.enhanced_results = {}
        
        # Results storage
        self.scan_results = {}
        self.analysis_results = {}
        self.poc_results = {}
        self.risk_results = {}
        self.cve_results = {}
        self.template_results = {}
        
        # Create AI results directory
        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        self.results_dir = f"{os.getcwd()}/log/ai-assessment-{timestamp}"
        lib.core.settings.create_dir(self.results_dir)

    def run_full_ai_assessment(self, urls_list=None):
        """
        Run complete AI-powered vulnerability assessment
        """
        print(f"\n{Fore.CYAN}{Style.BRIGHT}Zeus AI-Powered Security Assessment Engine{Style.RESET_ALL}")
        print(f"{Fore.BLUE}Target: {Fore.WHITE}{self.target_url}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}Assessment ID: {Fore.WHITE}{os.path.basename(self.results_dir)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
        
        assessment_start_time = time.time()
        
        try:
            # Phase 1: Vulnerability Detection
            print(f"\n{Fore.MAGENTA}Phase 1: AI Vulnerability Detection{Style.RESET_ALL}")
            vulnerabilities = self.vulnerability_detector.start_detection(urls_list)
            self.scan_results = self.vulnerability_detector.generate_report()
            
            if not vulnerabilities:
                print(f"{Fore.YELLOW}No vulnerabilities detected. Assessment complete.{Style.RESET_ALL}")
                return self._generate_final_report(assessment_start_time)
            
            print(f"{Fore.GREEN}Found {len(vulnerabilities)} vulnerabilities{Style.RESET_ALL}")
            
            # Phase 2: AI Analysis
            print(f"\n{Fore.MAGENTA}Phase 2: AI-Powered Analysis{Style.RESET_ALL}")
            self.analysis_results = self.ai_analyzer.analyze_vulnerabilities(vulnerabilities)
            
            # Phase 3: PoC Generation
            print(f"\n{Fore.MAGENTA}Phase 3: Proof-of-Concept Generation{Style.RESET_ALL}")
            self.poc_results = self.poc_generator.generate_batch_poc(vulnerabilities)
            
            # Phase 4: CVE Detection
            print(f"\n{Fore.MAGENTA}Phase 4: CVE Detection & Analysis{Style.RESET_ALL}")
            detected_cves = self.cve_detector.detect_cves(self.target_url, urls_list)
            self.cve_results = self.cve_detector.generate_cve_report()
            
            # Combine traditional vulnerabilities with CVEs
            all_vulnerabilities = vulnerabilities + detected_cves
            
            # Phase 5: Risk Assessment
            print(f"\n{Fore.MAGENTA}Phase 5: Risk Assessment{Style.RESET_ALL}")
            self.risk_results = self.risk_assessor.assess_portfolio_risk(all_vulnerabilities, self.context)
            
            # Phase 6: Enhanced AI Analysis with Massive Knowledge Base
            print(f"\n{Fore.MAGENTA}Phase 6: Enhanced AI Analysis with Massive Knowledge Base{Style.RESET_ALL}")
            self.enhanced_results = self._run_enhanced_ai_analysis(all_vulnerabilities)
            
            # Phase 7: Nuclei Template Generation
            print(f"\n{Fore.MAGENTA}Phase 7: Nuclei Template Generation{Style.RESET_ALL}")
            template_dir = f"{self.results_dir}/nuclei-templates"
            generated_templates = self.template_generator.generate_nuclei_templates(all_vulnerabilities, template_dir)
            self.template_results = {
                'generated_templates': generated_templates,
                'template_directory': template_dir,
                'total_templates': len(generated_templates)
            }
            
            # Phase 8: Generate Reports
            print(f"\n{Fore.MAGENTA}Phase 8: Report Generation{Style.RESET_ALL}")
            final_report = self._generate_final_report(assessment_start_time)
            
            # Save all results
            self._save_all_results()
            
            # Validate generated templates
            validation_results = self.template_generator.validate_templates(template_dir)
            
            # Display summary
            self._display_assessment_summary()
            
            return final_report
            
        except Exception as e:
            error_msg = f"AI assessment failed: {str(e)}"
            print(f"{Fore.RED}Error: {error_msg}{Style.RESET_ALL}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            
            return {
                'status': 'error',
                'error': error_msg,
                'timestamp': time.time()
            }

    def run_quick_assessment(self, urls_list=None):
        """
        Run quick vulnerability detection and basic analysis
        """
        print(f"\n{Fore.CYAN}Zeus Quick AI Assessment{Style.RESET_ALL}")
        print(f"{Fore.BLUE}Target: {Fore.WHITE}{self.target_url}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*50}{Style.RESET_ALL}")
        
        # Quick vulnerability detection
        vulnerabilities = self.vulnerability_detector.start_detection(urls_list)
        
        if not vulnerabilities:
            print(f"{Fore.GREEN}No vulnerabilities detected{Style.RESET_ALL}")
            return {'vulnerabilities': [], 'status': 'clean'}
        
        # Basic risk assessment
        quick_risk = []
        for vuln in vulnerabilities:
            risk = self.risk_assessor.assess_vulnerability_risk(vuln, self.context)
            quick_risk.append({
                'type': vuln.get('type'),
                'url': vuln.get('url'),
                'severity': vuln.get('severity'),
                'risk_level': risk['risk_level'],
                'priority': risk['priority']
            })
        
        # Sort by priority
        quick_risk.sort(key=lambda x: x['priority'])
        
        print(f"\n{Fore.YELLOW}Quick Assessment Results:{Style.RESET_ALL}")
        for i, item in enumerate(quick_risk[:5], 1):  # Show top 5
            color = Fore.RED if item['risk_level'] == 'CRITICAL' else Fore.YELLOW if item['risk_level'] == 'HIGH' else Fore.GREEN
            print(f"{color}[{i}] {item['type']} - {item['risk_level']} Risk{Style.RESET_ALL}")
        
        return {
            'vulnerabilities': vulnerabilities,
            'risk_summary': quick_risk,
            'status': 'vulnerabilities_found'
        }

    def run_targeted_scan(self, scan_type, urls_list=None):
        """
        Run targeted scan for specific vulnerability types
        """
        print(f"\n{Fore.CYAN}Zeus Targeted AI Scan: {scan_type}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}Target: {Fore.WHITE}{self.target_url}{Style.RESET_ALL}")
        
        # Override detection methods based on scan type
        if scan_type.lower() == 'sql':
            vulnerabilities = []
            for url in (urls_list or [self.target_url]):
                sql_vulns = self.vulnerability_detector.detect_sql_injection(url)
                vulnerabilities.extend(sql_vulns)
        
        elif scan_type.lower() == 'xss':
            vulnerabilities = []
            for url in (urls_list or [self.target_url]):
                xss_vulns = self.vulnerability_detector.detect_xss(url)
                vulnerabilities.extend(xss_vulns)
        
        elif scan_type.lower() == 'lfi':
            vulnerabilities = []
            for url in (urls_list or [self.target_url]):
                lfi_vulns = self.vulnerability_detector.detect_lfi(url)
                vulnerabilities.extend(lfi_vulns)
        
        else:
            print(f"{Fore.RED}Unknown scan type: {scan_type}{Style.RESET_ALL}")
            return {'error': f'Unknown scan type: {scan_type}'}
        
        if vulnerabilities:
            # Generate PoCs for found vulnerabilities
            poc_results = self.poc_generator.generate_batch_poc(vulnerabilities)
            
            print(f"\n{Fore.GREEN}Found {len(vulnerabilities)} {scan_type.upper()} vulnerabilities{Style.RESET_ALL}")
            print(f"{Fore.BLUE}Generated {len(poc_results.get('individual_pocs', []))} PoCs{Style.RESET_ALL}")
            
            return {
                'scan_type': scan_type,
                'vulnerabilities': vulnerabilities,
                'poc_results': poc_results,
                'status': 'success'
            }
        else:
            print(f"{Fore.GREEN}No {scan_type.upper()} vulnerabilities found{Style.RESET_ALL}")
            return {
                'scan_type': scan_type,
                'vulnerabilities': [],
                'status': 'clean'
            }

    def _run_enhanced_ai_analysis(self, vulnerabilities):
        """
        Run enhanced AI analysis with massive knowledge base
        """
        enhanced_results = {
            'analyzed_vulnerabilities': [],
            'generated_nuclei_templates': [],
            'exploit_suggestions': [],
            'advanced_payloads': {},
            'bypass_techniques': {},
            'statistics': {}
        }
        
        print(f"{Fore.CYAN}[*] Running enhanced AI analysis with massive vulnerability database...{Style.RESET_ALL}")
        
        for i, vuln in enumerate(vulnerabilities):
            print(f"{Fore.YELLOW}[{i+1}/{len(vulnerabilities)}] Analyzing: {vuln.get('type', 'Unknown')} vulnerability{Style.RESET_ALL}")
            
            # Simulate response analysis (in real scenario, you'd have actual response data)
            mock_response = vuln.get('response', '') or vuln.get('description', '')
            mock_url = vuln.get('url', self.target_url)
            mock_payload = vuln.get('payload', '')
            
            # Run enhanced analysis
            analysis = self.enhanced_ai.analyze_response(mock_response, mock_url, mock_payload)
            
            if analysis['vulnerabilities_found']:
                enhanced_results['analyzed_vulnerabilities'].extend(analysis['vulnerabilities_found'])
                
                # Add Nuclei template if generated
                if analysis['nuclei_template']:
                    enhanced_results['generated_nuclei_templates'].append(analysis['nuclei_template'])
                    print(f"{Fore.GREEN}  [+] Generated Nuclei template: {analysis['nuclei_template']['id']}{Style.RESET_ALL}")
                
                # Add exploit suggestions
                enhanced_results['exploit_suggestions'].extend(analysis['exploit_suggestions'])
                
                # Collect advanced payloads by type
                for vuln_found in analysis['vulnerabilities_found']:
                    vuln_type = vuln_found['type']
                    if vuln_type not in enhanced_results['advanced_payloads']:
                        enhanced_results['advanced_payloads'][vuln_type] = []
                    enhanced_results['advanced_payloads'][vuln_type].extend(vuln_found.get('payloads', []))
                
                print(f"{Fore.GREEN}  [+] Found {len(analysis['vulnerabilities_found'])} enhanced vulnerability patterns{Style.RESET_ALL}")
                print(f"{Fore.GREEN}  [+] Confidence: {analysis['confidence_score']:.2f}, Severity: {analysis['severity']}{Style.RESET_ALL}")
                
                if analysis['exploit_suggestions']:
                    print(f"{Fore.MAGENTA}  [+] Generated {len(analysis['exploit_suggestions'])} exploit suggestions{Style.RESET_ALL}")
        
        # Export generated Nuclei templates
        if enhanced_results['generated_nuclei_templates']:
            template_file = f"{self.results_dir}/enhanced_nuclei_templates.yaml"
            self.enhanced_ai.export_nuclei_templates(template_file)
            print(f"{Fore.GREEN}[+] Exported {len(enhanced_results['generated_nuclei_templates'])} enhanced Nuclei templates to {template_file}{Style.RESET_ALL}")
        
        # Get final statistics
        enhanced_results['statistics'] = self.enhanced_ai.get_vulnerability_stats()
        
        # Export fetched payloads
        payload_dir = f"{self.results_dir}/fetched_payloads"
        try:
            self.enhanced_ai.payload_fetcher.export_to_files(payload_dir)
            print(f"{Fore.GREEN}[+] Exported fetched payloads to {payload_dir}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[-] Could not export fetched payloads: {e}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] Enhanced AI analysis completed!{Style.RESET_ALL}")
        print(f"    Total enhanced vulnerabilities found: {len(enhanced_results['analyzed_vulnerabilities'])}")
        print(f"    Nuclei templates generated: {len(enhanced_results['generated_nuclei_templates'])}")
        print(f"    Exploit suggestions: {len(enhanced_results['exploit_suggestions'])}")
        print(f"    Advanced payload types: {len(enhanced_results['advanced_payloads'])}")
        
        return enhanced_results

    def _generate_final_report(self, start_time):
        """
        Generate comprehensive final assessment report
        """
        assessment_duration = time.time() - start_time
        
        report = {
            'assessment_info': {
                'target': self.target_url,
                'assessment_id': os.path.basename(self.results_dir),
                'start_time': start_time,
                'end_time': time.time(),
                'duration_seconds': assessment_duration,
                'zeus_version': lib.core.settings.VERSION,
                'ai_engine_version': '1.0.0'
            },
            'executive_summary': self._generate_executive_summary(),
            'vulnerability_summary': self._generate_vulnerability_summary(),
            'risk_summary': self._generate_risk_summary(),
            'detailed_results': {
                'vulnerability_scan': self.scan_results,
                'ai_analysis': self.analysis_results,
                'poc_generation': self.poc_results,
                'risk_assessment': self.risk_results
            },
            'recommendations': self._generate_recommendations(),
            'next_steps': self._generate_next_steps()
        }
        
        return report

    def _generate_executive_summary(self):
        """
        Generate executive summary of the assessment
        """
        total_vulns = len(self.scan_results.get('vulnerabilities', []))
        
        if total_vulns == 0:
            return {
                'status': 'SECURE',
                'overall_risk': 'LOW',
                'key_findings': ['No significant vulnerabilities detected'],
                'immediate_actions': ['Continue regular security monitoring'],
                'business_impact': 'MINIMAL'
            }
        
        # Get risk distribution
        risk_dist = self.risk_results.get('risk_distribution', {})
        critical_count = risk_dist.get('critical', 0)
        high_count = risk_dist.get('high', 0)
        
        # Determine overall status
        if critical_count > 0:
            status = 'CRITICAL'
            overall_risk = 'CRITICAL'
        elif high_count > 0:
            status = 'HIGH_RISK'
            overall_risk = 'HIGH'
        elif risk_dist.get('medium', 0) > 0:
            status = 'MEDIUM_RISK'
            overall_risk = 'MEDIUM'
        else:
            status = 'LOW_RISK'
            overall_risk = 'LOW'
        
        # Key findings
        key_findings = []
        if critical_count > 0:
            key_findings.append(f'{critical_count} critical vulnerabilities require immediate attention')
        if high_count > 0:
            key_findings.append(f'{high_count} high-risk vulnerabilities identified')
        
        # Get top vulnerability types
        vuln_types = {}
        for vuln in self.scan_results.get('vulnerabilities', []):
            vtype = vuln.get('type', 'Unknown')
            vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
        
        top_types = sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:3]
        for vtype, count in top_types:
            key_findings.append(f'{count} {vtype} vulnerabilities detected')
        
        # Immediate actions
        immediate_actions = []
        if critical_count > 0:
            immediate_actions.append('Patch critical vulnerabilities within 4 hours')
        if high_count > 0:
            immediate_actions.append('Address high-risk vulnerabilities within 24 hours')
        
        # Add specific actions based on vulnerability types
        if any('SQL' in vuln.get('type', '') for vuln in self.scan_results.get('vulnerabilities', [])):
            immediate_actions.append('Deploy Web Application Firewall (WAF)')
        
        return {
            'status': status,
            'overall_risk': overall_risk,
            'total_vulnerabilities': total_vulns,
            'critical_vulnerabilities': critical_count,
            'high_risk_vulnerabilities': high_count,
            'key_findings': key_findings,
            'immediate_actions': immediate_actions,
            'business_impact': 'SEVERE' if critical_count > 2 else 'HIGH' if high_count > 3 else 'MODERATE'
        }

    def _generate_vulnerability_summary(self):
        """
        Generate vulnerability summary statistics
        """
        vulnerabilities = self.scan_results.get('vulnerabilities', [])
        
        # Count by type
        type_counts = {}
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for vuln in vulnerabilities:
            vtype = vuln.get('type', 'Unknown')
            type_counts[vtype] = type_counts.get(vtype, 0) + 1
            
            severity = vuln.get('severity', 'LOW')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'by_type': type_counts,
            'by_severity': severity_counts,
            'unique_urls_affected': len(set(v.get('url', '') for v in vulnerabilities)),
            'parameterized_vulnerabilities': len([v for v in vulnerabilities if v.get('parameter')]),
            'detection_coverage': {
                'sql_injection': len([v for v in vulnerabilities if 'SQL' in v.get('type', '')]),
                'xss': len([v for v in vulnerabilities if 'XSS' in v.get('type', '')]),
                'file_inclusion': len([v for v in vulnerabilities if 'File' in v.get('type', '')]),
                'information_disclosure': len([v for v in vulnerabilities if 'Information' in v.get('type', '')])
            }
        }

    def _generate_risk_summary(self):
        """
        Generate risk assessment summary
        """
        if not self.risk_results:
            return {'status': 'No risk assessment performed'}
        
        risk_metrics = self.risk_results.get('risk_metrics', {})
        risk_dist = self.risk_results.get('risk_distribution', {})
        
        return {
            'overall_risk_score': risk_metrics.get('average_risk_score', 0),
            'maximum_risk_score': risk_metrics.get('maximum_risk_score', 0),
            'risk_distribution': risk_dist,
            'top_priorities': [
                {
                    'vulnerability_type': item['vulnerability_type'],
                    'risk_level': item['risk_level'],
                    'priority': item['priority']
                }
                for item in self.risk_results.get('priority_queue', [])[:5]
            ],
            'remediation_timeline': self.risk_results.get('remediation_timeline', {}),
            'compliance_impact': self.risk_results.get('compliance_impact', {})
        }

    def _generate_recommendations(self):
        """
        Generate comprehensive recommendations
        """
        recommendations = {
            'immediate_actions': [],
            'short_term_actions': [],
            'long_term_actions': [],
            'security_controls': [],
            'monitoring_improvements': []
        }
        
        # Get AI analysis recommendations
        ai_recommendations = self.analysis_results.get('recommendations', [])
        
        for rec in ai_recommendations:
            if rec.get('priority') == 'CRITICAL':
                recommendations['immediate_actions'].extend(rec.get('remediation_steps', []))
            else:
                recommendations['short_term_actions'].extend(rec.get('remediation_steps', []))
        
        # Add general security improvements
        vulnerabilities = self.scan_results.get('vulnerabilities', [])
        
        if any('SQL' in v.get('type', '') for v in vulnerabilities):
            recommendations['security_controls'].extend([
                'Deploy Web Application Firewall (WAF)',
                'Implement database activity monitoring',
                'Enable query parameterization'
            ])
        
        if any('XSS' in v.get('type', '') for v in vulnerabilities):
            recommendations['security_controls'].extend([
                'Implement Content Security Policy (CSP)',
                'Enable XSS filtering',
                'Use secure coding practices'
            ])
        
        # Monitoring improvements
        recommendations['monitoring_improvements'].extend([
            'Implement continuous security monitoring',
            'Deploy intrusion detection system (IDS)',
            'Enable security event logging',
            'Regular vulnerability assessments'
        ])
        
        # Long-term actions
        recommendations['long_term_actions'].extend([
            'Implement Security Development Lifecycle (SDL)',
            'Regular security training for developers',
            'Establish bug bounty program',
            'Conduct regular penetration testing'
        ])
        
        return recommendations

    def _generate_next_steps(self):
        """
        Generate actionable next steps
        """
        next_steps = {
            'priority_1_immediate': [],
            'priority_2_short_term': [],
            'priority_3_long_term': []
        }
        
        # Immediate steps based on critical findings
        critical_count = self.risk_results.get('risk_distribution', {}).get('critical', 0)
        high_count = self.risk_results.get('risk_distribution', {}).get('high', 0)
        
        if critical_count > 0:
            next_steps['priority_1_immediate'].extend([
                f'Address {critical_count} critical vulnerabilities within 4 hours',
                'Activate incident response procedures',
                'Notify stakeholders of security findings',
                'Implement immediate compensating controls'
            ])
        
        if high_count > 0:
            next_steps['priority_2_short_term'].extend([
                f'Remediate {high_count} high-risk vulnerabilities within 24 hours',
                'Review and update security policies',
                'Conduct impact analysis',
                'Plan security control improvements'
            ])
        
        # Long-term improvements
        next_steps['priority_3_long_term'].extend([
            'Schedule follow-up security assessment in 90 days',
            'Implement continuous security monitoring',
            'Establish regular security review process',
            'Plan security architecture improvements'
        ])
        
        return next_steps

    def _save_all_results(self):
        """
        Save all assessment results to files
        """
        try:
            # Save individual component results
            with open(f"{self.results_dir}/vulnerability_scan.json", 'w') as f:
                json.dump(self.scan_results, f, indent=2, default=str)
            
            with open(f"{self.results_dir}/ai_analysis.json", 'w') as f:
                json.dump(self.analysis_results, f, indent=2, default=str)
            
            with open(f"{self.results_dir}/poc_generation.json", 'w') as f:
                json.dump(self.poc_results, f, indent=2, default=str)
            
            with open(f"{self.results_dir}/risk_assessment.json", 'w') as f:
                json.dump(self.risk_results, f, indent=2, default=str)
            
            # Save enhanced AI results
            if hasattr(self, 'enhanced_results') and self.enhanced_results:
                with open(f"{self.results_dir}/enhanced_ai_analysis.json", 'w') as f:
                    json.dump(self.enhanced_results, f, indent=2, default=str)
            
            with open(f"{self.results_dir}/cve_detection.json", 'w') as f:
                json.dump(self.cve_results, f, indent=2, default=str)
            
            with open(f"{self.results_dir}/template_generation.json", 'w') as f:
                json.dump(self.template_results, f, indent=2, default=str)
            
            # Generate and save final report
            final_report = self._generate_final_report(time.time())
            with open(f"{self.results_dir}/final_assessment_report.json", 'w') as f:
                json.dump(final_report, f, indent=2, default=str)
            
            # Generate human-readable summary
            self._generate_html_report(final_report)
            
            print(f"{Fore.GREEN}Results saved to: {self.results_dir}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}Error saving results: {e}{Style.RESET_ALL}")

    def _generate_html_report(self, report):
        """
        Generate HTML report for better readability
        """
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Zeus AI Security Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; }}
                .summary {{ background-color: #ecf0f1; padding: 15px; margin: 10px 0; }}
                .critical {{ background-color: #e74c3c; color: white; padding: 10px; }}
                .high {{ background-color: #f39c12; color: white; padding: 10px; }}
                .medium {{ background-color: #f1c40f; padding: 10px; }}
                .low {{ background-color: #2ecc71; color: white; padding: 10px; }}
                .section {{ margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #34495e; color: white; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Zeus AI Security Assessment Report</h1>
                <p>Target: {report['assessment_info']['target']}</p>
                <p>Assessment ID: {report['assessment_info']['assessment_id']}</p>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Status:</strong> {report['executive_summary']['status']}</p>
                <p><strong>Overall Risk:</strong> {report['executive_summary']['overall_risk']}</p>
                <p><strong>Total Vulnerabilities:</strong> {report['executive_summary']['total_vulnerabilities']}</p>
            </div>
            
            <div class="section">
                <h2>Vulnerability Summary</h2>
                <table>
                    <tr><th>Severity</th><th>Count</th></tr>
                    <tr><td>Critical</td><td>{report['executive_summary'].get('critical_vulnerabilities', 0)}</td></tr>
                    <tr><td>High</td><td>{report['executive_summary'].get('high_risk_vulnerabilities', 0)}</td></tr>
                </table>
            </div>
            
            <div class="section">
                <h2>Key Findings</h2>
                <ul>
        """
        
        for finding in report['executive_summary'].get('key_findings', []):
            html_content += f"<li>{finding}</li>"
        
        html_content += """
                </ul>
            </div>
            
            <div class="section">
                <h2>Immediate Actions Required</h2>
                <ul>
        """
        
        for action in report['executive_summary'].get('immediate_actions', []):
            html_content += f"<li>{action}</li>"
        
        html_content += """
                </ul>
            </div>
        </body>
        </html>
        """
        
        with open(f"{self.results_dir}/assessment_report.html", 'w') as f:
            f.write(html_content)

    def _display_assessment_summary(self):
        """
        Display assessment summary in terminal
        """
        print(f"\n{Fore.CYAN}{Style.BRIGHT}Assessment Complete!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
        
        # Display key metrics
        total_vulns = len(self.scan_results.get('vulnerabilities', []))
        risk_dist = self.risk_results.get('risk_distribution', {})
        
        print(f"{Fore.BLUE}Summary:{Style.RESET_ALL}")
        print(f"  Total Vulnerabilities: {total_vulns}")
        print(f"  Critical Risk: {risk_dist.get('critical', 0)}")
        print(f"  High Risk: {risk_dist.get('high', 0)}")
        print(f"  Medium Risk: {risk_dist.get('medium', 0)}")
        print(f"  Low Risk: {risk_dist.get('low', 0)}")
        
        print(f"\n{Fore.BLUE}Files Generated:{Style.RESET_ALL}")
        print(f"    final_assessment_report.json")
        print(f"    vulnerability_scan.json")
        print(f"   ai_analysis.json")
        print(f"    poc_generation.json")
        print(f"     risk_assessment.json")
        print(f"     cve_detection.json")
        print(f"    template_generation.json")
        print(f"    assessment_report.html")
        if self.template_results.get('total_templates', 0) > 0:
            print(f"    nuclei-templates/ ({self.template_results['total_templates']} templates)")
        
        print(f"\n{Fore.GREEN}Results Directory: {self.results_dir}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")

    def get_assessment_status(self):
        """
        Get current assessment status
        """
        return {
            'target': self.target_url,
            'results_dir': self.results_dir,
            'components_completed': {
                'vulnerability_detection': bool(self.scan_results),
                'ai_analysis': bool(self.analysis_results),
                'poc_generation': bool(self.poc_results),
                'risk_assessment': bool(self.risk_results)
            },
            'total_vulnerabilities': len(self.scan_results.get('vulnerabilities', [])),
            'assessment_complete': all([
                self.scan_results, self.analysis_results,
                self.poc_results, self.risk_results
            ])
        }
