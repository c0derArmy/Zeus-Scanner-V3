#!/usr/bin/env python3

import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from lib.core.settings import logger, set_color

class EnhancedAIOrchestrator:
    """
    Enhanced AI Orchestrator for Zeus Scanner
    Coordinates AI analysis with ZAP, Burp Suite, and Metasploit integrations
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.zap_integration = None
        self.burp_integration = None
        self.msf_integration = None
        self.ai_engine = None
        self.results = {
            'scan_id': f"zeus_ai_{int(time.time())}",
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'target': None,
            'phases': {},
            'vulnerabilities': [],
            'exploits': [],
            'recommendations': []
        }
    
    def initialize_integrations(self, target: str):
        """Initialize all security tool integrations"""
        try:
            logger.info(set_color("Initializing security tool integrations...", level=35))
            
            # Initialize ZAP Integration
            if self.config.get('use_zap', True):
                try:
                    from .zap_integration import ZAPIntegration
                    self.zap_integration = ZAPIntegration(
                        zap_host=self.config.get('zap_host', '127.0.0.1'),
                        zap_port=self.config.get('zap_port', 8080),
                        api_key=self.config.get('zap_api_key')
                    )
                    if not self.zap_integration.check_zap_status():
                        self.zap_integration.start_zap_daemon()
                    logger.info(set_color("ZAP integration initialized", level=35))
                except Exception as e:
                    logger.warning(set_color(f"ZAP integration failed: {str(e)}", level=33))
                    self.zap_integration = None
            
            # Initialize Burp Integration
            if self.config.get('use_burp', False):
                try:
                    from .burp_integration import BurpIntegration
                    self.burp_integration = BurpIntegration(
                        burp_host=self.config.get('burp_host', '127.0.0.1'),
                        burp_port=self.config.get('burp_port', 1337),
                        api_key=self.config.get('burp_api_key')
                    )
                    if not self.burp_integration.check_burp_status():
                        self.burp_integration.start_burp_suite()
                    logger.info(set_color("Burp Suite integration initialized", level=35))
                except Exception as e:
                    logger.warning(set_color(f"Burp integration failed: {str(e)}", level=33))
                    self.burp_integration = None
            
            # Initialize Metasploit Integration
            if self.config.get('use_metasploit', False):
                try:
                    from .metasploit_integration import MetasploitIntegration
                    self.msf_integration = MetasploitIntegration(
                        msf_host=self.config.get('msf_host', '127.0.0.1'),
                        msf_port=self.config.get('msf_port', 55553),
                        username=self.config.get('msf_username', 'msf'),
                        password=self.config.get('msf_password', 'msf')
                    )
                    if not self.msf_integration.connect_rpc():
                        self.msf_integration.start_msf_rpc()
                        self.msf_integration.connect_rpc()
                    self.msf_integration.create_workspace()
                    logger.info(set_color("Metasploit integration initialized", level=35))
                except Exception as e:
                    logger.warning(set_color(f"Metasploit integration failed: {str(e)}", level=33))
                    self.msf_integration = None
            
            # Initialize AI Engine
            try:
                from lib.ai_engine.enhanced_ai_engine import EnhancedAIEngine
                self.ai_engine = EnhancedAIEngine()
                logger.info(set_color("Enhanced AI Engine initialized", level=35))
            except Exception as e:
                logger.warning(set_color(f"AI Engine initialization failed: {str(e)}", level=33))
                self.ai_engine = None
            
            self.results['target'] = target
            return True
            
        except Exception as e:
            logger.error(set_color(f"Integration initialization failed: {str(e)}", level=40))
            return False
    
    def phase_1_reconnaissance(self, target: str) -> Dict:
        """Phase 1: Comprehensive reconnaissance using all tools"""
        logger.info(set_color("=== PHASE 1: AI-POWERED RECONNAISSANCE ===", level=35))
        
        phase_results = {
            'phase': 'reconnaissance',
            'start_time': time.time(),
            'zap_spider': {},
            'burp_crawl': {},
            'ai_analysis': {},
            'discovered_urls': [],
            'technologies': [],
            'attack_surface': {}
        }
        
        tasks = []
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            # ZAP Spider
            if self.zap_integration:
                tasks.append(executor.submit(self._zap_reconnaissance, target))
            
            # Burp Crawling
            if self.burp_integration:
                tasks.append(executor.submit(self._burp_reconnaissance, target))
            
            # AI-powered reconnaissance
            if self.ai_engine:
                tasks.append(executor.submit(self._ai_reconnaissance, target))
            
            # Collect results
            for future in as_completed(tasks):
                try:
                    result = future.result()
                    phase_results.update(result)
                except Exception as e:
                    logger.error(set_color(f"Reconnaissance task failed: {str(e)}", level=40))
        
        # Merge and analyze reconnaissance data
        self._merge_reconnaissance_data(phase_results)
        
        phase_results['end_time'] = time.time()
        phase_results['duration'] = phase_results['end_time'] - phase_results['start_time']
        
        self.results['phases']['reconnaissance'] = phase_results
        
        logger.info(set_color(f"Phase 1 completed - Discovered {len(phase_results['discovered_urls'])} URLs", level=35))
        return phase_results
    
    def phase_2_vulnerability_discovery(self, target: str, discovered_urls: List[str]) -> Dict:
        """Phase 2: AI-guided vulnerability discovery"""
        logger.info(set_color("=== PHASE 2: AI-GUIDED VULNERABILITY DISCOVERY ===", level=35))
        
        phase_results = {
            'phase': 'vulnerability_discovery',
            'start_time': time.time(),
            'zap_scan': {},
            'burp_scan': {},
            'ai_vulnerability_analysis': {},
            'cve_analysis': {},
            'vulnerabilities': [],
            'risk_assessment': {}
        }
        
        tasks = []
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            # ZAP Active Scan
            if self.zap_integration:
                tasks.append(executor.submit(self._zap_vulnerability_scan, target))
            
            # Burp Active Scan
            if self.burp_integration:
                tasks.append(executor.submit(self._burp_vulnerability_scan, target))
            
            # AI Vulnerability Analysis
            if self.ai_engine:
                tasks.append(executor.submit(self._ai_vulnerability_analysis, target, discovered_urls))
            
            # CVE Analysis
            if self.ai_engine:
                tasks.append(executor.submit(self._ai_cve_analysis, target))
            
            # Collect results
            for future in as_completed(tasks):
                try:
                    result = future.result()
                    phase_results.update(result)
                except Exception as e:
                    logger.error(set_color(f"Vulnerability discovery task failed: {str(e)}", level=40))
        
        # AI-powered vulnerability correlation and risk assessment
        if self.ai_engine:
            phase_results['risk_assessment'] = self._ai_risk_assessment(phase_results['vulnerabilities'])
        
        phase_results['end_time'] = time.time()
        phase_results['duration'] = phase_results['end_time'] - phase_results['start_time']
        
        self.results['phases']['vulnerability_discovery'] = phase_results
        
        logger.info(set_color(f"Phase 2 completed - Found {len(phase_results['vulnerabilities'])} vulnerabilities", level=35))
        return phase_results
    
    def phase_3_exploitation_validation(self, target: str, vulnerabilities: List[Dict]) -> Dict:
        """Phase 3: AI-guided exploitation and validation"""
        logger.info(set_color("=== PHASE 3: AI-GUIDED EXPLOITATION VALIDATION ===", level=35))
        
        phase_results = {
            'phase': 'exploitation_validation',
            'start_time': time.time(),
            'metasploit_exploitation': {},
            'ai_exploit_generation': {},
            'poc_generation': {},
            'successful_exploits': [],
            'sessions': [],
            'impact_analysis': {}
        }
        
        # Only proceed if Metasploit is available and exploitation is enabled
        if self.msf_integration and self.config.get('enable_exploitation', False):
            
            # Filter high-risk vulnerabilities for exploitation
            high_risk_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() in ['high', 'critical']]
            
            if high_risk_vulns:
                logger.info(set_color(f"Attempting exploitation of {len(high_risk_vulns)} high-risk vulnerabilities", level=35))
                
                # Metasploit exploitation
                msf_results = self.msf_integration.comprehensive_exploitation(target, high_risk_vulns)
                phase_results['metasploit_exploitation'] = msf_results
                
                # Check for successful sessions
                sessions = self.msf_integration.get_sessions()
                phase_results['sessions'] = sessions
                
                if sessions:
                    logger.info(set_color(f"Exploitation successful - {len(sessions)} active sessions", level=35))
        
        # AI-powered exploit generation and PoC creation
        if self.ai_engine:
            for vuln in vulnerabilities[:10]:  # Limit to top 10 vulnerabilities
                try:
                    # Generate proof-of-concept
                    poc_result = self.ai_engine.generate_poc(vuln, target)
                    if poc_result:
                        phase_results.setdefault('poc_generation', []).append(poc_result)
                    
                    # AI exploit analysis
                    exploit_analysis = self.ai_engine.analyze_exploit_potential(vuln, target)
                    if exploit_analysis:
                        phase_results.setdefault('ai_exploit_generation', []).append(exploit_analysis)
                        
                except Exception as e:
                    logger.debug(set_color(f"AI exploit analysis failed for vulnerability: {str(e)}", level=33))
        
        # Impact analysis
        if self.ai_engine and phase_results.get('successful_exploits'):
            phase_results['impact_analysis'] = self.ai_engine.assess_exploitation_impact(
                phase_results['successful_exploits'], 
                target
            )
        
        phase_results['end_time'] = time.time()
        phase_results['duration'] = phase_results['end_time'] - phase_results['start_time']
        
        self.results['phases']['exploitation_validation'] = phase_results
        
        logger.info(set_color(f"Phase 3 completed - {len(phase_results.get('successful_exploits', []))} successful exploits", level=35))
        return phase_results
    
    def phase_4_reporting_recommendations(self) -> Dict:
        """Phase 4: AI-powered reporting and recommendations"""
        logger.info(set_color("=== PHASE 4: AI-POWERED REPORTING ===", level=35))
        
        phase_results = {
            'phase': 'reporting',
            'start_time': time.time(),
            'comprehensive_report': {},
            'risk_matrix': {},
            'remediation_plan': {},
            'executive_summary': {},
            'technical_details': {}
        }
        
        if self.ai_engine:
            try:
                # Generate comprehensive AI report
                all_vulnerabilities = []
                for phase in self.results['phases'].values():
                    all_vulnerabilities.extend(phase.get('vulnerabilities', []))
                
                # AI-powered report generation
                phase_results['comprehensive_report'] = self.ai_engine.generate_comprehensive_report(
                    self.results['target'],
                    all_vulnerabilities,
                    self.results['phases']
                )
                
                # Generate risk matrix
                phase_results['risk_matrix'] = self.ai_engine.generate_risk_matrix(all_vulnerabilities)
                
                # Generate remediation plan
                phase_results['remediation_plan'] = self.ai_engine.generate_remediation_plan(all_vulnerabilities)
                
                # Executive summary
                phase_results['executive_summary'] = self.ai_engine.generate_executive_summary(
                    self.results['target'],
                    all_vulnerabilities,
                    phase_results['risk_matrix']
                )
                
            except Exception as e:
                logger.error(set_color(f"AI reporting failed: {str(e)}", level=40))
        
        phase_results['end_time'] = time.time()
        phase_results['duration'] = phase_results['end_time'] - phase_results['start_time']
        
        self.results['phases']['reporting'] = phase_results
        
        logger.info(set_color("Phase 4 completed - Comprehensive report generated", level=35))
        return phase_results
    
    def comprehensive_ai_assessment(self, target: str, assessment_config: Dict = None) -> Dict:
        """Run comprehensive AI-powered security assessment"""
        try:
            logger.info(set_color(f"Starting comprehensive AI assessment of {target}", level=35))
            
            # Initialize integrations
            if not self.initialize_integrations(target):
                return {'error': 'Failed to initialize integrations'}
            
            # Phase 1: Reconnaissance
            recon_results = self.phase_1_reconnaissance(target)
            discovered_urls = recon_results.get('discovered_urls', [])
            
            # Phase 2: Vulnerability Discovery
            vuln_results = self.phase_2_vulnerability_discovery(target, discovered_urls)
            vulnerabilities = vuln_results.get('vulnerabilities', [])
            
            # Phase 3: Exploitation Validation (if enabled)
            if self.config.get('enable_exploitation', False):
                exploit_results = self.phase_3_exploitation_validation(target, vulnerabilities)
            
            # Phase 4: Reporting and Recommendations
            report_results = self.phase_4_reporting_recommendations()
            
            # Final results compilation
            self.results['total_vulnerabilities'] = len(vulnerabilities)
            self.results['assessment_duration'] = time.time() - self.results.get('start_time', time.time())
            self.results['status'] = 'completed'
            
            logger.info(set_color(f"Comprehensive AI assessment completed - Found {len(vulnerabilities)} vulnerabilities", level=35))
            
            return self.results
            
        except Exception as e:
            logger.error(set_color(f"Comprehensive assessment failed: {str(e)}", level=40))
            self.results['status'] = 'failed'
            self.results['error'] = str(e)
            return self.results
        
        finally:
            # Cleanup integrations
            self._cleanup_integrations()
    
    # Helper methods for individual tool operations
    def _zap_reconnaissance(self, target: str) -> Dict:
        """ZAP reconnaissance tasks"""
        try:
            results = self.zap_integration.comprehensive_scan(target, include_ajax=True)
            
            urls = []
            if 'spider_results' in results:
                urls.extend(results['spider_results'].get('urls', []))
            if 'ajax_spider_results' in results:
                urls.extend(results['ajax_spider_results'].get('urls', []))
            
            return {
                'zap_spider': results,
                'discovered_urls': list(set(urls))
            }
        except Exception as e:
            logger.error(set_color(f"ZAP reconnaissance failed: {str(e)}", level=40))
            return {'zap_spider': {'error': str(e)}}
    
    def _burp_reconnaissance(self, target: str) -> Dict:
        """Burp reconnaissance tasks"""
        try:
            results = self.burp_integration.start_crawl(target)
            urls = [item.get('url', '') for item in results.get('items', [])]
            
            return {
                'burp_crawl': results,
                'discovered_urls': urls
            }
        except Exception as e:
            logger.error(set_color(f"Burp reconnaissance failed: {str(e)}", level=40))
            return {'burp_crawl': {'error': str(e)}}
    
    def _ai_reconnaissance(self, target: str) -> Dict:
        """AI-powered reconnaissance"""
        try:
            if self.ai_engine:
                analysis = self.ai_engine.analyze_target(target)
                return {'ai_analysis': analysis}
            return {}
        except Exception as e:
            logger.error(set_color(f"AI reconnaissance failed: {str(e)}", level=40))
            return {'ai_analysis': {'error': str(e)}}
    
    def _zap_vulnerability_scan(self, target: str) -> Dict:
        """ZAP vulnerability scanning"""
        try:
            results = self.zap_integration.active_scan(target)
            vulnerabilities = self._convert_zap_alerts_to_vulnerabilities(results.get('alerts', []))
            
            return {
                'zap_scan': results,
                'vulnerabilities': vulnerabilities
            }
        except Exception as e:
            logger.error(set_color(f"ZAP vulnerability scan failed: {str(e)}", level=40))
            return {'zap_scan': {'error': str(e)}}
    
    def _burp_vulnerability_scan(self, target: str) -> Dict:
        """Burp vulnerability scanning"""
        try:
            results = self.burp_integration.start_scan(target)
            vulnerabilities = self._convert_burp_issues_to_vulnerabilities(results.get('issues', []))
            
            return {
                'burp_scan': results,
                'vulnerabilities': vulnerabilities
            }
        except Exception as e:
            logger.error(set_color(f"Burp vulnerability scan failed: {str(e)}", level=40))
            return {'burp_scan': {'error': str(e)}}
    
    def _ai_vulnerability_analysis(self, target: str, urls: List[str]) -> Dict:
        """AI vulnerability analysis"""
        try:
            if self.ai_engine:
                analysis = self.ai_engine.comprehensive_vulnerability_analysis(target, urls)
                return {'ai_vulnerability_analysis': analysis}
            return {}
        except Exception as e:
            logger.error(set_color(f"AI vulnerability analysis failed: {str(e)}", level=40))
            return {'ai_vulnerability_analysis': {'error': str(e)}}
    
    def _ai_cve_analysis(self, target: str) -> Dict:
        """AI CVE analysis"""
        try:
            if self.ai_engine:
                cve_analysis = self.ai_engine.cve_detection_scan(target)
                return {'cve_analysis': cve_analysis}
            return {}
        except Exception as e:
            logger.error(set_color(f"AI CVE analysis failed: {str(e)}", level=40))
            return {'cve_analysis': {'error': str(e)}}
    
    def _ai_risk_assessment(self, vulnerabilities: List[Dict]) -> Dict:
        """AI risk assessment"""
        try:
            if self.ai_engine and vulnerabilities:
                return self.ai_engine.comprehensive_risk_assessment(vulnerabilities)
            return {}
        except Exception as e:
            logger.error(set_color(f"AI risk assessment failed: {str(e)}", level=40))
            return {'error': str(e)}
    
    def _merge_reconnaissance_data(self, phase_results: Dict):
        """Merge reconnaissance data from all sources"""
        all_urls = set()
        
        # Collect URLs from all sources
        for key in ['discovered_urls']:
            if key in phase_results:
                all_urls.update(phase_results[key])
        
        # Additional URL extraction from tool-specific results
        if 'zap_spider' in phase_results:
            zap_urls = phase_results['zap_spider'].get('spider_results', {}).get('urls', [])
            all_urls.update(zap_urls)
        
        phase_results['discovered_urls'] = list(all_urls)
    
    def _convert_zap_alerts_to_vulnerabilities(self, alerts: List[Dict]) -> List[Dict]:
        """Convert ZAP alerts to standardized vulnerability format"""
        vulnerabilities = []
        
        for alert in alerts:
            vuln = {
                'source': 'zap',
                'name': alert.get('alert', ''),
                'description': alert.get('description', ''),
                'severity': alert.get('risk', '').lower(),
                'confidence': alert.get('confidence', ''),
                'url': alert.get('url', ''),
                'parameter': alert.get('param', ''),
                'evidence': alert.get('evidence', ''),
                'solution': alert.get('solution', ''),
                'reference': alert.get('reference', ''),
                'cwe_id': alert.get('cweid', ''),
                'wasc_id': alert.get('wascid', '')
            }
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _convert_burp_issues_to_vulnerabilities(self, issues: List[Dict]) -> List[Dict]:
        """Convert Burp issues to standardized vulnerability format"""
        vulnerabilities = []
        
        for issue in issues:
            vuln = {
                'source': 'burp',
                'name': issue.get('issue_name', ''),
                'description': issue.get('issue_description', ''),
                'severity': issue.get('severity', '').lower(),
                'confidence': issue.get('confidence', ''),
                'url': issue.get('url', ''),
                'evidence': issue.get('evidence', ''),
                'remediation': issue.get('remediation', ''),
                'issue_type': issue.get('type_index', '')
            }
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _cleanup_integrations(self):
        """Cleanup all integrations"""
        try:
            if self.zap_integration:
                self.zap_integration.shutdown_zap()
            
            if self.burp_integration:
                self.burp_integration.shutdown_burp()
            
            if self.msf_integration:
                self.msf_integration.shutdown_msf()
                
        except Exception as e:
            logger.warning(set_color(f"Cleanup warning: {str(e)}", level=33))
    
    def export_results(self, output_file: str = None, format: str = 'json') -> str:
        """Export comprehensive results"""
        try:
            output_file = output_file or f"zeus_ai_assessment_{int(time.time())}.{format}"
            
            if format.lower() == 'json':
                with open(output_file, 'w') as f:
                    json.dump(self.results, f, indent=2, default=str)
            elif format.lower() == 'html':
                html_report = self._generate_html_report()
                with open(output_file, 'w') as f:
                    f.write(html_report)
            
            logger.info(set_color(f"Results exported to: {output_file}", level=35))
            return output_file
            
        except Exception as e:
            logger.error(set_color(f"Export failed: {str(e)}", level=40))
            return None
    
    def _generate_html_report(self) -> str:
        """Generate HTML report from results"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Zeus Scanner - AI Assessment Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background: #2c3e50; color: white; padding: 20px; }
                .section { margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; }
                .vulnerability { background: #f8f9fa; margin: 10px 0; padding: 10px; border-radius: 5px; }
                .high-severity { border-left: 4px solid #e74c3c; }
                .medium-severity { border-left: 4px solid #f39c12; }
                .low-severity { border-left: 4px solid #f1c40f; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Zeus Scanner - AI-Powered Assessment Report</h1>
                <p>Target: {target}</p>
                <p>Scan Date: {timestamp}</p>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <p>Total Vulnerabilities Found: {total_vulnerabilities}</p>
                <p>Assessment Duration: {duration} seconds</p>
            </div>
            
            <div class="section">
                <h2>Vulnerabilities</h2>
                {vulnerabilities_html}
            </div>
        </body>
        </html>
        """
        
        # Generate vulnerabilities HTML
        vulnerabilities_html = ""
        all_vulnerabilities = []
        
        for phase in self.results.get('phases', {}).values():
            all_vulnerabilities.extend(phase.get('vulnerabilities', []))
        
        for vuln in all_vulnerabilities:
            severity = vuln.get('severity', 'low')
            vulnerabilities_html += f"""
                <div class="vulnerability {severity}-severity">
                    <h3>{vuln.get('name', 'Unknown')}</h3>
                    <p><strong>Severity:</strong> {severity.upper()}</p>
                    <p><strong>URL:</strong> {vuln.get('url', 'N/A')}</p>
                    <p><strong>Description:</strong> {vuln.get('description', 'N/A')}</p>
                </div>
            """
        
        return html_template.format(
            target=self.results.get('target', 'Unknown'),
            timestamp=self.results.get('timestamp', 'Unknown'),
            total_vulnerabilities=len(all_vulnerabilities),
            duration=self.results.get('assessment_duration', 0),
            vulnerabilities_html=vulnerabilities_html
        )