"""
MCP Server - Model Context Protocol for Zeus-Scanner
Implements Web Application Penetration Testing Phases:
1. Reconnaissance
2. Scanning & Enumeration
3. Vulnerability Assessment
4. Exploitation
5. Post-Exploitation
6. Reporting
"""

import json
import asyncio
import subprocess
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
import threading
import os
from datetime import datetime

from lib.core.settings import logger, set_color


class Phase(Enum):
    RECON = "1. Reconnaissance"
    SCANNING = "2. Scanning & Enumeration"
    VULN_ASSESSMENT = "3. Vulnerability Assessment"
    EXPLOITATION = "4. Exploitation"
    POST_EXPLOIT = "5. Post-Exploitation"
    REPORTING = "6. Reporting"


@dataclass
class PhaseResult:
    phase: str
    success: bool
    findings: List[Dict]
    summary: str
    execution_time: float
    errors: List[str] = None


@dataclass
class PentestReport:
    target: str
    start_time: str
    end_time: str = ""
    phases: Dict[str, PhaseResult] = None
    total_findings: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0
    medium_vulns: int = 0
    low_vulns: int = 0
    recommendations: List[str] = None

    def __post_init__(self):
        if self.phases is None:
            self.phases = {}
        if self.recommendations is None:
            self.recommendations = []

    def to_dict(self) -> Dict:
        return {
            'target': self.target,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'phases': {k: asdict(v) for k, v in self.phases.items()},
            'total_findings': self.total_findings,
            'critical_vulns': self.critical_vulns,
            'high_vulns': self.high_vulns,
            'medium_vulns': self.medium_vulns,
            'low_vulns': self.low_vulns,
            'recommendations': self.recommendations
        }


class MCPServer:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.executor = ThreadPoolExecutor(max_workers=10)
        self.report = None

    async def execute_phase(self, phase: Phase, target: str, context: Dict = None) -> PhaseResult:
        import time
        start = time.time()
        errors = []

        logger.info(set_color(f"\n{'='*60}", level=25))
        logger.info(set_color(f"{phase.value}", level=25))
        logger.info(set_color(f"{'='*60}", level=25))

        findings = []

        try:
            if phase == Phase.RECON:
                findings = await self._phase_reconnaissance(target, context or {})
            elif phase == Phase.SCANNING:
                findings = await self._phase_scanning(target, context or {})
            elif phase == Phase.VULN_ASSESSMENT:
                findings = await self._phase_vulnerability_assessment(target, context or {})
            elif phase == Phase.EXPLOITATION:
                findings = await self._phase_exploitation(target, context or {})
            elif phase == Phase.POST_EXPLOIT:
                findings = await self._phase_post_exploitation(target, context or {})
            elif phase == Phase.REPORTING:
                findings = await self._phase_reporting(target, context or {})

        except Exception as e:
            errors.append(str(e))
            logger.error(set_color(f"Phase error: {str(e)}", level=40))

        execution_time = time.time() - start

        return PhaseResult(
            phase=phase.value,
            success=len(errors) == 0,
            findings=findings,
            summary=f"Found {len(findings)} items",
            execution_time=execution_time,
            errors=errors
        )

    async def _phase_reconnaissance(self, target: str, context: Dict) -> List[Dict]:
        """Phase 1: Information Gathering"""
        findings = []

        logger.info(set_color("[*] Starting Reconnaissance...", level=25))

        waf_result = await self._run_tool('waf_detect', target, {})
        if waf_result.get('success'):
            findings.append({
                'type': 'waf_detection',
                'data': waf_result.get('data', {})
            })

        header_result = await self._run_tool('header_check', target, {})
        if header_result.get('success'):
            findings.append({
                'type': 'header_analysis',
                'data': header_result.get('data', {})
            })

        technology_result = self._identify_technologies(target)
        if technology_result:
            findings.append({
                'type': 'technology_stack',
                'data': technology_result
            })
            context['technologies'] = technology_result.get('technologies', [])

        crawler_result = await self._run_tool('crawler', target, {'depth': 2})
        if crawler_result.get('success'):
            findings.append({
                'type': 'crawling_results',
                'data': crawler_result.get('data', {})
            })

        logger.info(set_color(f"[+] Reconnaissance complete: {len(findings)} findings", level=25))
        return findings

    async def _phase_scanning(self, target: str, context: Dict) -> List[Dict]:
        """Phase 2: Scanning & Enumeration"""
        findings = []

        logger.info(set_color("[*] Starting Scanning & Enumeration...", level=25))

        nmap_result = await self._run_tool('nmap', target, {})
        if nmap_result.get('success'):
            findings.append({
                'type': 'port_scan',
                'data': nmap_result.get('data', {})
            })

        nuclei_result = await self._run_tool('nuclei', target, {'severity': 'info,low,medium,high,critical'})
        if nuclei_result.get('success'):
            nuclei_data = nuclei_result.get('data', {})
            if 'vulnerabilities' in nuclei_data:
                findings.append({
                    'type': 'vulnerability_scan',
                    'data': nuclei_data['vulnerabilities']
                })

        admin_result = await self._run_tool('admin_panel', target, {})
        if admin_result.get('success'):
            findings.append({
                'type': 'admin_panels',
                'data': admin_result.get('data', {})
            })

        logger.info(set_color(f"[+] Scanning complete: {len(findings)} findings", level=25))
        return findings

    async def _phase_vulnerability_assessment(self, target: str, context: Dict) -> List[Dict]:
        """Phase 3: Vulnerability Assessment"""
        findings = []

        logger.info(set_color("[*] Starting Vulnerability Assessment...", level=25))

        xsstrike_result = await self._run_tool('xsstrike', target, {'mode': 'crawl'})
        if xsstrike_result.get('success'):
            xs_data = xsstrike_result.get('data', {})
            if xs_data.get('vulnerabilities'):
                findings.append({
                    'type': 'xss_vulnerabilities',
                    'severity': 'high',
                    'data': xs_data['vulnerabilities']
                })
            if xs_data.get('cves'):
                for cve in xs_data['cves']:
                    cve_result = await self._run_tool('sploitscan', target, {'cve_id': cve.get('cve_id')})
                    if cve_result.get('success'):
                        findings.append({
                            'type': 'cve_details',
                            'data': cve_result.get('data', {})
                        })

        sqlmap_result = await self._run_tool('sqlmap', target, {'auto_start': False})
        if sqlmap_result.get('success'):
            findings.append({
                'type': 'sqli_scan',
                'severity': 'critical',
                'data': sqlmap_result.get('data', {})
            })

        techs = context.get('technologies', [])
        for tech in techs:
            related_cves = self._search_tech_cves(tech)
            if related_cves:
                findings.append({
                    'type': 'technology_cves',
                    'technology': tech,
                    'data': related_cves
                })

        logger.info(set_color(f"[+] Vulnerability Assessment complete: {len(findings)} findings", level=25))
        return findings

    async def _phase_exploitation(self, target: str, context: Dict) -> List[Dict]:
        """Phase 4: Exploitation"""
        findings = []

        logger.info(set_color("[*] Starting Exploitation Phase...", level=25))

        vuln_findings = context.get('vulnerability_findings', [])

        for vuln in vuln_findings:
            vuln_type = vuln.get('type', '')

            if vuln_type == 'xss_vulnerabilities':
                for xss in vuln.get('data', []):
                    payload = xss.get('payload', '')
                    verify_result = await self._verify_payload({
                        'payload': payload,
                        'type': 'XSS',
                        'param': xss.get('param', '')
                    }, target)
                    if verify_result.get('verified'):
                        findings.append({
                            'type': 'exploited_xss',
                            'severity': 'high',
                            'payload': payload,
                            'verification': verify_result
                        })

            elif vuln_type == 'cve_details':
                cve_data = vuln.get('data', {})
                exploits = cve_data.get('exploits', [])
                for exploit in exploits:
                    if exploit.get('path'):
                        verify_result = await self._verify_exploit(exploit, target)
                        if verify_result.get('verified'):
                            findings.append({
                                'type': 'verified_exploit',
                                'severity': 'critical',
                                'exploit': exploit,
                                'verification': verify_result
                            })

        if not findings:
            logger.info(set_color("[*] No exploitable vulnerabilities found", level=25))

        logger.info(set_color(f"[+] Exploitation complete: {len(findings)} successful", level=25))
        return findings

    async def _phase_post_exploitation(self, target: str, context: Dict) -> List[Dict]:
        """Phase 5: Post-Exploitation"""
        findings = []

        logger.info(set_color("[*] Starting Post-Exploitation...", level=25))

        exploit_findings = context.get('exploit_findings', [])

        if exploit_findings:
            findings.append({
                'type': 'access_achieved',
                'severity': 'critical',
                'details': 'Vulnerable to multiple exploits'
            })

            recommendations = self._generate_post_exploit_recommendations(exploit_findings)
            findings.extend(recommendations)
        else:
            findings.append({
                'type': 'access_achieved',
                'severity': 'info',
                'details': 'No successful exploitation'
            })

        logger.info(set_color(f"[+] Post-Exploitation complete", level=25))
        return findings

    async def _phase_reporting(self, target: str, context: Dict) -> List[Dict]:
        """Phase 6: Reporting"""
        findings = []

        logger.info(set_color("[*] Generating Report...", level=25))

        all_findings = context.get('all_findings', [])
        report = self._generate_report(target, all_findings)

        findings.append({
            'type': 'pentest_report',
            'data': report.to_dict()
        })

        logger.info(set_color("[+] Report generated", level=25))
        return findings

    async def _run_tool(self, tool_name: str, target: str, params: Dict) -> Dict:
        from concurrent.futures import ThreadPoolExecutor

        tool_map = {
            'nuclei': self._run_nuclei,
            'xsstrike': self._run_xsstrike,
            'sploitscan': self._run_sploitscan,
            'sqlmap': self._run_sqlmap,
            'nmap': self._run_nmap,
            'crawler': self._run_crawler,
            'waf_detect': self._run_waf_detect,
            'header_check': self._run_header_check,
            'admin_panel': self._run_admin_panel,
        }

        if tool_name not in tool_map:
            return {'success': False, 'error': f'Unknown tool: {tool_name}'}

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, tool_map[tool_name], target, params)

    def _run_nuclei(self, target: str, params: Dict) -> Dict:
        try:
            from lib.integrations.nuclei_integration import NucleiIntegration
            nuclei = NucleiIntegration()
            severity = params.get('severity', 'medium,high,critical')
            result = nuclei.comprehensive_scan(target, severity_filter=severity.split(','))
            return {'success': True, 'data': result}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _run_xsstrike(self, target: str, params: Dict) -> Dict:
        try:
            from lib.attacks.xsstrike_integration import run_xsstrike_scan
            mode = params.get('mode', 'crawl')
            result = run_xsstrike_scan(target, mode=mode, verbose=self.verbose)
            return {'success': result.get('success', False), 'data': result}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _run_sploitscan(self, target: str, params: Dict) -> Dict:
        try:
            from lib.cve_exploit.sploitscan_integration import scan_cve_main
            cve_id = params.get('cve_id', '')
            if not cve_id:
                return {'success': False, 'error': 'No CVE ID provided'}
            result = scan_cve_main(cve_id, verify=False, target=target, verbose=self.verbose)
            return {'success': True, 'data': result}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _run_sqlmap(self, target: str, params: Dict) -> Dict:
        try:
            from lib.attacks.sqlmap_scan import sqlmap_scan_main
            result = sqlmap_scan_main(target, verbose=self.verbose, auto_start=params.get('auto_start', False))
            return {'success': True, 'data': {'result': result}}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _run_nmap(self, target: str, params: Dict) -> Dict:
        try:
            from urllib.parse import urlparse
            from lib.attacks.nmap_scan import perform_port_scan
            parsed = urlparse(target)
            ip = parsed.netloc.split(':')[0] if ':' in parsed.netloc else parsed.netloc
            result = perform_port_scan(ip, verbose=self.verbose)
            return {'success': True, 'data': {'result': result}}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _run_crawler(self, target: str, params: Dict) -> Dict:
        try:
            from lib.integrations.katana_integration import KatanaIntegration
            depth = params.get('depth', 3)
            katana = KatanaIntegration({})
            result = katana.crawl_target(target, depth=depth, verbose=self.verbose)
            return {'success': result.get('success', False), 'data': result}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _run_waf_detect(self, target: str, params: Dict) -> Dict:
        try:
            from lib.core.wafw00f_integration import detect_waf_with_wafw00f
            result = detect_waf_with_wafw00f(target, verbose=self.verbose)
            return {'success': True, 'data': {'waf': result}}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _run_header_check(self, target: str, params: Dict) -> Dict:
        try:
            from lib.header_check import main_header_check
            result = main_header_check(target, verbose=self.verbose)
            return {'success': True, 'data': {'headers': result}}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _run_admin_panel(self, target: str, params: Dict) -> Dict:
        try:
            from lib.attacks.admin_panel_finder import main
            result = main(target, verbose=self.verbose, do_threading=True)
            return {'success': True, 'data': {'panels': result}}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _identify_technologies(self, target: str) -> Dict:
        try:
            import requests
            response = requests.get(target, timeout=10, verify=False)
            headers = response.headers
            technologies = []

            server = headers.get('Server', '')
            if server:
                technologies.append({'name': server, 'type': 'server'})

            powered_by = headers.get('X-Powered-By', '')
            if powered_by:
                technologies.append({'name': powered_by, 'type': 'backend'})

            html = response.text.lower()

            tech_map = {
                'wordpress': 'WordPress',
                'joomla': 'Joomla',
                'drupal': 'Drupal',
                'jquery': 'jQuery',
                'react': 'React',
                'vue': 'Vue.js',
                'angular': 'Angular',
                'bootstrap': 'Bootstrap',
                'django': 'Django',
                'flask': 'Flask',
                'laravel': 'Laravel',
                'spring': 'Spring',
                'nodejs': 'Node.js',
                'express': 'Express.js',
            }

            for keyword, name in tech_map.items():
                if keyword in html:
                    technologies.append({'name': name, 'type': 'framework'})

            return {'technologies': technologies}

        except Exception as e:
            logger.warning(set_color(f"Technology detection error: {str(e)}", level=30))
            return {'technologies': []}

    def _search_tech_cves(self, tech_name: str) -> List[Dict]:
        try:
            from lib.cve_exploit.sploitscan_integration import SploitScanIntegration
            scanner = SploitScanIntegration(verbose=self.verbose)
            cve_ids = scanner.search_cve_by_keyword(tech_name)
            return [{'cve_id': cve} for cve in cve_ids[:5]]
        except Exception:
            return []

    async def _verify_payload(self, payload_data: Dict, target: str) -> Dict:
        try:
            from lib.cve_exploit.cve_verifier import verify_payload_main
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                self.executor,
                verify_payload_main,
                payload_data,
                target
            )
        except Exception as e:
            return {'verified': False, 'error': str(e)}

    async def _verify_exploit(self, exploit_data: Dict, target: str) -> Dict:
        try:
            from lib.cve_exploit.sploitscan_integration import SploitScanIntegration
            scanner = SploitScanIntegration(verbose=self.verbose)
            exploit_path = exploit_data.get('path', '')
            if exploit_path:
                result = scanner.verify_exploit(exploit_path, target)
                return result
            return {'verified': False, 'error': 'No path'}
        except Exception as e:
            return {'verified': False, 'error': str(e)}

    def _generate_post_exploit_recommendations(self, findings: List[Dict]) -> List[Dict]:
        return [
            {
                'type': 'recommendation',
                'severity': 'critical',
                'title': 'Immediate Action Required',
                'description': 'Multiple critical vulnerabilities found. Patch immediately.'
            },
            {
                'type': 'recommendation',
                'severity': 'high',
                'title': 'Input Validation',
                'description': 'Implement proper input validation and sanitization.'
            },
            {
                'type': 'recommendation',
                'severity': 'high',
                'title': 'Output Encoding',
                'description': 'Use proper output encoding to prevent XSS.'
            },
            {
                'type': 'recommendation',
                'severity': 'medium',
                'title': 'Security Headers',
                'description': 'Implement CSP, X-XSS-Protection, and other security headers.'
            }
        ]

    def _generate_report(self, target: str, findings: List[Dict]) -> PentestReport:
        report = PentestReport(
            target=target,
            start_time=datetime.now().isoformat()
        )

        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        severity_map = {
            'critical': 'critical_vulns',
            'high': 'high_vulns',
            'medium': 'medium_vulns',
            'low': 'low_vulns',
            'info': 'low_vulns'
        }

        for finding in findings:
            severity = finding.get('severity', 'low')
            attr = severity_map.get(severity, 'low_vulns')
            if attr == 'critical_vulns':
                critical_count += 1
            elif attr == 'high_vulns':
                high_count += 1
            elif attr == 'medium_vulns':
                medium_count += 1
            else:
                low_count += 1

        report.critical_vulns = critical_count
        report.high_vulns = high_count
        report.medium_vulns = medium_count
        report.low_vulns = low_count
        report.total_findings = len(findings)
        report.end_time = datetime.now().isoformat()

        report.recommendations = [
            "Patch critical vulnerabilities immediately",
            "Implement WAF rules for detected attack patterns",
            "Add input validation on all user inputs",
            "Enable security headers (CSP, HSTS, X-Frame-Options)",
            "Regular security scanning and penetration testing"
        ]

        return report


class AutonomousPentester:
    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.mcp = MCPServer(verbose=verbose)
        self.context: Dict = {'all_findings': []}
        self.report = PentestReport(
            target=target,
            start_time=datetime.now().isoformat()
        )

    async def run_full_audit(self) -> Dict:
        phases_order = [
            Phase.RECON,
            Phase.SCANNING,
            Phase.VULN_ASSESSMENT,
            Phase.EXPLOITATION,
            Phase.POST_EXPLOIT,
            Phase.REPORTING
        ]

        logger.info(set_color(
            f"\n{'#'*70}\n"
            f"#  AUTONOMOUS PENETRATION TEST - {self.target}\n"
            f"{'#'*70}",
            level=25
        ))

        for phase in phases_order:
            phase_result = await self.mcp.execute_phase(phase, self.target, self.context)

            self.report.phases[phase.value] = phase_result
            self.context['all_findings'].extend(phase_result.findings)

            if phase == Phase.VULN_ASSESSMENT:
                self.context['vulnerability_findings'] = phase_result.findings
            elif phase == Phase.EXPLOITATION:
                self.context['exploit_findings'] = phase_result.findings

            logger.info(set_color(
                f"[{phase.value}] Completed in {phase_result.execution_time:.2f}s - {phase_result.summary}",
                level=25
            ))

        self.report.end_time = datetime.now().isoformat()
        self._update_report_stats()

        return self.report.to_dict()

    def _update_report_stats(self):
        severity_map = {
            'critical': 'critical_vulns',
            'high': 'high_vulns',
            'medium': 'medium_vulns',
            'low': 'low_vulns'
        }

        for finding in self.context['all_findings']:
            severity = finding.get('severity', 'low')
            if severity in severity_map:
                attr = severity_map[severity]
                current = getattr(self.report, attr, 0)
                setattr(self.report, attr, current + 1)

        self.report.total_findings = len(self.context['all_findings'])


def run_autonomous_scan(target: str, **kwargs) -> Dict:
    verbose = kwargs.get("verbose", False)

    pentester = AutonomousPentester(target, verbose=verbose)
    result = asyncio.run(pentester.run_full_audit())

    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python mcp_server.py <target_url>")
        sys.exit(1)

    result = asyncio.run(run_autonomous_scan(sys.argv[1], verbose=True))
    print(json.dumps(result, indent=2))
