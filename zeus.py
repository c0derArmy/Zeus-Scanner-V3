#!/usr/bin/env python3

import sys
import time
import json
import requests
import os
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urljoin
import re
from typing import List, Dict, Any, Optional

from lib.core.parse import ZeusParser
from lib.core.common import start_up, shutdown
from lib.core.settings import (
    setup, logger, set_color, get_latest_log_file,
    fix_log_file, BANNER, URL_REGEX
)
from lib.integrations.katana_integration import KatanaIntegration
from lib.integrations.ffuf_integration import FFUFScan
from lib.ai_engine.ai_orchestrator import AIOrchestrator
from lib.ai_engine.exploit_verifier import ExploitVerifier
from lib.core.ai_config_manager import AIConfigManager

class ZeusAIAgent:
    """Autonomous AI Pentesting Agent for Zeus-Scanner-V3."""
    
    def __init__(self, target_url: str, verbose: bool = False, proxy=None):
        self.target_url = target_url
        self.verbose = verbose
        self.proxy = proxy
        self.vulnerabilities = []
        self.discovered_urls = []
        self.attack_surfaces = []
        
        # Load AI Configuration
        self.config_manager = AIConfigManager()
        self.orchestrator = AIOrchestrator(
            target_url=target_url,
            provider=self.config_manager.get_provider(),
            model=self.config_manager.get_model(),
            verbose=verbose
        )
        self.verifier = ExploitVerifier(target_url, self.orchestrator.analyzer)
        
        # Suppress InsecureRequestWarning
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def print_phase(self, text: str):
        print(f"\n{set_color('='*70, level=25)}")
        print(set_color(f"  {text}", level=25))
        print(set_color('='*70, level=25))

    def run_autonomous_scan(self):
        self.print_phase("ZEUS AUTONOMOUS AI PENTESTER")
        print(f"Target: {self.target_url}")
        print(f"AI Provider: {self.config_manager.get_provider()} ({self.config_manager.get_model()})")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        start_time = time.time()

        # Phase 1: Reconnaissance
        self._phase_recon()
        
        # Phase 2: Discovery
        self._phase_discovery()
        
        # Phase 3: Strategic Planning
        self._phase_planning()
        
        # Phase 4: Autonomous Testing
        self._phase_testing()
        
        # Phase 5: Reporting
        self._phase_reporting()

        elapsed = time.time() - start_time
        print(f"\n{set_color(f'[*] Scan completed in {elapsed:.2f}s', level=25)}")

    def _phase_recon(self):
        self.print_phase("PHASE 1: AI-ENHANCED RECONNAISSANCE")
        self.recon_data = self.orchestrator.perform_recon()
        
        techs = self.recon_data.get('technologies', [])
        print(set_color(f"[+] Detected Technologies: {', '.join(techs) if techs else 'None extracted'}", level=25))
        
        leaks = self.recon_data.get('information_leaks', [])
        if leaks:
            print(set_color(f"[!] Information Leaks Found: {len(leaks)}", level=30))
            for leak in leaks[:3]:
                print(f"    - {leak['header']}: {leak['value']}")

    def _phase_discovery(self):
        self.print_phase("PHASE 2: ATTACK SURFACE DISCOVERY")
        
        # Crawling
        print(set_color("[*] Crawling target for endpoints...", level=25))
        try:
            katana = KatanaIntegration({'rate_limit': 50, 'parallelism': 5})
            if katana.available:
                result = katana.crawl_target(self.target_url, depth=2, verbose=False)
                if result['success']:
                    self.discovered_urls = result['urls']
            else:
                self.discovered_urls = self._basic_crawl()
        except Exception as e:
            logger.error(f"Discovery error: {e}")
            self.discovered_urls = [self.target_url]

        # 2. Deep Discovery (Fuzzing)
        fuzzer = FFUFScan(self.target_url)
        fuzz_results = fuzzer.run_fuzz()
        
        # Merge results into a single set of unique URLs
        all_urls = set(self.discovered_urls)
        for res in fuzz_results:
            url = res.get("url")
            if url: all_urls.add(url)
                
        logger.info(set_color(f"[*] Discovery complete. Total potential endpoints: {len(all_urls)}", level=25))
        
        # Surface Analysis - Extracting params/forms from all discovered URLs
        print(set_color("[*] Analyzing parameters and forms for attack vectors...", level=25))
        self.attack_surfaces = self._extract_surfaces(list(all_urls)[:50]) # Limit to top 50 for performance
        
        # Ensure discovered directories are also treated as surfaces (even if no params found)
        existing_surface_urls = [s['url'] for s in self.attack_surfaces]
        for url in all_urls:
            if url not in existing_surface_urls and any(x in url.lower() for x in ['admin', 'log', 'backup', 'config', 'user', 'faculty', 'student']):
                self.attack_surfaces.append({
                    "url": url,
                    "method": "GET",
                    "params": ["_path"] # Dummy param for testing the directory itself
                })
                
        print(set_color(f"[+] Identified {len(self.attack_surfaces)} potential attack vectors", level=25))

    def _phase_planning(self):
        self.print_phase("PHASE 3: STRATEGIC ATTACK PLANNING")
        
        # 2. AI Path Analysis (Specialized strategy for directories)
        dirs = [u.get('url', '') for u in self.attack_surfaces if not u.get('url', '').endswith(('.php', '.aspx', '.jsp', '.html', '.js'))]
        if dirs:
            logger.info(set_color(f"[*] AI analyzing {len(dirs)} discovered directories for sensitive data exposure...", level=25))
            # AI logic to prioritize paths like /backup, /config, /admin
            
        self.attack_plan = self.orchestrator.attack_plan
        
        if not self.attack_plan:
            print(set_color("[-] AI failed to generate a strategic plan. Falling back to default testing.", level=30))
            return

        print(set_color("[+] AI Strategic Priorities:", level=25))
        for test in sorted(self.attack_plan, key=lambda x: x.get('priority', 5)):
            print(f"    [{test.get('priority')}] {test.get('type').upper()}: {test.get('reason')}")

    def _phase_testing(self):
        self.print_phase("PHASE 4: CONTEXT-AWARE DYNAMIC TESTING")
        
        if not self.attack_surfaces:
            print(set_color("[-] No attack surfaces found to test.", level=30))
            return

        # Iterate through prioritized vulnerability types from the plan
        priorities = [p.get('type').lower() for p in self.attack_plan] if self.attack_plan else ['sqli', 'xss', 'lfi']
        
        tested_count = 0
        for surface in self.attack_surfaces:
            url = surface['url']
            params = surface['params']
            method = surface['method']
            
            for param in params:
                for vuln_type in priorities[:3]: # Focus on top 3 priorities
                    context = {
                        "technologies": self.recon_data.get('technologies', []),
                        "waf": self.recon_data.get('waf_detected', False),
                        "method": method
                    }
                    payloads = self.orchestrator.generate_contextual_payloads(vuln_type, param, context)
                    for p_data in payloads[:2]: # Test top 2 AI-generated payloads
                        payload = p_data.get('payload')
                        print(f"    -> Action: {p_data.get('description')}")
                        
                        # Iterative Bypass Loop (New 'Advanced' Logic)
                        max_retries = 3
                        for attempt in range(max_retries):
                            # Avoid hitting AI too fast
                            time.sleep(1)
                            
                            result = self._execute_test(url, method, param, payload)
                            if result:
                                analysis = self.orchestrator.analyze_test_result(
                                    request_info={"url": url, "method": method, "param": param, "payload": payload, "attempt": attempt},
                                    response_info=result
                                )
                                
                                if analysis.get('vulnerable'):
                                    print(set_color(f"    [!] Potential {vuln_type.upper()} detected. Verifying...", level=30))
                                    
                                    # Definitive PoC Verification through unified interface
                                    proof = self.verifier.verify(vuln_type, url, method, param, payload)
                                    if proof.get('verified'):
                                        print(set_color(f"    [!!!] VERIFIED: {proof.get('proof')}", level=50))
                                        self.vulnerabilities.append({
                                            "type": vuln_type,
                                            "url": url,
                                            "parameter": param,
                                            "payload": proof.get('poc_payload'),
                                            "evidence": proof.get('proof'),
                                            "confidence": "CRITICAL"
                                        })
                                        break # Verified
                                    else:
                                        # Fallback but with lowered confidence if PoC fails
                                        logger.info(f"    [-] Verification failed: {proof.get('proof')}")
                                        self.vulnerabilities.append({
                                            "type": vuln_type,
                                            "url": url,
                                            "parameter": param,
                                            "payload": payload,
                                            "evidence": analysis.get('evidence'),
                                            "confidence": "LOW (Unverified)"
                                        })
                                        break
                                elif analysis.get('waf_detected') and attempt < max_retries - 1:
                                    print(set_color(f"    [-] WAF Blocked. Re-generating bypass (Attempt {attempt+2})...", level=30))
                                    # Ask AI for a targeted bypass
                                    bypass_prompt = f"The payload '{payload}' was blocked by a WAF. Suggest an evasive bypass payload for {vuln_type} on {param}. RETURN ONLY THE PAYLOAD."
                                    payload = self.orchestrator.ai.analyze(bypass_prompt)
                                else:
                                    break # Not vulnerable or last attempt failed
                        
                        tested_count += 1
                        if tested_count > 50: break # Global limit
                if tested_count > 50: break
            if tested_count > 50: break

    def _phase_reporting(self):
        self.print_phase("PHASE 5: ADVANCED SECURITY REPORT")
        
        if not self.vulnerabilities:
            print(set_color("\n[+] No vulnerabilities verified during this autonomous run.", level=25))
        else:
            print(set_color(f"\n[!] VERIFIED VULNERABILITIES: {len(self.vulnerabilities)}", level=50))
            for v in self.vulnerabilities:
                print(f"\n--- {v['type'].upper()} ---")
                print(f"URL: {v['url']}")
                print(f"Parameter: {v['parameter']}")
                print(f"Payload: {v['payload']}")
                print(f"Confidence: {v['confidence'].upper()}")
                print(f"Evidence: {v['evidence']}")

        # Save report
        report_data = {
            "target": self.target_url,
            "scan_time": datetime.now().isoformat(),
            "recon_data": self.recon_data,
            "vulnerabilities": self.vulnerabilities,
            "discovered_urls": self.discovered_urls
        }
        filename = f"zeus-autonomous-report-{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        print(f"\n[*] Full autonomous report saved: {filename}")

    def _execute_test(self, url, method, param, payload) -> Optional[Dict[str, Any]]:
        """Execute a single HTTP test and return response info."""
        try:
            session = requests.Session()
            session.verify = False
            
            # Build data/params
            data = {param: payload}
            
            if method.upper() == 'POST':
                resp = session.post(url, data=data, timeout=10, proxies=self.proxy)
            else:
                resp = session.get(url, params=data, timeout=10, proxies=self.proxy)
            
            return {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body_preview": resp.text[:2000]
            }
        except Exception as e:
            if self.verbose: logger.error(f"Test execution error: {e}")
            return None

    def _extract_surfaces(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Extract parameters and forms from a list of URLs."""
        surfaces = []
        from bs4 import BeautifulSoup
        
        for url in urls:
            try:
                # 1. URL Parameters
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())
                if params:
                    surfaces.append({
                        "url": url.split('?')[0],
                        "method": "GET",
                        "params": params
                    })
                
                # 2. Form Inputs
                resp = requests.get(url, timeout=10, verify=False, proxies=self.proxy)
                soup = BeautifulSoup(resp.text, 'html.parser')
                for form in soup.find_all('form'):
                    method = form.get('method', 'GET').upper()
                    action = urljoin(url, form.get('action', ''))
                    inputs = [i.get('name') for i in form.find_all(['input', 'textarea']) if i.get('name')]
                    if inputs:
                        surfaces.append({
                            "url": action,
                            "method": method,
                            "params": inputs
                        })
            except:
                continue
        return surfaces

    def _basic_crawl(self) -> List[str]:
        """Simple fallback crawler."""
        urls = [self.target_url]
        try:
            resp = requests.get(self.target_url, timeout=10, verify=False, proxies=self.proxy)
            links = re.findall(r'href=["\'](https?://[^"\']+|/[^"\']+)["\']', resp.text)
            for link in links:
                full_url = urljoin(self.target_url, link)
                if urlparse(full_url).netloc == urlparse(self.target_url).netloc:
                    if full_url not in urls: urls.append(full_url)
        except: pass
        return urls

if __name__ == "__main__":
    opt = ZeusParser.cmd_parser()
    
    # Check if user wants interactive setup
    if opt.setupConfig:
        AIConfigManager.setup_interactive()
        sys.exit(0)

    ZeusParser().single_show_args(opt)
    setup(verbose=opt.runInVerbose)

    if not opt.hideBanner:
        print(BANNER)

    start_up()

    proxy_to_use = None
    if opt.proxyConfig:
        proxy_to_use = {'http': opt.proxyConfig, 'https': opt.proxyConfig}

    try:
        if opt.singleTargetURL:
            target_url = opt.singleTargetURL.strip()
            if not URL_REGEX.match(target_url):
                raise ValueError("Invalid URL format")
            
            agent = ZeusAIAgent(target_url, verbose=opt.runInVerbose, proxy=proxy_to_use)
            agent.run_autonomous_scan()
        else:
            print(set_color("[-] No target specified. Use: python zeus.py -u URL", level=40))
            print(set_color("[*] Tip: Use --setup to configure AI providers.", level=25))

    except KeyboardInterrupt:
        print(set_color("\n[-] Aborted by user", level=40))
    except Exception as e:
        print(set_color(f"[-] Fatal Error: {e}", level=50))
        if opt.runInVerbose:
            import traceback
            traceback.print_exc()

    fix_log_file()
    shutdown()
