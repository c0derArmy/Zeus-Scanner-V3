#!/usr/bin/env python3

import json
import time
import requests
import subprocess
from typing import Dict, List, Optional
from urllib.parse import urljoin
from lib.core.settings import logger, set_color

class ZAPIntegration:
    """
    OWASP ZAP (Zed Attack Proxy) Integration for Zeus Scanner
    Provides comprehensive web application security testing through ZAP's REST API
    """
    
    def __init__(self, zap_host="127.0.0.1", zap_port=8080, api_key=None):
        self.zap_host = zap_host
        self.zap_port = zap_port
        self.api_key = api_key
        self.base_url = f"http://{zap_host}:{zap_port}"
        self.api_url = f"{self.base_url}/JSON"
        self.session = requests.Session()
        
        if self.api_key:
            self.session.params['apikey'] = self.api_key
    
    def start_zap_daemon(self, headless=True):
        """Start ZAP in daemon mode"""
        try:
            cmd = [
                "zap.sh", "-daemon", 
                "-host", self.zap_host, 
                "-port", str(self.zap_port)
            ]
            
            if headless:
                cmd.append("-headless")
            
            if self.api_key:
                cmd.extend(["-config", f"api.key={self.api_key}"])
            
            logger.info(set_color("Starting OWASP ZAP daemon...", level=35))
            self.zap_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait for ZAP to start
            for i in range(60):  # Wait up to 60 seconds
                try:
                    response = self.session.get(f"{self.api_url}/core/view/version/")
                    if response.status_code == 200:
                        logger.info(set_color("ZAP daemon started successfully", level=35))
                        return True
                except:
                    time.sleep(1)
            
            return False
        except Exception as e:
            logger.error(set_color(f"Failed to start ZAP daemon: {str(e)}", level=40))
            return False
    
    def check_zap_status(self):
        """Check if ZAP is running and accessible"""
        try:
            response = self.session.get(f"{self.api_url}/core/view/version/")
            if response.status_code == 200:
                version_info = response.json()
                logger.info(set_color(f"ZAP is running - Version: {version_info.get('version', 'Unknown')}", level=35))
                return True
        except Exception as e:
            logger.warning(set_color(f"ZAP not accessible: {str(e)}", level=33))
        return False
    
    def spider_target(self, target_url: str, max_depth=5) -> Dict:
        """Spider/crawl target website to discover URLs"""
        try:
            logger.info(set_color(f"Starting ZAP spider scan on: {target_url}", level=35))
            
            # Start spider scan
            response = self.session.get(f"{self.api_url}/spider/action/scan/", params={
                'url': target_url,
                'maxChildren': str(max_depth * 10),
                'recurse': 'true',
                'contextName': '',
                'subtreeOnly': 'false'
            })
            
            if response.status_code != 200:
                return {'error': f'Spider scan failed: HTTP {response.status_code}'}
            
            scan_id = response.json().get('scan', '')
            
            # Monitor spider progress
            while True:
                progress_response = self.session.get(f"{self.api_url}/spider/view/status/", params={'scanId': scan_id})
                progress = int(progress_response.json().get('status', 0))
                
                if progress >= 100:
                    break
                    
                logger.debug(set_color(f"Spider progress: {progress}%", level=36))
                time.sleep(2)
            
            # Get spider results
            results_response = self.session.get(f"{self.api_url}/spider/view/results/", params={'scanId': scan_id})
            results = results_response.json().get('results', [])
            
            logger.info(set_color(f"Spider discovered {len(results)} URLs", level=35))
            return {
                'scan_id': scan_id,
                'urls': results,
                'total_urls': len(results)
            }
            
        except Exception as e:
            logger.error(set_color(f"Spider scan error: {str(e)}", level=40))
            return {'error': str(e)}
    
    def active_scan(self, target_url: str, scan_policy=None) -> Dict:
        """Perform active vulnerability scan"""
        try:
            logger.info(set_color(f"Starting ZAP active scan on: {target_url}", level=35))
            
            params = {'url': target_url, 'recurse': 'true'}
            if scan_policy:
                params['scanPolicyName'] = scan_policy
            
            # Start active scan
            response = self.session.get(f"{self.api_url}/ascan/action/scan/", params=params)
            
            if response.status_code != 200:
                return {'error': f'Active scan failed: HTTP {response.status_code}'}
            
            scan_id = response.json().get('scan', '')
            
            # Monitor scan progress
            while True:
                progress_response = self.session.get(f"{self.api_url}/ascan/view/status/", params={'scanId': scan_id})
                progress = int(progress_response.json().get('status', 0))
                
                if progress >= 100:
                    break
                    
                logger.debug(set_color(f"Active scan progress: {progress}%", level=36))
                time.sleep(5)
            
            # Get scan results
            alerts = self.get_alerts(target_url)
            
            logger.info(set_color(f"Active scan completed - Found {len(alerts)} alerts", level=35))
            return {
                'scan_id': scan_id,
                'alerts': alerts,
                'total_alerts': len(alerts)
            }
            
        except Exception as e:
            logger.error(set_color(f"Active scan error: {str(e)}", level=40))
            return {'error': str(e)}
    
    def passive_scan(self, target_url: str) -> Dict:
        """Enable passive scanning and get results"""
        try:
            logger.info(set_color(f"Enabling passive scan for: {target_url}", level=35))
            
            # Enable passive scanning
            self.session.get(f"{self.api_url}/pscan/action/enableAllScanners/")
            
            # Access the target to trigger passive scanning
            self.session.get(f"{self.api_url}/core/action/accessUrl/", params={'url': target_url})
            
            # Wait for passive scan to process
            time.sleep(10)
            
            # Get passive scan results
            alerts = self.get_alerts(target_url)
            passive_alerts = [alert for alert in alerts if alert.get('confidence') != 'High']
            
            logger.info(set_color(f"Passive scan found {len(passive_alerts)} alerts", level=35))
            return {
                'alerts': passive_alerts,
                'total_alerts': len(passive_alerts)
            }
            
        except Exception as e:
            logger.error(set_color(f"Passive scan error: {str(e)}", level=40))
            return {'error': str(e)}
    
    def get_alerts(self, base_url=None) -> List[Dict]:
        """Retrieve all alerts/vulnerabilities found"""
        try:
            params = {}
            if base_url:
                params['baseurl'] = base_url
            
            response = self.session.get(f"{self.api_url}/core/view/alerts/", params=params)
            return response.json().get('alerts', [])
            
        except Exception as e:
            logger.error(set_color(f"Error getting alerts: {str(e)}", level=40))
            return []
    
    def ajax_spider(self, target_url: str) -> Dict:
        """Run AJAX spider for modern web applications"""
        try:
            logger.info(set_color(f"Starting AJAX spider on: {target_url}", level=35))
            
            # Start AJAX spider
            response = self.session.get(f"{self.api_url}/ajaxSpider/action/scan/", params={
                'url': target_url,
                'inScope': 'false'
            })
            
            if response.status_code != 200:
                return {'error': f'AJAX spider failed: HTTP {response.status_code}'}
            
            # Monitor AJAX spider progress
            while True:
                status_response = self.session.get(f"{self.api_url}/ajaxSpider/view/status/")
                status = status_response.json().get('status', '')
                
                if status == 'stopped':
                    break
                    
                logger.debug(set_color(f"AJAX spider status: {status}", level=36))
                time.sleep(2)
            
            # Get AJAX spider results
            results_response = self.session.get(f"{self.api_url}/ajaxSpider/view/results/")
            results = results_response.json().get('results', [])
            
            logger.info(set_color(f"AJAX spider discovered {len(results)} URLs", level=35))
            return {
                'urls': results,
                'total_urls': len(results)
            }
            
        except Exception as e:
            logger.error(set_color(f"AJAX spider error: {str(e)}", level=40))
            return {'error': str(e)}
    
    def comprehensive_scan(self, target_url: str, include_ajax=True) -> Dict:
        """Run comprehensive scan including spider, AJAX spider, and active scan"""
        results = {
            'target': target_url,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'spider_results': {},
            'ajax_spider_results': {},
            'active_scan_results': {},
            'passive_scan_results': {},
            'total_vulnerabilities': 0
        }
        
        try:
            # Step 1: Traditional spider
            logger.info(set_color("Phase 1: Traditional Spider Crawling", level=35))
            results['spider_results'] = self.spider_target(target_url)
            
            # Step 2: AJAX spider if requested
            if include_ajax:
                logger.info(set_color("Phase 2: AJAX Spider for Modern Web Apps", level=35))
                results['ajax_spider_results'] = self.ajax_spider(target_url)
            
            # Step 3: Passive scanning
            logger.info(set_color("Phase 3: Passive Vulnerability Detection", level=35))
            results['passive_scan_results'] = self.passive_scan(target_url)
            
            # Step 4: Active scanning
            logger.info(set_color("Phase 4: Active Vulnerability Scanning", level=35))
            results['active_scan_results'] = self.active_scan(target_url)
            
            # Calculate total vulnerabilities
            active_alerts = results['active_scan_results'].get('total_alerts', 0)
            passive_alerts = results['passive_scan_results'].get('total_alerts', 0)
            results['total_vulnerabilities'] = active_alerts + passive_alerts
            
            logger.info(set_color(f"ZAP comprehensive scan completed - Total vulnerabilities: {results['total_vulnerabilities']}", level=35))
            
        except Exception as e:
            logger.error(set_color(f"Comprehensive scan error: {str(e)}", level=40))
            results['error'] = str(e)
        
        return results
    
    def export_report(self, format='json', output_file=None) -> str:
        """Export scan results in various formats"""
        try:
            if format.lower() == 'json':
                response = self.session.get(f"{self.api_url}/core/view/alerts/")
                report_data = response.json()
            elif format.lower() == 'html':
                response = self.session.get(f"{self.base_url}/HTML/core/view/alerts/")
                report_data = response.text
            elif format.lower() == 'xml':
                response = self.session.get(f"{self.base_url}/XML/core/view/alerts/")
                report_data = response.text
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            if output_file:
                with open(output_file, 'w') as f:
                    if format.lower() == 'json':
                        json.dump(report_data, f, indent=2)
                    else:
                        f.write(report_data)
                        
                logger.info(set_color(f"Report exported to: {output_file}", level=35))
                return output_file
            
            return report_data
            
        except Exception as e:
            logger.error(set_color(f"Export error: {str(e)}", level=40))
            return None
    
    def shutdown_zap(self):
        """Shutdown ZAP daemon"""
        try:
            logger.info(set_color("Shutting down ZAP daemon...", level=35))
            self.session.get(f"{self.api_url}/core/action/shutdown/")
            
            if hasattr(self, 'zap_process'):
                self.zap_process.terminate()
                self.zap_process.wait()
                
        except Exception as e:
            logger.warning(set_color(f"Error shutting down ZAP: {str(e)}", level=33))
    
    def get_scan_summary(self, target_url: str) -> Dict:
        """Get summary of all scans for a target"""
        alerts = self.get_alerts(target_url)
        
        summary = {
            'high_risk': 0,
            'medium_risk': 0,
            'low_risk': 0,
            'informational': 0,
            'vulnerabilities_by_type': {},
            'total_alerts': len(alerts)
        }
        
        for alert in alerts:
            risk = alert.get('risk', '').lower()
            vuln_type = alert.get('alert', 'Unknown')
            
            # Count by risk level
            if risk == 'high':
                summary['high_risk'] += 1
            elif risk == 'medium':
                summary['medium_risk'] += 1
            elif risk == 'low':
                summary['low_risk'] += 1
            else:
                summary['informational'] += 1
            
            # Count by vulnerability type
            if vuln_type not in summary['vulnerabilities_by_type']:
                summary['vulnerabilities_by_type'][vuln_type] = 0
            summary['vulnerabilities_by_type'][vuln_type] += 1
        
        return summary