import json
import ssl
import socket
import requests
from urllib.parse import urlparse
from lib.core.ai_config import AIConfig
from lib.core.settings import logger, set_color


class EnhancedAIEngine:
    """Enhanced AI Engine for real vulnerability analysis and reporting."""

    # Security headers to check for
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'severity': 'high',
            'description': 'Missing HSTS header - browser can be tricked into HTTP connections'
        },
        'Content-Security-Policy': {
            'severity': 'medium',
            'description': 'Missing CSP header - vulnerable to XSS and data injection attacks'
        },
        'X-Frame-Options': {
            'severity': 'medium',
            'description': 'Missing X-Frame-Options - vulnerable to clickjacking attacks'
        },
        'X-Content-Type-Options': {
            'severity': 'low',
            'description': 'Missing X-Content-Type-Options - vulnerable to MIME-type sniffing'
        },
        'X-XSS-Protection': {
            'severity': 'low',
            'description': 'Missing X-XSS-Protection - browser XSS filter not enforced'
        },
        'Referrer-Policy': {
            'severity': 'low',
            'description': 'Missing Referrer-Policy - referrer information may leak to third parties'
        },
        'Permissions-Policy': {
            'severity': 'low',
            'description': 'Missing Permissions-Policy - browser features not restricted'
        },
    }

    # Dangerous headers that reveal server information
    INFO_LEAK_HEADERS = [
        'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
        'X-Generator', 'X-Drupal-Cache', 'X-Varnish'
    ]

    def __init__(self):
        self.api_key = AIConfig.get_api_key('openai')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Zeus-Scanner/2.0 (Security Assessment)'
        })
        self.session.verify = False  # Allow self-signed certs for scanning
        # Suppress InsecureRequestWarning
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def analyze_target(self, target):
        """Perform real HTTP header and technology fingerprinting analysis."""
        results = {
            'target': target,
            'reachable': False,
            'status_code': None,
            'headers': {},
            'technologies': [],
            'security_headers_missing': [],
            'information_leaks': [],
            'ssl_info': {},
            'cookies': [],
            'redirects': []
        }

        try:
            response = self.session.get(target, timeout=15, allow_redirects=True)
            results['reachable'] = True
            results['status_code'] = response.status_code
            results['headers'] = dict(response.headers)

            # Track redirects
            if response.history:
                results['redirects'] = [
                    {'url': r.url, 'status': r.status_code}
                    for r in response.history
                ]

            # Check missing security headers
            for header, info in self.SECURITY_HEADERS.items():
                if header.lower() not in {k.lower() for k in response.headers}:
                    results['security_headers_missing'].append({
                        'header': header,
                        'severity': info['severity'],
                        'description': info['description']
                    })

            # Check information leak headers
            for header in self.INFO_LEAK_HEADERS:
                value = response.headers.get(header)
                if value:
                    results['information_leaks'].append({
                        'header': header,
                        'value': value,
                        'severity': 'info',
                        'description': f"Server reveals {header}: {value}"
                    })

            # Technology fingerprinting from headers
            self._fingerprint_technologies(response, results)

            # Cookie analysis
            for cookie in response.cookies:
                cookie_info = {
                    'name': cookie.name,
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('httponly') or cookie.has_nonstandard_attr('HttpOnly'),
                    'samesite': cookie.get_nonstandard_attr('samesite', 'Not Set'),
                    'issues': []
                }
                if not cookie.secure:
                    cookie_info['issues'].append('Cookie missing Secure flag')
                if not cookie_info['httponly']:
                    cookie_info['issues'].append('Cookie missing HttpOnly flag')
                results['cookies'].append(cookie_info)

            # SSL certificate analysis
            parsed = urlparse(target)
            if parsed.scheme == 'https':
                results['ssl_info'] = self._check_ssl(parsed.hostname, parsed.port or 443)

            logger.info(set_color(
                f"AI Engine: Target analysis complete - {len(results['security_headers_missing'])} "
                f"missing security headers, {len(results['information_leaks'])} info leaks", level=25
            ))

        except requests.exceptions.ConnectionError:
            logger.error(set_color(f"AI Engine: Cannot connect to {target}", level=40))
            results['error'] = 'Connection failed'
        except requests.exceptions.Timeout:
            logger.error(set_color(f"AI Engine: Connection timed out for {target}", level=40))
            results['error'] = 'Timeout'
        except Exception as e:
            logger.error(set_color(f"AI Engine: Analysis error - {str(e)}", level=40))
            results['error'] = str(e)

        return results

    def _fingerprint_technologies(self, response, results):
        """Detect technologies from response headers and body."""
        headers = {k.lower(): v for k, v in response.headers.items()}
        body = response.text[:5000].lower() if response.text else ""

        tech_signatures = {
            'Apache': lambda: 'apache' in headers.get('server', '').lower(),
            'Nginx': lambda: 'nginx' in headers.get('server', '').lower(),
            'IIS': lambda: 'microsoft-iis' in headers.get('server', '').lower(),
            'PHP': lambda: 'x-powered-by' in headers and 'php' in headers['x-powered-by'].lower(),
            'ASP.NET': lambda: 'x-aspnet-version' in headers or 'asp.net' in headers.get('x-powered-by', '').lower(),
            'WordPress': lambda: 'wp-content' in body or 'wp-includes' in body,
            'Drupal': lambda: 'x-drupal-cache' in headers or 'drupal' in body,
            'Joomla': lambda: '/media/jui' in body or 'joomla' in body,
            'React': lambda: 'react' in body or '__next' in body,
            'jQuery': lambda: 'jquery' in body,
            'Bootstrap': lambda: 'bootstrap' in body,
            'Cloudflare': lambda: 'cloudflare' in headers.get('server', '').lower() or 'cf-ray' in headers,
            'AWS': lambda: 'amazons3' in headers.get('server', '').lower() or 'x-amz' in str(headers),
        }

        for tech, check in tech_signatures.items():
            try:
                if check():
                    results['technologies'].append(tech)
            except Exception:
                pass

    def _check_ssl(self, hostname, port=443):
        """Check SSL certificate details."""
        ssl_info = {
            'valid': False,
            'issuer': None,
            'subject': None,
            'expires': None,
            'protocol': None,
            'issues': []
        }

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info['valid'] = True
                    ssl_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    ssl_info['subject'] = dict(x[0] for x in cert.get('subject', []))
                    ssl_info['expires'] = cert.get('notAfter', 'Unknown')
                    ssl_info['protocol'] = ssock.version()

                    # Check for weak protocol
                    if ssock.version() in ('TLSv1', 'TLSv1.1', 'SSLv3'):
                        ssl_info['issues'].append(f'Weak SSL/TLS protocol: {ssock.version()}')

        except ssl.SSLCertVerificationError as e:
            ssl_info['issues'].append(f'Certificate verification failed: {str(e)}')
        except Exception as e:
            ssl_info['error'] = str(e)

        return ssl_info

    def comprehensive_vulnerability_analysis(self, target, urls):
        """Analyze target and discovered URLs for common vulnerabilities."""
        analysis = self.analyze_target(target)

        findings = []

        # Convert security header issues to vulnerability findings
        for missing in analysis.get('security_headers_missing', []):
            findings.append({
                'type': 'missing_security_header',
                'name': f"Missing {missing['header']} Header",
                'severity': missing['severity'],
                'description': missing['description'],
                'url': target,
                'remediation': f"Add '{missing['header']}' header to server responses"
            })

        # Convert info leak findings
        for leak in analysis.get('information_leaks', []):
            findings.append({
                'type': 'information_disclosure',
                'name': f"Information Disclosure via {leak['header']}",
                'severity': 'info',
                'description': leak['description'],
                'url': target,
                'remediation': f"Remove or obfuscate the '{leak['header']}' response header"
            })

        # Cookie security issues
        for cookie in analysis.get('cookies', []):
            for issue in cookie.get('issues', []):
                findings.append({
                    'type': 'insecure_cookie',
                    'name': f"Insecure Cookie: {cookie['name']}",
                    'severity': 'medium',
                    'description': issue,
                    'url': target,
                    'remediation': 'Set Secure, HttpOnly, and SameSite attributes on all cookies'
                })

        # SSL issues
        for issue in analysis.get('ssl_info', {}).get('issues', []):
            findings.append({
                'type': 'ssl_issue',
                'name': 'SSL/TLS Configuration Issue',
                'severity': 'high',
                'description': issue,
                'url': target,
                'remediation': 'Upgrade to TLSv1.2 or TLSv1.3'
            })

        return {
            'target': target,
            'analyzed_urls': len(urls) if urls else 0,
            'technologies': analysis.get('technologies', []),
            'findings': findings,
            'total_findings': len(findings),
            'severity_breakdown': self._count_severities(findings)
        }

    def _count_severities(self, findings):
        """Count findings by severity level."""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = f.get('severity', 'info').lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def cve_detection_scan(self, target):
        """Check for known CVEs based on detected technologies."""
        analysis = self.analyze_target(target)
        technologies = analysis.get('technologies', [])
        info_leaks = analysis.get('information_leaks', [])

        cves = []

        # Check server version for known CVEs
        for leak in info_leaks:
            header = leak.get('header', '')
            value = leak.get('value', '')

            if header == 'Server':
                if 'apache' in value.lower():
                    cves.append({
                        'cve': 'CVE-2021-44790',
                        'description': f'Apache HTTP Server {value} - Check for mod_lua buffer overflow',
                        'tool': 'AI-Enhanced CVE Scanner',
                        'severity': 'critical',
                        'recommendation': 'Update Apache to latest version'
                    })
                elif 'nginx' in value.lower():
                    cves.append({
                        'cve': 'CVE-2021-23017',
                        'description': f'Nginx {value} - Check for DNS resolver vulnerability',
                        'tool': 'AI-Enhanced CVE Scanner',
                        'severity': 'high',
                        'recommendation': 'Update Nginx to latest version'
                    })

            if header == 'X-Powered-By' and 'php' in value.lower():
                cves.append({
                    'cve': 'CVE-2024-2756',
                    'description': f'PHP {value} - Check for session fixation via __Host-/__Secure- cookies',
                    'tool': 'AI-Enhanced CVE Scanner',
                    'severity': 'medium',
                    'recommendation': 'Update PHP to latest version'
                })

        if not cves:
            cves.append({
                'cve': 'N/A',
                'description': 'No version-specific CVEs detected from exposed headers (server may be hardened)',
                'tool': 'AI-Enhanced CVE Scanner',
                'severity': 'info',
                'recommendation': 'Run Nuclei for deeper CVE scanning: --use-nuclei'
            })

        return {'cves_found': cves, 'technologies': technologies}

    def comprehensive_risk_assessment(self, vulnerabilities):
        """Assess overall risk based on discovered vulnerabilities."""
        if not vulnerabilities:
            return {'risk_level': 'Low', 'details': 'No vulnerabilities found'}

        severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}
        total_score = 0
        for vuln in vulnerabilities:
            sev = vuln.get('severity', 'info').lower()
            total_score += severity_weights.get(sev, 1)

        if total_score >= 30:
            risk_level = 'Critical'
        elif total_score >= 20:
            risk_level = 'High'
        elif total_score >= 10:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'

        return {
            'risk_level': risk_level,
            'risk_score': total_score,
            'total_vulnerabilities': len(vulnerabilities),
            'details': f'{len(vulnerabilities)} vulnerabilities with risk score {total_score}'
        }

    def generate_poc(self, vuln, target):
        """Generate proof-of-concept details for a vulnerability."""
        vuln_name = vuln.get('name', 'Unknown')
        vuln_type = vuln.get('type', 'unknown')

        poc = {
            'vuln_name': vuln_name,
            'target': target,
            'type': vuln_type,
        }

        if vuln_type == 'missing_security_header':
            header = vuln_name.replace('Missing ', '').replace(' Header', '')
            poc['poc'] = f"curl -sI {target} | grep -i '{header}' || echo 'MISSING: {header}'"
            poc['description'] = f"Verify that {header} header is not present in the response"
        elif vuln_type == 'insecure_cookie':
            poc['poc'] = f"curl -sI {target} | grep -i 'set-cookie'"
            poc['description'] = 'Inspect Set-Cookie headers for missing security flags'
        elif vuln_type == 'information_disclosure':
            poc['poc'] = f"curl -sI {target} | grep -iE 'server|x-powered-by|x-aspnet'"
            poc['description'] = 'Check response headers for information disclosure'
        else:
            poc['poc'] = f'Proof of Concept for {vuln_name} — manual verification recommended'
            poc['description'] = f'Vulnerability {vuln_name} detected on {target}'

        return poc

    def analyze_exploit_potential(self, vuln, target):
        """Analyze the exploitability of a vulnerability."""
        severity = vuln.get('severity', 'info').lower()
        exploitability_map = {
            'critical': 'High', 'high': 'High',
            'medium': 'Medium', 'low': 'Low', 'info': 'None'
        }
        return {
            'vuln_name': vuln.get('name', 'Unknown'),
            'exploitability': exploitability_map.get(severity, 'Unknown'),
            'details': f"Based on severity ({severity}) and vulnerability type ({vuln.get('type', 'unknown')})"
        }

    def assess_exploitation_impact(self, successful_exploits, target):
        """Assess impact of successful exploits."""
        return {
            'impact': 'Critical' if successful_exploits else 'None',
            'exploits_analyzed': len(successful_exploits),
            'target': target
        }

    def generate_comprehensive_report(self, target, vulnerabilities, phases):
        """Generate comprehensive security report."""
        severity_breakdown = self._count_severities(vulnerabilities)
        return {
            'report': f"Comprehensive security assessment for {target}",
            'target': target,
            'vuln_count': len(vulnerabilities),
            'severity_breakdown': severity_breakdown,
            'phases_completed': len(phases),
            'findings': vulnerabilities[:20]  # Top 20 findings
        }

    def generate_risk_matrix(self, vulnerabilities):
        """Generate vulnerability risk matrix."""
        counts = self._count_severities(vulnerabilities)
        return {
            'matrix': f"Critical={counts['critical']}, High={counts['high']}, "
                      f"Medium={counts['medium']}, Low={counts['low']}, Info={counts['info']}",
            'counts': counts,
            'total': len(vulnerabilities)
        }

    def generate_remediation_plan(self, vulnerabilities):
        """Generate prioritized remediation plan."""
        priority_order = ['critical', 'high', 'medium', 'low', 'info']
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: priority_order.index(v.get('severity', 'info').lower())
            if v.get('severity', 'info').lower() in priority_order else 5
        )

        steps = []
        for i, vuln in enumerate(sorted_vulns[:10], 1):
            steps.append({
                'priority': i,
                'name': vuln.get('name', 'Unknown'),
                'severity': vuln.get('severity', 'info'),
                'action': vuln.get('remediation', 'Review and remediate')
            })

        return {
            'plan': steps,
            'total_items': len(steps),
            'summary': f'{len(steps)} remediation items prioritized by severity'
        }

    def generate_executive_summary(self, target, vulnerabilities, risk_matrix):
        """Generate executive-level summary."""
        counts = risk_matrix.get('counts', self._count_severities(vulnerabilities))
        risk = self.comprehensive_risk_assessment(vulnerabilities)

        return {
            'summary': (
                f"Security assessment of {target} identified {len(vulnerabilities)} findings. "
                f"Overall risk level: {risk['risk_level']}. "
                f"Critical: {counts.get('critical', 0)}, High: {counts.get('high', 0)}, "
                f"Medium: {counts.get('medium', 0)}, Low: {counts.get('low', 0)}."
            ),
            'risk_level': risk['risk_level'],
            'total_findings': len(vulnerabilities)
        }
