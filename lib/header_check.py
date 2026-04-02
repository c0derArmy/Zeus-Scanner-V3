#!/usr/bin/env python3
"""
Header checking module for Zeus Scanner
Detects web server headers, technologies, and WAF information
"""

import requests
from lib.core.settings import set_color, logger

def main_header_check(url, verbose=False, agent=None, proxy=None, xforward=False, 
                      identify_plugins=False, identify_waf=False, show_description=False):
    """
    Check HTTP headers of target URL to identify technologies and WAF
    
    Args:
        url: Target URL to check
        verbose: Enable verbose output
        agent: User-Agent string to use
        proxy: Proxy configuration
        xforward: Add X-Forwarded-For header
        identify_plugins: Identify plugins/extensions
        identify_waf: Identify WAF protection
        show_description: Show descriptions of found technologies
    
    Returns:
        bool: True if headers were successfully retrieved, False otherwise
    """
    try:
        headers = {}
        if agent:
            headers['User-Agent'] = agent
        
        if xforward:
            import random
            random_ip = ".".join([str(random.randint(1, 255)) for _ in range(4)])
            headers['X-Forwarded-For'] = random_ip
        
        # Prepare proxy configuration
        proxies = None
        if proxy:
            if proxy.startswith('socks'):
                proxies = {'http': proxy, 'https': proxy}
            else:
                proxies = {'http': proxy, 'https': proxy}
        
        # Make request
        response = requests.get(url, headers=headers, proxies=proxies, timeout=10, verify=False)
        
        if verbose:
            logger.debug(set_color("Retrieved headers from target", level=10))
        
        # Log some basic header information
        logger.info(set_color(f"Target: {url}", level=25))
        logger.info(set_color(f"Status Code: {response.status_code}", level=25))
        
        # Check for common server headers
        server = response.headers.get('Server', 'Unknown')
        if server != 'Unknown':
            logger.info(set_color(f"Server: {server}", level=25))
        
        # Check for X-Powered-By header
        powered_by = response.headers.get('X-Powered-By', None)
        if powered_by:
            logger.info(set_color(f"Powered By: {powered_by}", level=25))
        
        # Check for WAF detection
        if identify_waf:
            waf_indicators = [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'Content-Security-Policy',
                'X-XSS-Protection'
            ]
            detected_waf = []
            for header in waf_indicators:
                if header in response.headers:
                    detected_waf.append(header)
            
            if detected_waf:
                logger.info(set_color(f"WAF/Security Headers Detected: {', '.join(detected_waf)}", level=35))
        
        return True
        
    except requests.exceptions.RequestException as e:
        if verbose:
            logger.debug(set_color(f"Failed to retrieve headers: {str(e)}", level=10))
        return False
    except Exception as e:
        logger.error(set_color(f"Error checking headers: {str(e)}", level=40))
        return False
