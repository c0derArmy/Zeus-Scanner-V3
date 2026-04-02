#!/usr/bin/env python3

"""
Katana Web Crawler Integration for Zeus Scanner
Katana is a fast web crawler focused on headless browsing
"""

import os
import sys
import json
import time
import subprocess
import tempfile
from typing import List, Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from lib.core.settings import logger, set_color, SPIDER_LOG_PATH


class KatanaIntegration:
    """
    Integration with ProjectDiscovery's Katana web crawler
    https://github.com/projectdiscovery/katana
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.katana_binary = self._find_katana_binary()
        self.available = self.katana_binary is not None
    
    def _find_katana_binary(self) -> Optional[str]:
        """Find katana binary in system PATH"""
        try:
            result = subprocess.run(
                ['which', 'katana'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                katana_path = result.stdout.strip()
                logger.info(set_color(f"Found Katana at: {katana_path}", level=25))
                return katana_path
            else:
                logger.warning(set_color("Katana not found in PATH", level=30))
                return None
        except Exception as e:
            logger.debug(set_color(f"Error finding Katana: {str(e)}", level=10))
            return None
    
    def crawl_target(self, target_url: str, depth: int = 3, output_file: str = None, 
                     verbose: bool = False) -> Dict:
        """
        Crawl a target URL using Katana
        
        Args:
            target_url: URL to crawl
            depth: Crawl depth (default: 3)
            output_file: Optional output file path
            verbose: Enable verbose output
        
        Returns:
            Dict with crawl results
        """
        if not self.available:
            logger.error(set_color("Katana is not available", level=40))
            return {
                'success': False,
                'error': 'Katana not found',
                'urls': []
            }
        
        logger.info(set_color(f"Starting Katana crawl on: {target_url}", level=25))
        logger.info(set_color(f"Crawl depth: {depth}", level=25))
        
        # Create temporary output file if not specified
        if output_file is None:
            temp_fd, output_file = tempfile.mkstemp(suffix='.txt', prefix='katana_')
            os.close(temp_fd)
        
        # Build katana command
        cmd = [
            self.katana_binary,
            '-u', target_url,
            '-d', str(depth),
            '-jc',  # JavaScript crawling
            '-kf', 'all',  # Known files filter
            '-silent' if not verbose else '-v',
            '-o', output_file
        ]
        
        # Add additional options from config
        if self.config.get('proxy'):
            cmd.extend(['-proxy', self.config['proxy']])
        
        if self.config.get('user_agent'):
            cmd.extend(['-H', f"User-Agent: {self.config['user_agent']}"])
        
        # Set rate limit (requests per second)
        rate_limit = self.config.get('rate_limit', 150)
        cmd.extend(['-rl', str(rate_limit)])
        
        # Set parallelism
        parallelism = self.config.get('parallelism', 10)
        cmd.extend(['-c', str(parallelism)])
        
        # Set timeout
        timeout = self.config.get('timeout', 300)
        
        try:
            logger.info(set_color("Executing Katana crawler...", level=25))
            logger.info(set_color("="*80, level=25))
            logger.info(set_color("DISCOVERED URLS (Real-time)", level=25))
            logger.info(set_color("="*80, level=25))
            
            # Run katana and capture output in real-time
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            discovered_urls = []
            url_count = 0
            
            # Display URLs line by line as they're discovered
            try:
                for line in process.stdout:
                    line = line.strip()
                    if line:
                        url_count += 1
                        discovered_urls.append(line)
                        
                        # Display with colorful output
                        if 'http://' in line:
                            color_code = '\033[96m'  # Cyan
                        elif 'https://' in line:
                            color_code = '\033[92m'  # Green
                        else:
                            color_code = '\033[93m'  # Yellow
                        
                        reset_code = '\033[0m'
                        print(f"{color_code}[{url_count}] {line}{reset_code}")
                
                process.wait(timeout=timeout)
                
            except subprocess.TimeoutExpired:
                process.kill()
                logger.warning(set_color(f"Katana process timed out, stopping...", level=30))
            
            logger.info(set_color("="*80, level=25))
            logger.info(set_color(f"Katana discovered {len(discovered_urls)} URLs total", level=25))
            logger.info(set_color("="*80, level=25))
            
            # Write URLs to output file if they weren't already
            if discovered_urls and output_file:
                with open(output_file, 'w') as f:
                    for url in discovered_urls:
                        f.write(url + '\n')
            
            # Save to Zeus spider log
            self._save_to_spider_log(discovered_urls)
            
            return {
                'success': True,
                'urls': discovered_urls,
                'url_count': len(discovered_urls),
                'output_file': output_file,
                'stdout': '',
                'stderr': ''
            }
            
        except subprocess.TimeoutExpired:
            logger.error(set_color(f"Katana crawl timed out after {timeout} seconds", level=40))
            return {
                'success': False,
                'error': 'Timeout',
                'urls': []
            }
        except Exception as e:
            logger.error(set_color(f"Katana crawl failed: {str(e)}", level=40))
            return {
                'success': False,
                'error': str(e),
                'urls': []
            }
    
    def crawl_multiple_targets(self, target_urls: List[str], depth: int = 3, 
                               verbose: bool = False) -> Dict:
        """
        Crawl multiple targets using Katana
        
        Args:
            target_urls: List of URLs to crawl
            depth: Crawl depth
            verbose: Enable verbose output
        
        Returns:
            Dict with aggregated results
        """
        if not self.available:
            return {
                'success': False,
                'error': 'Katana not found',
                'results': []
            }
        
        logger.info(set_color(f"Crawling {len(target_urls)} targets with Katana", level=25))
        
        all_results = []
        all_urls = set()
        
        for target_url in target_urls:
            result = self.crawl_target(target_url, depth=depth, verbose=verbose)
            all_results.append(result)
            
            if result['success']:
                all_urls.update(result['urls'])
        
        logger.info(set_color(f"Total unique URLs discovered: {len(all_urls)}", level=25))
        
        return {
            'success': True,
            'total_urls': len(all_urls),
            'unique_urls': list(all_urls),
            'individual_results': all_results
        }
    
    def _save_to_spider_log(self, urls: List[str]):
        """Save discovered URLs to Zeus spider log"""
        try:
            # Ensure spider log directory exists
            spider_dir = os.path.dirname(SPIDER_LOG_PATH)
            os.makedirs(spider_dir, exist_ok=True)
            
            # Get the latest spider log file
            spider_files = [f for f in os.listdir(spider_dir) if f.startswith('spider-log-')]
            if spider_files:
                # Append to latest log file
                latest_log = max(spider_files, key=lambda x: os.path.getctime(os.path.join(spider_dir, x)))
                log_file = os.path.join(spider_dir, latest_log)
            else:
                # Create new log file
                log_file = os.path.join(spider_dir, f'spider-log-{int(time.time())}.log')
            
            # Write URLs to log file
            with open(log_file, 'a') as f:
                for url in urls:
                    f.write(url + '\n')
            
            logger.info(set_color(f"Saved {len(urls)} URLs to {log_file}", level=25))
            
        except Exception as e:
            logger.error(set_color(f"Failed to save URLs to spider log: {str(e)}", level=40))
    
    def install_katana(self) -> bool:
        """
        Install Katana using go install
        """
        logger.info(set_color("Installing Katana...", level=25))
        
        try:
            # Check if Go is installed
            result = subprocess.run(['which', 'go'], capture_output=True, timeout=5)
            if result.returncode != 0:
                logger.error(set_color("Go is not installed. Install Go first: https://golang.org/dl/", level=40))
                return False
            
            # Install katana
            install_cmd = ['go', 'install', 'github.com/projectdiscovery/katana/cmd/katana@latest']
            
            result = subprocess.run(
                install_cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                logger.info(set_color("Katana installed successfully!", level=25))
                logger.info(set_color("Make sure ~/go/bin is in your PATH", level=25))
                self.katana_binary = self._find_katana_binary()
                self.available = self.katana_binary is not None
                return True
            else:
                logger.error(set_color(f"Failed to install Katana: {result.stderr}", level=40))
                return False
                
        except Exception as e:
            logger.error(set_color(f"Error installing Katana: {str(e)}", level=40))
            return False


def katana_crawl(target_url: str, depth: int = 3, verbose: bool = False, 
                 proxy: str = None, user_agent: str = None) -> List[str]:
    """
    Convenience function to crawl a URL with Katana
    
    Args:
        target_url: URL to crawl
        depth: Crawl depth
        verbose: Enable verbose output
        proxy: Proxy to use
        user_agent: User agent string
    
    Returns:
        List of discovered URLs
    """
    config = {}
    if proxy:
        config['proxy'] = proxy
    if user_agent:
        config['user_agent'] = user_agent
    
    katana = KatanaIntegration(config)
    
    if not katana.available:
        logger.warning(set_color("Katana not available, falling back to default crawler", level=30))
        return []
    
    result = katana.crawl_target(target_url, depth=depth, verbose=verbose)
    
    if result['success']:
        return result['urls']
    else:
        return []
