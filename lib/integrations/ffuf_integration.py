import subprocess
import json
import os
from typing import List, Dict, Any, Optional
from lib.core.settings import logger, set_color

class FFUFScan:
    """Wrapper for the ffuf directory fuzzer."""
    
    DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
    
    def __init__(self, target: str, wordlist: Optional[str] = None, 
                 threads: int = 10, rate_limit: int = 0):
        self.target = target.rstrip('/')
        self.wordlist = wordlist or self.DEFAULT_WORDLIST
        self.threads = threads
        self.rate_limit = rate_limit
        
        if not os.path.exists(self.wordlist):
            logger.warning(set_color(f"Wordlist not found: {self.wordlist}. Fuzzer may fail.", level=30))

    def run_fuzz(self, extensions: str = "php,aspx,jsp,html,txt") -> List[Dict[str, Any]]:
        """Run ffuf and return interesting discoveries."""
        logger.info(set_color(f"[*] Starting deep discovery (fuzzing) on {self.target}...", level=25))
        
        # Build command
        # -u: Target URL with FUZZ keyword
        # -w: Wordlist
        # -e: Extensions to append
        # -mc: Match status codes (200, 301, 302, 403)
        # -s: Silent mode
        # -json: Output in JSON format
        cmd = [
            "ffuf",
            "-u", f"{self.target}/FUZZ",
            "-w", self.wordlist,
            "-mc", "200,301,302,403",
            "-t", str(self.threads),
            "-s", "-json"
        ]
        
        if extensions:
            cmd.extend(["-e", extensions])
        
        if self.rate_limit > 0:
            cmd.extend(["-p", str(self.rate_limit)]) # Delay between requests

        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            results = []
            
            # Use stdout.readline() to get results in real-time
            for line in process.stdout:
                try:
                    data = json.loads(line)
                    # ffuf JSON output for each finding
                    result = {
                        "url": data.get("url"),
                        "status": data.get("status"),
                        "length": data.get("length"),
                        "words": data.get("words"),
                        "input": data.get("input")
                    }
                    results.append(result)
                    logger.info(set_color(f"    [+] Found: {result['url']} ({result['status']})", level=25))
                except json.JSONDecodeError:
                    continue
            
            process.wait()
            return results
            
        except FileNotFoundError:
            logger.error(set_color("ffuf is not installed. Skipping directroy fuzzing.", level=40))
            return []
        except Exception as e:
            logger.error(set_color(f"Fuzzing error: {e}", level=40))
            return []

def get_fuzzer(target: str, **kwargs) -> FFUFScan:
    return FFUFScan(target, **kwargs)
