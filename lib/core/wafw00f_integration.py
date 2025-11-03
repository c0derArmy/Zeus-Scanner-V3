import subprocess
import json
import tempfile
import os

from lib.core.settings import logger, set_color


def detect_waf_with_wafw00f(url, **kwargs):
    """
    Detect WAF using wafw00f tool
    """
    verbose = kwargs.get("verbose", False)
    proxy = kwargs.get("proxy", None)
    
    try:
        if verbose:
            logger.debug(set_color(
                "using wafw00f for WAF detection", level=10
            ))
        
        # Create a temporary file for JSON output
        temp_file = tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False)
        temp_file.close()
        
        # Build wafw00f command
        cmd = ['wafw00f', url, '-o', temp_file.name, '-f', 'json']
        
        # Add proxy if provided
        if proxy:
            cmd.extend(['-p', proxy])
        
        # Add verbosity if needed
        if verbose:
            cmd.append('-v')
        
        if verbose:
            logger.debug(set_color(
                "running command: {}".format(' '.join(cmd)), level=10
            ))
        
        # Run wafw00f
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            universal_newlines=True
        )
        
        # Read the JSON output
        try:
            with open(temp_file.name, 'r') as f:
                data = json.load(f)
            
            # Clean up temp file
            os.unlink(temp_file.name)
            
            # Parse wafw00f output
            if isinstance(data, list) and len(data) > 0:
                waf_data = data[0]
                detected_waf = waf_data.get('firewall', None)
                
                if detected_waf and detected_waf.lower() != 'none':
                    if verbose:
                        logger.debug(set_color(
                            "wafw00f detected: {}".format(detected_waf), level=10
                        ))
                    return detected_waf
                else:
                    if verbose:
                        logger.debug(set_color(
                            "wafw00f did not detect any WAF", level=10
                        ))
                    return None
            else:
                return None
                
        except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
            if verbose:
                logger.debug(set_color(
                    "failed to parse wafw00f output: {}".format(str(e)), level=10
                ))
            # Clean up temp file if it exists
            if os.path.exists(temp_file.name):
                os.unlink(temp_file.name)
            return None
            
    except subprocess.TimeoutExpired:
        logger.warning(set_color(
            "wafw00f detection timed out after 30 seconds", level=30
        ))
        if os.path.exists(temp_file.name):
            os.unlink(temp_file.name)
        return None
        
    except FileNotFoundError:
        logger.error(set_color(
            "wafw00f is not installed. Install it with one of the following methods:", level=40
        ))
        logger.info(set_color(
            "  - Debian/Ubuntu: sudo apt install wafw00f", level=25
        ))
        logger.info(set_color(
            "  - From source: git clone https://github.com/EnableSecurity/wafw00f.git && cd wafw00f && sudo python setup.py install", level=25
        ))
        logger.info(set_color(
            "  - Pip (if available): pip install git+https://github.com/EnableSecurity/wafw00f.git", level=25
        ))
        return None
        
    except Exception as e:
        logger.warning(set_color(
            "wafw00f detection failed: {}".format(str(e)), level=30
        ))
        if os.path.exists(temp_file.name):
            os.unlink(temp_file.name)
        return None
