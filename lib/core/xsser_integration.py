import subprocess
import os
import tempfile
import json

from lib.core.settings import logger, set_color


def run_xsser_scan(url, **kwargs):
    """
    Run XSS scan using XSSer tool
    """
    verbose = kwargs.get("verbose", False)
    proxy = kwargs.get("proxy", None)
    xsser_args = kwargs.get("xsser_args", None)
    batch = kwargs.get("batch", False)
    
    try:
        if verbose:
            logger.debug(set_color(
                "using XSSer for XSS vulnerability scanning", level=10
            ))
        
        # Build base XSSer command
        cmd = ['xsser', '-u', url]
        
        # Add automatic mode
        cmd.append('--auto')
        
        # Add proxy if provided
        if proxy:
            cmd.extend(['--proxy', proxy])
        
        # Parse and add custom XSSer arguments if provided
        if xsser_args:
            if verbose:
                logger.debug(set_color(
                    "parsing custom XSSer arguments: '{}'".format(xsser_args), level=10
                ))
            
            # Parse arguments (comma or pipe separated)
            if ',' in xsser_args:
                args_list = [arg.strip() for arg in xsser_args.split(',')]
            elif '|' in xsser_args:
                args_list = [arg.strip() for arg in xsser_args.split('|')]
            else:
                args_list = [xsser_args.strip()]
            
            # Add each argument
            for arg in args_list:
                if arg:
                    if not arg.startswith('-'):
                        arg = '--' + arg if len(arg) > 1 else '-' + arg
                    
                    # Handle arguments with values (e.g., "timeout=30" or "-timeout 30")
                    if '=' in arg:
                        key, value = arg.split('=', 1)
                        cmd.append(key.strip())
                        cmd.append(value.strip())
                    elif ' ' in arg:
                        parts = arg.split(' ', 1)
                        cmd.extend([p.strip() for p in parts])
                    else:
                        cmd.append(arg)
        
        if verbose:
            logger.debug(set_color(
                "running command: {}".format(' '.join(cmd)), level=10
            ))
        
        logger.info(set_color(
            "starting XSSer vulnerability scan on '{}'".format(url)
        ))
        
        # Create temporary output file
        temp_output = tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False)
        temp_output.close()
        
        # Add output file to command
        cmd.extend(['--save', temp_output.name])
        
        # Run XSSer
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,  # 5 minutes timeout
            universal_newlines=True
        )
        
        # Parse output
        vulnerabilities_found = False
        xss_count = 0
        
        if result.returncode == 0 or result.returncode == 1:
            # Check stdout for XSS findings
            output = result.stdout
            
            if 'XSS FOUND!' in output or 'Vector found!' in output:
                vulnerabilities_found = True
                # Count XSS vectors
                xss_count = output.count('XSS FOUND!')
                if xss_count == 0:
                    xss_count = output.count('Vector found!')
            
            # Try to read the save file if it exists
            if os.path.exists(temp_output.name) and os.path.getsize(temp_output.name) > 0:
                with open(temp_output.name, 'r') as f:
                    saved_output = f.read()
                    if 'XSS' in saved_output.upper():
                        vulnerabilities_found = True
            
            # Clean up temp file
            try:
                os.unlink(temp_output.name)
            except:
                pass
            
            if vulnerabilities_found:
                logger.warning(set_color(
                    "XSS vulnerability detected! Found {} potential XSS vector(s)".format(xss_count if xss_count > 0 else 'multiple'),
                    level=35
                ))
                if verbose and output:
                    logger.debug(set_color(
                        "XSSer output:\n{}".format(output[:500]), level=10
                    ))
                return {'vulnerable': True, 'count': xss_count}
            else:
                logger.info(set_color(
                    "no XSS vulnerabilities detected on target", level=25
                ))
                return {'vulnerable': False, 'count': 0}
        else:
            logger.warning(set_color(
                "XSSer scan completed with warnings (exit code: {})".format(result.returncode), level=30
            ))
            # Clean up temp file
            try:
                os.unlink(temp_output.name)
            except:
                pass
            return {'vulnerable': False, 'count': 0}
            
    except subprocess.TimeoutExpired:
        logger.warning(set_color(
            "XSSer scan timed out after 5 minutes", level=30
        ))
        try:
            os.unlink(temp_output.name)
        except:
            pass
        return None
        
    except FileNotFoundError:
        logger.error(set_color(
            "XSSer is not installed. Install it with one of the following methods:", level=40
        ))
        logger.info(set_color(
            "  - Debian/Ubuntu: sudo apt install xsser", level=25
        ))
        logger.info(set_color(
            "  - From source: git clone https://github.com/epsylon/xsser.git && cd xsser && sudo python setup.py install", level=25
        ))
        logger.info(set_color(
            "  - Note: XSSer requires Python 3.12 or earlier due to cgi module deprecation", level=25
        ))
        return None
        
    except Exception as e:
        logger.warning(set_color(
            "XSSer scan failed: {}".format(str(e)), level=30
        ))
        try:
            os.unlink(temp_output.name)
        except:
            pass
        return None
