#!/usr/bin/env python3
"""
Zeus Scanner - Command Line Interface

This module provides the main entry point for Zeus Scanner when installed as a package.
"""

import os
import sys
import subprocess
from pathlib import Path

def print_banner():
    """Print the Zeus Scanner banner"""
    print(r"""
    __          __________                             __   
   / /          \____    /____  __ __  ______          \ \  
  / /    ______   /     // __ \|  |  \/  ___/  ______   \ \ 
  \ \   /_____/  /     /\  ___/|  |  /\___ \  /_____/   / / 
   \_\          /_______ \___  >____//____  >          /_/  
                       \/   \/           \/  v1.5.2
                https://github.com/shiva345-star/zeus-scanner
                    Advanced Reconnaissance & Exploitation
    """)

def main():
    """Main entry point for Zeus Scanner CLI"""
    original_argv = None
    
    try:
        # Find Zeus Scanner installation directory
        package_dir = Path(__file__).parent.absolute()
        zeus_script = package_dir / "zeus.py"
        
        # Store original argv
        original_argv = sys.argv[:]
        
        # If zeus.py exists in current package directory, use it
        if zeus_script.exists():
            # Add package directory to Python path
            if str(package_dir) not in sys.path:
                sys.path.insert(0, str(package_dir))
            
            # Import and run zeus main
            try:
                import zeus
                # Set up argv for zeus.py
                sys.argv[0] = "zeus-scanner"
                
                # Check if it has main function
                if hasattr(zeus, 'main') and callable(zeus.main):
                    return zeus.main()
                else:
                    # Try to execute the module
                    exec(open(zeus_script).read())
                    return 0
            except Exception as e:
                print(f"Error running Zeus Scanner: {e}")
                return 1
        else:
            # Fallback: try to run zeus.py from different locations
            possible_locations = [
                str(package_dir.parent / "zeus.py"),  # Parent directory
                str(package_dir.parent / "Desktop" / "Zeus-Scanner" / "zeus.py"), # Desktop location
                "/usr/local/bin/zeus.py",
                "/usr/bin/zeus.py", 
                str(Path.home() / ".local" / "bin" / "zeus.py"),
                "zeus.py"
            ]
            
            for location in possible_locations:
                if os.path.exists(location):
                    cmd = [sys.executable, location] + sys.argv[1:]
                    return subprocess.run(cmd).returncode
            
            # If no zeus.py found, show help message
            print("Zeus Scanner - Advanced Web Vulnerability Assessment Tool")
            print_banner()
            print("Error: Zeus Scanner main script not found.")
            print("Please ensure Zeus Scanner is properly installed.")
            print("\nTry running from the Zeus Scanner directory:")
            print("  cd /path/to/zeus-scanner")
            print("  python3 zeus.py [options]")
            return 1
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        return 130
    except Exception as e:
        print(f"Error: {e}")
        return 1
    finally:
        # Restore original sys.argv if it was modified
        if original_argv:
            sys.argv = original_argv

if __name__ == "__main__":
    sys.exit(main())
