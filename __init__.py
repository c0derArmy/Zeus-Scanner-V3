"""
Zeus Scanner - Advanced Web Vulnerability Assessment Tool

A comprehensive security testing framework that combines automated reconnaissance
with advanced exploitation capabilities for web application security assessment.

Author: Zeus Scanner Team
License: GPL-3.0
Version: 1.5.2
"""

__title__ = "zeus-scanner"
__version__ = "1.5.2"
__author__ = "Dark x Devil"
__license__ = "GPL-3.0"
__copyright__ = "Copyright 2025 Zeus Scanner Project"

# Package metadata
__all__ = [
    "__title__",
    "__version__", 
    "__author__",
    "__license__",
    "__copyright__"
]

# Version info tuple
VERSION = (1, 5, 2)

def get_version():
    """Return the version string"""
    return __version__

def get_banner():
    """Return the Zeus Scanner ASCII banner"""
    return r"""
    __          __________                             __   
   / /          \____    /____  __ __  ______          \ \  
  / /    ______   /     // __ \|  |  \/  ___/  ______   \ \ 
  \ \   /_____/  /     /\  ___/|  |  /\___ \  /_____/   / / 
   \_\          /_______ \___  >____//____  >          /_/  
                       \/   \/           \/  v{version}
                https://github.com/shiva345-star/zeus-scanner
                    Advanced Reconnaissance & Exploitation
""".format(version=__version__)

def get_info():
    """Return package information"""
    return {
        "name": __title__,
        "version": __version__,
        "author": __author__, 
        "license": __license__,
        "copyright": __copyright__
    }
