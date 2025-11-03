"""
Zeus Scanner Integration Module
Provides integration with AI-powered penetration testing tools
"""

# REMOVED: ZAP, Burp, and Metasploit integrations (causing errors/hanging)
# from .zap_integration import ZAPIntegration
# from .burp_integration import BurpIntegration  
# from .metasploit_integration import MetasploitIntegration

from .ai_orchestrator import EnhancedAIOrchestrator
from .nuclei_integration import NucleiIntegration
# REMOVED: Wapiti and Nikto integrations
# from .wapiti_integration import WapitiIntegration
# from .nikto_integration import NiktoIntegration
# REMOVED: AutoRecon integration (files deleted)
# from .autorecon_integration import AutoReconIntegration

__all__ = [
    'EnhancedAIOrchestrator',
    'NucleiIntegration',
]