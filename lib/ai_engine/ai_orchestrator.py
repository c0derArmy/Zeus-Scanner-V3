import json
from typing import Dict, List, Any, Optional
from .enhanced_ai_engine import EnhancedAIEngine
from .free_ai_analyzer import FreeAIAnalyzer
from lib.payloads.ai_payload_generator import get_payload_generator
from lib.core.settings import logger, set_color

class StrategicPlanner:
    """AI-driven strategic planner for vulnerability assessments."""
    def __init__(self, analyzer: FreeAIAnalyzer):
        self.analyzer = analyzer

    def plan_attack_strategy(self, target_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        AI decides which vulnerability types to test based on reconnaissance data.
        """
        prompt = f"""You are a Strategic Pentesting Planner. Analyze this target:

Target: {target_info.get('target')}
Technologies: {json.dumps(target_info.get('technologies', []))}
Security Headers: {json.dumps(target_info.get('security_headers_missing', []))}
Info Leaks: {json.dumps(target_info.get('information_leaks', []))}

Tasks:
1. Identify the most likely high-impact vulnerability types for this specific stack.
2. Prioritize testing areas (e.g., 'focus on SQLi in login', 'check XSS in search').
3. Suggest a sequence of testing.

Respond in JSON format:
{{
  "prioritized_tests": [
    {{
      "type": "vulnerability_type",
      "reason": "why this is high priority",
      "priority": 1-5
    }}
  ],
  "general_strategy": "overall approach"
}}
Only respond with valid JSON."""

        try:
            result = self.analyzer.analyze(prompt)
            
            return self.analyzer._parse_json(result).get("prioritized_tests", [])
        except Exception as e:
            logger.error(set_color(f"Strategic planning failed: {e}", level=40))
            return []

class AIOrchestrator:
    """
    Main orchestrator for AI-powered autonomous pentesting.
    Matches the signature expected by zeus.py while providing advanced AI capabilities.
    """
    
    def __init__(self, target_url: str, provider: str = "ollama", 
                 model: Optional[str] = None, verbose: bool = False):
        self.target_url = target_url
        self.verbose = verbose
        
        # Initialize AI components
        self.analyzer = FreeAIAnalyzer(provider=provider, model=model)
        self.static_engine = EnhancedAIEngine()
        self.planner = StrategicPlanner(self.analyzer)
        self.payload_gen = get_payload_generator(self.analyzer)
        
        self.recon_data = {}
        self.attack_plan = []
        self.findings = []

    def perform_recon(self) -> Dict[str, Any]:
        """Perform combined static and AI reconnaissance."""
        logger.info(set_color(f"[*] Starting AI-enhanced reconnaissance on {self.target_url}", level=25))
        
        # Static analysis first
        self.recon_data = self.static_engine.analyze_target(self.target_url)
        
        # Get AI strategic plan
        self.attack_plan = self.planner.plan_attack_strategy(self.recon_data)
        
        return self.recon_data

    def generate_contextual_payloads(self, vuln_type: str, parameter: str, 
                                    context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate payloads dynamically based on target context."""
        # Map broad types to specialized generators
        VULN_MAP = {
            'sqli': 'sql',
            'sql_injection': 'sql',
            'xss': 'html_tag',
            'lfi': 'url',
            'rce': 'command',
            'command_injection': 'command',
            'ssrf': 'ssrf',
            'xxe': 'xxe'
        }
        
        target_type = VULN_MAP.get(vuln_type.lower(), 'sql') # Default to sql if unknown
        
        # Use specialized generator for context-aware payloads
        raw_payloads = self.payload_gen.generate_payloads(target_type, context)
        
        # Fallback to generic AI generator if raw_payloads is empty
        if not raw_payloads:
            logger.info(set_color(f"[-] Specialized {target_type} generation failed, using generic model...", level=30))
            raw_payloads_dict = self.analyzer.generate_payload(self.target_url, vuln_type, parameter, context)
            raw_payloads = [p.get('payload') for p in raw_payloads_dict if p.get('payload')]

        # Format for use in ZeusAIAgent
        return [{"payload": p, "description": f"AI-generated {vuln_type} test", "bypass_technique": "dynamic"} 
                for p in raw_payloads]

    def analyze_test_result(self, request_info: Dict[str, Any], 
                            response_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a test result using AI."""
        return self.analyzer.analyze_web_response(request_info, response_info)
