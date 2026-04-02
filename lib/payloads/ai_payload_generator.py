"""
AI-Powered Payload Generator - No Hardcoded Payloads
Uses AI to generate intelligent payloads based on detected vulnerabilities
"""

import json
import re
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from lib.core.settings import logger, set_color


class AIPayloadGenerator:
    def __init__(self, ai_analyzer=None):
        self.ai_analyzer = ai_analyzer
        self.context_patterns = {
            'html_tag': self._generate_html_tag_payloads,
            'html_attribute': self._generate_html_attribute_payloads,
            'javascript': self._generate_javascript_payloads,
            'url': self._generate_url_payloads,
            'sql': self._generate_sql_payloads,
            'command': self._generate_command_payloads,
            'ssrf': self._generate_ssrf_payloads,
            'xxe': self._generate_xxe_payloads,
        }
    
    def _generate_html_tag_payloads(self, context: Dict) -> List[str]:
        prompt = f"""Generate XSS payloads for HTML tag context.
Target: {context.get('target', 'unknown')}
Tag: {context.get('tag', 'div')}
Existing filters: {context.get('filters', [])}

Generate 5 unique XSS payloads that would work in this context.
Return ONLY JSON array of payloads, nothing else."""

        return self._get_ai_payloads(prompt)
    
    def _generate_html_attribute_payloads(self, context: Dict) -> List[str]:
        prompt = f"""Generate XSS payloads for HTML attribute context.
Attribute: {context.get('attribute', 'value')}
Tag: {context.get('tag', 'input')}
Event handlers allowed: {context.get('allowed_events', [])}

Generate 5 unique XSS payloads for attribute injection.
Return ONLY JSON array of payloads, nothing else."""

        return self._get_ai_payloads(prompt)
    
    def _generate_javascript_payloads(self, context: Dict) -> List[str]:
        prompt = f"""Generate XSS payloads for JavaScript context.
Context: {context.get('context', 'string')}
Quote type: {context.get('quote', 'single')}

Generate 5 unique XSS payloads that execute JavaScript.
Return ONLY JSON array of payloads, nothing else."""

        return self._get_ai_payloads(prompt)
    
    def _generate_url_payloads(self, context: Dict) -> List[str]:
        prompt = f"""Generate payloads for URL parameter injection.
Parameter: {context.get('parameter', 'url')}
Expected format: {context.get('expected_format', 'url')}

Generate 5 unique payloads for URL injection attacks (SSRF, redirect, etc).
Return ONLY JSON array of payloads, nothing else."""

        return self._get_ai_payloads(prompt)
    
    def _generate_sql_payloads(self, context: Dict) -> List[str]:
        prompt = f"""Generate SQL injection payloads.
Parameter: {context.get('parameter', 'id')}
DBMS target: {context.get('dbms', 'unknown')}
Context: {context.get('sql_context', 'number')}

Generate 5 unique SQL injection payloads.
Return ONLY JSON array of payloads, nothing else."""

        return self._get_ai_payloads(prompt)
    
    def _generate_command_payloads(self, context: Dict) -> List[str]:
        prompt = f"""Generate command injection payloads.
Parameter: {context.get('parameter', 'host')}
OS: {context.get('os', 'linux')}
Context: {context.get('context', 'ping')}

Generate 5 unique command injection payloads.
Return ONLY JSON array of payloads, nothing else."""

        return self._get_ai_payloads(prompt)
    
    def _generate_ssrf_payloads(self, context: Dict) -> List[str]:
        prompt = f"""Generate SSRF (Server-Side Request Forgery) payloads.
Parameter: {context.get('parameter', 'url')}
Allowed protocols: {context.get('allowed_protocols', ['http', 'https'])}

Generate 5 unique SSRF payloads for testing.
Return ONLY JSON array of payloads, nothing else."""

        return self._get_ai_payloads(prompt)
    
    def _generate_xxe_payloads(self, context: Dict) -> List[str]:
        prompt = f"""Generate XXE (XML External Entity) injection payloads.
Parameter: {context.get('parameter', 'xml')}
Context: {context.get('xml_context', 'xml_data')}

Generate 5 unique XXE payloads.
Return ONLY JSON array of payloads, nothing else."""

        return self._get_ai_payloads(prompt)
    
    def _get_ai_payloads(self, prompt: str) -> List[str]:
        if not self.ai_analyzer:
            logger.warning(set_color("AI analyzer not available, returning empty payloads", level=30))
            return []
        
        try:
            response = self.ai_analyzer.analyze(prompt)
            
            payloads = self._extract_payloads_from_response(response)
            
            return payloads
        except Exception as e:
            logger.warning(set_color(f"AI payload generation error: {str(e)}", level=30))
            return []
    
    def _extract_payloads_from_response(self, response: Any) -> List[str]:
        if isinstance(response, str):
            try:
                data = json.loads(response)
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict) and 'payloads' in data:
                    return data['payloads']
            except json.JSONDecodeError:
                pass
            
            match = re.search(r'\[.*\]', response, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass
        
        elif isinstance(response, list):
            return response
        elif isinstance(response, dict) and 'payloads' in response:
            return response['payloads']
        
        return []
    
    def analyze_context(self, url: str, param: str, response: str) -> str:
        if not self.ai_analyzer:
            return 'unknown'
        
        prompt = f"""Analyze this HTTP response to determine the injection context.

URL: {url}
Parameter: {param}
Response snippet: {response[:500]}

Determine the context type:
- html_tag: Payload injects inside an HTML tag
- html_attribute: Payload injects into an HTML attribute value
- javascript: Payload injects into JavaScript code
- url: Payload injects into a URL parameter
- sql: Payload is used for SQL injection
- command: Payload is used for command injection
- ssrf: Payload is used for SSRF
- xxe: Payload is used for XXE injection

Return ONLY the context type, nothing else."""

        try:
            context = self.ai_analyzer.analyze(prompt)
            context = context.strip().lower()
            
            if context in self.context_patterns:
                return context
            return 'unknown'
        except Exception as e:
            logger.warning(set_color(f"Context analysis error: {str(e)}", level=30))
            return 'unknown'
    
    def generate_payloads(self, vulnerability_type: str, context: Dict) -> List[str]:
        if vulnerability_type not in self.context_patterns:
            logger.warning(set_color(
                f"Unknown vulnerability type: {vulnerability_type}", level=30
            ))
            return []
        
        generator = self.context_patterns[vulnerability_type]
        payloads = generator(context)
        
        logger.info(set_color(
            f"AI generated {len(payloads)} payloads for {vulnerability_type}",
            level=25
        ))
        
        return payloads
    
    def mutate_payload(self, payload: str, mutation_type: str = 'all') -> List[str]:
        if not self.ai_analyzer:
            return []
        
        mutation_prompts = {
            'encoding': f"""Mutate this payload using various encoding techniques:
{payload}

Mutate using: URL encoding, HTML encoding, Unicode encoding, Base64, Hex encoding.
Return JSON array of mutated payloads.""",

            'case': f"""Mutate this payload using case manipulation:
{payload}

Generate versions with mixed case, uppercase, lowercase variations.
Return JSON array of mutated payloads.""",

            'bypass': f"""Mutate this payload to bypass WAF/filters:
{payload}

Generate versions that bypass common WAF rules and filters.
Return JSON array of mutated payloads.""",

            'all': f"""Mutate this payload using all available techniques:
{payload}

Include: encoding variations, case manipulation, WAF bypass, comment insertion, etc.
Return JSON array of unique mutated payloads."""
        }
        
        prompt = mutation_prompts.get(mutation_type, mutation_prompts['all'])
        
        try:
            response = self.ai_analyzer.analyze(prompt)
            return self._extract_payloads_from_response(response)
        except Exception as e:
            logger.warning(set_color(f"Payload mutation error: {str(e)}", level=30))
            return []
    
    def suggest_mitigation(self, vulnerability_type: str, context: Dict) -> List[str]:
        if not self.ai_analyzer:
            return ["Input validation recommended", "Use parameterized queries", 
                    "Implement output encoding"]
        
        prompt = f"""Suggest mitigation strategies for this vulnerability:
Type: {vulnerability_type}
Context: {json.dumps(context)}

Provide 5 specific mitigation recommendations.
Return JSON array of recommendations."""

        try:
            response = self.ai_analyzer.analyze(prompt)
            
            if isinstance(response, list):
                return response
            elif isinstance(response, str):
                return [r.strip() for r in response.split('\n') if r.strip()]
            return []
        except Exception as e:
            logger.warning(set_color(f"Mitigation suggestion error: {str(e)}", level=30))
            return []


def get_payload_generator(ai_analyzer=None) -> AIPayloadGenerator:
    return AIPayloadGenerator(ai_analyzer=ai_analyzer)
