import json
import requests
from typing import Optional, Dict, List, Any
from lib.core.settings import logger, set_color


class FreeAIAnalyzer:
    """
    Free AI-powered vulnerability analyzer using Ollama (local) or Groq (free tier).
    No API costs - fully local or free API access.
    """

    OLLAMA_DEFAULT_URL = "http://localhost:11434"
    OLLAMA_DEFAULT_MODEL = "llama3.2"
    
    GROQ_BASE_URL = "https://api.groq.com/openai/v1"
    GROQ_DEFAULT_MODEL = "llama-3.3-70b-versatile"
    GROQ_API_KEY_ENV = "GROQ_API_KEY"

    def __init__(self, provider: str = "ollama", model: Optional[str] = None,
                 ollama_url: Optional[str] = None):
        self.provider = provider.lower()
        self.model = model
        self.ollama_url = ollama_url or self.OLLAMA_DEFAULT_URL
        
        if self.provider == "ollama":
            self._setup_ollama()
        elif self.provider == "groq":
            self._setup_groq()
        else:
            raise ValueError(f"Unknown provider: {provider}. Use 'ollama' or 'groq'")

    def _setup_ollama(self):
        self.model = self.model or self.OLLAMA_DEFAULT_MODEL
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get("models", [])
                available = [m["name"] for m in models]
                if self.model not in available:
                    logger.warning(set_color(
                        f"Model '{self.model}' not found. Available: {available}", level=30
                    ))
                logger.info(set_color(
                    f"Ollama connected with {len(available)} models available", level=25
                ))
            else:
                logger.warning(set_color(
                    "Ollama server not responding correctly", level=30
                ))
        except requests.exceptions.ConnectionError:
            logger.error(set_color(
                f"Cannot connect to Ollama at {self.ollama_url}. "
                f"Start Ollama: `ollama serve`", level=40
            ))
        except Exception as e:
            logger.error(set_color(f"Ollama setup error: {e}", level=40))

    def _setup_groq(self):
        import os
        self.model = self.model or self.GROQ_DEFAULT_MODEL
        api_key = os.environ.get(self.GROQ_API_KEY_ENV)
        
        if not api_key:
            logger.warning(set_color(
                f"Groq API key not set. Set GROQ_API_KEY environment variable. "
                f"Get free key at https://console.groq.com/keys", level=30
            ))
        else:
            logger.info(set_color(
                "Groq API configured (free tier available)", level=25
            ))
        self.api_key = api_key

    def generate_payload(self, url: str, vuln_type: str, parameter: str, 
                         context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Use AI to generate context-aware payloads for a specific parameter.
        """
        prompt = f"""You are an advanced penetration tester. Generate payloads for:

URL: {url}
Parameter: {parameter}
Vulnerability Type: {vuln_type}
Target Context: {json.dumps(context, indent=2)}

Tasks:
1. Analyze the context (tech stack, parameter location, detected WAF/filters).
2. Generate 5 highly effective, unique payloads designed to bypass common security filters.
3. For each payload, provide a description and the bypass technique used.

Respond in JSON format:
{{
  "payloads": [
    {{
      "payload": "the_payload",
      "description": "what it tests",
      "bypass_technique": "explanation of filter bypass"
    }}
  ]
}}
Only respond with valid JSON."""

        try:
            if self.provider == "ollama":
                result = self._query_ollama(prompt)
            else:
                result = self._query_groq(prompt)
            
            data = self._parse_json(result)
            return data.get("payloads", [])
        except Exception as e:
            logger.error(set_color(f"Payload generation failed: {e}", level=40))
            return []

    def analyze_web_response(self, request_info: Dict[str, Any], 
                             response_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        In-depth AI analysis of an HTTP transaction to detect vulnerabilities.
        """
        prompt = f"""You are an expert vulnerability analyzer. Review this HTTP transaction:

REQUEST:
{json.dumps(request_info, indent=2)}

RESPONSE:
Status: {response_info.get('status')}
Headers: {json.dumps(response_info.get('headers', {}), indent=2)}
Body (Preview): {response_info.get('body_preview', '')[:1500]}

Tasks:
1. Determine if the payload in the request was successfully executed.
2. Look for reflections, SQL errors, timing differences, or unexpected behavior.
3. Identify any WAF blocking or filtering patterns.

Respond in JSON format:
{{
  "vulnerable": true/false,
  "confidence": "high/medium/low",
  "evidence": "detailed explanation of findings",
  "waf_detected": true/false,
  "waf_name": "name if known",
  "next_step_suggestion": "what to try next if failed (e.g., 'try double encoding')"
}}
Only respond with valid JSON."""

        try:
            if self.provider == "ollama":
                result = self._query_ollama(prompt)
            else:
                result = self._query_groq(prompt)
            
            return self._parse_json(result)
        except Exception as e:
            logger.error(set_color(f"Response analysis failed: {e}", level=40))
            return {"vulnerable": False, "confidence": "low", "error": str(e)}

    def _query_ollama(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 512
            }
        }
        response = requests.post(
            f"{self.ollama_url}/api/generate",
            json=payload,
            timeout=60
        )
        response.raise_for_status()
        return response.json().get("response", "")

    def _query_groq(self, prompt: str) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "max_tokens": 512
        }
        
        # Retry logic for rate limits (429)
        import time
        max_retries = 3
        for i in range(max_retries):
            response = requests.post(
                f"{self.GROQ_BASE_URL}/chat/completions",
                headers=headers,
                json=payload,
                timeout=60
            )
            if response.status_code == 429:
                wait = (i + 1) * 5
                logger.warning(set_color(f"Groq Rate Limit (429). Retrying in {wait}s...", level=30))
                time.sleep(wait)
                continue
            
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
            
        return ""

    def analyze(self, prompt: str) -> str:
        """Unified entry point for AI queries."""
        try:
            if self.provider == "ollama":
                return self._query_ollama(prompt)
            else:
                return self._query_groq(prompt)
        except Exception as e:
            logger.error(f"AI Query Error: {e}")
            return ""

    def _parse_json(self, response: str) -> Dict[str, Any]:
        """Helper to extract JSON from AI response."""
        try:
            json_start = response.find("{")
            json_end = response.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                return json.loads(response[json_start:json_end])
        except json.JSONDecodeError:
            logger.debug(f"JSON Parse Error. Raw response: {response}")
        return {}

    def _fallback_analysis(self, vuln_type: str, 
                           evidence: Dict[str, Any]) -> Dict[str, Any]:
        severity_map = {
            "sql_injection": {"severity": "critical", "cvss": 9.8},
            "xss": {"severity": "high", "cvss": 7.5},
            "lfi": {"severity": "high", "cvss": 8.2},
            "rce": {"severity": "critical", "cvss": 10.0},
            "csrf": {"severity": "medium", "cvss": 6.5},
            "idor": {"severity": "medium", "cvss": 6.5},
        }
        defaults = severity_map.get(vuln_type.lower(), 
                                   {"severity": "info", "cvss": 5.0})
        
        return {
            "severity": defaults["severity"],
            "cvss_score": defaults["cvss"],
            "description": f"Potential {vuln_type} vulnerability detected",
            "impact": "Requires manual verification",
            "remediation": "Review and implement security controls",
            "is_false_positive": False,
            "cwe_id": "CWE-OTHER"
        }

    @staticmethod
    def check_ollama_running(url: str = OLLAMA_DEFAULT_URL) -> bool:
        """Check if Ollama server is running."""
        try:
            response = requests.get(f"{url}/api/tags", timeout=3)
            return response.status_code == 200
        except:
            return False

    @staticmethod
    def get_available_models(url: str = OLLAMA_DEFAULT_URL) -> List[str]:
        """Get list of available Ollama models."""
        try:
            response = requests.get(f"{url}/api/tags", timeout=5)
            if response.status_code == 200:
                return [m["name"] for m in response.json().get("models", [])]
        except:
            pass
        return []


def create_ai_analyzer(provider: str = "ollama", model: Optional[str] = None,
                       ollama_url: Optional[str] = None) -> Optional[FreeAIAnalyzer]:
    """Factory function to create AI analyzer with automatic fallback."""
    try:
        analyzer = FreeAIAnalyzer(provider=provider, model=model, ollama_url=ollama_url)
        logger.info(set_color(
            f"AI Analyzer initialized: {provider}/{analyzer.model}", level=25
        ))
        return analyzer
    except Exception as e:
        logger.error(set_color(f"Failed to initialize AI analyzer: {e}", level=40))
        return None
