import os
import json
from typing import Dict, Any, Optional
from lib.core.settings import logger, set_color

class AIConfigManager:
    """Manages AI configuration, providers, and models."""
    
    CONFIG_FILE = "etc/ai_config.json"
    
    DEFAULT_CONFIG = {
        "provider": "ollama",
        "model": "llama3.2",
        "groq_api_key": "",
        "ollama_url": "http://localhost:11434"
    }

    def __init__(self):
        self.config = self.load_config()

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file or use defaults."""
        if os.path.exists(self.CONFIG_FILE):
            try:
                with open(self.CONFIG_FILE, 'r') as f:
                    return {**self.DEFAULT_CONFIG, **json.load(f)}
            except Exception as e:
                logger.error(set_color(f"Error loading AI config: {e}", level=40))
        
        # Check environment variables
        config = self.DEFAULT_CONFIG.copy()
        if os.environ.get("GROQ_API_KEY"):
            config["groq_api_key"] = os.environ.get("GROQ_API_KEY")
            config["provider"] = "groq"
            config["model"] = "llama-3.3-70b-versatile"
        
        return config

    def save_config(self, config: Dict[str, Any]):
        """Save configuration to file."""
        try:
            os.makedirs(os.path.dirname(self.CONFIG_FILE), exist_ok=True)
            with open(self.CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            self.config = config
        except Exception as e:
            logger.error(set_color(f"Error saving AI config: {e}", level=40))

    def get_provider(self) -> str:
        return self.config.get("provider", "ollama")

    def get_model(self) -> str:
        return self.config.get("model", "llama3.2")

    def get_groq_key(self) -> str:
        return self.config.get("groq_api_key", "")

    def get_ollama_url(self) -> str:
        return self.config.get("ollama_url", "http://localhost:11434")

    @classmethod
    def setup_interactive(cls):
        """Setup AI configuration interactively."""
        print(set_color("\n[ AI CONFIGURATION SETUP ]", level=25))
        
        config = cls.DEFAULT_CONFIG.copy()
        
        provider = input(f"Select AI Provider (ollama/groq) [default: {config['provider']}]: ").strip().lower()
        if provider:
            config["provider"] = provider
            
        if config["provider"] == "ollama":
            url = input(f"Ollama URL [default: {config['ollama_url']}]: ").strip()
            if url:
                config["ollama_url"] = url
            
            model = input(f"Ollama Model [default: {config['model']}]: ").strip()
            if model:
                config["model"] = model
        else:
            key = input("Groq API Key: ").strip()
            if key:
                config["groq_api_key"] = key
            
            model = input("Groq Model [default: llama-3.3-70b-versatile]: ").strip()
            if model:
                config["model"] = model
            else:
                config["model"] = "llama-3.3-70b-versatile"

        manager = cls()
        manager.save_config(config)
        print(set_color("\n[+] Configuration saved to " + cls.CONFIG_FILE, level=25))
