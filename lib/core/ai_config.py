# AI Configuration and Key Management

import os
from lib.core.settings import logger, set_color

class AIConfig:
    """Manages AI configuration and API keys securely."""
    
    _config = {}

    @classmethod
    def setup(cls):
        """Loads configuration from environment variables."""
        # Check environment variables
        cls._config['OPENAI_API_KEY'] = os.environ.get('OPENAI_API_KEY', '')
        cls._config['GEMINI_API_KEY'] = os.environ.get('GEMINI_API_KEY', '')
        
        # Could also load from a zeus.conf file here if needed
    
    @classmethod
    def get_api_key(cls, provider="openai"):
        """Get the API key for the specified provider."""
        if not cls._config:
            cls.setup()
            
        key_name = f"{provider.upper()}_API_KEY"
        key = cls._config.get(key_name, '')
        
        if not key:
            logger.warning(set_color(
                f"No API key found for {provider}. Some AI features may not work. Set {key_name} in environment.", 
                level=30
            ))
            
        return key

