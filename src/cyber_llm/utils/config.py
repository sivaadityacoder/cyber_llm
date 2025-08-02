"""
Configuration management for the cyber_llm framework.

This module provides centralized configuration management with support for
environment variables, configuration files, and default settings.
"""

import os
import json
from typing import Any, Dict, Optional, Union, List
from pathlib import Path
from dataclasses import dataclass

# Try to load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # dotenv not available, skip loading .env file
    pass


@dataclass
class SecurityConfig:
    """Security-related configuration."""
    max_input_length: int = 10000
    max_output_length: int = 5000
    rate_limit_requests: int = 100
    rate_limit_window: int = 3600  # 1 hour
    sanitization_level: str = "moderate"
    enable_monitoring: bool = True
    log_level: str = "INFO"


@dataclass
class APIConfig:
    """API-related configuration."""
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    cors_origins: list = None
    api_key_required: bool = True
    
    def __post_init__(self):
        if self.cors_origins is None:
            self.cors_origins = ["http://localhost:3000", "http://localhost:8080"]


@dataclass
class LLMConfig:
    """LLM provider configuration."""
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    default_provider: str = "openai"
    default_model: str = "gpt-3.5-turbo"
    max_tokens: int = 1000
    temperature: float = 0.7
    timeout: int = 30


class Config:
    """
    Central configuration management for the cyber_llm framework.
    
    This class handles loading configuration from multiple sources:
    1. Environment variables
    2. Configuration files
    3. Default values
    """
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration.
        
        Args:
            config_file: Optional path to configuration file
        """
        self.config_file = config_file
        self._load_config()
    
    def _load_config(self):
        """Load configuration from various sources."""
        # Start with defaults
        self.security = SecurityConfig()
        self.api = APIConfig()
        self.llm = LLMConfig()
        
        # Load from file if provided
        if self.config_file and os.path.exists(self.config_file):
            self._load_from_file()
        
        # Override with environment variables
        self._load_from_env()
    
    def _load_from_file(self):
        """Load configuration from file."""
        try:
            with open(self.config_file, 'r') as f:
                if self.config_file.endswith('.json'):
                    config_data = json.load(f)
                else:
                    # Assume YAML (would need PyYAML)
                    import yaml
                    config_data = yaml.safe_load(f)
            
            # Update security config
            if 'security' in config_data:
                for key, value in config_data['security'].items():
                    if hasattr(self.security, key):
                        setattr(self.security, key, value)
            
            # Update API config
            if 'api' in config_data:
                for key, value in config_data['api'].items():
                    if hasattr(self.api, key):
                        setattr(self.api, key, value)
            
            # Update LLM config
            if 'llm' in config_data:
                for key, value in config_data['llm'].items():
                    if hasattr(self.llm, key):
                        setattr(self.llm, key, value)
                        
        except Exception as e:
            print(f"Warning: Could not load config file {self.config_file}: {e}")
    
    def _load_from_env(self):
        """Load configuration from environment variables."""
        # Security settings
        self.security.max_input_length = int(os.getenv('CYBER_LLM_MAX_INPUT_LENGTH', self.security.max_input_length))
        self.security.max_output_length = int(os.getenv('CYBER_LLM_MAX_OUTPUT_LENGTH', self.security.max_output_length))
        self.security.rate_limit_requests = int(os.getenv('CYBER_LLM_RATE_LIMIT_REQUESTS', self.security.rate_limit_requests))
        self.security.rate_limit_window = int(os.getenv('CYBER_LLM_RATE_LIMIT_WINDOW', self.security.rate_limit_window))
        self.security.sanitization_level = os.getenv('CYBER_LLM_SANITIZATION_LEVEL', self.security.sanitization_level)
        self.security.enable_monitoring = os.getenv('CYBER_LLM_ENABLE_MONITORING', 'true').lower() == 'true'
        self.security.log_level = os.getenv('CYBER_LLM_LOG_LEVEL', self.security.log_level)
        
        # API settings
        self.api.host = os.getenv('CYBER_LLM_HOST', self.api.host)
        self.api.port = int(os.getenv('CYBER_LLM_PORT', self.api.port))
        self.api.debug = os.getenv('CYBER_LLM_DEBUG', 'false').lower() == 'true'
        self.api.api_key_required = os.getenv('CYBER_LLM_API_KEY_REQUIRED', 'true').lower() == 'true'
        
        # CORS origins from environment
        cors_origins = os.getenv('CYBER_LLM_CORS_ORIGINS')
        if cors_origins:
            self.api.cors_origins = [origin.strip() for origin in cors_origins.split(',')]
        
        # LLM settings
        self.llm.openai_api_key = os.getenv('OPENAI_API_KEY')
        self.llm.anthropic_api_key = os.getenv('ANTHROPIC_API_KEY')
        self.llm.default_provider = os.getenv('CYBER_LLM_DEFAULT_PROVIDER', self.llm.default_provider)
        self.llm.default_model = os.getenv('CYBER_LLM_DEFAULT_MODEL', self.llm.default_model)
        self.llm.max_tokens = int(os.getenv('CYBER_LLM_MAX_TOKENS', self.llm.max_tokens))
        self.llm.temperature = float(os.getenv('CYBER_LLM_TEMPERATURE', self.llm.temperature))
        self.llm.timeout = int(os.getenv('CYBER_LLM_TIMEOUT', self.llm.timeout))
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by key.
        
        Args:
            key: Configuration key (e.g., 'security.max_input_length')
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        try:
            parts = key.split('.')
            if len(parts) == 2:
                section, setting = parts
                section_obj = getattr(self, section, None)
                if section_obj:
                    return getattr(section_obj, setting, default)
            return default
        except Exception:
            return default
    
    def set(self, key: str, value: Any):
        """
        Set configuration value by key.
        
        Args:
            key: Configuration key (e.g., 'security.max_input_length')
            value: Value to set
        """
        try:
            parts = key.split('.')
            if len(parts) == 2:
                section, setting = parts
                section_obj = getattr(self, section, None)
                if section_obj and hasattr(section_obj, setting):
                    setattr(section_obj, setting, value)
        except Exception as e:
            print(f"Warning: Could not set config {key}={value}: {e}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'security': {
                'max_input_length': self.security.max_input_length,
                'max_output_length': self.security.max_output_length,
                'rate_limit_requests': self.security.rate_limit_requests,
                'rate_limit_window': self.security.rate_limit_window,
                'sanitization_level': self.security.sanitization_level,
                'enable_monitoring': self.security.enable_monitoring,
                'log_level': self.security.log_level,
            },
            'api': {
                'host': self.api.host,
                'port': self.api.port,
                'debug': self.api.debug,
                'cors_origins': self.api.cors_origins,
                'api_key_required': self.api.api_key_required,
            },
            'llm': {
                'openai_api_key': '***' if self.llm.openai_api_key else None,
                'anthropic_api_key': '***' if self.llm.anthropic_api_key else None,
                'default_provider': self.llm.default_provider,
                'default_model': self.llm.default_model,
                'max_tokens': self.llm.max_tokens,
                'temperature': self.llm.temperature,
                'timeout': self.llm.timeout,
            }
        }
    
    def save_to_file(self, filepath: str):
        """
        Save current configuration to file.
        
        Args:
            filepath: Path to save configuration file
        """
        config_dict = self.to_dict()
        
        # Don't save API keys to file for security
        if 'llm' in config_dict:
            config_dict['llm'].pop('openai_api_key', None)
            config_dict['llm'].pop('anthropic_api_key', None)
        
        try:
            with open(filepath, 'w') as f:
                if filepath.endswith('.json'):
                    json.dump(config_dict, f, indent=2)
                else:
                    # Assume YAML
                    import yaml
                    yaml.dump(config_dict, f, default_flow_style=False, indent=2)
        except Exception as e:
            print(f"Error saving config to {filepath}: {e}")
    
    def validate(self) -> List[str]:
        """
        Validate configuration and return list of issues.
        
        Returns:
            List of validation error messages
        """
        issues = []
        
        # Validate security settings
        if self.security.max_input_length <= 0:
            issues.append("max_input_length must be positive")
        
        if self.security.max_output_length <= 0:
            issues.append("max_output_length must be positive")
        
        if self.security.rate_limit_requests <= 0:
            issues.append("rate_limit_requests must be positive")
        
        if self.security.sanitization_level not in ['basic', 'moderate', 'strict', 'paranoid']:
            issues.append("sanitization_level must be one of: basic, moderate, strict, paranoid")
        
        # Validate API settings
        if not (1 <= self.api.port <= 65535):
            issues.append("port must be between 1 and 65535")
        
        # Validate LLM settings
        if self.llm.max_tokens <= 0:
            issues.append("max_tokens must be positive")
        
        if not (0.0 <= self.llm.temperature <= 2.0):
            issues.append("temperature must be between 0.0 and 2.0")
        
        if self.llm.timeout <= 0:
            issues.append("timeout must be positive")
        
        if self.llm.default_provider not in ['openai', 'anthropic', 'local']:
            issues.append("default_provider must be one of: openai, anthropic, local")
        
        return issues


# Global configuration instance
_config_instance: Optional[Config] = None


def get_config(config_file: Optional[str] = None) -> Config:
    """
    Get the global configuration instance.
    
    Args:
        config_file: Optional path to configuration file
        
    Returns:
        Configuration instance
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = Config(config_file)
    return _config_instance


def reset_config():
    """Reset the global configuration instance."""
    global _config_instance
    _config_instance = None