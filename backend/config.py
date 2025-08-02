"""
Configuration management for the Cyber LLM application.
"""

import os
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings."""
    
    # Environment
    environment: str = Field(default="development", env="ENVIRONMENT")
    debug: bool = Field(default=True, env="DEBUG")
    secret_key: str = Field(default="dev-secret-key", env="SECRET_KEY")
    jwt_secret_key: str = Field(default="dev-jwt-secret", env="JWT_SECRET_KEY")
    
    # API Configuration
    api_host: str = Field(default="0.0.0.0", env="API_HOST")
    api_port: int = Field(default=8000, env="API_PORT")
    
    # Database
    database_url: str = Field(default="sqlite:///./cyber_llm.db", env="DATABASE_URL")
    redis_url: str = Field(default="redis://localhost:6379", env="REDIS_URL")
    
    # LLM Configuration
    llm_model_path: str = Field(default="./models/", env="LLM_MODEL_PATH")
    default_model: str = Field(default="llama-2-7b-chat.gguf", env="DEFAULT_MODEL")
    max_tokens: int = Field(default=2048, env="MAX_TOKENS")
    temperature: float = Field(default=0.7, env="TEMPERATURE")
    
    # RAG Configuration
    vector_db_path: str = Field(default="./data/vectorstore/", env="VECTOR_DB_PATH")
    embeddings_model: str = Field(default="sentence-transformers/all-MiniLM-L6-v2", env="EMBEDDINGS_MODEL")
    chunk_size: int = Field(default=1000, env="CHUNK_SIZE")
    chunk_overlap: int = Field(default=200, env="CHUNK_OVERLAP")
    
    # Voice Configuration
    voice_enabled: bool = Field(default=False, env="VOICE_ENABLED")
    voice_rate: int = Field(default=150, env="VOICE_RATE")
    voice_volume: float = Field(default=0.9, env="VOICE_VOLUME")
    
    # Security Configuration
    rate_limit_per_minute: int = Field(default=60, env="RATE_LIMIT_PER_MINUTE")
    session_timeout: int = Field(default=3600, env="SESSION_TIMEOUT")
    allowed_hosts: str = Field(default="localhost,127.0.0.1", env="ALLOWED_HOSTS")
    
    # Tools Configuration
    nmap_path: str = Field(default="/usr/bin/nmap", env="NMAP_PATH")
    nuclei_path: str = Field(default="/usr/bin/nuclei", env="NUCLEI_PATH")
    tools_timeout: int = Field(default=300, env="TOOLS_TIMEOUT")
    
    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_file: str = Field(default="./logs/cyber_llm.log", env="LOG_FILE")
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()