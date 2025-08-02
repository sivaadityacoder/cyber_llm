"""
FastAPI server for the cyber_llm framework.

This module provides a REST API for testing LLM security mechanisms.
"""

import asyncio
import time
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

from cyber_llm.attacks.prompt_injection import PromptInjection
from cyber_llm.defenses.input_sanitization import InputSanitizer, SanitizationLevel
from cyber_llm.utils.config import get_config
from cyber_llm.utils.logging_utils import setup_logging, get_logger

# Setup logging
setup_logging()
logger = get_logger(__name__)

# Load configuration
config = get_config()

# Security
security = HTTPBearer(auto_error=False)

app = FastAPI(
    title="Cyber LLM Security API",
    description="Educational API for testing LLM security vulnerabilities and defenses",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.api.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
injection_tester = PromptInjection()
sanitizer = InputSanitizer(SanitizationLevel.MODERATE)

# Rate limiting storage (in production, use Redis or similar)
rate_limit_storage: Dict[str, List[float]] = {}


# Request/Response Models
class TestPromptRequest(BaseModel):
    prompt: str = Field(..., description="The prompt to test", max_length=10000)
    sanitization_level: Optional[str] = Field("moderate", description="Sanitization level")


class VulnerabilityAnalysis(BaseModel):
    prompt: str
    vulnerabilities: List[Dict]
    overall_risk: str
    recommendations: List[str]


class SanitizationResult(BaseModel):
    original_input: str
    sanitized_input: str
    blocked_patterns: List[str]
    risk_score: float
    action_taken: str
    recommendations: List[str]


class TestResult(BaseModel):
    analysis: VulnerabilityAnalysis
    sanitization: SanitizationResult
    timestamp: float
    processing_time_ms: float


# Authentication
async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Validate API key if required."""
    if not config.api.api_key_required:
        return "anonymous"
    
    if not credentials:
        raise HTTPException(status_code=401, detail="API key required")
    
    # In production, validate against a proper key store
    if credentials.credentials != "demo_key_123":
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    return "authenticated_user"


# Rate limiting
async def check_rate_limit(user: str = Depends(get_current_user)):
    """Check rate limiting for user."""
    current_time = time.time()
    window_start = current_time - config.security.rate_limit_window
    
    # Clean old entries
    if user in rate_limit_storage:
        rate_limit_storage[user] = [
            timestamp for timestamp in rate_limit_storage[user]
            if timestamp > window_start
        ]
    else:
        rate_limit_storage[user] = []
    
    # Check limit
    if len(rate_limit_storage[user]) >= config.security.rate_limit_requests:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. {config.security.rate_limit_requests} requests per {config.security.rate_limit_window} seconds allowed."
        )
    
    # Add current request
    rate_limit_storage[user].append(current_time)
    return user


# Routes
@app.get("/")
async def root():
    """Root endpoint with basic information."""
    return {
        "name": "Cyber LLM Security API",
        "version": "0.1.0",
        "description": "Educational API for testing LLM security",
        "endpoints": {
            "docs": "/docs",
            "test": "/test",
            "analyze": "/analyze",
            "sanitize": "/sanitize",
            "health": "/health"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "version": "0.1.0"
    }


@app.post("/test", response_model=TestResult)
async def test_prompt(
    request: TestPromptRequest,
    user: str = Depends(check_rate_limit)
):
    """
    Test a prompt for security vulnerabilities and sanitization.
    
    This endpoint combines vulnerability analysis and input sanitization
    to provide a comprehensive security assessment.
    """
    start_time = time.time()
    
    try:
        # Validate input length
        if len(request.prompt) > config.security.max_input_length:
            raise HTTPException(
                status_code=400,
                detail=f"Prompt too long. Maximum {config.security.max_input_length} characters allowed."
            )
        
        # Analyze vulnerabilities
        analysis = injection_tester.analyze_vulnerability(request.prompt)
        
        # Sanitize input
        sanitization_level = SanitizationLevel(request.sanitization_level or "moderate")
        test_sanitizer = InputSanitizer(sanitization_level)
        sanitization_result = test_sanitizer.sanitize(request.prompt)
        
        processing_time = (time.time() - start_time) * 1000  # Convert to milliseconds
        
        logger.info(f"Processed test request for user {user}: risk_score={sanitization_result.risk_score}")
        
        return TestResult(
            analysis=VulnerabilityAnalysis(**analysis),
            sanitization=SanitizationResult(
                original_input=sanitization_result.original_input,
                sanitized_input=sanitization_result.sanitized_input,
                blocked_patterns=sanitization_result.blocked_patterns,
                risk_score=sanitization_result.risk_score,
                action_taken=sanitization_result.action_taken,
                recommendations=sanitization_result.recommendations
            ),
            timestamp=time.time(),
            processing_time_ms=processing_time
        )
        
    except Exception as e:
        logger.error(f"Error processing test request: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/analyze", response_model=VulnerabilityAnalysis)
async def analyze_prompt(
    request: TestPromptRequest,
    user: str = Depends(check_rate_limit)
):
    """
    Analyze a prompt for security vulnerabilities.
    
    This endpoint focuses specifically on vulnerability detection
    without sanitization.
    """
    try:
        # Validate input length
        if len(request.prompt) > config.security.max_input_length:
            raise HTTPException(
                status_code=400,
                detail=f"Prompt too long. Maximum {config.security.max_input_length} characters allowed."
            )
        
        analysis = injection_tester.analyze_vulnerability(request.prompt)
        logger.info(f"Analyzed prompt for user {user}: risk={analysis['overall_risk']}")
        
        return VulnerabilityAnalysis(**analysis)
        
    except Exception as e:
        logger.error(f"Error analyzing prompt: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/sanitize", response_model=SanitizationResult)
async def sanitize_prompt(
    request: TestPromptRequest,
    user: str = Depends(check_rate_limit)
):
    """
    Sanitize a prompt using the specified security level.
    
    This endpoint focuses specifically on input sanitization
    without vulnerability analysis.
    """
    try:
        # Validate input length
        if len(request.prompt) > config.security.max_input_length:
            raise HTTPException(
                status_code=400,
                detail=f"Prompt too long. Maximum {config.security.max_input_length} characters allowed."
            )
        
        sanitization_level = SanitizationLevel(request.sanitization_level or "moderate")
        test_sanitizer = InputSanitizer(sanitization_level)
        result = test_sanitizer.sanitize(request.prompt)
        
        logger.info(f"Sanitized prompt for user {user}: action={result.action_taken}")
        
        return SanitizationResult(
            original_input=result.original_input,
            sanitized_input=result.sanitized_input,
            blocked_patterns=result.blocked_patterns,
            risk_score=result.risk_score,
            action_taken=result.action_taken,
            recommendations=result.recommendations
        )
        
    except Exception as e:
        logger.error(f"Error sanitizing prompt: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/stats")
async def get_stats(user: str = Depends(get_current_user)):
    """Get API usage statistics."""
    current_time = time.time()
    window_start = current_time - config.security.rate_limit_window
    
    user_requests = len([
        timestamp for timestamp in rate_limit_storage.get(user, [])
        if timestamp > window_start
    ])
    
    return {
        "user": user,
        "requests_in_window": user_requests,
        "window_duration": config.security.rate_limit_window,
        "rate_limit": config.security.rate_limit_requests,
        "remaining_requests": max(0, config.security.rate_limit_requests - user_requests)
    }


@app.get("/config")
async def get_api_config(user: str = Depends(get_current_user)):
    """Get API configuration (sanitized)."""
    return {
        "max_input_length": config.security.max_input_length,
        "max_output_length": config.security.max_output_length,
        "rate_limit_requests": config.security.rate_limit_requests,
        "rate_limit_window": config.security.rate_limit_window,
        "sanitization_levels": ["basic", "moderate", "strict", "paranoid"],
        "api_version": "0.1.0"
    }


def main():
    """Run the API server."""
    uvicorn.run(
        "cyber_llm.server:app",
        host=config.api.host,
        port=config.api.port,
        reload=config.api.debug,
        log_level=config.security.log_level.lower()
    )


if __name__ == "__main__":
    main()