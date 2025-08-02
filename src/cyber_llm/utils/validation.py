"""Validation utilities for the cyber_llm framework."""

import re
from typing import Any, Optional


def validate_input(user_input: str, max_length: int = 10000) -> bool:
    """
    Validate user input.
    
    Args:
        user_input: Input to validate
        max_length: Maximum allowed length
        
    Returns:
        True if input is valid
    """
    if not user_input or len(user_input) > max_length:
        return False
    return True


def sanitize_output(output: str) -> str:
    """
    Sanitize output text.
    
    Args:
        output: Output to sanitize
        
    Returns:
        Sanitized output
    """
    # Basic sanitization - remove potential harmful content
    sanitized = re.sub(r'<script.*?</script>', '', output, flags=re.IGNORECASE | re.DOTALL)
    return sanitized
