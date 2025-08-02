"""Cryptographic utilities for the cyber_llm framework."""

import hashlib
import hmac


def hash_prompt(prompt: str, salt: str = "") -> str:
    """
    Hash a prompt for privacy and logging.
    
    Args:
        prompt: Prompt to hash
        salt: Optional salt
        
    Returns:
        Hashed prompt
    """
    combined = f"{salt}{prompt}".encode('utf-8')
    return hashlib.sha256(combined).hexdigest()


def generate_signature(data: str, key: str) -> str:
    """
    Generate HMAC signature for data.
    
    Args:
        data: Data to sign
        key: Signing key
        
    Returns:
        HMAC signature
    """
    return hmac.new(
        key.encode('utf-8'),
        data.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
