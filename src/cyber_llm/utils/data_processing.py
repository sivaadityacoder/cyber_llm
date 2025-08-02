"""Data processing utilities for the cyber_llm framework."""

import re
from typing import List, Dict, Any


def tokenize_text(text: str) -> List[str]:
    """
    Simple text tokenization.
    
    Args:
        text: Text to tokenize
        
    Returns:
        List of tokens
    """
    # Basic tokenization - split on whitespace and punctuation
    tokens = re.findall(r'\b\w+\b', text.lower())
    return tokens


def analyze_sentiment(text: str) -> Dict[str, Any]:
    """
    Basic sentiment analysis.
    
    Args:
        text: Text to analyze
        
    Returns:
        Sentiment analysis results
    """
    # Very basic sentiment analysis
    positive_words = ['good', 'great', 'excellent', 'amazing', 'wonderful']
    negative_words = ['bad', 'terrible', 'awful', 'horrible', 'disgusting']
    
    tokens = tokenize_text(text)
    positive_count = sum(1 for token in tokens if token in positive_words)
    negative_count = sum(1 for token in tokens if token in negative_words)
    
    if positive_count > negative_count:
        sentiment = 'positive'
    elif negative_count > positive_count:
        sentiment = 'negative'
    else:
        sentiment = 'neutral'
    
    return {
        'sentiment': sentiment,
        'positive_words': positive_count,
        'negative_words': negative_count,
        'confidence': abs(positive_count - negative_count) / max(len(tokens), 1)
    }
