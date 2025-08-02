"""
Attack Vector Implementations

This module contains implementations of various LLM attack vectors for educational
and defensive testing purposes. All attacks are designed to help security
professionals understand vulnerabilities and develop better defenses.

WARNING: These implementations are for educational purposes only. Do not use
for malicious activities.

Available attack vectors:
- Prompt Injection
- Jailbreaking
- Data Extraction
- Model Inversion
- Adversarial Prompts
- Social Engineering
- Chain-of-Thought Manipulation
- Context Window Attacks
- Role-Playing Exploits
- Multi-Turn Attacks
"""

from .prompt_injection import PromptInjection
from .jailbreaking import Jailbreaking
from .data_extraction import DataExtraction
from .adversarial_prompts import AdversarialPrompts
from .social_engineering import SocialEngineering
from .chain_of_thought import ChainOfThoughtManipulation
from .context_window import ContextWindowAttacks
from .role_playing import RolePlayingExploits
from .multi_turn import MultiTurnAttacks

__all__ = [
    "PromptInjection",
    "Jailbreaking", 
    "DataExtraction",
    "AdversarialPrompts",
    "SocialEngineering",
    "ChainOfThoughtManipulation",
    "ContextWindowAttacks",
    "RolePlayingExploits",
    "MultiTurnAttacks",
]