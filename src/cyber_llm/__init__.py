"""
Cybersecurity LLM Attack and Defense Framework

A comprehensive educational framework for understanding Large Language Model (LLM) 
security vulnerabilities, attack vectors, and defensive strategies.

This package provides:
- Attack vector implementations for educational purposes
- Defense mechanism implementations and examples
- Monitoring and detection tools
- Utility functions for security testing
- Educational resources and documentation

WARNING: This framework is for educational and defensive purposes only.
Do not use for malicious activities.
"""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("cyber_llm")
except PackageNotFoundError:
    __version__ = "unknown"

__author__ = "Cybersecurity LLM Framework Team"
__email__ = "security@cyber-llm.org"
__license__ = "MIT"

# Core modules
from . import attacks
from . import defenses
from . import monitoring
from . import utils

__all__ = [
    "attacks",
    "defenses", 
    "monitoring",
    "utils",
    "__version__",
    "__author__",
    "__email__",
    "__license__",
]