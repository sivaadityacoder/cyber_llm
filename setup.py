#!/usr/bin/env python3
"""
Setup script for cyber_llm package.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="cyber_llm",
    version="0.1.0",
    author="Cybersecurity LLM Framework Team",
    author_email="security@cyber-llm.org",
    description="A comprehensive educational framework for LLM security vulnerabilities, attacks, and defenses",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sivaadityacoder/cyber_llm",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pre-commit>=3.0.0",
        ],
        "api": [
            "fastapi>=0.100.0",
            "uvicorn>=0.23.0",
            "pydantic>=2.0.0",
        ],
        "monitoring": [
            "prometheus-client>=0.17.0",
            "structlog>=23.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "cyber-llm=cyber_llm.cli:main",
            "cyber-llm-server=cyber_llm.server:main",
            "cyber-llm-test=cyber_llm.testing:main",
        ],
    },
    include_package_data=True,
    keywords="cybersecurity, llm, security, ai, machine learning, attacks, defense",
)