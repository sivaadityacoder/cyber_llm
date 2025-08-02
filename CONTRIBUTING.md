# Contributing to Cyber LLM Framework

Thank you for your interest in contributing to the Cyber LLM Framework! This document provides guidelines for contributing to this educational cybersecurity project.

## Code of Conduct

This project is committed to providing a welcoming and safe environment for all contributors. We expect all participants to:

- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community
- Show empathy towards other community members

## How to Contribute

### Reporting Issues

Before creating an issue, please check if a similar issue already exists. When creating a new issue:

1. Use a clear and descriptive title
2. Provide a detailed description of the problem
3. Include steps to reproduce the issue
4. Specify your environment (OS, Python version, etc.)
5. Add relevant labels

### Suggesting Enhancements

Enhancement suggestions are welcome! Please:

1. Use a clear and descriptive title
2. Provide a detailed description of the proposed feature
3. Explain why this enhancement would be useful
4. Include examples if applicable

### Contributing Code

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/AmazingFeature`)
3. **Make your changes**
4. **Add tests** for your changes
5. **Ensure tests pass** (`pytest`)
6. **Follow code style guidelines** (see below)
7. **Commit your changes** (`git commit -m 'Add some AmazingFeature'`)
8. **Push to the branch** (`git push origin feature/AmazingFeature`)
9. **Open a Pull Request**

## Development Setup

1. Clone the repository:
```bash
git clone https://github.com/sivaadityacoder/cyber_llm.git
cd cyber_llm
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install development dependencies:
```bash
pip install -e ".[dev]"
```

4. Set up pre-commit hooks:
```bash
pre-commit install
```

## Code Style Guidelines

- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Write docstrings for all public functions and classes
- Keep functions small and focused
- Use meaningful variable and function names

### Code Formatting

We use the following tools for code quality:

- **Black**: Code formatting
- **isort**: Import sorting
- **flake8**: Linting
- **mypy**: Type checking

Run these before submitting:
```bash
black src tests
isort src tests
flake8 src tests
mypy src
```

## Testing Guidelines

- Write tests for all new functionality
- Ensure existing tests continue to pass
- Aim for high test coverage
- Use descriptive test names
- Include both positive and negative test cases

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test categories
pytest -m security
pytest -m unit
```

## Security Considerations

This project deals with cybersecurity topics. When contributing:

1. **Educational Purpose Only**: All contributions must be for educational and defensive purposes
2. **No Malicious Code**: Do not include code that could be used maliciously
3. **Clear Documentation**: Document the educational purpose of any attack demonstrations
4. **Responsible Disclosure**: Follow responsible disclosure practices for any vulnerabilities found
5. **Legal Compliance**: Ensure all contributions comply with applicable laws

### Attack Vector Contributions

When contributing new attack vectors:

1. Include comprehensive documentation explaining the attack
2. Provide clear educational context
3. Include appropriate warnings about responsible use
4. Implement corresponding defense mechanisms
5. Add thorough test coverage

### Defense Mechanism Contributions

When contributing defense mechanisms:

1. Document the threat model
2. Provide performance characteristics
3. Include configuration options
4. Add comprehensive testing
5. Explain integration with existing defenses

## Documentation

- Update documentation for any new features
- Use clear and concise language
- Include code examples where appropriate
- Ensure documentation is accessible to beginners

## Pull Request Process

1. **Update the README** if needed
2. **Update documentation** for new features
3. **Ensure tests pass** on all supported Python versions
4. **Get review approval** from at least one maintainer
5. **Squash commits** if requested

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] All tests pass
- [ ] New tests added for new functionality
- [ ] Manual testing completed

## Security
- [ ] No malicious code included
- [ ] Educational purpose documented
- [ ] Appropriate warnings added

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
```

## Release Process

Releases follow semantic versioning (SemVer):
- **Major**: Breaking changes
- **Minor**: New features (backward compatible)
- **Patch**: Bug fixes (backward compatible)

## Community

- Join discussions in GitHub Issues
- Ask questions in GitHub Discussions
- Follow the project for updates
- Share feedback and suggestions

## Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes
- Project documentation

## Legal and Ethical Guidelines

By contributing, you agree that:

1. Your contributions are your own work or properly attributed
2. You have the right to submit your contributions
3. Your contributions will be used for educational purposes
4. You will not contribute malicious code
5. You understand the educational nature of this project

## Questions?

If you have questions about contributing:
- Open a GitHub Discussion
- Create an issue with the "question" label
- Contact the maintainers

Thank you for helping make cybersecurity education more accessible!