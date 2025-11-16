# Contributing to Agent Zero

Thank you for your interest in contributing to Agent Zero! This document provides guidelines and information for contributors.

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Docker (optional, for containerized development)

### Development Setup

1. Fork the repository
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/agent-zero.git
   cd agent-zero
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the health check to ensure everything is working:
   ```bash
   python health_check.py
   ```

## How to Contribute

### Reporting Issues

- Use GitHub Issues to report bugs or request features
- Provide clear, descriptive titles and detailed descriptions
- Include steps to reproduce for bugs
- Mention your environment (OS, Python version, etc.)

### Submitting Pull Requests

1. Create a new branch for your feature/fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following the coding standards below

3. Test your changes:
   ```bash
   python -m pytest tests/
   python health_check.py
   ```

4. Commit your changes with clear messages:
   ```bash
   git commit -m "feat: add your feature description"
   ```

5. Push to your fork and create a pull request

### Coding Standards

- Follow PEP 8 for Python code style
- Use descriptive variable and function names
- Add docstrings for new functions and classes
- Keep functions focused and small (single responsibility)
- Update documentation for any API changes

### Testing

- Write tests for new functionality
- Ensure all existing tests pass
- Test security-related changes carefully
- Run the full test suite before submitting

## Security Considerations

Agent Zero handles code execution and processes user inputs, so security is critical:

- Never trust user input directly
- Validate and sanitize all inputs
- Use secure coding practices
- Review security implications of changes
- Report security vulnerabilities privately

## Development Guidelines

### Code Structure

- Keep the `agent.py` and `models.py` files focused on core functionality
- Use utility modules for reusable code
- Follow the existing patterns and abstractions
- Maintain backward compatibility when possible

### Performance

- Consider performance implications of changes
- Avoid blocking operations in async contexts
- Use appropriate data structures
- Test with realistic workloads

### Documentation

- Update README.md for user-facing changes
- Update relevant documentation in `docs/`
- Add inline comments for complex logic
- Keep examples up to date

## Repository Health

The repository includes a `health_check.py` script that verifies:
- Git repository status
- Python syntax validation
- Basic functionality tests
- Documentation completeness
- Dependencies configuration

Run this script regularly to ensure repository health.

## Getting Help

- Check existing documentation in `docs/`
- Search existing issues and discussions
- Join our community Discord
- Ask questions in GitHub Discussions

## License

By contributing to Agent Zero, you agree that your contributions will be licensed under the same license as the repository.

---

Thank you for contributing to Agent Zero! Your contributions help make this project better for everyone.