# Contributing to Agent Zero

Contributions to improve Agent Zero are very welcome!  This guide outlines how to contribute code, documentation, or other improvements.

## Getting Started

- See [development](development.md) for instructions on how to set up a development environment.
- See [extensibility](extensibility.md) for instructions on how to create custom extensions.

1. **Fork the Repository:** Fork the Agent Zero repository on GitHub.
2. **Clone Your Fork:** Clone your forked repository to your local machine.
3. **Create a Branch:** Create a new branch for your changes. Use a descriptive name that reflects the purpose of your contribution (e.g., `fix-memory-leak`, `add-search-tool`, `improve-docs`).

## Making Changes

* **Code Style:** Follow the existing code style. Agent Zero generally follows PEP 8 conventions.
* **Linting:** Use flake8 for code linting. Install it with `pip install flake8` and run `flake8 .` before committing. Configuration is in `.flake8`.
* **Documentation:**  Update the documentation if your changes affect user-facing functionality. The documentation is written in Markdown.
* **Commit Messages:**  Write clear and concise commit messages that explain the purpose of your changes.

## Submitting a Pull Request

1. **Push Your Branch:** Push your branch to your forked repository on GitHub.
2. **Create a Pull Request:** Create a pull request from your branch to the appropriate branch in the main Agent Zero repository.
   * Target the `development` branch.
3. **Provide Details:** In your pull request description, clearly explain the purpose and scope of your changes. Include relevant context, test results, and any other information that might be helpful for reviewers.
4. **Address Feedback:**  Be responsive to feedback from the community. We love changes, but we also love to discuss them!

## Security Considerations

When contributing to Agent Zero, please keep these security guidelines in mind:

### Code Execution Safety
- **Review all code execution paths**: Ensure that any code execution tool has proper sandboxing and input validation
- **Validate user inputs**: Sanitize and validate all user inputs before processing or execution
- **Resource limits**: Implement appropriate timeouts and resource usage limits
- **Command whitelisting**: Restrict executable commands to a safe, predefined list

### Authentication & Authorization
- **Secure API key handling**: Never hardcode API keys or secrets in code
- **Session management**: Implement secure session handling with proper expiration
- **Rate limiting**: Add rate limiting to prevent abuse and brute force attacks
- **Principle of least privilege**: Ensure components only have access to necessary resources

### Dependency Security
- **Vet new dependencies**: Review security implications of new third-party packages
- **Keep dependencies updated**: Regularly update to address security vulnerabilities
- **Use pinned versions**: Pin dependency versions to prevent automatic updates
- **Security scanning**: Run security scanning tools on dependencies

### Data Protection
- **Secrets masking**: Ensure sensitive data is masked in logs and outputs
- **Secure file handling**: Validate file types, sizes, and paths for uploads
- **Input sanitization**: Properly sanitize all user-provided data
- **HTTPS enforcement**: Use secure communication channels

### Security Testing
- **Include security tests**: Add tests for security-critical functionality
- **Penetration testing**: Consider security implications in your changes
- **Code reviews**: Pay special attention to security-related code changes

For detailed security guidelines, see the [SECURITY.md](../SECURITY.md) file.

## Documentation Stack

- The documentation is built using Markdown. We appreciate your contributions even if you don't know Markdown, and look forward to improve Agent Zero for everyone's benefit.