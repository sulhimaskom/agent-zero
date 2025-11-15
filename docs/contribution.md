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
* **Documentation:**  Update the documentation if your changes affect user-facing functionality. The documentation is written in Markdown.
* **Commit Messages:**  Write clear and concise commit messages that explain the purpose of your changes.

## Security Considerations

Agent Zero is designed to execute code and interact with system resources, which requires special attention to security:

### For Contributors
* **Security Reviews:** All code changes that affect security, authentication, or code execution will undergo security review
* **Input Validation:** Always validate and sanitize user inputs and file uploads
* **Least Privilege:** Ensure code runs with minimal required permissions
* **Secrets Management:** Never hardcode API keys, passwords, or other secrets in code
* **Dependencies:** Keep dependencies updated and scan for known vulnerabilities

### Security Vulnerability Reporting
If you discover a security vulnerability, **do NOT** report it through public GitHub issues. Instead:
- Email: security@agent-zero.ai
- See [SECURITY.md](../SECURITY.md) for detailed reporting guidelines

### Security Best Practices for Development
* Use parameterized queries to prevent injection attacks
* Implement proper error handling without exposing sensitive information
* Validate all file uploads with type and size restrictions
* Use secure communication protocols (HTTPS/TLS)
* Follow the principle of least privilege in all implementations

## Areas of Contribution

We welcome contributions in many areas:

### Code Contributions
* **Core Features:** New agent capabilities, tools, and integrations
* **Performance:** Optimizations, memory management, and efficiency improvements
* **Security:** Security enhancements, vulnerability fixes, and hardening
* **Bug Fixes:** Resolving issues reported in the GitHub issue tracker
* **Refactoring:** Code cleanup, architectural improvements, and technical debt reduction

### Documentation Contributions
* **User Documentation:** Improving installation guides, usage examples, and tutorials
* **Developer Documentation:** API documentation, architecture guides, and development setup
* **Security Documentation:** Security best practices, threat models, and hardening guides

### Testing Contributions
* **Unit Tests:** Improving test coverage for core functionality
* **Integration Tests:** Testing component interactions and end-to-end scenarios
* **Security Tests:** Penetration testing, vulnerability scanning, and security validation

## Submitting a Pull Request

1. **Push Your Branch:** Push your branch to your forked repository on GitHub.
2. **Create a Pull Request:** Create a pull request from your branch to the appropriate branch in the main Agent Zero repository.
   * Target the `development` branch.
3. **Provide Details:** In your pull request description, clearly explain the purpose and scope of your changes. Include relevant context, test results, and any other information that might be helpful for reviewers.
4. **Security Review:** If your changes affect security, authentication, or code execution, they will require additional security review.
5. **Address Feedback:**  Be responsive to feedback from the community. We love changes, but we also love to discuss them!

## Code Review Process

All contributions go through code review:

### Standard Review
* **Functionality:** Does the code work as intended?
* **Quality:** Is the code well-written, readable, and maintainable?
* **Testing:** Are appropriate tests included?
* **Documentation:** Is the documentation updated?

### Security Review
* **Input Validation:** Are all inputs properly validated?
* **Authentication:** Are authentication mechanisms secure?
* **Authorization:** Are access controls properly implemented?
* **Data Protection:** Is sensitive data properly protected?
* **Code Execution:** Are code execution paths secure and sandboxed?

## Development Guidelines

### Branch Naming
* `feature/feature-name` - New features
* `fix/issue-description` - Bug fixes
* `security/vulnerability-fix` - Security fixes
* `docs/documentation-update` - Documentation updates
* `refactor/code-cleanup` - Refactoring and cleanup

### Commit Message Format
```
type(scope): brief description

Detailed explanation of the change, including:
- What was changed and why
- How it was implemented
- Any breaking changes or migration notes
- Related issues or PRs

Types: feat, fix, docs, style, refactor, test, security, chore
Scopes: core, ui, api, auth, tools, docs, tests
```

### Testing Requirements
* **Unit Tests:** All new functionality must include unit tests
* **Integration Tests:** Complex features should include integration tests
* **Security Tests:** Security-related changes must include security tests
* **Manual Testing:** All changes should be manually tested before submission
* **Dependency Verification:** Run `python scripts/check_dependencies.py` to ensure all dependencies are properly installed

## Documentation Stack

- The documentation is built using Markdown. We appreciate your contributions even if you don't know Markdown, and look forward to improve Agent Zero for everyone's benefit.

## Getting Help

* **Discord Community:** Join our [Discord server](https://discord.gg/B8KZKNsPpj) for discussions
* **GitHub Issues:** Use GitHub issues for bug reports and feature requests
* **Security Issues:** Email security@agent-zero.ai for security vulnerabilities

## Recognition

Contributors who make significant contributions will be:
* Listed in our contributors section
* Recognized in release notes
* Invited to join our core contributor Discord channel
* Considered for maintainer roles based on consistent, high-quality contributions

Thank you for contributing to Agent Zero! Your contributions help make this project better for everyone.