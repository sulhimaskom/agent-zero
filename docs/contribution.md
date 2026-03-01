# Contributing to Agent Zero

> Last Updated: 2026-03-01

Contributions to improve Agent Zero are very welcome! This guide outlines how to contribute code, documentation, or other improvements.

## Getting Started

- See [development](development.md) for instructions on how to set up a development environment.
- See [extensibility](extensibility.md) for instructions on how to create custom extensions.

1. **Fork the Repository:** Fork the Agent Zero repository on GitHub.
2. **Clone Your Fork:** Clone your forked repository to your local machine.
3. **Create a Branch:** Create a new branch for your changes. Use a descriptive name that reflects the purpose of your contribution (e.g., `fix-memory-leak`, `add-search-tool`, `improve-docs`).

## Branch Naming Convention

Use the following prefixes for branch names:

| Prefix | Example | Use For |
|--------|---------|---------|
| `fix/` | `fix/memory-leak-in-store` | Bug fixes |
| `feat/` | `feat/add-new-tool` | New features |
| `refactor/` | `refactor/settings-module` | Code refactoring |
| `docs/` | `docs/contribution-guide` | Documentation improvements |
| `infra/` | `infra/add-ci-check` | Infrastructure changes |
| `rnd/` | `rnd/experiment-logging` | Research & Development |

## Commit Message Format

Use clear, descriptive commit messages:

```
<type>: <short description>

<optional longer description>
```

Types: `feat`, `fix`, `refactor`, `docs`, `infra`, `rnd`, `chore`

Example:
```
feat: Add memory leak cleanup to welcome-store

Added clearInterval in x-destroy handler to prevent
interval leaks when component is destroyed.
```

## Making Changes

- **Code Style:** Follow the existing code style. Agent Zero generally follows PEP 8 conventions.
- **Documentation:** Update the documentation if your changes affect user-facing functionality. The documentation is written in Markdown.
- **Commit Messages:** Write clear and concise commit messages that explain the purpose of your changes.

### Code Quality Standards

- Run linting before submitting: `ruff check .`
- Run formatting: `ruff format .`
- Run tests: `pytest tests/ -v`
- Check types: `mypy python/`

### Pre-commit Hooks

Install pre-commit hooks to catch issues early:

```bash
pip install pre-commit
pre-commit install
```

## Submitting a Pull Request

1. **Push Your Branch:** Push your branch to your forked repository on GitHub.
2. **Create a Pull Request:** Create a pull request from your branch to the appropriate branch in the main Agent Zero repository.
   - Target the `custom` branch.
3. **Use PR Template:** Fill out the [PR template](https://github.com/agent0ai/agent-zero/blob/main/.github/PULL_REQUEST_TEMPLATE.md) - it helps reviewers understand your changes.
4. **Provide Details:** In your pull request description, clearly explain the purpose and scope of your changes. Include relevant context, test results, and any other information that might be helpful for reviewers.
5. **Link Issues:** If your PR addresses an existing issue, link it using GitHub keywords (e.g., `Fixes #123`).
6. **Address Feedback:** Be responsive to feedback from the community. We love changes, but we also love to discuss them!

## Code Review Expectations

- PRs should be focused and atomic (small, single-purpose changes)
- All CI checks must pass
- No linting errors or warnings
- Tests should pass (or pre-existing failures documented)
- Changes should not break existing functionality

## First Contribution Steps

1. Good first issues are tagged with `good first issue` on GitHub
2. Start with small changes (documentation, typo fixes)
3. Read the existing code to understand patterns
4. Don't hesitate to ask questions in issues or discussions

## Documentation Stack

- The documentation is built using Markdown. We appreciate your contributions even if you don't know Markdown, and look forward to improve Agent Zero for everyone's benefit.

## Related Resources

- [Development Guide](development.md)
- [Extensibility Guide](extensibility.md)
- [Architecture Overview](architecture.md)
- [API Reference](api.md)
