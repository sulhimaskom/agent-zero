# Contributing to Agent Zero

> Last Updated: 2026-03-01

Contributions to improve Agent Zero are very welcome! This guide outlines how to contribute code, documentation, or other improvements.

## Getting Started

- See [development](development.md) for instructions on how to set up a development environment.
- See [extensibility](extensibility.md) for instructions on how to create custom extensions.

1. **Fork the Repository:** Fork the Agent Zero repository on GitHub.
2. **Clone Your Fork:** Clone your forked repository to your local machine.
3. **Create a Branch:** Create a new branch for your changes. Use a descriptive name that reflects the purpose of your contribution.

## Branch Strategy

Agent Zero uses the following branch naming conventions:

| Prefix | Purpose | Example |
|--------|---------|---------|
| `feature/` | New features | `feature/add-search-tool` |
| `fix/` | Bug fixes | `fix/memory-leak` |
| `docs/` | Documentation | `docs/improve-contribution-guide` |
| `test/` | Test additions | `test/add-crypto-tests` |
| `refactor/` | Code refactoring | `refactor/settings-module` |
| `user-story-engineer/` | Small improvements | `user-story-engineer/fix-typo` |

**Main branch:** `custom` (not `main` or `development`)

All PRs should target the `custom` branch.

## Commit Message Format

Follow conventional commit format:

```
<type>(<scope>): <description>

[optional body]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `test`: Tests
- `refactor`: Refactoring
- `chore`: Maintenance

**Examples:**
```
fix(memory): resolve memory leak in vector_db
docs(readme): add installation instructions
test(crypto): add tests for encrypt/decrypt functions
```

## Making Changes

- **Code Style:** Follow the existing code style. Agent Zero generally follows PEP 8 conventions.
- **Documentation:** Update the documentation if your changes affect user-facing functionality. The documentation is written in Markdown.
- **Commit Messages:** Write clear and concise commit messages that explain the purpose of your changes.

## First Contribution Tutorial

### Step 1: Fork and Clone

```bash
git clone https://github.com/YOUR_USERNAME/agent-zero.git
cd agent-zero
```

### Step 2: Create a Branch

```bash
git checkout -b fix/your-bug-fix
```

### Step 3: Make Your Changes

Edit files, add tests, update documentation as needed.

### Step 4: Test Your Changes

```bash
# Run existing tests
pytest tests/ -v

# Check for linting issues (if configured)
ruff check .
```

### Step 5: Commit and Push

```bash
git add .
git commit -m "fix(scope): description of your fix"
git push origin fix/your-bug-fix
```

### Step 6: Create Pull Request

1. Go to the Agent Zero repository on GitHub
2. Click "Compare & pull request"
3. Target the `custom` branch
4. Fill in the PR template (see below)
5. Submit

## Pull Request Template

```markdown
## Summary

- [Brief description of change]

## Context

[Why this change matters]

## Changes

- [File]: [What changed]

## Testing

- [How verified]
- [Any test results]

## Labels

- [Add relevant labels: bug, enhancement, documentation, etc.]
```

## Code Review Expectations

- **Keep PRs small:** Focus on one feature or fix per PR
- **Include tests:** Add tests for new functionality
- **Update docs:** Documentation should reflect changes
- **Be responsive:** Address reviewer feedback promptly
- **CI checks:** Ensure all CI checks pass before requesting review

## Labels

Common labels for PRs:

| Label | Purpose |
|-------|---------|
| `bug` | Bug fixes |
| `enhancement` | New features |
| `documentation` | Doc changes |
| `test` | Test additions |
| `refactor` | Code improvements |
| `user-story-engineer` | Small improvements |

## Documentation Stack

The documentation is built using Markdown. We appreciate your contributions even if you don't know Markdown, and look forward to improving Agent Zero for everyone's benefit.
