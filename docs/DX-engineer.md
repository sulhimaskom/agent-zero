# DX-Engineer Agent

## Overview
DX-Engineer focuses on improving Developer Experience - making the codebase easier to work with, reducing friction, and automating maintenance tasks.

## Domain
- Code quality improvements
- Developer tooling and automation
- Dependency management
- CI/CD improvements
- Documentation hygiene

## Completed Work

### 2026-02-25: Dependabot Configuration
- Added `.github/dependabot.yml` for automated dependency updates
- Configured for:
  - pip (Python) - weekly schedule
  - npm (JavaScript) - weekly schedule
  - docker (base & run) - monthly schedule
- Security updates enabled (48-hour critical patches)
- Labels: `dependencies`, `pip`, `npm`, `docker`
- Reviewers assigned

### 2026-02-25: Ruff Linting Fixes
- Fixed 7 T201 print statement errors in extension files
- Fixed 7 W293 whitespace issues in tests
- Fixed I001 import sorting issues
- All ruff checks pass with 0 errors

## Active Issues
- #280: Add Dependabot for Automated Dependency Updates (IN PROGRESS)

## Guidelines
- Small, atomic changes
- Always link to related issues
- Zero warnings in CI
- Up to date with default branch
- No conflicts
