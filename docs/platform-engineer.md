# Platform Engineer Agent - Long-term Memory

**Created:** 2026-02-25
**Agent:** platform-engineer

## Mission
Deliver small, safe, measurable improvements strictly inside the platform engineering domain:
- CI/CD pipelines and workflows
- Developer tooling and experience
- Build and runtime optimizations
- Repository infrastructure

## Operating Rules

### Strict Phase Workflow
1. **INITIATE** - Check for existing PRs/issues, proactive scan
2. **PLAN** - Create detailed TODO list
3. **IMPLEMENT** - Execute changes
4. **VERIFY** - Validate changes work correctly
5. **SELF-REVIEW** - Review own work
6. **SELF-EVOLVE** - Check teammates' memory, update docs
7. **DELIVER** - Create PR with platform-engineer label

### PR Requirements
- Label: `platform-engineer`
- Linked to issue if any
- Up to date with default branch
- No conflict
- Build/lint/test success
- ZERO warnings
- Small atomic diff

## Improvements Log

### 2026-02-25 - Pre-commit Redundancy Removal
- **Change:** Removed redundant `black` configuration from `.pre-commit-config.yaml`
- **Rationale:** Both `ruff-format` and `black` were configured but perform the same function. Ruff is significantly faster and is already configured as the primary formatter in `pyproject.toml`.
- **Impact:** Faster pre-commit runs, reduced tooling redundancy, better alignment with project config

## Known Platform Opportunities

### CI/CD
- GitHub workflows use OpenCode AI agent for automation (innovative approach)
- No explicit ruff/black/mypy validation steps in CI (AI agents handle it)
- Consider adding explicit lint validation for faster feedback

### Python Tooling
- pyproject.toml is well-configured with ruff, black, mypy
- Pre-commit config has redundancy (black + ruff-format)
- 176 `# type: ignore` comments in codebase - type safety opportunity

### Docker
- Multi-stage builds could potentially optimize image size
- Base image: debian:13-slim (already optimized)

## Teammate Memory References
- Check other agents' long-term memory for coordination
- Avoid duplicate work across platform-engineer runs
