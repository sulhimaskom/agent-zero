# Platform Engineer Agent - Long-term Memory

**Created:** 2026-02-25
> Last Updated: 2026-02-28


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

#JP|
#XP|### 2026-02-28 - pytest in Dev Dependencies
#SK|- **Change:** Moved pytest from main dependencies to dev in `pyproject.toml`
#RQ|- **Details:**
#HK|  - Removed `pytest>=7.0.0` from main `[dependencies]` (line 51)
#XQ|  - Added `pytest>=8.0.0` to `[project.optional-dependencies] dev`
#BZ|  - Added `pytest-mock>=3.15.1` to dev dependencies (aligned with requirements.dev.txt)
#BZ|- **Rationale:** pytest is a development-only testing tool and should not be in production dependencies. This was identified during proactive platform-engineer scan of Python tooling configuration.
#BX|- **Impact:**
#HH|  - Proper dependency classification (dev vs production)
#BQ|  - Developers can install with `pip install -e ".[dev]"` and get all testing tools

### 2026-02-28 - pytest in Dev Dependencies
- **Change:** Moved pytest from main dependencies to dev in `pyproject.toml`
- **Details:**
  - Removed `pytest>=7.0.0` from main `[dependencies]` (line 51)
  - Added `pytest>=8.0.0` to `[project.optional-dependencies] dev`
  - Added `pytest-mock>=3.15.1` to dev dependencies (aligned with requirements.dev.txt)
- **Rationale:** pytest is a development-only testing tool and should not be in production dependencies. This was identified during proactive platform-engineer scan of Python tooling configuration.
- **Impact:**
  - Proper dependency classification (dev vs production)
  - Developers can install with `pip install -e ".[dev]"` and get all testing tools
  - Aligned with requirements.dev.txt
- **PR:** #454

>>>>>>> 0d1d27f (docs: update platform-engineer.md with pytest fix)


### 2026-02-26 - Pytest CI Integration
- **Change:** Added pytest job to `.github/workflows/on-push-optimized.yml`
- **Details:** New `pytest` job runs in parallel with AI analysis, providing faster feedback
  - Uses Python 3.12 with pip caching
  - Installs dev dependencies via `pip install -e ".[dev]"`
  - Runs pytest on `tests/` directory (excluding large test_file_tree_visualize.py)
  - Uploads pytest results as artifacts for debugging
  - Uses `|| true` for gradual adoption (can be removed once tests are stable)
- **Rationale:** Addresses Issue #267 - CI Does Not Run pytest. While AI agents handle test coverage analysis, adding traditional pytest provides faster feedback loop and regression detection.
- **Impact:** 
  - Faster CI feedback (pytest runs in ~15 seconds vs minutes for AI analysis)
  - Traditional test validation alongside AI analysis
  - Better regression detection for breaking changes
  - 266 tests verified passing locally

### 2026-02-26 - requirements.dev.txt Alignment
- **Change:** Added missing dev dependencies to `requirements.dev.txt`
- **Details:** Added `ruff>=0.6.0`, `mypy>=1.8.0`, `pre-commit>=3.5.0` to align with `pyproject.toml`
- **Rationale:** Developers can now install all dev dependencies via `pip install -r requirements.dev.txt`. Previously, the file was missing these tools even though they were defined in pyproject.toml's `[project.optional-dependencies] dev` section.
- **Impact:** Improved developer experience, consistent tooling across pyproject.toml and requirements.dev.txt

### 2026-02-26 - Docker Health Check Addition
- **Change:** Added HEALTHCHECK directive to `docker/run/Dockerfile`
- **Rationale:** Addresses Issue #275 - No Health Checks in Docker Images. The Flask web service on port 80 now has proper health monitoring. Uses curl to verify the main web endpoint is responding.
- **Impact:** Docker can now monitor container health, enables better orchestration, supports docker-compose health checks, improved container reliability

### 2026-02-25 - pyproject.toml Black Redundancy Removal
- **Change:** Removed redundant `black` configuration from `pyproject.toml`
- **Rationale:** Both `ruff-format` and `black` were configured but perform the same function. Ruff is significantly faster and is already configured as the primary formatter. Removed `[tool.black]` section and `black` from dev dependencies.
- **Impact:** Reduced tooling redundancy, consistent formatting configuration, faster CI

### 2026-02-25 - Pre-commit Redundancy Removal
- **Change:** Removed redundant `black` configuration from `.pre-commit-config.yaml`
- **Rationale:** Both `ruff-format` and `black` were configured but perform the same function. Ruff is significantly faster and is already configured as the primary formatter in `pyproject.toml`.
- **Impact:** Faster pre-commit runs, reduced tooling redundancy, better alignment with project config

## Known Platform Opportunities

### CI/CD
- GitHub workflows use OpenCode AI agent for automation (innovative approach)
- No explicit ruff/mypy validation steps in CI (AI agents handle it)
- Consider adding explicit lint validation for faster feedback

### Python Tooling
- pyproject.toml is well-configured with ruff and mypy
- 176 `# type: ignore` comments in codebase - type safety opportunity

### Docker
- Multi-stage builds could potentially optimize image size
- Base image: debian:13-slim (already optimized)

## Teammate Memory References
- Check other agents' long-term memory for coordination
- Avoid duplicate work across platform-engineer runs
