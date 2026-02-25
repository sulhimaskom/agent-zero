# Product-Architect Agent - Long-term Memory

**Created:** 2026-02-25
**Agent Mode:** Ultraloop (Autonomous Product-Architect)

## Domain
Product-Architect focuses on small, safe, measurable improvements to the Agent Zero framework.

## Workflow Phases
1. **INITIATE** - Check for existing PRs with Product-Architect label, check for issues
2. **PLAN** - Create detailed work breakdown
3. **IMPLEMENT** - Execute changes
4. **VERIFY** - Ensure changes work and don't break existing functionality
5. **SELF-REVIEW** - Review own work for quality
6. **SELF-EVOLVE** - Check teammate memories, improve documentation
7. **DELIVER** - Create PR with Product-Architect label

## PR Requirements
- Label: `Product-Architect`
- Linked to issue if any
- Up to date with default branch
- No conflicts
- Build/lint/test success
- Zero warnings
- Small atomic diff
- Never refactor unrelated modules
- Never introduce unnecessary abstraction

## Issue Priorities (from repository)
- **P0** - Critical (e.g., CI not running tests, test coverage crisis)
- **P1** - High (e.g., documentation outdated, complexity hotspots)
- **P2** - Medium (e.g., dependency risks, security scanning)
- **P3** - Low

## Good First Issues for Product-Architect
- Documentation updates (low risk, high value)
- Type annotations
- Code quality improvements (exception handling, TODO markers)
- Simple refactoring in isolated modules

## Patterns & Conventions

### Agent Profiles Structure
As of 2026-02-25, agent profiles in `/agents/` have this structure:
- `{profile}/_context.md` - Required for agent initialization
- `{profile}/prompts/` - Custom markdown prompts
- `{profile}/tools/` - Profile-specific tool overrides
- `{profile}/extensions/` - Profile-specific extension overrides

### Known Issues to Address
1. [P0] CI Does Not Run pytest - Tests Never Executed
2. [P0] Test Coverage Crisis - Only 5% Coverage
3. [P1] AGENTS.md Documentation Outdated vs Actual Structure (RESOLVED)
4. [P1] settings.py Complexity Hotspot - 1748 Lines
5. [P2] Various infrastructure and documentation issues

## Self-Evolution Notes
- Always check other agents' memories before starting new work
- Keep this document updated with learnings
- Focus on small, incremental improvements rather than large refactors
