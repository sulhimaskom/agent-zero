# CLI Agent Collection

Condensed AI coding agents optimized for CLI tools (Gemini CLI, Claude CLI, OpenCode CLI, etc).

## Architecture

```
User Input → [00 Strategist] → feature.md + task.md
                                    ↓
                             [01-11 Agents] execute
                                    ↓
                           [00 Strategist] review
```

## Usage

```bash
# Example with Gemini CLI
gemini --system-prompt "$(cat 00-strategist.md)" "new feature request"
gemini --system-prompt "$(cat 02.md)" "fix the build"

# Example with Claude CLI
claude --system "$(cat 04.md)" "audit dependencies"
```

## Agents

| File | Agent | Focus |
|------|-------|-------|
| `00-strategist.md` | **Product Strategist** 🧠 | Planning, docs, direction |
| `01-code-review.md` | Code Reviewer | Review, refactoring |
| `02-docs-hygiene.md` | Documentation Hygiene | Docs sync, accuracy |
| `03-test-coverage.md` | Test Coverage | Testing, coverage |
| `04.md` | Agent 04 | General purpose |
| `05.md` | Agent 05 | General purpose |
| `06.md` | Agent 06 | General purpose |
| `07.md` | Agent 07 | General purpose |
| `08.md` | Agent 08 | General purpose |
| `09.md` | Agent 09 | General purpose |
| `10.md` | Agent 10 | General purpose |
| `11.md` | Agent 11 | General purpose |

## Autonomous Workflow

```bash
# 1. Start with strategist for planning
gemini -s "$(cat 00-strategist.md)" "User wants dark mode"

# 2. Specialists execute assigned tasks
gemini -s "$(cat 08.md)" "Create dark mode toggle"
gemini -s "$(cat 02.md)" "Extract theme to config"
gemini -s "$(cat 03.md)" "Add dark mode tests"

# 3. Strategist reviews
gemini -s "$(cat 00-strategist.md)" "Review dark mode progress"
```

## Documents Managed

| Document | Purpose | Managed By |
|----------|---------|------------|
| `docs/blueprint.md` | Architecture & standards | 00 Strategist |
| `docs/task.md` | Task backlog | 00 Strategist |
| `docs/feature.md` | Feature specs | 00 Strategist |
| `docs/roadmap.md` | Strategic direction | 00 Strategist |

## Size

| Version | Size | For |
|---------|------|-----|
| Full (root/*.txt) | 7-15 KB | IDE, manual use |
| Condensed (cli/*.md) | 1.5-3 KB | CLI tools |
