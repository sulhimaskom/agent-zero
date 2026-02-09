# OpenCode Configuration for Agent Zero

This directory contains OpenCode configuration with oh-my-opencode and additional skills.

## Installed Components

### 1. oh-my-opencode
- **Purpose**: Multi-agent orchestration harness for OpenCode
- **Configuration**: `oh-my-opencode.json`
- **Models Configured**:
  - Sisyphus: opencode/kimi-k2.5-free (main orchestrator)
  - Hephaestus: opencode/big-pickle (autonomous worker)
  - Oracle: opencode/minimax-m2.1-free (design/debugging)
  - Librarian: opencode/kimi-k2.5-free (documentation)
  - Explore: opencode/kimi-k2.5-free (codebase exploration)
  - Frontend: opencode/kimi-k2.5-free (UI/UX)

### 2. Superpowers
- **Source**: https://github.com/obra/superpowers
- **Integration**: Skills linked in `skills/superpowers/`
- **Plugin**: Linked in `plugins/superpowers.js`
- **Available Skills**:
  - brainstorming
  - test-driven-development
  - systematic-debugging
  - writing-plans
  - executing-plans
  - subagent-driven-development
  - requesting-code-review
  - using-git-worktrees
  - finishing-a-development-branch
  - And more...

### 3. Agent Skills
- **Source**: https://github.com/sulhi-sabil/agent-skill
- **Integration**: Skills linked in `skills/`
- **Available Skills**:
  - github-workflow-automation
  - planning
  - skill-creator

## Features Enabled

- LSP/AST Support
- Todo Enforcer
- Comment Checker
- Background Agents
- Claude Code Compatibility
- MCP Servers (Exa, Context7, Grep.app)

## Usage

Include `ultrawork` or `ulw` in your prompt to activate all features.

## Installation

```bash
cd .opencode
npm install
```

## Directory Structure

```
.opencode/
├── oh-my-opencode.json    # Main configuration
├── node_modules/          # Dependencies (gitignored)
├── skills/               # Skill symlinks
│   ├── superpowers -> ../superpowers/skills
│   ├── github-workflow-automation
│   ├── planning
│   └── skill-creator
├── plugins/              # Plugin symlinks
│   └── superpowers.js
├── superpowers/          # Superpowers repository
└── agent-skill/          # Agent-skill repository
```
