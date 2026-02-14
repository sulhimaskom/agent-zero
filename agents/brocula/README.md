# 🧛 BroCula - Browser Console & Lighthouse Optimization Specialist

BroCula is a specialized agent profile for Agent Zero that focuses on browser console monitoring, error detection, and Lighthouse performance optimization.

## Overview

BroCula loves working in the browser console. He follows strict workflows to ensure your web application has:
- **Zero console errors**
- **Optimized Lighthouse scores**
- **Clean build output**
- **Zero lint errors**

## Strict Workflows

### 1. Browser Console Error Detection
- Uses Playwright MCP or browser_agent to monitor console
- Captures all logs (errors, warnings, info)
- **Errors are FATAL** - must be fixed immediately
- Fixes issues without deferring
- Verifies console is clean after fixes

### 2. Lighthouse Optimization
- Runs Lighthouse audits on all pages
- Targets: Performance 90+, Accessibility 100, Best Practices 100, SEO 100
- Identifies top optimization opportunities
- Implements fixes
- Re-audits to verify improvements

### 3. Build & Lint Validation
- Runs production build
- **Build errors = FATAL** - blocks all progress
- Runs lint checks
- **Lint errors = FATAL** - blocks all progress
- Fixes all issues immediately

### 4. PR Creation & Branch Management
- Syncs branch with main before creating PR
- Creates descriptive PR with findings
- Links to relevant issues
- Monitors CI/CD for failures

## Quick Start

### Local Execution

```bash
# Run BroCula locally
python agents/brocula/brocula.py

# Or use the Agent Zero CLI
./run_ui.py --agent brocula
```

### GitHub Actions (Automated)

The workflow runs automatically:
- Every 4 hours
- On every push to main/develop
- Manually via workflow_dispatch

```bash
# Trigger manually
curl -X POST \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/repos/$OWNER/$REPO/actions/workflows/brocula-monitor.yml/dispatches \
  -d '{"ref":"main"}'
```

## Configuration

### MCP Servers

BroCula uses the following MCP servers:

1. **Playwright MCP** (`@anthropic-ai/playwright-mcp`)
   - Browser automation
   - Console log capture
   - Screenshot capture
   - JavaScript evaluation

2. **Chrome DevTools MCP** (`@chrome-ai/devtools-mcp`)
   - Performance profiling
   - Memory analysis
   - Network monitoring
   - Advanced debugging

3. **Lighthouse MCP** (`@modelcontextprotocol/server-lighthouse`)
   - Performance auditing
   - Accessibility checking
   - Best practices validation
   - SEO analysis

### Configuration Files

- `agents/brocula/mcp-servers.json` - MCP server definitions
- `agents/brocula/prompts/agent.system.brocula.md` - System prompt
- `.github/workflows/brocula-monitor.yml` - GitHub Actions workflow

## Response Format

BroCula provides detailed reports:

```
## Browser Console Report
- **Errors**: 0 - Clean
- **Warnings**: 2 - Non-critical
- **Status**: ✅ Clean

## Lighthouse Report
- **Performance**: 94/100 (↑5)
- **Accessibility**: 100/100
- **Best Practices**: 100/100
- **SEO**: 98/100 (↑2)
- **Opportunities**:
  1. Eliminate render-blocking resources
  2. Optimize images (WebP format)
  3. Enable text compression

## Actions Taken
1. Fixed null reference error in app.js:42
2. Optimized hero image (2.3MB → 180KB)
3. Enabled gzip compression

## Build/Lint Status
- **Build**: ✅ Pass
- **Lint**: ✅ Pass

## PR Status
- **Branch**: brocula/fix-browser-issues-123456
- **Status**: ✅ Created
- **URL**: https://github.com/owner/repo/pull/123
```

## Rules

1. **Errors are fatal**: Console or build errors block all progress
2. **Fix immediately**: No deferring of console fixes
3. **Verify after fix**: Always re-check console
4. **Branch hygiene**: Sync with main before PR
5. **Clean builds**: Build/lint errors are unacceptable
6. **Document everything**: Report all findings clearly

## Agent Profile

- **Name**: BroCula
- **Model**: opencode/kimi-k2.5-free
- **Temperature**: 0.2 (focused, deterministic)
- **Tools**: Playwright MCP, Chrome DevTools MCP, browser_agent
- **Mission**: Maintain pristine browser console and optimal Lighthouse scores

## Integration with Oh My OpenCode

Add to `.opencode/oh-my-opencode.json`:

```json
{
  "agents": {
    "BroCula": {
      "model": "opencode/kimi-k2.5-free",
      "temperature": 0.2,
      "description": "Browser console monitoring and Lighthouse optimization specialist"
    }
  },
  "mcpServers": {
    "enabled": true,
    "servers": [
      "playwright",
      "chrome-devtools",
      "lighthouse"
    ]
  }
}
```

## Usage Examples

### Manual Trigger

```bash
# Via OpenCode CLI
opencode run "ultrawork

Act as BroCula. Monitor browser console at http://localhost:3000,
fix any errors, run Lighthouse audit, and create PR if needed." \
  --model opencode/kimi-k2.5-free
```

### GitHub Comment Trigger

Comment on any PR or issue:
```
/ulw-loop "Act as BroCula. Check browser console on this PR's preview URL."
```

### Scheduled Monitoring

The GitHub Actions workflow runs automatically every 4 hours to catch issues early.

## Troubleshooting

### MCP Server Not Found

Install MCP servers:
```bash
npx --yes --package @anthropic-ai/playwright-mcp playwright-mcp
npx --yes --package @chrome-ai/devtools-mcp devtools-mcp
```

### Browser Not Starting

Check Playwright installation:
```bash
npx playwright install chromium
npx playwright install-deps chromium
```

### Build/Lint Failures

BroCula treats these as fatal. Check:
```bash
npm run build
npm run lint
```

## Contributing

To extend BroCula:

1. Add tools to `agents/brocula/tools/`
2. Add extensions to `agents/brocula/extensions/`
3. Update prompts in `agents/brocula/prompts/`
4. Update this README

## License

Same as Agent Zero project license.

---

*"You are BroCula. You love working in the browser console. You fix errors immediately. You optimize relentlessly. You never leave a mess behind."*
