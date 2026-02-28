# Technical Writer Agent - Long-term Memory

> Last Updated: 2026-02-28

## Entry #16: PR #447 - Timestamp Format Standardization
**Date:** 2026-02-28
**PR:** #447
**Summary:** Standardized Last Updated metadata format in docs/setup/vps-deployment.md
- Converted from bold (**Last Updated:**) to plain text format
- Standardized date to YYYY-MM-DD format
- Fixed 1 file on current main branch

## Entry #15: PR #445 - Timestamp Format Standardization (Initial)
**Date:** 2026-02-27
**PR:** #445 (closed - replaced by #447)
**Summary:** Standardized Last Updated metadata format across documentation files
- Converted 14+ files from bold (**Last Updated:**) to blockquote (> Last Updated:) format
- Fixed user-story-engineer.md with duplicate timestamps
- Standard format: > Last Updated: YYYY-MM-DD

## Domain Guidelines

### Documentation Standards
1. **Timestamp Format**: Use `> Last Updated: YYYY-MM-DD` (blockquote with ISO date)
2. **File Organization**: All documentation in `docs/` directory
3. **Markdown**: Use standard Markdown syntax
4. **Front Matter**: Not required - use blockquote metadata instead

### Workflow
1. **INITIATE**: Check for existing technical-writer PRs/issues
2. **PLAN**: Identify scope of documentation changes
3. **IMPLEMENT**: Make targeted changes
4. **VERIFY**: Run grep to confirm changes
5. **SELF-REVIEW**: Review diff for quality
6. **SELF_EVOLV**: Update this memory file
7. **DELIVER**: Create PR with technical-writer label

### Common Issues Found
- Duplicate timestamps in some docs
- Inconsistent formatting (bold vs blockquote)
- Non-standard date formats (e.g., "December 21 2025" instead of "2025-12-21")

### PR Requirements
- Label: technical-writer
- Linked to issue if any
- Up to date with default branch
- No conflict
- Build/lint/test success
- ZERO warnings
- Small atomic diff
