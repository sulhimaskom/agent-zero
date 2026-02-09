# Notes: Hardcoded Values Analysis

## Existing Configuration System
- `.env.example` - Environment variables
- `conf/` - Configuration directory with `model_providers.yaml`
- `python/helpers/settings.py` - Settings management (1741 lines - identified as complexity hotspot)

## Categories of Hardcoded Values to Find
1. Magic numbers (numeric constants)
2. Hardcoded strings (messages, labels)
3. URLs and endpoints
4. File paths
5. Timeouts and retry limits
6. Buffer sizes and limits
7. Default values

## Files with Known Issues (from AGENTS.md)
- `/python/helpers/settings.py` - 1741 lines, complexity hotspot
- `/python/helpers/task_scheduler.py` - 1156 lines
- `/python/helpers/mcp_handler.py` - 1116 lines
- `/webui/js/scheduler.js` - 1835 lines
- `/webui/js/messages.js` - 1009 lines

## Analysis Status
- [x] Python helpers/ - Found constants.py already exists and is comprehensive!
- [ ] Python helpers/ - Need to verify all files use constants
- [ ] Python api/ - Pending
- [ ] Python tools/ - Pending
- [ ] WebUI js/ - Pending
- [ ] WebUI components/ - Pending
- [ ] Root level files (agent.py, models.py, run_ui.py) - Pending

## Key Findings
1. **EXCELLENT**: `python/helpers/constants.py` already exists with:
   - Timeouts class with 25+ timeout constants
   - Limits class with 50+ limit constants  
   - Network class with ports and URLs
   - Paths class with directory structures
   - Colors class with UI colors
   - Config class with environment variable support
   
2. **Files NOT using constants** (hardcoded values found):
   - `python/helpers/backup.py:262` - max_files: int = 1000
   - `python/helpers/email_client.py:98` - maxline = 100000
   - `python/helpers/fasta2a_client.py:19,191` - timeout: int = 30
   - `python/helpers/file_browser.py:22` - MAX_FILE_SIZE = 100MB
   - `python/helpers/notification.py:128` - seconds: int = 30
   - `python/helpers/rate_limiter.py:7` - seconds: int = 60
   - `python/helpers/task_scheduler.py:183,344,419` - frequency_seconds: float = 60.0

3. **Task**: Refactor files to use constants from constants.py
