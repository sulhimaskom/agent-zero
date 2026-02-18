# P1: Implement Structured Logging

**Priority:** P1  
**Category:** enhancement  
**Impact:** MEDIUM - Production observability

## Current State
- **101 PrintStyle calls** across 29 files
- PrintStyle provides basic logging but:
  - No structured format (JSON)
  - No log levels configuration
  - No log rotation
  - No external log aggregation support

## Current Implementation
```python
# python/helpers/print_style.py
class PrintStyle:
    @staticmethod
    def standard(message: str, **kwargs):
        PrintStyle._print(message, log_only=False, **kwargs)
    
    @staticmethod
    def error(message: str, **kwargs):
        PrintStyle._print(message, log_only=False, print_enum=PrintStyleEnum.ERROR, **kwargs)
```

## Problems
- **Not production-ready** for log aggregation systems
- **No log rotation** - files grow indefinitely
- **No configuration** - can't adjust log levels
- **No structured data** - hard to query logs
- **Limited context** - no request IDs, timestamps, etc.

## Proposed Solution
Replace PrintStyle with Python's `logging` module:

```python
import logging
import json
from pythonjsonlogger import jsonlogger

# Structured logging configuration
logger = logging.getLogger("agent-zero")

# JSON formatter for production
formatter = jsonlogger.JsonFormatter(
    '%(timestamp)s %(level)s %(name)s %(message)s %(context_id)s'
)

# Log rotation
handler = logging.handlers.RotatingFileHandler(
    'logs/agent-zero.log',
    maxBytes=10485760,  # 10MB
    backupCount=5
)
```

## Acceptance Criteria
- [ ] Replace PrintStyle with logging module
- [ ] JSON format option for production
- [ ] Log rotation (10MB files, 5 backups)
- [ ] Configurable log levels (DEBUG, INFO, WARN, ERROR)
- [ ] Request/context ID tracking
- [ ] Backward compatibility (don't break existing calls)
- [ ] Documentation updated

## Migration Strategy
1. **Phase 1:** Create wrapper around logging that mimics PrintStyle API
2. **Phase 2:** Add JSON formatter option
3. **Phase 3:** Add log rotation
4. **Phase 4:** Add configuration options
5. **Phase 5:** Gradually replace PrintStyle calls with logger calls
6. **Phase 6:** Deprecate PrintStyle

## Files to Modify
- `python/helpers/print_style.py` - Replace implementation
- `python/helpers/log.py` - May need updates
- `conf/settings.yaml` or similar - Add logging config
- `docs/configuration.md` - Document logging options

## Benefits
- Integration with ELK, Splunk, Datadog
- Better debugging with context
- Production-ready observability
- Standard Python logging ecosystem

---
*Generated from Audit Report 2026-02-18*
