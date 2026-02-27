# Testing Guide

> Last Updated: 2026-02-27

This guide covers the testing infrastructure, patterns, and best practices for Agent Zero.

## Running Tests

### Prerequisites

Install test dependencies:

```bash
pip install -r requirements.dev.txt
```

This installs:
- `pytest>=8.4.2`
- `pytest-asyncio>=1.2.0`
- `pytest-mock>=3.15.1`

### Basic Commands

```bash
# Run all tests
pytest tests/

# Run with verbose output
pytest tests/ -v

# Run specific test file
pytest tests/test_tokens.py -v

# Run specific test class
pytest tests/test_tokens.py::TestCountTokens -v

# Run specific test method
pytest tests/test_tokens.py::TestCountTokens::test_empty_string -v

# Run tests matching a pattern
pytest tests/ -k "test_token"

# Show test coverage (requires pytest-cov)
pytest tests/ --cov=python --cov-report=term-missing
```

### Asyncio Tests

```bash
# Run async tests (asyncio_mode is auto-configured)
pytest tests/ -v

# Run with detailed asyncio output
pytest tests/ -v --asyncio-mode=auto
```

## Test Structure

### File Organization

```
tests/
├── conftest.py              # Pytest configuration and fixtures
├── test_*.py               # Test files (discovered automatically)
└── *_test.py              # Alternative naming pattern
```

### Test Class Pattern

Tests are organized into classes by functionality:

```python
class TestCountTokens:
    """Test count_tokens function"""

    def test_empty_string(self):
        """Test empty string returns 0 tokens"""
        result = count_tokens("")
        assert result == 0

    def test_simple_text(self):
        """Test simple text returns expected token count"""
        result = count_tokens("hello world")
        assert result == 2
```

### Naming Conventions

- **Files**: `test_*.py` or `*_test.py`
- **Classes**: `Test*` (PascalCase)
- **Methods**: `test_*` (snake_case starting with test_)
- **Docstrings**: Required for every test method

## Mock Usage

### Global Mocks (conftest.py)

The `tests/conftest.py` provides extensive mocking for heavy ML/AI dependencies:

```python
# Heavy ML/AI dependencies are pre-mocked
from unittest.mock import MagicMock
import sys

# Mock modules that require GPU/heavy installation
sys.modules["whisper"] = MagicMock()
sys.modules["transformers"] = MagicMock()
sys.modules["torch"] = MagicMock()
sys.modules["faiss"] = MagicMock()
sys.modules["browser_use"] = MagicMock()
# ... 100+ more mocks
```

This allows tests to run without installing GPU-intensive packages.

### AsyncMock for Async Methods

```python
from unittest.mock import MagicMock

class AsyncMock(MagicMock):
    async def __call__(self, *args, **kwargs):
        return super().__call__(*args, **kwargs)
```

### Using Mocks in Tests

```python
from unittest.mock import patch, MagicMock

def test_something_with_mock():
    with patch("module.function") as mock:
        mock.return_value = "mocked"
        # test code here

def test_something_with_context():
    with patch.dict(os.environ, {"VAR": "value"}):
        # test code here
```

### Custom Module Mocks

```python
# Create a mock module with attributes
def create_mock_module(name):
    module = MagicMock()
    sys.modules[name] = module
    return module
```

## Async Testing

### Configuration

The project uses `asyncio_mode = "auto"` in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
asyncio_default_fixture_loop_scope = "function"
```

This automatically detects async test functions.

### Async Test Methods

```python
import pytest

@pytest.mark.asyncio
async def test_async_function():
    result = await some_async_function()
    assert result is not None

# With fixtures
@pytest.mark.asyncio
async def test_with_fixture(async_fixture):
    result = await async_fixture.process()
    assert result.success
```

### Async Fixtures

```python
@pytest.fixture
async def async_client():
    client = await create_client()
    yield client
    await client.close()
```

## Pytest Configuration

Configuration is in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py", "*_test.py"]
python_functions = ["test_*"]
asyncio_mode = "auto"
asyncio_default_fixture_loop_scope = "function"
filterwarnings = [
    "ignore::DeprecationWarning",
    "ignore::PendingDeprecationWarning",
]
```

## Test Coverage Priorities

Based on the codebase analysis, priority areas for test coverage:

### High Priority
1. **python/helpers/** - Core utilities (memory, history, settings)
2. **python/api/** - Flask API endpoints
3. **python/tools/** - Tool implementations
4. **python/extensions/** - Extension hooks

### Medium Priority
1. **python/helpers/task_scheduler.py** - Complex scheduling logic
2. **python/helpers/mcp_handler.py** - MCP protocol handling
3. **python/helpers/settings.py** - Configuration management

### Test Coverage Commands

```bash
# Run with coverage
pytest tests/ --cov=python --cov-report=term-missing

# Generate HTML report
pytest tests/ --cov=python --cov-report=html

# Show uncovered lines
pytest tests/ --cov=python --cov-report=term-missing --cov-fail-under=0
```

## Best Practices

### 1. One Assertion Per Test

```python
# Good: Single, clear assertion
def test_count_tokens_empty():
    result = count_tokens("")
    assert result == 0

# Avoid: Multiple assertions
def test_count_tokens():
    result = count_tokens("")
    assert result == 0  # Don't do this
    assert isinstance(result, int)  # Separate test
```

### 2. Descriptive Names

```python
# Good: Describes what is being tested
def test_trim_from_start_keeps_beginning():
    ...

# Avoid: Vague names
def test_trim():
    ...
```

### 3. Docstrings

Every test should have a docstring explaining what it verifies:

```python
def test_approximate_tokens_buffer_consistency(self):
    """Test buffer is applied consistently"""
    ...
```

### 4. Use Fixtures for Reusable Setup

```python
@pytest.fixture
def sample_text():
    return "The quick brown fox jumps over the lazy dog"

def test_with_fixture(sample_text):
    result = count_tokens(sample_text)
    assert result > 0
```

### 5. Test Edge Cases

```python
def test_edge_cases():
    # Empty
    assert count_tokens("") == 0
    # Whitespace
    assert count_tokens("   ") > 0
    # Special characters
    assert count_tokens("hello\n\tworld!") >= 2
```

## Troubleshooting

### Import Errors

If you get import errors, check `tests/conftest.py` for required mocks. The test framework pre-mocks heavy dependencies.

### Async Warnings

If you see asyncio warnings, ensure:
1. `pytest-asyncio` is installed
2. Test methods are marked with `@pytest.mark.asyncio`
3. `asyncio_mode = "auto"` is set in pyproject.toml

### Missing Dependencies

Install all dev dependencies:

```bash
pip install -r requirements.dev.txt
```

## CI Integration

Tests run in GitHub Actions on pull requests. See `.github/workflows/on-push-optimized.yml` for the pytest job configuration.

```bash
# Local CI check
pytest tests/ -v --tb=short
```

## Related Documentation

- [Development Guide](./development.md)
- [Architecture Overview](./architecture.md)
- [Extensibility Guide](./extensibility.md)
