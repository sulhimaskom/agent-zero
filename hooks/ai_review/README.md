# AI Code Review Hook

A pre-commit Git hook that uses local LLMs (via Ollama) to provide inline code review suggestions.

## Features

- **Security Analysis**: Detects potential security vulnerabilities
- **Code Quality**: Identifies code quality issues
- **Best Practices**: Suggests improvements based on language best practices
- **Bug Detection**: Spots potential bugs before they reach CI

## Requirements

1. **Ollama** installed and running
2. **Python 3.8+** with litellm

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a coding model
ollama pull codellama
# or
ollama pull llama2
```

## Installation

### Method 1: Using pre-commit (Recommended)

Add to your `.pre-commit-config.yaml`:

```yaml
- repo: local
  hooks:
    - id: ai-code-review
      name: AI Code Review
      entry: python hooks/ai_review/ai_review_hook.py
      language: system
      stages: [pre-commit]
      types: [python, javascript, typescript, java, go, rust]
```

Then run:
```bash
pre-commit install
```

### Method 2: Using Makefile

```bash
make ai-review-install
```

### Method 3: Manual

```bash
# Create the hook file
cp hooks/ai_review/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Usage

The hook runs automatically on `git commit`. It will:

1. Get staged files
2. Send each file to the local LLM
3. Display inline suggestions
4. Allow the commit to proceed (non-blocking)

### Running Manually

```bash
# Review staged files
python hooks/ai_review/ai_review_hook.py

# Review specific files
python hooks/ai_review/ai_review_hook.py --files src/main.py

# Use a specific model
python hooks/ai_review/ai_review_hook.py --model ollama/llama2
```

## Configuration

Edit `hooks/ai_review/ai_review_config.yaml` to customize:

- Model selection
- File patterns to include/exclude
- Review categories
- Behavior (blocking/non-blocking)

## Supported Languages

- Python (.py)
- JavaScript (.js)
- TypeScript (.ts, .tsx)
- Java (.java)
- Go (.go)
- Rust (.rs)
- Ruby (.rb)
- PHP (.php)
- C# (.cs)
- C/C++ (.c, .cpp)

## Troubleshooting

### "Ollama not running"

Start Ollama:
```bash
ollama serve
```

### "Model not found"

Pull a model:
```bash
ollama pull codellama
```

### "litellm not installed"

```bash
pip install litellm
# or
make install-dev
```

## Integration with Agent Zero

This hook integrates with Agent Zero's existing infrastructure:

- Uses LiteLLM (already in requirements.txt)
- Respects existing model providers configuration
- Compatible with existing pre-commit setup
