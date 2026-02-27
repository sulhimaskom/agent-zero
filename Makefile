# Agent Zero Makefile
# Common development tasks for Agent Zero
#
# Usage: make <target>
#
# Targets:
#   help          - Show this help message (default)
#   install       - Install production dependencies
#   install-dev   - Install development dependencies
#   lint          - Run ruff linter
#   format        - Format code with ruff
#   typecheck     - Run mypy type checker
#   test          - Run pytest tests
#   run           - Run Agent Zero in development mode
#   docker-build  - Build local Docker image
#   docker-run    - Run Agent Zero Docker container
#   pre-commit    - Install pre-commit hooks
#   ai-review     - Run AI code review on staged files
#   ai-review-install - Install AI code review hook
#   clean         - Clean up cache files

.PHONY: help install install-dev lint format typecheck test run docker-build docker-run pre-commit ai-review ai-review-install clean

# Default target
help:
	@echo "Agent Zero - Common Development Tasks"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Development:"
	@echo "  install-dev   - Install development dependencies"
	@echo "  lint          - Run ruff linter"
	@echo "  format        - Format code with ruff"
	@echo "  typecheck     - Run mypy type checker"
	@echo "  test          - Run pytest tests"
	@echo "  run           - Run Agent Zero in development mode"
	@echo "  pre-commit    - Install pre-commit hooks"
	@echo "  ai-review     - Run AI code review on staged files"
	@echo "  ai-review-install - Install AI code review pre-commit hook"
	@echo ""
	@echo "Installation:"
	@echo "  install       - Install production dependencies"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build  - Build local Docker image"
	@echo "  docker-run    - Run Agent Zero Docker container"
	@echo ""
	@echo "Cleanup:"
	@echo "  clean         - Clean up cache files"
	@echo ""
	@echo "Examples:"
	@echo "  make install-dev      # Install dev dependencies"
	@echo "  make lint             # Check for linting errors"
	@echo "  make format           # Auto-fix linting issues"
	@echo "  make test             # Run tests"
	@echo "  make run              # Start development server"
	@echo "  make ai-review        # Run AI code review"

# Install production dependencies
install:
	pip install -r requirements.txt
	playwright install chromium

# Install development dependencies
install-dev: install
	pip install -r requirements.dev.txt

# Run ruff linter
lint:
	ruff check .

# Format code with ruff
format:
	ruff format .

# Run mypy type checker
typecheck:
	mypy python/

# Run pytest tests
test:
	pytest tests/ -v

# Run Agent Zero in development mode
run:
	python run_ui.py --development=true -Xfrozen_modules=off

# Build local Docker image
docker-build:
	docker build -f DockerfileLocal -t agent-zero-local --build-arg CACHE_DATE=$$(date +%Y-%m-%d:%H:%M:%S) .

# Run Agent Zero Docker container
docker-run:
	docker run -p 50001:80 agent-zero-local

# Install pre-commit hooks
pre-commit:
	pre-commit install

# Run AI code review on staged files
ai-review:
	@echo "Running AI code review..."
	python hooks/ai_review/ai_review_hook.py

# Install AI code review pre-commit hook
ai-review-install: pre-commit
	@echo "Installing AI code review hook..."
	@echo "Note: Ensure Ollama is installed and running"
	@echo "  Install: https://ollama.com"
	@echo "  Then run: ollama pull codellama"

# Clean up cache files
clean:
	rm -rf __pycache__ .pytest_cache .mypy_cache
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type f -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
