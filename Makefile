# Agent Zero - Makefile for Common Development Tasks
# https://github.com/agent0ai/agent-zero

.PHONY: help install install-dev install-browser test lint format typecheck docker-build docker-run clean pre-commit pre-commit-install

# Default target
help:
	@echo "Agent Zero - Development Commands"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Development:"
	@echo "  install         Install production dependencies"
	@echo "  install-dev     Install development dependencies"
	@echo "  install-browser Install Playwright browser binaries"
	@echo "  test            Run pytest test suite"
	@echo "  lint            Run ruff linter"
	@echo "  format          Run ruff formatter"
	@echo "  typecheck       Run mypy type checker"
	@echo "  pre-commit      Run pre-commit hooks"
	@echo "  pre-commit-install Install pre-commit hooks"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build    Build local Docker image"
	@echo "  docker-run      Run Agent Zero in Docker"
	@echo ""
	@echo "Utilities:"
	@echo "  clean           Remove Python cache files"
	@echo ""

# Development setup
install:
	pip install -r requirements.txt

install-dev:
	pip install -e ".[dev]"

install-browser:
	playwright install chromium

# Testing
test:
	pytest tests/ -v

# Linting and formatting
lint:
	ruff check .

format:
	ruff format .

# Type checking
typecheck:
	mypy .

# Pre-commit
pre-commit:
	pre-commit run --all-files

pre-commit-install:
	pre-commit install

# Docker
docker-build:
	docker build -f DockerfileLocal -t agent-zero-local --build-arg CACHE_DATE=$(shell date +%Y-%m-%d:%H:%M:%S) .

docker-run:
	docker run -p 50001:80 agent-zero-local

# Utilities
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ 2>/dev/null || true
