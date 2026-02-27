# Makefile for Agent Zero Development
# Run `make help` to see available targets

.PHONY: help install install-playwright test test-verbose run clean docker-build docker-pull

# Default target
.DEFAULT_GOAL := help

# Colors for help output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
CYAN := \033[0;36m
NC := \033[0m # No Color

help:
	@echo ""
	@echo "$(CYAN)Agent Zero Development Commands$(NC)"
	@echo "$(CYAN)===============================$(NC)"
	@echo ""
	@echo "$(GREEN)Setup$(NC):"
	@echo "  $(YELLOW)make install$(NC)          Install Python dependencies"
	@echo "  $(YELLOW)make install-playwright$(NC)  Install Playwright browser binaries"
	@echo "  $(YELLOW)make install-all$(NC)       Install dependencies + Playwright"
	@echo ""
	@echo "$(GREEN)Development$(NC):"
	@echo "  $(YELLOW)make run$(NC)               Run Agent Zero UI (python run_ui.py)"
	@echo "  $(YELLOW)make test$(NC)               Run test suite with pytest"
	@echo "  $(YELLOW)make test-verbose$(NC)       Run tests with verbose output"
	@echo ""
	@echo "$(GREEN)Docker$(NC):"
	@echo "  $(YELLOW)make docker-build$(NC)       Build local Docker image"
	@echo "  $(YELLOW)make docker-pull$(NC)         Pull latest Agent Zero image"
	@echo ""
	@echo "$(GREEN)Utilities$(NC):"
	@echo "  $(YELLOW)make clean$(NC)              Clean temporary files"
	@echo ""
	@echo "For more details, see docs/setup/dev-setup.md"
	@echo ""

# Install Python dependencies
install:
	@echo "$(BLUE)Installing Python dependencies...$(NC)"
	pip install -r requirements.txt

# Install Playwright browsers
install-playwright:
	@echo "$(BLUE)Installing Playwright browsers...$(NC)"
	playwright install chromium

# Install all dependencies
install-all: install install-playwright
	@echo "$(GREEN)All dependencies installed!$(NC)"

# Run Agent Zero UI
run:
	@echo "$(BLUE)Starting Agent Zero UI...$(NC)"
	python run_ui.py

# Run tests
test:
	@echo "$(BLUE)Running test suite...$(NC)"
	pytest tests/ -v

# Run tests with verbose output
test-verbose:
	@echo "$(BLUE)Running test suite (verbose)...$(NC)"
	pytest tests/ -vv --tb=long

# Build local Docker image
docker-build:
	@echo "$(BLUE)Building local Docker image...$(NC)"
	docker build -f DockerfileLocal -t agent-zero-local --build-arg CACHE_DATE=$(shell date +%Y-%m-%d:%H:%M:%S) .

# Pull latest Docker image
docker-pull:
	@echo "$(BLUE)Pulling latest Agent Zero image...$(NC)"
	docker pull agent0ai/agent-zero

# Clean temporary files
clean:
	@echo "$(BLUE)Cleaning temporary files...$(NC)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)Clean complete!$(NC)"
