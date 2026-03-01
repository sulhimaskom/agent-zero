#!/usr/bin/env python3
"""
AI Code Review Pre-commit Hook

Runs on staged files and provides AI-powered code review suggestions
using local Ollama LLM. Non-blocking - suggestions only.

Usage:
    Pre-commit hook (automatic via pre-commit framework)
    Or run directly: python hooks/ai_review/ai_review_hook.py

Requirements:
    - pip install litellm
    - Ollama running locally with a model pulled
    - Default model: codellama (configurable)
"""

import argparse
import os
import sys
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

# Try to import litellm, provide helpful error if not installed
try:
    import litellm
except ImportError:
    print("ERROR: litellm not installed. Install with: pip install litellm")
    print("Or run: make install-dev")
    sys.exit(0)  # Non-blocking - don't fail commit

# Configuration
DEFAULT_MODEL = "ollama/codellama"
DEFAULT_MAX_TOKENS = 512
DEFAULT_TEMPERATURE = 0.3

# File extensions to review
SUPPORTED_EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript React",
    ".jsx": "JavaScript React",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".cpp": "C++",
    ".c": "C",
}

# Files to skip
SKIP_PATTERNS = [
    "vendor/",
    "node_modules/",
    "__pycache__/",
    ".git/",
    "venv/",
    ".venv/",
    "dist/",
    "build/",
    ".pytest_cache/",
    ".ruff_cache/",
    ".mypy_cache/",
]


def get_staged_files() -> list[str]:
    """Get list of staged files from git."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            check=True,
        )
        files = result.stdout.strip().split("\n")
        return [f for f in files if f]
    except subprocess.CalledProcessError as e:
        print(f"Warning: Could not get staged files: {e}")
        return []


def should_skip_file(filepath: str) -> bool:
    """Check if file should be skipped."""
    for pattern in SKIP_PATTERNS:
        if pattern in filepath:
            return True
    return False


def get_file_extension(filepath: str) -> Optional[str]:
    """Get the file extension and language."""
    ext = Path(filepath).suffix.lower()
    return SUPPORTED_EXTENSIONS.get(ext)


def read_file_content(filepath: str) -> Optional[str]:
    """Read file content."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        print(f"Warning: Could not read {filepath}: {e}")
        return None


def build_review_prompt(content: str, language: str, filepath: str) -> str:
    """Build the prompt for code review."""
    return f"""You are an expert code reviewer. Review the following {language} code for:
1. Security vulnerabilities
2. Code quality issues
3. Best practices violations
4. Potential bugs

File: {filepath}

Code:
```{language.lower()}
{content}
```

Provide a concise review with specific, actionable suggestions.
Format your response as:
- Issue: [brief description]
- Suggestion: [how to fix]
- Line: [approximate line number if applicable]

If no issues found, respond with "NO ISSUES FOUND" only.
"""


def call_llm(prompt: str, model: str = DEFAULT_MODEL) -> Optional[str]:
    """Call the LLM via LiteLLM."""
    try:
        # Check if Ollama is running
        try:
            response = litellm.completion(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=DEFAULT_MAX_TOKENS,
                temperature=DEFAULT_TEMPERATURE,
            )
            return response.choices[0].message.content
        except Exception as e:
            # Check if it's a connection error (Ollama not running)
            if "connection" in str(e).lower() or "connect" in str(e).lower():
                print(f"Note: Ollama not running. Skipping AI review.")
                print(f"      Start Ollama with: ollama serve")
                print(f"      And pull a model: ollama pull codellama")
                return None
            # Other errors - still skip but warn
            print(f"Warning: LLM call failed: {e}")
            return None
    except Exception as e:
        print(f"Warning: Unexpected error calling LLM: {e}")
        return None


def review_file(filepath: str, model: str) -> Optional[str]:
    """Review a single file."""
    # Check if we should skip
    if should_skip_file(filepath):
        return None

    # Get language
    language = get_file_extension(filepath)
    if not language:
        return None

    # Read content
    content = read_file_content(filepath)
    if not content:
        return None

    # Skip empty files
    if not content.strip():
        return None

    # Build prompt
    prompt = build_review_prompt(content, language, filepath)

    # Call LLM
    return call_llm(prompt, model)


def print_review(filepath: str, review: str) -> None:
    """Print the review in a formatted way."""
    print("\n" + "=" * 60)
    print(f"🤖 AI Code Review: {filepath}")
    print("=" * 60)
    print(review)
    print("=" * 60 + "\n")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AI Code Review Pre-commit Hook"
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"LLM model to use (default: {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--files",
        nargs="*",
        help="Specific files to review (instead of staged files)",
    )
    parser.add_argument(
        "--fail-on-issues",
        action="store_true",
        help="Fail commit if issues found (for testing)",
    )
    args = parser.parse_args()

    # Get files to review
    if args.files:
        files_to_review = args.files
    else:
        files_to_review = get_staged_files()

    if not files_to_review:
        print("No files to review.")
        return

    print(f"🔍 AI Code Review - Checking {len(files_to_review)} file(s)...\n")

    # Review each file
    total_issues = 0
    files_with_issues = 0

    for filepath in files_to_review:
        review = review_file(filepath, args.model)
        if review:
            print_review(filepath, review)
            if "NO ISSUES FOUND" not in review.upper():
                total_issues += 1
                files_with_issues += 1

    # Summary
    print("\n" + "=" * 60)
    print(f"📊 Review Summary")
    print("=" * 60)
    print(f"Files reviewed: {len(files_to_review)}")
    print(f"Files with suggestions: {files_with_issues}")
    print("=" * 60)

    if files_with_issues > 0:
        print("\n💡 Review suggestions above. Commit continues...")
        # Non-blocking - just print suggestions
        return

    print("\n✅ No issues found. Good to commit!")


if __name__ == "__main__":
    main()
