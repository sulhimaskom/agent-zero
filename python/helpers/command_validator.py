"""
Command validation and sanitization utilities for secure code execution.

This module provides security functions to validate and sanitize shell commands
to prevent command injection vulnerabilities while maintaining functionality
for legitimate use cases.
"""

import re
import shlex
import logging
from typing import List, Optional, Tuple, Set


# Dangerous patterns that should be blocked
DANGEROUS_PATTERNS = [
    # Command chaining and redirection
    r'[;&|`$()]',  # Shell metacharacters
    r'\|\|',       # OR operator
    r'&&',         # AND operator
    r'>>',         # Append redirection
    r'<',          # Input redirection
    r'>',          # Output redirection
    
    # Command substitution
    r'\$\(',       # Command substitution
    r'`',          # Backtick command substitution
    
    # Variable expansion that could be dangerous
    r'\$\{',       # Variable expansion
    r'\$\w+',      # Simple variable expansion
    
    # Background execution
    r'&\s*$',      # Background process at end
    r'\s+&\s+',    # Background process in middle
    
    # History expansion
    r'!!',         # History expansion
    r'!\d+',       # History reference
    r'!\w+',       # History by name
    
    # Process substitution
    r'<\(',        # Process substitution
    r'>\(',        # Process substitution
    
    # Arithmetic expansion
    r'\$\(\(',     # Arithmetic expansion
    r'\[\[',       # Conditional expression
    
    # Covert channels
    r'/dev/',      # Device file access
    r'/proc/',     # Process filesystem
    r'/sys/',      # System filesystem
]

# Compile patterns for efficiency
COMPILED_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in DANGEROUS_PATTERNS]

# Allowed commands (whitelist approach)
ALLOWED_COMMANDS = {
    # File operations
    'ls', 'cat', 'head', 'tail', 'grep', 'find', 'locate', 'which', 'whereis',
    'file', 'stat', 'wc', 'sort', 'uniq', 'cut', 'awk', 'sed', 'tr',
    
    # Directory operations
    'pwd', 'cd', 'mkdir', 'rmdir', 'rm', 'cp', 'mv', 'ln',
    
    # Text processing
    'echo', 'printf', 'date', 'whoami', 'id', 'uname', 'uptime',
    
    # System information
    'ps', 'top', 'htop', 'df', 'du', 'free', 'mount', 'umount',
    
    # Network (basic diagnostics only)
    'ping', 'traceroute', 'nslookup', 'dig', 'netstat', 'ss',
    
    # Compression
    'tar', 'gzip', 'gunzip', 'zip', 'unzip',
    
    # Development tools
    'git', 'python', 'python3', 'node', 'npm', 'pip', 'pip3',
    'make', 'cmake', 'gcc', 'g++', 'javac', 'java',
    
    # Package managers (read-only operations)
    'apt', 'apt-cache', 'yum', 'dnf', 'pacman',
    
    # Editors (safe mode)
    'nano', 'vim', 'vi', 'emacs',
}

# Commands that require special handling
SPECIAL_COMMANDS = {
    'cd': {'max_args': 1, 'allow_flags': []},
    'rm': {'max_args': 10, 'allow_flags': ['-r', '-f', '-i']},
    'cp': {'max_args': 10, 'allow_flags': ['-r', '-f', '-i', '-v']},
    'mv': {'max_args': 10, 'allow_flags': ['-f', '-i', '-v']},
    'mkdir': {'max_args': 5, 'allow_flags': ['-p', '-v']},
    'find': {'max_args': 20, 'allow_flags': ['-name', '-type', '-path', '-maxdepth', '-mindepth']},
    'grep': {'max_args': 20, 'allow_flags': ['-i', '-v', '-r', '-n', '-l', '-w', '-E', '-F']},
}

logger = logging.getLogger(__name__)


def contains_dangerous_patterns(command: str) -> Tuple[bool, List[str]]:
    """
    Check if a command contains dangerous patterns.
    
    Args:
        command: The command string to check
        
    Returns:
        Tuple of (is_dangerous, list_of_matched_patterns)
    """
    matched_patterns = []
    
    for pattern in COMPILED_PATTERNS:
        if pattern.search(command):
            matched_patterns.append(pattern.pattern)
    
    return len(matched_patterns) > 0, matched_patterns


def parse_command(command: str) -> Tuple[str, List[str], List[str]]:
    """
    Parse a command into its base command, arguments, and flags.
    
    Args:
        command: The command string to parse
        
    Returns:
        Tuple of (base_command, arguments, flags)
    """
    try:
        # Use shlex to properly parse the command
        parts = shlex.split(command)
        if not parts:
            return "", [], []
        
        base_cmd = parts[0]
        args = []
        flags = []
        
        for part in parts[1:]:
            if part.startswith('-'):
                flags.append(part)
            else:
                args.append(part)
        
        return base_cmd, args, flags
    except ValueError as e:
        # If parsing fails, treat as dangerous
        logger.warning(f"Failed to parse command '{command}': {e}")
        return "", [], []


def validate_command_structure(command: str) -> Tuple[bool, str]:
    """
    Validate the structure of a command against allowed patterns.
    
    Args:
        command: The command string to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    base_cmd, args, flags = parse_command(command)
    
    if not base_cmd:
        return False, "Unable to parse command"
    
    # Check if base command is allowed
    if base_cmd not in ALLOWED_COMMANDS:
        return False, f"Command '{base_cmd}' is not in the allowed commands list"
    
    # Check special command requirements
    if base_cmd in SPECIAL_COMMANDS:
        special_config = SPECIAL_COMMANDS[base_cmd]
        
        # Check argument count
        if len(args) > special_config['max_args']:
            return False, f"Too many arguments for command '{base_cmd}'. Maximum allowed: {special_config['max_args']}"
        
        # Check allowed flags
        for flag in flags:
            if flag not in special_config['allow_flags']:
                return False, f"Flag '{flag}' is not allowed for command '{base_cmd}'"
    
    return True, ""


def sanitize_command(command: str) -> Tuple[bool, str, str]:
    """
    Sanitize a command for safe execution.
    
    Args:
        command: The command string to sanitize
        
    Returns:
        Tuple of (is_safe, sanitized_command, error_message)
    """
    # Check for dangerous patterns
    is_dangerous, patterns = contains_dangerous_patterns(command)
    if is_dangerous:
        error_msg = f"Command contains dangerous patterns: {', '.join(patterns)}"
        logger.warning(f"Blocked dangerous command: {command} - {error_msg}")
        return False, "", error_msg
    
    # Validate command structure
    is_valid, error_msg = validate_command_structure(command)
    if not is_valid:
        logger.warning(f"Blocked invalid command: {command} - {error_msg}")
        return False, "", error_msg
    
    # Parse and reconstruct command safely
    base_cmd, args, flags = parse_command(command)
    
    # Reconstruct command with proper quoting
    try:
        sanitized_parts = [base_cmd] + flags + args
        sanitized_command = ' '.join(shlex.quote(part) for part in sanitized_parts)
        return True, sanitized_command, ""
    except Exception as e:
        error_msg = f"Failed to sanitize command: {e}"
        logger.error(f"Sanitization failed for command: {command} - {error_msg}")
        return False, "", error_msg


def is_safe_command(command: str) -> bool:
    """
    Quick check if a command is safe for execution.
    
    Args:
        command: The command string to check
        
    Returns:
        True if the command is safe, False otherwise
    """
    is_safe, _, _ = sanitize_command(command)
    return is_safe


def get_allowed_commands() -> Set[str]:
    """
    Get the set of allowed commands.
    
    Returns:
        Set of allowed command names
    """
    return ALLOWED_COMMANDS.copy()


def add_allowed_command(command: str, special_config: Optional[dict] = None) -> None:
    """
    Add a command to the allowed commands list.
    
    Args:
        command: The command name to add
        special_config: Optional special configuration for the command
    """
    ALLOWED_COMMANDS.add(command)
    if special_config:
        SPECIAL_COMMANDS[command] = special_config
    logger.info(f"Added allowed command: {command}")


def remove_allowed_command(command: str) -> None:
    """
    Remove a command from the allowed commands list.
    
    Args:
        command: The command name to remove
    """
    ALLOWED_COMMANDS.discard(command)
    SPECIAL_COMMANDS.pop(command, None)
    logger.info(f"Removed allowed command: {command}")