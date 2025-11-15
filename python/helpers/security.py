import re
import shlex
from typing import List, Optional, Tuple


class CommandValidator:
    """
    Security-focused command validator to prevent command injection attacks.
    Implements whitelist/blacklist validation and dangerous pattern detection.
    """

    # Whitelist of allowed base commands
    ALLOWED_COMMANDS = {
        # File operations
        'ls', 'cat', 'head', 'tail', 'grep', 'find', 'wc', 'sort', 'uniq',
        # Directory operations  
        'pwd', 'cd', 'mkdir', 'rmdir', 'rm', 'cp', 'mv', 'ln',
        # Text processing
        'echo', 'printf', 'sed', 'awk', 'tr', 'cut', 'split', 'join',
        # System info
        'whoami', 'id', 'uname', 'date', 'uptime', 'df', 'du', 'free',
        # Process management
        'ps', 'top', 'htop', 'jobs', 'kill', 'killall',
        # Network (read-only)
        'ping', 'nslookup', 'dig', 'netstat', 'ss', 'lsof',
        # Compression
        'tar', 'gzip', 'gunzip', 'zip', 'unzip',
        # Development tools
        'git', 'python', 'python3', 'node', 'npm', 'pip', 'pip3',
        # Package managers (read-only operations)
        'apt', 'yum', 'dnf', 'brew',
    }

    # Blacklist of dangerous commands and patterns
    BLACKLISTED_PATTERNS = [
        # Command injection vectors (only when unquoted)
        r';\s*(rm|dd|mkfs|fdisk|format|shutdown|reboot|halt|su|sudo|passwd|chown|chmod|ssh|scp|rsync|curl|wget|mount|umount|iptables|nc|nmap|tcpdump)',
        r'\|\s*(rm|dd|mkfs|fdisk|format|shutdown|reboot|halt|su|sudo|passwd|chown|chmod|ssh|scp|rsync|curl|wget|mount|umount|iptables|nc|nmap|tcpdump)',
        r'&\s*(rm|dd|mkfs|fdisk|format|shutdown|reboot|halt|su|sudo|passwd|chown|chmod|ssh|scp|rsync|curl|wget|mount|umount|iptables|nc|nmap|tcpdump)',
        r'\$\(',       # Command substitution
        r'(?<!\\)`.*?(?<!\\)`',      # Backtick command substitution (unescaped)
        r'\$\{.*?\}',  # Variable expansion
        r'>>|<<|<>',   # Dangerous redirections
        r'&&|\|\|',    # Command chaining
        
        # Dangerous commands
        r'\brm\s+-rf\s+/',  # Dangerous rm
        r'\bdd\s+if=.*\s+of=',  # dd disk writing
        r'\bmkfs\.',     # Filesystem formatting
        r'\bfdisk\b',    # Disk partitioning
        r'\bformat\b',   # Windows format
        r'\bshutdown\b', # System shutdown
        r'\breboot\b',   # System reboot
        r'\bhalt\b',     # System halt
        r'\bsu\b',       # Switch user
        r'\bsudo\b',     # Super user do
        r'\bpasswd\b',   # Password change
        r'\bchown\b',    # Change ownership
        r'\bchmod\s+[0-9]{3,}',    # Change permissions (dangerous modes)
        r'\bssh\b',      # SSH connections
        r'\bscp\b',      # Secure copy
        r'\brsync\b',    # Remote sync
        r'\bcurl\b.*\|\s*sh',  # Download and execute
        r'\bwget\b.*\|\s*sh',  # Download and execute
        
        # Script execution (direct execution without interpreter)
        r'^\./.*\.sh\s*$',     # Shell script execution
        r'^\./.*\.py\s*$',     # Python script execution
        r'^\./.*\.js\s*$',     # Node script execution
        r'^\./.*\.pl\s*$',     # Perl execution
        r'^\./.*\.rb\s*$',     # Ruby execution
        
        # Shell execution
        r'\bbash\s+[^-]',     # Bash execution (not bash -c)
        r'\bsh\s+[^-]',       # Shell execution (not sh -c)
        r'\bzsh\s+[^-]',      # Zsh execution
        r'\bfish\s+[^-]',     # Fish shell execution
        
        # System modification
        r'\bmount\b',    # Mount filesystems
        r'\bumount\b',   # Unmount filesystems
        r'\bswap\b',     # Swap operations
        r'\bsysctl\b',   # System control
        r'\bmodprobe\b', # Kernel modules
        r'\binsmod\b',   # Insert kernel module
        r'\brmmod\b',    # Remove kernel module
        
        # Network dangerous operations
        r'\biptables\b', # Firewall rules
        r'\bnc\b',       # Netcat
        r'\bnmap\b',     # Network scanning
        r'\btcpdump\b',  # Packet capture
    ]

    # Safe argument patterns
    SAFE_ARG_PATTERNS = [
        r'^[a-zA-Z0-9_\-\.\/]+$',  # Standard file paths and names
        r'^-[a-zA-Z0-9]+$',         # Short flags
        r'^--[a-zA-Z0-9\-]+$',     # Long flags
        r'^\d+$',                   # Numbers
        r'^"[^"]*"$',               # Double quoted strings
        r'^\'[^\']*\'$',            # Single quoted strings
        r'^\*.*\*$',                # Wildcard patterns
        r'^\*$',                    # Single wildcard
        r'^\?.*$',                  # Single character wildcards
        r'^\[.*\]$',                # Character classes
        r'^\{.*\}$',                # Brace expansion
        r'^\*.*\.[a-zA-Z0-9]+$',    # File extension wildcards like *.py
    ]

    @classmethod
    def validate_command(cls, command: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a command for security.
        
        Args:
            command: The command string to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not command or not command.strip():
            return False, "Empty command not allowed"
        
        # Strip leading/trailing whitespace
        command = command.strip()
        
        # Check for blacklisted patterns first (but allow them inside quotes)
        for pattern in cls.BLACKLISTED_PATTERNS:
            # Only check for patterns outside of quotes
            if cls._pattern_outside_quotes(command, pattern):
                return False, f"Command contains dangerous pattern: {pattern}"
        
        # Parse command using shlex to handle quotes properly
        try:
            parts = shlex.split(command)
        except ValueError as e:
            return False, f"Invalid command syntax: {str(e)}"
        
        if not parts:
            return False, "Empty command after parsing"
        
        base_command = parts[0].lower()
        
        # Check if base command is in whitelist
        if base_command not in cls.ALLOWED_COMMANDS:
            return False, f"Command '{base_command}' is not in the allowed commands list"
        
        # For arguments, be more permissive since we already checked for dangerous patterns
        # Only validate unquoted arguments that could be problematic
        for arg in parts[1:]:
            # Skip validation for arguments that contain spaces (they were likely quoted)
            if ' ' in arg:
                continue
                
            # Only check unquoted arguments for obvious issues
            is_safe, error = cls._validate_argument(arg)
            if not is_safe:
                return False, f"Unsafe argument '{arg}': {error}"
        
        return True, None

    @classmethod
    def _pattern_outside_quotes(cls, text: str, pattern: str) -> bool:
        """
        Check if a pattern exists outside of quotes in the text.
        
        Args:
            text: The text to search in
            pattern: The regex pattern to search for
            
        Returns:
            True if pattern is found outside quotes, False otherwise
        """
        # Remove quoted sections and check if pattern remains
        # This is a simplified approach - for production, use a proper parser
        text_without_quotes = re.sub(r'"[^"]*"', '', text)  # Remove double quoted sections
        text_without_quotes = re.sub(r"'[^']*'", '', text_without_quotes)  # Remove single quoted sections
        
        return bool(re.search(pattern, text_without_quotes, re.IGNORECASE))

    @classmethod
    def _validate_argument(cls, arg: str) -> Tuple[bool, Optional[str]]:
        """
        Validate individual command arguments.
        
        Args:
            arg: The argument to validate
            
        Returns:
            Tuple of (is_safe, error_message)
        """
        # Skip dangerous pattern checks for properly quoted arguments
        if (arg.startswith('"') and arg.endswith('"')) or (arg.startswith("'") and arg.endswith("'")):
            return True, None
        
        # Check for dangerous patterns in arguments
        for pattern in cls.BLACKLISTED_PATTERNS:
            if re.search(pattern, arg, re.IGNORECASE):
                return False, f"Argument contains dangerous pattern: {pattern}"
        
        # Check if argument matches safe patterns
        for pattern in cls.SAFE_ARG_PATTERNS:
            if re.match(pattern, arg):
                return True, None
        
        # Additional checks for specific cases
        if arg.startswith('-') and len(arg) > 2 and not arg.startswith('--'):
            # Combined short flags (e.g., -la, -rf)
            flags = arg[1:]
            if all(flag.isalpha() for flag in flags):
                return True, None
        
        # If no pattern matches, be conservative and reject
        return False, "Argument does not match safe patterns"

    @classmethod
    def sanitize_command(cls, command: str) -> str:
        """
        Sanitize a command by escaping dangerous characters.
        Note: This is a fallback - validation should be used first.
        
        Args:
            command: The command to sanitize
            
        Returns:
            Sanitized command string
        """
        # Use shlex.quote for proper shell escaping
        try:
            parts = shlex.split(command)
            if not parts:
                return ""
            
            # Quote each part to prevent injection
            sanitized_parts = [shlex.quote(part) for part in parts]
            return ' '.join(sanitized_parts)
        except ValueError:
            # If parsing fails, return empty string for safety
            return ""

    @classmethod
    def log_security_event(cls, event_type: str, command: str, reason: str):
        """
        Log security events for monitoring.
        
        Args:
            event_type: Type of security event (e.g., 'BLOCKED_COMMAND')
            command: The command that triggered the event
            reason: Reason for the security event
        """
        print(f"SECURITY ALERT - {event_type}: {reason}")
        print(f"Command: {command}")
        # In a production environment, this would log to a security monitoring system
        # For now, we just print to console