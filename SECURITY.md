# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.9.x   | :white_check_mark: |
| < 0.9   | :x:                |

## Reporting a Vulnerability

The Agent Zero team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose your findings.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please send an email to: **security@agent-zero.ai**

Include the following information in your report:
- Type of vulnerability (e.g., XSS, SQL injection, authentication bypass)
- Affected versions of Agent Zero
- Detailed steps to reproduce the vulnerability
- Potential impact of the vulnerability
- Any proof-of-concept code or screenshots (if applicable)

### What to Expect

- **Initial Response**: We will acknowledge receipt of your report within 48 hours
- **Detailed Review**: We will investigate the report and provide a detailed response within 7 days
- **Resolution**: We will work on a fix and provide an estimated timeline for patch release
- **Disclosure**: We will coordinate with you on public disclosure timing

### Security Awards

We offer security awards for valid vulnerability reports:

| Severity | Award Range |
|----------|-------------|
| Critical | $500 - $1,000 |
| High     | $200 - $500 |
| Medium   | $100 - $200 |
| Low      | $50 - $100 |

Severity is determined using the [CVSS v3.1](https://www.first.org/cvss/) standard.

## Security Features

Agent Zero includes several security features:

### Authentication & Authorization
- API key-based authentication
- Configurable session management
- Role-based access control (in development)

### Data Protection
- Secrets management with masking
- Encrypted storage for sensitive data
- Secure file upload handling

### Code Execution Security
- Sandboxed code execution environments
- Resource limits and monitoring
- Command validation and filtering

### Network Security
- HTTPS enforcement for external communications
- Secure tunneling for remote access
- Rate limiting on API endpoints

## Security Best Practices

### For Users
1. **Run in Isolated Environments**: Always run Agent Zero in Docker or isolated containers
2. **Use Strong API Keys**: Generate unique, complex API keys for each installation
3. **Regular Updates**: Keep Agent Zero updated to the latest version
4. **Network Isolation**: Limit network access when possible
5. **Monitor Logs**: Regularly review agent activity logs

### For Developers
1. **Input Validation**: Validate all user inputs and file uploads
2. **Least Privilege**: Run agents with minimal required permissions
3. **Secure Coding**: Follow secure coding practices and perform security reviews
4. **Dependency Management**: Keep all dependencies updated and scan for vulnerabilities

## Known Security Considerations

### Code Execution
Agent Zero is designed to execute code and commands to accomplish tasks. This inherently carries security risks:

- Agents can execute arbitrary code within their environment
- File system access is available by design
- Network access may be used for external API calls

**Mitigation**: Always run Agent Zero in isolated environments with limited permissions.

### File Uploads
File uploads are supported for document processing and agent inputs:

- Files are stored in designated directories
- Basic file type validation is performed
- File size limits are configurable

**Mitigation**: Configure appropriate file size limits and monitor upload directories.

### External API Access
Agents can make external API calls:

- API keys are masked in logs and outputs
- Rate limiting is implemented where possible
- Secure HTTPS connections are enforced

**Mitigation**: Use dedicated API keys with limited scopes for agent usage.

## Security Updates

Security updates will be announced through:
- GitHub Security Advisories
- Release notes with security fixes
- Discord community announcements

Critical security updates may be released as patch versions outside the regular release schedule.

## Security Contacts

- **Security Team**: security@agent-zero.ai
- **General Security Questions**: security@agent-zero.ai
- **Discord Security Channel**: https://discord.gg/B8KZKNsPpj

## Security Scanning

We use automated security scanning tools:
- **CodeQL**: Static analysis for code vulnerabilities
- **Dependabot**: Automated dependency updates
- **Snyk**: Open-source dependency scanning
- **Container Security**: Docker image vulnerability scanning

## Responsible Disclosure Policy

We follow a responsible disclosure approach:

1. **Private Reporting**: Vulnerabilities are reported privately
2. **Coordination**: We work with reporters to validate and fix issues
3. **Timely Disclosure**: Public disclosure happens after fixes are available
4. **Credit**: We credit reporters for their contributions (with permission)

## Security Changelog

### Recent Security Fixes
- **v0.9.6**: Improved secrets masking and streaming security
- **v0.9.5**: Enhanced secrets management with encryption at rest
- **v0.9.4**: Added rate limiting and input validation improvements
- **v0.9.3**: Fixed file upload validation and path traversal issues

For a complete list of security fixes, see the [GitHub Security Advisories](https://github.com/agent0ai/agent-zero/security/advisories).

---

Thank you for helping keep Agent Zero secure!