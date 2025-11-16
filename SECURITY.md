# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| Current | ✅                 |

## Reporting a Vulnerability

We take the security of Agent Zero seriously. If you discover a security vulnerability, please report it to us privately before disclosing it publicly.

### How to Report

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please send an email to: security@agent-zero.ai

Include the following information in your report:
- Type of vulnerability (e.g., XSS, SQL injection, etc.)
- Steps to reproduce the vulnerability
- Potential impact of the vulnerability
- Any screenshots or proof-of-concept code (if applicable)

### Response Time

We will acknowledge receipt of your vulnerability report within 48 hours and provide a detailed response within 7 days. We'll keep you informed of our progress towards a fix and announcement.

### Security Measures

Agent Zero includes several security features:
- Code execution sandboxing
- Input validation and sanitization
- Secrets management with masking
- Rate limiting on API endpoints
- Secure file upload handling

### Security Best Practices for Users

1. **Run in Isolated Environments**: Always run Agent Zero in Docker or isolated environments
2. **Review Code Before Execution**: Carefully review any code before allowing execution
3. **Use Strong Authentication**: Implement strong API keys and authentication
4. **Regular Updates**: Keep Agent Zero updated to the latest version
5. **Monitor Logs**: Regularly check logs for suspicious activity

### Security-Related Configuration

- Disable code execution tool in untrusted environments
- Implement proper network segmentation
- Use environment variables for secrets (never hardcode)
- Enable audit logging for sensitive operations
- Configure appropriate file permissions

## Security Features

### Code Execution Safety
- Sandboxed execution environment
- Command whitelisting capabilities
- Resource usage limits
- Timeout protections

### Authentication & Authorization
- API key-based authentication
- Session management
- Rate limiting
- CSRF protection

### Data Protection
- Secrets masking in logs and outputs
- Encrypted storage for sensitive data
- Secure file handling
- Input validation

## Security Updates

We will:
- Provide security updates for the current version
- Announce security fixes in release notes
- Follow responsible disclosure practices
- Credit security researchers in our acknowledgments

## Security Acknowledgments

We thank all security researchers who help us keep Agent Zero secure. Your responsible disclosure helps protect our users.

## Additional Resources

- [Security Analysis](./docs/SECURITY_ANALYSIS.md) - Detailed security analysis
- [Contributing Guidelines](./docs/contribution.md) - Security considerations for contributors
- [Installation Guide](./docs/installation.md) - Secure installation practices

---

For questions about this security policy, please contact security@agent-zero.ai