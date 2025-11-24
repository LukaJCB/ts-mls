# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in ts-mls, please help keep the project secure by disclosing it responsibly.

### How to Report

**Please DO NOT open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities via one of these methods:

1. **Email**: Send details to luka.jacobowitz@gmail.com
 
2. **GitHub Security Advisory**: Use GitHub's [private vulnerability reporting](https://github.com/LukaJCB/ts-mls/security/advisories/new) feature.

### What to Include

When reporting, please provide:
- A description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Any suggested fixes (if you have them)

### Response Time

As this project is maintained by a single volunteer, please be patient. 

## Security Considerations

### Important Notice

While ts-mls implements the MLS protocol (RFC 9420) with care, please note:

- This is a volunteer-maintained project
- It has NOT undergone professional security audits
- Use in production or security-critical contexts is at your own risk
- Consider getting an independent security review for production use


## Best Practices for Users

1. **Always use the latest version**
2. **Keep dependencies updated**
3. **Follow the MLS specification guidance** on secure group management
4. **Use secure transport** (TLS/QUIC) for transmitting MLS messages
5. **Implement proper key management** in your application
6. **Test thoroughly** in your specific use case

## Disclosure Policy

When a vulnerability is confirmed:

1. A fix will be developed privately
2. A new version will be released with the fix
3. The vulnerability will be disclosed in the release notes after users have had time to upgrade


For non-security issues, please use GitHub Issues.

---

*Thank you for helping keep ts-mls secure!*
