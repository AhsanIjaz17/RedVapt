# Security Policy

## Security & Responsible Disclosure

The RedVapt team takes the security of our platform and users seriously. If you discover a security vulnerability within this repository or application, please follow responsible disclosure guidelines.

### Reporting a Vulnerability

- **Do NOT** open a public issue on GitHub for security vulnerabilities.
- Send a detailed security advisory or description of the vulnerability to the project maintainers.
- Provide step-by-step reproduction steps or a proof-of-concept (PoC) demonstration where applicable.
- Allow reasonable time for the maintainers to investigate and address the vulnerability before public disclosure.

---

## Best Practices for Deploying RedVapt

1. **Environment Credentials & API Keys**:
   - Never commit `.env` files or API keys (`ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`, JWT secrets) to version control.
   - Use `.env.example` as a template for setting up local environment variables.

2. **Authorized Penetration Testing Only**:
   - RedVapt is designed for security assessments against targets you own or have explicit, documented authorization to test.
   - Unauthorized scanning or testing of third-party infrastructure may violate local and international laws.

3. **Database & Scan Reports Security**:
   - Local database instances (`redvapt.db`) and generated evidence reports (`server/data/evidence/`, `server/data/reports/`) are ignored by version control to prevent exposing target infrastructure details.
   - Secure report storage permissions in production environments.
