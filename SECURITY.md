# Security Policy

strongroom is a secrets broker for autonomous agents — leases instead of raw keys. Vulnerability reports get priority attention.

## Reporting a vulnerability

Please **do not open a public issue** for security reports.

- **Preferred:** [GitHub private vulnerability reporting](https://github.com/askalf/strongroom/security/advisories/new) — creates a private advisory visible only to maintainers.
- **Email:** support@askalf.org with `strongroom security` in the subject.

You'll get an acknowledgement within 72 hours. Please include a minimal reproduction where possible.

## Supported versions

strongroom is pre-1.0: only the latest release receives security fixes; there are no maintenance branches.

## In scope

Anything that breaks the core promise — agents get leases, never raw key material:

- The broker leaking raw secrets to a leaseholder (in responses, logs, or errors)
- Lease escalation: extending scope, TTL, or audience beyond what was granted
- The sanitizer failing to redact a secret pattern it claims to cover
- Audit-trail tampering or bypass
