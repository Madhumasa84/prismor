# Security policy

Prismor Warden is a security tool that sits inline with agent tool calls and
secrets. We take vulnerabilities seriously and appreciate responsible disclosure.

## Reporting a vulnerability

**Do not open a public issue for security reports.** Instead:

- Use GitHub's private **"Report a vulnerability"** advisory on this repository, or
- Email **security@prismor.dev** with details and a reproduction.

Please include the affected version/commit, impact, and steps to reproduce. We
aim to acknowledge within 3 business days and to ship or coordinate a fix before
public disclosure.

## Scope

In scope: the Warden runtime, the framework adapters, the detection rules, and
the enrolled-device client protocol in this repository. The commercial control
plane is handled separately — note it in your report and we will route it.

## Secrets and keys

The signing **private key** and any real secrets must never appear in this public
repo. `scripts/check_oss_safe.py` enforces this in CI. If you discover an exposed
secret in the history, report it privately so we can rotate it.
