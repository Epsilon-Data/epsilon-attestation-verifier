# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email: **security@epsilon-data.com**

We will respond within 48 hours and work with you to understand and address the issue.

## Scope

This tool verifies AWS Nitro Enclave attestation documents. Security-sensitive areas include:

- **Certificate chain validation** (`verifier.py`): X.509 chain verification against AWS root
- **COSE signature verification** (`verifier.py`): ECDSA signature validation
- **AWS root certificate management** (`aws_root_cert.py`): Download, cache, and fingerprint verification
- **PCR value comparison** (`pcr_registry.py`): Enclave identity verification

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x.x   | Yes       |
