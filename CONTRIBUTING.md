# Contributing to Epsilon Attestation Verifier

Thanks for your interest in contributing! This document explains how to get started.

## Development Setup

### Prerequisites

- Python 3.8+

### Local Development

```bash
# Clone the repo
git clone https://github.com/Epsilon-Data/epsilon-attestation-verifier.git
cd epsilon-attestation-verifier

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install with dev dependencies
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest
```

With coverage:

```bash
pytest --cov=epsilon_verifier --cov-report=term-missing
```

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/). This is **enforced on PR titles** (not individual commits).

### Format

```
<type>: <short description>
```

### Types

| Type | When to use | Version bump |
|------|------------|--------------|
| `feat` | New feature | Minor (1.x.0) |
| `fix` | Bug fix | Patch (1.0.x) |
| `docs` | Documentation only | None |
| `refactor` | Code change that neither fixes a bug nor adds a feature | None |
| `test` | Adding or updating tests | None |
| `chore` | Build, CI, dependency updates | None |
| `feat!` or `fix!` | Breaking change (append `!`) | Major (x.0.0) |

### Examples

```
feat: add P-256 ECDSA signature support
fix: handle missing cabundle in attestation document
docs: add verification flow diagram
refactor: extract certificate chain builder
chore: upgrade cryptography to 43.0.0
feat!: change VerificationResult API
```

### How it works

1. You make commits with any message style in your feature branch
2. Your **PR title** must follow conventional commit format
3. PRs are **squash-merged** into `main`, so the PR title becomes the commit message
4. `release-please` reads those commits and automatically determines the version bump and generates the changelog

## Pull Request Process

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Run tests (`pytest`)
4. Open a PR with a conventional commit title
5. The PR title CI check must pass
6. A maintainer will review and merge

## Release Process

Releases are fully automated:

1. `feat:` and `fix:` commits on `main` trigger `release-please` to open a release PR
2. The release PR bumps the version in `VERSION` and updates `CHANGELOG.md`
3. Merging the release PR creates a GitHub Release
4. The GitHub Release triggers the PyPI publish workflow

`docs:`, `refactor:`, `test:`, and `chore:` commits do **not** trigger a release.

## Architecture

```
src/epsilon_verifier/
├── __init__.py          # Public API exports
├── verifier.py          # Core verification engine
├── cli.py               # Command-line interface
├── exceptions.py        # Custom exception hierarchy
├── aws_root_cert.py     # AWS root certificate management
└── pcr_registry.py      # PCR value registry
```

### Key Principles

- **Top-level imports**: All imports at the top of the file, use absolute imports
- **Type hints**: All functions should have type annotations
- **No hardcoded values**: Constants at module level with clear names
- **Cryptographically sound**: Use `cryptography` library, never roll your own crypto

## Security

This is a security verification tool. Security-sensitive areas:

- **Certificate chain validation** (`verifier.py`): X.509 chain to AWS root
- **COSE signature verification** (`verifier.py`): ECDSA with P-384
- **Root certificate management** (`aws_root_cert.py`): Fingerprint verification
- **PCR comparison** (`pcr_registry.py`): Case-insensitive hex comparison

If you find a security issue, see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
