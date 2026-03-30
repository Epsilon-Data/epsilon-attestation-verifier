# Epsilon Attestation Verifier

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/Epsilon-Data/epsilon-attestation-verifier)](https://github.com/Epsilon-Data/epsilon-attestation-verifier/releases/latest)
[![Tests](https://github.com/Epsilon-Data/epsilon-attestation-verifier/actions/workflows/tests.yml/badge.svg)](https://github.com/Epsilon-Data/epsilon-attestation-verifier/actions/workflows/tests.yml)

Verify AWS Nitro Enclave attestation documents in Python. No AWS account or Nitro hardware required. Works with **any** Nitro Enclave attestation, not just Epsilon.

## Install

```bash
pip install epsilon-attestation-verifier
```

## Usage

```python
from epsilon_verifier import verify_attestation

result = verify_attestation(
    attestation_doc="<base64 attestation>",
    expected_pcr0="abc123...",    # Optional: verify enclave image
    expected_output="Hello",      # Optional: verify output hash
    allow_expired=True            # For historical attestations (~3hr cert lifetime)
)

if result.valid:
    print(f"Verified: PCR0={result.pcr0}, AWS signature={result.aws_signature_valid}")
else:
    print(f"Failed: {result.error}")
```

### CLI

```bash
epsilon-verify verify attestation.json
epsilon-verify verify attestation.json --pcr0 abc123... --output output.txt --json
epsilon-verify extract attestation.json
```

## API Reference

### `verify_attestation(attestation_doc, **kwargs) → VerificationResult`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `attestation_doc` | `str` | required | Base64-encoded COSE_Sign1 attestation document |
| `expected_output` | `str` | `None` | Expected output string (verifies SHA-256 hash) |
| `expected_pcr0` | `str` | `None` | Expected PCR0 hex string (enclave image hash) |
| `expected_pcr1` | `str` | `None` | Expected PCR1 hex string (kernel hash) |
| `expected_pcr2` | `str` | `None` | Expected PCR2 hex string (application hash) |
| `aws_root_cert_path` | `str` | `None` | Custom path to AWS Nitro root certificate PEM |
| `skip_certificate_verification` | `bool` | `False` | Skip all cert checks (testing only) |
| `allow_expired` | `bool` | `False` | Skip certificate date validation (for historical attestations with ~3hr cert lifetime) |

### `VerificationResult`

| Field | Type | Description |
|-------|------|-------------|
| `valid` | `bool` | Overall verification result |
| `syntax_valid` | `bool` | CBOR/COSE structure parsed correctly |
| `aws_signature_valid` | `bool` | ECDSA P-384 signature verified |
| `certificate_chain_valid` | `bool` | Chain to AWS Nitro root CA verified |
| `pcr_verified` | `bool` | PCR values match expected (if provided) |
| `output_verified` | `bool` | Output hash matches expected (if provided) |
| `pcr0` | `str` | PCR0 value (enclave image hash, hex) |
| `pcr1` | `str` | PCR1 value (kernel hash, hex) |
| `pcr2` | `str` | PCR2 value (application hash, hex) |
| `user_data` | `dict` | Parsed application data (job_id, script_hash, dataset_hash, output_hash, timestamp) |
| `output_hash` | `str` | SHA-256 hash of output from attestation |
| `timestamp` | `datetime` | Execution timestamp |
| `module_id` | `str` | Enclave instance identifier |
| `error` | `str` | Error message if verification failed |
| `timing` | `dict` | Per-step timing in milliseconds |

## What It Checks

1. **COSE_Sign1 parsing** — Decode CBOR structure, validate required fields per AWS spec
2. **Certificate chain** — Verify chain from AWS Nitro root CA to enclave leaf certificate
3. **COSE signature** — Verify ECDSA P-384/SHA-384 signature using leaf certificate public key
4. **PCR values** — Compare PCR0/1/2 against expected values (if provided)
5. **Output hash** — Verify SHA-256 of execution output matches attested `user_data` hash (if provided)

## Use in Your Own Project

**Verify attestations from any Nitro Enclave app:**
```python
from epsilon_verifier import verify_attestation

# Your own Nitro Enclave app, not Epsilon
result = verify_attestation(
    attestation_doc=my_attestation_base64,
    expected_pcr0=MY_PUBLISHED_PCR0,
    allow_expired=True,
)
assert result.valid
print(f"Module: {result.module_id}")
print(f"User data: {result.user_data}")
print(f"Timing: {result.timing}")
```

**Batch verification:**
```python
from epsilon_verifier import verify_attestation

for doc in attestation_documents:
    result = verify_attestation(doc, allow_expired=True)
    print(f"{result.module_id}: {'PASS' if result.valid else 'FAIL'}")
```

**Extract metadata without PCR checking:**
```python
result = verify_attestation(attestation_doc=doc, allow_expired=True)
print(f"Job ID: {result.user_data['job_id']}")
print(f"Script hash: {result.user_data['script_hash']}")
print(f"Dataset hash: {result.user_data['dataset_hash']}")
print(f"Output hash: {result.user_data['output_hash']}")
print(f"Timestamp: {result.timestamp}")
```

## Testing

```bash
pip install -e ".[dev]"
pytest
```

## Attestation Structure

```
COSE_Sign1 (CBOR):
├── module_id      Enclave instance ID
├── pcrs           PCR0 (image), PCR1 (kernel), PCR2 (app)
├── certificate    Enclave certificate (DER)
├── cabundle       Chain to AWS root
├── user_data      Job ID, script hash, dataset hash, output hash
├── nonce          Replay protection
└── timestamp      Execution time (ms)
```

## Trust Model

**You trust:** AWS Nitro Attestation PKI (hardware root of trust)
**You verify:** COSE signature, certificate chain, PCR values, output hash

## Requirements

- Python 3.8+
- No system dependencies — pure Python with `cbor2`, `cryptography`, `requests`

## License

[MIT](LICENSE)
