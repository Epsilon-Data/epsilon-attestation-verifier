# Epsilon Attestation Verifier

Standalone tool to verify AWS Nitro Enclave attestation documents from Epsilon.

**No AWS account or Nitro Enclave required** - runs on any machine.

## What This Verifies

1. **AWS Signature** - Document is signed by genuine AWS Nitro hardware
2. **PCR Values** - Enclave ran the expected code (image hash)
3. **Output Integrity** - Output hash matches the actual output
4. **Timestamp** - When the execution occurred
5. **Certificate Chain** - Valid chain to AWS Nitro root certificate

## Installation

```bash
pip install epsilon-attestation-verifier
```

Or from source:
```bash
git clone https://github.com/epsilon-data/epsilon-attestation-verifier
cd epsilon-attestation-verifier
pip install -e .
```

## Quick Start

### Python API

```python
from epsilon_verifier import verify_attestation

result = verify_attestation(
    attestation_doc="<base64 attestation from Epsilon>",
    expected_output="Hello, World!",  # The output you received
    expected_pcr0="abc123..."          # Optional: verify specific enclave version
)

if result.valid:
    print("Attestation verified!")
    print(f"  PCR0: {result.pcr0}")
    print(f"  Output hash matches: {result.output_verified}")
    print(f"  Signed by AWS: {result.aws_signature_valid}")
else:
    print(f"Verification failed: {result.error}")
```

### CLI

```bash
# Verify an attestation file
epsilon-verify attestation.json --output output.txt

# Verify with expected PCR0
epsilon-verify attestation.json --output output.txt --pcr0 abc123...

# Output as JSON
epsilon-verify attestation.json --output output.txt --json
```

### From Epsilon Job Response

```python
import json
from epsilon_verifier import verify_attestation

# Parse Epsilon job response
job_response = json.loads(response_data)

result = verify_attestation(
    attestation_doc=job_response['attestation']['attestation']['attestation_document'],
    expected_output=job_response['output'],
    expected_pcr0=PUBLISHED_PCR0  # From Epsilon's published values
)
```

## What's Inside an Attestation

```
Attestation Document (CBOR + COSE_Sign1):
├── module_id      : Enclave instance identifier
├── timestamp      : Unix timestamp (ms)
├── digest         : Hash algorithm (SHA384)
├── pcrs           : Platform Configuration Registers
│   ├── PCR0       : Enclave image hash (48 bytes)
│   ├── PCR1       : Linux kernel + bootstrap
│   └── PCR2       : Application hash
├── certificate    : Enclave certificate (DER)
├── cabundle       : Certificate chain to AWS root
├── user_data      : Custom data (output hash, job_id, etc.)
├── nonce          : Replay protection
└── public_key     : Optional encryption key
```

## Verification Steps

```
Step 1: Base64 decode attestation document
            │
            ▼
Step 2: Parse COSE_Sign1 structure
            │
            ▼
Step 3: Extract certificate chain (cabundle)
            │
            ▼
Step 4: Verify chain against AWS Nitro root cert
        (Downloaded from AWS)
            │
            ▼
Step 5: Verify COSE signature using leaf cert
            │
            ▼
Step 6: Extract PCR values
        Compare PCR0 with published enclave image hash
            │
            ▼
Step 7: Extract user_data
        Verify output_hash == SHA256(actual_output)
            │
            ▼
        ✓ VERIFIED: Output was generated inside
          the verified Epsilon enclave
```

## Trust Model

**You trust:**
- AWS Nitro Attestation PKI (hardware root of trust)
- Epsilon's published PCR0 value (open source, reproducible build)

**You verify:**
- AWS signature on attestation document
- PCR0 matches published value
- Output hash matches actual output

## AWS Nitro Root Certificate

The verifier automatically downloads and caches the AWS Nitro root certificate from:
```
https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
```

Or manually specify:
```python
result = verify_attestation(
    attestation_doc="...",
    expected_output="...",
    aws_root_cert_path="/path/to/aws_root.pem"
)
```

## Published Epsilon PCR Values

Get the expected PCR0 for each Epsilon version:

```python
from epsilon_verifier import get_published_pcrs

pcrs = get_published_pcrs("1.0.0")
print(pcrs['pcr0'])  # Compare with attestation
```

Or check: https://github.com/epsilon-data/epsilon-enclave/blob/main/published/pcr_values.json

## License

MIT
