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
epsilon-verify verify attestation.json --files results.csv plot.png
epsilon-verify verify attestation.json --files-root outputs
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
| `expected_files` | `list[tuple[str, bytes]]` | `None` | Output files as `(name, bytes)` pairs (verifies `files_manifest_sha256`) |

### `VerificationResult`

| Field | Type | Description |
|-------|------|-------------|
| `valid` | `bool` | Overall verification result |
| `syntax_valid` | `bool` | CBOR/COSE structure parsed correctly |
| `aws_signature_valid` | `bool` | ECDSA P-384 signature verified |
| `certificate_chain_valid` | `bool` | Chain to AWS Nitro root CA verified |
| `pcr_verified` | `bool` | PCR values match expected (if provided) |
| `output_verified` | `bool` | Output hash matches expected (if provided) |
| `files_verified` | `bool` | Files manifest hash matches expected files (if provided) |
| `pcr0` | `str` | PCR0 value (enclave image hash, hex) |
| `pcr1` | `str` | PCR1 value (kernel hash, hex) |
| `pcr2` | `str` | PCR2 value (application hash, hex) |
| `user_data` | `dict` | Parsed application data (job_id, script_hash, dataset_hash, output_hash, timestamp) |
| `output_hash` | `str` | SHA-256 hash of output from attestation |
| `files_manifest_sha256` | `str` | Attested output files manifest hash (`None` for older attestations) |
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
6. **Output files** — Rebuild the files manifest and match its SHA-256 against attested `files_manifest_sha256` (if provided)

## Output Files Manifest

Files a script writes are attested via `files_manifest_sha256` in `user_data`. The manifest is a list of
`{"name", "size", "sha256", "type"}` sorted by name (plain code-point order), encoded as
`json.dumps(manifest, sort_keys=True, separators=(",", ":"))`. No files → manifest `[]`.

- `name` is the file's path relative to the job's `outputs/` folder, with `/` as separator (e.g. `plots/fig1.png`).
  It must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,99}(/[A-Za-z0-9][A-Za-z0-9._-]{0,99}){0,4}$` (at most 5 segments,
  no `.`/`..`/hidden/empty segments) and be at most 255 characters.
- `type` comes from the lower-cased extension of the last segment: `csv` text/csv, `png` image/png,
  `jpg`/`jpeg` image/jpeg, `json` application/json, `txt` text/plain, `pdf` application/pdf. Any other extension,
  or none, is `application/octet-stream`.

With the CLI, `--files a.csv b.png` names each file by its basename (fine for files at the top of `outputs/`).
For files in subfolders, pass `--files-root DIR`: files are named by their path relative to `DIR`, and if `--files`
is omitted every file under `DIR` is checked (symlinks and other non-regular entries are rejected):

```bash
epsilon-verify verify attestation.json --files-root outputs                       # whole folder
epsilon-verify verify attestation.json --files-root outputs --files outputs/plots/fig1.png outputs/a.csv
```

```python
from epsilon_verifier import verify_files_manifest

files = [("results.csv", open("results.csv", "rb").read()),
         ("plots/fig1.png", open("outputs/plots/fig1.png", "rb").read())]
assert verify_files_manifest(files, result.files_manifest_sha256)
```

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
