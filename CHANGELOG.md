# Changelog

## 1.0.0 (2026-02-17)

### Features

* AWS Nitro Enclave attestation document verification
* Certificate chain validation against AWS Nitro root certificate
* COSE_Sign1 signature verification (ES384)
* PCR value comparison with built-in registry and GitHub fetch
* Output hash integrity verification (SHA256)
* CLI with `verify`, `extract`, and `list-versions` commands
* Automatic AWS root certificate download and caching with fingerprint verification
* Python API: `verify_attestation()`, `get_published_pcrs()`
