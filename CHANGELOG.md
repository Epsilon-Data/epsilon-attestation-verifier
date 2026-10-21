# Changelog

## [1.3.0](https://github.com/Epsilon-Data/epsilon-attestation-verifier/compare/v1.2.0...v1.3.0) (2026-10-21)


### Features

* accept any output file type and subfolder paths in files manifest ([#6](https://github.com/Epsilon-Data/epsilon-attestation-verifier/issues/6)) ([e908e83](https://github.com/Epsilon-Data/epsilon-attestation-verifier/commit/e908e83f36aa78856e1611ec111d80f38420394f))
* add code-digest to recompute script_hash from a build folder ([#7](https://github.com/Epsilon-Data/epsilon-attestation-verifier/issues/7)) ([7299d90](https://github.com/Epsilon-Data/epsilon-attestation-verifier/commit/7299d90b354cfdb6604d153d36c976b49b84c47a))

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
