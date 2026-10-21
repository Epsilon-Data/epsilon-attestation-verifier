"""
Epsilon Attestation Verifier

Standalone library to verify AWS Nitro Enclave attestation documents.
No AWS account or Nitro hardware required.
"""

from .verifier import (
    verify_attestation,
    VerificationResult,
    AttestationDocument,
)
from .files_manifest import (
    DEFAULT_OUTPUT_FILE_TYPE,
    OUTPUT_FILE_TYPES,
    is_valid_output_file_name,
    build_files_manifest,
    canonical_manifest_bytes,
    compute_files_manifest_sha256,
    verify_files_manifest,
)
from .code_digest import build_code_bundle, compute_code_digest
from .pcr_registry import get_published_pcrs
from .exceptions import (
    VerificationError,
    InvalidAttestationError,
    CertificateVerificationError,
    SignatureVerificationError,
    PCRMismatchError,
    OutputHashMismatchError,
    InvalidOutputFileError,
)

__version__ = "1.0.0"
__all__ = [
    "verify_attestation",
    "VerificationResult",
    "AttestationDocument",
    "get_published_pcrs",
    "build_code_bundle",
    "compute_code_digest",
    "DEFAULT_OUTPUT_FILE_TYPE",
    "OUTPUT_FILE_TYPES",
    "is_valid_output_file_name",
    "build_files_manifest",
    "canonical_manifest_bytes",
    "compute_files_manifest_sha256",
    "verify_files_manifest",
    "VerificationError",
    "InvalidAttestationError",
    "CertificateVerificationError",
    "SignatureVerificationError",
    "PCRMismatchError",
    "OutputHashMismatchError",
    "InvalidOutputFileError",
]
