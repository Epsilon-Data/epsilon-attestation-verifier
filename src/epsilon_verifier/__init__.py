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
from .pcr_registry import get_published_pcrs
from .exceptions import (
    VerificationError,
    InvalidAttestationError,
    CertificateVerificationError,
    SignatureVerificationError,
    PCRMismatchError,
    OutputHashMismatchError,
)

__version__ = "1.0.0"
__all__ = [
    "verify_attestation",
    "VerificationResult",
    "AttestationDocument",
    "get_published_pcrs",
    "VerificationError",
    "InvalidAttestationError",
    "CertificateVerificationError",
    "SignatureVerificationError",
    "PCRMismatchError",
    "OutputHashMismatchError",
]
