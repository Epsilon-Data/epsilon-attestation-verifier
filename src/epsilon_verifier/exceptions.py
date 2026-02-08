"""
Custom exceptions for attestation verification.
"""


class VerificationError(Exception):
    """Base exception for all verification errors."""
    pass


class InvalidAttestationError(VerificationError):
    """Attestation document is malformed or invalid."""
    pass


class CertificateVerificationError(VerificationError):
    """Certificate chain verification failed."""
    pass


class SignatureVerificationError(VerificationError):
    """COSE signature verification failed."""
    pass


class PCRMismatchError(VerificationError):
    """PCR values don't match expected values."""

    def __init__(self, pcr_index: int, expected: str, actual: str):
        self.pcr_index = pcr_index
        self.expected = expected
        self.actual = actual
        super().__init__(f"PCR{pcr_index} mismatch: expected {expected}, got {actual}")


class OutputHashMismatchError(VerificationError):
    """Output hash doesn't match expected value."""

    def __init__(self, expected: str, actual: str):
        self.expected = expected
        self.actual = actual
        super().__init__(f"Output hash mismatch: expected {expected}, got {actual}")
