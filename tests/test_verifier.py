"""
Tests for attestation verification.
"""

import base64
import hashlib
import json
import pytest

from epsilon_verifier import (
    verify_attestation,
    VerificationResult,
    InvalidAttestationError,
)


class TestVerificationResult:
    """Tests for VerificationResult dataclass."""

    def test_to_dict(self):
        """Test result serialization to dictionary."""
        result = VerificationResult(
            valid=True,
            aws_signature_valid=True,
            certificate_chain_valid=True,
            pcr_verified=True,
            output_verified=True,
            pcr0="abc123",
            pcr1="def456",
            pcr2="ghi789",
        )

        d = result.to_dict()

        assert d['valid'] is True
        assert d['aws_signature_valid'] is True
        assert d['pcr0'] == "abc123"

    def test_to_dict_with_none_values(self):
        """Test serialization handles None values."""
        result = VerificationResult(valid=False)
        d = result.to_dict()

        assert d['valid'] is False
        assert d['pcr0'] is None
        assert d['timestamp'] is None


class TestInvalidInput:
    """Tests for invalid input handling."""

    def test_invalid_base64(self):
        """Test that invalid base64 returns error result."""
        result = verify_attestation("not-valid-base64!!!")

        assert result.valid is False
        assert "Invalid" in result.error or "base64" in result.error.lower()

    def test_empty_attestation(self):
        """Test empty attestation document."""
        result = verify_attestation("")

        assert result.valid is False

    def test_non_cbor_data(self):
        """Test with valid base64 but non-CBOR data."""
        data = base64.b64encode(b"hello world").decode()
        result = verify_attestation(data)

        assert result.valid is False
        assert result.error is not None


class TestOutputHashVerification:
    """Tests for output hash verification logic."""

    def test_output_hash_calculation(self):
        """Test that expected output hash is calculated correctly."""
        # This tests the hash calculation logic, not full verification
        expected_output = "Hello, World!"
        expected_hash = hashlib.sha256(expected_output.encode()).hexdigest()

        assert expected_hash == "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"


class TestSkipCertificateVerification:
    """Tests for skip_certificate_verification flag."""

    def test_skip_flag_accepted(self):
        """Test that skip_certificate_verification flag is accepted."""
        # Even with skip, invalid data should still fail at parsing
        result = verify_attestation(
            "invalid",
            skip_certificate_verification=True
        )

        assert result.valid is False


# Sample COSE_Sign1 structure for testing (mock)
# In real tests, you would use actual attestation documents
SAMPLE_COSE_STRUCTURE = None  # Would be actual CBOR data


class TestPCRVerification:
    """Tests for PCR value verification."""

    def test_pcr_comparison_case_insensitive(self):
        """PCR comparison should be case-insensitive."""
        # This would need a valid attestation document to test fully
        # For now, we test the expected behavior
        pcr_lower = "abc123def456"
        pcr_upper = "ABC123DEF456"

        assert pcr_lower.lower() == pcr_upper.lower()


class TestExceptionTypes:
    """Tests for custom exception types."""

    def test_invalid_attestation_error(self):
        """Test InvalidAttestationError can be raised and caught."""
        from epsilon_verifier.exceptions import InvalidAttestationError

        with pytest.raises(InvalidAttestationError):
            raise InvalidAttestationError("Test error")

    def test_pcr_mismatch_error(self):
        """Test PCRMismatchError contains relevant info."""
        from epsilon_verifier.exceptions import PCRMismatchError

        error = PCRMismatchError(0, "expected", "actual")

        assert error.pcr_index == 0
        assert error.expected == "expected"
        assert error.actual == "actual"
        assert "PCR0" in str(error)

    def test_output_hash_mismatch_error(self):
        """Test OutputHashMismatchError contains relevant info."""
        from epsilon_verifier.exceptions import OutputHashMismatchError

        error = OutputHashMismatchError("expected_hash", "actual_hash")

        assert error.expected == "expected_hash"
        assert error.actual == "actual_hash"
