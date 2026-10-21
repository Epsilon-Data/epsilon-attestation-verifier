"""A real attestation stays verifiable after its leaf certificate expires.

Fixture: the public attestation of JOB-MVGTRGV2 (enclave 1.6.0, signed 2026-10-20 15:15:37 UTC), as served by
https://trust.epsilon-data.org/api/verify/JOB-MVGTRGV2, and the AWS Nitro Enclaves Root-G1 certificate.
NSM leaf certificates are valid for a few hours, so this document's leaf has long expired.
"""
from datetime import datetime, timezone
from pathlib import Path

from epsilon_verifier import verify_attestation
from epsilon_verifier.verifier import _parse_and_validate_attestation, _verify_certificate_chain

FIXTURES = Path(__file__).parent / "fixtures"
ROOT_CERT = str(FIXTURES / "aws_nitro_root_g1.pem")
DOC = (FIXTURES / "JOB-MVGTRGV2.attestation.b64").read_text().strip()
PCR0 = "fa7679fc7bb152f63fed375c8db4be5ec632ef27d3d4f6dc7adbc4e728f57825614bdd2d766c6b45198328211f83fd3a"


def test_chain_is_checked_at_the_signing_time():
    result = verify_attestation(DOC, expected_pcr0=PCR0, aws_root_cert_path=ROOT_CERT)

    assert result.valid, result.error
    assert result.certificate_chain_valid
    assert result.timestamp == datetime(2026, 10, 20, 15, 15, 37, 340000, tzinfo=timezone.utc)


def test_the_same_chain_is_expired_today():
    attestation = _parse_and_validate_attestation(DOC)
    later = datetime(2026, 10, 21, tzinfo=timezone.utc)

    assert not _verify_certificate_chain(
        attestation.certificate, attestation.cabundle, ROOT_CERT, validation_time=later,
    )
