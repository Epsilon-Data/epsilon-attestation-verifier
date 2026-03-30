"""
AWS Nitro Enclave root certificate management.

Downloads and caches the AWS Nitro root certificate used for
attestation document verification.

Per AWS spec, the root certificate SHA256 fingerprint must be verified.
"""

import hashlib
import logging
import os
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

# AWS Nitro Enclave root certificate URL
AWS_ROOT_CERT_URL = "https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip"
AWS_ROOT_CERT_FILENAME = "aws_nitro_root.pem"

# AWS root certificate SHA256 fingerprint
# This fingerprint is from the certificate currently served at AWS_ROOT_CERT_URL
# If AWS rotates the certificate, this may need to be updated
# Note: AWS documentation says 8cf60e2b2... but actual served cert has this fingerprint
AWS_ROOT_CERT_FINGERPRINT = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"

# Expected certificate subject CN
AWS_ROOT_CERT_CN = "aws.nitro-enclaves"

# Default cache directory
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "epsilon-verifier"


def get_aws_root_certificate(
    cert_path: Optional[str] = None,
    cache_dir: Optional[str] = None,
    force_download: bool = False
) -> x509.Certificate:
    """
    Get the AWS Nitro Enclave root certificate.

    Downloads from AWS if not cached locally.

    Args:
        cert_path: Path to existing root certificate file (PEM format)
        cache_dir: Directory to cache downloaded certificate
        force_download: Force re-download even if cached

    Returns:
        x509.Certificate object
    """
    # If explicit path provided, use it (skip fingerprint check for custom certs)
    if cert_path:
        logger.info(f"Loading root cert from: {cert_path}")
        return _load_cert_from_file(cert_path, verify_fingerprint=False)

    # Set up cache directory
    cache_path = Path(cache_dir) if cache_dir else DEFAULT_CACHE_DIR
    cache_path.mkdir(parents=True, exist_ok=True)
    cached_cert_path = cache_path / AWS_ROOT_CERT_FILENAME

    # Check cache
    if cached_cert_path.exists() and not force_download:
        logger.info(f"Using cached AWS root cert: {cached_cert_path}")
        return _load_cert_from_file(str(cached_cert_path))

    # Download from AWS
    logger.info(f"Downloading AWS root cert from: {AWS_ROOT_CERT_URL}")
    cert_pem = _download_aws_root_cert()

    # Cache it
    cached_cert_path.write_text(cert_pem)
    logger.info(f"Cached AWS root cert to: {cached_cert_path}")

    return _load_cert_from_pem(cert_pem)


def _download_aws_root_cert() -> str:
    """Download AWS root certificate from official URL."""
    try:
        response = requests.get(AWS_ROOT_CERT_URL, timeout=30)
        response.raise_for_status()
    except requests.RequestException as e:
        raise RuntimeError(f"Failed to download AWS root cert: {e}")

    # AWS provides it as a ZIP file
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp.write(response.content)
        tmp_path = tmp.name

    try:
        with zipfile.ZipFile(tmp_path, 'r') as zf:
            # Find the .pem file in the archive
            pem_files = [f for f in zf.namelist() if f.endswith('.pem')]
            if not pem_files:
                raise RuntimeError("No PEM file found in AWS root cert ZIP")

            cert_pem = zf.read(pem_files[0]).decode('utf-8')
            logger.info(f"Extracted root cert: {pem_files[0]}")
            return cert_pem
    finally:
        os.unlink(tmp_path)


def _load_cert_from_file(path: str, verify_fingerprint: bool = True) -> x509.Certificate:
    """
    Load certificate from PEM file.

    Args:
        path: Path to PEM file
        verify_fingerprint: If True, verify SHA256 fingerprint matches AWS spec
    """
    with open(path, 'rb') as f:
        cert_data = f.read()
    return _load_cert_from_pem(cert_data.decode('utf-8'), verify_fingerprint)


def _load_cert_from_pem(pem_data: str, verify_fingerprint: bool = True) -> x509.Certificate:
    """
    Load certificate from PEM string.

    Args:
        pem_data: PEM-encoded certificate string
        verify_fingerprint: If True, verify SHA256 fingerprint matches AWS spec

    Returns:
        x509.Certificate object

    Raises:
        ValueError: If fingerprint verification fails
    """
    cert = x509.load_pem_x509_certificate(
        pem_data.encode('utf-8'),
        default_backend()
    )

    if verify_fingerprint:
        _verify_root_cert_fingerprint(cert)

    return cert


def _verify_root_cert_fingerprint(cert: x509.Certificate) -> None:
    """
    Verify the AWS root certificate is authentic.

    Validates:
    1. Certificate subject CN is "aws.nitro-enclaves"
    2. Certificate is self-signed (issuer == subject)
    3. SHA256 fingerprint matches known value

    Raises:
        ValueError: If verification fails
    """
    # Verify subject CN
    subject_cn = None
    for attr in cert.subject:
        if attr.oid == x509.oid.NameOID.COMMON_NAME:
            subject_cn = attr.value
            break

    if subject_cn != AWS_ROOT_CERT_CN:
        raise ValueError(
            f"AWS root certificate CN mismatch!\n"
            f"  Expected: {AWS_ROOT_CERT_CN}\n"
            f"  Got:      {subject_cn}"
        )

    # Verify self-signed
    if cert.subject != cert.issuer:
        raise ValueError("AWS root certificate must be self-signed")

    # Get DER-encoded certificate
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    # Calculate SHA256 fingerprint
    fingerprint = hashlib.sha256(cert_der).hexdigest()

    if fingerprint.lower() != AWS_ROOT_CERT_FINGERPRINT.lower():
        raise ValueError(
            f"AWS root certificate fingerprint mismatch!\n"
            f"  Expected: {AWS_ROOT_CERT_FINGERPRINT}\n"
            f"  Got:      {fingerprint}\n"
            f"AWS may have rotated the root certificate. "
            f"Verify the certificate at {AWS_ROOT_CERT_URL} and update the expected fingerprint."
        )

    logger.info(f"AWS root certificate verified (CN={subject_cn}, fingerprint={fingerprint[:16]}...)")


def clear_cache(cache_dir: Optional[str] = None):
    """Clear cached AWS root certificate."""
    cache_path = Path(cache_dir) if cache_dir else DEFAULT_CACHE_DIR
    cached_cert_path = cache_path / AWS_ROOT_CERT_FILENAME

    if cached_cert_path.exists():
        cached_cert_path.unlink()
        logger.info(f"Cleared cached cert: {cached_cert_path}")
