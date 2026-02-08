"""
Production-ready AWS Nitro Enclave attestation verification.

Implements verification according to AWS official documentation:
https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md

Verification steps:
1. CBOR/COSE decoding and syntactical validation
2. Certificate chain validation (validity, constraints, key usage)
3. COSE signature verification
4. PCR value comparison
5. Output hash verification
"""

import base64
import hashlib
import json
import logging
import time as _time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_der_x509_certificate, ExtensionOID, ExtensionNotFound
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.exceptions import InvalidSignature

from .aws_root_cert import get_aws_root_certificate
from .exceptions import (
    VerificationError,
    InvalidAttestationError,
    CertificateVerificationError,
    SignatureVerificationError,
    PCRMismatchError,
    OutputHashMismatchError,
)

logger = logging.getLogger(__name__)

# AWS Nitro attestation constants per AWS spec
VALID_PCR_LENGTHS = {32, 48, 64}  # SHA256, SHA384, SHA512
MAX_PCR_INDEX = 31
REQUIRED_DIGEST = "SHA384"
MAX_PAYLOAD_SIZE = 16384  # 16KB max payload
MAX_CERTIFICATE_SIZE = 1024  # 1KB max certificate
MAX_USER_DATA_SIZE = 512  # 512 bytes max user_data (AWS spec)
MAX_NONCE_SIZE = 512  # 512 bytes max nonce
MAX_PUBLIC_KEY_SIZE = 1024  # 1KB max public_key


@dataclass
class AttestationDocument:
    """Parsed attestation document contents."""
    module_id: str
    timestamp: int
    digest: str
    pcrs: Dict[int, str]
    certificate: bytes
    cabundle: List[bytes]
    user_data: Optional[bytes]
    nonce: Optional[bytes]
    public_key: Optional[bytes]
    raw_payload: bytes
    raw_signature: bytes
    raw_protected: bytes

    @property
    def timestamp_datetime(self) -> datetime:
        return datetime.utcfromtimestamp(self.timestamp / 1000)

    @property
    def pcr0(self) -> Optional[str]:
        return self.pcrs.get(0)

    @property
    def pcr1(self) -> Optional[str]:
        return self.pcrs.get(1)

    @property
    def pcr2(self) -> Optional[str]:
        return self.pcrs.get(2)


@dataclass
class VerificationResult:
    """Result of attestation verification."""
    valid: bool
    attestation: Optional[AttestationDocument] = None

    # Individual check results
    syntax_valid: bool = False
    aws_signature_valid: bool = False
    certificate_chain_valid: bool = False
    pcr_verified: bool = False
    output_verified: bool = False

    # Extracted data
    pcr0: Optional[str] = None
    pcr1: Optional[str] = None
    pcr2: Optional[str] = None
    user_data: Optional[Dict[str, Any]] = None
    output_hash: Optional[str] = None
    expected_output_hash: Optional[str] = None
    timestamp: Optional[datetime] = None
    module_id: Optional[str] = None

    # Error info
    error: Optional[str] = None
    error_details: Dict[str, Any] = field(default_factory=dict)

    # Per-step timing (milliseconds)
    timing: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'valid': self.valid,
            'syntax_valid': self.syntax_valid,
            'aws_signature_valid': self.aws_signature_valid,
            'certificate_chain_valid': self.certificate_chain_valid,
            'pcr_verified': self.pcr_verified,
            'output_verified': self.output_verified,
            'pcr0': self.pcr0,
            'pcr1': self.pcr1,
            'pcr2': self.pcr2,
            'user_data': self.user_data,
            'output_hash': self.output_hash,
            'expected_output_hash': self.expected_output_hash,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'module_id': self.module_id,
            'error': self.error,
            'error_details': self.error_details,
            'timing': self.timing,
        }


def verify_attestation(
    attestation_doc: str,
    expected_output: Optional[str] = None,
    expected_pcr0: Optional[str] = None,
    expected_pcr1: Optional[str] = None,
    expected_pcr2: Optional[str] = None,
    aws_root_cert_path: Optional[str] = None,
    skip_certificate_verification: bool = False,
) -> VerificationResult:
    """
    Verify an AWS Nitro Enclave attestation document.

    Follows AWS official verification process:
    https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md

    Args:
        attestation_doc: Base64-encoded attestation document
        expected_output: Expected output string (to verify output hash)
        expected_pcr0: Expected PCR0 value (enclave image hash)
        expected_pcr1: Expected PCR1 value (kernel hash)
        expected_pcr2: Expected PCR2 value (application hash)
        aws_root_cert_path: Path to AWS root cert (auto-downloads if not provided)
        skip_certificate_verification: Skip cert chain verification (TESTING ONLY)

    Returns:
        VerificationResult with all verification details
    """
    result = VerificationResult(valid=False)
    total_start = _time.time()

    try:
        # Step 1: Parse and syntactically validate attestation document
        logger.info("Step 1: Parsing and validating attestation document...")
        t0 = _time.time()
        attestation = _parse_and_validate_attestation(attestation_doc)
        result.timing['parse_ms'] = round((_time.time() - t0) * 1000, 2)
        result.attestation = attestation
        result.syntax_valid = True
        result.pcr0 = attestation.pcr0
        result.pcr1 = attestation.pcr1
        result.pcr2 = attestation.pcr2
        result.timestamp = attestation.timestamp_datetime
        result.module_id = attestation.module_id

        # Step 2: Parse user_data
        if attestation.user_data:
            try:
                result.user_data = json.loads(attestation.user_data.decode())
                result.output_hash = result.user_data.get('output_hash')
            except (json.JSONDecodeError, UnicodeDecodeError):
                result.user_data = {'raw': base64.b64encode(attestation.user_data).decode()}

        # Step 3: Verify certificate chain (AWS recommended)
        if not skip_certificate_verification:
            logger.info("Step 2: Verifying certificate chain...")
            t0 = _time.time()
            result.certificate_chain_valid = _verify_certificate_chain(
                attestation.certificate,
                attestation.cabundle,
                aws_root_cert_path
            )
            result.timing['cert_chain_ms'] = round((_time.time() - t0) * 1000, 2)
            if not result.certificate_chain_valid:
                result.error = "Certificate chain verification failed"
                result.timing['total_ms'] = round((_time.time() - total_start) * 1000, 2)
                return result
        else:
            result.certificate_chain_valid = True
            logger.warning("Skipping certificate verification (testing mode)")

        # Step 4: Verify COSE signature
        logger.info("Step 3: Verifying COSE signature...")
        t0 = _time.time()
        result.aws_signature_valid = _verify_cose_signature(
            attestation.raw_protected,
            attestation.raw_payload,
            attestation.raw_signature,
            attestation.certificate
        )
        result.timing['signature_ms'] = round((_time.time() - t0) * 1000, 2)
        if not result.aws_signature_valid:
            result.error = "COSE signature verification failed"
            result.timing['total_ms'] = round((_time.time() - total_start) * 1000, 2)
            return result

        # Step 5: Verify PCR values
        logger.info("Step 4: Verifying PCR values...")
        t0 = _time.time()
        pcr_errors = []
        if expected_pcr0 and attestation.pcr0:
            if attestation.pcr0.lower() != expected_pcr0.lower():
                pcr_errors.append(f"PCR0 mismatch: got {attestation.pcr0}, expected {expected_pcr0}")
        if expected_pcr1 and attestation.pcr1:
            if attestation.pcr1.lower() != expected_pcr1.lower():
                pcr_errors.append(f"PCR1 mismatch: got {attestation.pcr1}, expected {expected_pcr1}")
        if expected_pcr2 and attestation.pcr2:
            if attestation.pcr2.lower() != expected_pcr2.lower():
                pcr_errors.append(f"PCR2 mismatch: got {attestation.pcr2}, expected {expected_pcr2}")
        result.timing['pcr_match_ms'] = round((_time.time() - t0) * 1000, 2)

        if pcr_errors:
            result.error = "; ".join(pcr_errors)
            result.error_details['pcr_errors'] = pcr_errors
            result.timing['total_ms'] = round((_time.time() - total_start) * 1000, 2)
            return result

        result.pcr_verified = True

        # Step 6: Verify output hash
        logger.info("Step 5: Verifying output hash...")
        t0 = _time.time()
        if expected_output is not None:
            result.expected_output_hash = hashlib.sha256(expected_output.encode()).hexdigest()
            if result.output_hash:
                if result.output_hash.lower() == result.expected_output_hash.lower():
                    result.output_verified = True
                else:
                    result.error = f"Output hash mismatch: got {result.output_hash}, expected {result.expected_output_hash}"
                    result.timing['output_hash_ms'] = round((_time.time() - t0) * 1000, 2)
                    result.timing['total_ms'] = round((_time.time() - total_start) * 1000, 2)
                    return result
            else:
                result.error = "No output hash in attestation user_data"
                result.timing['total_ms'] = round((_time.time() - total_start) * 1000, 2)
                return result
        else:
            result.output_verified = True
            logger.info("No expected output provided, skipping output hash verification")
        result.timing['output_hash_ms'] = round((_time.time() - t0) * 1000, 2)

        # All checks passed
        result.valid = True
        result.timing['total_ms'] = round((_time.time() - total_start) * 1000, 2)
        logger.info(f"Attestation verification successful! timing={result.timing}")
        return result

    except InvalidAttestationError as e:
        result.error = f"Invalid attestation: {e}"
        return result
    except CertificateVerificationError as e:
        result.error = f"Certificate error: {e}"
        return result
    except SignatureVerificationError as e:
        result.error = f"Signature error: {e}"
        return result
    except Exception as e:
        result.error = f"Verification error: {e}"
        result.error_details['exception'] = str(e)
        logger.exception("Verification failed with exception")
        return result


def _parse_and_validate_attestation(attestation_doc_b64: str) -> AttestationDocument:
    """
    Parse and syntactically validate COSE_Sign1 attestation document.

    Implements AWS syntactical validation requirements.
    """
    # Base64 decode
    try:
        raw_bytes = base64.b64decode(attestation_doc_b64)
    except Exception as e:
        raise InvalidAttestationError(f"Invalid base64: {e}")

    # Parse CBOR
    try:
        cose_structure = cbor2.loads(raw_bytes)
    except cbor2.CBORDecodeError as e:
        raise InvalidAttestationError(f"Invalid CBOR: {e}")

    # Extract COSE_Sign1 array
    if isinstance(cose_structure, cbor2.CBORTag):
        if cose_structure.tag != 18:
            raise InvalidAttestationError(f"Expected COSE_Sign1 (tag 18), got tag {cose_structure.tag}")
        cose_array = cose_structure.value
    elif isinstance(cose_structure, list):
        cose_array = cose_structure
    else:
        raise InvalidAttestationError(f"Invalid COSE structure type: {type(cose_structure).__name__}")

    if len(cose_array) != 4:
        raise InvalidAttestationError(f"COSE_Sign1 must have 4 elements, got {len(cose_array)}")

    protected, unprotected, payload, signature = cose_array

    # Validate protected header
    if not isinstance(protected, bytes):
        raise InvalidAttestationError("Protected header must be bytes")

    try:
        protected_header = cbor2.loads(protected) if protected else {}
        alg = protected_header.get(1)
        if alg != -35:  # ES384
            logger.warning(f"Unexpected algorithm {alg}, expected -35 (ES384)")
    except Exception as e:
        raise InvalidAttestationError(f"Invalid protected header: {e}")

    # Validate signature length
    if not isinstance(signature, bytes):
        raise InvalidAttestationError("Signature must be bytes")
    if len(signature) not in {64, 96, 132}:  # ES256, ES384, ES512
        raise InvalidAttestationError(f"Invalid signature length: {len(signature)}")

    # Parse payload
    if not isinstance(payload, bytes):
        raise InvalidAttestationError("Payload must be bytes")

    # Validate payload size per AWS spec (1-16,384 bytes)
    if len(payload) == 0:
        raise InvalidAttestationError("Payload cannot be empty")
    if len(payload) > MAX_PAYLOAD_SIZE:
        raise InvalidAttestationError(f"Payload exceeds max size: {len(payload)} > {MAX_PAYLOAD_SIZE}")

    try:
        payload_data = cbor2.loads(payload)
    except Exception as e:
        raise InvalidAttestationError(f"Invalid payload CBOR: {e}")

    # Syntactical validation per AWS spec
    _validate_attestation_fields(payload_data)

    # Extract PCRs
    pcrs = {}
    for idx, value in payload_data.get('pcrs', {}).items():
        pcrs[idx] = value.hex() if isinstance(value, bytes) else str(value)

    return AttestationDocument(
        module_id=payload_data.get('module_id', ''),
        timestamp=payload_data.get('timestamp', 0),
        digest=payload_data.get('digest', 'SHA384'),
        pcrs=pcrs,
        certificate=payload_data.get('certificate', b''),
        cabundle=payload_data.get('cabundle', []),
        user_data=payload_data.get('user_data'),
        nonce=payload_data.get('nonce'),
        public_key=payload_data.get('public_key'),
        raw_payload=payload,
        raw_signature=signature,
        raw_protected=protected,
    )


def _validate_attestation_fields(payload: Dict[str, Any]) -> None:
    """
    Validate attestation document fields per AWS specification.

    Required fields: module_id, digest, timestamp, pcrs, certificate, cabundle
    Optional fields: public_key, user_data, nonce
    """
    # module_id: non-empty text string
    module_id = payload.get('module_id')
    if not module_id or not isinstance(module_id, str):
        raise InvalidAttestationError("module_id must be a non-empty string")

    # digest: must be "SHA384"
    digest = payload.get('digest')
    if digest != REQUIRED_DIGEST:
        raise InvalidAttestationError(f"digest must be '{REQUIRED_DIGEST}', got '{digest}'")

    # timestamp: positive integer
    timestamp = payload.get('timestamp')
    if not isinstance(timestamp, int) or timestamp <= 0:
        raise InvalidAttestationError("timestamp must be a positive integer")

    # pcrs: map with 1-32 entries
    pcrs = payload.get('pcrs')
    if not isinstance(pcrs, dict) or len(pcrs) == 0:
        raise InvalidAttestationError("pcrs must be a non-empty map")
    if len(pcrs) > MAX_PCR_INDEX + 1:
        raise InvalidAttestationError(f"pcrs cannot have more than {MAX_PCR_INDEX + 1} entries")

    for idx, value in pcrs.items():
        if not isinstance(idx, int) or idx < 0 or idx > MAX_PCR_INDEX:
            raise InvalidAttestationError(f"Invalid PCR index: {idx}")
        if not isinstance(value, bytes) or len(value) not in VALID_PCR_LENGTHS:
            raise InvalidAttestationError(f"PCR{idx} must be {VALID_PCR_LENGTHS} bytes")

    # certificate: DER-encoded bytes (1-1024 bytes per AWS spec)
    certificate = payload.get('certificate')
    if not isinstance(certificate, bytes) or len(certificate) == 0:
        raise InvalidAttestationError("certificate must be non-empty bytes")
    if len(certificate) > MAX_CERTIFICATE_SIZE:
        raise InvalidAttestationError(f"certificate exceeds max size: {len(certificate)} > {MAX_CERTIFICATE_SIZE}")

    # cabundle: non-empty array
    cabundle = payload.get('cabundle')
    if not isinstance(cabundle, list) or len(cabundle) == 0:
        raise InvalidAttestationError("cabundle must be a non-empty array")

    # Optional fields validation per AWS spec
    if 'user_data' in payload and payload['user_data'] is not None:
        if not isinstance(payload['user_data'], bytes):
            raise InvalidAttestationError("user_data must be bytes")
        if len(payload['user_data']) > MAX_USER_DATA_SIZE:
            raise InvalidAttestationError(f"user_data cannot exceed {MAX_USER_DATA_SIZE} bytes")

    if 'nonce' in payload and payload['nonce'] is not None:
        if not isinstance(payload['nonce'], bytes):
            raise InvalidAttestationError("nonce must be bytes")
        if len(payload['nonce']) > MAX_NONCE_SIZE:
            raise InvalidAttestationError(f"nonce cannot exceed {MAX_NONCE_SIZE} bytes")

    if 'public_key' in payload and payload['public_key'] is not None:
        if not isinstance(payload['public_key'], bytes):
            raise InvalidAttestationError("public_key must be bytes")
        if len(payload['public_key']) > MAX_PUBLIC_KEY_SIZE:
            raise InvalidAttestationError(f"public_key cannot exceed {MAX_PUBLIC_KEY_SIZE} bytes")


def _verify_certificate_chain(
    leaf_cert_der: bytes,
    cabundle: List[bytes],
    aws_root_cert_path: Optional[str] = None
) -> bool:
    """
    Verify certificate chain per AWS specification.

    Validates:
    - Certificate validity periods
    - Basic Constraints (CA flag, pathLenConstraint)
    - Key Usage extensions
    - Signature chain from leaf to AWS root
    """
    try:
        # Get AWS root certificate
        root_cert = get_aws_root_certificate(aws_root_cert_path)

        # Load leaf certificate
        leaf_cert = load_der_x509_certificate(leaf_cert_der, default_backend())

        # Load all CA certificates from bundle
        ca_certs = []
        for cert_der in cabundle:
            cert = load_der_x509_certificate(cert_der, default_backend())
            ca_certs.append(cert)

        # Build chain by matching issuer to subject
        chain = [leaf_cert]
        current_cert = leaf_cert

        while True:
            issuer_name = current_cert.issuer
            issuer_cert = None

            for ca_cert in ca_certs:
                if ca_cert.subject == issuer_name:
                    issuer_cert = ca_cert
                    break

            if issuer_cert is None:
                break

            chain.append(issuer_cert)
            current_cert = issuer_cert

            if current_cert.subject == current_cert.issuer:
                break

        # Current time for validity checks
        now = datetime.now(timezone.utc)

        # Validate each certificate in chain
        for i, cert in enumerate(chain):
            is_leaf = (i == 0)
            is_last = (i == len(chain) - 1)

            # Check validity period
            if cert.not_valid_before_utc > now:
                logger.error(f"Certificate {i} not yet valid")
                return False
            if cert.not_valid_after_utc < now:
                logger.error(f"Certificate {i} has expired")
                return False

            # Check Basic Constraints
            try:
                bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                basic_constraints = bc.value

                if is_leaf:
                    # Leaf cert should NOT be a CA
                    if basic_constraints.ca:
                        logger.warning(f"Leaf certificate has CA=True (unusual but not fatal)")
                else:
                    # Intermediate certs must be CA
                    if not basic_constraints.ca:
                        logger.error(f"Certificate {i} is not a CA but is in chain")
                        return False

                    # Check pathLenConstraint
                    # pathLenConstraint = max number of CA certs that can follow this one
                    # Certificate at index i has (i - 1) CA certs between it and the leaf
                    if basic_constraints.path_length is not None:
                        ca_certs_below = i - 1  # Number of CA certs between this and leaf
                        if basic_constraints.path_length < ca_certs_below:
                            logger.error(f"Certificate {i} pathLenConstraint {basic_constraints.path_length} < {ca_certs_below}")
                            return False

            except ExtensionNotFound:
                if not is_leaf:
                    logger.error(f"Certificate {i} missing Basic Constraints")
                    return False

            # Check Key Usage
            try:
                ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
                key_usage = ku.value

                if is_leaf:
                    # Leaf cert needs digitalSignature
                    if not key_usage.digital_signature:
                        logger.error("Leaf certificate missing digitalSignature key usage")
                        return False
                else:
                    # CA certs need keyCertSign
                    if not key_usage.key_cert_sign:
                        logger.error(f"Certificate {i} missing keyCertSign key usage")
                        return False

            except ExtensionNotFound:
                # Key Usage is optional but recommended
                logger.warning(f"Certificate {i} missing Key Usage extension")

        # Verify signatures up the chain
        for i in range(len(chain) - 1):
            cert = chain[i]
            issuer_cert = chain[i + 1]

            if not _verify_cert_signature(cert, issuer_cert.public_key()):
                logger.error(f"Certificate {i} signature verification failed")
                return False

        # Verify last cert in chain is signed by root
        last_cert = chain[-1]
        if not _verify_cert_signature(last_cert, root_cert.public_key()):
            logger.error("Root certificate signature verification failed")
            return False

        # Verify root certificate validity
        if root_cert.not_valid_before_utc > now:
            logger.error("Root certificate not yet valid")
            return False
        if root_cert.not_valid_after_utc < now:
            logger.error("Root certificate has expired")
            return False

        logger.info(f"Certificate chain verified ({len(chain)} certs + root)")
        return True

    except Exception as e:
        logger.error(f"Certificate chain verification error: {e}")
        raise CertificateVerificationError(str(e))


def _verify_cert_signature(cert: x509.Certificate, issuer_public_key) -> bool:
    """Verify a certificate's signature using the issuer's public key."""
    try:
        if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm)
            )
        else:
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        logger.error(f"Certificate signature verification error: {e}")
        return False


def _verify_cose_signature(
    protected: bytes,
    payload: bytes,
    signature: bytes,
    cert_der: bytes
) -> bool:
    """
    Verify COSE_Sign1 signature per RFC 8152.

    AWS Nitro uses ES384 (ECDSA with P-384 and SHA-384).
    """
    try:
        # Load certificate and extract public key
        cert = load_der_x509_certificate(cert_der, default_backend())
        public_key = cert.public_key()

        # Build Sig_structure per RFC 8152
        sig_structure = cbor2.dumps([
            "Signature1",
            protected,
            b"",  # external_aad
            payload
        ])

        if isinstance(public_key, ec.EllipticCurvePublicKey):
            # Parse algorithm from protected header
            protected_header = cbor2.loads(protected) if protected else {}
            alg = protected_header.get(1)

            # Map COSE algorithm to parameters
            # -7 = ES256, -35 = ES384, -36 = ES512
            if alg == -7:
                hash_alg = hashes.SHA256()
                component_size = 32
            elif alg == -35:
                hash_alg = hashes.SHA384()
                component_size = 48
            elif alg == -36:
                hash_alg = hashes.SHA512()
                component_size = 66
            else:
                # Default to ES384 for AWS Nitro
                hash_alg = hashes.SHA384()
                component_size = 48

            # COSE uses raw (r || s) signatures, convert to DER
            if len(signature) != component_size * 2:
                raise SignatureVerificationError(
                    f"Invalid signature length: {len(signature)}, expected {component_size * 2}"
                )

            r = int.from_bytes(signature[:component_size], 'big')
            s = int.from_bytes(signature[component_size:], 'big')
            der_signature = utils.encode_dss_signature(r, s)

            public_key.verify(der_signature, sig_structure, ec.ECDSA(hash_alg))
        else:
            public_key.verify(signature, sig_structure, padding.PKCS1v15(), hashes.SHA384())

        logger.info("COSE signature verified")
        return True

    except InvalidSignature:
        logger.error("COSE signature invalid")
        return False
    except Exception as e:
        logger.error(f"COSE signature verification error: {e}")
        raise SignatureVerificationError(str(e))
