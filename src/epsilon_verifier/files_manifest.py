"""
Output files manifest verification.

The enclave attests the files a script writes by putting the SHA-256 of a
canonical manifest into the attestation user_data as `files_manifest_sha256`.

Manifest = list of {"name", "size", "sha256", "type"} sorted by name (plain
code-point order), where name is the file's path relative to outputs/ with "/"
as separator, size is the byte length, sha256 the lowercase hex digest of the
file bytes and type comes from the fixed extension table below
(application/octet-stream for any other or no extension). Canonical bytes are
json.dumps(manifest, sort_keys=True, separators=(",", ":")) encoded as UTF-8.
No files -> manifest [] -> SHA-256 of b"[]".
"""

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .exceptions import InvalidOutputFileError

# Known extensions (lower-cased, after the last dot of the last segment) and their
# content type. Part of the attested manifest: do not extend.
OUTPUT_FILE_TYPES: Dict[str, str] = {
    "csv": "text/csv",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "json": "application/json",
    "txt": "text/plain",
    "pdf": "application/pdf",
}

DEFAULT_OUTPUT_FILE_TYPE = "application/octet-stream"

# Relative path: 1-5 segments, each starting with an alphanumeric (no ".", "..",
# hidden or empty segments), whole name at most 255 characters.
OUTPUT_FILE_NAME_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}(/[A-Za-z0-9][A-Za-z0-9._-]{0,99}){0,4}$"
)
OUTPUT_FILE_NAME_MAX_LENGTH = 255


def is_valid_output_file_name(name: Any) -> bool:
    """True when name is a valid output file path (relative to outputs/)."""
    return (
        isinstance(name, str)
        and len(name) <= OUTPUT_FILE_NAME_MAX_LENGTH
        and OUTPUT_FILE_NAME_RE.fullmatch(name) is not None
    )


def output_file_type(name: str) -> str:
    """Return the content type for an output file name, or raise InvalidOutputFileError."""
    if not is_valid_output_file_name(name):
        raise InvalidOutputFileError(f"Invalid output file name: {name!r}")
    basename = name.rsplit("/", 1)[-1]
    ext = basename.rsplit(".", 1)[-1].lower() if "." in basename else ""
    return OUTPUT_FILE_TYPES.get(ext, DEFAULT_OUTPUT_FILE_TYPE)


def build_files_manifest(files: Iterable[Tuple[str, bytes]]) -> List[Dict[str, Any]]:
    """Build the manifest (sorted by name) from (name, bytes) pairs."""
    manifest = []
    seen = set()
    for name, data in files:
        content_type = output_file_type(name)
        if name in seen:
            raise InvalidOutputFileError(f"Duplicate output file name: {name!r}")
        seen.add(name)
        manifest.append({
            "name": name,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "type": content_type,
        })
    manifest.sort(key=lambda entry: entry["name"])
    return manifest


def canonical_manifest_bytes(manifest: List[Dict[str, Any]]) -> bytes:
    """Canonical JSON encoding of a manifest."""
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_files_manifest_sha256(files: Iterable[Tuple[str, bytes]]) -> str:
    """Lowercase hex SHA-256 of the canonical manifest built from (name, bytes) pairs."""
    return hashlib.sha256(canonical_manifest_bytes(build_files_manifest(files))).hexdigest()


def verify_files_manifest(files: Iterable[Tuple[str, bytes]], attested_sha256: Optional[str]) -> bool:
    """
    Check (name, bytes) pairs against the attested files_manifest_sha256.

    Returns False when the attestation carries no manifest hash (older attestations)
    or the hash differs. Raises InvalidOutputFileError for names outside the
    allowed rules.
    """
    computed = compute_files_manifest_sha256(files)
    if not attested_sha256:
        return False
    return computed == attested_sha256.lower()
