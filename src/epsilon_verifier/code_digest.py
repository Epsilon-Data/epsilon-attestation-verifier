"""
Code digest: rebuild the code bundle of a job from its build/ folder.

The coordinator zips the job's build/ folder and the enclave attests SHA-256 of
that archive as `script_hash` in the attestation user_data. The archive is
deterministic, so anyone with the submitted commit can recompute the digest:

- every regular file under build/ (symlinks followed only if they stay inside
  it), skipping any path with a part named __pycache__, .git, .DS_Store, .env or
  node_modules and any file ending in .pyc or .pyo;
- entries named by their POSIX path relative to build/, sorted by that name;
- stored uncompressed, timestamp 1980-01-01 00:00:00, mode 0100644, Unix
  creator, written with Python's zipfile.

Empty directories are not included.
"""

import hashlib
import io
import os
import zipfile
from pathlib import Path
from typing import List, Tuple

EXCLUDED_PARTS = {"__pycache__", ".git", ".DS_Store", ".env", "node_modules"}
EXCLUDED_SUFFIXES = (".pyc", ".pyo")
ENTRY_DATE_TIME = (1980, 1, 1, 0, 0, 0)
ENTRY_MODE = 0o100644


def _is_excluded(relative: Path) -> bool:
    if any(part in EXCLUDED_PARTS for part in relative.parts):
        return True
    return relative.name.endswith(EXCLUDED_SUFFIXES)


def _bundle_entries(build_dir: Path) -> List[Tuple[str, Path]]:
    root = build_dir.resolve()
    entries = []
    for path in build_dir.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(build_dir)
        if _is_excluded(relative):
            continue
        resolved = path.resolve()
        if os.path.commonpath([str(root), str(resolved)]) != str(root):
            continue
        entries.append((relative.as_posix(), path))
    entries.sort()
    return entries


def build_code_bundle(build_dir: str) -> bytes:
    """Return the deterministic ZIP the coordinator builds from `build_dir`."""
    directory = Path(build_dir)
    if not directory.is_dir():
        raise ValueError(f"Not a directory: {build_dir}")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name, path in _bundle_entries(directory):
            info = zipfile.ZipInfo(name, date_time=ENTRY_DATE_TIME)
            info.create_system = 3
            info.external_attr = ENTRY_MODE << 16
            archive.writestr(info, path.read_bytes())
    return buffer.getvalue()


def compute_code_digest(build_dir: str) -> str:
    """SHA-256 (hex) of the code bundle: compare with `script_hash` in the attestation."""
    return hashlib.sha256(build_code_bundle(build_dir)).hexdigest()
