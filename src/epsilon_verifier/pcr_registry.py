"""
PCR value registry for Epsilon enclave versions.

Provides expected PCR values for verification against known
Epsilon enclave releases.
"""

import json
import logging
from dataclasses import dataclass
from typing import Dict, Optional

import requests

logger = logging.getLogger(__name__)

# GitHub URL for published PCR values
EPSILON_PCR_URL = "https://raw.githubusercontent.com/epsilon-data/epsilon-enclave/main/published/pcr_values.json"


@dataclass
class PCRValues:
    """PCR values for a specific enclave version."""
    version: str
    pcr0: str  # Enclave image hash
    pcr1: str  # Kernel + bootstrap hash
    pcr2: str  # Application hash
    release_date: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, str]:
        return {
            'version': self.version,
            'pcr0': self.pcr0,
            'pcr1': self.pcr1,
            'pcr2': self.pcr2,
            'release_date': self.release_date,
            'notes': self.notes,
        }


# Built-in registry of known PCR values
# These are embedded for offline verification
KNOWN_PCR_VALUES: Dict[str, PCRValues] = {
    # Add known versions here as they are released
    # Example:
    # "1.0.0": PCRValues(
    #     version="1.0.0",
    #     pcr0="abc123...",
    #     pcr1="def456...",
    #     pcr2="ghi789...",
    #     release_date="2025-02-01",
    # ),
}


def get_published_pcrs(
    version: Optional[str] = None,
    fetch_latest: bool = False
) -> Optional[PCRValues]:
    """
    Get published PCR values for an Epsilon enclave version.

    Args:
        version: Specific version to get (e.g., "1.0.0"). If None, returns latest.
        fetch_latest: If True, fetch from GitHub instead of using built-in values.

    Returns:
        PCRValues for the specified version, or None if not found.
    """
    if fetch_latest:
        try:
            return _fetch_pcrs_from_github(version)
        except Exception as e:
            logger.warning(f"Failed to fetch PCRs from GitHub: {e}")
            # Fall back to built-in values

    if version:
        return KNOWN_PCR_VALUES.get(version)

    # Return latest version from built-in values
    if KNOWN_PCR_VALUES:
        latest_version = max(KNOWN_PCR_VALUES.keys())
        return KNOWN_PCR_VALUES[latest_version]

    return None


def _fetch_pcrs_from_github(version: Optional[str] = None) -> Optional[PCRValues]:
    """Fetch PCR values from Epsilon's GitHub repository."""
    try:
        response = requests.get(EPSILON_PCR_URL, timeout=10)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as e:
        raise RuntimeError(f"Failed to fetch PCR values: {e}")

    versions = data.get('versions', {})

    if version:
        if version in versions:
            v = versions[version]
            return PCRValues(
                version=version,
                pcr0=v.get('pcr0', ''),
                pcr1=v.get('pcr1', ''),
                pcr2=v.get('pcr2', ''),
                release_date=v.get('release_date'),
                notes=v.get('notes'),
            )
        return None

    # Return latest
    latest = data.get('latest')
    if latest and latest in versions:
        v = versions[latest]
        return PCRValues(
            version=latest,
            pcr0=v.get('pcr0', ''),
            pcr1=v.get('pcr1', ''),
            pcr2=v.get('pcr2', ''),
            release_date=v.get('release_date'),
            notes=v.get('notes'),
        )

    return None


def list_known_versions() -> list:
    """List all known enclave versions with PCR values."""
    return list(KNOWN_PCR_VALUES.keys())


def register_pcr_values(pcr_values: PCRValues):
    """
    Register PCR values for a version.

    Useful for testing or adding custom versions.
    """
    KNOWN_PCR_VALUES[pcr_values.version] = pcr_values
    logger.info(f"Registered PCR values for version {pcr_values.version}")
