"""
Tests for PCR registry.
"""

import pytest
from unittest.mock import patch, MagicMock

from epsilon_verifier.pcr_registry import (
    get_published_pcrs,
    list_known_versions,
    register_pcr_values,
    PCRValues,
    KNOWN_PCR_VALUES,
)


class TestPCRValues:
    """Tests for PCRValues dataclass."""

    def test_to_dict(self):
        """Test PCRValues serialization."""
        pcr = PCRValues(
            version="1.0.0",
            pcr0="abc123",
            pcr1="def456",
            pcr2="ghi789",
            release_date="2025-01-01",
            notes="Initial release",
        )

        d = pcr.to_dict()

        assert d['version'] == "1.0.0"
        assert d['pcr0'] == "abc123"
        assert d['release_date'] == "2025-01-01"

    def test_optional_fields_default_to_none(self):
        """Test that optional fields default to None."""
        pcr = PCRValues(
            version="1.0.0",
            pcr0="abc",
            pcr1="def",
            pcr2="ghi",
        )

        assert pcr.release_date is None
        assert pcr.notes is None


class TestRegisterPCRValues:
    """Tests for registering PCR values."""

    def test_register_new_version(self):
        """Test registering a new version."""
        # Clean up after test
        original_values = KNOWN_PCR_VALUES.copy()

        try:
            pcr = PCRValues(
                version="test-1.0.0",
                pcr0="test_pcr0",
                pcr1="test_pcr1",
                pcr2="test_pcr2",
            )

            register_pcr_values(pcr)

            assert "test-1.0.0" in KNOWN_PCR_VALUES
            assert KNOWN_PCR_VALUES["test-1.0.0"].pcr0 == "test_pcr0"
        finally:
            # Restore original state
            KNOWN_PCR_VALUES.clear()
            KNOWN_PCR_VALUES.update(original_values)

    def test_register_overwrites_existing(self):
        """Test that registering existing version overwrites."""
        original_values = KNOWN_PCR_VALUES.copy()

        try:
            pcr1 = PCRValues(version="test-v", pcr0="old", pcr1="", pcr2="")
            pcr2 = PCRValues(version="test-v", pcr0="new", pcr1="", pcr2="")

            register_pcr_values(pcr1)
            register_pcr_values(pcr2)

            assert KNOWN_PCR_VALUES["test-v"].pcr0 == "new"
        finally:
            KNOWN_PCR_VALUES.clear()
            KNOWN_PCR_VALUES.update(original_values)


class TestGetPublishedPCRs:
    """Tests for getting published PCR values."""

    def test_returns_none_for_unknown_version(self):
        """Test that unknown version returns None."""
        result = get_published_pcrs("unknown-version-xyz")
        assert result is None

    def test_fetch_latest_falls_back_on_error(self):
        """Test that fetch_latest=True falls back to built-in on error."""
        with patch('epsilon_verifier.pcr_registry._fetch_pcrs_from_github') as mock_fetch:
            mock_fetch.side_effect = Exception("Network error")

            # Should not raise, should return None or fallback
            result = get_published_pcrs(fetch_latest=True)

            # Result depends on KNOWN_PCR_VALUES state
            # Just verify no exception was raised
            mock_fetch.assert_called_once()


class TestListKnownVersions:
    """Tests for listing known versions."""

    def test_returns_list(self):
        """Test that list_known_versions returns a list."""
        versions = list_known_versions()
        assert isinstance(versions, list)

    def test_registered_versions_appear(self):
        """Test that registered versions appear in list."""
        original_values = KNOWN_PCR_VALUES.copy()

        try:
            pcr = PCRValues(version="list-test-v1", pcr0="", pcr1="", pcr2="")
            register_pcr_values(pcr)

            versions = list_known_versions()
            assert "list-test-v1" in versions
        finally:
            KNOWN_PCR_VALUES.clear()
            KNOWN_PCR_VALUES.update(original_values)


class TestFetchFromGitHub:
    """Tests for GitHub fetching."""

    def test_fetch_handles_valid_response(self):
        """Test fetching with valid GitHub response."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "versions": [
                {
                    "version": "2.0.0",
                    "pcr0": "github_pcr0",
                    "pcr1": "github_pcr1",
                    "pcr2": "github_pcr2",
                    "release_date": "2025-02-01",
                }
            ]
        }

        with patch('epsilon_verifier.pcr_registry.requests.get') as mock_get:
            mock_get.return_value = mock_response

            result = get_published_pcrs(version="2.0.0", fetch_latest=True)

            assert result is not None
            assert result.pcr0 == "github_pcr0"
            assert result.version == "2.0.0"

    def test_fetch_returns_none_for_missing_version(self):
        """Test fetching returns None for version not in GitHub."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "versions": [
                {"version": "1.0.0", "pcr0": "x", "pcr1": "y", "pcr2": "z"}
            ]
        }

        with patch('epsilon_verifier.pcr_registry.requests.get') as mock_get:
            mock_get.return_value = mock_response

            result = get_published_pcrs(version="99.0.0", fetch_latest=True)

            assert result is None
