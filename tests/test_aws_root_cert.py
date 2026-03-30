"""
Tests for AWS root certificate management.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from epsilon_verifier.aws_root_cert import (
    get_aws_root_certificate,
    clear_cache,
    DEFAULT_CACHE_DIR,
    AWS_ROOT_CERT_FILENAME,
)


class TestCacheDirectory:
    """Tests for cache directory behavior."""

    def test_default_cache_dir_is_in_home(self):
        """Test that default cache is under home directory."""
        assert str(Path.home()) in str(DEFAULT_CACHE_DIR)

    def test_cache_dir_created_on_demand(self):
        """Test that cache directory is created if it doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "new_cache"
            assert not cache_dir.exists()

            # Mock the download to avoid network call
            with patch('epsilon_verifier.aws_root_cert._download_aws_root_cert') as mock_dl:
                mock_dl.return_value = SAMPLE_PEM_CERT

                with patch('epsilon_verifier.aws_root_cert._load_cert_from_pem') as mock_load:
                    mock_load.return_value = MagicMock()

                    get_aws_root_certificate(cache_dir=str(cache_dir))

            assert cache_dir.exists()


class TestClearCache:
    """Tests for cache clearing."""

    def test_clear_nonexistent_cache(self):
        """Test that clearing nonexistent cache doesn't raise."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Should not raise
            clear_cache(cache_dir=tmpdir)

    def test_clear_existing_cache(self):
        """Test that clearing existing cache removes the file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / AWS_ROOT_CERT_FILENAME
            cache_path.write_text("dummy cert")

            assert cache_path.exists()
            clear_cache(cache_dir=tmpdir)
            assert not cache_path.exists()


class TestLoadFromExplicitPath:
    """Tests for loading cert from explicit path."""

    def test_explicit_path_used(self):
        """Test that explicit cert_path is used when provided."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f:
            f.write(SAMPLE_PEM_CERT)
            cert_path = f.name

        try:
            with patch('epsilon_verifier.aws_root_cert._load_cert_from_file') as mock_load:
                mock_load.return_value = MagicMock()

                get_aws_root_certificate(cert_path=cert_path)

                mock_load.assert_called_once_with(cert_path, verify_fingerprint=False)
        finally:
            os.unlink(cert_path)


# Sample PEM certificate for testing (not a real cert)
SAMPLE_PEM_CERT = """-----BEGIN CERTIFICATE-----
MIICTjCCAdSgAwIBAgIUAQAAAAAAAAAAAAAAAAAAAAAwCgYIKoZIzj0EAwMwgYkx
CzAJBgNVBAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQHDAdTZWF0
dGxlMQ8wDQYDVQQKDAZBbWF6b24xDDAKBgNVBAsMA0FXUzE0MDIGA1UEAwwrYXdz
Lm5pdHJvLWVuY2xhdmVzLTEyMy5hbWF6b25hd3MuY29tLnJvb3QwHhcNMjQwMTAx
MDAwMDAwWhcNMzQwMTAxMDAwMDAwWjCBiTELMAkGA1UEBhMCVVMxEzARBgNVBAgM
Cldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxDzANBgNVBAoMBkFtYXpvbjEM
MAoGA1UECwwDQVdTMTQwMgYDVQQDDCthd3Mubml0cm8tZW5jbGF2ZXMtMTIzLmFt
YXpvbmF3cy5jb20ucm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDummy==
-----END CERTIFICATE-----"""


class TestDownloadBehavior:
    """Tests for download behavior."""

    def test_cached_cert_used_if_exists(self):
        """Test that cached cert is used without downloading."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / AWS_ROOT_CERT_FILENAME
            cache_path.write_text(SAMPLE_PEM_CERT)

            with patch('epsilon_verifier.aws_root_cert._download_aws_root_cert') as mock_dl:
                with patch('epsilon_verifier.aws_root_cert._load_cert_from_file') as mock_load:
                    mock_load.return_value = MagicMock()

                    get_aws_root_certificate(cache_dir=tmpdir)

                    # Download should not be called
                    mock_dl.assert_not_called()

    def test_force_download_ignores_cache(self):
        """Test that force_download=True ignores cache."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / AWS_ROOT_CERT_FILENAME
            cache_path.write_text(SAMPLE_PEM_CERT)

            with patch('epsilon_verifier.aws_root_cert._download_aws_root_cert') as mock_dl:
                mock_dl.return_value = SAMPLE_PEM_CERT

                with patch('epsilon_verifier.aws_root_cert._load_cert_from_pem') as mock_load:
                    mock_load.return_value = MagicMock()

                    get_aws_root_certificate(cache_dir=tmpdir, force_download=True)

                    # Download should be called even though cache exists
                    mock_dl.assert_called_once()
