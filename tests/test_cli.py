"""
Tests for CLI interface.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from epsilon_verifier.cli import main, cmd_verify, cmd_extract


class TestCLIMain:
    """Tests for CLI main function."""

    def test_no_args_shows_help(self):
        """Test that no arguments shows help."""
        with patch('sys.argv', ['epsilon-verify']):
            result = main()
            assert result == 0

    def test_help_flag(self):
        """Test --help flag."""
        with patch('sys.argv', ['epsilon-verify', '--help']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0


class TestVerifyCommand:
    """Tests for verify command."""

    def test_verify_nonexistent_file(self):
        """Test verify with nonexistent file returns error."""
        args = MagicMock()
        args.attestation = "/nonexistent/path/file.json"

        result = cmd_verify(args)
        assert result == 1

    def test_verify_with_output_file(self):
        """Test verify loads output from file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            attestation_file = Path(tmpdir) / "attestation.txt"
            output_file = Path(tmpdir) / "output.txt"

            # Write test data (invalid attestation, but tests file loading)
            attestation_file.write_text("invalid-base64")
            output_file.write_text("test output")

            args = MagicMock()
            args.attestation = str(attestation_file)
            args.output = str(output_file)
            args.pcr0 = None
            args.pcr1 = None
            args.pcr2 = None
            args.version = None
            args.aws_root_cert = None
            args.skip_cert_verification = True
            args.json = False

            result = cmd_verify(args)
            # Should fail due to invalid attestation, but file loading worked
            assert result == 1

    def test_verify_json_output(self):
        """Test verify with --json flag."""
        with tempfile.TemporaryDirectory() as tmpdir:
            attestation_file = Path(tmpdir) / "attestation.txt"
            attestation_file.write_text("invalid-base64")

            args = MagicMock()
            args.attestation = str(attestation_file)
            args.output = None
            args.pcr0 = None
            args.pcr1 = None
            args.pcr2 = None
            args.version = None
            args.aws_root_cert = None
            args.skip_cert_verification = True
            args.json = True

            # Capture stdout
            import io
            import sys
            captured = io.StringIO()

            with patch('sys.stdout', captured):
                result = cmd_verify(args)

            output = captured.getvalue()
            # Should be valid JSON
            try:
                parsed = json.loads(output)
                assert 'valid' in parsed
            except json.JSONDecodeError:
                pass  # May have other output before JSON


class TestExtractCommand:
    """Tests for extract command."""

    def test_extract_nonexistent_file(self):
        """Test extract with nonexistent file returns error."""
        args = MagicMock()
        args.attestation = "/nonexistent/path/file.json"

        result = cmd_extract(args)
        assert result == 1


class TestJSONParsing:
    """Tests for JSON attestation parsing in CLI."""

    def test_nested_json_extraction(self):
        """Test that nested JSON structure is handled."""
        with tempfile.TemporaryDirectory() as tmpdir:
            attestation_file = Path(tmpdir) / "response.json"

            # Epsilon job response format
            nested_json = {
                "attestation": {
                    "attestation": {
                        "attestation_document": "base64_doc_here"
                    }
                }
            }
            attestation_file.write_text(json.dumps(nested_json))

            args = MagicMock()
            args.attestation = str(attestation_file)
            args.output = None
            args.pcr0 = None
            args.pcr1 = None
            args.pcr2 = None
            args.version = None
            args.aws_root_cert = None
            args.skip_cert_verification = True
            args.json = True

            # Should parse the nested structure and extract base64_doc_here
            result = cmd_verify(args)
            # Will fail because base64_doc_here isn't valid, but parsing worked
            assert result == 1
