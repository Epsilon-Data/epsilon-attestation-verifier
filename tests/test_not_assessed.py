"""A check with nothing to compare with is reported as not assessed, never as a pass."""
import argparse
import hashlib
import json

from epsilon_verifier import NOT_ASSESSED, verify_attestation
from epsilon_verifier.cli import cmd_verify
from tests.test_files_manifest import EMPTY_SHA256, _make_attestation

OUTPUT = "count=7\n"
PCR0 = "00" * 48  # the PCR0 of _make_attestation documents


def _doc():
    return _make_attestation({
        "output_hash": hashlib.sha256(OUTPUT.encode()).hexdigest(),
        "files_manifest_sha256": EMPTY_SHA256,
    })


def _args(attestation_path, **overrides):
    values = dict(
        attestation=str(attestation_path), output=None, files=None, files_root=None,
        pcr0=None, pcr1=None, pcr2=None, version=None, aws_root_cert=None,
        skip_cert_verification=True, json=True,
    )
    values.update(overrides)
    return argparse.Namespace(**values)


class TestResult:
    def test_without_expected_values_nothing_optional_is_assessed(self):
        result = verify_attestation(_doc(), skip_certificate_verification=True)

        assert result.valid is True
        assert result.fully_assessed is False
        assert result.not_assessed == ["certificate_chain_valid", "pcr_verified", "output_verified", "files_verified"]
        for name in result.not_assessed:
            assert result.check(name) == NOT_ASSESSED
        # The signature is always checked
        assert result.check("aws_signature_valid") is True

    def test_each_expected_value_assesses_its_check(self):
        result = verify_attestation(
            _doc(), skip_certificate_verification=True,
            expected_output=OUTPUT, expected_pcr0=PCR0, expected_files=[],
        )

        assert result.valid is True
        assert result.not_assessed == ["certificate_chain_valid"]
        assert [result.check(name) for name in ("pcr_verified", "output_verified", "files_verified")] == [True] * 3

    def test_a_failed_check_is_reported_as_failed_and_later_ones_as_not_assessed(self):
        result = verify_attestation(
            _doc(), skip_certificate_verification=True, expected_output="another output", expected_files=[],
        )

        assert result.valid is False
        assert result.check("output_verified") is False
        # Verification stopped at the output hash: the files manifest was never compared
        assert result.check("files_verified") == NOT_ASSESSED
        assert result.check("pcr_verified") == NOT_ASSESSED

    def test_a_pcr_mismatch_is_failed_not_unassessed(self):
        result = verify_attestation(_doc(), skip_certificate_verification=True, expected_pcr0="ab" * 48)

        assert result.valid is False
        assert result.check("pcr_verified") is False

    def test_to_dict_reports_not_assessed_instead_of_true(self):
        report = verify_attestation(_doc(), skip_certificate_verification=True, expected_output=OUTPUT).to_dict()

        assert report["valid"] is True
        assert report["fully_assessed"] is False
        assert report["output_verified"] is True
        assert report["pcr_verified"] == "not_assessed"
        assert report["files_verified"] == "not_assessed"
        assert report["certificate_chain_valid"] == "not_assessed"
        assert report["not_assessed"] == ["certificate_chain_valid", "pcr_verified", "files_verified"]

    def test_boolean_fields_keep_their_meaning_for_existing_callers(self):
        result = verify_attestation(_doc(), skip_certificate_verification=True)

        assert (result.pcr_verified, result.output_verified, result.files_verified) == (True, True, True)


class TestCLI:
    def test_json_without_expected_output_reports_not_assessed(self, tmp_path, capsys):
        attestation_path = tmp_path / "attestation.txt"
        attestation_path.write_text(_doc())

        assert cmd_verify(_args(attestation_path)) == 0

        report = json.loads(capsys.readouterr().out)
        assert report["output_verified"] == "not_assessed"
        assert report["pcr_verified"] == "not_assessed"
        assert report["fully_assessed"] is False

    def test_text_names_what_was_not_assessed_and_does_not_say_verified(self, tmp_path, capsys):
        attestation_path = tmp_path / "attestation.txt"
        attestation_path.write_text(_doc())

        assert cmd_verify(_args(attestation_path, json=False, output=OUTPUT)) == 0

        text = capsys.readouterr().out
        assert "ATTESTATION VERIFIED" not in text
        assert "NOT EVERY CHECK WAS MADE" in text
        assert "Not assessed: certificate chain, PCR values, files manifest" in text
        assert "Output Hash:          ✓" in text
        assert "PCR Values:           – not assessed" in text

    def test_text_says_verified_only_when_every_check_was_made(self, tmp_path, capsys, monkeypatch):
        attestation_path = tmp_path / "attestation.txt"
        attestation_path.write_text(_doc())
        # The test document is self-signed: accept its chain so no check is skipped
        monkeypatch.setattr("epsilon_verifier.verifier._verify_certificate_chain", lambda *args, **kwargs: True)

        args = _args(attestation_path, json=False, output=OUTPUT, pcr0=PCR0, files_root=str(tmp_path / "outputs"),
                     skip_cert_verification=False)
        (tmp_path / "outputs").mkdir()
        assert cmd_verify(args) == 0

        text = capsys.readouterr().out
        assert "ATTESTATION VERIFIED" in text
        assert "not assessed" not in text.lower()
