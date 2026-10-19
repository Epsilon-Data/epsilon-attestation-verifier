"""
Tests for output files manifest verification.
"""

import argparse
import base64
import json
from datetime import datetime, timedelta, timezone

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

from epsilon_verifier import (
    InvalidOutputFileError,
    build_files_manifest,
    canonical_manifest_bytes,
    compute_files_manifest_sha256,
    verify_attestation,
    verify_files_manifest,
)
from epsilon_verifier.cli import cmd_verify

# Known-answer vector, computed independently with shasum over the literal canonical JSON.
KAT_FILES = [
    ("results.csv", b"a,b\n1,2\n"),
    ("notes.txt", b"hello\n"),
]
KAT_CANONICAL = (
    b'[{"name":"notes.txt","sha256":"5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",'
    b'"size":6,"type":"text/plain"},'
    b'{"name":"results.csv","sha256":"492d5ea496056f1a6a6592241032fab764c321596317930b4fa0e1e8bc3b7470",'
    b'"size":8,"type":"text/csv"}]'
)
KAT_SHA256 = "a1a158edd1957e859b8f27392f9591fa79a202cc90c05e161dbfb06ced480934"
# Subfolder + unknown/missing extension vector (shared with the other repos).
KAT2_FILES = [
    ("a.csv", b"x,y\n1,2\n"),
    ("plots/fig.bin", bytes([0, 1, 2])),
    ("notes", b"hi\n"),
]
KAT2_CANONICAL = (
    b'[{"name":"a.csv","sha256":"81bf9fa83c6f7f151bd491a98cd7d933de3965289e3ebd77c6c425f7eaa16392",'
    b'"size":8,"type":"text/csv"},'
    b'{"name":"notes","sha256":"98ea6e4f216f2fb4b69fff9b3a44842c38686ca685f3f55dc48c5d3fb1107be4",'
    b'"size":3,"type":"application/octet-stream"},'
    b'{"name":"plots/fig.bin","sha256":"ae4b3280e56e2faf83f414a6e3dabe9d5fbe18976544c05fed121accb85b53fc",'
    b'"size":3,"type":"application/octet-stream"}]'
)
KAT2_SHA256 = "49f15dcc85c70e4712ab20edd5e118eb3ea2526e264da93628522a3a6c456907"
EMPTY_SHA256 = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"


class TestBuildManifest:

    def test_known_answer_vector(self):
        manifest = build_files_manifest(KAT_FILES)
        assert [entry["name"] for entry in manifest] == ["notes.txt", "results.csv"]
        assert canonical_manifest_bytes(manifest) == KAT_CANONICAL
        assert compute_files_manifest_sha256(KAT_FILES) == KAT_SHA256

    def test_known_answer_vector_with_subfolder_and_unknown_types(self):
        manifest = build_files_manifest(KAT2_FILES)
        assert [entry["name"] for entry in manifest] == ["a.csv", "notes", "plots/fig.bin"]
        assert canonical_manifest_bytes(manifest) == KAT2_CANONICAL
        assert compute_files_manifest_sha256(KAT2_FILES) == KAT2_SHA256

    def test_sorts_by_code_point(self):
        names = [e["name"] for e in build_files_manifest([("b", b""), ("B", b""), ("a/b", b""), ("a.b", b""), ("a_b", b"")])]
        assert names == ["B", "a.b", "a/b", "a_b", "b"]

    def test_no_files_hashes_empty_list(self):
        assert canonical_manifest_bytes(build_files_manifest([])) == b"[]"
        assert compute_files_manifest_sha256([]) == EMPTY_SHA256

    @pytest.mark.parametrize("name,expected_type", [
        ("a.csv", "text/csv"),
        ("a.png", "image/png"),
        ("a.jpg", "image/jpeg"),
        ("a.JPEG", "image/jpeg"),
        ("a.json", "application/json"),
        ("a.txt", "text/plain"),
        ("a.pdf", "application/pdf"),
        ("plots/fig.PNG", "image/png"),
        ("noext", "application/octet-stream"),
        ("script.py", "application/octet-stream"),
        ("page.html", "application/octet-stream"),
        ("a.csv.exe", "application/octet-stream"),
        ("data.csv/raw", "application/octet-stream"),
        ("archive.tar.gz", "application/octet-stream"),
    ])
    def test_type_table(self, name, expected_type):
        assert build_files_manifest([(name, b"")])[0]["type"] == expected_type

    @pytest.mark.parametrize("name", [
        "",
        ".hidden.csv",
        "-a.csv",
        "a b.csv",
        "a.csv\n",
        "a" * 97 + ".csv",
        "/a.csv",
        "dir/",
        "dir//a.csv",
        "./a.csv",
        "../a.csv",
        "dir/../a.csv",
        "dir/.hidden",
        "dir\\a.csv",
        "a/b/c/d/e/f.csv",
        "/".join(["a" * 50] * 4 + ["b" * 52]),
    ])
    def test_rejects_invalid_names(self, name):
        with pytest.raises(InvalidOutputFileError):
            build_files_manifest([(name, b"x")])

    def test_accepts_paths_up_to_limits(self):
        five_deep = "a/b/c/d/e.csv"
        longest = "/".join(["a" * 50] * 4 + ["b" * 51])
        assert len(longest) == 255
        names = [e["name"] for e in build_files_manifest([(five_deep, b""), (longest, b"")])]
        assert names == sorted([five_deep, longest])

    def test_rejects_duplicate_names(self):
        with pytest.raises(InvalidOutputFileError):
            build_files_manifest([("a.csv", b"1"), ("a.csv", b"2")])


class TestVerifyFilesManifest:

    def test_match(self):
        assert verify_files_manifest(KAT_FILES, KAT_SHA256) is True
        assert verify_files_manifest(KAT_FILES, KAT_SHA256.upper()) is True

    def test_mismatch(self):
        tampered = [("results.csv", b"a,b\n1,3\n"), ("notes.txt", b"hello\n")]
        assert verify_files_manifest(tampered, KAT_SHA256) is False
        assert verify_files_manifest(KAT_FILES[:1], KAT_SHA256) is False

    def test_absent_attested_value(self):
        assert verify_files_manifest(KAT_FILES, None) is False


def _make_attestation(user_data: dict) -> str:
    """Build a self-signed COSE_Sign1 attestation (cert chain must be skipped)."""
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .sign(key, hashes.SHA384())
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    payload = cbor2.dumps({
        "module_id": "test-module",
        "digest": "SHA384",
        "timestamp": int(now.timestamp() * 1000),
        "pcrs": {0: b"\x00" * 48},
        "certificate": cert_der,
        "cabundle": [cert_der],
        "user_data": json.dumps(user_data).encode(),
    })
    protected = cbor2.dumps({1: -35})
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    r, s = utils.decode_dss_signature(key.sign(sig_structure, ec.ECDSA(hashes.SHA384())))
    signature = r.to_bytes(48, "big") + s.to_bytes(48, "big")
    return base64.b64encode(cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, signature]))).decode()


class TestVerifyAttestationFiles:

    def test_exposes_files_manifest_sha256(self):
        doc = _make_attestation({"output_hash": "ab", "files_manifest_sha256": KAT_SHA256})
        result = verify_attestation(doc, skip_certificate_verification=True)
        assert result.valid is True
        assert result.files_manifest_sha256 == KAT_SHA256
        assert result.to_dict()["files_manifest_sha256"] == KAT_SHA256

    def test_accepts_user_data_with_manifest_above_512_bytes(self):
        # A full execution proof with the manifest hash is about 587 bytes
        doc = _make_attestation({"padding": "x" * 560, "files_manifest_sha256": KAT_SHA256})
        result = verify_attestation(doc, skip_certificate_verification=True)
        assert result.valid is True
        assert result.files_manifest_sha256 == KAT_SHA256

    def test_rejects_user_data_above_1024_bytes(self):
        doc = _make_attestation({"padding": "x" * 1100})
        result = verify_attestation(doc, skip_certificate_verification=True)
        assert result.valid is False

    def test_absent_in_older_attestations(self):
        doc = _make_attestation({"output_hash": "ab"})
        result = verify_attestation(doc, skip_certificate_verification=True)
        assert result.valid is True
        assert result.files_manifest_sha256 is None

    def test_expected_files_match(self):
        doc = _make_attestation({"files_manifest_sha256": KAT_SHA256})
        result = verify_attestation(doc, skip_certificate_verification=True, expected_files=KAT_FILES)
        assert result.valid is True
        assert result.files_verified is True
        assert result.expected_files_manifest_sha256 == KAT_SHA256

    def test_expected_no_files_match_empty_manifest(self):
        doc = _make_attestation({"files_manifest_sha256": EMPTY_SHA256})
        result = verify_attestation(doc, skip_certificate_verification=True, expected_files=[])
        assert result.valid is True
        assert result.files_verified is True

    def test_expected_files_mismatch(self):
        doc = _make_attestation({"files_manifest_sha256": KAT_SHA256})
        result = verify_attestation(doc, skip_certificate_verification=True, expected_files=KAT_FILES[:1])
        assert result.valid is False
        assert result.files_verified is False
        assert "Files manifest hash mismatch" in result.error

    def test_expected_files_but_attestation_has_none(self):
        doc = _make_attestation({"output_hash": "ab"})
        result = verify_attestation(doc, skip_certificate_verification=True, expected_files=KAT_FILES)
        assert result.valid is False
        assert result.error == "No files_manifest_sha256 in attestation user_data"

    def test_expected_files_invalid_name(self):
        doc = _make_attestation({"files_manifest_sha256": KAT_SHA256})
        result = verify_attestation(doc, skip_certificate_verification=True, expected_files=[("../x.csv", b"")])
        assert result.valid is False
        assert result.error.startswith("Invalid output file:")


class TestCLIFiles:

    def _args(self, attestation_path, files, files_root=None):
        return argparse.Namespace(
            attestation=str(attestation_path), output=None, files=files, files_root=files_root,
            pcr0=None, pcr1=None, pcr2=None, version=None, aws_root_cert=None,
            skip_cert_verification=True, json=True,
        )

    def test_files_flag_verifies_manifest(self, tmp_path, capsys):
        attestation_path = tmp_path / "attestation.txt"
        attestation_path.write_text(_make_attestation({"files_manifest_sha256": KAT_SHA256}))
        paths = []
        for name, data in KAT_FILES:
            (tmp_path / name).write_bytes(data)
            paths.append(str(tmp_path / name))

        assert cmd_verify(self._args(attestation_path, paths)) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["files_verified"] is True
        assert out["files_manifest_sha256"] == KAT_SHA256

        (tmp_path / "notes.txt").write_bytes(b"tampered\n")
        assert cmd_verify(self._args(attestation_path, paths)) == 1

    def test_files_flag_missing_file(self, tmp_path):
        attestation_path = tmp_path / "attestation.txt"
        attestation_path.write_text(_make_attestation({"files_manifest_sha256": KAT_SHA256}))
        assert cmd_verify(self._args(attestation_path, [str(tmp_path / "missing.csv")])) == 1

    def _write_kat2(self, root):
        for name, data in KAT2_FILES:
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_bytes(data)

    def test_files_root_walks_directory(self, tmp_path, capsys):
        attestation_path = tmp_path / "attestation.txt"
        attestation_path.write_text(_make_attestation({"files_manifest_sha256": KAT2_SHA256}))
        root = tmp_path / "outputs"
        self._write_kat2(root)
        (root / "empty" / "dir").mkdir(parents=True)

        assert cmd_verify(self._args(attestation_path, None, str(root))) == 0
        assert json.loads(capsys.readouterr().out)["files_verified"] is True

    def test_files_root_names_listed_files_relative_to_root(self, tmp_path, capsys):
        attestation_path = tmp_path / "attestation.txt"
        attestation_path.write_text(_make_attestation({"files_manifest_sha256": KAT2_SHA256}))
        root = tmp_path / "outputs"
        self._write_kat2(root)
        paths = [str(root / name) for name, _ in KAT2_FILES]

        assert cmd_verify(self._args(attestation_path, paths, str(root))) == 0
        assert json.loads(capsys.readouterr().out)["files_verified"] is True
        # Without the root, plots/fig.bin is named fig.bin and the hash differs
        assert cmd_verify(self._args(attestation_path, paths)) == 1

    def test_files_root_rejects_file_outside_root(self, tmp_path):
        attestation_path = tmp_path / "attestation.txt"
        attestation_path.write_text(_make_attestation({"files_manifest_sha256": KAT2_SHA256}))
        root = tmp_path / "outputs"
        root.mkdir()
        (tmp_path / "other.csv").write_bytes(b"x")
        assert cmd_verify(self._args(attestation_path, [str(tmp_path / "other.csv")], str(root))) == 1

    def test_files_root_rejects_symlink(self, tmp_path):
        attestation_path = tmp_path / "attestation.txt"
        attestation_path.write_text(_make_attestation({"files_manifest_sha256": KAT2_SHA256}))
        root = tmp_path / "outputs"
        self._write_kat2(root)
        (root / "link.csv").symlink_to(root / "a.csv")
        assert cmd_verify(self._args(attestation_path, None, str(root))) == 1
