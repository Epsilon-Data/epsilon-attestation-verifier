"""Code digest (script_hash) rebuilt from a build/ folder.

KAT_SHA256 is shared with the coordinator's ZipService test (tests/executor/test_code_bundle.py), which builds
the archive the enclave attests.
"""
import io
import os
import zipfile
from unittest.mock import patch

import pytest

from epsilon_verifier.cli import main
from epsilon_verifier.code_digest import build_code_bundle, compute_code_digest

# build.yml, main.py and generated/data.csv below, plus excluded __pycache__/ and .DS_Store
KAT_SHA256 = "b544578c808dfdf0f988fb168dad8e30a154fe6831bc337237b821bee3a36a03"


@pytest.fixture
def build_dir(tmp_path):
    (tmp_path / "generated").mkdir()
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "build.yml").write_bytes(b"analysis:\n  script_file: main.py\n")
    (tmp_path / "main.py").write_bytes(b"print(1)\n")
    (tmp_path / "generated" / "data.csv").write_bytes(b"a,b\n1,2\n")
    (tmp_path / "__pycache__" / "main.cpython-311.pyc").write_bytes(b"x")
    (tmp_path / ".DS_Store").write_bytes(b"x")
    return tmp_path


def test_known_answer(build_dir):
    assert compute_code_digest(str(build_dir)) == KAT_SHA256


def test_modification_times_do_not_change_the_digest(build_dir):
    os.utime(build_dir / "main.py", (1, 1))
    assert compute_code_digest(str(build_dir)) == KAT_SHA256


def test_content_and_new_files_change_the_digest(build_dir):
    (build_dir / "extra.py").write_bytes(b"")
    assert compute_code_digest(str(build_dir)) != KAT_SHA256


def test_bundle_is_sorted_and_stored(build_dir):
    archive = zipfile.ZipFile(io.BytesIO(build_code_bundle(str(build_dir))))
    assert archive.namelist() == ["build.yml", "generated/data.csv", "main.py"]
    assert {i.compress_type for i in archive.infolist()} == {zipfile.ZIP_STORED}


def test_not_a_directory(tmp_path):
    with pytest.raises(ValueError):
        build_code_bundle(str(tmp_path / "missing"))


class TestCli:
    def _run(self, *argv):
        with patch("sys.argv", ["epsilon-verify", "code-digest", *argv]):
            return main()

    def test_prints_digest(self, build_dir, capsys):
        assert self._run(str(build_dir)) == 0
        assert KAT_SHA256 in capsys.readouterr().out

    def test_expect_match(self, build_dir, capsys):
        assert self._run(str(build_dir), "--expect", KAT_SHA256.upper()) == 0
        assert "Matches" in capsys.readouterr().out

    def test_expect_mismatch(self, build_dir, capsys):
        assert self._run(str(build_dir), "--expect", "00" * 32) == 1
        assert "MISMATCH" in capsys.readouterr().err
