"""Tests of written files in expected/ (no ggshield involved)."""

import os
from pathlib import Path

import pytest
import yaml

from tests.contract.harness import expected
from tests.contract.harness.expected_files import WrittenFiles
from tests.contract.harness.placeholders import Placeholders


def _outputs(files: dict) -> expected.Outputs:
    return expected.Outputs(
        exit_code=0, stdout="", stderr="", written=WrittenFiles(files=files)
    )


def test_written_files_are_compared(tmp_path: Path) -> None:
    """
    GIVEN a recorded test that wrote a text file and a binary file
    WHEN a run writes different content, an extra file, and not the binary
    THEN each problem is reported, the text one with a diff
    """
    expected_dir = tmp_path / "expected"
    expected.record(
        expected_dir,
        _outputs(
            {"config/auth_config.yaml": "lifetime: 30\n", "data/blob.bin": b"\x00\x01"}
        ),
    )
    assert (
        expected.compare(
            expected_dir,
            _outputs(
                {
                    "config/auth_config.yaml": "lifetime: 30\n",
                    "data/blob.bin": b"\x00\x01",
                }
            ),
        )
        == []
    )

    failures = expected.compare(
        expected_dir,
        _outputs({"config/auth_config.yaml": "lifetime: 60\n", "work/extra.txt": "x"}),
    )

    assert failures[0] == "file data/blob.bin: expected to be written, but was not"
    assert failures[1].startswith("file work/extra.txt: written, but not expected")
    # A .yaml file: compared as data, so the diff shows the canonical form
    assert failures[2].startswith("file config/auth_config.yaml (compared as data)")
    assert '-  "lifetime": 30' in failures[2] and '+  "lifetime": 60' in failures[2]


def test_binary_recording_against_text_is_reported(tmp_path: Path) -> None:
    """
    GIVEN a test that recorded a binary file
    WHEN a run writes text to the same file
    THEN a failure is reported (not a decoding crash), showing the text
    """
    expected_dir = tmp_path / "expected"
    expected.record(expected_dir, _outputs({"data/blob.bin": b"\xff\xfe"}))

    failures = expected.compare(expected_dir, _outputs({"data/blob.bin": "hello"}))

    assert failures == [
        "file data/blob.bin: expected binary content, got text:\n    hello\n"
    ]


posix_only = pytest.mark.skipif(os.name == "nt", reason="no POSIX file modes")


@posix_only
def test_file_modes_are_compared(tmp_path: Path) -> None:
    """
    GIVEN a test that recorded an owner-only file (0600)
    WHEN a run writes the same content readable by everyone (0644)
    THEN the mode difference is reported
    """
    expected_dir = tmp_path / "expected"
    recorded = _outputs({"config/auth_config.yaml": "x: 1\n"})
    recorded.written.permissions = {"config/auth_config.yaml": "0600"}
    expected.record(expected_dir, recorded)

    run = _outputs({"config/auth_config.yaml": "x: 1\n"})
    run.written.permissions = {"config/auth_config.yaml": "0644"}

    assert expected.compare(expected_dir, run) == [
        "file config/auth_config.yaml: mode expected 0600, got 0644"
    ]


@posix_only
def test_written_file_without_recorded_mode_is_reported(tmp_path: Path) -> None:
    """
    GIVEN a recording made before modes were recorded
    WHEN a run writes that file
    THEN the missing mode is reported, so the recording gets refreshed
    """
    expected_dir = tmp_path / "expected"
    expected.record(expected_dir, _outputs({"home/.gitguardian.yaml": "version: 2\n"}))

    run = _outputs({"home/.gitguardian.yaml": "version: 2\n"})
    run.written.permissions = {"home/.gitguardian.yaml": "0644"}

    assert expected.compare(expected_dir, run) == [
        "file home/.gitguardian.yaml: no mode recorded in expected.yaml,"
        " re-record with --record"
    ]


def test_os_junk_in_recorded_files_is_ignored(tmp_path: Path) -> None:
    """
    GIVEN a recorded files/ folder where the OS dropped a .DS_Store
    WHEN the run writes the recorded file
    THEN validation passes: the .DS_Store is not an expected file
    """
    expected_dir = tmp_path / "expected"
    expected.record(expected_dir, _outputs({"work/out.txt": "ok\n"}))
    (expected_dir / "files" / "work" / ".DS_Store").write_bytes(b"\x00\x00\x00\x01Bud1")

    assert expected.compare(expected_dir, _outputs({"work/out.txt": "ok\n"})) == []


def test_re_recording_removes_stale_files(tmp_path: Path) -> None:
    """
    GIVEN a recording with two written files and a deleted file
    WHEN the test is recorded again and the run only writes one file
    THEN the other file and the deleted_files entry are gone from expected/
    """
    expected_dir = tmp_path / "expected"
    first = _outputs({"work/a.txt": "a\n", "work/b.txt": "b\n"})
    first.written.deleted = ["config/old.yaml"]
    expected.record(expected_dir, first)

    expected.record(expected_dir, _outputs({"work/a.txt": "a\n"}))

    files = sorted(
        p.relative_to(expected_dir).as_posix()
        for p in (expected_dir / "files").rglob("*")
        if p.is_file()
    )
    assert files == ["files/work/a.txt"]
    assert "deleted_files" not in (expected_dir / "expected.yaml").read_text()


def test_written_text_is_normalized(tmp_path: Path) -> None:
    """
    GIVEN a written text file with Windows line endings and a sandbox path
    THEN it is stored with \\n line endings and the placeholder
    """
    work = tmp_path / "work"
    collapse = Placeholders({"work": str(work)}).collapse
    data = f"path: {work}/a.py\r\nok: true\r\n".encode()

    written = WrittenFiles.from_changes({"work/a.yaml": (data, 0o644)}, [], collapse)

    assert written.files == {"work/a.yaml": "path: {{work}}/a.py\nok: true\n"}


def test_deleted_files_mismatch_is_reported(tmp_path: Path) -> None:
    """
    GIVEN a recording where the command deleted a file
    WHEN a run deletes nothing
    THEN the difference is reported
    """
    expected_dir = tmp_path / "expected"
    recorded = _outputs({})
    recorded.written.deleted = ["config/auth_config.yaml"]
    expected.record(expected_dir, recorded)

    assert expected.compare(expected_dir, _outputs({})) == [
        "deleted files: expected ['config/auth_config.yaml'], got []"
    ]


def test_recording_sets_a_compare_mode_per_file(tmp_path: Path) -> None:
    """
    GIVEN written YAML, JSON and text files
    WHEN recorded
    THEN YAML and JSON are compared as data, others in full
    """
    expected_dir = tmp_path / "expected"
    expected.record(
        expected_dir,
        _outputs({"config/a.yaml": "x: 1\n", "work/b.json": "{}", "work/c.txt": "c\n"}),
    )

    spec = yaml.safe_load((expected_dir / "expected.yaml").read_text())
    assert spec["files"] == {
        "config/a.yaml": "data",
        "work/b.json": "data",
        "work/c.txt": "full",
    }


def test_data_mode_ignores_formatting_but_not_values(tmp_path: Path) -> None:
    """
    GIVEN a recorded YAML file holding a placeholder
    WHEN a run writes the same data with other key order, quoting and indentation
    THEN it passes; a different value or type fails
    """
    expected_dir = tmp_path / "expected"
    recorded = (
        "instances:\n- url: https://a.example.com\n  lifetime: 30\npath: {{work}}/x\n"
    )
    expected.record(expected_dir, _outputs({"config/auth_config.yaml": recorded}))

    reformatted = "path: '{{work}}/x'\ninstances:\n  - lifetime: 30\n    url: https://a.example.com\n"
    assert (
        expected.compare(
            expected_dir, _outputs({"config/auth_config.yaml": reformatted})
        )
        == []
    )

    as_float = reformatted.replace("lifetime: 30", "lifetime: 30.0")
    assert (
        expected.compare(expected_dir, _outputs({"config/auth_config.yaml": as_float}))
        != []
    )


def test_hand_written_file_mode_is_kept_on_re_record(tmp_path: Path) -> None:
    """
    GIVEN a recording where someone set a YAML file to `full` by hand
    WHEN the test is recorded again
    THEN that file stays `full`, and is then compared byte for byte
    """
    expected_dir = tmp_path / "expected"
    files = {"home/.gitguardian.yaml": "version: 2\n"}
    expected.record(expected_dir, _outputs(files))
    spec_path = expected_dir / "expected.yaml"
    spec_path.write_text(spec_path.read_text().replace(": data", ": full"))

    expected.record(expected_dir, _outputs(files))

    assert "home/.gitguardian.yaml: full" in spec_path.read_text()
    assert (
        expected.compare(
            expected_dir, _outputs({"home/.gitguardian.yaml": "version:   2\n"})
        )
        != []
    )
