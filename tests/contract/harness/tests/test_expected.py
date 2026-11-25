"""Tests of the contract test expected-output comparison (no ggshield involved)."""

from pathlib import Path

import pytest

from tests.contract.harness import expected


def _record_json(tmp_path: Path, stdout: str) -> Path:
    expected_dir = tmp_path / "expected"
    expected.record(
        expected_dir, expected.Outputs(exit_code=0, stdout=stdout, stderr="")
    )
    return expected_dir


def _validate(expected_dir: Path, stdout: str) -> list:
    return expected.compare(
        expected_dir, expected.Outputs(exit_code=0, stdout=stdout, stderr="")
    )


@pytest.mark.parametrize("actual", ['{"a": 1.0}', '{"a": true}'])
def test_json_values_of_different_types_do_not_match(
    tmp_path: Path, actual: str
) -> None:
    """
    GIVEN a recorded JSON output {"a": 1}
    WHEN the actual output has the same value with another type
    THEN the comparison fails (Python alone would say 1 == 1.0 == True)
    """
    expected_dir = _record_json(tmp_path, '{"a": 1}')

    assert _validate(expected_dir, actual) != []


def test_json_key_order_and_spacing_do_not_matter(tmp_path: Path) -> None:
    """
    GIVEN a recorded JSON output
    WHEN the actual output has the same data with other key order and spacing
    THEN the comparison passes
    """
    expected_dir = _record_json(tmp_path, '{"a": 1, "b": [true, null]}')

    assert _validate(expected_dir, '{"b":[true,null],"a":1}') == []


def test_non_ascii_output_round_trips(tmp_path: Path) -> None:
    """
    GIVEN text output with characters outside cp1252 (ggshield prints such symbols)
    WHEN it is recorded then validated
    THEN it matches, and the file is UTF-8 with \\n line endings on every OS
    """
    stdout = "✓ No secrets found → 0 incident\n🛡️ done\n"
    expected_dir = tmp_path / "expected"
    expected.record(
        expected_dir, expected.Outputs(exit_code=0, stdout=stdout, stderr="")
    )

    assert (expected_dir / "stdout.txt").read_bytes() == stdout.encode("utf-8")
    assert _validate(expected_dir, stdout) == []
