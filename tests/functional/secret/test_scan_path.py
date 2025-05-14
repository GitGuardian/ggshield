import json
import shutil
import sys
from pathlib import Path

import jsonschema
import pytest

from tests.conftest import (
    GG_VALID_TOKEN,
    GG_VALID_TOKEN_IGNORE_SHA,
    KNOWN_SECRET,
    UNKNOWN_SECRET,
)
from tests.functional.utils import (
    recreate_censored_content,
    recreate_censored_string,
    run_ggshield_scan,
)


@pytest.mark.parametrize("path", ("config.py", ".git/config"))
@pytest.mark.parametrize("show_secrets", (True, False))
def test_scan_path(tmp_path: Path, path: str, show_secrets: bool) -> None:
    # GIVEN a secret
    test_file = tmp_path / path
    test_file.parent.mkdir(exist_ok=True, parents=True)
    test_file.write_text(f"SECRET='{GG_VALID_TOKEN}'")

    # WHEN ggshield scans it
    args = ["path", str(test_file)]
    if show_secrets:
        args.append("--show-secrets")
    result = run_ggshield_scan(*args, cwd=tmp_path, expected_code=1)

    # THEN the output contains the context and the expected ignore sha
    assert "SECRET=" in result.stdout
    assert GG_VALID_TOKEN_IGNORE_SHA in result.stdout
    # AND the secrets are shown only with --show-secrets
    if show_secrets:
        assert GG_VALID_TOKEN in result.stdout
    else:
        assert recreate_censored_string(GG_VALID_TOKEN) in result.stdout


def test_scan_path_does_not_fail_on_long_paths(tmp_path: Path) -> None:
    # GIVEN a secret stored in a file whose path is longer than 256 characters
    secret_content = f"SECRET='{GG_VALID_TOKEN}'"

    # Create the file in a subdir because filenames cannot be longer than 255
    # characters. What we care here is the length of the path.
    test_file = tmp_path / ("d" * 255) / ("f" * 255)
    test_file.parent.mkdir()
    test_file.write_text(secret_content)

    # WHEN ggshield scans it
    result = run_ggshield_scan("path", str(test_file), cwd=tmp_path, expected_code=1)

    # THEN it finds the secret in it
    assert recreate_censored_content(secret_content, GG_VALID_TOKEN) in result.stdout


@pytest.mark.parametrize("show_secrets", (True, False))
def test_scan_path_json_output(
    tmp_path: Path, secret_json_schema, show_secrets: bool
) -> None:
    # GIVEN a secret
    test_file = tmp_path / "config.py"
    test_file.write_text(f"SECRET='{GG_VALID_TOKEN}'")

    # WHEN ggshield scans it with --json
    args = ["path", "--json", str(test_file)]
    if show_secrets:
        args.append("--show-secrets")
    result = run_ggshield_scan(*args, cwd=tmp_path, expected_code=1)
    # THEN the output is a valid JSON
    parsed_result = json.loads(result.stdout)
    # AND there is one incident with one occurrence
    assert parsed_result["total_incidents"] == 1
    assert parsed_result["total_occurrences"] == 1
    incident = parsed_result["entities_with_incidents"][0]["incidents"][0]
    # AND it has the expected ignore_sha
    assert incident["ignore_sha"] == GG_VALID_TOKEN_IGNORE_SHA
    # AND the secrets are shown only if --show-secrets has been set
    if show_secrets:
        assert incident["occurrences"][0]["match"] == GG_VALID_TOKEN
    else:
        assert incident["occurrences"][0]["match"] == recreate_censored_string(
            GG_VALID_TOKEN
        )
    # AND the schema is valid
    jsonschema.validate(parsed_result, secret_json_schema)


def test_scan_path_ignore_known_secrets(tmp_path: Path) -> None:
    if not KNOWN_SECRET:
        pytest.fail(
            "You must define $TEST_KNOWN_SECRET to run this test,"
            " see .env.example for details"
        )

    # GIVEN a document containing 2 secrets, one known and one unknown
    test_file = tmp_path / "config.py"
    test_file.write_text(
        f"""
KNOWN_SECRET='{KNOWN_SECRET}'

# Extra lines to ensure the line containing the known secret is not included when
# ggshield shows the lines around the unknown secret.

UNKNOWN_SECRET='{UNKNOWN_SECRET}'
"""
    )

    # WHEN ggshield scans it with --ignore-known-secrets
    result = run_ggshield_scan(
        "path",
        str(test_file),
        "--ignore-known-secrets",
        "--show-secrets",
        cwd=tmp_path,
        expected_code=1,
    )

    # THEN only the unknown secret is reported
    assert f"KNOWN_SECRET='{KNOWN_SECRET}'" not in result.stdout
    assert f"UNKNOWN_SECRET='{UNKNOWN_SECRET}'" in result.stdout


def create_fake_path(tmp_path: Path) -> Path:
    # Create a bin dir
    bin_path = (tmp_path / "bin").absolute()
    bin_path.mkdir()

    # Copy the binary of our interpreter to it
    shutil.copy2(sys.executable, bin_path)

    return bin_path


def test_scan_path_works_if_git_not_found(monkeypatch, tmp_path: Path) -> None:
    # GIVEN a test file with no secret
    test_file = tmp_path / "hello"
    test_file.write_text("harmless")

    # AND a fake PATH containing only Python
    fake_path = create_fake_path(tmp_path)
    monkeypatch.setenv("PATH", str(fake_path))

    # the name of the interpreter might be python3, not just python
    python_filename = Path(sys.executable).name
    assert shutil.which(python_filename) is not None

    # AND git cannot be found
    assert shutil.which("git") is None

    # WHEN ggshield scans the test file
    # THEN it does not fail
    run_ggshield_scan("path", "--debug", str(test_file), cwd=tmp_path, expected_code=0)
