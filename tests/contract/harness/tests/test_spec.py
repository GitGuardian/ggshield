"""Tests of test.yaml validation (no ggshield involved)."""

from pathlib import Path

import pytest
import yaml

from tests.contract.harness import spec


def test_valid_spec_has_no_error() -> None:
    data = {
        "command": ["quota", "--json"],
        "setup": [["git", "init"], ["git", "commit", "--allow-empty", "-m", "x"]],
        "env": {"GITGUARDIAN_TIMEOUT": "5", "GITGUARDIAN_INSTANCE": None},
        "stdin": "{}",
    }

    assert spec.validate(data) == []


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (
            {"command": ["quota"], "env": {"GITGUARDIAN_TIMEOUT": 5}},
            "env value for GITGUARDIAN_TIMEOUT must be a string or null, got int 5:"
            " quote it as written in test.yaml",
        ),
        (
            {"command": ["quota"], "env": {"FLAG": True}},
            "env value for FLAG must be a string or null, got bool True:"
            " quote it as written in test.yaml",
        ),
        (
            {"command": ["quota", "--limit", 5]},
            "command argument 2 must be a string, got int 5:"
            " quote it as written in test.yaml",
        ),
        ({"command": ["quota"], "stdin": 12}, "stdin must be a string, got int 12"),
        ({"command": []}, "`command` must be a non-empty list"),
        ({"command": ["quota"], "unknown": 1}, "unknown keys ['unknown']"),
        ({"command": ["quota"], "setup": "git init"}, "`setup` must be a list"),
        ({"command": ["quota"], "setup": [[]]}, "setup step 0 must be a non-empty"),
        (
            {"command": ["quota"], "setup": [["sh", "-c", "git init"]]},
            "setup step 0 must run one of ['git'], got 'sh'",
        ),
        (
            {"command": ["quota"], "setup": [["git", "commit", "-m", 1]]},
            "setup step 0 argument 3 must be a string, got int 1",
        ),
    ],
)
def test_invalid_spec_is_reported(data: dict, message: str) -> None:
    errors = spec.validate(data)

    assert len(errors) == 1
    assert errors[0].startswith(message)


def test_invalid_file_is_reported_with_its_path(tmp_path: Path) -> None:
    """
    GIVEN a test.yaml with an unquoted number in the command
    WHEN it is loaded
    THEN loading fails, and the message starts with the file's path
    """
    path = tmp_path / "test.yaml"
    path.write_text("command: [quota, --limit, 5]\n")

    with pytest.raises(spec.SpecError) as error:
        spec.load(path)

    assert str(error.value).startswith(f"{path}: command argument 2 must be a string")


def test_yaml_octal_is_refused_without_a_wrong_hint() -> None:
    """
    GIVEN a command argument written 0600 without quotes
    WHEN test.yaml is validated
    THEN it is refused (YAML read it as 384), and no "384" is suggested
    """
    data = yaml.safe_load("command: [quota, 0600]")

    assert spec.validate(data) == [
        "command argument 1 must be a string, got int 384:"
        " quote it as written in test.yaml"
    ]
