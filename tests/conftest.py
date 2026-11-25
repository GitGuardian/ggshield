import json
import os
import platform
from pathlib import Path
from typing import Any, Dict

import pytest


# The directory holding ggshield repository checkout
ROOT_DIR = Path(__file__).parent.parent

JSON_SCHEMAS_DIR = ROOT_DIR / "doc/schemas"

# This is a test token, it is always reported as a valid secret
# Use your own value if needed
GG_VALID_TOKEN = os.getenv("TEST_GG_VALID_TOKEN", "ggtt-v-12345azert")  # ggignore
GG_VALID_TOKEN_IGNORE_SHA = os.getenv(
    "TEST_GG_VALID_TOKEN_IGNORE_SHA",
    "56c126cef75e3d17c3de32dac60bab688ecc384a054c2c85b688c1dd7ac4eefd",
)

# This secret must be a secret known by the dashboard running functional tests
KNOWN_SECRET = os.environ.get("TEST_KNOWN_SECRET", "")


def pytest_addoption(parser: pytest.Parser) -> None:
    # Contract test options (tests/contract/). Declared here rather than in
    # tests/contract/conftest.py: pytest only accepts options from conftests loaded
    # at startup, and that one is not when running `pytest` from the repo root.
    group = parser.getgroup("contract", "ggshield contract tests")
    group.addoption(
        "--impl",
        choices=["python", "rust"],
        default=None,
        help="Implementation to run contract tests against. Contract tests are"
        " skipped when not set.",
    )
    group.addoption(
        "--record",
        action="store_true",
        help="Save the output of contract tests as their expected output instead of"
        " comparing with it. Replays the recorded API calls, never calls the real API.",
    )
    group.addoption(
        "--record-api",
        action="store_true",
        help="Record the API calls of contract tests against the real GitGuardian API, then"
        " save the expected output. Needs GITGUARDIAN_API_KEY.",
    )
    group.addoption(
        "--rust-bin",
        default=str(ROOT_DIR / "rust/target/release/ggshield"),
        help="Rust dispatcher binary used by --impl=rust.",
    )


def pytest_configure(config: pytest.Config) -> None:
    if config.getoption("--record-api"):
        config.option.record = True
    if config.getoption("--record") and is_windows():
        raise pytest.UsageError(
            "Record contract tests on Linux or macOS: recordings must be identical"
            " across OSes (Windows prints other paths and has no POSIX file modes)."
        )
    # Contract tests are skipped without --impl; asking to record and silently
    # recording nothing would be a trap.
    if config.getoption("--record") and config.getoption("--impl") is None:
        raise pytest.UsageError(
            "--record and --record-api need --impl=python or --impl=rust"
        )
    # `--lf` after a run with no failure selects every test, so `--lf --record`
    # would re-record the whole suite. Make it select nothing instead.
    # (`lf` is absent when the cache plugin is disabled with -p no:cacheprovider.)
    if config.getoption("--record") and config.getoption("lf", default=False):
        config.option.last_failed_no_failures = "none"


def is_windows():
    return platform.system() == "Windows"


skipwindows = pytest.mark.skipif(
    is_windows() and not os.environ.get("DISABLE_SKIPWINDOWS"),
    reason="Skipped on Windows for now, define DISABLE_SKIPWINDOWS environment variable to unskip",
)


@pytest.fixture(autouse=True)
def do_not_use_real_user_dirs(monkeypatch, tmp_path):
    """
    This fixture ensures we do not use real user directories.
    Overridden directories are:
    - the auth configuration directory, where `ggshield auth` stores credentials.
    - the cache directory
    - the home directory
    """
    monkeypatch.setenv("GG_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setenv("GG_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("GG_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("GG_USER_HOME_DIR", str(tmp_path / "home"))
    # Machine-wide dirs too: otherwise load_effective() and the plugin
    # downloader's read paths would reach the real system locations.
    monkeypatch.setenv("GG_SYSTEM_CONFIG_DIR", str(tmp_path / "system-config"))
    monkeypatch.setenv("GG_SYSTEM_DATA_DIR", str(tmp_path / "system-data"))


@pytest.fixture(autouse=True)
def do_not_use_colors(monkeypatch):
    """
    This fixture ensures we do not print colors for easier testing.
    """
    monkeypatch.setenv("NO_COLOR", "1")


def clean_directory(path: Path):
    for filepath in path.iterdir():
        if filepath.is_file():
            os.remove(filepath)


@pytest.fixture(scope="session")
def secret_json_schema() -> Dict[str, Any]:
    """Load the JSON schema for all `secret scan` commands,"""
    return _load_json_schema("secret.json")


@pytest.fixture(scope="session")
def quota_json_schema() -> Dict[str, Any]:
    """Load the JSON schema for `quota` command."""
    return _load_json_schema("quota.json")


@pytest.fixture(scope="session")
def api_status_json_schema() -> Dict[str, Any]:
    """Load the JSON schema for `api-status` command."""
    return _load_json_schema("api-status.json")


@pytest.fixture(scope="session")
def config_list_json_schema() -> Dict[str, Any]:
    """Load the JSON schema for `config list` command."""
    return _load_json_schema("config_list.json")


def _load_json_schema(name: str) -> Dict[str, Any]:
    """Load a JSON schema and patch it to reject additional properties. We patch it this
    way to ensure all fields of ggshield JSON output are documented in the JSON schema.
    """
    with (JSON_SCHEMAS_DIR / name).open() as fp:
        dct = json.load(fp)
    _reject_additional_properties(dct)
    return dct


def _reject_additional_properties(dct: Dict[str, Any]):
    """Helper for JSON Schema fixtures: adds `"additionalProperties": false` to all
    objects of the JSON schema, ensuring we do not add fields without updating the
    schema.
    """
    try:
        type_ = dct["type"]
    except KeyError:
        return
    if type_ == "object":
        dct["additionalProperties"] = False
        for child in dct["properties"].values():
            _reject_additional_properties(child)
    elif type_ == "array":
        _reject_additional_properties(dct["items"])
