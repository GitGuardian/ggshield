import os
import sys
from typing import AnyStr, Tuple

import pytest

from ggshield.utils.os import (
    cd,
    getenv_bool,
    getenv_float,
    getenv_int,
    parse_os_release,
)


@pytest.mark.skipif(
    sys.platform.lower() != "linux", reason="This test is only relevant on Linux."
)
@pytest.mark.parametrize(
    "file_contents, file_permissions, expected_tuple",
    [
        ('ID="ubuntu"\nVERSION_ID=""22.04""', 777, ("ubuntu", "22.04")),
        ('ID="arch"', 777, ("arch", "unknown")),
        ("", 777, ("linux", "unknown")),
        ('ID="ubuntu"\nVERSION_ID="22.04"\n', 640, ("linux", "unknown")),
    ],
)
def test_parse_os_release(
    tmp_path,
    file_contents: AnyStr,
    file_permissions: int,
    expected_tuple: Tuple[str, str],
):
    file = tmp_path / "os-release"

    file.write_text(file_contents)
    file.chmod(file_permissions)
    assert parse_os_release(file) == expected_tuple


@pytest.mark.parametrize(
    ("env_value", "default", "expected"),
    (
        ("12", 5, 12),
        ("12", None, 12),
        (None, 5, 5),
        (None, None, None),
    ),
)
def test_getenv_int(monkeypatch, env_value, default, expected):
    key = "TEST_GETENV_VAR"
    if env_value:
        monkeypatch.setenv(key, env_value)
    else:
        monkeypatch.delenv(key, raising=False)
    assert getenv_int(key, default) == expected


@pytest.mark.parametrize(
    ("env_value", "default", "expected"),
    (
        ("12.5", 5.3, 12.5),
        ("12.5", None, 12.5),
        (None, 5.5, 5.5),
        (None, None, None),
    ),
)
def test_getenv_float(monkeypatch, env_value, default, expected):
    key = "TEST_GETENV_VAR"
    if env_value:
        monkeypatch.setenv(key, env_value)
    else:
        monkeypatch.delenv(key, raising=False)
    assert getenv_float(key, default) == expected


@pytest.mark.parametrize(
    ("env_value", "default", "expected"),
    (
        ("true", False, True),
        ("Whatever", False, True),
        ("1", False, True),
        (None, True, True),
        (None, False, False),
        ("0", True, False),
        ("false", True, False),
        ("FaLsE", True, False),
        (None, None, None),
    ),
)
def test_getenv_bool(monkeypatch, env_value, default, expected):
    key = "TEST_GETENV_VAR"
    if env_value:
        monkeypatch.setenv(key, env_value)
    else:
        monkeypatch.delenv(key, raising=False)
    assert getenv_bool(key, default) == expected


def test_cd_context_manager(tmpdir):
    prev = os.getcwd()
    assert prev != tmpdir
    with cd(tmpdir):
        assert os.getcwd() == tmpdir
    assert os.getcwd() == prev
