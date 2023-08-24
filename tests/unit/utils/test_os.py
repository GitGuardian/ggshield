import sys
from typing import AnyStr, Tuple

import pytest

from ggshield.utils.os import parse_os_release


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
