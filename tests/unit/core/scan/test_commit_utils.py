import pytest

from ggshield.core.scan.commit_utils import _parse_patch_header_line
from ggshield.utils.git_shell import Filemode


@pytest.mark.parametrize(
    ("line", "expected_name", "expected_mode"),
    [
        (":100644 100644 bcd1234 0123456 M\0file0\0", "file0", Filemode.MODIFY),
        (":100644 100644 abcd123 1234567 C68\0file1\0file2\0", "file2", Filemode.NEW),
        (
            ":100644 100644 abcd123 1234567 R86\0file1\0file3\0",
            "file3",
            Filemode.RENAME,
        ),
        (":000000 100644 0000000 1234567 A\0file4\0", "file4", Filemode.NEW),
        (":100644 000000 1234567 0000000 D\0file5\0", "file5", Filemode.DELETE),
        (
            ":100644 100755 abcd123 abcd123 M\0file6\0",
            "file6",
            Filemode.MODIFY,
        ),
        (
            ":::100644 100644 100644 100644 c57e98a c9d3d3d 6eb4116 127e89b MMM\0file7\0",
            "file7",
            Filemode.MODIFY,
        ),
    ],
)
def test_parse_patch_header_line(
    line: str, expected_name: str, expected_mode: Filemode
):
    """
    GIVEN a header line from a git show raw patch
    WHEN _parse_patch_header_line() is called
    THEN it returns the correct filename and mode
    """
    name, mode = _parse_patch_header_line(line)
    assert (name, mode) == (expected_name, expected_mode)
