import tempfile
from pathlib import Path
from typing import Optional, Tuple

import pytest

from ggshield.core.scan.commit_utils import (
    PatchFileInfo,
    convert_multi_parent_diff,
    get_file_sha_in_ref,
)
from ggshield.utils.git_shell import Filemode
from tests.repository import Repository


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (":100644 100644 bcd1234 0123456 M\0file0\0", (None, "file0", Filemode.MODIFY)),
        (
            ":100644 100644 abcd123 1234567 C68\0file1\0file2\0",
            ("file1", "file2", Filemode.NEW),
        ),
        (
            ":100644 100644 abcd123 1234567 R86\0file1\0file3\0",
            ("file1", "file3", Filemode.RENAME),
        ),
        (":000000 100644 0000000 1234567 A\0file4\0", (None, "file4", Filemode.NEW)),
        (":100644 000000 1234567 0000000 D\0file5\0", (None, "file5", Filemode.DELETE)),
        (
            ":100644 100755 abcd123 abcd123 M\0file6\0",
            (None, "file6", Filemode.MODIFY),
        ),
        (
            ":::100644 100644 100644 100644 c57e98a c9d3d3d 6eb4116 127e89b MMM\0file7\0",
            (None, "file7", Filemode.MODIFY),
        ),
    ],
)
def test_patch_file_info_from_string(
    line: str, expected: Tuple[Optional[str], str, Filemode]
):
    """
    GIVEN a header line from a git show raw patch
    WHEN _parse_patch_header_line() is called
    THEN it returns the correct filename and mode
    """
    old_path_str, new_path_str, mode = expected
    expected_info = PatchFileInfo(
        old_path=Path(old_path_str) if old_path_str else None,
        path=Path(new_path_str),
        mode=mode,
    )
    assert PatchFileInfo.from_string(line) == expected_info


@pytest.mark.parametrize(
    ("diff", "expected"),
    [
        (
            """
@@@ -1,1 -1,1 +1,2 @@@
- baz
 -bar
++hello
++world
""",
            """
@@ -1,1 +1,2 @@
-baz
+hello
+world
""",
        ),
        (
            """
@@@ -1,8 -1,7 +1,8 @@@
  Some longer content.

--With more text.
++
++% This is the result of the merge.
 +# This text comes from the main branch.
- # It spawns...
- # 3 lines.
+ > This is some text from the commit branch.
 -> It spawns 2 lines.

  To get interesting indices.
""",
            """
@@ -1,8 +1,8 @@
 Some longer content.
 
-With more text.
+
+% This is the result of the merge.
 # This text comes from the main branch.
-# It spawns...
-# 3 lines.
+> This is some text from the commit branch.
 
 To get interesting indices.
""",  # noqa:W293
        ),
        (
            """
@@@ -1,1 -1,1 +1,2 @@@ I'm on the hunk header
- baz
 -bar
++hello
++world
""",
            """
@@ -1,1 +1,2 @@ I'm on the hunk header
-baz
+hello
+world
""",
        ),
    ],
)
def test_convert_multi_parent_diff(diff: str, expected: str):
    """
    GIVEN a multi parent diff
    WHEN convert_multi_parent_diff() is called on it
    THEN it returns the expected result
    """
    diff = diff.strip()
    expected = expected.strip()
    result = convert_multi_parent_diff(diff)
    assert result == expected


def test_get_file_sha_in_ref():
    """
    Assert that get_file_sha_in_ref doesn't crash when called
    with a large number of files
    """
    with tempfile.TemporaryDirectory() as tmp_path_str:

        tmp_path = Path(tmp_path_str)
        repo = Repository.create(tmp_path)

        for i in range(200):
            file_path = tmp_path / f"{i:0200d}.txt"
            file_path.write_text("dummy content")

        repo.add(".")
        repo.create_commit("Add 200 dummy files")

        try:
            files = [f"{i:0200d}.txt" for i in range(200)]
            result = list(get_file_sha_in_ref("HEAD", files))

            assert isinstance(result, list), "The result should be a list."

        except Exception as e:
            assert False, f"get_file_sha_in_ref crashed with error: {e}"
