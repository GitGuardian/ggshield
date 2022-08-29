from typing import List, Tuple

import pytest

from ggshield.core.utils import Filemode
from ggshield.scan import Commit
from ggshield.scan.scannable import _parse_patch_header_line
from tests.conftest import DATA_PATH


PATCHES_DIR = DATA_PATH / "patches"


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
    name, mode = _parse_patch_header_line(line)
    assert (name, mode) == (expected_name, expected_mode)


@pytest.mark.parametrize(
    ("patch_name", "expected_names_and_modes"),
    [
        ("add.patch", [("README.md", Filemode.NEW)]),
        ("pre-commit.patch", [("NEW.md", Filemode.NEW)]),
        (
            "add_two_files.patch",
            [
                ("one", Filemode.NEW),
                ("two", Filemode.NEW),
            ],
        ),
        (
            "add_unusual.patch",
            [
                ("I'm unusual!", Filemode.NEW),
            ],
        ),
        (
            "chmod.patch",
            [],  # a permission change with no content change yields no content
        ),
        (
            "chmod_rename_modify.patch",
            [
                ("newscript", Filemode.RENAME),
            ],
        ),
        (
            "modify.patch",
            [
                ("README.md", Filemode.MODIFY),
            ],
        ),
        (
            "remove.patch",
            [
                ("foo_file", Filemode.DELETE),
            ],
        ),
        (
            "rename.patch",
            [],  # a rename with no content change yields no content
        ),
        (
            "merge.patch",
            [
                ("longfile", Filemode.MODIFY),
                ("longfile", Filemode.MODIFY),
                ("longfile", Filemode.MODIFY),
            ],
        ),
        (
            "merge-with-changes.patch",
            [
                ("conflicted", Filemode.MODIFY),
                ("conflicted", Filemode.MODIFY),
            ],
        ),
        (
            "type-change.patch",
            [
                ("README2.md", Filemode.NEW),
            ],
        ),
    ],
)
def test_get_files(
    patch_name: str, expected_names_and_modes: List[Tuple[str, Filemode]]
):
    patch_path = PATCHES_DIR / patch_name

    commit = Commit()
    commit._patch = patch_path.read_text()
    files = list(commit.get_files())

    names_and_modes = [(x.filename, x.filemode) for x in files]
    assert names_and_modes == expected_names_and_modes
