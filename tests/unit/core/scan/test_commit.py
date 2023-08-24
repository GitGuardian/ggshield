from typing import List, Tuple

import pytest
from pygitguardian.config import DOCUMENT_SIZE_THRESHOLD_BYTES

from ggshield.core.filter import init_exclusion_regexes
from ggshield.core.scan import Commit
from ggshield.core.scan.commit import _parse_patch_header_line
from ggshield.utils.git_shell import Filemode
from tests.unit.conftest import DATA_PATH


PATCHES_DIR = DATA_PATH / "patches"
PATCH_SEPARATION = (
    """commit 3e0d3805080b044ab221fa8b8998e3039be0a5ca6
Author: Testificate Jose <test@test.test>
Date:   Fri Oct 18 13:20:00 2012 +0100
"""
    + ":100644 000000 1233aef 0000000 D\0ggshield/tests/cassettes/test_files_yes.yaml\0"
    + ":000000 100644 0000000 19465ef A\0tests/test_scannable.py\0"
    + ":100644 100755 b4d3aef b4d3aef M\0bin/shutdown.sh\0"
    + ":000000 100644 0000000 12356ef A\0.env\0"
    + ":100644 100644 ac204ec ac204ec R100\0ggshield/tests/test_config.py\0tests/test_config.py\0"
    + ":100644 100644 6546aef b41653f M\0data/utils/email_sender.py\0"
    + """\0diff --git a/ggshield/tests/cassettes/test_files_yes.yaml b/ggshield/tests/cassettes/test_files_yes.yaml
deleted file mode 100644
index 0000000..0000000
--- a/ggshield/tests/cassettes/test_files_yes.yaml
+++ /dev/null
@@ -1,45 +0,0 @@
-interactions:

diff --git a/tests/test_scannable.py b/tests/test_scannable.py
new file mode 100644
index 0000000..0000000
--- /dev/null
+++ b/tests/test_scannable.py
@@ -0,0 +1,112 @@
+from collections import namedtuple

diff --git a/bin/shutdown.sh b/bin/shutdown.sh
old mode 100644
new mode 100755

diff --git a/.env b/.env
new file mode 100644
index 0000000..0000000
--- /dev/null
+++ b/.env
@@ -0,0 +1,112 @@
CHECK_ENVIRONMENT=true

diff --git a/ggshield/tests/test_config.py b/tests/test_config.py
similarity index 100%
rename from ggshield/tests/test_config.py
rename to tests/test_config.py

diff --git a/data/utils/email_sender.py b/data/utils/email_sender.py
index 56dc0d42..fdf48995 100644
--- a/data/utils/email_sender.py
+++ b/data/utils/email_sender.py
@@ -49,6 +49,7 @@ def send_email(config, subject, content, tos, seperate):
    def send_email(subject, content, to, seperate=True):
+   logger.bind(operation_name="send_email")
@@ -73,22 +74,11 @@ def send_email(subject, content, to, seperate=True):
-   removed
+   added
"""
)  # noqa
EXPECTED_PATCH_CONTENT = (
    (
        "ggshield/tests/cassettes/test_files_yes.yaml",
        """@@ -1,45 +0,0 @@
-interactions:

""",
    ),
    (
        "tests/test_scannable.py",
        """@@ -0,0 +1,112 @@
+from collections import namedtuple

""",
    ),
    (
        ".env",
        """@@ -0,0 +1,112 @@
CHECK_ENVIRONMENT=true

""",
    ),
    (
        "data/utils/email_sender.py",
        """@@ -49,6 +49,7 @@ def send_email(config, subject, content, tos, seperate):
    def send_email(subject, content, to, seperate=True):
+   logger.bind(operation_name="send_email")
@@ -73,22 +74,11 @@ def send_email(subject, content, to, seperate=True):
-   removed
+   added
""",
    ),
)


def test_patch_separation():
    c = Commit()
    c._patch = PATCH_SEPARATION
    files = list(c.get_files())

    assert c.info.author == "Testificate Jose"
    assert c.info.email == "test@test.test"
    assert c.info.date == "Fri Oct 18 13:20:00 2012 +0100"

    assert len(files) == len(EXPECTED_PATCH_CONTENT)
    for file_, (name, content) in zip(files, EXPECTED_PATCH_CONTENT):
        assert file_.filename == name
        assert file_.content == content


def test_patch_separation_ignore():
    c = Commit()
    c._patch = PATCH_SEPARATION
    file_to_ignore = ".env"
    c.exclusion_regexes = init_exclusion_regexes([file_to_ignore])
    files = list(c.get_files())

    assert len(files) == 3
    assert not (any(entry.filename == file_to_ignore for entry in files))


def test_patch_max_size():
    c = Commit()
    c._patch = """
diff --git a/.env b/.env
new file mode 100644
index 0000000..0000000
--- /dev/null
+++ b/.env
@@ -0,0 +1,112 @@
CHECK_ENVIRONMENT=true
    """
    c._patch += "a" * DOCUMENT_SIZE_THRESHOLD_BYTES
    files = list(c.get_files())

    assert len(files) == 0


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
    """
    GIVEN a Commit created from a patch from data/patches
    WHEN Commit.get_files() is called
    THEN it returns files with correct names and modes
    """
    patch_path = PATCHES_DIR / patch_name

    commit = Commit()
    commit._patch = patch_path.read_text()
    files = list(commit.get_files())

    names_and_modes = [(x.filename, x.filemode) for x in files]
    assert names_and_modes == expected_names_and_modes
