import pytest

from ggshield.core.utils import Filemode
from ggshield.scan import Commit


NEW_FILE = """
a/test.txt b/test.txt
new file mode 100644
"""

DELETED_FILE = """
a/test.txt b/test.txt
deleted file mode 100644
"""

MODIFIED_FILE = """
a/test.txt b/test.txt
index e965047..802992c 100644
"""

MODIFIED_FILE_WITH_SPACES = """
a/some spaces.txt b/some spaces.txt
index e965047..802992c 100644
"""

RENAMED_FILE = """
a/old.txt b/new.txt
similarity index 71%
rename from old.txt
rename to new.txt
"""

PERMISSION_CHANGE = """
a/script.py b/script.py
old mode 100644
new mode 100755
"""


@pytest.mark.parametrize(
    ("header", "expected_name", "expected_mode"),
    (
        (NEW_FILE, "test.txt", Filemode.NEW),
        (
            DELETED_FILE,
            "test.txt",
            Filemode.DELETE,
        ),
        (
            MODIFIED_FILE,
            "test.txt",
            Filemode.MODIFY,
        ),
        (
            MODIFIED_FILE_WITH_SPACES,
            "some spaces.txt",
            Filemode.MODIFY,
        ),
        (RENAMED_FILE, "new.txt", Filemode.RENAME),
        (PERMISSION_CHANGE, "script.py", Filemode.PERMISSION_CHANGE),
    ),
)
def test_parse_diff_header_lines(header, expected_name, expected_mode):
    lines = header.strip().split("\n")
    name, mode = Commit._parse_diff_header_lines(lines)
    assert (name, mode) == (expected_name, expected_mode)
