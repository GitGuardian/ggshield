import click
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


INVALID_FILE_MODE = """
diff --git a/old.txt b/new.txt
similarity index 71%
indx 0000000..b80e3df
"""


INVALID_RENAMED_FILE = """
diff --git a/old.txt b/new.txt
similarity index 71%
index 0000000..b80e3df
"""


INVALID_MODIFIED_FILE = """
diff --git a/test1.txt b/test2.txt
index e965047..802992c 100644
"""


@pytest.mark.parametrize(
    ("patch",),
    (
        pytest.param(INVALID_FILE_MODE, id="invalid-filemode"),
        pytest.param(INVALID_RENAMED_FILE, id="invalid-renamed"),
        pytest.param(INVALID_MODIFIED_FILE, id="invalid-modified"),
    ),
)
def test_parsing_invalid_patch_fails(patch: str):
    commit = Commit()
    commit._patch = patch.lstrip()
    with pytest.raises(click.ClickException) as info:
        list(commit.get_files())
    assert "Error parsing diff:" in info.value.message

    commit.sha = "1234567"
    with pytest.raises(click.ClickException) as info:
        list(commit.get_files())
    assert f"Error parsing commit {commit.sha}:" in info.value.message
