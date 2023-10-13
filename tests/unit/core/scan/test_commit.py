import subprocess
from pathlib import Path
from typing import Callable, List, Tuple

import pytest

from ggshield.core.filter import init_exclusion_regexes
from ggshield.core.scan import Commit
from ggshield.core.scan.commit import CommitInformation, _parse_patch_header_line
from ggshield.utils.git_shell import Filemode
from tests.conftest import is_windows
from tests.repository import Repository


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
    commit = Commit.from_patch(PATCH_SEPARATION)
    files = list(commit.get_files())

    assert commit.info.author == "Testificate Jose"
    assert commit.info.email == "test@test.test"
    assert commit.info.date == "Fri Oct 18 13:20:00 2012 +0100"

    assert len(files) == len(EXPECTED_PATCH_CONTENT)
    for file_, (name, content) in zip(files, EXPECTED_PATCH_CONTENT):
        assert file_.filename == name
        assert file_.content == content


def test_patch_separation_ignore():
    file_to_ignore = ".env"
    commit = Commit.from_patch(
        PATCH_SEPARATION, init_exclusion_regexes([file_to_ignore])
    )
    files = list(commit.get_files())

    assert len(files) == 3
    assert not (any(entry.filename == file_to_ignore for entry in files))


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


def create_file(repo: Repository, name: str = "f", content: str = "Hello\n") -> Path:
    path = repo.path / name
    path.write_text(content)
    return path


def file_append(path: Path, content: str) -> None:
    with path.open("a") as f:
        f.write(content)


def file_search_and_replace(path: Path, src: str, dst: str) -> None:
    content = path.read_text().replace(src, dst)
    path.write_text(content)


def scenario_add(repo: Repository) -> None:
    repo.add(create_file(repo))
    repo.create_commit()


def scenario_add_unusual_chars(repo: Repository) -> None:
    repo.add(create_file(repo, "I'm unusual!"))
    repo.create_commit()


def scenario_add_two(repo: Repository) -> None:
    repo.add(create_file(repo, "one"))
    repo.add(create_file(repo, "two"))
    repo.create_commit()


def scenario_modify(repo: Repository) -> None:
    path = create_file(repo, "f", "Old content")
    repo.add(path)
    repo.create_commit()
    path.write_text("New content")
    repo.add(path)
    repo.create_commit()


def scenario_remove(repo: Repository) -> None:
    path = create_file(repo)
    repo.add(path)
    repo.create_commit()
    repo.git("rm", path)
    repo.create_commit()


def scenario_rename(repo: Repository) -> None:
    path = create_file(repo, "old file.txt")
    repo.add(path)
    repo.create_commit()
    repo.git("mv", path.name, "new file.txt")
    repo.create_commit()


def scenario_chmod(repo: Repository) -> None:
    path = create_file(repo)
    repo.add(path)
    repo.create_commit()
    path.chmod(0o755)
    repo.add(path)
    repo.create_commit()


def scenario_rename_chmod_modify(repo: Repository) -> None:
    path = create_file(repo, "oldscript", "another script\n")
    repo.add(path)
    repo.create_commit()

    # rename
    new_path = repo.path / "newscript"
    repo.git("mv", path.name, new_path.name)

    # chmod
    new_path.chmod(0o755)

    # modify, but not too much so that it's still considered as a rename
    file_append(new_path, "more content\n")

    repo.add(new_path)
    repo.create_commit()


def scenario_merge(repo: Repository) -> None:
    long_file = create_file(
        repo,
        "longfile",
        """Some content

long enough


for changes
to merge

without conflict...

hopefully
""",
    )
    repo.add(long_file)
    repo.create_commit()

    # Append to long_file in branch b1
    repo.create_branch("b1")
    file_append(long_file, "Hello from b1\n")
    repo.add(long_file)
    repo.create_commit()

    # Replace text in long_file in branch b2
    repo.checkout("main")
    repo.create_branch("b2")
    file_search_and_replace(long_file, "for changes", "for changes from b2")
    repo.add(long_file)
    repo.create_commit()

    # Replace text in branch main
    repo.checkout("main")
    file_search_and_replace(long_file, "Some content", "## Some content")
    repo.add(long_file)
    repo.create_commit()

    # Merge all branches
    repo.git("merge", "--no-ff", "b1", "b2")


def scenario_merge_with_changes(repo: Repository) -> None:
    path = create_file(repo, "conflicted")
    repo.add(path)
    repo.create_commit()

    # Append from branch b1
    repo.create_branch("b1")
    file_append(path, "Hello from b1\n")
    repo.add(path)
    repo.create_commit()

    # Append from main
    repo.checkout("main")
    file_append(path, "Hello from main\n")
    repo.add(path)
    repo.create_commit()

    # Try to merge
    try:
        repo.git("merge", "--no-ff", "b1", "--no-commit")
    except subprocess.CalledProcessError:
        pass

    # Solve conflict
    path.write_text("Solve conflict\n")
    repo.add(path)
    repo.create_commit()


def scenario_type_change(repo: Repository) -> None:
    path = create_file(repo)

    # Create `f2` as a symlink to path
    f2_path = repo.path / "f2"
    f2_path.symlink_to(path)
    repo.add(path, f2_path)
    repo.create_commit()

    # Turn `f2` into a file
    f2_path.unlink()
    f2_path.write_text("file")
    repo.add(f2_path)
    repo.create_commit()


@pytest.mark.parametrize(
    ("scenario", "expected_names_and_modes"),
    [
        pytest.param(*x, id=x[0].__name__)
        for x in [
            (scenario_add, [("f", Filemode.NEW)]),
            (scenario_add_unusual_chars, [("I'm unusual!", Filemode.NEW)]),
            (
                scenario_add_two,
                [
                    ("one", Filemode.NEW),
                    ("two", Filemode.NEW),
                ],
            ),
            (
                scenario_modify,
                [
                    ("f", Filemode.MODIFY),
                ],
            ),
            (
                scenario_remove,
                [
                    ("f", Filemode.DELETE),
                ],
            ),
            (
                scenario_rename,
                [],  # a rename with no content change yields no content
            ),
            (
                scenario_chmod,
                [],  # a permission change with no content change yields no content
            ),
            (
                scenario_rename_chmod_modify,
                [
                    ("newscript", Filemode.RENAME),
                ],
            ),
            (
                scenario_merge,
                [
                    ("longfile", Filemode.MODIFY),
                    ("longfile", Filemode.MODIFY),
                    ("longfile", Filemode.MODIFY),
                ],
            ),
            (
                scenario_merge_with_changes,
                [
                    ("conflicted", Filemode.MODIFY),
                    ("conflicted", Filemode.MODIFY),
                ],
            ),
            (
                scenario_type_change,
                [
                    ("f2", Filemode.NEW),
                ],
            ),
        ]
    ],
)
def test_from_sha(
    tmp_path,
    scenario: Callable[[Repository], None],
    expected_names_and_modes: List[Tuple[str, Filemode]],
):
    """
    GIVEN a Commit created from `scenario`
    WHEN Commit.get_files() is called
    THEN it returns files with correct names and modes
    """
    if is_windows() and scenario == scenario_type_change:
        # Path.symlink_to() does not produce the expected diff changes on Windows, so
        # skip this test for now
        pytest.skip()
    repo = Repository.create(tmp_path)
    scenario(repo)

    commit = Commit.from_sha(repo.get_top_sha(), cwd=tmp_path)
    files = list(commit.get_files())

    names_and_modes = [(x.filename, x.filemode) for x in files]
    assert names_and_modes == expected_names_and_modes


def test_from_staged(tmp_path):
    """
    GIVEN a new file added with `git add`
    AND a Commit instance created from git staged files
    WHEN Commit.get_files() is called
    THEN it returns files with correct names and modes
    """
    repository = Repository.create(tmp_path)
    new_file = tmp_path / "NEW.md"
    new_file.write_text("Hello")
    repository.add(new_file)

    commit = Commit.from_staged(cwd=tmp_path)
    files = list(commit.get_files())

    names_and_modes = [(x.filename, x.filemode) for x in files]
    assert names_and_modes == [("NEW.md", Filemode.NEW)]


@pytest.mark.parametrize(
    ("patch", "expected"),
    [
        (
            "Author: ezra <ezra@lothal.sw>\nDate: Thu Sep 29 15:55:41 2022 +0000\n",
            CommitInformation(
                "ezra", "ezra@lothal.sw", "Thu Sep 29 15:55:41 2022 +0000"
            ),
        ),
        # This can happen, see: https://github.com/sqlite/sqlite/commit/981706534.patch
        (
            "Author: emptymail <>\nDate: Thu Sep 29 15:55:41 2022 +0000\n",
            CommitInformation("emptymail", "", "Thu Sep 29 15:55:41 2022 +0000"),
        ),
    ],
)
def test_commit_information_from_patch_header(patch: str, expected: CommitInformation):
    """
    GIVEN a patch header
    WHEN parsing it with CommitInformation.from_patch_header()
    THEN it extracts the expected values
    """
    assert CommitInformation.from_patch_header(patch) == expected
