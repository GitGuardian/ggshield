import subprocess
from pathlib import Path
from typing import Callable, List, Tuple

import pytest

from ggshield.core.filter import init_exclusion_regexes
from ggshield.core.scan import Commit
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
    + ":000000 100644 0000000 12323ef U\0unmerged.txt\0"
    + ":100644 100644 ac204ec ac204ec R100\0ggshield/tests/test_config.py\0tests/test_config.py\0"
    + ":100644 100644 6546aef b41653f M\0data/utils/email_sender.py\0"
    + """\0diff --git a/ggshield/tests/cassettes/test_files_yes.yaml b/ggshield/tests/cassettes/test_files_yes.yaml
deleted file mode 100644
index 1233aef..0000000
--- a/ggshield/tests/cassettes/test_files_yes.yaml
+++ /dev/null
@@ -1,45 +0,0 @@
-interactions:

diff --git a/tests/test_scannable.py b/tests/test_scannable.py
new file mode 100644
index 0000000..19465ef
--- /dev/null
+++ b/tests/test_scannable.py
@@ -0,0 +1,112 @@
+from collections import namedtuple

diff --git a/bin/shutdown.sh b/bin/shutdown.sh
old mode 100644
new mode 100755

diff --git a/.env b/.env
new file mode 100644
index 0000000..12356ef
--- /dev/null
+++ b/.env
@@ -0,0 +1,112 @@
CHECK_ENVIRONMENT=true

diff --git a/ggshield/tests/test_config.py b/tests/test_config.py
similarity index 100%
rename from ggshield/tests/test_config.py
rename to tests/test_config.py

diff --git a/data/utils/email_sender.py b/data/utils/email_sender.py
index 6546aef..b41653f 100644
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
    for file_, (path, content) in zip(files, EXPECTED_PATCH_CONTENT):
        assert file_.path == Path(path)
        assert file_.content == content


def test_patch_separation_ignore():
    file_to_ignore = ".env"
    commit = Commit.from_patch(
        PATCH_SEPARATION, init_exclusion_regexes([file_to_ignore])
    )
    files = list(commit.get_files())

    assert len(files) == 3
    assert not (any(entry.filename == file_to_ignore for entry in files))


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
    ("scenario", "expected_paths_and_modes"),
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
                [],  # no conflict -> nothing to scan
            ),
            (
                scenario_merge_with_changes,
                [
                    ("conflicted", Filemode.MODIFY),
                ],
            ),
            (
                scenario_type_change,
                [
                    ("f2", Filemode.NEW),
                    ("f2", Filemode.NEW),
                ],
            ),
        ]
    ],
)
def test_from_sha(
    tmp_path,
    scenario: Callable[[Repository], None],
    expected_paths_and_modes: List[Tuple[str, Filemode]],
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

    sha = repo.get_top_sha()
    commit = Commit.from_sha(sha, cwd=tmp_path)
    files = list(commit.get_files())

    paths_and_modes = [(x.path, x.filemode) for x in files]
    assert paths_and_modes == [
        (Path(name), mode) for name, mode in expected_paths_and_modes
    ]


def test_from_sha_gets_right_content_for_conflicts(tmp_path):
    """
    GIVEN a merge commit with a conflict, loaded with Commit.from_sha()
    WHEN Commit.get_files() is called
    THEN it returns the right content
    """
    repo = Repository.create(tmp_path)
    scenario_merge_with_changes(repo)

    sha = repo.get_top_sha()
    commit = Commit.from_sha(sha, cwd=tmp_path)

    files = list(commit.get_files())
    assert len(files) == 1
    content = files[0].content

    # Content has been turned into a single-parent diff
    assert (
        content
        == """
@@ -1,2 +1,1 @@
-Hello
-Hello from main
+Solve conflict
""".strip()
    )


def test_from_sha_files_matches_content(tmp_path):
    """
    GIVEN a commit with many files
    WHEN Commit.get_files() is called
    THEN the reported file names match their expected content
    """
    repo = Repository.create(tmp_path)

    for idx in range(50):
        path = tmp_path / str(idx)
        path.parent.mkdir(exist_ok=True)
        path.write_text(f"{idx}\n")
        repo.add(path)
    repo.create_commit()

    sha = repo.get_top_sha()
    commit = Commit.from_sha(sha, cwd=tmp_path)
    files = list(commit.get_files())

    for file in files:
        last_line = file.content.splitlines()[-1]
        assert last_line == f"+{file.path.name}"


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

    paths_and_modes = [(x.path, x.filemode) for x in files]
    assert paths_and_modes == [(Path("NEW.md"), Filemode.NEW)]


def test_from_merge(tmp_path):
    """
    GIVEN a Commit instance created from a git merge (after conflict)
    WHEN Commit.get_files() is called
    THEN it returns files with correct names and modes
    """
    repo = Repository.create(tmp_path, initial_branch="master")

    Path(tmp_path / "inital.md").write_text("Initial")
    repo.add(".")
    repo.create_commit("Initial commit on master")

    repo.create_branch("feature_branch")
    repo.checkout("master")
    conflict_file = tmp_path / "conflict.md"
    conflict_file.write_text("Hello")
    Path(tmp_path / "Other.md").write_text("Other")
    repo.add(".")
    repo.create_commit("Commit on master")

    repo.checkout("feature_branch")
    conflict_file.write_text("World")
    Path(tmp_path / "Another.md").write_text("Another")
    repo.add(".")
    repo.create_commit("Commit on feature_branch")

    # Create merge commit with conflict
    with pytest.raises(subprocess.CalledProcessError) as exc:
        repo.git("merge", "master")

    # check stdout for conflict message
    stdout = exc.value.stdout.decode()
    assert "CONFLICT" in stdout

    conflict_file.write_text("Hello World !")
    Path(tmp_path / "new.md").write_text("Something added at conflict")
    repo.add(".")
    commit = Commit.from_merge(cwd=tmp_path)
    files = list(commit.get_files())

    paths_and_modes = [(x.path, x.filemode) for x in files]
    assert paths_and_modes == [
        (Path("conflict.md"), Filemode.MODIFY),
        (Path("new.md"), Filemode.NEW),
    ]


def test_from_merge_filename_with_spaces(tmp_path):
    """
    GIVEN two commits on different branches with a conflict
    involving a filename with spaces
    WHEN Commit.from_merge() is called
    THEN it returns successfully
    AND get_files returns the correct filename
    """
    repo = Repository.create(tmp_path, initial_branch="master")

    Path(tmp_path / "inital.md").write_text("Initial")
    repo.add(".")
    repo.create_commit("Initial commit on master")

    repo.create_branch("feature_branch")
    repo.checkout("master")
    conflict_file = tmp_path / "file with spaces.md"
    conflict_file.write_text("Hello")
    repo.add(".")
    repo.create_commit("Commit on master")

    repo.checkout("feature_branch")
    conflict_file.write_text("World")
    repo.add(".")
    repo.create_commit("Commit on feature_branch")

    # Create merge commit with conflict
    with pytest.raises(subprocess.CalledProcessError):
        repo.git("merge", "master")

    conflict_file.write_text("Hello World !")
    repo.add(".")
    commit = Commit.from_merge(cwd=tmp_path)
    files = list(commit.get_files())
    assert len(files) == 1
    assert files[0].path == Path("file with spaces.md")
