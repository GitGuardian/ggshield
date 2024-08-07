#!/usr/bin/env python3
"""
Generate a repo with two branches: master and feature_branch.
(all commits contain DEFAULT_FILE_COUNT files, each of size DEFAULT_FILE_SIZE bytes).
There is an initial commit, then:
 - the feature branch is created and one commit is added (possibly containing secrets),
 - we add 3 more commit on the master branch,
 - we install the ggshield pre-commit hook
 - and finally merges master in feature_branch.

 This gives the following commit graph:
 *   17d3a27 (HEAD -> feature_branch) Merge branch 'master' into feature_branch
|\
| * db20e84 (master) Commit master n°2
| * 53a4cd0 Commit master n°1
| * a78f68d Commit master n°0
* | 9f5717c Commit feature branch
|/
* e1db622 Initial commit

This script has an option to create a conflict file in the feature branch (--with_conflict true),
in which case the merge will fail. We catch the error and automatically resolve the conflict by overwriting the file
then commit the change. ggshield is called in pre-commit mode which allow to test performances.
"""
import argparse
import random
import re
import shutil
import subprocess
import sys
import time
from enum import Enum
from pathlib import Path
from subprocess import CalledProcessError

import pytest

from tests.functional.utils import run_ggshield
from tests.repository import Repository


DEFAULT_FILE_COUNT = 10
DEFAULT_SECRET_COUNT = 5
DEFAULT_FILE_SIZE = 200 * 1024

AVERAGE_LINE_LENGTH = 80
LINE_VARIATION = 20

SECRET_SUFFIX_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"


class SecretLocation(str, Enum):
    no_secret = "no_secret"
    master_branch = "master_branch"
    feature_branch = "feature_branch"
    conflict_file = "conflict_file"


def generate_file(size):
    content = []
    while len(content) < size:
        line_length = AVERAGE_LINE_LENGTH + random.randrange(
            -LINE_VARIATION, LINE_VARIATION
        )
        for _ in range(line_length):
            content.append(chr(random.randrange(32, 127)))
        content.append("\n")
    remove_pwd = re.compile(re.escape("pwd"), re.IGNORECASE)
    return remove_pwd.sub("not", "".join(content))


def generate_secret():
    # var = random.choice(["kay", "taken", "possword"])
    var = random.choice(["key", "token", "password"])
    suffix = "".join(random.choice(SECRET_SUFFIX_CHARS) for _ in range(20))
    return f"{var} = 'glpat-{suffix}'"


def plant_secret(path, secret):

    lines = path.read_text().splitlines()

    idx = random.randrange(len(lines))
    lines.insert(idx, secret)

    path.write_text("\n".join(lines))


def generate_commit(
    repo,
    root_dir,
    file_size,
    nb_files,
    nb_secrets,
    commit_message,
    file_prefix="file",
    files_with_conflict=[],
):
    content = generate_file(file_size)
    for idx in range(nb_files):
        Path(root_dir / f"{file_prefix}-{random.randrange(10000)}").write_text(content)

    # Plant secrets
    files = list(Path(root_dir).glob("*"))
    for _ in range(nb_secrets):
        while True:
            path = random.choice(files)
            if not path.is_dir():
                break
        secret = generate_secret()
        plant_secret(path, secret)
        print(f"Planted secret in {path}")

    for file in files_with_conflict:
        Path(root_dir / file).write_text("conflict")

    repo.add(".")
    repo.create_commit(commit_message)


def generate_repo_with_merge_commit(
    root_dir: Path,
    file_size: int = DEFAULT_FILE_SIZE,
    nb_files_per_commit: int = DEFAULT_FILE_COUNT,
    with_conflict: bool = False,
    secret_location: SecretLocation = SecretLocation.no_secret,
    merge_skip_unchanged: bool = True,
) -> None:
    shutil.rmtree(root_dir, ignore_errors=True)
    Path(root_dir).mkdir(parents=True, exist_ok=True)
    repo = Repository.create(root_dir, initial_branch="master")
    # First commit, on master no secrets
    generate_commit(repo, root_dir, file_size, nb_files_per_commit, 0, "Initial commit")
    # Create a feature branch
    repo.create_branch("feature_branch")
    repo.checkout("master")
    # 3 more commits, on master no secrets
    for i in range(2):
        generate_commit(
            repo,
            root_dir,
            file_size,
            nb_files_per_commit,
            0,
            f"Commit master n°{i}",
            file_prefix=f"file-master-{i}",
        )
    # Pick one of the files of HEAD  commit at random
    files_last_commit = repo.git(*["diff", "--name-only", "HEAD~1"]).splitlines()
    generate_commit(
        repo,
        root_dir,
        file_size,
        nb_files_per_commit,
        DEFAULT_SECRET_COUNT if secret_location == SecretLocation.master_branch else 0,
        f"Commit master n°{3}",
        file_prefix=f"file-master-{3}",
    )

    repo.checkout("feature_branch")
    # Additional commit, on feature_branch with secrets
    files_with_conflict = [random.choice(files_last_commit)] if with_conflict else []
    print(f"Files with conflict: {files_with_conflict}")
    generate_commit(
        repo,
        root_dir,
        file_size,
        nb_files_per_commit,
        DEFAULT_SECRET_COUNT if secret_location == SecretLocation.feature_branch else 0,
        "Commit feature branch",
        files_with_conflict=files_with_conflict,
    )

    # Install ggshield hook
    if merge_skip_unchanged:
        run_ggshield(
            "install",
            "-m",
            "local",
            "-t",
            "pre-commit",
            "-o",
            "--merge-skip-unchanged",
            cwd=repo.path,
        )
    else:
        run_ggshield(
            "install",
            "-m",
            "local",
            "-t",
            "pre-commit",
            cwd=repo.path,
        )

    if not with_conflict:
        # Create merge commit
        start = time.perf_counter()
        repo.git("merge", "master")
        end = time.perf_counter()
        print(
            f"GGshield scan on merge commit (no conflict) with ggshield took: {end - start:.6f} seconds"
        )
    else:
        # Create merge commit with conflict
        try:
            repo.git("merge", "master")
        except subprocess.CalledProcessError:
            for file in files_with_conflict:
                Path(root_dir / file).write_text(
                    generate_secret()
                    if secret_location == SecretLocation.conflict_file
                    else "conflict solved !"
                )
            repo.add(".")
            start = time.perf_counter()
            repo.create_commit("Solved conflict")
            end = time.perf_counter()
            print(
                "GGshield scan on merge commit with conflict took: {:.6f} seconds".format(
                    end - start
                )
            )


@pytest.mark.parametrize(
    "with_conflict",
    [
        True,
        False,
    ],
)
@pytest.mark.parametrize(
    "secret_location",
    [
        SecretLocation.master_branch,
        SecretLocation.feature_branch,
        SecretLocation.no_secret,
    ],
)
@pytest.mark.parametrize(
    "merge_skip_unchanged",
    [
        True,
        False,
    ],
)
def test_merge_commit_no_conflict(
    tmp_path: Path,
    with_conflict: bool,
    secret_location: SecretLocation,
    merge_skip_unchanged: bool,
) -> None:
    if (
        secret_location == SecretLocation.master_branch
        and with_conflict
        and not merge_skip_unchanged
    ):
        with pytest.raises(CalledProcessError) as exc:
            generate_repo_with_merge_commit(
                tmp_path,
                with_conflict=with_conflict,
                secret_location=secret_location,
                merge_skip_unchanged=merge_skip_unchanged,
            )

        # AND the error message contains the Gitlab Token
        stderr = exc.value.stderr.decode()
        assert "GitLab Token" in stderr
    else:
        generate_repo_with_merge_commit(
            tmp_path,
            with_conflict=with_conflict,
            secret_location=secret_location,
            merge_skip_unchanged=merge_skip_unchanged,
        )


def test_merge_commit_with_conflict_and_secret_in_conflict(
    tmp_path: Path,
) -> None:

    with pytest.raises(CalledProcessError) as exc:
        generate_repo_with_merge_commit(
            tmp_path, with_conflict=True, secret_location=SecretLocation.conflict_file
        )

    # AND the error message contains the Gitlab Token
    stderr = exc.value.stderr.decode()
    assert "GitLab Token" in stderr


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter, description=__doc__
    )

    parser.add_argument(
        "-s", "--size", type=int, help="file size", default=DEFAULT_FILE_SIZE
    )

    parser.add_argument(
        "-c", "--count", type=int, help="number of files", default=DEFAULT_FILE_COUNT
    )

    parser.add_argument(
        "--with_conflict",
        type=bool,
        help="Whether to create a conflict file",
        default=False,
    )

    parser.add_argument(
        "--secret_location",
        type=SecretLocation,
        help="where to add secrets",
        default=SecretLocation.no_secret,
    )

    parser.add_argument("dir", help="where to generate the files")

    args = parser.parse_args()
    root_dir = Path(args.dir)
    generate_repo_with_merge_commit(
        root_dir,
        args.size,
        args.count,
        args.with_conflict,
        args.secret_location,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
