"""
Generate a repo with two branches: master and feature_branch.
(all commits contain DEFAULT_FILE_COUNT files, each of size DEFAULT_FILE_SIZE bytes).
There is an initial commit, then:
 - the feature branch is created and one commit is added (possibly containing secrets),
 - we add 3 more commits on the master branch,
 - we install the ggshield pre-commit hook
 - and finally merge master in feature_branch.

 This gives the following commit graph:
 *   17d3a27 (HEAD -> feature_branch) Merge branch 'master' into feature_branch
|\
| * db20e84 (master) Commit master n°3
| * 53a4cd0 Commit master n°2
| * a78f68d Commit master n°1
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
import subprocess
import sys
import time
from enum import Enum
from pathlib import Path
from typing import List, Optional

from tests.functional.utils import run_ggshield
from tests.repository import Repository


DEFAULT_FILE_COUNT = 10
DEFAULT_SECRET_COUNT = 5
DEFAULT_FILE_SIZE = 200 * 1024

AVERAGE_LINE_LENGTH = 80
LINE_VARIATION = 20

SECRET_SUFFIX_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"


class SecretLocation(str, Enum):
    NO_SECRET = "no_secret"
    MASTER_BRANCH = "master_branch"
    FEATURE_BRANCH = "feature_branch"
    CONFLICT_FILE = "conflict_file"


def generate_file(size):
    content = []
    while len(content) < size:
        line_length = AVERAGE_LINE_LENGTH + random.randrange(
            -LINE_VARIATION, LINE_VARIATION
        )
        for _ in range(line_length):
            content.append(chr(random.randrange(32, 127)))
        content.append("\n")
    remove_pwd = re.compile("pwd", re.IGNORECASE)
    return remove_pwd.sub("not", "".join(content))


def generate_secret():
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
    files_with_conflict: Optional[List[str]] = None,
):
    content = generate_file(file_size)
    for idx in range(nb_files):
        Path(root_dir / f"{file_prefix}-{random.randrange(10000)}").write_text(content)

    # Plant secrets
    files = list(Path(root_dir).glob(f"{file_prefix}-*"))
    for _ in range(nb_secrets):
        while True:
            path = random.choice(files)
            if not path.is_dir():
                break
        secret = generate_secret()
        plant_secret(path, secret)
        print(f"Planted secret in {path}")

    if files_with_conflict is not None:
        for file in files_with_conflict:
            Path(root_dir / file).write_text("conflict")

    repo.add(".")
    repo.create_commit(commit_message)


def generate_repo_with_merge_commit(
    root_dir: Path,
    file_size: int = DEFAULT_FILE_SIZE,
    nb_files_per_commit: int = DEFAULT_FILE_COUNT,
    with_conflict: bool = False,
    secret_location: SecretLocation = SecretLocation.NO_SECRET,
    scan_all_merge_files: bool = False,
) -> None:
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
            f"Commit master n°{i + 1}",
            file_prefix=f"file-master-{i + 1}",
        )
    # Pick one of the files of HEAD  commit at random
    files_last_commit = repo.git(*["diff", "--name-only", "HEAD~1"]).splitlines()
    generate_commit(
        repo,
        root_dir,
        file_size,
        nb_files_per_commit,
        DEFAULT_SECRET_COUNT if secret_location == SecretLocation.MASTER_BRANCH else 0,
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
        DEFAULT_SECRET_COUNT if secret_location == SecretLocation.MASTER_BRANCH else 0,
        "Commit feature branch",
        files_with_conflict=files_with_conflict,
        file_prefix="file-feature",
    )

    # Install ggshield hook
    run_ggshield(
        "install",
        "-m",
        "local",
        "-t",
        "pre-commit",
        cwd=repo.path,
    )
    if scan_all_merge_files:
        # rewrite the git hook file to add the option --skip-unchanged-merge-files
        hook_path = Path(
            f"{root_dir}/.git/hooks/pre-commit",
        )
        with open(hook_path, "r") as f:
            hook = f.read()
        hook = hook.replace(r"pre-commit", r"pre-commit --scan-all-merge-files")
        with open(hook_path, "w") as f:
            f.write(hook)

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
                    if secret_location == SecretLocation.CONFLICT_FILE
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
        default=SecretLocation.NO_SECRET,
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
