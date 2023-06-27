import logging
import os
import subprocess
import tarfile
from functools import lru_cache
from io import BytesIO
from pathlib import Path
from shutil import which
from typing import Callable, Iterable, List, Optional

import click
from click import UsageError
from pygitguardian import ContentTooLarge
from pygitguardian.client import MAX_TAR_CONTENT_SIZE

from ggshield.core.errors import UnexpectedError


COMMAND_TIMEOUT = 45
INDEX_REF = ""

logger = logging.getLogger(__name__)


@lru_cache(None)
def _get_git_path() -> str:
    git_path = which("git")

    if git_path is None:
        raise UnexpectedError("unable to find git executable in PATH/PATHEXT")

    # lower()ing these would provide additional coverage on case-
    # insensitive filesystems but detection is problematic
    git_path = os.path.abspath(git_path)
    cwd = os.getcwd()
    path_env = [
        os.path.abspath(p) for p in os.environ.get("PATH", "").split(os.pathsep)
    ]

    # git was found - ignore git in cwd if cwd not in PATH
    if cwd == os.path.dirname(git_path) and cwd not in path_env:
        raise UnexpectedError("rejecting git executable in CWD not in PATH")

    logger.debug("Found git at %s", git_path)
    return git_path


@lru_cache(None)
def is_git_dir(wd: str) -> bool:
    try:
        git(["rev-parse", "--show-toplevel"], cwd=wd)
    except subprocess.CalledProcessError:
        return False
    return True


def check_git_dir(wd: Optional[str] = None) -> None:
    """Check if folder is git directory."""
    if wd is None:
        wd = os.getcwd()
    if not is_git_dir(wd):
        raise UsageError("Not a git directory.")


def get_git_root(wd: Optional[str] = None) -> str:
    return git(["rev-parse", "--show-toplevel"], cwd=wd)


def git(
    command: List[str],
    timeout: int = COMMAND_TIMEOUT,
    check: bool = True,
    cwd: Optional[str] = None,
) -> str:
    """Calls git with the given arguments, returns stdout as a string"""
    env = os.environ.copy()
    env["LANG"] = "C"

    try:
        logger.debug("command=%s", command)
        result = subprocess.run(
            [_get_git_path()] + command,
            check=check,
            capture_output=True,
            timeout=timeout,
            env=env,
            cwd=cwd,
        )
        if result.stderr:
            logger.debug("stderr=%s", result.stderr.decode("utf-8", errors="ignore"))
        return result.stdout.decode("utf-8", errors="ignore").rstrip()
    except subprocess.CalledProcessError as e:
        if "detected dubious ownership in repository" in e.stderr.decode(
            "utf-8", errors="ignore"
        ):
            raise UnexpectedError(
                "Git command failed because of a dubious ownership in repository.\n"
                "If you still want to run ggshield, make sure you mark "
                "the current repository as safe for git with:\n"
                "   git config --global --add safe.repository <YOUR_REPO>"
            )
        raise e
    except subprocess.TimeoutExpired:
        raise click.Abort('Command "{}" timed out'.format(" ".join(command)))


def git_ls(wd: Optional[str] = None) -> List[str]:
    cmd = ["ls-files", "--recurse-submodules"]
    return git(cmd, timeout=600, cwd=wd).split("\n")


def is_valid_git_commit_ref(ref: str, wd: Optional[str] = None) -> bool:
    """
    Check if a reference is valid and can be resolved to a commit
    """
    if not wd:
        wd = os.getcwd()

    ref += "^{commit}"
    cmd = ["cat-file", "-e", ref]

    try:
        git(cmd, cwd=wd)
    except subprocess.CalledProcessError:
        return False

    return True


def check_git_ref(ref: str, wd: Optional[str] = None) -> None:
    """Check if folder is a git repository and ref is a git reference."""
    if wd is None:
        wd = os.getcwd()
    check_git_dir(wd)

    if not is_valid_git_commit_ref(ref=ref, wd=wd):
        raise UsageError(f"Not a git reference: {ref}.")


def get_list_commit_SHA(
    commit_range: str, max_count: Optional[int] = None
) -> List[str]:
    """
    Retrieve the list of commit SHA from a range.
    :param commit_range: A range of commits (ORIGIN...HEAD)
    :param max_count: If set, limits the number of SHA returned to this amount. This
    returns the *end* of the list, so max_count=3 returns [HEAD~2, HEAD~1, HEAD].
    """

    cmd = ["rev-list", "--reverse", *commit_range.split()]
    if max_count is not None:
        cmd.extend(["--max-count", str(max_count)])
    # Makes rev-list print "bad revision" instead of telling the range is ambiguous
    cmd.append("--")

    try:
        commit_list = git(cmd).split("\n")
    except subprocess.CalledProcessError as e:
        if b"bad revision" in e.stderr and "~1.." in commit_range:
            # We got asked to list commits for A~1...B. If A~1 does not exist, but A
            # does, then return A and its descendants until B.
            a_ref, remaining = commit_range.split("~1", maxsplit=1)
            if not is_valid_git_commit_ref(f"{a_ref}~1") and is_valid_git_commit_ref(
                a_ref
            ):
                commit_range = a_ref + remaining
                return [a_ref] + get_list_commit_SHA(commit_range)
        return []

    if "" in commit_list:
        commit_list.remove("")
        # only happens when git rev-list doesn't error
        # but returns an empty range, example git rev-list HEAD...

    return commit_list


def get_filepaths_from_ref(ref: str, wd: Optional[str] = None) -> List[Path]:
    """
    Fetches a list of all file paths indexed at a given reference in a git repository.
    :param ref: git reference, like a commit SHA, a relative reference like HEAD~1, ...
    :param wd: string path to the git repository. Defaults to current directory
    """
    if not wd:
        wd = os.getcwd()

    check_git_ref(ref, wd)

    filepaths = git(["ls-tree", "--name-only", "-r", ref], cwd=wd).splitlines()
    return [Path(path_str) for path_str in filepaths]


def get_staged_filepaths(wd: Optional[str] = None) -> List[Path]:
    """
    Fetches a list of all file paths at the index in a git repository.
    :param wd: string path to the git repository. Defaults to current directory
    """
    if not wd:
        wd = os.getcwd()

    filepaths = git(["ls-files", "-c"], cwd=wd).splitlines()
    return [Path(path_str) for path_str in filepaths]


def tar_from_ref_and_filepaths(
    ref: str,
    filepaths: Iterable[Path],
    acceptation_func: Optional[Callable[[Path, str], bool]] = None,
    wd: Optional[str] = None,
) -> bytes:
    """
    Builds a gzipped archive from a given git reference, and selected filepaths.
    The filepaths are typically obtained via `get_filepaths_from_ref` or `get_staged_filepaths`
    before being filtered.
    The archive is returned as raw bytes.
    :param ref: git reference, like a commit SHA, a relative reference like HEAD~1,\
        or any argument accepted as <ref> by git show <ref>:<filepath>
    :param filepaths: string paths to selected files
    :param acceptation_func: provided a filepath and its raw content, \
        returns whether the file should be included in the archive
    :param wd: string path to the git repository. Defaults to current directory
    """
    if not wd:
        wd = os.getcwd()

    # Empty string as ref makes the path valid for index
    if ref != INDEX_REF:
        check_git_ref(ref, wd)

    tar_stream = BytesIO()
    total_tar_size = 0

    with tarfile.open(fileobj=tar_stream, mode="w:gz") as tar:
        for path in filepaths:
            raw_file_content = git(["show", f"{ref}:./{path}"], cwd=wd)

            if acceptation_func is not None and not (
                acceptation_func(path, raw_file_content)
            ):
                continue

            data = BytesIO(raw_file_content.encode())

            tarinfo = tarfile.TarInfo(str(path))
            tarinfo.size = len(data.getbuffer())
            total_tar_size += tarinfo.size

            if total_tar_size > MAX_TAR_CONTENT_SIZE:
                raise ContentTooLarge(
                    f"The total size of the files processed exceeds {MAX_TAR_CONTENT_SIZE / (1024 * 1024):.0f}MB, "
                    f"please try again with less files"
                )

            tar.addfile(tarinfo, fileobj=data)

    return tar_stream.getvalue()
