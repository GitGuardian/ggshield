import logging
import os
import sys
from typing import List, Optional, Tuple

from ggshield.core import ui
from ggshield.utils.git_shell import EMPTY_SHA, git, is_valid_git_commit_ref


logger = logging.getLogger(__name__)


OUTDATED_HOOK_MESSAGE = """The installed pre-push hook did not pass its command-line arguments to ggshield. This can cause the hook to fail if the name of the remote you are pushing to is not "origin".

This can happen if the hook has been created manually or by an old version of ggshield.

To fix it, either edit the hook manually or make a backup of it and reinstall it with the following command:

    ggshield install -m local -t pre-push -f
"""  # noqa: E501

BYPASS_MESSAGE = """  - if you use the pre-commit framework:

     SKIP=ggshield-push git push

  - otherwise (warning: the following command bypasses all pre-push hooks):

     git push --no-verify"""


def find_branch_start(commit: str, remote: str) -> Optional[str]:
    """
    Returns the first local-only commit of the branch.
    Returns None if the branch does not contain any new commit.
    """
    # List all ancestors of `commit` which are not in `remote`
    # Based on _pre_push_ns() from pre-commit
    #
    # Note: The `--remotes` argument MUST be set using a `=`: `--remotes={remote}` works,
    # but `--remotes {remote}` fails.
    output = git(
        [
            "rev-list",
            commit,
            "--topo-order",
            "--reverse",
            "--not",
            f"--remotes={remote}",
        ]
    )
    ancestors = output.splitlines()

    if ancestors:
        return ancestors[0]
    return None


def collect_commits_from_stdin(remote_name: str) -> Tuple[str, str]:
    """
    Collect pre-commit variables from stdin.
    """
    prepush_input = sys.stdin.read().strip()
    logger.debug("input=%s", prepush_input)
    if not prepush_input:
        # Happens when there's nothing to push
        return (EMPTY_SHA, EMPTY_SHA)

    # TODO There can be more than one line here, for example when pushing multiple
    # branches. We should support this.
    line = prepush_input.splitlines()[0]
    _, local_commit, _, remote_commit = line.split(maxsplit=3)

    if is_valid_git_commit_ref(remote_commit):
        # Pushing to an existing branch
        return (local_commit, remote_commit)

    # Pushing to a new branch
    start_commit = find_branch_start(local_commit, remote_name)
    if start_commit is None:
        return local_commit, local_commit
    return (local_commit, f"{start_commit}~1")


def collect_commits_from_precommit_env() -> Tuple[Optional[str], Optional[str]]:
    """
    Collect from pre-commit framework environment.
    """
    # pre-commit framework <2.2.0
    local_commit = os.getenv("PRE_COMMIT_SOURCE", None)
    remote_commit = os.getenv("PRE_COMMIT_ORIGIN", None)

    if local_commit is None or remote_commit is None:
        # pre-commit framework >=2.2.0
        local_commit = os.getenv("PRE_COMMIT_FROM_REF", None)
        remote_commit = os.getenv("PRE_COMMIT_TO_REF", None)

    return (local_commit, remote_commit)


def collect_commits_refs(prepush_args: List[str] = []) -> Tuple[str, str]:
    local_commit, remote_commit = collect_commits_from_precommit_env()
    if local_commit is None or remote_commit is None:
        if len(prepush_args) == 0:
            ui.display_warning(OUTDATED_HOOK_MESSAGE)
            remote_name = "origin"
        else:
            remote_name = prepush_args[0]
        local_commit, remote_commit = collect_commits_from_stdin(remote_name)
    return (local_commit, remote_commit)
