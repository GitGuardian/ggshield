import logging
import os
import subprocess
from typing import List, Tuple

from ggshield.core.errors import UnexpectedError
from ggshield.core.git_hooks.ci.get_scan_ci_parameters import (
    CI_TARGET_BRANCH_ASSOC,
    get_remote_prefix,
)
from ggshield.utils.git_shell import (
    EMPTY_SHA,
    GitCommandTimeoutExpired,
    get_list_commit_SHA,
    git,
)

from ... import ui
from .supported_ci import SupportedCI


logger = logging.getLogger(__name__)


CI_PREVIOUS_COMMIT_VAR = {
    SupportedCI.JENKINS: "GIT_PREVIOUS_COMMIT",
    SupportedCI.CIRCLECI: "CIRCLE_RANGE",
    SupportedCI.TRAVIS: "TRAVIS_COMMIT_RANGE",
    SupportedCI.GITLAB: "CI_COMMIT_BEFORE_SHA",
    SupportedCI.GITHUB: "GITHUB_PUSH_BASE_SHA",
    SupportedCI.DRONE: "DRONE_COMMIT_BEFORE",
}

CI_COMMIT_VAR = {
    SupportedCI.JENKINS: "GIT_COMMIT",
    SupportedCI.CIRCLECI: "CIRCLE_SHA1",
    SupportedCI.TRAVIS: "TRAVIS_COMMIT",
    SupportedCI.GITLAB: "CI_COMMIT_SHA",
    SupportedCI.GITHUB: "GITHUB_SHA",
    SupportedCI.AZURE: "BUILD_SOURCEVERSION",
    SupportedCI.BITBUCKET: "BITBUCKET_COMMIT",
}


def _fetch_target_branch(remote: str, branch: str) -> None:
    """
    Fetch the target branch from the remote to ensure the local ref is up to date.

    In CI environments with cached repos (GIT_STRATEGY=fetch) or shallow clones,
    the local origin/<target_branch> ref can be stale, causing the commit range
    computation to include unrelated commits from the target branch.
    """
    try:
        ui.display_verbose(f"\tFetching {branch} from {remote}")
        git(["fetch", remote, branch])
    except (subprocess.CalledProcessError, GitCommandTimeoutExpired):
        logger.warning("Failed to fetch %s from %s", branch, remote)


def collect_commit_range_from_ci_env() -> Tuple[List[str], SupportedCI]:
    ci_mode = SupportedCI.from_ci_env()

    base_commit_var = CI_COMMIT_VAR.get(ci_mode)
    base_commit = os.getenv(base_commit_var, "HEAD") if base_commit_var else "HEAD"

    ui.display_verbose(f"\tIdentified base commit as {base_commit}")

    target_branch_var = CI_TARGET_BRANCH_ASSOC.get(ci_mode)
    target_branch = None
    if target_branch_var:
        target_branch = os.getenv(target_branch_var)
        if target_branch and target_branch != EMPTY_SHA:
            ui.display_verbose(f"\tIdentified target branch as {target_branch}")
            remote_prefix = get_remote_prefix()
            if remote_prefix:
                _fetch_target_branch(remote_prefix.rstrip("/"), target_branch)
            commit_list = get_list_commit_SHA(
                f"{remote_prefix}{target_branch}..{base_commit}"
            )
            if commit_list:
                return commit_list, ci_mode

    previous_commit = None
    previous_commit_var = CI_PREVIOUS_COMMIT_VAR.get(ci_mode)
    if previous_commit_var:
        previous_commit = os.getenv(previous_commit_var)
        if (
            previous_commit is None or previous_commit == EMPTY_SHA
        ) and ci_mode == SupportedCI.GITHUB:
            previous_commit = os.getenv("GITHUB_DEFAULT_BRANCH")
        if (
            previous_commit is not None
            and previous_commit != EMPTY_SHA
            and not previous_commit.startswith("...")
        ):
            ui.display_verbose(
                f"\tIdentified previous commit or commit range as {previous_commit}"
            )
            if ci_mode in [SupportedCI.CIRCLECI, SupportedCI.TRAVIS]:
                # for these ci envs, previous_commit is a range of commits
                commit_range = previous_commit
            elif ci_mode == SupportedCI.GITLAB:
                commit_range = f"{previous_commit}~1..{base_commit}"
            else:
                commit_range = f"{previous_commit}..{base_commit}"
            commit_list = get_list_commit_SHA(commit_range)
            if commit_list:
                return commit_list, ci_mode

    commit_list = get_list_commit_SHA(f"{base_commit}~1...")
    if commit_list:
        return commit_list, ci_mode

    raise UnexpectedError(
        "Unable to get commit range. Please submit an issue with the following info:\n"
        "  Repository URL: <Fill if public>\n"
        f"  CI_TYPE: {ci_mode.value}\n"
        f"  TARGET_BRANCH: {target_branch}\n"
        f"  PREVIOUS_COMMIT: {previous_commit}\n"
        f"  BASE_COMMIT: {base_commit}"
    )
