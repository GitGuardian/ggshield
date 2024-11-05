import os
from pathlib import Path
from typing import Dict, Optional, Tuple, Union

from ggshield.core import ui
from ggshield.core.errors import NotAMergeRequestError, UnexpectedError
from ggshield.utils.git_shell import get_commits_not_in_branch, get_remotes

from .supported_ci import SupportedCI


def travis_scan_ci_args() -> Tuple[str, str]:
    if "TRAVIS_PULL_REQUEST" not in os.environ:
        raise NotAMergeRequestError()
    try:
        commit_range = os.environ["TRAVIS_COMMIT_RANGE"]
        first_commit, last_commit = commit_range.split("..")
        return last_commit, first_commit + "~1"
    except Exception as exc:
        raise UnexpectedError("Failed to extract scan ci arguments for travis") from exc


# Note: this does not exist (yet ?) for CircleCI, see
# https://circleci.canny.io/config/p/provide-env-variable-for-branch-name-targeted-by-pull-request
CI_TARGET_BRANCH_ASSOC: Dict[SupportedCI, str] = {
    SupportedCI.GITHUB: "GITHUB_BASE_REF",
    SupportedCI.GITLAB: "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
    SupportedCI.JENKINS: "CHANGE_TARGET",
    SupportedCI.AZURE: "SYSTEM_PULLREQUEST_TARGETBRANCHNAME",
    SupportedCI.BITBUCKET: "BITBUCKET_PR_DESTINATION_BRANCH",
    SupportedCI.DRONE: "DRONE_COMMIT_BRANCH",
}


def get_remote_prefix(wd: Optional[Union[str, Path]] = None) -> str:
    remotes = get_remotes(wd=wd)
    if len(remotes) == 0:
        # note: this should not happen in practice, esp. in a CI job
        ui.display_verbose("\tNo remote found.")
        return ""
    else:
        ui.display_verbose(f"\tUsing first remote {remotes[0]}.")
        return f"{remotes[0]}/"


def get_scan_ci_parameters(
    current_ci: SupportedCI, wd: Optional[Union[str, Path]] = None
) -> Union[Tuple[str, str], None]:
    """
    Function used to gather current commit and reference commit, for the SCA/IaC scan
    ci commands.
    Return:
      - a tuple (current_commit, reference commit) in the nominal case
      - or None if the MR has no associated commits
        (i.e. the mr branch has no new commit compared to the target branch)

    Note: this function will not work (i.e. probably raise) if the git directory is a shallow clone
    """
    ui.display_verbose(f"\tIdentified current ci as {current_ci.value}")

    if current_ci == SupportedCI.TRAVIS:
        return travis_scan_ci_args()

    remote_prefix = get_remote_prefix(wd=wd)
    target_branch_var = CI_TARGET_BRANCH_ASSOC.get(current_ci)
    if not target_branch_var:
        raise UnexpectedError(f"Using scan ci is not supported for {current_ci.value}.")

    if not os.getenv(target_branch_var):
        raise NotAMergeRequestError()
    target_branch = remote_prefix + os.environ[target_branch_var]

    mr_tip = "HEAD"
    if current_ci == SupportedCI.GITHUB:
        # - GitHub pipelines are all merge results
        # - GITHUB_BASE_REF and GITHUB_HEAD_REF are always set together
        #   "when the event that triggers a workflow run is either pull_request or pull_request_target"
        mr_tip = remote_prefix + os.environ["GITHUB_HEAD_REF"]
    if current_ci == SupportedCI.GITLAB:
        # Handles gitlab's MR, whether merge results pipelines are enabled or not
        mr_tip = remote_prefix + os.environ["CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"]

    mr_commits = get_commits_not_in_branch(
        current_tip=mr_tip, target_branch=target_branch, wd=wd
    )
    if len(mr_commits) == 0:
        return None

    current_commit = mr_commits[0]
    reference_commit = mr_commits[-1] + "~1"
    ui.display_verbose(
        (
            f"\tIdentified current commit as {current_commit}\n"
            f"\tIdentified reference commit as {reference_commit}"
        )
    )

    return current_commit, reference_commit
