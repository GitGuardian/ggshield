from ggshield.utils.git_shell import check_git_dir

from ... import ui
from .commit_range import collect_commit_range_from_ci_env
from .previous_commit import get_previous_commit_from_ci_env


def get_current_and_previous_state_from_ci_env():
    """
    Returns the current commit sha and the previous commit sha of the targeted
    branch in a CI env
    """
    check_git_dir()

    new_commits, _ = collect_commit_range_from_ci_env()
    previous_commit = get_previous_commit_from_ci_env()

    if not new_commits:
        current_commit = "HEAD"
    else:
        current_commit = new_commits[-1]

    if new_commits:
        ui.display_verbose("List of new commits: ")
        for commit in new_commits:
            ui.display_verbose(f"- {commit}")

    ui.display_verbose(
        f"Comparing commit {current_commit} to commit {previous_commit}",
    )

    return current_commit, previous_commit
