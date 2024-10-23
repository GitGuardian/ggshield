import logging
import os
import sys
from typing import Optional, Tuple

from ggshield.core import ui
from ggshield.core.errors import UnexpectedError
from ggshield.utils.git_shell import EMPTY_SHA, git
from ggshield.utils.os import getenv_float, getenv_int


logger = logging.getLogger(__name__)


# GitHub timeouts every pre-receive hook after 5s with an error.
# We try and anticipate that so we can control the return code
PRERECEIVE_TIMEOUT = 4.5


BYPASS_MESSAGE = """\n     git push -o breakglass"""


def get_prereceive_timeout() -> float:
    try:
        return getenv_float("GITGUARDIAN_TIMEOUT", PRERECEIVE_TIMEOUT)
    except BaseException as e:
        ui.display_error(f"Unable to parse GITGUARDIAN_TIMEOUT: {str(e)}")
        return PRERECEIVE_TIMEOUT


def get_breakglass_option() -> bool:
    """Test all options passed to git for `breakglass`"""
    option_count = getenv_int("GIT_PUSH_OPTION_COUNT")
    if option_count is not None:
        for option in range(option_count):
            if os.getenv(f"GIT_PUSH_OPTION_{option}", "") == "breakglass":
                ui.display_info(
                    "SKIP: breakglass detected. Skipping GitGuardian pre-receive hook."
                )
                return True

    return False


def find_branch_start(commit: str) -> Optional[str]:
    """
    Returns the first local-only commit of the branch.
    Returns None if the branch does not contain any new commit.
    """
    # List all ancestors of `commit` which are not in any branches
    output = git(
        ["rev-list", commit, "--topo-order", "--reverse", "--not", "--branches"]
    )
    ancestors = output.splitlines()

    if ancestors:
        return ancestors[0]
    return None


def parse_stdin() -> Optional[Tuple[str, str]]:
    """
    Parse stdin and return the first and last commit to scan,
    or None if there is nothing to do, allowing for early stopping.
    """
    prereceive_input = sys.stdin.read().strip()
    if not prereceive_input:
        raise UnexpectedError(f"Invalid input arguments: '{prereceive_input}'")

    # TODO There can be more than one line here, for example when pushing multiple
    # branches. We should support this.
    line = prereceive_input.splitlines()[0]
    logger.debug("stdin: %s", line)
    _old_commit, new_commit, _ = line.split(maxsplit=2)

    if new_commit == EMPTY_SHA:
        # Deletion event, nothing to do
        ui.display_info("Deletion event or nothing to scan.")
        return None

    # ignore _old_commit because in case of a force-push, it is going to be overwritten
    # and should not be scanned (see #437)
    start_commit = find_branch_start(new_commit)
    if start_commit is None:
        # branch does not contain any new commit
        old_commit = new_commit
    else:
        old_commit = f"{start_commit}~1"

    assert old_commit != EMPTY_SHA
    assert new_commit != EMPTY_SHA
    if old_commit == new_commit:
        ui.display_info("Pushed branch does not contain any new commit.")
        return None

    return (old_commit, new_commit)
