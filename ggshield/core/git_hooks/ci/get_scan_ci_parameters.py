from pathlib import Path
from typing import Dict, Optional, Union

from ggshield.core import ui
from ggshield.utils.git_shell import get_remotes

from .supported_ci import SupportedCI


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
