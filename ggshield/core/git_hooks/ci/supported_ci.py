import os
from enum import Enum

from ggshield.core.errors import UnexpectedError


class SupportedCI(Enum):
    GITLAB = "GITLAB"
    TRAVIS = "TRAVIS"
    CIRCLECI = "CIRCLECI"
    JENKINS = "JENKINS HOME"
    GITHUB = "GITHUB ACTIONS"
    BITBUCKET = "BITBUCKET PIPELINES"
    DRONE = "DRONE"
    AZURE = "AZURE PIPELINES"

    @staticmethod
    def from_ci_env() -> "SupportedCI":
        if os.getenv("GITLAB_CI"):
            return SupportedCI.GITLAB
        if os.getenv("GITHUB_ACTIONS"):
            return SupportedCI.GITHUB
        if os.getenv("TRAVIS"):
            return SupportedCI.TRAVIS
        if os.getenv("JENKINS_HOME") or os.getenv("JENKINS_URL"):
            return SupportedCI.JENKINS
        if os.getenv("CIRCLECI"):
            return SupportedCI.CIRCLECI
        if os.getenv("BITBUCKET_COMMIT"):
            return SupportedCI.BITBUCKET
        if os.getenv("DRONE"):
            return SupportedCI.DRONE
        if os.getenv("BUILD_BUILDID"):
            return SupportedCI.AZURE

        raise UnexpectedError(
            f"Current CI is not detected or supported."
            f" Supported CIs: {', '.join([ci.value for ci in SupportedCI])}."
        )
