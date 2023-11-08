import os
from typing import Optional

from ggshield.core.git_hooks.ci.supported_ci import SupportedCI
from ggshield.utils.git_shell import simplify_git_url


def get_repository_url_from_ci() -> Optional[str]:
    supported_ci = SupportedCI.from_ci_env()
    if supported_ci == SupportedCI.AZURE:
        repository_url = os.getenv("BUILD_REPOSITORY_URI")
    elif supported_ci == SupportedCI.DRONE:
        repository_url = os.getenv("DRONE_REPO_LINK")
    elif supported_ci == SupportedCI.GITHUB:
        domain = os.getenv("GITHUB_SERVER_URL")
        slug = os.getenv("GITHUB_REPOSITORY")
        repository_url = f"{domain}/{slug}" if domain and slug else None
    elif supported_ci == SupportedCI.GITLAB:
        repository_url = os.getenv("CI_REPOSITORY_URL")
    elif supported_ci == SupportedCI.CIRCLECI:
        repository_url = os.getenv("CIRCLE_REPOSITORY_URL")
    elif supported_ci == SupportedCI.BITBUCKET:
        repository_url = os.getenv("BITBUCKET_GIT_HTTP_ORIGIN")
    # TRAVIS_REPO_SLUG does not provide the domain name
    # JENKINS provides nothing
    else:
        repository_url = None

    if not repository_url:
        return None
    return simplify_git_url(repository_url)
