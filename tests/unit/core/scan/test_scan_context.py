import os
from pathlib import Path
from typing import Union
from unittest import mock

import pytest

from ggshield.core.scan.scan_context import ScanContext
from ggshield.core.scan.scan_mode import ScanMode
from tests.repository import Repository


DOMAIN = "https://github.com"
SLUG = "from-env/repository"
ENV_REPO_URL = f"{DOMAIN}/{SLUG}"
EXPECTED_HEADER_ENV = "github.com/from-env/repository"

REMOTE_URL = "https://github.com/from-remote/repository"
FULL_REMOTE_URL = "https://user:password@github.com:84/from-remote/repository.git"
EXPECTED_HEADER_REMOTE = "github.com/from-remote/repository"


@pytest.fixture(scope="module")
def fake_url_repo(tmp_path_factory: pytest.TempPathFactory) -> Repository:
    repo = Repository.create(tmp_path_factory.mktemp("fake_url_repo"))
    repo.git("remote", "add", "origin", REMOTE_URL)
    return repo


def _assert_repo_url_in_headers(context: ScanContext, expected_url: Union[Path, str]):
    assert context.get_http_headers().get("GGShield-Repository-URL") == str(
        expected_url
    )


def _assert_no_repo_url_in_headers(context: ScanContext):
    assert context.get_http_headers().get("GGShield-Repository-URL") is None


def test_scan_context_no_repo(
    tmp_path: Path,
):
    """
    GIVEN a directory which is not a git repo
    WHEN passing the local path to the scan context
    THEN there is no GGShield-Repository-URL in the headers
    """
    context = ScanContext(
        scan_mode=ScanMode.PATH,
        command_path="ggshield secret scan path",
        target_path=tmp_path,
    )
    _assert_no_repo_url_in_headers(context)


def test_scan_context_repository_url_parsed(fake_url_repo: Repository):
    """
    GIVEN a repository with a remote (url)
    WHEN passing the local path to the scan context
    THEN the remote url is found and simplified
    """
    context = ScanContext(
        scan_mode=ScanMode.PATH,
        command_path="ggshield secret scan path",
        target_path=fake_url_repo.path,
    )
    _assert_repo_url_in_headers(context, EXPECTED_HEADER_REMOTE)


@pytest.mark.parametrize(
    "env",
    (
        {"BUILD_BUILDID": "1", "BUILD_REPOSITORY_URI": ENV_REPO_URL},
        {"DRONE": "1", "DRONE_REPO_LINK": ENV_REPO_URL},
        {
            "GITHUB_ACTIONS": "1",
            "GITHUB_SERVER_URL": DOMAIN,
            "GITHUB_REPOSITORY": SLUG,
        },
        {"GITLAB_CI": "1", "CI_REPOSITORY_URL": ENV_REPO_URL},
        {"CIRCLECI": "1", "CIRCLE_REPOSITORY_URL": ENV_REPO_URL},
        {"BITBUCKET_COMMIT": "1", "BITBUCKET_GIT_HTTP_ORIGIN": ENV_REPO_URL},
    ),
)
def test_ci_repo_found(env, fake_url_repo: Repository) -> None:
    """
    GIVEN a repository with a remote url
    WHEN a repository url is found in the CI environment
    THEN it is sent instead of the remote url
    """
    with mock.patch.dict(os.environ, env, clear=True):
        context = ScanContext(
            scan_mode=ScanMode.CI,
            command_path="ggshield secret scan path",
            target_path=fake_url_repo.path,
        )
        _assert_repo_url_in_headers(context, EXPECTED_HEADER_ENV)


@pytest.mark.parametrize(
    "env",
    (
        {"BUILD_BUILDID": "1"},
        {"DRONE": "1"},
        {"GITHUB_ACTIONS": "1"},
        {"GITLAB_CI": "1"},
        {"CIRCLECI": "1"},
        {"BITBUCKET_COMMIT": "1"},
    ),
)
def test_ci_no_env(env, fake_url_repo: Repository) -> None:
    """
    GIVEN a repository with a remote url
    WHEN there is no repository url in the environment
    THEN the remote url is sent by default
    """
    # Copying the path is needed for windows to find git
    environ = {"PATH": os.environ.get("PATH"), **env}
    with mock.patch.dict(os.environ, environ, clear=True):
        context = ScanContext(
            scan_mode=ScanMode.PATH,
            command_path="ggshield secret scan path",
            target_path=fake_url_repo.path,
        )
        _assert_repo_url_in_headers(context, EXPECTED_HEADER_REMOTE)
