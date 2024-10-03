import pytest

from ggshield.core.errors import NotAMergeRequestError, UnexpectedError
from ggshield.core.git_hooks.ci.get_scan_ci_parameters import (
    CI_TARGET_BRANCH_ASSOC,
    get_scan_ci_parameters,
)
from ggshield.core.git_hooks.ci.supported_ci import SupportedCI
from tests.repository import Repository


class TestGetScanCIParameters:

    @pytest.fixture(autouse=True)
    def git_repo(self, tmp_path):
        repo = Repository.create(tmp_path)
        repo.create_commit()

        first_file_name = "first.py"

        # add a commit
        first_file = repo.path / first_file_name
        first_content = "First file (included)"
        first_file.write_text(first_content)
        repo.add(first_file_name)
        self.ref_commit = repo.create_commit()

        repo.create_branch("mr_branch")
        self.repo = repo

    @pytest.mark.parametrize(
        "ci",
        (
            SupportedCI.JENKINS,
            SupportedCI.AZURE,
            SupportedCI.BITBUCKET,
            SupportedCI.DRONE,
        ),
    )
    def test_regular_pipeline(self, ci, monkeypatch):
        """
        GIVEN a ci env
        WHEN calling get_scan_ci_parameters
        THEN the parameters are returned
        """
        repo = self.repo
        monkeypatch.setenv(CI_TARGET_BRANCH_ASSOC[ci], "main")
        first_commit = repo.create_commit()
        last_commit = repo.create_commit()
        params = get_scan_ci_parameters(ci, wd=repo.path)
        assert params == (last_commit, f"{first_commit}~1")

    def test_gitlab_ci(self, monkeypatch):
        """
        GIVEN a gitlab ci env
        WHEN calling get_scan_ci_parameters
        THEN the parameters are returned
        """
        repo = self.repo
        monkeypatch.setenv(CI_TARGET_BRANCH_ASSOC[SupportedCI.GITLAB], "main")
        monkeypatch.setenv("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME", "mr_branch")
        first_commit = repo.create_commit()
        last_commit = repo.create_commit()
        params = get_scan_ci_parameters(SupportedCI.GITLAB, wd=repo.path)
        assert params == (last_commit, f"{first_commit}~1")

    def test_github_ci(self, monkeypatch):
        """
        GIVEN a  github ci env
        WHEN calling get_scan_ci_parameters
        THEN the parameters are returned
        """
        repo = self.repo
        monkeypatch.setenv(CI_TARGET_BRANCH_ASSOC[SupportedCI.GITHUB], "main")
        monkeypatch.setenv("GITHUB_HEAD_REF", "mr_branch")
        first_commit = repo.create_commit()
        last_commit = repo.create_commit()

        repo.create_branch("simulate_merge_commit")
        repo.create_commit()
        params = get_scan_ci_parameters(SupportedCI.GITHUB, wd=repo.path)
        assert params == (last_commit, f"{first_commit}~1")

    def test_travis_ci(self, monkeypatch):
        """
        GIVEN a travis ci env
        WHEN calling get_scan_ci_parameters
        THEN the parameters are returned
        """
        repo = self.repo
        first_commit = repo.create_commit()
        last_commit = repo.create_commit()
        monkeypatch.setenv("TRAVIS_PULL_REQUEST", "1")
        monkeypatch.setenv("TRAVIS_COMMIT_RANGE", f"{first_commit}..{last_commit}")
        params = get_scan_ci_parameters(SupportedCI.TRAVIS, wd=repo.path)
        assert params == (last_commit, f"{first_commit}~1")

    @pytest.mark.parametrize(
        "ci",
        [ci for ci in SupportedCI if ci != SupportedCI.CIRCLECI],
    )
    def test_not_a_merge_request_error_is_raised(self, ci, monkeypatch):
        """
        GIVEN a ci (excluding CircleCI)
        WHEN no merge-request related env var is set
        THEN NotAMergeRequestError is raised
        """
        # we unset variables that may be set by the CI in which tests are run
        monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
        monkeypatch.delenv("GITHUB_HEAD_REF", raising=False)
        with pytest.raises(NotAMergeRequestError):
            get_scan_ci_parameters(ci, wd=self.repo.path)

    def test_circleci_not_supported(self):
        """
        GIVEN -
        WHEN calling get scan_ci_parameters for circleci
        THEN an UnexpectedError is raised
        """
        with pytest.raises(
            UnexpectedError, match="Using scan ci is not supported for CIRCLECI"
        ):
            get_scan_ci_parameters(SupportedCI.CIRCLECI, wd=self.repo.path)
