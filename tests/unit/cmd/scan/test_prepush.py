from pathlib import Path
from unittest.mock import ANY, Mock, patch

import pytest
from click.testing import CliRunner

from ggshield.__main__ import cli
from ggshield.cmd.secret.scan.secret_scan_common_options import (
    IGNORED_DEFAULT_WILDCARDS,
)
from ggshield.core.errors import (
    ExitCode,
    QuotaLimitReachedError,
    ServiceUnavailableError,
)
from ggshield.core.filter import init_exclusion_regexes
from ggshield.core.scan import ScanContext, ScanMode
from ggshield.utils.git_shell import EMPTY_SHA, EMPTY_TREE
from ggshield.utils.os import cd
from tests.repository import Repository
from tests.unit.conftest import assert_invoke_exited_with, assert_invoke_ok


def create_local_repo_with_remote(work_dir: Path) -> Repository:
    remote_repo_path = work_dir / "remote"
    remote_repo = Repository.create(remote_repo_path)
    remote_repo.create_commit("initial commit")

    local_repo_path = work_dir / "local"
    local_repo = Repository.clone(str(remote_repo_path), local_repo_path)

    return local_repo


class TestPrepush:
    @patch("ggshield.cmd.secret.scan.prepush.get_list_commit_SHA")
    def test_prepush_no_commits(self, get_list_mock: Mock, cli_fs_runner: CliRunner):
        """
        GIVEN a prepush range with 0 commits
        WHEN the command is run
        THEN it should return 0 and warn it was unable to get range
        """
        get_list_mock.return_value = []
        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-push"],
            env={"PRE_COMMIT_FROM_REF": "a" * 40, "PRE_COMMIT_TO_REF": "b" * 40},
        )
        assert_invoke_ok(result)
        assert "Unable to get commit range." in result.output

    @patch("ggshield.cmd.secret.scan.prepush.scan_commit_range")
    def test_prepush_no_commits_stdin(
        self,
        scan_commit_range_mock: Mock,
        tmp_path,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a repository
        AND a new branch pushed from another repository, without any commit
        WHEN the pre-push command is run on the commits from the push
        THEN it scans nothing
        """
        local_repo = create_local_repo_with_remote(tmp_path)

        branch = "topic"
        local_repo.create_branch(branch)

        sha = local_repo.get_top_sha()

        with cd(str(local_repo.path)):
            result = cli_fs_runner.invoke(
                cli,
                ["-v", "secret", "scan", "pre-push", "origin", local_repo.remote_url],
                input=f"refs/heads/master {sha} refs/heads/master {EMPTY_SHA}\n",
            )

        assert_invoke_ok(result)
        scan_commit_range_mock.assert_not_called()
        assert "Unable to get commit range." in result.output

    @patch("ggshield.cmd.secret.scan.prepush.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prepush.scan_commit_range")
    @patch("ggshield.cmd.secret.scan.prepush.check_git_dir")
    def test_prepush_too_many(
        self,
        check_dir_mock: Mock,
        scan_commit_range_mock: Mock,
        get_list_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a prepush range with 51 commits
        WHEN the command is run
        THEN it should return 0 warn too many commits for scanning, and scan last 50
        """
        scan_commit_range_mock.return_value = 0
        get_list_mock.return_value = ["a"] * 51
        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-push"],
            env={"PRE_COMMIT_FROM_REF": "a" * 40, "PRE_COMMIT_TO_REF": "b" * 40},
        )
        assert_invoke_ok(result)
        scan_commit_range_mock.assert_called_once()
        _, kwargs = scan_commit_range_mock.call_args_list[0]
        assert len(kwargs["commit_list"]) == 50
        assert "Too many commits. Scanning last 50" in result.output

    @patch("ggshield.cmd.secret.scan.prepush.scan_commit_range")
    @pytest.mark.parametrize(
        ["local_ref_env_var", "remote_ref_env_var"],
        [
            pytest.param(
                "PRE_COMMIT_SOURCE",
                "PRE_COMMIT_ORIGIN",
                id="old env names",
            ),
            pytest.param(
                "PRE_COMMIT_FROM_REF",
                "PRE_COMMIT_TO_REF",
                id="new env names",
            ),
        ],
    )
    def test_prepush_pre_commit_framework(
        self,
        scan_commit_range_mock: Mock,
        tmp_path,
        cli_fs_runner: CliRunner,
        local_ref_env_var: str,
        remote_ref_env_var: str,
    ):
        """
        GIVEN a prepush range with 20 commits provided by the pre-commit framework
        WHEN the command is run
        THEN it should pass onto scan and return 0
        AND the `exclusion_regexes` argument of the scan_commit_range() call should
        match IGNORED_DEFAULT_WILDCARDS
        """
        local_repo = create_local_repo_with_remote(tmp_path)
        remote_sha = local_repo.get_top_sha()
        shas = [local_repo.create_commit() for _ in range(20)]

        scan_commit_range_mock.return_value = 0

        env = {local_ref_env_var: shas[-1], remote_ref_env_var: remote_sha}

        with cd(str(local_repo.path)):
            result = cli_fs_runner.invoke(
                cli,
                [
                    "-v",
                    "secret",
                    "scan",
                    "pre-push",
                    "origin",
                    "https://example.com/remote",
                ],
                env=env,
            )

        scan_commit_range_mock.assert_called_once_with(
            client=ANY,
            cache=ANY,
            commit_list=shas,
            output_handler=ANY,
            exclusion_regexes=ANY,
            scan_context=ScanContext(
                scan_mode=ScanMode.PRE_PUSH,
                command_path="cli secret scan pre-push",
                target_path=local_repo.path,
                endpoint_registration=True,
            ),
            secret_config=ANY,
        )
        assert_invoke_ok(result)
        assert "Commits to scan: 20" in result.output

        expected_exclusion_regexes = init_exclusion_regexes(IGNORED_DEFAULT_WILDCARDS)
        expected_exclusion_patterns = [r.pattern for r in expected_exclusion_regexes]
        result_exclusion_regexes = scan_commit_range_mock.call_args_list[0][1][
            "exclusion_regexes"
        ]
        result_exclusion_patterns = [r.pattern for r in result_exclusion_regexes]

        assert sorted(result_exclusion_patterns) == sorted(expected_exclusion_patterns)

    @patch("ggshield.cmd.secret.scan.prepush.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prepush.scan_commit_range")
    @patch("ggshield.cmd.secret.scan.prepush.check_git_dir")
    def test_prepush_stdin_input_empty(
        self,
        check_dir_mock: Mock,
        scan_commit_range_mock: Mock,
        get_list_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN an empty stdin input
        WHEN the command is run
        THEN it should print nothing to scan and return 0
        """

        result = cli_fs_runner.invoke(
            cli,
            [
                "-v",
                "secret",
                "scan",
                "pre-push",
                "origin",
                "https://example.com/remote",
            ],
            input="",
        )
        assert_invoke_ok(result)
        assert "Deletion event or nothing to scan.\n" in result.output

    @patch("ggshield.cmd.secret.scan.prepush.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prepush.scan_commit_range")
    @patch("ggshield.cmd.secret.scan.prepush.check_git_dir")
    def test_prepush_new_branch_pre_commit_framework(
        self,
        check_dir_mock: Mock,
        scan_commit_range_mock: Mock,
        get_list_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a target commit of EMPTY_SHA
        WHEN the command is run
        THEN it should warn of new branch and return 0
        """
        scan_commit_range_mock.return_value = 0
        get_list_mock.return_value = ["a" for _ in range(60)]

        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-push"],
            env={"PRE_COMMIT_FROM_REF": "a" * 40, "PRE_COMMIT_TO_REF": EMPTY_SHA},
        )
        assert_invoke_ok(result)
        get_list_mock.assert_called_once_with(f"{EMPTY_TREE} {'a' * 40}", max_count=51)
        scan_commit_range_mock.assert_called_once()

        assert "New tree event. Scanning last 50 commits" in result.output
        assert "Commits to scan: 50" in result.output

    @patch("ggshield.cmd.secret.scan.prepush.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prepush.scan_commit_range")
    @patch("ggshield.cmd.secret.scan.prepush.check_git_dir")
    def test_prepush_deletion(
        self,
        check_dir_mock: Mock,
        scan_commit_range_mock: Mock,
        get_list_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN an origin commit of EMPTY_SHA
        WHEN the command is run
        THEN it should warn of new branch and return 0
        """
        scan_commit_range_mock.return_value = 0
        get_list_mock.return_value = ["a" for _ in range(10)]

        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-push"],
            env={"PRE_COMMIT_FROM_REF": EMPTY_SHA, "PRE_COMMIT_TO_REF": "a" * 40},
        )
        assert_invoke_ok(result)
        assert "Deletion event or nothing to scan.\n" in result.output

    @patch("ggshield.cmd.secret.scan.prepush.scan_commit_range")
    def test_prepush_stdin_input_no_newline(
        self,
        scan_commit_range_mock: Mock,
        tmp_path,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN 20 commits through stdin input
        WHEN the command is run
        THEN it should pass onto scan and return 0
        """
        local_repo = create_local_repo_with_remote(tmp_path)
        remote_sha = local_repo.get_top_sha()
        shas = [local_repo.create_commit() for _ in range(20)]

        scan_commit_range_mock.return_value = 0

        with cd(str(local_repo.path)):
            result = cli_fs_runner.invoke(
                cli,
                [
                    "-v",
                    "secret",
                    "scan",
                    "pre-push",
                    "origin",
                    "https://example.com/remote",
                ],
                input=f"refs/heads/main {shas[-1]} refs/heads/main {remote_sha}",
            )
        assert_invoke_ok(result)
        scan_commit_range_mock.assert_called_once()
        assert "Commits to scan: 20" in result.output

    @pytest.mark.parametrize(
        ["called_with_pre_push_args"],
        [
            (True,),
            (False,),
        ],
    )
    @patch("ggshield.cmd.secret.scan.prepush.scan_commit_range")
    def test_prepush_new_branch(
        self,
        scan_commit_range_mock: Mock,
        tmp_path,
        cli_fs_runner: CliRunner,
        called_with_pre_push_args: bool,
    ):
        """
        GIVEN a cloned repository
        AND a local branch with new commits in it
        WHEN the command is run
        THEN it should only scan the new commits
        """
        local_repo = create_local_repo_with_remote(tmp_path)

        branch = "topic"
        local_repo.create_branch(branch)
        shas = [local_repo.create_commit() for _ in range(3)]

        scan_commit_range_mock.return_value = 0

        cmd = ["-v", "secret", "scan", "pre-push"]
        if called_with_pre_push_args:
            cmd.extend(["origin", local_repo.remote_url])
        with cd(str(local_repo.path)):
            result = cli_fs_runner.invoke(
                cli,
                cmd,
                input=f"refs/heads/{branch} {shas[-1]} refs/heads/{branch} {EMPTY_SHA}\n",
            )

        assert_invoke_ok(result)
        scan_commit_range_mock.assert_called_once_with(
            client=ANY,
            cache=ANY,
            commit_list=shas,
            output_handler=ANY,
            exclusion_regexes=ANY,
            scan_context=ANY,
            secret_config=ANY,
        )

    @patch("ggshield.cmd.secret.scan.prepush.scan_commit_range")
    def test_prepush_new_orphan_branch(
        self,
        scan_commit_range_mock: Mock,
        tmp_path,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a cloned repository
        AND an orphan branch with commits in it
        WHEN the command is run
        THEN it should only scan the orphan branch commits
        """
        local_repo = create_local_repo_with_remote(tmp_path)

        branch = "topic"
        local_repo.create_branch(branch, orphan=True)
        shas = [local_repo.create_commit() for _ in range(3)]

        scan_commit_range_mock.return_value = 0

        with cd(str(local_repo.path)):
            result = cli_fs_runner.invoke(
                cli,
                ["-v", "secret", "scan", "pre-push", "origin", local_repo.remote_url],
                input=f"refs/heads/{branch} {shas[-1]} refs/heads/{branch} {EMPTY_SHA}\n",
            )

        assert_invoke_ok(result)
        scan_commit_range_mock.assert_called_once_with(
            client=ANY,
            cache=ANY,
            commit_list=shas,
            output_handler=ANY,
            exclusion_regexes=ANY,
            scan_context=ANY,
            secret_config=ANY,
        )

    @patch("ggshield.cmd.secret.scan.prepush.scan_commit_range")
    def test_remediation_message(
        self,
        scan_commit_range_mock: Mock,
        tmp_path,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN some commits
        WHEN the command is run and some secrets are found
        THEN the remediation message is present in the output
        """
        local_repo = create_local_repo_with_remote(tmp_path)
        remote_sha = local_repo.get_top_sha()
        shas = [local_repo.create_commit() for _ in range(20)]

        scan_commit_range_mock.return_value = ExitCode.SCAN_FOUND_PROBLEMS

        with cd(str(local_repo.path)):
            result = cli_fs_runner.invoke(
                cli,
                [
                    "-v",
                    "secret",
                    "scan",
                    "pre-push",
                    "origin",
                    "https://example.com/remote",
                ],
                input=f"refs/heads/main {shas[-1]} refs/heads/main {remote_sha}",
            )
        assert_invoke_exited_with(result, ExitCode.SCAN_FOUND_PROBLEMS)
        scan_commit_range_mock.assert_called_once()
        assert "Commits to scan: 20" in result.output

        assert (
            """
> How to remediate

  Since the secret was detected before the push BUT after the commit, you need to:
  1. rewrite the git history making sure to replace the secret with its reference (e.g. environment variable).
  2. push again.

  To prevent having to rewrite git history in the future, setup ggshield as a pre-commit hook:
    https://docs.gitguardian.com/ggshield-docs/integrations/git-hooks/pre-commit

> [To apply with caution] If you want to bypass ggshield (false positive or other reason), run:
  - if you use the pre-commit framework:

    SKIP=ggshield-push git push"""
            in result.output
        )

    @patch("ggshield.cmd.secret.scan.prepush.check_git_dir")
    @patch("ggshield.cmd.secret.scan.prepush.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prepush.scan_commit_range")
    def test_server_unavailable_default_blocks(
        self,
        scan_commit_range_mock: Mock,
        get_list_mock: Mock,
        check_dir_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a prepush range with commits
        AND the default configuration (fail_on_server_error=True)
        WHEN the server returns a 5xx error
        THEN the command exits with GITGUARDIAN_SERVER_UNAVAILABLE
        """
        scan_commit_range_mock.side_effect = ServiceUnavailableError(
            message="GitGuardian server is not responding.\nDetails: 503",
        )
        get_list_mock.return_value = ["a"] * 3
        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-push"],
            env={"PRE_COMMIT_FROM_REF": "a" * 40, "PRE_COMMIT_TO_REF": "b" * 40},
        )
        assert_invoke_exited_with(result, ExitCode.GITGUARDIAN_SERVER_UNAVAILABLE)
        assert "Skipping ggshield checks" not in result.output

    @patch("ggshield.cmd.secret.scan.prepush.check_git_dir")
    @patch("ggshield.cmd.secret.scan.prepush.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prepush.scan_commit_range")
    def test_server_unavailable_opt_in_fail_open(
        self,
        scan_commit_range_mock: Mock,
        get_list_mock: Mock,
        check_dir_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a prepush range with commits
        AND --no-fail-on-server-error is passed
        WHEN the server returns a 5xx error
        THEN it should return 0
        AND display an error message about skipping checks
        """
        scan_commit_range_mock.side_effect = ServiceUnavailableError(
            message="GitGuardian server is not responding.\nDetails: 503",
        )
        get_list_mock.return_value = ["a"] * 3
        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-push", "--no-fail-on-server-error"],
            env={"PRE_COMMIT_FROM_REF": "a" * 40, "PRE_COMMIT_TO_REF": "b" * 40},
        )
        assert_invoke_ok(result)
        assert "Skipping ggshield checks" in result.output

    @patch("ggshield.cmd.secret.scan.prepush.check_git_dir")
    @patch("ggshield.cmd.secret.scan.prepush.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prepush.scan_commit_range")
    def test_connection_error_opt_in_fail_open(
        self,
        scan_commit_range_mock: Mock,
        get_list_mock: Mock,
        check_dir_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a prepush range with commits
        AND GITGUARDIAN_FAIL_ON_SERVER_ERROR=false
        WHEN the server is not reachable (ConnectionError)
        THEN it should return 0
        AND display an error message about skipping checks
        """
        scan_commit_range_mock.side_effect = ServiceUnavailableError(
            message="Failed to connect to GitGuardian server.",
        )
        get_list_mock.return_value = ["a"] * 3
        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-push"],
            env={
                "PRE_COMMIT_FROM_REF": "a" * 40,
                "PRE_COMMIT_TO_REF": "b" * 40,
                "GITGUARDIAN_FAIL_ON_SERVER_ERROR": "false",
            },
        )
        assert_invoke_ok(result)
        assert "Skipping ggshield checks" in result.output

    @patch("ggshield.cmd.secret.scan.prepush.check_git_dir")
    @patch("ggshield.cmd.secret.scan.prepush.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prepush.scan_commit_range")
    def test_quota_error_still_fails_with_flag(
        self,
        scan_commit_range_mock: Mock,
        get_list_mock: Mock,
        check_dir_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN --no-fail-on-server-error is passed
        WHEN the server returns a non-5xx error (e.g. quota reached)
        THEN the command still fails
        """
        scan_commit_range_mock.side_effect = QuotaLimitReachedError()
        get_list_mock.return_value = ["a"] * 3
        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-push", "--no-fail-on-server-error"],
            env={"PRE_COMMIT_FROM_REF": "a" * 40, "PRE_COMMIT_TO_REF": "b" * 40},
        )
        assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
