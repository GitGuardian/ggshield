from unittest.mock import ANY, Mock, patch

import pytest
from click.testing import CliRunner
from pygitguardian.models import Detail

from ggshield.__main__ import cli
from ggshield.core.config.user_config import SecretConfig
from ggshield.core.errors import ExitCode
from ggshield.core.scan import StringScannable
from ggshield.utils.git_shell import EMPTY_SHA, Filemode
from ggshield.utils.os import cd
from ggshield.verticals.secret import Result, Results, SecretScanCollection
from tests.repository import Repository, create_pre_receive_repo
from tests.unit.conftest import (
    _SIMPLE_SECRET_PATCH,
    _SIMPLE_SECRET_PATCH_SCAN_RESULT,
    _SIMPLE_SECRET_TOKEN,
    assert_invoke_exited_with,
    assert_invoke_ok,
)


def contains_secret(line: str, secret: str) -> bool:
    """Returns True if `line` contains an obfuscated version of `secret`"""
    return f'"{secret[:6]}' in line and f'{secret[-6:]}"' in line


def mock_multiprocessing_process(mock: Mock):
    """Mock to execute the target and return the mock object"""

    def mock_constructor(target, args=(), kwargs=None):
        if kwargs is None:
            kwargs = {}

        try:
            target(*args, **kwargs)
        except SystemExit as exit_exc:
            mock.exitcode = exit_exc.code

        mock.is_alive.return_value = False
        return mock

    mock.is_alive.return_value = True
    mock.exitcode = None
    return mock_constructor


class TestPreReceive:
    @pytest.fixture(autouse=True)
    def mock_multiprocessing(self):
        """
        multiprocessing.Process is mocked to make everything run on the main process
        to permit mocking of scan_commit_range
        """
        with patch(
            "ggshield.cmd.secret.scan.prereceive.multiprocessing"
        ) as multiprocessing_mock:
            multiprocessing_mock.Process.side_effect = mock_multiprocessing_process(
                multiprocessing_mock.Process
            )
            yield

    @patch("ggshield.cmd.secret.scan.prereceive.scan_commit_range")
    def test_stdin_input(
        self,
        scan_commit_range_mock: Mock,
        tmp_path,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN 3 commits through stdin input
        WHEN the command is run
        THEN it should pass onto scan and return 0
        """
        scan_commit_range_mock.return_value = ExitCode.SUCCESS

        repo = create_pre_receive_repo(tmp_path)
        old_sha = repo.get_top_sha()
        shas = [repo.create_commit() for _ in range(3)]
        with cd(repo.path):
            result = cli_fs_runner.invoke(
                cli,
                ["-v", "secret", "scan", "pre-receive"],
                input=f"{old_sha} {shas[-1]} origin/main\n",
            )
        assert_invoke_ok(result)
        scan_commit_range_mock.assert_called_once()
        assert "Commits to scan: 3" in result.output

    @patch("ggshield.cmd.secret.scan.prereceive.scan_commit_range")
    def test_stdin_input_secret(
        self,
        scan_commit_range_mock: Mock,
        tmp_path,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN 3 commits through stdin input
        WHEN the command is run and there are secrets
        THEN it should return a special remediation message
        """
        scan_commit_range_mock.return_value = ExitCode.SCAN_FOUND_PROBLEMS

        repo = create_pre_receive_repo(tmp_path)
        old_sha = repo.get_top_sha()
        shas = [repo.create_commit() for _ in range(3)]
        with cd(repo.path):
            result = cli_fs_runner.invoke(
                cli,
                ["-v", "secret", "scan", "pre-receive"],
                input=f"{old_sha} {shas[-1]} origin/main\n",
            )
        assert_invoke_exited_with(result, ExitCode.SCAN_FOUND_PROBLEMS)
        scan_commit_range_mock.assert_called_once()
        assert (
            """> How to remediate

  A pre-receive hook set server side prevented you from pushing secrets.

  Since the secret was detected during the push BUT after the commit, you need to:
  1. rewrite the git history making sure to replace the secret with its reference (e.g. environment variable).
  2. push again.

  To prevent having to rewrite git history in the future, setup ggshield as a pre-commit hook:
    https://docs.gitguardian.com/ggshield-docs/integrations/git-hooks/pre-commit

> [To apply with caution] If you want to bypass ggshield (false positive or other reason), run:

    git push -o breakglass"""
            in result.output
        )

    @patch("ggshield.cmd.secret.scan.prereceive.scan_commit_range")
    def test_stdin_breakglass_2ndoption(
        self,
        scan_commit_range_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN commits sent through stdin but breakglass active
        WHEN the command is run
        THEN it should return 0
        AND no commits should be scanned
        """
        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-receive"],
            input="bbbb aaaa origin/main\n",
            env={
                "GIT_PUSH_OPTION_COUNT": "2",
                "GIT_PUSH_OPTION_0": "unrelated",
                "GIT_PUSH_OPTION_1": "breakglass",
            },
        )
        assert_invoke_ok(result)
        scan_commit_range_mock.assert_not_called()
        assert (
            "SKIP: breakglass detected. Skipping GitGuardian pre-receive hook.\n"
            in result.output
        )

    @patch("ggshield.verticals.secret.repo.check_client_api_key")
    @patch("ggshield.verticals.secret.repo.scan_commits_content")
    def test_stdin_supports_gitlab_web_ui(
        self,
        scan_commits_content_mock: Mock,
        check_client_api_key_mock: Mock,
        tmp_path,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN 1 webpush commit
        WHEN the command is run and there are secrets
        THEN it should return a special remediation message
        AND the GL-HOOK-ERR line should be there
        AND it should contain an obfuscated version of the secret
        """
        repo = create_pre_receive_repo(tmp_path)
        old_sha = repo.get_top_sha()
        secret_file = repo.path / "server.conf"
        secret_file.write_text(f"github_token = {_SIMPLE_SECRET_TOKEN}\n")
        repo.add(secret_file)
        secret_sha = repo.create_commit()

        check_client_api_key_mock.return_value = None

        # This test cannot mock scan_commit_range(): if it did that we would not get
        # the GitLab-specific output because output_handler.process_scan() would not be
        # called.
        scan_commits_content_mock.return_value = SecretScanCollection(
            id="some_id",
            type="commit-ranges",
            scans=[
                SecretScanCollection(
                    secret_sha,
                    type="commit",
                    results=Results(
                        results=[
                            Result.from_scan_result(
                                file=StringScannable(
                                    content=_SIMPLE_SECRET_PATCH,
                                    url="server.conf",
                                    filemode=Filemode.MODIFY,
                                ),
                                scan_result=_SIMPLE_SECRET_PATCH_SCAN_RESULT,
                                secret_config=SecretConfig(),
                            )
                        ],
                        errors=[],
                    ),
                )
            ],
        )

        with cd(repo.path):
            result = cli_fs_runner.invoke(
                cli,
                ["-v", "secret", "scan", "pre-receive"],
                input=f"{old_sha} {secret_sha} origin/main\n",
                env={
                    "GL_PROTOCOL": "web",
                },
            )
        assert_invoke_exited_with(result, ExitCode.SCAN_FOUND_PROBLEMS)
        scan_commits_content_mock.assert_called_once()
        web_ui_lines = [
            x for x in result.output.splitlines() if x.startswith("GL-HOOK-ERR: ")
        ]
        assert web_ui_lines
        assert any(contains_secret(x, _SIMPLE_SECRET_TOKEN) for x in web_ui_lines)

    def test_stdin_input_empty(
        self,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN an empty stdin input
        WHEN the command is run
        THEN it should raise an error and return 1
        """

        result = cli_fs_runner.invoke(
            cli, ["-v", "secret", "scan", "pre-receive"], input=""
        )
        assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
        assert "Error: Invalid input arguments: ''\n" in result.output

    @patch("ggshield.cmd.secret.scan.prereceive.scan_commit_range")
    def test_changing_max_commit_hooks(
        self,
        scan_commit_range_mock: Mock,
        tmp_path,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a ref creation event
        WHEN the command is run with a changed env variable for max commit hooks
        THEN it should scan the last 2 commits
        """
        repo = create_pre_receive_repo(tmp_path)
        old_sha = repo.get_top_sha()
        shas = [repo.create_commit() for _ in range(3)]

        scan_commit_range_mock.return_value = ExitCode.SUCCESS

        with cd(repo.path):
            result = cli_fs_runner.invoke(
                cli,
                ["-v", "secret", "scan", "pre-receive"],
                input=f"{old_sha} {shas[-1]} main",
                env={"GITGUARDIAN_MAX_COMMITS_FOR_HOOK": "2"},
            )

        assert_invoke_ok(result)
        assert "Too many commits. Scanning last 2 commits" in result.output
        assert "Commits to scan: 2" in result.output
        scan_commit_range_mock.assert_called_once()

    @patch("ggshield.cmd.secret.scan.prereceive.scan_commit_range")
    def test_new_branch(
        self,
        scan_commit_range_mock: Mock,
        tmp_path,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a repository
        AND commits received by a push of a new branch from another repository
        WHEN the pre-receive command is run on the commits from the push
        THEN it should scan only scan the commits of the new branch
        """
        repo = Repository.create(tmp_path)
        repo.create_commit("initial commit")

        # Detach from the current branch to simulate what happens when pre-receive
        # is called: the new commits are not in any branch yet.
        repo.git("checkout", "--detach")
        shas = [repo.create_commit() for _ in range(3)]

        scan_commit_range_mock.return_value = 0

        with cd(str(repo.path)):
            result = cli_fs_runner.invoke(
                cli,
                ["-v", "secret", "scan", "pre-receive"],
                input=f"{EMPTY_SHA} {shas[-1]} refs/heads/topic",
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

    @patch("ggshield.cmd.secret.scan.prereceive.scan_commit_range")
    def test_new_branch_without_commits(
        self,
        scan_commit_range_mock: Mock,
        tmp_path,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a repository
        AND a new branch pushed from another repository, without any commit
        WHEN the pre-receive command is run on the commits from the push
        THEN it scans nothing
        """
        repo = Repository.create(tmp_path)
        sha = repo.create_commit("initial commit")
        branch_name = "topic"
        repo.create_branch(branch_name)

        with cd(str(repo.path)):
            result = cli_fs_runner.invoke(
                cli,
                ["-v", "secret", "scan", "pre-receive"],
                input=f"{EMPTY_SHA} {sha} refs/heads/{branch_name}",
            )

        assert_invoke_ok(result)
        scan_commit_range_mock.assert_not_called()
        assert "Pushed branch does not contain any new commit" in result.output

    def test_stdin_input_deletion(
        self,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a deletion event
        WHEN the command is run
        THEN it should return 0 and indicate nothing to do
        """

        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-receive"],
            input=f"{'a' * 40} {EMPTY_SHA} main",
        )
        assert_invoke_ok(result)
        assert "Deletion event or nothing to scan.\n" in result.output

    @patch(
        "pygitguardian.client.GGClient.read_metadata",
        return_value=Detail("Service is unavailable", 503),
    )
    def test_server_unavailable(self, _: Mock, tmp_path, cli_fs_runner: CliRunner):
        """
        GIVEN a repo on which the command is ran
        WHEN the server is not responding (503)
        THEN it should return 0
        AND display an error message
        """
        # setting up repo to run the command
        repo = create_pre_receive_repo(tmp_path)
        old_sha = repo.get_top_sha()
        shas = [repo.create_commit() for _ in range(3)]
        with cd(repo.path):
            result = cli_fs_runner.invoke(
                cli,
                ["-v", "secret", "scan", "pre-receive"],
                input=f"{old_sha} {shas[-1]} origin/main\n",
            )
        assert_invoke_ok(result)
        assert "GitGuardian server is not responding" in result.output
