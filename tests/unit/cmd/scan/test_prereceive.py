import os
import time
from unittest.mock import ANY, Mock, patch

from click.testing import CliRunner

from ggshield.cmd.main import cli
from ggshield.core.errors import ExitCode
from ggshield.core.utils import EMPTY_SHA, Filemode
from ggshield.scan import Commit, Result, Results, ScanCollection
from ggshield.scan.repo import cd
from ggshield.scan.scannable import File
from tests.repository import Repository
from tests.unit.conftest import (
    _SIMPLE_SECRET_PATCH,
    _SIMPLE_SECRET_PATCH_SCAN_RESULT,
    _SIMPLE_SECRET_TOKEN,
    assert_invoke_exited_with,
    assert_invoke_ok,
    is_macos,
)


def contains_secret(line: str, secret: str) -> bool:
    """Returns True if `line` contains an obfuscated version of `secret`"""
    return f'"{secret[:6]}' in line and f'{secret[-6:]}"' in line


class TestPreReceive:
    @patch("ggshield.cmd.secret.scan.prereceive.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prereceive.scan_commit_range")
    def test_stdin_input(
        self,
        scan_commit_range_mock: Mock,
        get_list_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN 20 commits through stdin input
        WHEN the command is run
        THEN it should pass onto scan and return 0
        """
        scan_commit_range_mock.return_value = 0
        get_list_mock.return_value = ["a" for _ in range(20)]

        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-receive"],
            input="bbbb aaaa origin/main\n",
        )
        assert_invoke_ok(result)
        get_list_mock.assert_called_once_with("bbbb...aaaa", max_count=51)
        scan_commit_range_mock.assert_called_once()
        assert "Commits to scan: 20" in result.output

    @patch("ggshield.cmd.secret.scan.prereceive.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prereceive.scan_commit_range")
    def test_stdin_input_secret(
        self,
        scan_commit_range_mock: Mock,
        get_list_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN 20 commits through stdin input
        WHEN the command is run and there are secrets
        THEN it should return a special remediation message
        """
        scan_commit_range_mock.return_value = ExitCode.SCAN_FOUND_PROBLEMS
        get_list_mock.return_value = ["a" for _ in range(20)]

        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-receive"],
            input="bbbb aaaa origin/main\n",
        )
        assert_invoke_exited_with(result, ExitCode.SCAN_FOUND_PROBLEMS)
        get_list_mock.assert_called_once_with("bbbb...aaaa", max_count=51)
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

    @patch("ggshield.cmd.secret.scan.prereceive.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prereceive.scan_commit_range")
    def test_stdin_input_no_commits(
        self,
        scan_commit_range_mock: Mock,
        get_list_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a range through stdin input but it corresponds to no commits
        WHEN the command is run
        THEN it should warn no commits were found and return 0
        """
        scan_commit_range_mock.return_value = 0
        get_list_mock.return_value = []

        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-receive"],
            input="bbbb aaaa origin/main\n",
        )
        assert_invoke_ok(result)
        get_list_mock.assert_called_once_with("bbbb...aaaa", max_count=51)
        scan_commit_range_mock.assert_not_called()
        assert (
            "Unable to get commit range.\n  before: bbbb\n  after: aaaa\nSkipping pre-receive hook\n\n"
            in result.output
        )

    @patch("ggshield.cmd.secret.scan.prereceive.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prereceive.scan_commit_range")
    def test_stdin_breakglass_2ndoption(
        self,
        scan_commit_range_mock: Mock,
        get_list_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN 20 commits through stdin input but breakglass active
        WHEN the command is run
        THEN it should return 0
        """
        get_list_mock.return_value = ["a" for _ in range(20)]

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
        get_list_mock.assert_not_called()
        scan_commit_range_mock.assert_not_called()
        assert (
            "SKIP: breakglass detected. Skipping GitGuardian pre-receive hook.\n"
            in result.output
        )

    @patch("ggshield.cmd.secret.scan.prereceive.get_list_commit_SHA")
    @patch("ggshield.scan.repo.get_commits_by_batch")
    @patch("ggshield.scan.repo.scan_commits_content")
    def test_stdin_supports_gitlab_web_ui(
        self,
        scan_commits_content_mock: Mock,
        get_commits_by_batch_mock: Mock,
        get_list_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN 1 webpush commit
        WHEN the command is run and there are secrets
        THEN it should return a special remediation message
        AND the GL-HOOK-ERR line should be there
        AND it should contain an obfuscated version of the secret
        """
        old_sha = "56781234"
        new_sha = "1234abcd"
        get_list_mock.return_value = [new_sha]
        get_commits_by_batch_mock.return_value = [[Commit(sha=new_sha)]]
        scan_commits_content_mock.return_value = ScanCollection(
            id="some_id",
            type="commit-ranges",
            scans=[
                ScanCollection(
                    new_sha,
                    type="commit",
                    results=Results(
                        results=[
                            Result(
                                file=File(
                                    _SIMPLE_SECRET_PATCH, "server.conf", Filemode.MODIFY
                                ),
                                scan=_SIMPLE_SECRET_PATCH_SCAN_RESULT,
                            )
                        ],
                        errors=[],
                    ),
                )
            ],
        )

        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-receive"],
            input=f"{old_sha} {new_sha} origin/main\n",
            env={
                "GL_PROTOCOL": "web",
            },
        )
        assert_invoke_exited_with(result, ExitCode.SCAN_FOUND_PROBLEMS)
        get_list_mock.assert_called_once_with(f"{old_sha}...{new_sha}", max_count=51)
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

    @patch("ggshield.cmd.secret.scan.prereceive.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prereceive.scan_commit_range")
    def test_changing_max_commit_hooks(
        self,
        scan_commit_range_mock: Mock,
        get_list_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a ref creation event
        WHEN the command is run with a changed env variable for max commit hooks
        THEN it should scan the last 20 commits
        """
        old_sha = "56781234"
        new_sha = "1234abcd"

        scan_commit_range_mock.return_value = 0
        get_list_mock.return_value = ["a" for _ in range(40)]

        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-receive"],
            input=f"{old_sha} {new_sha} main",
            env={"GITGUARDIAN_MAX_COMMITS_FOR_HOOK": "20"},
        )

        assert_invoke_ok(result)
        assert "Too many commits. Scanning last 20 commits" in result.output
        assert "Commits to scan: 20" in result.output
        get_list_mock.assert_called_once_with(f"{old_sha}...{new_sha}", max_count=21)
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
            matches_ignore=ANY,
            scan_context=ANY,
            ignored_detectors=set(),
            ignore_known_secrets=False,
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
            input=f"{'a'*40} {EMPTY_SHA} main",
        )
        assert_invoke_ok(result)
        assert "Deletion event or nothing to scan.\n" in result.output

    @patch("ggshield.cmd.secret.scan.prereceive.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prereceive.scan_commit_range")
    def test_stdin_input_no_newline(
        self,
        scan_commit_range_mock: Mock,
        get_list_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN 20 commits through stdin input
        WHEN the command is run
        THEN it should pass onto scan and return 0
        """
        scan_commit_range_mock.return_value = 0
        get_list_mock.return_value = ["a" for _ in range(20)]
        old_sha = "649061dcda8bff94e02adbaac70ca64cfb84bc78"
        new_sha = "bfffbd925b1ce9298e6c56eb525b8d7211603c09"

        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-receive"],
            input=f"{old_sha} {new_sha} refs/heads/main",
        )
        assert_invoke_ok(result)
        get_list_mock.assert_called_once_with(
            f"{old_sha}...{new_sha}",
            max_count=51,
        )
        scan_commit_range_mock.assert_called_once()
        assert "Commits to scan: 20" in result.output

    @patch("ggshield.cmd.secret.scan.prereceive.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prereceive.scan_commit_range")
    def test_timeout(
        self,
        scan_commit_range_mock: Mock,
        get_list_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a scan taking too long
        WHEN ggshield hits the timeout
        THEN it stops and return 0
        """

        scan_timeout = 0.1

        def sleepy_scan(*args, **kwargs):
            # Sleep for 5 seconds. Do not use a time.sleep(5) because our time limit is
            # not able to interrupt it before it ends.
            for _ in range(100):
                time.sleep(0.05)

        scan_commit_range_mock.side_effect = sleepy_scan
        scan_commit_range_mock.return_value = 2
        get_list_mock.return_value = ["a" for _ in range(20)]

        start = time.time()
        with patch.dict(os.environ, {"GITGUARDIAN_TIMEOUT": str(scan_timeout)}):
            result = cli_fs_runner.invoke(
                cli,
                ["-v", "secret", "scan", "pre-receive"],
                input="bbbb aaaa origin/main\n",
            )
        duration = time.time() - start
        assert_invoke_ok(result)

        # This test often fails on GitHub macOS runner: duration can reach between
        # 0.3 and 0.4. Workaround this by using a longer timeout on macOS.
        max_duration = (6 if is_macos() else 3) * scan_timeout
        assert duration < max_duration
        scan_commit_range_mock.assert_called_once()
