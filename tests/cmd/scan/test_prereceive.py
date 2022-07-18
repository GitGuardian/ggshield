import os
import time
from unittest.mock import Mock, patch

from click.testing import CliRunner

from ggshield.cmd.main import cli
from ggshield.core.utils import EMPTY_SHA, EMPTY_TREE, Filemode
from ggshield.scan import Result, Results, ScanCollection
from tests.conftest import (
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
            input="bbbb\naaaa\norigin/main\n",
        )
        assert_invoke_ok(result)
        get_list_mock.assert_called_once_with("--max-count=51 bbbb" + "..." + "aaaa")
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
        scan_commit_range_mock.return_value = 1
        get_list_mock.return_value = ["a" for _ in range(20)]

        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-receive"],
            input="bbbb\naaaa\norigin/main\n",
        )
        assert_invoke_exited_with(result, 1)
        get_list_mock.assert_called_once_with("--max-count=51 bbbb" + "..." + "aaaa")
        scan_commit_range_mock.assert_called_once()
        assert (
            "if those secrets are false positives and you still want your push to pass, run:\n'git push -o breakglass'"
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
            input="bbbb\naaaa\norigin/main\n",
        )
        assert_invoke_ok(result)
        get_list_mock.assert_called_once_with("--max-count=51 bbbb" + "..." + "aaaa")
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
            input="bbbb\naaaa\norigin/main\n",
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
    @patch("ggshield.scan.repo.scan_commit")
    def test_stdin_supports_gitlab_web_ui(
        self,
        scan_commit_mock: Mock,
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
        scan_commit_mock.return_value = ScanCollection(
            new_sha,
            type="commit",
            results=Results(
                results=[
                    Result(
                        _SIMPLE_SECRET_PATCH,
                        Filemode.MODIFY,
                        "server.conf",
                        _SIMPLE_SECRET_PATCH_SCAN_RESULT,
                    )
                ],
                errors=[],
            ),
        )

        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-receive"],
            input=f"{old_sha}\n{new_sha}\norigin/main\n",
            env={
                "GL_PROTOCOL": "web",
            },
        )
        assert_invoke_exited_with(result, 1)
        get_list_mock.assert_called_once_with(f"--max-count=51 {old_sha}...{new_sha}")
        scan_commit_mock.assert_called_once()
        web_ui_lines = [
            x for x in result.output.splitlines() if x.startswith("GL-HOOK-ERR: ")
        ]
        assert web_ui_lines
        assert any(contains_secret(x, _SIMPLE_SECRET_TOKEN) for x in web_ui_lines)

    @patch("ggshield.cmd.secret.scan.prereceive.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prereceive.scan_commit_range")
    def test_stdin_input_empty(
        self,
        scan_commit_range_mock: Mock,
        get_list_mock: Mock,
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
        assert_invoke_exited_with(result, 1)
        assert "Error: Invalid input arguments: []\n" in result.output

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

        scan_commit_range_mock.return_value = 0
        get_list_mock.side_effect = [[], ["a" for _ in range(60)]]

        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-receive"],
            input=f"{EMPTY_SHA}\n{'a'*40}\nmain",
            env={"GITGUARDIAN_MAX_COMMITS_FOR_HOOK": "20"},
        )

        assert_invoke_ok(result)
        assert "New tree event. Scanning last 20 commits" in result.output
        assert "Commits to scan: 20" in result.output
        assert get_list_mock.call_count == 2
        get_list_mock.assert_called_with(f"--max-count=21 {EMPTY_TREE} { 'a' * 40}")
        scan_commit_range_mock.assert_called_once()

    @patch("ggshield.cmd.secret.scan.prereceive.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prereceive.scan_commit_range")
    def test_new_branch_diff_with_head_success(
        self,
        scan_commit_range_mock: Mock,
        get_list_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a ref creation event
        WHEN the command is run and its able to diff with HEAD
        THEN it should scan the rev-list presented
        """

        scan_commit_range_mock.return_value = 0
        get_list_mock.side_effect = [["a" for _ in range(60)]]

        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-receive"],
            input=f"{EMPTY_SHA}\n{'a'*40}\nmain",
        )

        assert_invoke_ok(result)
        assert get_list_mock.call_count == 1
        get_list_mock.assert_called_with(f"--max-count=51 HEAD...{ 'a' * 40}")
        scan_commit_range_mock.assert_called_once()

    @patch("ggshield.cmd.secret.scan.prereceive.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prereceive.scan_commit_range")
    def test_stdin_input_creation(
        self,
        scan_commit_range_mock: Mock,
        get_list_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a ref creation event
        WHEN the command is run
        THEN it should scan the last 50 commits
        """

        scan_commit_range_mock.return_value = 0
        get_list_mock.side_effect = [[], ["a" for _ in range(60)]]

        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-receive"],
            input=f"{EMPTY_SHA}\n{'a'*40}\nmain",
        )

        assert_invoke_ok(result)
        assert "New tree event. Scanning last 50 commits" in result.output
        assert "Commits to scan: 50" in result.output
        assert get_list_mock.call_count == 2
        get_list_mock.assert_called_with(f"--max-count=51 {EMPTY_TREE} { 'a' * 40}")
        scan_commit_range_mock.assert_called_once()

    @patch("ggshield.cmd.secret.scan.prereceive.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prereceive.scan_commit_range")
    def test_stdin_input_deletion(
        self,
        scan_commit_range_mock: Mock,
        get_list_mock: Mock,
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
            input=f"{'a'*40} {EMPTY_SHA}  main",
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

        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "pre-receive"],
            input="649061dcda8bff94e02adbaac70ca64cfb84bc78 bfffbd925b1ce9298e6c56eb525b8d7211603c09 refs/heads/main",  # noqa: E501
        )
        assert_invoke_ok(result)
        get_list_mock.assert_called_once_with(
            "--max-count=51 649061dcda8bff94e02adbaac70ca64cfb84bc78...bfffbd925b1ce9298e6c56eb525b8d7211603c09"  # noqa: E501
        )  # noqa: E501
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
                input="bbbb\naaaa\norigin/main\n",
            )
        duration = time.time() - start
        assert_invoke_ok(result)

        # This test often fails on GitHub macOS runner: duration can reach between
        # 0.3 and 0.4. Workaround this by using a longer timeout on macOS.
        max_duration = (6 if is_macos() else 3) * scan_timeout
        assert duration < max_duration
        scan_commit_range_mock.assert_called_once()
