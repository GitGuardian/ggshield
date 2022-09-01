from typing import Dict, Optional
from unittest.mock import ANY, Mock, patch

import pytest
from click.testing import CliRunner

from ggshield.cmd.main import cli
from ggshield.core.filter import init_exclusion_regexes
from ggshield.core.utils import (
    EMPTY_SHA,
    EMPTY_TREE,
    IGNORED_DEFAULT_WILDCARDS,
    ScanContext,
    ScanMode,
)
from tests.conftest import assert_invoke_ok


class TestPrepush:
    @patch("ggshield.cmd.secret.scan.prepush.get_list_commit_SHA")
    def test_pre_push_no_commits(self, get_list_mock: Mock, cli_fs_runner: CliRunner):
        """
        GIVEN a prepush range with 0 commits
        WHEN the command is run
        THEN it should return 0 and warn it was unable to get range
        """
        get_list_mock.return_value = []
        result = cli_fs_runner.invoke(
            cli,
            ["-v", "scan", "pre-push"],
            env={"PRE_COMMIT_FROM_REF": "a" * 40, "PRE_COMMIT_TO_REF": "b" * 40},
        )
        assert_invoke_ok(result)
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
            ["-v", "scan", "pre-push"],
            env={"PRE_COMMIT_FROM_REF": "a" * 40, "PRE_COMMIT_TO_REF": "b" * 40},
        )
        assert_invoke_ok(result)
        scan_commit_range_mock.assert_called_once()
        _, kwargs = scan_commit_range_mock.call_args_list[0]
        assert len(kwargs["commit_list"]) == 50
        assert "Too many commits. Scanning last 50" in result.output

    @patch("ggshield.cmd.secret.scan.prepush.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prepush.scan_commit_range")
    @patch("ggshield.cmd.secret.scan.prepush.check_git_dir")
    @pytest.mark.parametrize(
        ["env", "input"],
        [
            pytest.param(
                {"PRE_COMMIT_SOURCE": "a" * 40, "PRE_COMMIT_ORIGIN": "b" * 40},
                None,
                id="old env names",
            ),
            pytest.param(
                {"PRE_COMMIT_FROM_REF": "a" * 40, "PRE_COMMIT_TO_REF": "b" * 40},
                None,
                id="new env names",
            ),
            pytest.param(
                {},
                f"main\n{'a'*40}\norigin/main\n{'b'*40}\n",
                id="stdin input",
            ),
        ],
    )
    def test_prepush_pre_commit_framework(
        self,
        check_dir_mock: Mock,
        scan_commit_range_mock: Mock,
        get_list_mock: Mock,
        cli_fs_runner: CliRunner,
        env: Dict,
        input: Optional[str],
    ):
        """
        GIVEN a prepush range with 20 commits provided by the pre-commit framework
        WHEN the command is run
        THEN it should pass onto scan and return 0
        AND the `exclusion_regexes` argument of the scan_commit_range() call should
        match IGNORED_DEFAULT_WILDCARDS
        """
        scan_commit_range_mock.return_value = 0
        commit_list = ["a"] * 20
        get_list_mock.return_value = commit_list

        result = cli_fs_runner.invoke(
            cli, ["-v", "scan", "pre-push"], env=env, input=input
        )
        get_list_mock.assert_called_once_with(
            "--max-count=51 " + "b" * 40 + "..." + "a" * 40
        )

        scan_commit_range_mock.assert_called_once_with(
            client=ANY,
            cache=ANY,
            commit_list=commit_list,
            output_handler=ANY,
            exclusion_regexes=ANY,
            matches_ignore=ANY,
            scan_context=ScanContext(
                scan_mode=ScanMode.PRE_PUSH,
                command_path="cli scan pre-push",
            ),
            ignored_detectors=set(),
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

        result = cli_fs_runner.invoke(cli, ["-v", "scan", "pre-push"], input="")
        assert_invoke_ok(result)
        assert "Deletion event or nothing to scan.\n" in result.output

    @patch("ggshield.cmd.secret.scan.prepush.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prepush.scan_commit_range")
    @patch("ggshield.cmd.secret.scan.prepush.check_git_dir")
    def test_prepush_new_branch(
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
            ["-v", "scan", "pre-push"],
            env={"PRE_COMMIT_FROM_REF": "a" * 40, "PRE_COMMIT_TO_REF": EMPTY_SHA},
        )
        assert_invoke_ok(result)
        get_list_mock.assert_called_once_with(
            f"--max-count=51 {EMPTY_TREE} { 'a' * 40}"
        )
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
            ["-v", "scan", "pre-push"],
            env={"PRE_COMMIT_FROM_REF": EMPTY_SHA, "PRE_COMMIT_TO_REF": "a" * 40},
        )
        assert_invoke_ok(result)
        assert "Deletion event or nothing to scan.\n" in result.output

    @patch("ggshield.cmd.secret.scan.prepush.get_list_commit_SHA")
    @patch("ggshield.cmd.secret.scan.prepush.scan_commit_range")
    @patch("ggshield.cmd.secret.scan.prepush.check_git_dir")
    def test_prepush_stdin_input_no_newline(
        self,
        check_dir_mock: Mock,
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
            ["-v", "scan", "pre-push"],
            input="refs/heads/main bfffbd925b1ce9298e6c56eb525b8d7211603c09 refs/heads/main 649061dcda8bff94e02adbaac70ca64cfb84bc78",  # noqa: E501
        )
        assert_invoke_ok(result)
        get_list_mock.assert_called_once_with(
            "--max-count=51 649061dcda8bff94e02adbaac70ca64cfb84bc78...bfffbd925b1ce9298e6c56eb525b8d7211603c09"  # noqa: E501
        )  # noqa: E501
        scan_commit_range_mock.assert_called_once()
        assert "Commits to scan: 20" in result.output
