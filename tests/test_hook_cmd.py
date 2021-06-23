from unittest.mock import ANY, Mock, patch

from click.testing import CliRunner

from ggshield.cmd import cli
from ggshield.utils import EMPTY_SHA, EMPTY_TREE


@patch("ggshield.hook_cmd.get_list_commit_SHA")
def test_pre_push_no_commits(get_list_mock: Mock, cli_fs_runner: CliRunner):
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
    assert result.exit_code == 0
    assert "Unable to get commit range." in result.output


@patch("ggshield.hook_cmd.get_list_commit_SHA")
def test_prepush_too_many(get_list_mock: Mock, cli_fs_runner: CliRunner):
    """
    GIVEN a prepush range with a 101 commits
    WHEN the command is run
    THEN it should return 0 and warn too many commits for scanning
    """
    get_list_mock.return_value = ["a" for _ in range(101)]
    result = cli_fs_runner.invoke(
        cli,
        ["-v", "scan", "pre-push"],
        env={"PRE_COMMIT_FROM_REF": "a" * 40, "PRE_COMMIT_TO_REF": "b" * 40},
    )
    assert result.exit_code == 0
    assert "Too many commits for scanning." in result.output


@patch("ggshield.hook_cmd.get_list_commit_SHA")
@patch("ggshield.hook_cmd.scan_commit_range")
@patch("ggshield.hook_cmd.check_git_dir")
def test_prepush_pre_commit_framework_new(
    check_dir_mock: Mock,
    scan_commit_range_mock: Mock,
    get_list_mock: Mock,
    cli_fs_runner: CliRunner,
):
    """
    GIVEN a prepush range with a 20 commits through the new env vars of the framework
    WHEN the command is run
    THEN it should pass onto scan and return 0
    """
    scan_commit_range_mock.return_value = 0
    commit_list = ["a" for _ in range(20)]
    get_list_mock.return_value = commit_list

    result = cli_fs_runner.invoke(
        cli,
        ["-v", "scan", "pre-push"],
        env={"PRE_COMMIT_FROM_REF": "a" * 40, "PRE_COMMIT_TO_REF": "b" * 40},
    )
    get_list_mock.assert_called_once_with("b" * 40 + "..." + "a" * 40)
    scan_commit_range_mock.assert_called_once_with(
        client=ANY,
        cache=ANY,
        commit_list=commit_list,
        output_handler=ANY,
        verbose=True,
        filter_set=set(),
        matches_ignore=ANY,
        all_policies=False,
        scan_id=ANY,
        mode_header="pre_push",
    )
    assert "Commits to scan: 20" in result.output
    assert result.exit_code == 0


@patch("ggshield.hook_cmd.get_list_commit_SHA")
@patch("ggshield.hook_cmd.scan_commit_range")
@patch("ggshield.hook_cmd.check_git_dir")
def test_prepush_pre_commit_framework_old(
    check_dir_mock: Mock,
    scan_commit_range_mock: Mock,
    get_list_mock: Mock,
    cli_fs_runner: CliRunner,
):
    """
    GIVEN a prepush range with a 20 commits through the old env vars of the framework
    WHEN the command is run
    THEN it should pass onto scan and return 0
    """
    scan_commit_range_mock.return_value = 0
    get_list_mock.return_value = ["a" for _ in range(20)]

    result = cli_fs_runner.invoke(
        cli,
        ["-v", "scan", "pre-push"],
        env={"PRE_COMMIT_SOURCE": "a" * 40, "PRE_COMMIT_ORIGIN": "b" * 40},
    )
    get_list_mock.assert_called_once_with("b" * 40 + "..." + "a" * 40)
    scan_commit_range_mock.assert_called_once()
    assert "Commits to scan: 20" in result.output
    assert result.exit_code == 0


@patch("ggshield.hook_cmd.get_list_commit_SHA")
@patch("ggshield.hook_cmd.scan_commit_range")
@patch("ggshield.hook_cmd.check_git_dir")
def test_prepush_stdin_input(
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
        cli, ["-v", "scan", "pre-push"], input="main\naaaa\norigin/main\nbbbb\n"
    )
    get_list_mock.assert_called_once_with("bbbb" + "..." + "aaaa")
    scan_commit_range_mock.assert_called_once()
    assert "Commits to scan: 20" in result.output
    assert result.exit_code == 0


@patch("ggshield.hook_cmd.get_list_commit_SHA")
@patch("ggshield.hook_cmd.scan_commit_range")
@patch("ggshield.hook_cmd.check_git_dir")
def test_prepush_stdin_input_empty(
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
    assert "Deletion event or nothing to scan.\n" in result.output
    assert result.exit_code == 0


@patch("ggshield.hook_cmd.get_list_commit_SHA")
@patch("ggshield.hook_cmd.scan_commit_range")
@patch("ggshield.hook_cmd.check_git_dir")
def test_prepush_new_branch(
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
    get_list_mock.return_value = ["a" for _ in range(10)]

    result = cli_fs_runner.invoke(
        cli,
        ["-v", "scan", "pre-push"],
        env={"PRE_COMMIT_FROM_REF": "a" * 40, "PRE_COMMIT_TO_REF": EMPTY_SHA},
    )
    get_list_mock.assert_called_once_with(f"--max-count=101 {EMPTY_TREE} { 'a' * 40}")
    scan_commit_range_mock.assert_called_once()

    assert "New tree event. Scanning all changes" in result.output
    assert "Commits to scan: 10" in result.output
    assert result.exit_code == 0


@patch("ggshield.hook_cmd.get_list_commit_SHA")
@patch("ggshield.hook_cmd.scan_commit_range")
@patch("ggshield.hook_cmd.check_git_dir")
def test_prepush_deletion(
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
    assert "Deletion event or nothing to scan.\n" in result.output
    assert result.exit_code == 0


@patch("ggshield.hook_cmd.get_list_commit_SHA")
@patch("ggshield.hook_cmd.scan_commit_range")
@patch("ggshield.hook_cmd.check_git_dir")
def test_prepush_stdin_input_no_newline(
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
    get_list_mock.assert_called_once_with(
        "649061dcda8bff94e02adbaac70ca64cfb84bc78...bfffbd925b1ce9298e6c56eb525b8d7211603c09"  # noqa: E501
    )  # noqa: E501
    scan_commit_range_mock.assert_called_once()
    assert "Commits to scan: 20" in result.output
    assert result.exit_code == 0
