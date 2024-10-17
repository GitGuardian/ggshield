from pathlib import Path
from unittest.mock import Mock, patch

from click.testing import CliRunner
from pygitguardian.sca_models import SCAScanAllOutput, SCAScanDiffOutput

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode, NotAMergeRequestError
from ggshield.core.scan.scan_mode import ScanMode
from tests.repository import Repository


@patch("ggshield.cmd.sca.scan.ci.sca_scan_diff", return_value=SCAScanDiffOutput())
@patch(
    "ggshield.cmd.sca.scan.ci.get_scan_ci_parameters",
)
def test_sca_scan_ci_mr_env(
    get_scan_ci_parameters_mock: Mock,
    sca_scan_diff_mock: Mock,
    monkeypatch,
    tmp_path: Path,
):
    """
    GIVEN a CI env for a Merge Request
    WHEN `sca scan ci` is called
    THEN sca_scan_diff is called with expected parameters
    THEN the command does not fail
    """
    cli_runner = CliRunner()
    with cli_runner.isolated_filesystem(temp_dir=tmp_path):
        local_repo = Repository.create(tmp_path)
        ref_commit = local_repo.create_commit()
        cur_commit = local_repo.create_commit()
        get_scan_ci_parameters_mock.return_value = (cur_commit, ref_commit)

        monkeypatch.setenv("GITLAB_CI", "true")

        result = cli_runner.invoke(cli, ["sca", "scan", "ci"], catch_exceptions=False)

        sca_scan_diff_mock.assert_called_once()
        assert set(
            {
                "current_ref": cur_commit,
                "previous_ref": ref_commit,
                "ci_mode": "GITLAB",
                "scan_mode": "ci_diff/GITLAB",
            }.items()
        ) <= set(sca_scan_diff_mock.call_args.kwargs.items())
        assert result.exit_code == ExitCode.SUCCESS


@patch("ggshield.cmd.sca.scan.ci.sca_scan_all", return_value=SCAScanAllOutput())
@patch(
    "ggshield.cmd.sca.scan.ci.get_scan_ci_parameters",
)
def test_sca_scan_ci_non_mr_env(
    get_scan_ci_parameters_mock: Mock,
    sca_scan_all_mock: Mock,
    monkeypatch,
    tmp_path: Path,
):
    """
    GIVEN a CI env not for a Merge Request
    WHEN `sca scan ci` is called
    THEN sca_scan_all is called with expected parameters
    THEN the command does not fail
    THEN a warning is logged
    """
    cli_runner = CliRunner(mix_stderr=False)
    with cli_runner.isolated_filesystem(temp_dir=tmp_path):
        Repository.create(tmp_path)
        get_scan_ci_parameters_mock.side_effect = NotAMergeRequestError

        monkeypatch.setenv("GITLAB_CI", "true")

        result = cli_runner.invoke(cli, ["sca", "scan", "ci"], catch_exceptions=False)

        sca_scan_all_mock.assert_called_once()
        assert set({"scan_mode": ScanMode.CI_ALL}.items()) <= set(
            sca_scan_all_mock.call_args.kwargs.items()
        )
        assert result.exit_code == ExitCode.SUCCESS
        assert "Warning: " in result.stderr
