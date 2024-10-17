import re
import tarfile
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock, patch

import click
from click.testing import CliRunner
from pygitguardian import GGClient
from pygitguardian.client import _create_tar
from pygitguardian.sca_models import (
    SCALocationVulnerability,
    SCAScanAllOutput,
    SCAScanDiffOutput,
    SCAScanParameters,
    SCAVulnerability,
    SCAVulnerablePackageVersion,
)

from ggshield.__main__ import cli
from ggshield.cmd.sca.scan.sca_scan_utils import (
    get_sca_scan_all_filepaths,
    sca_scan_all,
    sca_scan_diff,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.config import Config
from ggshield.core.errors import ExitCode
from ggshield.core.scan.scan_mode import ScanMode
from ggshield.utils.os import cd
from tests.repository import Repository
from tests.unit.conftest import assert_invoke_exited_with, my_vcr, write_text


def get_valid_ctx(client: GGClient) -> click.Context:
    """
    Returns a valid click.Context to run sca scan all
    """
    config = Config()
    config.user_config.verbose = False
    ctx_obj = ContextObj()
    ctx_obj.client = client
    ctx_obj.config = config
    ctx = click.Context(
        click.Command("sca scan all"),
        obj=ctx_obj,
    )
    return ctx


@my_vcr.use_cassette("test_sca_get_scan_all_filepaths.yaml", ignore_localhost=False)
def test_get_sca_scan_all_filepaths(client: GGClient, tmp_path) -> None:
    """
    GIVEN a directory and a client instance
    WHEN requesting the SCA filepaths in this directory
    THEN the API called is made without error
    THEN the existing SCA related files are listed
    """
    # Create tmp directory with some files in it
    write_text(filename=str(tmp_path / "Pipfile"), content="")
    write_text(filename=str(tmp_path / "Some_other_file.txt"), content="")
    # This one should not appear in response
    write_text(filename=str(tmp_path / ".venv" / "Pipfile"), content="")

    result = get_sca_scan_all_filepaths(
        directory=tmp_path, exclusion_regexes=set(), client=client
    )

    assert result == (["Pipfile"], 200)


@my_vcr.use_cassette("test_sca_scan_all_valid.yaml", ignore_localhost=False)
def test_sca_scan_all_valid(client: GGClient) -> None:
    """
    GIVEN a valid click context
    WHEN calling sca_scan_all
    THEN we get an SCAScanAllOutput
    """

    ctx = get_valid_ctx(client)
    with ctx:
        result = sca_scan_all(ctx, Path("."))

    assert isinstance(result, SCAScanAllOutput)


@my_vcr.use_cassette("test_sca_scan_all_no_file.yaml", ignore_localhost=False)
def test_sca_scan_all_no_sca_file(client: GGClient, tmp_path: Path) -> None:
    """
    GIVEN a valid click context
    WHEN calling sca_scan_all on a directory with no sca files in it
    THEN sca_scan_all returns an empty SCAScanAllOutput instance
    """

    ctx = get_valid_ctx(client)
    with ctx:
        result = sca_scan_all(ctx, tmp_path)

    assert result == SCAScanAllOutput()


def test_sca_scan_all_ignore_path(client: GGClient, dummy_sca_repo: Repository) -> None:
    """
    GIVEN a directory with sca files that are ignored
    WHEN scanning
    THEN no files are scanned
    """
    dummy_sca_repo.git("checkout", "branch_with_vuln")
    ctx = get_valid_ctx(client)
    ctx_obj = ContextObj.get(ctx)
    ctx_obj.exclusion_regexes = {
        re.compile(r"Pipfile"),
        re.compile(r"Pipfile.lock"),
        re.compile(r"dummy_file.py"),
    }
    with ctx:
        result = sca_scan_all(ctx, dummy_sca_repo.path)

    assert result == SCAScanAllOutput()


@my_vcr.use_cassette("test_sca_scan_diff.yaml", ignore_localhost=False)
def test_sca_scan_diff(client: GGClient, dummy_sca_repo: Repository):
    ctx = get_valid_ctx(client)
    with ctx:
        result = sca_scan_diff(
            ctx=ctx,
            directory=dummy_sca_repo.path,
            previous_ref="branch_with_vuln",
            scan_mode=ScanMode.DIFF,
        )
    assert isinstance(result, SCAScanDiffOutput)
    assert result.scanned_files == ["Pipfile", "Pipfile.lock"]
    assert result.added_vulns == []
    assert len(result.removed_vulns) == 1


def test_sca_scan_diff_same_ref(client: GGClient, dummy_sca_repo: Repository):
    ctx = get_valid_ctx(client)
    with ctx:
        result = sca_scan_diff(
            ctx=ctx,
            directory=dummy_sca_repo.path,
            previous_ref="HEAD",
            scan_mode=ScanMode.DIFF,
        )
    assert isinstance(result, SCAScanDiffOutput)
    assert result.scanned_files == []
    assert result.added_vulns == []
    assert result.removed_vulns == []


@my_vcr.use_cassette("test_sca_scan_diff_ignore.yaml", ignore_localhost=False)
def test_sca_scan_diff_ignore_path(
    client: GGClient, dummy_sca_repo: Repository
) -> None:
    """
    GIVEN a directory with sca files that are ignored
    WHEN scanning
    THEN no files are scanned
    """
    dummy_sca_repo.git("checkout", "branch_without_vuln")
    ctx = get_valid_ctx(client)
    ctx_obj = ContextObj.get(ctx)
    ctx_obj.exclusion_regexes = {
        re.compile(r"Pipfile"),
        re.compile(r"Pipfile.lock"),
    }
    with ctx:
        result = sca_scan_diff(
            ctx=ctx,
            directory=dummy_sca_repo.path,
            previous_ref="branch_with_vuln",
            scan_mode=ScanMode.DIFF,
        )

    assert result == SCAScanDiffOutput()


@patch("pygitguardian.GGClient.scan_diff")
def test_sca_scan_diff_no_files(
    scan_diff_mock, client: GGClient, dummy_sca_repo: Repository
) -> None:
    """
    GIVEN a repo
    WHEN scanning the diff with all files ignored
    THEN no scan is triggered
    """
    dummy_sca_repo.git("checkout", "branch_without_vuln")
    ctx = get_valid_ctx(client)
    ctx_obj = ContextObj.get(ctx)
    ctx_obj.exclusion_regexes = {re.compile(r"Pipfile"), re.compile(r"\.py")}
    with ctx:
        sca_scan_diff(
            ctx=ctx,
            directory=dummy_sca_repo.path,
            previous_ref="branch_with_vuln",
            scan_mode=ScanMode.DIFF,
        )

    scan_diff_mock.assert_not_called()


@my_vcr.use_cassette("test_sca_scan_all_no_file.yaml", ignore_localhost=False)
def test_sca_scan_all_cmd_no_sca_file(cli_fs_runner: CliRunner, tmp_path) -> None:
    """
    GIVEN a directory with no sca files in it
    WHEN running the sca scan all command
    THEN command returns the expected output
    """
    result = cli_fs_runner.invoke(
        cli,
        [
            "sca",
            "scan",
            "all",
            str(tmp_path),
        ],
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert "No file to scan." in result.stdout
    assert "No SCA vulnerability has been found" in result.stdout


@my_vcr.use_cassette(ignore_localhost=False)
def test_sca_scan_all_cmd(
    cli_fs_runner: CliRunner, tmp_path, pipfile_lock_with_vuln
) -> None:
    """
    GIVEN a directory with SCA incidents
    WHEN running the sca scan all command
    THEN command returns the expected output
    """

    Path(tmp_path / "Pipfile.lock").write_text(pipfile_lock_with_vuln)

    result = cli_fs_runner.invoke(
        cli,
        [
            "sca",
            "scan",
            "all",
            str(tmp_path),
        ],
    )
    assert result.exit_code == ExitCode.SCAN_FOUND_PROBLEMS
    assert "> Pipfile.lock: 1 incident detected" in result.stdout
    assert (
        """
Severity: High
Summary: sqlparse parsing heavily nested list leads to Denial of Service
A fix is available at version 0.5.0
Identifier: GHSA-2m57-hf25-phgg
CVE IDs: CVE-2024-4340"""
        in result.stdout
    )


@my_vcr.use_cassette("test_sca_scan_all_exit_zero.yaml")
def test_sca_scan_all_exit_zero(
    tmp_path, cli_fs_runner, pipfile_lock_with_vuln
) -> None:
    file_with_vulns = Path(tmp_path / "Pipfile.lock")
    file_with_vulns.write_text(pipfile_lock_with_vuln)

    with cd(str(tmp_path)):
        result = cli_fs_runner.invoke(
            cli,
            [
                "sca",
                "scan",
                "all",
                "--exit-zero",
            ],
        )

        assert result.exit_code == ExitCode.SUCCESS


@patch("ggshield.cmd.sca.scan.all.sca_scan_all")
def test_sca_text_handler_ordering(patch_scan_all, cli_fs_runner):
    """
    GIVEN an unordered result for a SCA scan all
    WHEN printing the result
    THEN vulnerabilities are ordered as expected
    """
    patch_scan_all.return_value = SCAScanAllOutput(
        scanned_files=["Pipfile.lock", "toto/Pipfile.lock"],
        found_package_vulns=[
            SCALocationVulnerability(
                location="Pipfile.lock",
                package_vulns=[
                    SCAVulnerablePackageVersion(
                        package_full_name="toto",
                        version="1.0.0",
                        ecosystem="pypi",
                        vulns=[
                            SCAVulnerability(severity="low", summary="", identifier="")
                        ],
                    ),
                    SCAVulnerablePackageVersion(
                        package_full_name="titi",
                        version="2.0.0",
                        ecosystem="pypi",
                        vulns=[
                            SCAVulnerability(
                                severity="medium", summary="", identifier=""
                            )
                        ],
                    ),
                ],
            ),
            SCALocationVulnerability(
                location="toto/Pipfile.lock",
                package_vulns=[
                    SCAVulnerablePackageVersion(
                        package_full_name="foo",
                        version="1.0.5",
                        ecosystem="pypi",
                        vulns=[
                            SCAVulnerability(severity="high", summary="", identifier="")
                        ],
                    ),
                    SCAVulnerablePackageVersion(
                        package_full_name="bar",
                        version="2.5.6",
                        ecosystem="pypi",
                        vulns=[
                            SCAVulnerability(
                                severity="critical", summary="", identifier=""
                            )
                        ],
                    ),
                ],
            ),
            SCALocationVulnerability(
                location="mal/Pipfile.lock",
                package_vulns=[
                    SCAVulnerablePackageVersion(
                        package_full_name="mal",
                        version="1.0.0",
                        ecosystem="pypi",
                        vulns=[
                            SCAVulnerability(
                                severity="malicious", summary="", identifier=""
                            )
                        ],
                    ),
                ],
            ),
        ],
    )

    result = cli_fs_runner.invoke(
        cli,
        [
            "sca",
            "scan",
            "all",
        ],
    )

    assert result.exit_code == ExitCode.SCAN_FOUND_PROBLEMS
    assert (
        """
> mal/Pipfile.lock: 1 incident detected

>>> : Incident 1 (SCA): mal@1.0.0
Severity: Malicious
Summary: 
No fix is currently available.
Identifier: 
CVE IDs: -

> toto/Pipfile.lock: 2 incidents detected

>>> : Incident 1 (SCA): bar@2.5.6
Severity: Critical
Summary: 
No fix is currently available.
Identifier: 
CVE IDs: -

>>> : Incident 2 (SCA): foo@1.0.5
Severity: High
Summary: 
No fix is currently available.
Identifier: 
CVE IDs: -

> Pipfile.lock: 2 incidents detected

>>> : Incident 1 (SCA): titi@2.0.0
Severity: Medium
Summary: 
No fix is currently available.
Identifier: 
CVE IDs: -

>>> : Incident 2 (SCA): toto@1.0.0
Severity: Low
Summary: 
No fix is currently available.
Identifier: 
CVE IDs: -

"""  # noqa W291
        in result.stdout
    )


@patch("pygitguardian.GGClient.compute_sca_files")
def test_sca_scan_all_ignored_directory(
    compute_sca_files_mock: Mock,
    cli_fs_runner: click.testing.CliRunner,
    dummy_sca_repo: Repository,
):
    """
    GIVEN a directory which is ignored
    WHEN running the sca scan all command on this directory
    THEN an error is raised
    """
    dummy_sca_repo.git("checkout", "branch_with_vuln")
    result = cli_fs_runner.invoke(
        cli,
        [
            "sca",
            "scan",
            "all",
            "--ignore-path",
            f"{dummy_sca_repo.path.name}/",
            str(dummy_sca_repo.path),
        ],
    )

    assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)
    assert "An ignored file or directory cannot be scanned." in result.stdout
    compute_sca_files_mock.assert_not_called()


@patch("pygitguardian.GGClient.compute_sca_files")
def test_sca_scan_all_ignored_directory_config(
    compute_sca_files_mock: Mock,
    cli_fs_runner: CliRunner,
    tmp_path: Path,
    pipfile_lock_with_vuln: str,
) -> None:
    """
    GIVEN a directory which is ignored in the config
    WHEN running the sca scan all command on this directory
    THEN an error is raised
    """
    repo = Repository.create(tmp_path)
    dir = tmp_path / "dir"
    dir.mkdir()
    subdir = dir / "subdir"
    subdir.mkdir()
    pipfile_lock = subdir / "Pipfile.lock"
    pipfile_lock.write_text(pipfile_lock_with_vuln)
    repo.add(pipfile_lock)
    repo.create_commit()

    config = """
version: 2
sca:
    ignored_paths:
        - "dir/subdir/"

"""
    (tmp_path / ".gitguardian.yaml").write_text(config)

    with cd(str(dir)):
        result = cli_fs_runner.invoke(
            cli,
            [
                "sca",
                "scan",
                "all",
                "subdir",
            ],
        )

    assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)
    assert "An ignored file or directory cannot be scanned." in result.stdout
    compute_sca_files_mock.assert_not_called()


@patch("pygitguardian.GGClient.compute_sca_files")
def test_sca_scan_diff_ignored_directory(
    compute_sca_files_mock: Mock,
    cli_fs_runner: click.testing.CliRunner,
    dummy_sca_repo: Repository,
) -> None:
    """
    GIVEN a directory which is ignored
    WHEN running the sca scan diff command on this directory
    THEN an error is raised
    """
    dummy_sca_repo.git("checkout", "branch_with_vuln")
    result = cli_fs_runner.invoke(
        cli,
        [
            "sca",
            "scan",
            "diff",
            "--ref",
            "branch_without_vuln",
            "--ignore-path",
            f"{dummy_sca_repo.path.name}/",
            str(dummy_sca_repo.path),
        ],
    )

    assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)
    assert "An ignored file or directory cannot be scanned." in result.stdout
    compute_sca_files_mock.assert_not_called()


@patch("pygitguardian.GGClient.sca_scan_directory")
@my_vcr.use_cassette("test_sca_scan_context_repository.yaml")
def test_sca_scan_context_repository(
    scan_mock: Mock, tmp_path: Path, cli_fs_runner: CliRunner, pipfile_lock_with_vuln
) -> None:
    """
    GIVEN a repository with a remote url
    WHEN executing a scan
    THEN repository url is sent
    """
    local_repo = Repository.create(tmp_path)
    remote_url = "https://github.com/owner/repository.git"
    local_repo.git("remote", "add", "origin", remote_url)

    file = local_repo.path / "Pipfile.lock"
    file.write_text(pipfile_lock_with_vuln)
    local_repo.add(file)
    local_repo.create_commit()

    cli_fs_runner.invoke(
        cli,
        [
            "sca",
            "scan",
            "all",
            str(local_repo.path),
        ],
    )

    scan_mock.assert_called_once()
    assert any(
        isinstance(arg, dict)
        and arg.get("GGShield-Repository-URL") == "github.com/owner/repository"
        for arg in scan_mock.call_args[0]
    )


@patch("ggshield.cmd.sca.scan.sca_scan_utils._create_tar")
@my_vcr.use_cassette("test_sca_scan_subdir_tar.yaml")
def test_sca_scan_subdir_tar(
    create_tar_mock: Mock,
    tmp_path: Path,
    cli_fs_runner: CliRunner,
    pipfile_lock_with_vuln: str,
) -> None:
    """
    GIVEN a git repository
    GIVEN an inner directory with a vulnerability
    GIVEN another directory with a vulnerability
    WHEN scanning the inner dir
    THEN tar is created with the correct structure
    """
    repo = Repository.create(tmp_path)
    repo.create_commit()

    inner_dir_path = tmp_path / "inner" / "dir"
    inner_dir_path.mkdir(parents=True)
    (inner_dir_path / "Pipfile.lock").write_text(pipfile_lock_with_vuln)

    other_dir_path = tmp_path / "other"
    other_dir_path.mkdir()
    (other_dir_path / "Pipfile.lock").write_text(pipfile_lock_with_vuln)

    repo.add(".")
    repo.create_commit()

    cli_fs_runner.invoke(
        cli,
        [
            "sca",
            "scan",
            "all",
            str(inner_dir_path),
        ],
    )

    create_tar_mock.assert_called_once()
    path, filenames = create_tar_mock.call_args.args
    tarbytes = _create_tar(path, filenames)
    fileobj = BytesIO(tarbytes)
    with tarfile.open(fileobj=fileobj) as tar:
        assert tar.getnames() == ["inner/dir/Pipfile.lock"]


@my_vcr.use_cassette("test_sca_scan_subdir_with_ignored_vuln.yaml")
@patch(
    "ggshield.cmd.sca.scan.sca_scan_utils.SCAScanParameters", wraps=SCAScanParameters
)
def test_sca_scan_subdir_with_ignored_vuln(
    sca_scan_params_mock: Mock,
    tmp_path: Path,
    cli_fs_runner: CliRunner,
    pipfile_lock_with_vuln: str,
) -> None:
    """
    GIVEN a git repository
    GIVEN an inner directory with a vulnerability
    GIVEN a .gitguardian.yaml file with an ignored vuln in the inner dir
    WHEN scanning the inner dir
    THEN the ignored vuln does not appear in the result
    """
    repo = Repository.create(tmp_path)
    repo.create_commit()

    inner_dir_path = tmp_path / "inner" / "dir"
    pipfile_path = inner_dir_path / "Pipfile.lock"

    ignored_vuln_text = f"""
version: 2

sca:
  ignored-vulnerabilities:
    - identifier: 'GHSA-2m57-hf25-phgg'
      path: {str(pipfile_path.relative_to(tmp_path))}
      comment: 'test ignored'
"""

    # Write .gitguardian.yaml config file at the root of the repo
    (tmp_path / ".gitguardian.yaml").write_text(ignored_vuln_text)
    inner_dir_path.mkdir(parents=True)
    pipfile_path.write_text(pipfile_lock_with_vuln)

    repo.add(".gitguardian.yaml")
    repo.add("inner/dir/Pipfile.lock")
    repo.create_commit()

    with cd(str(tmp_path)):
        result = cli_fs_runner.invoke(
            cli,
            [
                "sca",
                "scan",
                "all",
                str(inner_dir_path.relative_to(tmp_path)),
            ],
        )

        ignored_vulns = sca_scan_params_mock.call_args.kwargs["ignored_vulnerabilities"]
        assert [i.identifier for i in ignored_vulns] == ["GHSA-2m57-hf25-phgg"]

        assert result.exit_code == ExitCode.SUCCESS
        assert "GHSA-2m57-hf25-phgg" not in result.stdout


@my_vcr.use_cassette("test_sca_scan_subdir_with_ignored_vuln_with_until.yaml")
def test_sca_scan_subdir_with_ignored_vuln_with_until(
    tmp_path: Path,
    cli_fs_runner: CliRunner,
    pipfile_lock_with_vuln: str,
) -> None:
    """
    GIVEN a git repository
    GIVEN an inner directory with a vulnerability
    GIVEN a .gitguardian.yaml file with an ignored vuln in the inner dir until a future date
    WHEN scanning the inner dir
    THEN the ignored vuln does not appear in the result
    """
    repo = Repository.create(tmp_path)
    repo.create_commit()

    inner_dir_path = tmp_path / "inner" / "dir"
    pipfile_path = inner_dir_path / "Pipfile.lock"

    ignored_vuln_text = f"""
version: 2

sca:
  ignored-vulnerabilities:
    - identifier: 'GHSA-2m57-hf25-phgg'
      path: {str(pipfile_path.relative_to(tmp_path))}
      comment: 'test ignored'
      until: '2200-06-30T10:00:00'
"""

    # Write .gitguardian.yaml config file at the root of the repo
    (tmp_path / ".gitguardian.yaml").write_text(ignored_vuln_text)
    inner_dir_path.mkdir(parents=True)
    pipfile_path.write_text(pipfile_lock_with_vuln)

    repo.add(".gitguardian.yaml")
    repo.add("inner/dir/Pipfile.lock")
    repo.create_commit()

    with cd(str(tmp_path)):
        result = cli_fs_runner.invoke(
            cli,
            [
                "sca",
                "scan",
                "all",
                str(inner_dir_path.relative_to(tmp_path)),
            ],
        )

        assert result.exit_code == ExitCode.SUCCESS
        assert "GHSA-2m57-hf25-phgg" not in result.stdout


@my_vcr.use_cassette("test_sca_scan_all_ignore_fixable.yaml")
def test_scan_all_ignore_fixable(
    cli_fs_runner: click.testing.CliRunner,
    dummy_sca_repo: Repository,
):
    """
    GIVEN a directory with a fixable vuln
    WHEN running the sca scan all command on this directory with the --ignore-fixable flag
    THEN no incidents are returned
    """
    dummy_sca_repo.git("checkout", "branch_with_vuln")
    result = cli_fs_runner.invoke(
        cli,
        [
            "sca",
            "scan",
            "all",
            "--ignore-fixable",
            str(dummy_sca_repo.path),
        ],
    )

    assert_invoke_exited_with(result, ExitCode.SUCCESS)
    assert "No SCA vulnerability has been found." in result.stdout


@my_vcr.use_cassette("test_sca_scan_diff_ignore_fixable.yaml")
def test_scan_diff_ignore_fixable(
    cli_fs_runner: click.testing.CliRunner,
    dummy_sca_repo: Repository,
) -> None:
    """
    GIVEN a directory which is ignored
    WHEN running the sca scan diff command on this directory with the --ignore-fixable flag
    THEN the scan succeeds
    THEN no incidents are returned
    """
    dummy_sca_repo.git("checkout", "branch_with_vuln")
    result = cli_fs_runner.invoke(
        cli,
        [
            "sca",
            "scan",
            "diff",
            "--ignore-fixable",
            "--ref",
            "branch_without_vuln",
            str(dummy_sca_repo.path),
        ],
    )

    assert_invoke_exited_with(result, ExitCode.SUCCESS)
    assert "No SCA vulnerability has been added." in result.stdout


@my_vcr.use_cassette("test_sca_scan_all_ignore_not_fixable.yaml")
def test_scan_all_ignore_not_fixable(
    cli_fs_runner: click.testing.CliRunner,
    dummy_sca_repo: Repository,
):
    """
    GIVEN a directory with a fixable vuln
    WHEN running the sca scan all command on this directory with the --ignore-not-fixable flag
    THEN no incidents are returned
    """
    dummy_sca_repo.git("checkout", "branch_with_vuln_no_fix")
    result = cli_fs_runner.invoke(
        cli,
        [
            "sca",
            "scan",
            "all",
            "--ignore-not-fixable",
            str(dummy_sca_repo.path),
        ],
    )

    assert_invoke_exited_with(result, ExitCode.SUCCESS)
    assert "No SCA vulnerability has been found." in result.stdout


@my_vcr.use_cassette("test_sca_scan_diff_ignore_not_fixable.yaml")
def test_scan_diff_ignore_not_fixable(
    cli_fs_runner: click.testing.CliRunner,
    dummy_sca_repo: Repository,
) -> None:
    """
    GIVEN a directory which is ignored
    WHEN running the sca scan diff command on this directory with the --ignore-not-fixable flag
    THEN the scan succeeds
    THEN no incidents are returned
    """
    dummy_sca_repo.git("checkout", "branch_with_vuln_no_fix")
    result = cli_fs_runner.invoke(
        cli,
        [
            "sca",
            "scan",
            "diff",
            "--ignore-not-fixable",
            "--ref",
            "branch_without_vuln",
            str(dummy_sca_repo.path),
        ],
    )

    assert_invoke_exited_with(result, ExitCode.SUCCESS)
    assert "No SCA vulnerability has been added." in result.stdout
