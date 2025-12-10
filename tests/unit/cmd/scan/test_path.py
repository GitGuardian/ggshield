import json
import os
import re
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner
from pygitguardian.models import MultiScanResult

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from tests.repository import Repository
from tests.unit.conftest import (
    _ONE_LINE_AND_MULTILINE_PATCH,
    UNCHECKED_SECRET_PATCH,
    VALID_SECRET_PATCH,
    assert_invoke_exited_with,
    assert_invoke_ok,
    my_vcr,
    write_text,
)


def create_normally_ignored_file() -> Path:
    path = Path("node_modules", "test.js")
    path.parent.mkdir()
    write_text(path, "// Test")
    return path


class TestPathScan:
    """
    Tests related to ggshield secret scan path
    """

    def create_files(self):
        write_text(Path("file1"), "This is a file with no secrets.")
        write_text(Path("file2"), "This is a file with no secrets.")

    @my_vcr.use_cassette("test_scan_file")
    @pytest.mark.parametrize("verbose", [True, False])
    def test_scan_file(self, cli_fs_runner, verbose):
        write_text(Path("file"), "This is a file with no secrets.")
        assert os.path.isfile("file")

        if verbose:
            result = cli_fs_runner.invoke(cli, ["-v", "secret", "scan", "path", "file"])
        else:
            result = cli_fs_runner.invoke(cli, ["secret", "scan", "path", "file"])
        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert not result.exception
        assert "No secrets have been found" in result.output

    def test_scan_file_secret(self, cli_fs_runner):
        """
        GIVEN a file with a secret
        WHEN it is scanned
        THEN the secret is reported
        AND the exit code is not 0
        """
        write_text(Path("file_secret"), UNCHECKED_SECRET_PATCH)
        assert os.path.isfile("file_secret")

        cmd = ["secret", "scan", "path", "file_secret"]

        with my_vcr.use_cassette("test_scan_file_secret"):
            result = cli_fs_runner.invoke(cli, cmd)
            assert_invoke_exited_with(result, ExitCode.SCAN_FOUND_PROBLEMS)
            assert result.exception
            assert re.search(
                """>> Secret detected: GitGuardian Development Secret
   Validity: No Checker
   Occurrences: 1
   Known by GitGuardian dashboard: (YES|NO)
   Incident URL: (https://.*|N/A)
   Secret SHA: 4f307a4cae8f14cc276398c666559a6d4f959640616ed733b168a9ee7ab08fd4
""",
                result.output,
            )

    def test_scan_file_secret_with_validity(self, cli_fs_runner):
        write_text(Path("file_secret"), VALID_SECRET_PATCH)
        assert os.path.isfile("file_secret")
        with my_vcr.use_cassette("test_scan_path_file_secret_with_validity"):
            result = cli_fs_runner.invoke(
                cli, ["-v", "secret", "scan", "path", "file_secret"]
            )
        assert_invoke_exited_with(result, ExitCode.SCAN_FOUND_PROBLEMS)
        assert result.exception
        assert re.search(
            """>> Secret detected: GitGuardian Test Token Checked
   Validity: Valid
   Occurrences: 1
   Known by GitGuardian dashboard: (YES|NO)
   Incident URL: (https://.*|N/A)
   Secret SHA: 56c126cef75e3d17c3de32dac60bab688ecc384a054c2c85b688c1dd7ac4eefd
""",
            result.output,
        )

    @pytest.mark.parametrize("validity", [True, False])
    def test_scan_file_secret_json_with_validity(self, cli_fs_runner, validity):
        secret = VALID_SECRET_PATCH if validity else UNCHECKED_SECRET_PATCH
        write_text(Path("file_secret"), secret)
        assert os.path.isfile("file_secret")

        cassette_name = f"test_scan_file_secret-{validity}"
        with my_vcr.use_cassette(cassette_name):
            cli_fs_runner.mix_stderr = False
            result = cli_fs_runner.invoke(
                cli, ["-v", "secret", "scan", "--json", "path", "file_secret"]
            )
        assert_invoke_exited_with(result, ExitCode.SCAN_FOUND_PROBLEMS)
        assert result.exception

        if validity:
            assert '"validity": "valid"' in result.output
        else:
            assert '"validity": "valid"' not in result.output
        json.loads(result.output)

    @pytest.mark.parametrize("json_output", [False, True])
    def test_scan_file_secret_exit_zero(self, cli_fs_runner, json_output):
        write_text(Path("file_secret"), UNCHECKED_SECRET_PATCH)
        assert os.path.isfile("file_secret")

        with my_vcr.use_cassette("test_scan_file_secret"):
            cli_fs_runner.mix_stderr = False
            json_arg = ["--json"] if json_output else []
            result = cli_fs_runner.invoke(
                cli,
                [
                    "secret",
                    "scan",
                    "-v",
                    "path",
                    *json_arg,
                    "--exit-zero",
                    "file_secret",
                ],
            )
            assert_invoke_ok(result)
            assert not result.exception
            if json_output:
                json.loads(result.output)

    def test_files_abort(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["secret", "scan", "path", "file1", "file2"], input="n\n"
        )
        assert_invoke_ok(result)
        assert not result.exception

    @my_vcr.use_cassette()
    def test_files_yes(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["secret", "scan", "path", "file1", "file2", "-r", "-y"]
        )
        assert_invoke_ok(result)
        assert not result.exception

    @my_vcr.use_cassette()
    def test_files_verbose(self, cli_fs_runner: CliRunner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli,
            ["-v", "secret", "scan", "path", "file1", "file2", "-r"],
            input="y\n",
            catch_exceptions=True,
        )
        assert_invoke_ok(result)
        assert not result.exception
        assert "file1\n" in result.output
        assert "file2\n" in result.output
        assert "No secrets have been found" in result.output

    def test_files_verbose_abort(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["-v", "secret", "scan", "path", "file1", "file2", "-r"], input="n\n"
        )
        assert_invoke_ok(result)
        assert not result.exception

    @my_vcr.use_cassette()
    def test_files_verbose_yes(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["-v", "secret", "scan", "path", "file1", "file2", "-r", "-y"]
        )
        assert_invoke_ok(result)
        assert not result.exception
        assert "file1\n" in result.output
        assert "file2\n" in result.output
        assert "No secrets have been found" in result.output

    @patch("ggshield.verticals.secret.secret_scanner.SecretScanner.scan")
    def test_scan_ignored_file(self, scan_mock, cli_fs_runner):
        self.create_files()
        config = """
version: 2
secret:
    ignored_paths:
        - "file1"

"""
        write_text(Path(".gitguardian.yaml"), config)

        result = cli_fs_runner.invoke(
            cli, ["secret", "scan", "path", "file1", "file2", "-y"]
        )

        assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)
        assert "An ignored file or directory cannot be scanned." in result.stdout
        scan_mock.assert_not_called()

    def test_instance_option(self, cli_fs_runner):
        """
        GIVEN an instance url
        WHEN running the path command and passing the instance url as option
        THEN the call resulting from the command is made to the instance url
        """
        self.create_files()

        uri = "https://dashboard.my-instance.com"

        with patch("ggshield.core.client.GGClient") as client_mock:
            cli_fs_runner.invoke(
                cli, ["secret", "scan", "--instance", uri, "path", "file1"]
            )
            _, kwargs = client_mock.call_args
            assert kwargs["base_uri"] == "https://dashboard.my-instance.com/exposed"

    @pytest.mark.parametrize("position", [0, 1, 2, 3, 4])
    def test_ssl_verify(self, cli_fs_runner, position):
        """
        GIVEN the --insecure flag
        WHEN running the path scan command
        THEN SSL verification is disabled
        """
        self.create_files()

        cmd = ["secret", "scan", "path", "file1"]
        cmd.insert(position, "--insecure")

        with patch("ggshield.core.client.GGClient") as client_mock:
            cli_fs_runner.invoke(cli, cmd)
            _, kwargs = client_mock.call_args
            assert kwargs["session"].verify is False


class TestScanDirectory:
    """
    Tests related to ggshield secret scan path -r
    """

    @staticmethod
    def path_line(path_str):
        # Turn a path string into a \n terminated line
        # Takes care of Windows paths
        return str(Path(path_str)) + "\n"

    def create_files(self):
        os.makedirs("dir", exist_ok=True)
        os.makedirs("dir/subdir", exist_ok=True)
        write_text(Path("file1"), "This is a file with no secrets.")
        write_text(Path("dir/file2"), "This is a file with no secrets.")
        write_text(Path("dir/subdir/file3"), "This is a file with no secrets.")
        write_text(Path("dir/subdir/file4"), "This is a file with no secrets.")

    def test_directory_error(self, cli_fs_runner):
        result = cli_fs_runner.invoke(
            cli, ["secret", "scan", "path", "-r", "./ewe-failing-test"]
        )
        assert_invoke_exited_with(result, 2)
        assert result.exception
        assert "does not exist" in result.output

    def test_directory_abort(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["secret", "scan", "path", "./", "-r"], input="n\n"
        )
        assert_invoke_ok(result)
        assert not result.exception

    @my_vcr.use_cassette()
    def test_directory_yes(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(cli, ["secret", "scan", "path", "./", "-r", "-y"])
        assert_invoke_ok(result)
        assert not result.exception

    @my_vcr.use_cassette()
    def test_directory_verbose(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["secret", "scan", "path", "./", "-r", "-v"], input="y\n"
        )
        assert_invoke_ok(result)
        assert not result.exception
        assert "file1\n" in result.output
        assert self.path_line("dir/file2") in result.output
        assert self.path_line("dir/subdir/file3") in result.output
        assert "No secrets have been found" in result.output

    def test_directory_verbose_abort(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["secret", "-v", "scan", "path", "./", "-r"], input="n\n"
        )
        assert_invoke_ok(result)
        assert not result.exception

    def test_directory_verbose_ignored_abort(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli,
            [
                "secret",
                "scan",
                "-v",
                "--exclude",
                "file1",
                "path",
                "./",
                "-r",
                "--exclude",
                "dir/file2",
            ],
            input="n\n",
        )
        assert_invoke_ok(result)
        assert "file1\n" not in result.output
        assert self.path_line("dir/file2") not in result.output
        assert self.path_line("dir/subdir/file3") in result.output
        assert self.path_line("dir/subdir/file4") in result.output
        assert not result.exception

    def test_directory_verbose_ignored_path_abort(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli,
            [
                "secret",
                "scan",
                "-v",
                "path",
                "./",
                "-r",
                "--exclude",
                "dir/subdir/*",
            ],
            input="n\n",
        )
        assert_invoke_ok(result)
        assert "file1\n" in result.output
        assert self.path_line("dir/file2") in result.output
        assert self.path_line("dir/subdir/file3") not in result.output
        assert self.path_line("dir/subdir/file4") not in result.output
        assert not result.exception

    @my_vcr.use_cassette()
    def test_directory_verbose_yes(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["secret", "scan", "path", "./", "-r", "-vy"]
        )
        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert not result.exception
        assert "file1\n" in result.output
        assert self.path_line("dir/file2") in result.output
        assert self.path_line("dir/subdir/file3") in result.output
        assert "No secrets have been found" in result.output

    def test_scan_path_should_detect_non_git_files(self, cli_fs_runner):
        """
        GIVEN a path scan on a git repository
        WHEN some files are not followed by git
        THEN those files should still be picked on by ggshield for analysis
        """
        os.makedirs("git_repo")
        Path("git_repo/committed_file.js").write_text(
            "NPM_TOKEN=npm_xxxxxxxxxxxxxxxxxxxxxxxxxx"
        )
        os.system("git init")
        os.system("git add .")
        os.system("git commit -m 'initial commit'")
        Path("git_repo/not_committed.js").write_text(
            "NPM_TOKEN=npm_xxxxxxxxxxxxxxxxxxxxxxxxxx"
        )

        result = cli_fs_runner.invoke(
            cli, ["secret", "scan", "-v", "path", "--recursive", "."]
        )
        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert all(
            string in result.output
            for string in ["Do you want to continue", "not_committed"]
        ), "not_committed files should not have been ignored"
        assert result.exception is None

    def test_scan_path_use_gitignore(
        self, tmp_path: Path, cli_runner: CliRunner
    ) -> None:
        """
        GIVEN a directory containing a gitignore
        WHEN executing a scan with --use-gitignore option
        THEN ggshield should not scan the ignored files
        """

        # We can't use cassettes for this test because we want to scan 2 files.
        # Depending on the order of the files, the request and response will be different.

        local_repo = Repository.create(tmp_path)

        # files in repo
        ignored_secret = local_repo.path / "ignored_file_secret"
        found_secret = local_repo.path / "found_file_secret"
        write_text(ignored_secret, VALID_SECRET_PATCH)
        write_text(found_secret, VALID_SECRET_PATCH)

        gitignore = local_repo.path / ".gitignore"
        write_text(gitignore, "ignored_file_secret")

        # Submodule
        submodule_path = tmp_path / "submodule_repo"
        local_submodule = Repository.create(submodule_path)
        staged_sm_file = local_submodule.path / "committed_sm_file"
        write_text(staged_sm_file, "This is a file with no secrets.")
        local_submodule.git("add", str(staged_sm_file))
        local_submodule.create_commit(message="Initial commit")

        # Add submodule to the repository
        local_repo.git("submodule", "add", str(submodule_path))

        # Unstaged file in the submodule
        submodule_unstaged_file = local_submodule.path / "unstaged_sm_file"
        write_text(submodule_unstaged_file, "This is a file with no secrets.")

        # Scan with --use-gitignore
        with cli_runner.isolated_filesystem(temp_dir=tmp_path):
            result = cli_runner.invoke(
                cli,
                [
                    "secret",
                    "scan",
                    "path",
                    "--recursive",
                    "--use-gitignore",
                    str(local_repo.path),
                    "--verbose",
                ],
            )

        assert_invoke_ok(result)
        # All files should have been scanned, including the unstaged one
        assert all(
            string in result.output
            for string in [
                "Do you want to continue",
                "found_file_secret",
                "unstaged_sm_file",
                "committed_sm_file",
            ]
        )

    @pytest.mark.parametrize("all_secrets", (True, False))
    @pytest.mark.parametrize(
        ("ignored_detectors", "nb_secret", "nb_ignored"),
        [
            ([], 2, 0),
            (["-b", "RSA Private Key"], 1, 1),
            (["-b", "SendGrid Key"], 1, 1),
            (["-b", "host"], 2, 0),
            (["-b", "SendGrid Key", "-b", "host"], 1, 1),
            (["-b", "SendGrid Key", "-b", "RSA Private Key"], 0, 2),
        ],
    )
    def test_ignore_detectors(
        self, cli_fs_runner, ignored_detectors, nb_secret, nb_ignored, all_secrets
    ):
        write_text(Path("file_secret"), _ONE_LINE_AND_MULTILINE_PATCH)
        all_secrets_option = ["--all-secrets"] if all_secrets else []
        with my_vcr.use_cassette("test_scan_path_file_one_line_and_multiline_patch"):
            result = cli_fs_runner.invoke(
                cli,
                [
                    "secret",
                    "scan",
                    "-v",
                    *ignored_detectors,
                    "path",
                    "file_secret",
                    "--exit-zero",
                    *all_secrets_option,
                ],
            )
            assert result.exit_code == ExitCode.SUCCESS, result.output
            if all_secrets:
                total_secrets = nb_secret + nb_ignored
                assert (
                    f": {total_secrets} secret{'s' if total_secrets != 1 else ''} detected"
                ) in result.output
            else:
                assert (
                    f": {nb_secret} secret{'s' if nb_secret != 1 else ''} detected"
                ) in result.output
                if nb_ignored > 0:
                    assert (
                        f"{nb_ignored} secret{'s' if nb_ignored != 1 else ''} ignored"
                    ) in result.output

    @patch("pygitguardian.GGClient.multi_content_scan")
    @my_vcr.use_cassette("test_scan_context_repository.yaml")
    def test_scan_context_repository(
        self,
        scan_mock: Mock,
        tmp_path: Path,
        cli_fs_runner: CliRunner,
    ) -> None:
        """
        GIVEN a repository with a remote url
        WHEN executing a scan
        THEN repository url is sent
        """
        local_repo = Repository.create(tmp_path)
        remote_url = "https://github.com/owner/repository.git"
        local_repo.git("remote", "add", "origin", remote_url)

        file = local_repo.path / "file_secret"
        write_text(file, "Hello")
        local_repo.add(file)
        local_repo.create_commit()

        scan_result = MultiScanResult([])
        scan_result.status_code = 200
        scan_mock.return_value = scan_result

        result = cli_fs_runner.invoke(
            cli,
            [
                "secret",
                "scan",
                "path",
                str(file),
            ],
        )
        assert result.exit_code == ExitCode.SUCCESS, result.output

        scan_mock.assert_called_once()
        assert any(
            isinstance(arg, dict)
            and arg.get("GGShield-Repository-URL") == "github.com/owner/repository"
            for arg in scan_mock.call_args[0]
        )

    @patch("pygitguardian.GGClient.multi_content_scan")
    @my_vcr.use_cassette("test_scan_context_repository.yaml")
    def test_scan_path_with_fallback_repository_url(
        self,
        scan_mock: Mock,
        tmp_path: Path,
        cli_fs_runner: CliRunner,
    ) -> None:
        """
        GIVEN a repository without a remote url
        WHEN executing a scan with GITGUARDIAN_GIT_REMOTE_FALLBACK_URL set
        THEN the environment variable value is sent in the headers
        """
        local_repo = Repository.create(tmp_path)

        file = local_repo.path / "file_secret"
        write_text(file, "Hello")
        local_repo.add(file)
        local_repo.create_commit()

        scan_result = MultiScanResult([])
        scan_result.status_code = 200
        scan_mock.return_value = scan_result

        fallback_url = "https://github.com/fallback/repository.git"
        env = {
            "PATH": os.environ.get("PATH", ""),
            "GITGUARDIAN_API_KEY": os.environ.get("GITGUARDIAN_API_KEY", ""),
            "GITGUARDIAN_GIT_REMOTE_FALLBACK_URL": fallback_url,
            # Preserve home directory env vars (USERPROFILE for Windows, HOME for Unix)
            # needed by Path.home() and platformdirs
            "HOME": os.environ.get("HOME", ""),
            "USERPROFILE": os.environ.get("USERPROFILE", ""),
        }
        with patch.dict(os.environ, env, clear=True):
            result = cli_fs_runner.invoke(
                cli,
                [
                    "secret",
                    "scan",
                    "path",
                    str(file),
                ],
            )
        assert_invoke_ok(result)

        scan_mock.assert_called_once()
        assert any(
            isinstance(arg, dict)
            and arg.get("GGShield-Repository-URL") == "github.com/fallback/repository"
            for arg in scan_mock.call_args[0]
        )
