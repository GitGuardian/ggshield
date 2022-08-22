import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from ggshield.cmd.main import cli
from tests.conftest import (
    _ONE_LINE_AND_MULTILINE_PATCH,
    UNCHECKED_SECRET_PATCH,
    VALID_SECRET_PATCH,
    assert_invoke_exited_with,
    assert_invoke_ok,
    my_vcr,
    skipwindows,
)


def create_normally_ignored_file() -> Path:
    path = Path("node_modules", "test.js")
    path.parent.mkdir()
    path.write_text("// Test")
    return path


class TestPathScan:
    """
    Tests related to ggshield secret scan path
    """

    def create_files(self):
        Path("file1").write_text("This is a file with no secrets.")
        Path("file2").write_text("This is a file with no secrets.")

    @my_vcr.use_cassette("test_scan_file")
    @pytest.mark.parametrize("verbose", [True, False])
    def test_scan_file(self, cli_fs_runner, verbose):
        Path("file").write_text("This is a file with no secrets.")
        assert os.path.isfile("file")

        if verbose:
            result = cli_fs_runner.invoke(cli, ["-v", "secret", "scan", "path", "file"])
        else:
            result = cli_fs_runner.invoke(cli, ["secret", "scan", "path", "file"])
        assert result.exit_code == 0, result.output
        assert not result.exception
        assert "No secrets have been found" in result.output

    @pytest.mark.parametrize("use_deprecated_syntax", [False, True])
    def test_scan_file_secret(self, cli_fs_runner, use_deprecated_syntax):
        """
        GIVEN a file with a secret
        WHEN it is scanned
        THEN the secret is reported
        AND the exit code is not 0
        AND there is a deprecated message in the output if the scan used the deprecated syntax
        """
        Path("file_secret").write_text(UNCHECKED_SECRET_PATCH)
        assert os.path.isfile("file_secret")

        cmd = ["scan", "path", "file_secret"]
        if not use_deprecated_syntax:
            cmd.insert(0, "secret")

        with my_vcr.use_cassette("test_scan_file_secret"):
            result = cli_fs_runner.invoke(cli, cmd)
            assert_invoke_exited_with(result, 1)
            assert result.exception
            assert (
                "GitGuardian Development Secret (Validity: No Checker)  (Ignore with SHA: 4f307a4cae8f14cc276398c666559a6d4f959640616ed733b168a9ee7ab08fd4)"  # noqa
                in result.output
            )

            if use_deprecated_syntax:
                assert "deprecated" in result.output

    def test_scan_file_secret_with_validity(self, cli_fs_runner):
        Path("file_secret").write_text(VALID_SECRET_PATCH)
        assert os.path.isfile("file_secret")

        with my_vcr.use_cassette("test_scan_path_file_secret_with_validity"):
            result = cli_fs_runner.invoke(
                cli, ["-v", "secret", "scan", "path", "file_secret"]
            )
        assert_invoke_exited_with(result, 1)
        assert result.exception
        assert (
            "Incident 1(Secrets detection): GitGuardian Test Token Checked (Validity: Valid)  (Ignore with SHA: 56c12"
            in result.output
        )

    @pytest.mark.parametrize("validity", [True, False])
    def test_scan_file_secret_json_with_validity(self, cli_fs_runner, validity):
        secret = VALID_SECRET_PATCH if validity else UNCHECKED_SECRET_PATCH
        Path("file_secret").write_text(secret)
        assert os.path.isfile("file_secret")

        cassette_name = f"test_scan_file_secret-{validity}"
        with my_vcr.use_cassette(cassette_name):
            cli_fs_runner.mix_stderr = False
            result = cli_fs_runner.invoke(
                cli, ["-v", "secret", "scan", "--json", "path", "file_secret"]
            )
        assert_invoke_exited_with(result, 1)
        assert result.exception

        if validity:
            assert '"validity": "valid"' in result.output
        else:
            assert '"validity": "valid"' not in result.output
        json.loads(result.output)

    @pytest.mark.parametrize("json_output", [False, True])
    def test_scan_file_secret_exit_zero(self, cli_fs_runner, json_output):
        Path("file_secret").write_text(UNCHECKED_SECRET_PATCH)
        assert os.path.isfile("file_secret")

        with my_vcr.use_cassette("test_scan_file_secret"):
            cli_fs_runner.mix_stderr = False
            json_arg = ["--json"] if json_output else []
            result = cli_fs_runner.invoke(
                cli,
                [
                    "secret",
                    "scan",
                    "--exit-zero",
                    "-v",
                    *json_arg,
                    "path",
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
        Path("file1").write_text("This is a file with no secrets.")
        Path("dir/file2").write_text("This is a file with no secrets.")
        Path("dir/subdir/file3").write_text("This is a file with no secrets.")
        Path("dir/subdir/file4").write_text("This is a file with no secrets.")

    def test_directory_error(self, cli_fs_runner):
        result = cli_fs_runner.invoke(cli, ["scan", "path", "-r", "./ewe-failing-test"])
        assert_invoke_exited_with(result, 2)
        assert result.exception
        assert "does not exist" in result.output

    def test_directory_abort(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(cli, ["scan", "path", "./", "-r"], input="n\n")
        assert_invoke_ok(result)
        assert not result.exception

    @my_vcr.use_cassette()
    def test_directory_yes(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(cli, ["scan", "path", "./", "-r", "-y"])
        assert_invoke_ok(result)
        assert not result.exception

    @my_vcr.use_cassette()
    def test_directory_verbose(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["-v", "secret", "scan", "path", "./", "-r"], input="y\n"
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
            cli, ["-v", "secret", "scan", "path", "./", "-r"], input="n\n"
        )
        assert_invoke_ok(result)
        assert not result.exception

    @skipwindows
    def test_directory_verbose_ignored_abort(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli,
            [
                "-v",
                "secret",
                "scan",
                "--exclude",
                "file1",
                "--exclude",
                "dir/file2",
                "path",
                "./",
                "-r",
            ],
            input="n\n",
        )
        assert_invoke_ok(result)
        assert "file1\n" not in result.output
        assert "dir/file2\n" not in result.output
        assert "dir/subdir/file3\n" in result.output
        assert not result.exception

    @my_vcr.use_cassette()
    def test_directory_verbose_yes(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["-v", "secret", "scan", "path", "./", "-r", "-y"]
        )
        assert result.exit_code == 0, result.output
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
        assert result.exit_code == 0, result.output
        assert all(
            string in result.output
            for string in ["Do you want to continue", "not_committed"]
        ), "not_committed files not should have been ignored"
        assert result.exception is None

    @pytest.mark.parametrize(
        "ignored_detectors, nb_secret",
        [
            ([], 2),
            (["-b", "RSA Private Key"], 1),
            (["-b", "SendGrid Key"], 1),
            (["-b", "host"], 2),
            (["-b", "SendGrid Key", "-b", "host"], 1),
            (["-b", "SendGrid Key", "-b", "RSA Private Key"], 0),
        ],
    )
    def test_ignore_detectors(
        self,
        cli_fs_runner,
        ignored_detectors,
        nb_secret,
    ):
        Path("file_secret").write_text(_ONE_LINE_AND_MULTILINE_PATCH)

        with my_vcr.use_cassette("test_scan_path_file_one_line_and_multiline_patch"):
            result = cli_fs_runner.invoke(
                cli,
                [
                    "secret",
                    "scan",
                    "--exit-zero",
                    "-v",
                    *ignored_detectors,
                    "path",
                    "file_secret",
                ],
            )
            assert result.exit_code == 0, result.output
            if nb_secret:
                plural = nb_secret > 1
                assert (
                    f"{nb_secret} incident{'s' if plural else ''} "
                    f"{'have' if plural else 'has'} been found"
                ) in result.output
            else:
                assert "No secrets have been found" in result.output
