import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from ggshield.cmd import cli

from .conftest import (
    _ONE_LINE_AND_MULTILINE_PATCH,
    UNCHECKED_SECRET,
    VALID_SECRET,
    my_vcr,
)


def create_normally_ignored_file() -> Path:
    path = Path("node_modules", "test.js")
    path.parent.mkdir()
    path.write_text("// Test")
    return path


class TestPathScan:
    """
    Tests related to ggshield scan path
    """

    def create_files(self):
        Path("file1").write_text("This is a file with no secrets.")
        Path("file2").write_text("This is a file with no secrets.")

    @my_vcr.use_cassette("test_scan_file")
    def test_scan_file(self, cli_fs_runner):
        Path("file").write_text("This is a file with no secrets.")
        assert os.path.isfile("file")

        result = cli_fs_runner.invoke(cli, ["-v", "scan", "path", "file"])
        assert not result.exception
        assert "No secrets have been found" in result.output

    def test_scan_file_secret(self, cli_fs_runner):
        Path("file_secret").write_text(UNCHECKED_SECRET)
        assert os.path.isfile("file_secret")

        with my_vcr.use_cassette("test_scan_file_secret"):
            result = cli_fs_runner.invoke(cli, ["-v", "scan", "path", "file_secret"])
            print(result.output)
            assert result.exit_code == 1
            assert result.exception
            assert (
                "GitGuardian Development Secret (Validity: Cannot Check)  (Ignore with SHA: 4f307a4cae8f14cc276398c666559a6d4f959640616ed733b168a9ee7ab08fd4)"  # noqa
                in result.output
            )

    def test_scan_file_secret_with_validity(self, cli_fs_runner):
        Path("file_secret").write_text(VALID_SECRET)
        assert os.path.isfile("file_secret")

        with my_vcr.use_cassette("test_scan_file_secret_with_validity"):
            result = cli_fs_runner.invoke(cli, ["-v", "scan", "path", "file_secret"])
        assert result.exit_code == 1
        assert result.exception
        assert (
            "Incident 1(Secrets detection): GitGuardian Test Token Checked (Validity: Valid)  (Ignore with SHA: 56c12"
            in result.output
        )

    @pytest.mark.parametrize("validity", [True, False])
    def test_scan_file_secret_json_with_validity(self, cli_fs_runner, validity):
        secret = VALID_SECRET if validity else UNCHECKED_SECRET
        Path("file_secret").write_text(secret)
        assert os.path.isfile("file_secret")

        cassette_name = f"test_scan_file_secret-{validity}"
        with my_vcr.use_cassette(cassette_name):
            result = cli_fs_runner.invoke(
                cli, ["-v", "scan", "--json", "path", "file_secret"]
            )
        assert result.exit_code == 1
        assert result.exception

        if validity:
            assert '"validity": "valid"' in result.output
        else:
            assert '"validity": "valid"' not in result.output

    def test_scan_file_secret_exit_zero(self, cli_fs_runner):
        Path("file_secret").write_text(UNCHECKED_SECRET)
        assert os.path.isfile("file_secret")

        with my_vcr.use_cassette("test_scan_file_secret"):
            result = cli_fs_runner.invoke(
                cli, ["scan", "--exit-zero", "-v", "path", "file_secret"]
            )
            assert result.exit_code == 0
            assert not result.exception

    def test_files_abort(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["scan", "path", "file1", "file2"], input="n\n"
        )
        assert result.exit_code == 0
        assert not result.exception

    @my_vcr.use_cassette()
    def test_files_yes(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["scan", "path", "file1", "file2", "-r", "-y"]
        )
        assert result.exit_code == 0
        assert not result.exception
        assert "" in result.output

    @my_vcr.use_cassette()
    def test_files_verbose(self, cli_fs_runner: CliRunner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli,
            ["-v", "scan", "path", "file1", "file2", "-r"],
            input="y\n",
            catch_exceptions=True,
        )
        assert result.exit_code == 0
        assert not result.exception
        assert "file1\n" in result.output
        assert "file2\n" in result.output
        assert "No secrets have been found" in result.output

    def test_files_verbose_abort(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["-v", "scan", "path", "file1", "file2", "-r"], input="n\n"
        )
        assert result.exit_code == 0
        assert not result.exception

    @my_vcr.use_cassette()
    def test_files_verbose_yes(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["-v", "scan", "path", "file1", "file2", "-r", "-y"]
        )
        assert result.exit_code == 0
        assert not result.exception
        assert "file1\n" in result.output
        assert "file2\n" in result.output
        assert "No secrets have been found" in result.output


class TestScanDirectory:
    """
    Tests related to ggshield scan path -r
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
        assert result.exit_code == 2
        assert result.exception
        assert "does not exist" in result.output

    def test_directory_abort(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(cli, ["scan", "path", "./", "-r"], input="n\n")
        assert result.exit_code == 0
        assert not result.exception

    @my_vcr.use_cassette()
    def test_directory_yes(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(cli, ["scan", "path", "./", "-r", "-y"])
        assert "" in result.output
        assert not result.exception

    @my_vcr.use_cassette()
    def test_directory_verbose(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["-v", "scan", "path", "./", "-r"], input="y\n"
        )
        assert not result.exception
        assert "file1\n" in result.output
        assert self.path_line("dir/file2") in result.output
        assert self.path_line("dir/subdir/file3") in result.output
        assert "No secrets have been found" in result.output

    def test_directory_verbose_abort(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["-v", "scan", "path", "./", "-r"], input="n\n"
        )
        assert result.exit_code == 0
        assert not result.exception

    def test_directory_verbose_ignored_abort(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli,
            [
                "-v",
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
        assert "file1\n" not in result.output
        assert "dir/file2\n" not in result.output
        assert "dir/subdir/file3\n" in result.output
        assert result.exit_code == 0
        assert not result.exception

    @my_vcr.use_cassette()
    def test_directory_verbose_yes(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(cli, ["-v", "scan", "path", "./", "-r", "-y"])
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

        result = cli_fs_runner.invoke(cli, ["scan", "-v", "path", "--recursive", "."])
        assert all(
            string in result.output
            for string in ["Do you want to continue", "not_committed"]
        ), "not_committed files not should have been ignored"
        assert result.exception is None

    def test_ignore_default_excludes(self, cli_fs_runner):
        """
        GIVEN a path scan
        WHEN no options are passed
        THEN ignored patterns by default should be used
        """
        path = create_normally_ignored_file()

        result = cli_fs_runner.invoke(cli, ["scan", "-v", "path", "--recursive", "."])
        assert str(path) not in result.output
        assert result.exit_code == 0
        assert result.exception is None

    def test_ignore_default_excludes_with_configuration(self, cli_fs_runner):
        """
        GIVEN a path scan
        WHEN ignore-default-excludes has been put to true in the configuration
        THEN ignored patterns by default should NOT be used
        """
        path = create_normally_ignored_file()
        Path(".gitguardian.yml").write_text("ignore-default-excludes: true")

        with my_vcr.use_cassette("ignore_default_excludes_from_configuration"):
            result = cli_fs_runner.invoke(
                cli, ["scan", "-v", "path", "--recursive", "-y", "."]
            )
        assert str(path) in result.output
        assert result.exit_code == 0
        assert result.exception is None

    def test_ignore_default_excludes_with_flag(self, cli_fs_runner):
        """
        GIVEN a path scan
        WHEN --ignore-default-excludes has been used
        THEN ignored patterns by default should NOT be used
        """
        path = create_normally_ignored_file()

        with my_vcr.use_cassette("ignore_default_excludes_from_flag"):
            result = cli_fs_runner.invoke(
                cli,
                ["scan", "-v", "--ignore-default-excludes", "path", "--recursive", "."],
            )
        assert str(path) in result.output
        assert result.exit_code == 0
        assert result.exception is None

    @pytest.mark.parametrize(
        "banlisted_detectors, nb_secret",
        [
            ([], 2),
            (["-b", "RSA Private Key"], 1),
            (["-b", "SendGrid Key"], 1),
            (["-b", "host"], 2),
            (["-b", "SendGrid Key", "-b", "host"], 1),
            (["-b", "SendGrid Key", "-b", "RSA Private Key"], 0),
        ],
    )
    def test_banlisted_detectors(
        self,
        cli_fs_runner,
        banlisted_detectors,
        nb_secret,
    ):
        Path("file_secret").write_text(_ONE_LINE_AND_MULTILINE_PATCH)

        with my_vcr.use_cassette("_ONE_LINE_AND_MULTILINE_PATCH"):
            result = cli_fs_runner.invoke(
                cli,
                [
                    "scan",
                    "--exit-zero",
                    "-v",
                    *banlisted_detectors,
                    "path",
                    "file_secret",
                ],
            )
            if nb_secret:
                plural = nb_secret > 1
                assert (
                    f"{nb_secret} incident{'s' if plural else ''} "
                    f"{'have' if plural else 'has'} been found"
                ) in result.output
            else:
                assert "No secrets have been found" in result.output
