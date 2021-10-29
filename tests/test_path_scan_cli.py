import os

import pytest
from click.testing import CliRunner

from ggshield.cmd import cli

from .conftest import _ONE_LINE_AND_MULTILINE_PATCH, _SIMPLE_SECRET, my_vcr


class TestPathScan:
    """
    Tests related to ggshield scan path
    """

    def create_files(self):
        os.system('echo "This is a file with no secrets." > file1')
        os.system('echo "This is a file with no secrets." > file2')

    @my_vcr.use_cassette("test_scan_file")
    def test_scan_file(self, cli_fs_runner):
        os.system('echo "This is a file with no secrets." > file')
        assert os.path.isfile("file")

        result = cli_fs_runner.invoke(cli, ["-v", "scan", "path", "file"])
        assert not result.exception
        assert "No secrets have been found" in result.output

    def test_scan_file_secret(self, cli_fs_runner):
        os.system(f'echo "{_SIMPLE_SECRET}" > file_secret')  # nosec
        assert os.path.isfile("file_secret")

        with my_vcr.use_cassette("test_scan_file_secret"):
            result = cli_fs_runner.invoke(cli, ["-v", "scan", "path", "file_secret"])
            assert result.exit_code == 1
            assert result.exception
            assert (
                "SendGrid Key (Ignore with SHA: 530e5a4a7ea00814db8845dd0cae5efaa4b974a3ce1c76d0384ba715248a5dc1)"
                in result.output
            )

    def test_scan_file_secret_with_validity(self, cli_fs_runner):
        os.system(f'echo "{_SIMPLE_SECRET}" > file_secret')  # nosec
        assert os.path.isfile("file_secret")

        with my_vcr.use_cassette("test_scan_file_secret_with_validity"):
            result = cli_fs_runner.invoke(cli, ["-v", "scan", "path", "file_secret"])
        assert result.exit_code == 1
        assert result.exception
        assert (
            "Incident 1(Secrets detection): SendGrid Key (Validity: Valid)  (Ignore with SHA: 530e5a4a7ea00814db8845d"
            in result.output
        )

    @pytest.mark.parametrize("validity", [True, False])
    def test_scan_file_secret_json_with_validity(self, cli_fs_runner, validity):
        os.system(f'echo "{_SIMPLE_SECRET}" > file_secret')  # nosec
        assert os.path.isfile("file_secret")

        cassette_name = "test_scan_file_secret"
        if validity:
            cassette_name = "test_scan_file_secret_with_validity"

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
        os.system(f'echo "{_SIMPLE_SECRET}" > file_secret')  # nosec
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

    def create_files(self):
        os.makedirs("dir", exist_ok=True)
        os.makedirs("dir/subdir", exist_ok=True)
        os.system('echo "This is a file with no secrets." > file1')
        os.system('echo "This is a file with no secrets." > dir/file2')
        os.system('echo "This is a file with no secrets." > dir/subdir/file3')
        os.system('echo "This is a file with no secrets." > dir/subdir/file4')

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
        assert "dir/file2\n" in result.output
        assert "dir/subdir/file3\n" in result.output
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
        assert "dir/file2\n" in result.output
        assert "dir/subdir/file3\n" in result.output
        assert "No secrets have been found" in result.output

    def test_scan_path_should_detect_non_git_files(self, cli_fs_runner):
        """
        GIVEN a path scan on a git repository
        WHEN some files are not followed by git
        THEN those files should still be picked on by ggshield for analysis
        """
        os.makedirs("git_repo")
        os.system(
            'echo "NPM_TOKEN=npm_xxxxxxxxxxxxxxxxxxxxxxxxxx" > git_repo/committed_file.js'
        )
        os.system("git init")
        os.system("git add .")
        os.system("git commit -m 'initial commit'")
        os.system(
            'echo "NPM_TOKEN=npm_xxxxxxxxxxxxxxxxxxxxxxxxxx" > git_repo/not_committed.js'
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
        os.makedirs("node_modules")
        os.system(
            'echo "NPM_TOKEN=npm_xxxxxxxxxxxxxxxxxxxxxxxxxx" > node_modules/test.js'
        )

        result = cli_fs_runner.invoke(cli, ["scan", "-v", "path", "--recursive", "."])
        assert result.exit_code == 0, "node_modules should have been ignored"
        assert result.exception is None

    def test_ignore_default_excludes_with_configuration(self, cli_fs_runner):
        """
        GIVEN a path scan
        WHEN ignore-default-excludes has been put to true in the configuration
        THEN ignored patterns by default should NOT be used
        """
        os.makedirs("node_modules")
        os.system(
            'echo "NPM_TOKEN=npm_xxxxxxxxxxxxxxxxxxxxxxxxxx" > node_modules/test.js'
        )
        os.system('echo "ignore-default-excludes: true" > .gitguardian.yml')

        with my_vcr.use_cassette("ignore_default_excludes_from_configuration"):
            result = cli_fs_runner.invoke(
                cli, ["scan", "-v", "path", "--recursive", "."]
            )
        assert result.exit_code == 0, "node_modules should not have been ignored"
        assert (
            "node_modules/test.js" in result.output
        ), "node_modules should not have been ignored"
        assert result.exception is None

    def test_ignore_default_excludes_with_flag(self, cli_fs_runner):
        """
        GIVEN a path scan
        WHEN --ignore-default-excludes has been used
        THEN ignored patterns by default should NOT be used
        """
        os.makedirs("node_modules")
        os.system(
            'echo "NPM_TOKEN=npm_xxxxxxxxxxxxxxxxxxxxxxxxxx" > node_modules/test.js'
        )

        with my_vcr.use_cassette("ignore_default_excludes_from_flag"):
            result = cli_fs_runner.invoke(
                cli,
                ["scan", "-v", "--ignore-default-excludes", "path", "--recursive", "."],
            )
        assert result.exit_code == 1, "node_modules should not have been ignored"
        assert result.exception

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
        os.system(f'echo "{_ONE_LINE_AND_MULTILINE_PATCH}" > file_secret')  # nosec

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
