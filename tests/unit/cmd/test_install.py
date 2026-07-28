import os
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner
from pygitguardian.models import HealthCheckResponse

from ggshield.__main__ import cli
from ggshield.cmd.install import (
    LOCAL_HOOK_SNIPPET,
    get_default_global_hook_dir_path,
    install_local,
)
from ggshield.core.errors import ExitCode, MissingTokenError
from ggshield.verticals.ai.installation import _is_interactive
from tests.repository import Repository
from tests.unit.conftest import assert_invoke_exited_with, assert_invoke_ok


SAMPLE_PRE_COMMIT = """#!/bin/sh
ggshield secret scan pre-commit "$@"
"""

SAMPLE_PRE_PUSH = """#!/bin/sh
ggshield secret scan pre-push "$@"
"""


class TestInstallLocal:
    def test_local_exist_is_dir(self, cli_fs_runner):
        os.system("git init")
        hook_path = Path(".git/hooks/pre-commit")
        hook_path.mkdir()

        result = cli_fs_runner.invoke(cli, ["install", "-m", "local"])
        assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)
        assert result.exception
        assert f"Error: {hook_path} is a directory" in result.output

    def test_local_exist_not_force(self, cli_fs_runner):
        os.system("git init")
        hook_path = Path(".git/hooks/pre-commit")
        hook_path.write_text("pre-commit file")

        result = cli_fs_runner.invoke(cli, ["install", "-m", "local"])
        assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
        assert result.exception
        assert f"Error: {hook_path} already exists." in result.output

    def test_local_exist_force(self, cli_fs_runner):
        os.system("git init")
        hook_path = Path(".git/hooks/pre-commit")
        hook_path.write_text("pre-commit file")

        result = cli_fs_runner.invoke(cli, ["install", "-f", "-m", "local"])
        assert_invoke_ok(result)
        assert f"pre-commit successfully added in {hook_path}" in result.output

    @patch("ggshield.cmd.install.check_git_dir")
    def test_precommit_install(
        self,
        check_dir_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN None
        WHEN the command is run
        THEN it should create a pre-commit git hook script
        """

        result = cli_fs_runner.invoke(
            cli,
            ["install", "-m", "local"],
        )
        hook_path = Path(".git/hooks/pre-commit")
        hook_str = hook_path.read_text()
        assert hook_str == SAMPLE_PRE_COMMIT

        assert f"pre-commit successfully added in {hook_path}\n" in result.output
        assert_invoke_ok(result)

    @pytest.mark.parametrize("hook_type", ["pre-push", "pre-commit"])
    @patch("ggshield.cmd.install.check_git_dir")
    def test_install_exists(
        self,
        check_dir_mock: Mock,
        hook_type: str,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a hook that already exists
        WHEN the command is run without --force or --append
        THEN it should error
        """
        hook_path = Path(".git/hooks") / hook_type
        hook_path.parent.mkdir(parents=True)
        hook_path.write_text("#!/bin/bash\nsample-command\n")

        result = cli_fs_runner.invoke(
            cli,
            ["install", "-m", "local", "-t", hook_type],
        )

        assert (
            "already exists. Use --force to override or --append to add to current script\n"
            in result.output
        )
        assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)

    @pytest.mark.parametrize("hook_type", ["pre-push", "pre-commit"])
    @patch("ggshield.cmd.install.check_git_dir")
    def test_install_exists_force(
        self,
        check_dir_mock: Mock,
        hook_type: str,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a hook that already exists
        WHEN the command is run with --force
        THEN it should return 0 and install the hook
        """
        hook_path = Path(".git/hooks") / hook_type
        hook_path.parent.mkdir(parents=True)
        hook_path.write_text("#!/bin/bash\nsample-command\n")

        result = cli_fs_runner.invoke(
            cli,
            ["install", "-m", "local", "-t", hook_type, "--force"],
        )

        assert f"{hook_type} successfully added in {hook_path}\n" in result.output
        assert_invoke_ok(result)

    @pytest.mark.parametrize("hook_type", ["pre-push", "pre-commit"])
    @patch("ggshield.cmd.install.check_git_dir")
    def test_install_exists_append(
        self,
        check_dir_mock: Mock,
        hook_type: str,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a hook that already exists
        WHEN the command is run with --append
        THEN it should return 0 and append the hook to the existing one
        """
        hook_path = Path(".git/hooks") / hook_type
        hook_path.parent.mkdir(parents=True)
        hook_path.write_text("#!/bin/bash\nsample-command\n")

        result = cli_fs_runner.invoke(
            cli,
            ["install", "-m", "local", "-t", hook_type, "--append"],
        )
        hook_str = hook_path.read_text()
        assert "sample-command" in hook_str
        assert "ggshield secret scan" in hook_str

        assert f"{hook_type} successfully added in {hook_path}\n" in result.output
        assert_invoke_ok(result)

    @patch("ggshield.cmd.install.check_git_dir")
    def test_prepush_install(
        self,
        check_dir_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN None
        WHEN the command is run
        THEN it should create a pre-push git hook script
        """

        result = cli_fs_runner.invoke(
            cli,
            ["install", "-m", "local", "-t", "pre-push"],
        )
        hook_path = Path(".git/hooks/pre-push")
        hook_str = hook_path.read_text()
        assert hook_str == SAMPLE_PRE_PUSH

        assert f"pre-push successfully added in {hook_path}\n" in result.output
        assert_invoke_ok(result)

    @patch("ggshield.cmd.install.check_git_dir")
    @patch("ggshield.cmd.install.git")
    def test_install_local_detects_husky(
        self,
        git_mock: Mock,
        check_dir_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a repository configured with Husky (.husky/_ directory as hooks path)
        WHEN install_local is called
        THEN it should create the hook in .husky/pre-commit instead of .git/hooks
        """
        husky_dir = Path(".husky")
        husky_hooks_dir = husky_dir / "_"
        husky_hooks_dir.mkdir(parents=True)

        # Mock git to return .husky/_ as the local hooks path
        git_mock.return_value = ".husky/_"

        return_code = install_local(hook_type="pre-commit", force=False, append=False)

        assert return_code == 0

        # Hook should be in .husky/pre-commit, not .husky/_/pre-commit
        husky_hook = husky_dir / "pre-commit"
        assert husky_hook.is_file()
        assert 'ggshield secret scan pre-commit "$@"' in husky_hook.read_text()

        # Hook should NOT be in .git/hooks/pre-commit
        default_hook = Path(".git/hooks/pre-commit")
        assert not default_hook.exists()


@pytest.fixture()
def custom_global_git_config_path(tmp_path, monkeypatch):
    config_path = tmp_path / "global-git-config"
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config_path))
    yield config_path


class TestInstallGlobal:
    """
    These tests use the cli_runner fixture and not the cli_fs_runner one. The reason for
    this is they execute git commands and git commands are not run in the fake
    filesystem created by cli_fs_runner so the fake filesystem is useless here.
    """

    def test_global_exist_is_dir(
        self, cli_runner: CliRunner, custom_global_git_config_path: Path
    ):
        global_pre_commit_hook_path = get_default_global_hook_dir_path() / "pre-commit"
        global_pre_commit_hook_path.mkdir(parents=True)

        result = cli_runner.invoke(cli, ["install", "-m", "global"])
        assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)
        assert result.exception

    def test_global_not_exist(self, cli_runner, custom_global_git_config_path: Path):
        global_pre_commit_hook_path = get_default_global_hook_dir_path() / "pre-commit"
        assert not global_pre_commit_hook_path.exists()

        result = cli_runner.invoke(cli, ["install", "-m", "global"])
        assert global_pre_commit_hook_path.is_file()
        assert_invoke_ok(result)
        assert (
            f"pre-commit successfully added in {global_pre_commit_hook_path}"
            in result.output
        )

    def test_install_custom_global_hook_dir(
        self, cli_runner: CliRunner, tmp_path: Path, custom_global_git_config_path: Path
    ):
        """
        GIVEN an existing global git config
        AND a custom value for core.hooksPath in the global git config
        WHEN `install -m global` is called
        THEN it installs the hook in the custom core.hooksPath dir
        """
        custom_hooks_dir = tmp_path / "custom-hooks-dir"
        custom_pre_commit_path = custom_hooks_dir / "pre-commit"
        custom_global_git_config_path.write_text(
            f"[core]\nhooksPath = {custom_hooks_dir.as_posix()}\n", encoding="utf-8"
        )

        result = cli_runner.invoke(cli, ["install", "-m", "global"])
        assert_invoke_ok(result)
        assert custom_pre_commit_path.is_file()
        assert (
            f"pre-commit successfully added in {custom_pre_commit_path}"
            in result.output
        )

    @pytest.mark.parametrize("hook_type", ["pre-push", "pre-commit"])
    def test_install_global(
        self,
        hook_type: str,
        cli_runner: CliRunner,
        custom_global_git_config_path: Path,
    ):
        """
        GIVEN None
        WHEN the command is run
        THEN it should create a pre-push git hook script in the global path
        """

        result = cli_runner.invoke(
            cli,
            ["install", "-m", "global", "-t", hook_type],
        )

        hook_path = get_default_global_hook_dir_path() / hook_type
        hook_str = hook_path.read_text()
        assert (
            f"_ggshield_local_hook=$(git rev-parse --git-common-dir)/hooks/{hook_type}"
            in hook_str
        )
        assert f"ggshield secret scan {hook_type}" in hook_str

        assert f"{hook_type} successfully added in {hook_path}\n" in result.output
        assert_invoke_ok(result)

    def test_global_exist_not_force(
        self, cli_runner: CliRunner, custom_global_git_config_path: Path
    ):
        """
        GIVEN a global hook dir with an exising pre-commit script
        WHEN install is called
        THEN it fails
        """
        hook_path = get_default_global_hook_dir_path() / "pre-commit"
        hook_path.parent.mkdir(parents=True, exist_ok=True)
        hook_path.write_text("pre-commit file")
        assert hook_path.is_file()

        result = cli_runner.invoke(cli, ["install", "-m", "global"])
        assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
        assert result.exception
        assert f"Error: {hook_path} already exists." in result.output

    def test_global_exist_force(
        self, cli_runner: CliRunner, custom_global_git_config_path: Path
    ):
        """
        GIVEN a global hook dir with an exising pre-commit script
        WHEN install is called with -f
        THEN it ignores the fact that the pre-commit script exists and succeeds
        """
        hook_path = get_default_global_hook_dir_path() / "pre-commit"
        hook_path.parent.mkdir(parents=True, exist_ok=True)
        hook_path.write_text("pre-commit file")
        assert hook_path.is_file()

        result = cli_runner.invoke(cli, ["install", "-m", "global", "-f"])
        assert_invoke_ok(result)
        assert f"pre-commit successfully added in {hook_path}" in result.output


class TestInstallAIHook:
    @patch("ggshield.verticals.ai.installation._is_interactive", return_value=False)
    def test_install_ai_hook_is_deprecated(
        self, interactive_mock: Mock, cli_fs_runner: CliRunner
    ):
        """Installing an AI hook per assistant warns it is deprecated."""
        result = cli_fs_runner.invoke(
            cli, ["install", "-m", "local", "-t", "claude-code"]
        )
        assert_invoke_ok(result)
        assert "deprecated" in result.output
        assert "machine setup" in result.output

    @patch("ggshield.cmd.install.check_git_dir")
    def test_install_git_hook_is_not_deprecated(
        self, check_dir_mock: Mock, cli_fs_runner: CliRunner
    ):
        """Installing a git hook is not deprecated and must not warn."""
        result = cli_fs_runner.invoke(
            cli, ["install", "-m", "local", "-t", "pre-commit"]
        )
        assert_invoke_ok(result)
        assert "deprecated" not in result.output

    @patch("ggshield.verticals.ai.installation._is_interactive", return_value=True)
    @patch("ggshield.verticals.ai.installation.create_client_from_config")
    def test_install_auth_preflight_success(
        self, create_client_mock: Mock, interactive_mock: Mock, cli_fs_runner: CliRunner
    ):
        """
        GIVEN a working authentication and an interactive install
        WHEN installing an AI agent hook
        THEN the hooks are installed and the preflight reports the hook is ready
        """
        create_client_mock.return_value.health_check.return_value = Mock(
            spec=HealthCheckResponse, status_code=200
        )

        result = cli_fs_runner.invoke(
            cli, ["install", "-m", "local", "-t", "claude-code"]
        )
        assert_invoke_ok(result)
        assert Path(".claude/settings.json").is_file()
        assert "the hook is ready to scan" in result.output

    @patch("ggshield.verticals.ai.installation._is_interactive", return_value=True)
    @patch(
        "ggshield.verticals.ai.installation.create_client_from_config",
        side_effect=MissingTokenError(instance="https://dashboard.gitguardian.com"),
    )
    def test_install_auth_preflight_failure_warns(
        self, create_client_mock: Mock, interactive_mock: Mock, cli_fs_runner: CliRunner
    ):
        """
        GIVEN a broken authentication (no token, unreadable keyring...)
        WHEN installing an AI agent hook interactively
        THEN the hooks are still installed but the user is warned the hook
        cannot scan yet
        """
        result = cli_fs_runner.invoke(
            cli, ["install", "-m", "local", "-t", "claude-code"]
        )
        assert_invoke_ok(result)
        assert Path(".claude/settings.json").is_file()
        assert "will NOT scan anything" in result.output
        assert "ggshield auth login" in result.output

    @patch("ggshield.verticals.ai.installation._is_interactive", return_value=False)
    @patch("ggshield.verticals.ai.installation.create_client_from_config")
    def test_install_auth_preflight_skipped_when_non_interactive(
        self, create_client_mock: Mock, interactive_mock: Mock, cli_fs_runner: CliRunner
    ):
        """
        GIVEN a non-interactive install (CI, automated fleet/MDM provisioning)
        WHEN installing an AI agent hook
        THEN the hooks are installed but the auth preflight is skipped, so no
        credential-store access is triggered
        """
        result = cli_fs_runner.invoke(
            cli, ["install", "-m", "local", "-t", "claude-code"]
        )
        assert_invoke_ok(result)
        assert Path(".claude/settings.json").is_file()
        create_client_mock.assert_not_called()
        assert "ready to scan" not in result.output

    @patch("ggshield.verticals.ai.installation._is_interactive", return_value=True)
    @patch("ggshield.verticals.ai.installation.create_client_from_config")
    def test_install_auth_preflight_unhealthy_warns(
        self, create_client_mock: Mock, interactive_mock: Mock, cli_fs_runner: CliRunner
    ):
        """
        GIVEN reachable authentication but an unhealthy GitGuardian instance
        WHEN installing an AI agent hook interactively
        THEN the user is warned the hook cannot scan yet
        """
        create_client_mock.return_value.health_check.return_value = Mock(
            spec=HealthCheckResponse, status_code=503, detail="service unavailable"
        )

        result = cli_fs_runner.invoke(
            cli, ["install", "-m", "local", "-t", "claude-code"]
        )
        assert_invoke_ok(result)
        assert "will NOT scan anything" in result.output

    def test_is_interactive_reflects_stdout_tty(self):
        """_is_interactive mirrors whether stdout is a terminal."""
        with patch("ggshield.verticals.ai.installation.sys.stdout") as stdout:
            stdout.isatty.return_value = True
            assert _is_interactive() is True
            stdout.isatty.return_value = False
            assert _is_interactive() is False


@pytest.fixture()
def custom_system_paths(tmp_path, monkeypatch):
    """Redirect git's system config + ggshield's system data dir to temp locations,
    so system-scope hooks can be tested without root or touching /etc."""
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(tmp_path / "system-git-config"))
    monkeypatch.setenv("GG_SYSTEM_DATA_DIR", str(tmp_path / "system-data"))
    yield


class TestInstallSystem:
    """`install_system` installs git hooks machine-wide (used by `machine setup` as root)."""

    def test_writes_hook_and_system_hookspath(self, custom_system_paths):
        from ggshield.cmd.install import (
            get_default_system_hook_dir_path,
            install_system,
        )

        assert install_system("pre-commit", force=False, append=False) == 0
        hook_path = get_default_system_hook_dir_path() / "pre-commit"
        assert hook_path.is_file()
        hook_str = hook_path.read_text()
        assert (
            "_ggshield_local_hook=$(git rev-parse --git-common-dir)/hooks/pre-commit"
            in hook_str
        )
        assert "ggshield secret scan pre-commit" in hook_str

        out = subprocess.check_output(
            ["git", "config", "--system", "--get", "core.hooksPath"], text=True
        ).strip()
        assert out == str(get_default_system_hook_dir_path())

    def test_honors_existing_system_hookspath(self, tmp_path, custom_system_paths):
        from ggshield.cmd.install import install_system

        custom = tmp_path / "shared-hooks"
        subprocess.run(
            ["git", "config", "--system", "core.hooksPath", str(custom)], check=True
        )
        assert install_system("pre-push", force=False, append=False) == 0
        assert (custom / "pre-push").is_file()

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX file mode bits")
    def test_hook_is_world_readable(self, custom_system_paths):
        from ggshield.cmd.install import (
            get_default_system_hook_dir_path,
            install_system,
        )

        install_system("pre-commit", force=False, append=False)
        hook_dir = get_default_system_hook_dir_path()
        assert stat.S_IMODE((hook_dir / "pre-commit").stat().st_mode) == 0o755
        assert stat.S_IMODE(hook_dir.stat().st_mode) == 0o755


class TestSystemDataDir:
    def test_env_override(self, tmp_path, monkeypatch):
        from ggshield.core.dirs import get_system_data_dir

        monkeypatch.setenv("GG_SYSTEM_DATA_DIR", str(tmp_path))
        assert get_system_data_dir() == tmp_path

    def test_default_uses_site_data_dir(self, monkeypatch):
        from ggshield.core.dirs import get_system_data_dir

        monkeypatch.delenv("GG_SYSTEM_DATA_DIR", raising=False)
        assert get_system_data_dir().name == "ggshield"


@pytest.mark.skipif(
    sys.platform == "win32", reason="the global hook is a POSIX /bin/sh script"
)
class TestLocalHookSnippet:
    """Behavior of ``LOCAL_HOOK_SNIPPET``, the code the global/system hook injects
    to run the repository's own hook.

    Regression coverage for the worktree bug: in a linked worktree ``.git`` is a
    file, not a directory, so resolving the local hook through a hardcoded
    ``.git/hooks/<type>`` path silently skipped it. The snippet resolves the path
    with ``git rev-parse --git-common-dir`` instead.
    """

    @staticmethod
    def _repo_with_local_hook(tmp_path: Path) -> "tuple[Repository, Path]":
        """Create a committed repo with a repo-local pre-commit hook that records
        when it runs; return the repo and the hook's sentinel path."""
        repo = Repository.create(tmp_path / "repo")
        repo.create_commit()
        sentinel = tmp_path / "local-hook-ran"
        hook = repo.path / ".git" / "hooks" / "pre-commit"
        hook.parent.mkdir(parents=True, exist_ok=True)
        hook.write_text(f'#!/bin/sh\ntouch "{sentinel}"\n')
        hook.chmod(0o755)
        return repo, sentinel

    @staticmethod
    def _run_snippet(run_dir: Path, script: Path) -> "subprocess.CompletedProcess[str]":
        """Run the snippet from ``run_dir`` the way the global hook would."""
        script.write_text(
            "#!/bin/sh\n" + LOCAL_HOOK_SNIPPET.format(hook_type="pre-commit")
        )
        script.chmod(0o755)
        return subprocess.run(
            [str(script)], cwd=run_dir, capture_output=True, text=True
        )

    def test_runs_local_hook_in_main_worktree(self, tmp_path):
        """
        GIVEN a repository whose .git/hooks/pre-commit exists
        WHEN the global hook snippet runs from the repository root
        THEN the local hook is invoked
        """
        repo, sentinel = self._repo_with_local_hook(tmp_path)

        result = self._run_snippet(repo.path, tmp_path / "snippet.sh")

        assert result.returncode == 0, result.stderr
        assert sentinel.exists()

    def test_runs_local_hook_in_linked_worktree(self, tmp_path):
        """
        GIVEN a linked worktree, where .git is a file pointer rather than a directory
        WHEN the global hook snippet runs from the worktree root
        THEN the local hook, shared through the common git dir, is still invoked
        """
        repo, sentinel = self._repo_with_local_hook(tmp_path)

        worktree = tmp_path / "worktree"
        repo.git("worktree", "add", worktree, "-b", "feature")
        assert (worktree / ".git").is_file()  # precondition the fix depends on

        result = self._run_snippet(worktree, tmp_path / "snippet.sh")

        assert result.returncode == 0, result.stderr
        assert sentinel.exists()


class TestHooksPathShadow:
    BASE = "ggshield.cmd.install"

    def test_configured_hook_dir_path_returns_value(self):
        from ggshield.cmd.install import get_configured_hook_dir_path

        # Pin _get_repo_root to None so the value is returned verbatim (no
        # relative-path resolution); on Windows "/some/hooks" is not absolute and
        # would otherwise be resolved against the repo root.
        with patch(f"{self.BASE}.git", return_value="/some/hooks"), patch(
            f"{self.BASE}._get_repo_root", return_value=None
        ):
            assert get_configured_hook_dir_path() == Path("/some/hooks")

    def test_configured_hook_dir_path_none_when_unset(self):
        from ggshield.cmd.install import get_configured_hook_dir_path

        with patch(
            f"{self.BASE}.git",
            side_effect=subprocess.CalledProcessError(1, "git"),
        ):
            assert get_configured_hook_dir_path() is None

    def test_is_ggshield_hook_dir_true(self, tmp_path):
        from ggshield.cmd.install import is_ggshield_hook_dir

        (tmp_path / "pre-commit").write_text(
            "#!/bin/sh\nggshield secret scan pre-commit\n"
        )
        assert is_ggshield_hook_dir(tmp_path) is True

    def test_is_ggshield_hook_dir_false_for_foreign(self, tmp_path):
        from ggshield.cmd.install import is_ggshield_hook_dir

        (tmp_path / "pre-commit").write_text("#!/bin/sh\nother-tool\n")
        assert is_ggshield_hook_dir(tmp_path) is False

    def test_shadow_none_when_no_override(self):
        from ggshield.cmd.install import get_shadowing_hooks_path

        with patch(f"{self.BASE}.get_configured_hook_dir_path", return_value=None):
            assert get_shadowing_hooks_path() is None

    def test_shadow_none_when_effective_is_ggshield(self, tmp_path):
        from ggshield.cmd.install import get_shadowing_hooks_path

        (tmp_path / "pre-commit").write_text(
            "#!/bin/sh\nggshield secret scan pre-commit\n"
        )
        with patch(f"{self.BASE}.get_configured_hook_dir_path", return_value=tmp_path):
            assert get_shadowing_hooks_path() is None

    def test_shadow_returns_path_when_foreign(self, tmp_path):
        from ggshield.cmd.install import get_shadowing_hooks_path

        husky = tmp_path / ".husky" / "_"
        husky.mkdir(parents=True)
        with patch(f"{self.BASE}.get_configured_hook_dir_path", return_value=husky):
            assert get_shadowing_hooks_path() == husky

    def test_configured_hook_dir_path_none_on_any_git_error(self):
        from ggshield.cmd.install import get_configured_hook_dir_path
        from ggshield.utils.git_shell import GitCommandTimeoutExpired

        with patch(f"{self.BASE}.git", side_effect=GitCommandTimeoutExpired("boom")):
            assert get_configured_hook_dir_path() is None

    def test_configured_hook_dir_path_resolves_relative_against_repo_root(
        self, tmp_path
    ):
        from ggshield.cmd.install import get_configured_hook_dir_path

        with patch(f"{self.BASE}.git", return_value=".husky/_"), patch(
            f"{self.BASE}._get_repo_root", return_value=tmp_path
        ):
            assert get_configured_hook_dir_path() == tmp_path / ".husky" / "_"

    def test_configured_hook_dir_path_relative_unchanged_without_repo_root(self):
        from ggshield.cmd.install import get_configured_hook_dir_path

        with patch(f"{self.BASE}.git", return_value=".husky/_"), patch(
            f"{self.BASE}._get_repo_root", return_value=None
        ):
            assert get_configured_hook_dir_path() == Path(".husky/_")

    def test_is_ggshield_hook_dir_true_for_husky_parent(self, tmp_path):
        from ggshield.cmd.install import is_ggshield_hook_dir

        husky = tmp_path / ".husky"
        wrappers = husky / "_"
        wrappers.mkdir(parents=True)
        # Husky's `_` wrapper does not run ggshield directly...
        (wrappers / "pre-commit").write_text("#!/bin/sh\n. ../pre-commit\n")
        # ...but the user hook ggshield writes into the parent does.
        (husky / "pre-commit").write_text(
            "#!/bin/sh\nggshield secret scan pre-commit\n"
        )
        assert is_ggshield_hook_dir(wrappers) is True

    def test_is_ggshield_hook_dir_false_for_husky_without_ggshield(self, tmp_path):
        from ggshield.cmd.install import is_ggshield_hook_dir

        husky = tmp_path / ".husky"
        wrappers = husky / "_"
        wrappers.mkdir(parents=True)
        (wrappers / "pre-commit").write_text("#!/bin/sh\n. ../pre-commit\n")
        (husky / "pre-commit").write_text("#!/bin/sh\nnpx lint-staged\n")
        assert is_ggshield_hook_dir(wrappers) is False

    def test_hook_invokes_ggshield(self, tmp_path):
        from ggshield.cmd.install import hook_invokes_ggshield

        ours = tmp_path / "pre-commit"
        ours.write_text("#!/bin/sh\nggshield secret scan pre-commit\n")
        assert hook_invokes_ggshield(ours) is True
        assert hook_invokes_ggshield(tmp_path / "pre-push") is False

    def test_hook_invokes_ggshield_false_on_oserror(self, tmp_path):
        from ggshield.cmd.install import hook_invokes_ggshield

        ours = tmp_path / "pre-commit"
        ours.write_text("#!/bin/sh\nggshield secret scan pre-commit\n")
        # An unreadable file (permissions, race, special file) must not crash the
        # caller — `errors="ignore"` only covers decoding, not the read itself.
        with patch.object(Path, "read_text", side_effect=OSError("denied")):
            assert hook_invokes_ggshield(ours) is False
