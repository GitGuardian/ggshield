from pathlib import Path

from ggshield.__main__ import cli
from ggshield.cmd.skill.targets import get_skill_path
from ggshield.core.errors import ExitCode
from tests.unit.conftest import assert_invoke_exited_with, assert_invoke_ok


class TestSkillInstall:
    def test_install_creates_skill_file(self, cli_runner, tmp_path, monkeypatch):
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
        result = cli_runner.invoke(cli, ["skill", "install"])
        assert_invoke_ok(result)
        assert (tmp_path / "skills" / "ggshield" / "SKILL.md").is_file()
        assert "installed" in result.output.lower()

    def test_install_already_exists_no_force(self, cli_runner, tmp_path, monkeypatch):
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
        cli_runner.invoke(cli, ["skill", "install"])
        result = cli_runner.invoke(cli, ["skill", "install"])
        assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
        assert (
            "already installed" in result.output.lower() or "--force" in result.output
        )

    def test_install_force_overwrites(self, cli_runner, tmp_path, monkeypatch):
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
        cli_runner.invoke(cli, ["skill", "install"])
        result = cli_runner.invoke(cli, ["skill", "install", "--force"])
        assert_invoke_ok(result)

    def test_install_cursor_target(self, cli_runner, tmp_path, monkeypatch):
        monkeypatch.setenv("CURSOR_CONFIG_DIR", str(tmp_path))
        result = cli_runner.invoke(cli, ["skill", "install", "--target", "cursor"])
        assert_invoke_ok(result)
        assert (tmp_path / "skills" / "ggshield" / "SKILL.md").is_file()

    def test_install_invalid_target(self, cli_runner):
        result = cli_runner.invoke(cli, ["skill", "install", "--target", "vscode"])
        assert result.exit_code != 0


class TestSkillUpdate:
    def test_update_overwrites_existing(self, cli_runner, tmp_path, monkeypatch):
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
        cli_runner.invoke(cli, ["skill", "install"])
        result = cli_runner.invoke(cli, ["skill", "update"])
        assert_invoke_ok(result)
        assert "updated" in result.output.lower()

    def test_update_when_not_installed(self, cli_runner, tmp_path, monkeypatch):
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
        result = cli_runner.invoke(cli, ["skill", "update"])
        assert_invoke_ok(result)
        assert (tmp_path / "skills" / "ggshield" / "SKILL.md").is_file()


class TestSkillUninstall:
    def test_uninstall_removes_file(self, cli_runner, tmp_path, monkeypatch):
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
        cli_runner.invoke(cli, ["skill", "install"])
        result = cli_runner.invoke(cli, ["skill", "uninstall"])
        assert_invoke_ok(result)
        assert not (tmp_path / "skills" / "ggshield" / "SKILL.md").exists()

    def test_uninstall_when_not_installed(self, cli_runner, tmp_path, monkeypatch):
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
        result = cli_runner.invoke(cli, ["skill", "uninstall"])
        assert_invoke_ok(result)


class TestTargetResolution:
    def test_env_var_overrides_default(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
        path = get_skill_path("claude")
        assert path == tmp_path / "skills" / "ggshield" / "SKILL.md"

    def test_default_path_when_no_env_var(self, monkeypatch):
        monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
        path = get_skill_path("claude")
        assert path == Path.home() / ".claude" / "skills" / "ggshield" / "SKILL.md"
