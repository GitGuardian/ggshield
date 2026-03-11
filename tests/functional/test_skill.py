from click.testing import CliRunner

from ggshield.__main__ import cli


def test_skill_lifecycle(tmp_path, monkeypatch):
    """Full install/update/uninstall lifecycle against a real temp directory."""
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    runner = CliRunner()
    skill_path = tmp_path / "skills" / "ggshield" / "SKILL.md"

    # Install
    result = runner.invoke(cli, ["skill", "install"])
    assert result.exit_code == 0, result.output
    assert skill_path.is_file()
    original_content = skill_path.read_text()
    assert "ggshield" in original_content.lower()

    # Reinstall without force should fail
    result = runner.invoke(cli, ["skill", "install"])
    assert result.exit_code != 0
    assert skill_path.read_text() == original_content  # unchanged

    # Force reinstall should succeed
    result = runner.invoke(cli, ["skill", "install", "--force"])
    assert result.exit_code == 0, result.output

    # Update should succeed and overwrite
    result = runner.invoke(cli, ["skill", "update"])
    assert result.exit_code == 0, result.output
    assert skill_path.is_file()

    # Uninstall
    result = runner.invoke(cli, ["skill", "uninstall"])
    assert result.exit_code == 0, result.output
    assert not skill_path.exists()

    # Uninstall again is a no-op
    result = runner.invoke(cli, ["skill", "uninstall"])
    assert result.exit_code == 0, result.output
