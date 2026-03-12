import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest

from ggshield.core.errors import UnexpectedError
from ggshield.verticals.secret.ai_hook.claude_code import Claude
from ggshield.verticals.secret.ai_hook.copilot import Copilot
from ggshield.verticals.secret.ai_hook.cursor import Cursor
from ggshield.verticals.secret.ai_hook.installation import (
    InstallationStats,
    _fill_dict,
    install_hooks,
)


def _locator(
    candidates: List[Dict[str, Any]], template: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """Locator that finds an object containing 'ggshield' or '<COMMAND>' in any value."""
    for obj in candidates:
        if isinstance(obj, dict):
            for v in obj.values():
                if "ggshield" in str(v) or "<COMMAND>" in str(v):
                    return obj
    return None


COMMAND = "ggshield secret scan ai-hook"


class TestFillDict:
    def test_empty_dict_fills_with_template_scalars(self):
        """Starting from an empty dict, scalar template entries are added."""
        config: Dict[str, Any] = {}
        template = {"a": 1, "b": "hello"}
        expected = {"a": 1, "b": "hello"}
        stats = InstallationStats(added=0, already_present=0)
        stats = _fill_dict(
            config, template, COMMAND, overwrite=False, stats=stats, locator=_locator
        )
        assert config == expected
        assert stats == InstallationStats(added=0, already_present=0)

    def test_empty_dict_fills_with_nested_dict(self):
        """Starting from an empty dict, nested dict template is merged recursively."""
        config: Dict[str, Any] = {}
        template = {"level1": {"level2": "x"}}
        expected = {"level1": {"level2": "x"}}
        stats = InstallationStats(added=0, already_present=0)
        stats = _fill_dict(
            config, template, COMMAND, overwrite=False, stats=stats, locator=_locator
        )
        assert config == expected
        assert stats == InstallationStats(added=0, already_present=0)

    def test_adding_keys_does_not_touch_existing(self):
        """Adding template keys leaves other existing keys unchanged."""
        config = {"other": 42, "nested": {"keep": True}}
        template = {"a": 1}
        expected = {"other": 42, "nested": {"keep": True}, "a": 1}
        stats = InstallationStats(added=0, already_present=0)
        stats = _fill_dict(
            config, template, COMMAND, overwrite=False, stats=stats, locator=_locator
        )
        assert config == expected
        assert stats == InstallationStats(added=0, already_present=0)

    def test_nested_dict_merges_without_overwriting_existing(self):
        """Nested template dict merges into existing nested dict, leaving existing keys."""
        config = {"level1": {"existing": 1}}
        template = {"level1": {"new": 2}}
        expected = {"level1": {"existing": 1, "new": 2}}
        stats = InstallationStats(added=0, already_present=0)
        stats = _fill_dict(
            config, template, COMMAND, overwrite=False, stats=stats, locator=_locator
        )
        assert config == expected
        assert stats == InstallationStats(added=0, already_present=0)

    def test_command_placeholder_replaced_by_command(self):
        """Template value '<COMMAND>' is replaced by the given command string."""
        config: Dict[str, Any] = {}
        template = {"cmd": "<COMMAND>"}
        expected = {"cmd": COMMAND}
        stats = InstallationStats(added=0, already_present=0)
        stats = _fill_dict(
            config, template, COMMAND, overwrite=False, stats=stats, locator=_locator
        )
        assert config == expected
        assert stats == InstallationStats(added=1, already_present=0)

    def test_overwrite_false_leaves_existing_scalar(self):
        """When overwrite is False, existing scalar value is left unchanged."""
        config = {"a": "existing"}
        template = {"a": "new"}
        expected = {"a": "existing"}
        stats = InstallationStats(added=0, already_present=0)
        stats = _fill_dict(
            config, template, COMMAND, overwrite=False, stats=stats, locator=_locator
        )
        assert config == expected
        assert stats == InstallationStats(added=0, already_present=0)

    def test_overwrite_true_replaces_existing_scalar(self):
        """When overwrite is True, existing scalar value is replaced by template."""
        config = {"a": "existing"}
        template = {"a": "new"}
        expected = {"a": "new"}
        stats = InstallationStats(added=0, already_present=0)
        stats = _fill_dict(
            config, template, COMMAND, overwrite=True, stats=stats, locator=_locator
        )
        assert config == expected
        assert stats == InstallationStats(added=0, already_present=0)

    def test_list_no_match_appends_new_object(self):
        """When locator finds no match in list, a new object is appended and filled."""
        config: Dict[str, Any] = {}
        template = {"hooks": [{"command": "<COMMAND>"}]}
        expected = {"hooks": [{"command": COMMAND}]}
        stats = InstallationStats(added=0, already_present=0)
        stats = _fill_dict(
            config, template, COMMAND, overwrite=False, stats=stats, locator=_locator
        )
        assert config == expected
        assert stats == InstallationStats(added=1, already_present=0)

    def test_list_match_found_updates_existing_object_overwrite_true(self):
        """When locator finds a match in list, that object is updated (overwrite True)."""
        config = {"hooks": [{"command": "ggshield already"}]}
        template = {"hooks": [{"command": "<COMMAND>"}]}
        expected = {"hooks": [{"command": COMMAND}]}
        stats = InstallationStats(added=0, already_present=0)
        stats = _fill_dict(
            config, template, COMMAND, overwrite=True, stats=stats, locator=_locator
        )
        assert config == expected
        assert stats == InstallationStats(added=1, already_present=1)

    def test_list_match_found_leaves_existing_object_overwrite_false(self):
        """When locator finds a match in list and overwrite is False, existing value is kept."""
        config = {"hooks": [{"command": "ggshield already"}]}
        template = {"hooks": [{"command": "<COMMAND>"}]}
        expected = {"hooks": [{"command": "ggshield already"}]}
        stats = InstallationStats(added=0, already_present=0)
        stats = _fill_dict(
            config, template, COMMAND, overwrite=False, stats=stats, locator=_locator
        )
        assert config == expected
        assert stats == InstallationStats(added=0, already_present=1)

    def test_multiple_lists(self):
        config = {
            "hooks": {
                "hook1": [{"command": "ggshield already"}],
                "hook2": [{"command": "other"}],
                "hook3": [],
            }
        }
        template = {
            "hooks": {
                "hook1": [{"command": "<COMMAND>"}],
                "hook2": [{"command": "<COMMAND>"}],
                "hook3": [{"command": "<COMMAND>"}],
            }
        }
        expected = {
            "hooks": {
                "hook1": [{"command": "ggshield already"}],
                "hook2": [{"command": "other"}, {"command": COMMAND}],
                "hook3": [{"command": COMMAND}],
            }
        }
        stats = InstallationStats(added=0, already_present=0)
        stats = _fill_dict(
            config, template, COMMAND, overwrite=False, stats=stats, locator=_locator
        )
        assert config == expected
        assert stats == InstallationStats(added=2, already_present=1)

    def test_template_list_must_have_exactly_one_element(self):
        """Template list value must have exactly one element (raises ValueError otherwise)."""
        config: Dict[str, Any] = {}
        template = {"hooks": [{"a": 1}, {"b": 2}]}
        stats = InstallationStats(added=0, already_present=0)
        with pytest.raises(ValueError, match="Expected only one object in template"):
            stats = _fill_dict(
                config,
                template,
                COMMAND,
                overwrite=False,
                stats=stats,
                locator=_locator,
            )
        assert stats == InstallationStats(added=0, already_present=0)


class TestFlavorSettingsProperties:
    """Unit tests for settings_path, settings_template, and settings_locate on each flavor."""

    def test_claude_settings_path(self):
        assert Claude().settings_path == Path(".claude") / "settings.json"

    def test_claude_settings_template(self):
        assert isinstance(Claude().settings_template, dict)

    def test_claude_settings_locate_finds_by_matcher(self):
        claude = Claude()
        candidates = [
            {"matcher": ".*", "hooks": [{"command": "ggshield"}]},
            {"matcher": "Bash", "hooks": [{"command": "other"}]},
        ]
        template = {"matcher": ".*"}
        result = claude.settings_locate(candidates, template)
        assert result is candidates[0]

    def test_claude_settings_locate_no_matcher_finds_ggshield(self):
        claude = Claude()
        candidates = [
            {"type": "command", "command": "ggshield secret scan ai-hook"},
        ]
        template = {"type": "command", "command": "<COMMAND>"}
        result = claude.settings_locate(candidates, template)
        assert result is candidates[0]

    def test_claude_settings_locate_no_matcher_finds_placeholder(self):
        claude = Claude()
        candidates = [
            {"type": "command", "command": "<COMMAND>"},
        ]
        template = {"type": "command", "command": "<COMMAND>"}
        result = claude.settings_locate(candidates, template)
        assert result is candidates[0]

    def test_claude_settings_locate_no_match_returns_none(self):
        claude = Claude()
        candidates = [
            {"matcher": "Bash", "hooks": []},
        ]
        template = {"matcher": ".*"}
        assert claude.settings_locate(candidates, template) is None

    def test_claude_settings_locate_no_matcher_no_match_returns_none(self):
        claude = Claude()
        candidates = [
            {"type": "command", "command": "other-tool"},
        ]
        template = {"type": "command", "command": "<COMMAND>"}
        assert claude.settings_locate(candidates, template) is None

    def test_cursor_settings_path(self):
        assert Cursor().settings_path == Path(".cursor") / "hooks.json"

    def test_cursor_settings_template(self):
        assert isinstance(Cursor().settings_template, dict)

    def test_cursor_settings_locate_finds_ggshield(self):
        cursor = Cursor()
        candidates = [
            {"command": "other-tool"},
            {"command": "ggshield secret scan ai-hook"},
        ]
        template = {"command": "<COMMAND>"}
        result = cursor.settings_locate(candidates, template)
        assert result is candidates[1]

    def test_cursor_settings_locate_finds_placeholder(self):
        cursor = Cursor()
        candidates = [{"command": "<COMMAND>"}]
        template = {"command": "<COMMAND>"}
        result = cursor.settings_locate(candidates, template)
        assert result is candidates[0]

    def test_cursor_settings_locate_no_match_returns_none(self):
        cursor = Cursor()
        candidates = [{"command": "other-tool"}]
        template = {"command": "<COMMAND>"}
        assert cursor.settings_locate(candidates, template) is None

    def test_copilot_settings_path(self):
        assert Copilot().settings_path == Path(".github") / "hooks" / "hooks.json"


class TestInstallHooks:
    """Unit tests for the install_hooks function."""

    @patch("ggshield.verticals.secret.ai_hook.installation.get_user_home_dir")
    def test_install_cursor_local_fresh(self, mock_home: Any, tmp_path: Path):
        """Install Cursor hooks locally into a fresh directory (no existing config)."""
        mock_home.return_value = tmp_path
        settings_path = tmp_path / ".cursor" / "hooks.json"
        assert not settings_path.exists()

        with patch(
            "ggshield.verticals.secret.ai_hook.installation.Path"
        ) as mock_path_cls:
            # Make Path(".") return tmp_path so local mode writes there
            mock_path_cls.side_effect = lambda *a: Path(*a) if a != (".",) else tmp_path
            code = install_hooks("cursor", mode="local")

        assert code == 0
        assert settings_path.exists()
        config = json.loads(settings_path.read_text())
        assert config["version"] == 1
        for key in ("beforeSubmitPrompt", "preToolUse", "postToolUse"):
            assert any("ggshield" in h["command"] for h in config["hooks"][key])

    @patch("ggshield.verticals.secret.ai_hook.installation.get_user_home_dir")
    def test_install_claude_global(self, mock_home: Any, tmp_path: Path):
        """Install Claude Code hooks globally."""
        mock_home.return_value = tmp_path
        code = install_hooks("claude-code", mode="global")
        assert code == 0

        settings_path = tmp_path / ".claude" / "settings.json"
        assert settings_path.exists()
        config = json.loads(settings_path.read_text())
        assert "hooks" in config
        for key in ("PreToolUse", "PostToolUse", "UserPromptSubmit"):
            assert key in config["hooks"]

    @patch("ggshield.verticals.secret.ai_hook.installation.get_user_home_dir")
    def test_install_copilot_global(self, mock_home: Any, tmp_path: Path):
        """Install Copilot hooks globally."""
        mock_home.return_value = tmp_path
        code = install_hooks("copilot", mode="global")
        assert code == 0

        settings_path = tmp_path / ".github" / "hooks" / "hooks.json"
        assert settings_path.exists()

    def test_install_unsupported_tool_raises(self):
        """install_hooks raises ValueError for unsupported tool name."""
        with pytest.raises(ValueError, match="Unsupported tool name"):
            install_hooks("unknown-tool", mode="local")

    @patch("ggshield.verticals.secret.ai_hook.installation.get_user_home_dir")
    def test_install_with_existing_config(self, mock_home: Any, tmp_path: Path):
        """Install hooks when a config file already exists (merges)."""
        mock_home.return_value = tmp_path
        settings_path = tmp_path / ".cursor" / "hooks.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text(json.dumps({"version": 1, "other_key": "keep_me"}))

        with patch(
            "ggshield.verticals.secret.ai_hook.installation.Path"
        ) as mock_path_cls:
            mock_path_cls.side_effect = lambda *a: Path(*a) if a != (".",) else tmp_path
            code = install_hooks("cursor", mode="local")

        assert code == 0
        config = json.loads(settings_path.read_text())
        assert config["other_key"] == "keep_me"
        assert "hooks" in config

    @patch("ggshield.verticals.secret.ai_hook.installation.get_user_home_dir")
    def test_install_with_corrupt_json_raises(self, mock_home: Any, tmp_path: Path):
        """install_hooks raises UnexpectedError when existing config is invalid JSON."""
        mock_home.return_value = tmp_path
        settings_path = tmp_path / ".cursor" / "hooks.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text("{ invalid json")

        with patch(
            "ggshield.verticals.secret.ai_hook.installation.Path"
        ) as mock_path_cls:
            mock_path_cls.side_effect = lambda *a: Path(*a) if a != (".",) else tmp_path
            with pytest.raises(UnexpectedError, match="Failed to parse"):
                install_hooks("cursor", mode="local")

    @patch("ggshield.verticals.secret.ai_hook.installation.get_user_home_dir")
    def test_install_already_present(self, mock_home: Any, tmp_path: Path):
        """install_hooks when hooks are already installed reports 'already installed'."""
        mock_home.return_value = tmp_path

        with patch(
            "ggshield.verticals.secret.ai_hook.installation.Path"
        ) as mock_path_cls:
            mock_path_cls.side_effect = lambda *a: Path(*a) if a != (".",) else tmp_path
            # Install once
            install_hooks("cursor", mode="local")
            # Install again — should detect already present
            code = install_hooks("cursor", mode="local")

        assert code == 0

    @patch("ggshield.verticals.secret.ai_hook.installation.get_user_home_dir")
    def test_install_force_updates(self, mock_home: Any, tmp_path: Path):
        """install_hooks with force=True updates existing hooks."""
        mock_home.return_value = tmp_path

        with patch(
            "ggshield.verticals.secret.ai_hook.installation.Path"
        ) as mock_path_cls:
            mock_path_cls.side_effect = lambda *a: Path(*a) if a != (".",) else tmp_path
            install_hooks("cursor", mode="local")
            code = install_hooks("cursor", mode="local", force=True)

        assert code == 0
