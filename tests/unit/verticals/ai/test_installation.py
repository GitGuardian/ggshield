import contextlib
import json
import ntpath
import os
import posixpath
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest


if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from ggshield.core.errors import UnexpectedError
from ggshield.verticals.ai.agents import Claude, Codex, Copilot, Cursor, Vibe
from ggshield.verticals.ai.installation import (
    AgentHookStatus,
    InstallationStats,
    _fill_dict,
    ai_hook_posture,
    are_hooks_installed_globally,
    build_hook_command,
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
        assert stats == InstallationStats(
            added=1, already_present=1, command="ggshield already"
        )

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
        assert stats == InstallationStats(
            added=0, already_present=1, command="ggshield already"
        )

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
        assert stats == InstallationStats(
            added=2, already_present=1, command="ggshield already"
        )

    def test_vanished_ggshield_command_is_repointed(self, tmp_path: Path):
        """GIVEN a hook pinned to a versioned bundle path an upgrade deleted
        WHEN the hooks are installed again
        THEN the command is repointed, instead of failing open on every prompt."""
        stale = f"{tmp_path / 'ggshield-1.53.0' / 'ggshield'} secret scan ai-hook"
        config = {"hooks": [{"command": stale}]}
        stats = _fill_dict(
            config,
            {"hooks": [{"command": "<COMMAND>"}]},
            COMMAND,
            overwrite=False,
            stats=InstallationStats(added=0, already_present=0),
            locator=_locator,
        )
        assert config == {"hooks": [{"command": COMMAND}]}
        assert stats == InstallationStats(added=1, already_present=1, command=stale)

    @pytest.mark.skipif(os.name == "nt", reason="creates a symlink")
    def test_versioned_path_to_the_same_binary_is_repointed(self, tmp_path: Path):
        """GIVEN a hook pinned to a still-valid versioned path
        WHEN the new command reaches that same binary through a launcher
        THEN the hook is migrated to the launcher before the next upgrade."""
        binary = tmp_path / "ggshield-1.53.0" / "ggshield"
        binary.parent.mkdir()
        binary.write_text("")
        launcher = tmp_path / "ggshield"
        launcher.symlink_to(binary)
        command = f"{launcher} secret scan ai-hook"
        config = {"hooks": [{"command": f"{binary} secret scan ai-hook"}]}
        _fill_dict(
            config,
            {"hooks": [{"command": "<COMMAND>"}]},
            command,
            overwrite=False,
            stats=InstallationStats(added=0, already_present=0),
            locator=_locator,
        )
        assert config == {"hooks": [{"command": command}]}

    def test_another_tool_command_is_left_alone(self, tmp_path: Path):
        """GIVEN a hook command running another tool, mentioning ggshield
        WHEN the hooks are installed again
        THEN it is kept: only the commands we wrote are ever repointed."""
        other = f"{tmp_path / 'other-scanner'} --ggshield-compat secret scan ai-hook"
        config = {"hooks": [{"command": other}]}
        _fill_dict(
            config,
            {"hooks": [{"command": "<COMMAND>"}]},
            COMMAND,
            overwrite=False,
            stats=InstallationStats(added=0, already_present=0),
            locator=_locator,
        )
        assert config["hooks"] == [{"command": other}]

    def test_another_tool_windows_command_is_left_alone(self):
        """GIVEN a Windows hook command running another tool, mentioning ggshield
        WHEN the hooks are installed again
        THEN it is kept: arguments mark a command as not ours on Windows too."""
        other = r"C:\Tools\other-scanner --ggshield-compat secret scan ai-hook"
        config = {"hooks": [{"command": other}]}
        with patch("ggshield.verticals.ai.installation.os.name", "nt"):
            _fill_dict(
                config,
                {"hooks": [{"command": "<COMMAND>"}]},
                COMMAND,
                overwrite=False,
                stats=InstallationStats(added=0, already_present=0),
                locator=_locator,
            )
        assert config["hooks"] == [{"command": other}]

    def test_non_command_scalar_is_not_an_existing_install(self):
        """A template scalar other than the command may contain "ggshield" (a hook
        name, say). It must not be mistaken for an existing installation."""
        config: Dict[str, Any] = {}
        template = {"hooks": [{"name": "ggshield-pre-tool", "command": "<COMMAND>"}]}
        stats = _fill_dict(
            config,
            template,
            COMMAND,
            overwrite=False,
            stats=InstallationStats(added=0, already_present=0),
            locator=_locator,
        )

        assert config == {"hooks": [{"name": "ggshield-pre-tool", "command": COMMAND}]}
        assert stats == InstallationStats(added=1, already_present=0)

    def test_non_object_entries_are_ignored(self):
        """Settings files are hand-editable: a stray scalar in a hook list must not
        crash the merge."""
        config: Dict[str, Any] = {"hooks": ["stray", {"command": "other"}]}
        template = {"hooks": [{"command": "<COMMAND>"}]}
        stats = _fill_dict(
            config,
            template,
            COMMAND,
            overwrite=False,
            stats=InstallationStats(added=0, already_present=0),
            locator=_locator,
        )

        assert config["hooks"][0] == "stray"
        assert {"command": COMMAND} in config["hooks"]
        assert stats.added == 1

    def test_unmergeable_shape_raises_value_error(self):
        """A list key holding something other than a list cannot be merged into."""
        with pytest.raises(ValueError, match="expected a list of objects"):
            _fill_dict(
                {"hooks": "not-a-list"},
                {"hooks": [{"command": "<COMMAND>"}]},
                COMMAND,
                overwrite=False,
                stats=InstallationStats(added=0, already_present=0),
                locator=_locator,
            )

    def test_template_list_supports_multiple_elements(self):
        config: Dict[str, Any] = {}
        template = {
            "hooks": [
                {"name": "pre", "command": "<COMMAND>"},
                {"name": "post", "command": "<COMMAND>"},
            ]
        }
        stats = InstallationStats(added=0, already_present=0)
        stats = _fill_dict(
            config,
            template,
            COMMAND,
            overwrite=False,
            stats=stats,
            locator=lambda candidates, item: next(
                (
                    candidate
                    for candidate in candidates
                    if candidate.get("name") == item["name"]
                ),
                None,
            ),
        )
        assert config == {
            "hooks": [
                {"name": "pre", "command": COMMAND},
                {"name": "post", "command": COMMAND},
            ]
        }
        assert stats == InstallationStats(added=2, already_present=0)


class TestFlavorSettingsProperties:
    """Unit tests for settings_path, settings_template, and settings_locate on each flavor."""

    def test_claude_settings_path(self):
        assert (
            Claude().settings_path("global")
            == Claude().settings_path("local")
            == Path(".claude") / "settings.json"
        )

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
        assert (
            Cursor().settings_path("global")
            == Cursor().settings_path("local")
            == Path(".cursor") / "hooks.json"
        )

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
        assert (
            Copilot().settings_path("local") == Path(".github") / "hooks" / "hooks.json"
        )
        assert (
            Copilot().settings_path("global")
            == Path(".copilot") / "hooks" / "hooks.json"
        )

    def test_codex_settings_path(self):
        assert (
            Codex().settings_path("global")
            == Codex().settings_path("local")
            == Path(".codex") / "hooks.json"
        )

    def test_codex_settings_template(self):
        assert isinstance(Codex().settings_template, dict)

    def test_vibe_settings_path_and_format(self, tmp_path: Path):
        with patch(
            "ggshield.verticals.ai.agents.vibe.os.getenv",
            return_value=str(tmp_path / "vibe-home"),
        ):
            assert (
                Vibe().settings_path("global") == tmp_path / "vibe-home" / "hooks.toml"
            )
            assert Vibe().settings_path("local") == Path(".vibe") / "hooks.toml"
            assert Vibe().settings_format == "toml"

    def test_vibe_settings_template(self):
        hooks = Vibe().settings_template["hooks"]
        assert [hook["type"] for hook in hooks] == ["pre_tool", "post_tool"]
        assert all(hook["match"] == "*" for hook in hooks)

    def test_vibe_post_install_warning_on_untrusted_folder(self, tmp_path: Path):
        """Vibe ignores project hooks in untrusted folders, so a local install
        there must say so instead of reporting plain success."""
        vibe_home = tmp_path / ".vibe"
        vibe_home.mkdir()
        project = tmp_path / "project"
        project.mkdir()

        with patch(
            "ggshield.verticals.ai.agents.vibe.os.getenv",
            return_value=str(vibe_home),
        ), patch("ggshield.verticals.ai.agents.vibe.Path.cwd", return_value=project):
            vibe = Vibe()
            # No trusted_folders.toml at all: the folder is not trusted.
            assert "trusted folders" in (vibe.post_install_warning("local") or "")
            # A global install is unaffected by folder trust.
            assert vibe.post_install_warning("global") is None

            # A TOML literal string: a Windows path's backslashes must not be
            # read as escape sequences.
            (vibe_home / "trusted_folders.toml").write_text(
                f"trusted = ['{project}']\n"
            )
            assert vibe.post_install_warning("local") is None


class TestInstallHooks:
    """Unit tests for the install_hooks function."""

    @patch("ggshield.verticals.ai.installation.get_user_home_dir")
    def test_install_cursor_local_fresh(self, mock_home: Any, tmp_path: Path):
        """Install Cursor hooks locally into a fresh directory (no existing config)."""
        mock_home.return_value = tmp_path
        settings_path = tmp_path / ".cursor" / "hooks.json"
        assert not settings_path.exists()

        with patch("ggshield.verticals.ai.installation.Path") as mock_path_cls:
            # Make Path(".") return tmp_path so local mode writes there
            mock_path_cls.side_effect = lambda *a: Path(*a) if a != (".",) else tmp_path
            code = install_hooks("cursor", mode="local")

        assert code == 0
        assert settings_path.exists()
        config = json.loads(settings_path.read_text())
        assert config["version"] == 1
        for key in ("beforeSubmitPrompt", "preToolUse", "postToolUse"):
            assert any("ggshield" in h["command"] for h in config["hooks"][key])

    @patch("ggshield.verticals.ai.installation.get_user_home_dir")
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

    @patch("ggshield.verticals.ai.installation.get_user_home_dir")
    def test_install_copilot_global(self, mock_home: Any, tmp_path: Path):
        """Install Copilot hooks globally."""
        mock_home.return_value = tmp_path
        code = install_hooks("copilot", mode="global")
        assert code == 0

        settings_path = tmp_path / ".copilot" / "hooks" / "hooks.json"
        assert settings_path.exists()

    @patch("ggshield.verticals.ai.installation.get_user_home_dir")
    def test_install_codex_global(self, mock_home: Any, tmp_path: Path):
        """Install Codex hooks globally without touching Codex config.toml."""
        mock_home.return_value = tmp_path
        code = install_hooks("codex", mode="global")
        assert code == 0

        settings_path = tmp_path / ".codex" / "hooks.json"
        assert settings_path.exists()
        config = json.loads(settings_path.read_text())
        for key in ("PreToolUse", "PostToolUse", "UserPromptSubmit"):
            assert key in config["hooks"]

        codex_config = tmp_path / ".codex" / "config.toml"
        assert not codex_config.exists()

    @patch("ggshield.verticals.ai.installation.get_user_home_dir")
    @patch("ggshield.verticals.ai.agents.vibe.get_user_home_dir")
    @patch("ggshield.verticals.ai.agents.vibe.os.getenv", return_value=None)
    def test_install_vibe_global(
        self,
        mock_getenv: Any,
        mock_vibe_home: Any,
        mock_home: Any,
        tmp_path: Path,
    ):
        mock_home.return_value = tmp_path
        mock_vibe_home.return_value = tmp_path

        code = install_hooks("vibe", mode="global")

        assert code == 0
        settings_path = tmp_path / ".vibe" / "hooks.toml"
        config = tomllib.loads(settings_path.read_text())
        assert [hook["name"] for hook in config["hooks"]] == [
            "ggshield-pre-tool",
            "ggshield-post-tool",
        ]
        assert all("ggshield" in hook["command"] for hook in config["hooks"])
        assert all(hook["strict"] is False for hook in config["hooks"])

        install_hooks("vibe", mode="global")
        config = tomllib.loads(settings_path.read_text())
        assert [hook["name"] for hook in config["hooks"]] == [
            "ggshield-pre-tool",
            "ggshield-post-tool",
        ]

        updated_command = "/opt/ggshield/bin/ggshield secret scan ai-hook"
        with patch(
            "ggshield.verticals.ai.installation.build_hook_command",
            return_value=updated_command,
        ):
            install_hooks("vibe", mode="global", force=True)
        config = tomllib.loads(settings_path.read_text())
        assert all(hook["command"] == updated_command for hook in config["hooks"])

    @patch("ggshield.verticals.ai.installation.get_user_home_dir")
    @patch("ggshield.verticals.ai.agents.vibe.get_user_home_dir")
    @patch("ggshield.verticals.ai.agents.vibe.os.getenv", return_value=None)
    def test_install_vibe_preserves_existing_toml(
        self,
        mock_getenv: Any,
        mock_vibe_home: Any,
        mock_home: Any,
        tmp_path: Path,
    ):
        mock_home.return_value = tmp_path
        mock_vibe_home.return_value = tmp_path
        settings_path = tmp_path / ".vibe" / "hooks.toml"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text(
            "# Keep this comment\n"
            "[[hooks]]\n"
            'name = "existing"\n'
            'type = "pre_tool"\n'
            'match = "bash"\n'
            'command = "other-tool"\n'
        )

        install_hooks("vibe", mode="global")

        text = settings_path.read_text()
        config = tomllib.loads(text)
        assert "# Keep this comment" in text
        assert [hook["name"] for hook in config["hooks"]] == [
            "existing",
            "ggshield-pre-tool",
            "ggshield-post-tool",
        ]

    @patch("ggshield.verticals.ai.installation.get_user_home_dir")
    @patch("ggshield.verticals.ai.agents.vibe.get_user_home_dir")
    @patch("ggshield.verticals.ai.agents.vibe.os.getenv", return_value=None)
    def test_install_vibe_with_corrupt_toml_raises(
        self,
        mock_getenv: Any,
        mock_vibe_home: Any,
        mock_home: Any,
        tmp_path: Path,
    ):
        mock_home.return_value = tmp_path
        mock_vibe_home.return_value = tmp_path
        settings_path = tmp_path / ".vibe" / "hooks.toml"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text("[[hooks]\n")

        with pytest.raises(UnexpectedError, match="Failed to parse"):
            install_hooks("vibe", mode="global")

        # The file is reported, never repaired: tomlkit alone parses "[[hooks]"
        # as "[[hooks]]" and would write that back over the user's file.
        assert settings_path.read_text() == "[[hooks]\n"

    @patch("ggshield.verticals.ai.installation.get_user_home_dir")
    @patch("ggshield.verticals.ai.agents.vibe.get_user_home_dir")
    @patch("ggshield.verticals.ai.agents.vibe.os.getenv", return_value=None)
    def test_install_vibe_with_duplicate_inline_key_raises(
        self,
        mock_getenv: Any,
        mock_vibe_home: Any,
        mock_home: Any,
        tmp_path: Path,
    ):
        """A duplicate key in an inline table raises tomlkit's KeyAlreadyPresent,
        which is a TOMLKitError but not a ParseError."""
        mock_home.return_value = tmp_path
        mock_vibe_home.return_value = tmp_path
        settings_path = tmp_path / ".vibe" / "hooks.toml"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text("a = { x = 1, x = 2 }\n")

        with pytest.raises(UnexpectedError, match="Failed to parse"):
            install_hooks("vibe", mode="global")

    @patch("ggshield.verticals.ai.installation.get_user_home_dir")
    @patch("ggshield.verticals.ai.agents.vibe.get_user_home_dir")
    @patch("ggshield.verticals.ai.agents.vibe.os.getenv", return_value=None)
    def test_install_vibe_with_unmergeable_toml_raises(
        self,
        mock_getenv: Any,
        mock_vibe_home: Any,
        mock_home: Any,
        tmp_path: Path,
    ):
        """Valid TOML of the wrong shape reports the same actionable error as a
        syntax error, instead of an unhandled traceback."""
        mock_home.return_value = tmp_path
        mock_vibe_home.return_value = tmp_path
        settings_path = tmp_path / ".vibe" / "hooks.toml"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text('hooks = "not-a-list"\n')

        with pytest.raises(UnexpectedError, match="Failed to update"):
            install_hooks("vibe", mode="global")

    def test_install_unsupported_agent_raises(self):
        """install_hooks raises ValueError for unsupported agent."""
        with pytest.raises(ValueError, match="Unsupported agent"):
            install_hooks("unknown-agent", mode="local")

    @patch("ggshield.verticals.ai.installation.get_user_home_dir")
    def test_install_with_existing_config(self, mock_home: Any, tmp_path: Path):
        """Install hooks when a config file already exists (merges)."""
        mock_home.return_value = tmp_path
        settings_path = tmp_path / ".cursor" / "hooks.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text(json.dumps({"version": 1, "other_key": "keep_me"}))

        with patch("ggshield.verticals.ai.installation.Path") as mock_path_cls:
            mock_path_cls.side_effect = lambda *a: Path(*a) if a != (".",) else tmp_path
            code = install_hooks("cursor", mode="local")

        assert code == 0
        config = json.loads(settings_path.read_text())
        assert config["other_key"] == "keep_me"
        assert "hooks" in config

    @patch("ggshield.verticals.ai.installation.get_user_home_dir")
    def test_install_with_corrupt_json_raises(self, mock_home: Any, tmp_path: Path):
        """install_hooks raises UnexpectedError when existing config is invalid JSON."""
        mock_home.return_value = tmp_path
        settings_path = tmp_path / ".cursor" / "hooks.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text("{ invalid json")

        with patch("ggshield.verticals.ai.installation.Path") as mock_path_cls:
            mock_path_cls.side_effect = lambda *a: Path(*a) if a != (".",) else tmp_path
            with pytest.raises(UnexpectedError, match="Failed to parse"):
                install_hooks("cursor", mode="local")

    @patch("ggshield.verticals.ai.installation.get_user_home_dir")
    def test_install_already_present(self, mock_home: Any, tmp_path: Path):
        """install_hooks when hooks are already installed reports 'already installed'."""
        mock_home.return_value = tmp_path

        with patch("ggshield.verticals.ai.installation.Path") as mock_path_cls:
            mock_path_cls.side_effect = lambda *a: Path(*a) if a != (".",) else tmp_path
            # Install once
            install_hooks("cursor", mode="local")
            # Install again — should detect already present
            code = install_hooks("cursor", mode="local")

        assert code == 0

    @patch("ggshield.verticals.ai.installation.get_user_home_dir")
    def test_install_force_updates(self, mock_home: Any, tmp_path: Path):
        """install_hooks with force=True updates existing hooks."""
        mock_home.return_value = tmp_path

        with patch("ggshield.verticals.ai.installation.Path") as mock_path_cls:
            mock_path_cls.side_effect = lambda *a: Path(*a) if a != (".",) else tmp_path
            install_hooks("cursor", mode="local")
            code = install_hooks("cursor", mode="local", force=True)

        assert code == 0


class TestAreHooksInstalledGlobally:
    """Unit tests for the are_hooks_installed_globally function."""

    @patch(
        "ggshield.verticals.ai.installation.build_hook_command", return_value=COMMAND
    )
    @patch("ggshield.verticals.ai.installation.get_user_home_dir")
    def test_detects_installed_global_hooks(
        self, mock_home: Any, mock_cmd: Any, tmp_path: Path
    ):
        mock_home.return_value = tmp_path

        installed, command = are_hooks_installed_globally("claude-code")
        assert installed is False
        assert command is None

        install_hooks("claude-code", mode="global")

        installed, command = are_hooks_installed_globally("claude-code")
        assert installed is True
        assert command == COMMAND

    @patch("ggshield.verticals.ai.installation.get_user_home_dir")
    def test_no_settings_file_returns_false(self, mock_home: Any, tmp_path: Path):
        mock_home.return_value = tmp_path
        installed, command = are_hooks_installed_globally("cursor")
        assert installed is False
        assert command is None

    @patch("ggshield.verticals.ai.installation.get_user_home_dir")
    def test_settings_without_ggshield_returns_false(
        self, mock_home: Any, tmp_path: Path
    ):
        mock_home.return_value = tmp_path
        settings = tmp_path / ".cursor" / "hooks.json"
        settings.parent.mkdir(parents=True)
        settings.write_text(
            json.dumps({"hooks": {"preToolUse": [{"command": "other-tool"}]}})
        )
        installed, command = are_hooks_installed_globally("cursor")
        assert installed is False
        assert command is None


@contextlib.contextmanager
def _simulate_platform(argv=("ggshield", "install"), *, windows, frozen=None):
    """Run build_hook_command as if on a given OS, regardless of the test host.

    Patches the path primitives the function uses (``os.name`` and the
    ``os.path`` functions) to the chosen flavor (ntpath or posixpath) so the
    same assertions hold whether the runner is Linux or Windows. ``frozen``
    names the ``sys.executable`` of a PyInstaller bundle; without it the
    argv[0] code paths are exercised.
    """
    flavor = ntpath if windows else posixpath
    mod = "ggshield.verticals.ai.installation"
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch(f"{mod}.sys.argv", list(argv)))
        stack.enter_context(patch(f"{mod}.os.name", "nt" if windows else "posix"))
        stack.enter_context(patch(f"{mod}.os.path.abspath", flavor.abspath))
        stack.enter_context(patch(f"{mod}.os.path.dirname", flavor.dirname))
        stack.enter_context(patch(f"{mod}.os.path.join", flavor.join))
        stack.enter_context(patch(f"{mod}.os.path.normpath", flavor.normpath))
        stack.enter_context(
            patch.object(sys, "frozen", frozen is not None, create=True)
        )
        if frozen is not None:
            stack.enter_context(patch.object(sys, "executable", frozen, create=True))
        yield


class TestBuildHookCommand:
    """Unit tests for build_hook_command (cross-platform).

    The hook is pinned to the absolute path of the ggshield that ran install,
    so it does not depend on the hook process's PATH (which differs from the
    user's shell and across launch contexts).
    """

    def test_absolute_argv0_is_used_verbatim(self):
        """An absolute argv[0] is used as-is (symlinks NOT resolved, so the
        stable launcher path survives version upgrades)."""
        with _simulate_platform(
            ["/opt/homebrew/bin/ggshield", "install"], windows=False
        ):
            assert (
                build_hook_command() == "/opt/homebrew/bin/ggshield secret scan ai-hook"
            )

    def test_windows_path_with_spaces_is_quoted(self):
        """On Windows, a path containing spaces is double-quoted so the shell
        does not split it (e.g. a username with a space)."""
        win_path = r"C:\Users\John Doe\AppData\Local\Programs\ggshield\ggshield.exe"
        with _simulate_platform([win_path, "install"], windows=True):
            assert build_hook_command() == f'"{win_path}" secret scan ai-hook'

    def test_windows_path_without_spaces_not_quoted(self):
        """On Windows, a space-free path is left unquoted (some agent parsers
        do not expect quoting)."""
        win_path = r"C:\Python312\Scripts\ggshield.exe"
        with _simulate_platform([win_path, "install"], windows=True):
            assert build_hook_command() == f"{win_path} secret scan ai-hook"

    def test_posix_path_with_spaces_is_shell_quoted(self):
        """On POSIX, shlex.quote protects a path containing spaces."""
        with _simulate_platform(
            ["/home/jane doe/.local/bin/ggshield", "install"], windows=False
        ):
            assert (
                build_hook_command()
                == "'/home/jane doe/.local/bin/ggshield' secret scan ai-hook"
            )

    def test_path_argv0_is_made_absolute(self):
        """An argv[0] that carries a path separator (explicit path, relative
        `./ggshield`, or a `uv run` venv path) is absolutized as-is."""
        for argv0 in (
            "/opt/homebrew/bin/ggshield",  # explicit absolute path
            "/proj/.venv/bin/ggshield",  # `uv run ggshield`
        ):
            with _simulate_platform([argv0, "install"], windows=False):
                assert build_hook_command() == f"{argv0} secret scan ai-hook"

    def test_bare_name_is_resolved_via_path(self):
        """A bare `ggshield` (the normal pip/pipx/Homebrew shell case) is NOT
        rewritten to an absolute path by the shell, so abspath would pin it to
        the CWD (NHI-1842). It must be resolved against the install-time PATH."""
        with _simulate_platform(["ggshield", "install"], windows=False), patch(
            "ggshield.verticals.ai.installation.shutil.which",
            return_value="/opt/homebrew/bin/ggshield",
        ) as which:
            assert (
                build_hook_command() == "/opt/homebrew/bin/ggshield secret scan ai-hook"
            )
        which.assert_called_once_with("ggshield")

    def test_bare_name_not_on_path_falls_back_to_abspath(self):
        """If PATH lookup fails (bare name no longer on PATH), fall back to
        abspath rather than to sys.executable, which is the Python interpreter,
        not ggshield."""
        with _simulate_platform(["ggshield", "install"], windows=False), patch(
            "ggshield.verticals.ai.installation.shutil.which", return_value=None
        ), patch(
            "ggshield.verticals.ai.installation.os.path.abspath",
            return_value="/tmp/ggshield",
        ):
            assert build_hook_command() == "/tmp/ggshield secret scan ai-hook"

    @pytest.mark.skipif(
        os.name == "nt",
        reason="asserts POSIX executable-bit / no-.exe-suffix semantics",
    )
    def test_wheel_install_prefers_the_dispatcher_sibling(self, tmp_path):
        """In a platform-wheel install the user runs `ggshield` (the Rust
        dispatcher), which execs its `ggshield-py` sibling -- so argv[0] names
        ggshield-py by the time Python builds the hook command. Pin the hook to
        the dispatcher, or every hook call pays the Python startup the wheel
        shipped a native binary to avoid."""
        launcher = tmp_path / "ggshield-py"
        launcher.write_text("")
        dispatcher = tmp_path / "ggshield"
        dispatcher.write_text("")
        dispatcher.chmod(0o755)
        with _simulate_platform([str(launcher), "machine", "setup"], windows=False):
            assert build_hook_command() == f"{dispatcher} secret scan ai-hook"

    def test_pure_wheel_install_keeps_its_own_path(self):
        """The pure-Python wheel installs no dispatcher: `ggshield` IS the Python
        entry point, and the sibling lookup must not turn it into a self-exec."""
        with _simulate_platform(
            ["/proj/.venv/bin/ggshield", "machine", "setup"], windows=False
        ):
            assert (
                build_hook_command() == "/proj/.venv/bin/ggshield secret scan ai-hook"
            )

    def test_frozen_bundle_uses_sys_executable(self):
        """In a PyInstaller standalone bundle (.pkg/.deb/.rpm) the frozen binary
        IS ggshield, so sys.executable is the correct self-path -- and PATH must
        NOT be consulted, to avoid resolving a different ggshield install."""
        with patch.object(sys, "frozen", True, create=True), patch.object(
            sys, "executable", "/opt/ggshield/ggshield", create=True
        ), patch("ggshield.verticals.ai.installation.shutil.which") as which:
            assert build_hook_command() == "/opt/ggshield/ggshield secret scan ai-hook"
        which.assert_not_called()

    # These two assert POSIX file semantics that build_hook_command does not
    # use on Windows: the sibling is named `ggshield` (no `.exe` suffix) and
    # its executability is the POSIX x-bit (os.access(X_OK)), which Windows
    # ignores. The Windows dispatcher-preference (the `.exe` branch in
    # build_hook_command) still runs in production and is exercised by the real
    # PyInstaller Windows packaging job; it just has no dedicated Windows unit
    # test here. Honest scoping, not a silent skip.
    @pytest.mark.skipif(
        os.name == "nt",
        reason="asserts POSIX executable-bit / no-.exe-suffix semantics",
    )
    def test_frozen_bundle_prefers_the_dispatcher_sibling(self, tmp_path):
        """In a dispatcher bundle, PyInstaller's sys.executable names the
        internal ggshield-py launcher (it comes from /proc/self/exe, not
        argv[0]). The hook must point at the sibling `ggshield` dispatcher,
        which answers `secret scan ai-hook` natively -- otherwise every hook
        call pays the Python startup the dispatcher exists to remove."""
        launcher = tmp_path / "ggshield-py"
        launcher.write_text("")
        dispatcher = tmp_path / "ggshield"
        dispatcher.write_text("")
        dispatcher.chmod(0o755)
        with patch.object(sys, "frozen", True, create=True), patch.object(
            sys, "executable", str(launcher), create=True
        ):
            assert build_hook_command() == f"{dispatcher} secret scan ai-hook"

    def test_frozen_bundle_without_dispatcher_keeps_sys_executable(self, tmp_path):
        """An older bundle has no dispatcher next to the launcher: keep
        sys.executable, exactly as before."""
        launcher = tmp_path / "ggshield-py"
        launcher.write_text("")
        with patch.object(sys, "frozen", True, create=True), patch.object(
            sys, "executable", str(launcher), create=True
        ):
            assert build_hook_command() == f"{launcher} secret scan ai-hook"

    @pytest.mark.skipif(
        os.name == "nt",
        reason="asserts POSIX executable-bit / no-.exe-suffix semantics",
    )
    def test_frozen_bundle_ignores_a_non_executable_dispatcher(self, tmp_path):
        """A `ggshield` file that cannot be executed (broken install) must not
        be written into the hook command -- the agent would see a failing hook
        on every tool call."""
        launcher = tmp_path / "ggshield-py"
        launcher.write_text("")
        dispatcher = tmp_path / "ggshield"
        dispatcher.write_text("")
        dispatcher.chmod(0o644)
        with patch.object(sys, "frozen", True, create=True), patch.object(
            sys, "executable", str(launcher), create=True
        ):
            assert build_hook_command() == f"{launcher} secret scan ai-hook"

    def test_frozen_bundle_prefers_the_stable_launcher(self):
        """GIVEN a frozen macOS bundle installed in a versioned directory
        WHEN /usr/local/bin/ggshield resolves to that very binary
        THEN the hook is pinned to the launcher, which survives an upgrade."""
        versioned = "/opt/gitguardian/ggshield-1.53.0/ggshield"
        with _simulate_platform(windows=False, frozen=versioned), patch(
            "ggshield.verticals.ai.installation.os.path.realpath",
            lambda path: versioned if path == "/usr/local/bin/ggshield" else path,
        ):
            assert build_hook_command() == "/usr/local/bin/ggshield secret scan ai-hook"

    def test_frozen_dispatcher_bundle_prefers_the_stable_launcher(self):
        """GIVEN a frozen bundle whose hook binary is the sibling dispatcher
        WHEN /usr/local/bin/ggshield resolves to that dispatcher
        THEN the launcher wins: the sibling is picked first, so the launcher has
        the dispatcher to match against and no versioned path is written."""
        versioned = "/opt/gitguardian/ggshield-1.53.0/ggshield"
        with _simulate_platform(windows=False, frozen=f"{versioned}-py"), patch(
            "ggshield.verticals.ai.installation.os.access", return_value=True
        ), patch(
            "ggshield.verticals.ai.installation.os.path.realpath",
            lambda path: versioned if path == "/usr/local/bin/ggshield" else path,
        ):
            assert build_hook_command() == "/usr/local/bin/ggshield secret scan ai-hook"

    def test_frozen_bundle_ignores_a_launcher_to_another_binary(self):
        """GIVEN a frozen bundle on a machine that also has a Homebrew ggshield
        WHEN /usr/local/bin/ggshield resolves to that other install
        THEN the bundle path is kept: the other binary holds no credentials."""
        versioned = "/opt/gitguardian/ggshield-1.53.0/ggshield"
        with _simulate_platform(windows=False, frozen=versioned), patch(
            "ggshield.verticals.ai.installation.os.path.realpath",
            lambda path: (
                "/opt/homebrew/bin/ggshield"
                if path == "/usr/local/bin/ggshield"
                else path
            ),
        ):
            assert build_hook_command() == f"{versioned} secret scan ai-hook"

    def test_stable_launcher_is_not_used_outside_a_frozen_bundle(self):
        """GIVEN a pip/Homebrew install (not frozen)
        WHEN a launcher would resolve to the same file
        THEN argv[0] is still used verbatim, symlinks unresolved."""
        with _simulate_platform(
            ["/opt/homebrew/bin/ggshield", "install"], windows=False
        ), patch(
            "ggshield.verticals.ai.installation.os.path.realpath",
            lambda path: "/opt/homebrew/bin/ggshield",
        ):
            assert (
                build_hook_command() == "/opt/homebrew/bin/ggshield secret scan ai-hook"
            )

    def test_frozen_bundle_on_windows_ignores_posix_launchers(self):
        """GIVEN a frozen Windows install
        WHEN the POSIX launcher paths would match
        THEN they are ignored: they mean nothing on Windows."""
        exe = r"C:\Program Files\GitGuardian\ggshield\ggshield.exe"
        with _simulate_platform(windows=True, frozen=exe), patch(
            "ggshield.verticals.ai.installation.os.path.realpath", lambda path: exe
        ):
            assert build_hook_command() == f'"{exe}" secret scan ai-hook'


class _FakeAgent:
    """Minimal stand-in for an Agent for posture tests."""

    def __init__(self, name: str, display_name: str, present: bool):
        self.name = name
        self.display_name = display_name
        self._present = present

    def is_present(self) -> bool:
        return self._present


class TestAiHookPosture:
    AGENTS_PATH = "ggshield.verticals.ai.installation.AGENTS"
    HOOKS_PATH = "ggshield.verticals.ai.installation.are_hooks_installed_globally"

    def test_reports_only_present_agents(self):
        fakes = {
            "a": _FakeAgent("a", "Agent A", present=True),
            "b": _FakeAgent("b", "Agent B", present=False),
        }
        with patch.dict(self.AGENTS_PATH, fakes, clear=True), patch(
            self.HOOKS_PATH, return_value=(True, "cmd")
        ):
            statuses = ai_hook_posture()
        assert statuses == [AgentHookStatus(display_name="Agent A", installed=True)]

    def test_reports_installed_flag(self):
        fakes = {"a": _FakeAgent("a", "Agent A", present=True)}
        with patch.dict(self.AGENTS_PATH, fakes, clear=True), patch(
            self.HOOKS_PATH, return_value=(False, None)
        ):
            statuses = ai_hook_posture()
        assert statuses == [AgentHookStatus(display_name="Agent A", installed=False)]

    def test_empty_when_no_agents_present(self):
        fakes = {"a": _FakeAgent("a", "Agent A", present=False)}
        with patch.dict(self.AGENTS_PATH, fakes, clear=True), patch(self.HOOKS_PATH):
            assert ai_hook_posture() == []
