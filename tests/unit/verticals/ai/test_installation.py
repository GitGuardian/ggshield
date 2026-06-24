import contextlib
import json
import ntpath
import posixpath
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest

from ggshield.core.errors import UnexpectedError
from ggshield.verticals.ai.agents import Claude, Codex, Copilot, Cursor
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
def _simulate_platform(argv, *, windows):
    """Run build_hook_command as if on a given OS, regardless of the test host.

    Patches the path primitives the function uses (``os.name`` and
    ``os.path.abspath``) to the chosen flavor (ntpath or posixpath) so the same
    assertions hold whether the runner is Linux or Windows.
    """
    flavor = ntpath if windows else posixpath
    mod = "ggshield.verticals.ai.installation"
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch(f"{mod}.sys.argv", argv))
        stack.enter_context(patch(f"{mod}.os.name", "nt" if windows else "posix"))
        stack.enter_context(patch(f"{mod}.os.path.abspath", flavor.abspath))
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

    def test_common_install_invocations_are_used_as_is(self):
        """Real install invocations yield an absolute argv[0], used as-is. A
        `uv run`/`uvx` wrapper is consumed by uv before ggshield starts, and a
        bare `ggshield` is resolved to its absolute path by the shell, so
        argv[0] is already the resolved executable in every case."""
        for argv0 in (
            "/usr/local/bin/ggshield",  # bare `ggshield`, resolved by the shell
            "/opt/homebrew/bin/ggshield",  # explicit absolute path
            "/proj/.venv/bin/ggshield",  # `uv run ggshield`
        ):
            with _simulate_platform([argv0, "install"], windows=False):
                assert build_hook_command() == f"{argv0} secret scan ai-hook"


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
