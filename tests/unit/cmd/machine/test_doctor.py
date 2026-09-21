from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from pygitguardian.models import APITokensResponse, HealthCheckResponse

from ggshield.__main__ import cli
from ggshield.cmd.machine.doctor import (
    Check,
    _check_ai_hooks,
    _check_auth_and_scopes,
    _check_git_hooks,
    _check_git_hooks_precedence,
    _check_plugin_native,
    _check_scopes,
    _is_plugin_installed,
)
from ggshield.verticals.ai.installation import AgentHookStatus
from tests.unit.cmd.machine.test_setup import _current_hook, _legacy_hook
from tests.unit.conftest import assert_invoke_ok


BASE = "ggshield.cmd.machine.doctor"


class TestDoctorCommand:
    def test_doctor_appears_in_machine_help(self, cli_fs_runner: CliRunner):
        result = cli_fs_runner.invoke(cli, ["machine", "--help"])
        assert_invoke_ok(result)
        assert "doctor" in result.output

    def _run(self, cli_fs_runner, *, auth_ok, ai_ok, git_ok, plugin_installed):
        auth = Check("Authentication", auth_ok)
        with patch(
            f"{BASE}._check_auth_and_scopes", return_value=(["scan"], auth)
        ), patch(f"{BASE}._is_plugin_installed", return_value=plugin_installed), patch(
            f"{BASE}._check_ai_hooks", return_value=Check("AI hooks", ai_ok)
        ), patch(
            f"{BASE}._check_git_hooks", return_value=Check("Git hooks", git_ok)
        ), patch(
            f"{BASE}._check_git_hooks_precedence",
            return_value=Check("Git hook precedence", True),
        ), patch(
            f"{BASE}._check_scopes", return_value=[Check("Scope", True)]
        ), patch(
            f"{BASE}._check_plugin_native", return_value=Check("Plugin", True)
        ) as m_plugin:
            result = cli_fs_runner.invoke(cli, ["machine", "doctor"])
        return result, m_plugin

    def test_exit_zero_when_all_pass(self, cli_fs_runner: CliRunner):
        result, _ = self._run(
            cli_fs_runner, auth_ok=True, ai_ok=True, git_ok=True, plugin_installed=False
        )
        assert result.exit_code == 0
        assert "correctly set up" in result.output

    def test_exit_nonzero_when_a_check_fails(self, cli_fs_runner: CliRunner):
        result, _ = self._run(
            cli_fs_runner,
            auth_ok=True,
            ai_ok=False,
            git_ok=True,
            plugin_installed=False,
        )
        assert result.exit_code == 1
        assert "failed" in result.output

    def test_plugin_check_skipped_without_plugin(self, cli_fs_runner: CliRunner):
        _result, m_plugin = self._run(
            cli_fs_runner, auth_ok=True, ai_ok=True, git_ok=True, plugin_installed=False
        )
        m_plugin.assert_not_called()

    def test_plugin_check_runs_with_plugin(self, cli_fs_runner: CliRunner):
        _result, m_plugin = self._run(
            cli_fs_runner, auth_ok=True, ai_ok=True, git_ok=True, plugin_installed=True
        )
        m_plugin.assert_called_once()


class TestCheckAuthAndScopes:
    def _health(self, status_code, detail="ok"):
        return MagicMock(
            spec=HealthCheckResponse, status_code=status_code, detail=detail
        )

    def test_healthy_returns_scopes(self):
        client = MagicMock()
        client.health_check.return_value = self._health(200)
        token = MagicMock(spec=APITokensResponse, scopes=["scan", "honeytokens:write"])
        with patch(f"{BASE}.create_client_from_config", return_value=client), patch(
            f"{BASE}.safe_api_tokens", return_value=token
        ):
            scopes, check = _check_auth_and_scopes(MagicMock())
        assert check.ok is True
        assert scopes == ["scan", "honeytokens:write"]

    def test_unhealthy_fails_and_no_scopes(self):
        client = MagicMock()
        client.health_check.return_value = self._health(401, detail="bad token")
        with patch(f"{BASE}.create_client_from_config", return_value=client):
            scopes, check = _check_auth_and_scopes(MagicMock())
        assert check.ok is False
        assert "bad token" in check.detail
        assert scopes is None

    def test_client_error_fails_gracefully(self):
        with patch(
            f"{BASE}.create_client_from_config", side_effect=RuntimeError("no key")
        ):
            scopes, check = _check_auth_and_scopes(MagicMock())
        assert check.ok is False
        assert "no key" in check.detail
        assert scopes is None


class TestCheckAiHooks:
    def test_all_installed(self):
        with patch(
            f"{BASE}.ai_hook_posture",
            return_value=[AgentHookStatus("Claude Code", True)],
        ):
            assert _check_ai_hooks().ok is True

    def test_some_missing(self):
        with patch(
            f"{BASE}.ai_hook_posture",
            return_value=[
                AgentHookStatus("Claude Code", True),
                AgentHookStatus("Cursor", False),
            ],
        ):
            check = _check_ai_hooks()
        assert check.ok is False
        assert "Cursor" in check.detail

    def test_none_detected_is_ok(self):
        with patch(f"{BASE}.ai_hook_posture", return_value=[]):
            assert _check_ai_hooks().ok is True


class TestCheckGitHooks:
    """Only a configured ``core.hooksPath`` counts. Git runs exactly one hooks
    directory, so the scope that is not configured -- and the directory ggshield
    *would* install into when nothing points git at it -- must not sway the verdict.
    """

    def _patch_dirs(self, global_dir, system_dir):
        """None means that scope has no core.hooksPath configured."""
        return patch.multiple(
            BASE,
            get_global_hook_dir_path=MagicMock(return_value=global_dir),
            get_system_hook_dir_path=MagicMock(return_value=system_dir),
        )

    def test_ok_when_present_in_global(self, tmp_path):
        (global_dir := tmp_path / "g").mkdir()
        for hook in ("pre-commit", "pre-push"):
            (global_dir / hook).write_text(_current_hook(hook))
        with self._patch_dirs(global_dir, None):
            assert _check_git_hooks().ok is True

    def test_fail_when_no_hooks_path_is_configured(self, tmp_path):
        """Without core.hooksPath git runs each repo's own hooks, whatever files
        happen to sit in the directory ggshield would install into."""
        with self._patch_dirs(None, None):
            check = _check_git_hooks()
        assert check.ok is False
        assert "core.hooksPath" in check.detail

    def test_fail_when_split_across_global_and_system(self, tmp_path):
        """Git reads one directory, so a hook in the out-ranked scope never runs."""
        (global_dir := tmp_path / "g").mkdir()
        (system_dir := tmp_path / "s").mkdir()
        (global_dir / "pre-commit").write_text(_current_hook("pre-commit"))
        (system_dir / "pre-push").write_text(_current_hook("pre-push"))
        with self._patch_dirs(global_dir, system_dir):
            check = _check_git_hooks()
        assert check.ok is False
        assert "pre-push" in check.detail and "pre-commit" not in check.detail

    def test_fail_when_missing(self, tmp_path):
        (global_dir := tmp_path / "g").mkdir()
        with self._patch_dirs(global_dir, None):
            check = _check_git_hooks()
        assert check.ok is False
        assert "pre-commit" in check.detail and "pre-push" in check.detail

    def test_fail_on_foreign_hook(self, tmp_path):
        (global_dir := tmp_path / "g").mkdir()
        for hook in ("pre-commit", "pre-push"):
            (global_dir / hook).write_text("#!/bin/sh\nother-tool\n")
        with self._patch_dirs(global_dir, None):
            assert _check_git_hooks().ok is False

    def test_fail_on_stale_hook(self, tmp_path):
        """A pre-1.53 hook carries the marker but the pre-worktree-fix template."""
        (global_dir := tmp_path / "g").mkdir()
        (global_dir / "pre-commit").write_text(_legacy_hook("pre-commit"))
        (global_dir / "pre-push").write_text(_current_hook("pre-push"))
        with self._patch_dirs(global_dir, None):
            check = _check_git_hooks()
        assert check.ok is False
        assert "pre-commit" in check.detail and "pre-push" not in check.detail

    @pytest.mark.parametrize(
        ("global_state", "system_state", "expected_ok"),
        [
            # A global core.hooksPath out-ranks the system one, so when both are
            # configured only the global hook decides.
            ("current", "legacy", True),
            ("legacy", "current", False),
            (None, "current", True),
            (None, "legacy", False),
        ],
    )
    def test_only_the_configured_scope_that_wins_decides(
        self, tmp_path, global_state, system_state, expected_ok
    ):
        render = {"current": _current_hook, "legacy": _legacy_hook}
        dirs = {}
        for name, state in (("g", global_state), ("s", system_state)):
            if state is None:
                dirs[name] = None
                continue
            (directory := tmp_path / name).mkdir()
            for hook in ("pre-commit", "pre-push"):
                (directory / hook).write_text(render[state](hook))
            dirs[name] = directory
        with self._patch_dirs(dirs["g"], dirs["s"]):
            assert _check_git_hooks().ok is expected_ok

    def test_leftover_hooks_in_the_default_dir_are_ignored(self, tmp_path):
        """The directory ggshield installs into is not the one git reads unless
        core.hooksPath says so. Reading it let stale leftovers fail a healthy
        machine, and current leftovers pass a stale one."""
        (default_global := tmp_path / "default-global").mkdir()
        (system_dir := tmp_path / "s").mkdir()
        for hook in ("pre-commit", "pre-push"):
            (default_global / hook).write_text(_legacy_hook(hook))
            (system_dir / hook).write_text(_current_hook(hook))
        with self._patch_dirs(None, system_dir), patch(
            "ggshield.cmd.install.get_default_global_hook_dir_path",
            return_value=default_global,
        ):
            assert _check_git_hooks().ok is True


class TestCheckScopes:
    def test_none_scopes_fails(self):
        checks = _check_scopes(None, plugin_installed=False)
        assert len(checks) == 1 and checks[0].ok is False

    def test_scan_and_honeytoken_reported(self):
        checks = _check_scopes(["scan"], plugin_installed=False)
        by_name = {c.name: c.ok for c in checks}
        assert by_name["Scope `scan`"] is True
        assert by_name["Scope `honeytokens:write`"] is False

    def test_ai_discover_scope_reported(self):
        checks = _check_scopes(["scan"], plugin_installed=False)
        by_name = {c.name: c.ok for c in checks}
        assert by_name["Scope `ai-discover:send`"] is False
        checks = _check_scopes(["scan", "ai-discover:send"], plugin_installed=False)
        by_name = {c.name: c.ok for c in checks}
        assert by_name["Scope `ai-discover:send`"] is True

    def test_endpoint_scope_only_with_plugin(self):
        without = _check_scopes(["scan"], plugin_installed=False)
        assert not any("endpoints:send" in c.name for c in without)
        with_plugin = _check_scopes(["scan", "endpoints:send"], plugin_installed=True)
        endpoint = [c for c in with_plugin if "endpoints:send" in c.name]
        assert endpoint and endpoint[0].ok is True


class TestPluginChecks:
    def test_is_plugin_installed_true(self):
        registry = MagicMock()
        registry.get_plugin.return_value = MagicMock()
        with patch(f"{BASE}.load_plugin_registry", return_value=registry):
            assert _is_plugin_installed() is True

    def test_is_plugin_installed_false_no_registry(self):
        with patch(f"{BASE}.load_plugin_registry", return_value=None):
            assert _is_plugin_installed() is False

    def test_is_plugin_installed_false_not_registered(self):
        registry = MagicMock()
        registry.get_plugin.return_value = None
        with patch(f"{BASE}.load_plugin_registry", return_value=registry):
            assert _is_plugin_installed() is False

    def test_native_loads_ok(self):
        registry = MagicMock()
        registry.get_plugin.return_value = MagicMock(
            metadata=MagicMock(version="1.2.3")
        )
        native = MagicMock()
        with patch(f"{BASE}.load_plugin_registry", return_value=registry), patch(
            f"{BASE}.import_module", return_value=native
        ):
            check = _check_plugin_native()
        assert check.ok is True
        assert "1.2.3" in check.detail
        native.Scanner.assert_called_once()

    def test_native_load_failure_reported(self):
        registry = MagicMock()
        registry.get_plugin.return_value = MagicMock(
            metadata=MagicMock(version="1.2.3")
        )
        with patch(f"{BASE}.load_plugin_registry", return_value=registry), patch(
            f"{BASE}.import_module", side_effect=ImportError("bad arch")
        ):
            check = _check_plugin_native()
        assert check.ok is False
        assert "bad arch" in check.detail


class TestCheckGitHooksPrecedence:
    def test_ok_when_no_shadow(self):
        with patch(f"{BASE}.get_shadowing_hooks_path", return_value=None):
            assert _check_git_hooks_precedence().ok is True

    def test_fail_when_shadowed(self):
        shadow = Path("/repo/.husky/_")
        with patch(f"{BASE}.get_shadowing_hooks_path", return_value=shadow):
            check = _check_git_hooks_precedence()
        assert check.ok is False
        # Use the rendered path (backslashes on Windows) so the assertion is portable.
        assert str(shadow) in check.detail
