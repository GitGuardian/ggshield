import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner
from pygitguardian.models import HealthCheckResponse

from ggshield.__main__ import cli
from ggshield.core.plugin.client import (
    PluginAPIError,
    PluginCatalog,
    PluginInfo,
    PluginsNotEnabledError,
)
from ggshield.core.plugin.installer import InstalledPlugin
from ggshield.verticals.ai.installation import (
    SetupSummary,
    install_all_agent_hooks,
    select_agents,
)
from tests.unit.conftest import assert_invoke_ok


AGENTS_PATH = "ggshield.verticals.ai.installation.AGENTS"


def _raise(error: Exception):
    raise error


class _FakeAgent:
    """Minimal stand-in for an Agent, controlling only what setup needs."""

    def __init__(self, name: str, present: bool):
        self.name = name
        self.display_name = name.replace("-", " ").title()
        self._present = present

    def is_present(self) -> bool:
        return self._present


class TestSelectAgents:
    def test_defaults_to_detected_agents(self):
        fakes = {
            "a": _FakeAgent("a", True),
            "b": _FakeAgent("b", False),
            "c": _FakeAgent("c", True),
        }
        with patch.dict(AGENTS_PATH, fakes, clear=True):
            selected = select_agents(only=(), exclude=())
        assert {agent.name for agent in selected} == {"a", "c"}

    def test_only_overrides_presence_detection(self):
        fakes = {"a": _FakeAgent("a", False), "b": _FakeAgent("b", False)}
        with patch.dict(AGENTS_PATH, fakes, clear=True):
            selected = select_agents(only=("a",), exclude=())
        assert [agent.name for agent in selected] == ["a"]

    def test_exclude_drops_from_detected(self):
        fakes = {"a": _FakeAgent("a", True), "b": _FakeAgent("b", True)}
        with patch.dict(AGENTS_PATH, fakes, clear=True):
            selected = select_agents(only=(), exclude=("b",))
        assert {agent.name for agent in selected} == {"a"}


class TestInstallAllAgentHooks:
    @patch("ggshield.verticals.ai.installation.install_hooks", return_value=0)
    def test_configures_every_detected_agent(self, mock_install):
        fakes = {"a": _FakeAgent("a", True), "b": _FakeAgent("b", True)}
        with patch.dict(AGENTS_PATH, fakes, clear=True):
            summary = install_all_agent_hooks()
        assert summary == SetupSummary(configured=2, failed=0)
        assert mock_install.call_count == 2

    @patch("ggshield.verticals.ai.installation.install_hooks", return_value=0)
    def test_no_detected_agents_does_nothing(self, mock_install):
        fakes = {"a": _FakeAgent("a", False)}
        with patch.dict(AGENTS_PATH, fakes, clear=True):
            summary = install_all_agent_hooks()
        assert summary == SetupSummary(configured=0, failed=0)
        mock_install.assert_not_called()

    @patch("ggshield.verticals.ai.installation.install_hooks", return_value=1)
    def test_counts_failures(self, mock_install):
        fakes = {"a": _FakeAgent("a", True)}
        with patch.dict(AGENTS_PATH, fakes, clear=True):
            summary = install_all_agent_hooks(only=("a",))
        assert summary == SetupSummary(configured=0, failed=1)


class TestMachineSetupCommand:
    @patch("ggshield.cmd.machine.setup.check_ai_hook_authentication")
    @patch("ggshield.cmd.machine.setup.install_all_agent_hooks")
    def test_runs_auth_preflight_when_configured(
        self, mock_install, mock_preflight, cli_fs_runner: CliRunner
    ):
        mock_install.return_value = SetupSummary(configured=2, failed=0)

        result = cli_fs_runner.invoke(
            cli, ["machine", "setup", "--no-git-hooks", "--no-honeytokens"]
        )

        assert_invoke_ok(result)
        mock_install.assert_called_once_with(only=(), exclude=())
        mock_preflight.assert_called_once()

    @patch("ggshield.cmd.machine.setup.check_ai_hook_authentication")
    @patch("ggshield.cmd.machine.setup.install_all_agent_hooks")
    def test_skips_preflight_when_nothing_configured(
        self, mock_install, mock_preflight, cli_fs_runner: CliRunner
    ):
        mock_install.return_value = SetupSummary(configured=0, failed=0)

        result = cli_fs_runner.invoke(
            cli, ["machine", "setup", "--no-git-hooks", "--no-honeytokens"]
        )

        assert_invoke_ok(result)
        mock_preflight.assert_not_called()

    @patch("ggshield.cmd.machine.setup.check_ai_hook_authentication")
    @patch("ggshield.cmd.machine.setup.install_all_agent_hooks")
    def test_passes_agents_through(
        self, mock_install, mock_preflight, cli_fs_runner: CliRunner
    ):
        mock_install.return_value = SetupSummary(configured=1, failed=0)

        result = cli_fs_runner.invoke(
            cli,
            [
                "machine",
                "setup",
                "--no-git-hooks",
                "--no-honeytokens",
                "--agent",
                "claude-code",
            ],
        )

        assert_invoke_ok(result)
        mock_install.assert_called_once_with(only=("claude-code",), exclude=())

    @patch("ggshield.cmd.machine.setup.check_ai_hook_authentication")
    @patch("ggshield.cmd.machine.setup.install_all_agent_hooks")
    def test_failure_returns_nonzero_and_skips_preflight(
        self, mock_install, mock_preflight, cli_fs_runner: CliRunner
    ):
        mock_install.return_value = SetupSummary(configured=1, failed=1)

        result = cli_fs_runner.invoke(
            cli, ["machine", "setup", "--no-git-hooks", "--no-honeytokens"]
        )

        assert result.exit_code == 1
        mock_preflight.assert_not_called()

    @patch("ggshield.cmd.machine.setup._warm_notifier")
    @patch("ggshield.verticals.ai.installation.create_client_from_config")
    @patch("ggshield.verticals.ai.installation._is_interactive", return_value=True)
    @patch("ggshield.cmd.machine.setup.install_all_agent_hooks")
    def test_a_broken_hook_binary_does_not_fail_setup(
        self,
        mock_install,
        mock_interactive,
        mock_client,
        mock_notifier,
        cli_fs_runner: CliRunner,
        monkeypatch,
    ):
        """
        GIVEN an interactive setup whose hook binary cannot be run at all
        WHEN the credential-store warm-up spawns it
        THEN setup still succeeds: the grant is best effort
        """
        mock_install.return_value = SetupSummary(configured=1, failed=0)
        mock_client.return_value.health_check.return_value = Mock(
            spec=HealthCheckResponse, status_code=200
        )
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "executable", "/opt/gitguardian/ggshield-py")
        monkeypatch.setattr(
            "ggshield.verticals.ai.installation.hook_executable",
            lambda: "/opt/gitguardian/ggshield",
        )
        # Only the warm-up spawn fails; git and the rest of setup run for real.
        real_run = subprocess.run
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda args, **kwargs: (
                _raise(FileNotFoundError("no hook binary here"))
                if args[0] == "/opt/gitguardian/ggshield"
                else real_run(args, **kwargs)
            ),
        )

        result = cli_fs_runner.invoke(
            cli, ["machine", "setup", "--no-git-hooks", "--no-honeytokens"]
        )

        assert_invoke_ok(result)

    def test_agent_and_exclude_agent_are_mutually_exclusive(
        self, cli_fs_runner: CliRunner
    ):
        result = cli_fs_runner.invoke(
            cli,
            ["machine", "setup", "--agent", "cursor", "--exclude-agent", "codex"],
        )
        assert result.exit_code != 0
        assert "cannot be used together" in result.output

    def test_setup_appears_in_machine_help(self, cli_fs_runner: CliRunner):
        result = cli_fs_runner.invoke(cli, ["machine", "--help"])
        assert_invoke_ok(result)
        assert "setup" in result.output


class TestMachineSetupOrchestration:
    """`machine setup` runs all four protections by default; flags drop one."""

    AI = "ggshield.cmd.machine.setup._setup_ai_hooks"
    GIT = "ggshield.cmd.machine.setup._setup_git_hooks"
    HT = "ggshield.cmd.machine.setup._setup_honeytokens"
    PLUGINS = "ggshield.cmd.machine.setup._setup_plugins"

    def _run(self, cli_fs_runner, args, ai=True, git=True, ht=True, plugins=True):
        with patch(self.AI, return_value=ai) as m_ai, patch(
            self.GIT, return_value=git
        ) as m_git, patch(self.HT, return_value=ht) as m_ht, patch(
            self.PLUGINS, return_value=plugins
        ) as m_plugins:
            result = cli_fs_runner.invoke(cli, ["machine", "setup", *args])
        return result, m_ai, m_git, m_ht, m_plugins

    def test_runs_all_features_by_default(self, cli_fs_runner: CliRunner):
        result, m_ai, m_git, m_ht, m_plugins = self._run(cli_fs_runner, [])
        assert_invoke_ok(result)
        m_ai.assert_called_once()
        m_git.assert_called_once()
        m_ht.assert_called_once()
        m_plugins.assert_called_once()

    def test_no_ai_hooks_skips_ai(self, cli_fs_runner: CliRunner):
        result, m_ai, m_git, m_ht, _m_plugins = self._run(
            cli_fs_runner, ["--no-ai-hooks"]
        )
        assert_invoke_ok(result)
        m_ai.assert_not_called()
        m_git.assert_called_once()
        m_ht.assert_called_once()

    def test_no_git_hooks_skips_git(self, cli_fs_runner: CliRunner):
        result, _m_ai, m_git, *_ = self._run(cli_fs_runner, ["--no-git-hooks"])
        assert_invoke_ok(result)
        m_git.assert_not_called()

    def test_no_honeytokens_skips_honeytokens(self, cli_fs_runner: CliRunner):
        result, _m_ai, _m_git, m_ht, _m_plugins = self._run(
            cli_fs_runner, ["--no-honeytokens"]
        )
        assert_invoke_ok(result)
        m_ht.assert_not_called()

    def test_no_plugins_skips_plugins(self, cli_fs_runner: CliRunner):
        result, _m_ai, _m_git, m_ht, m_plugins = self._run(
            cli_fs_runner, ["--no-plugins"]
        )
        assert_invoke_ok(result)
        m_plugins.assert_not_called()
        m_ht.assert_called_once()

    def test_failing_feature_returns_nonzero(self, cli_fs_runner: CliRunner):
        result, *_ = self._run(cli_fs_runner, [], git=False)
        assert result.exit_code == 1

    def test_failing_plugin_step_returns_nonzero(self, cli_fs_runner: CliRunner):
        result, *_ = self._run(cli_fs_runner, [], plugins=False)
        assert result.exit_code == 1

    def test_system_flag_forwarded_to_git_hooks(self, cli_fs_runner: CliRunner):
        result, _m_ai, m_git, *_ = self._run(
            cli_fs_runner, ["--system", "--no-ai-hooks", "--no-honeytokens"]
        )
        assert_invoke_ok(result)
        m_git.assert_called_once_with(True)

    def test_git_hooks_default_to_non_system(self, cli_fs_runner: CliRunner):
        result, _m_ai, m_git, *_ = self._run(
            cli_fs_runner, ["--no-ai-hooks", "--no-honeytokens"]
        )
        assert_invoke_ok(result)
        m_git.assert_called_once_with(False)


class TestSetupGitHooks:
    BASE = "ggshield.cmd.machine.setup"

    @pytest.fixture(autouse=True)
    def _no_shadow(self):
        # Pin the core.hooksPath shadow check so these tests don't shell out to the
        # real `git config`. Tests that exercise it override this.
        with patch(f"{self.BASE}.get_shadowing_hooks_path", return_value=None):
            yield

    # ``is_root`` is pinned False so the per-user branch is deterministic even when
    # the test runs as root (e.g. a CI container).
    @patch(f"{BASE}.is_root", return_value=False)
    @patch(f"{BASE}.install_global")
    @patch(f"{BASE}.get_global_hook_dir_path", return_value=None)
    @patch(f"{BASE}.get_default_global_hook_dir_path")
    def test_installs_absent_hooks(
        self, mock_dir, _mock_cfg, mock_install, _mock_root, tmp_path
    ):
        from ggshield.cmd.machine.setup import _setup_git_hooks

        mock_dir.return_value = tmp_path  # empty dir -> both hooks absent
        assert _setup_git_hooks(system=False) is True
        assert mock_install.call_count == 2  # pre-commit + pre-push

    @patch(f"{BASE}.is_root", return_value=False)
    @patch(f"{BASE}.install_global")
    @patch(f"{BASE}.get_global_hook_dir_path", return_value=None)
    @patch(f"{BASE}.get_default_global_hook_dir_path")
    def test_skips_existing_ggshield_hooks(
        self, mock_dir, _mock_cfg, mock_install, _mock_root, tmp_path
    ):
        from ggshield.cmd.machine.setup import _setup_git_hooks

        mock_dir.return_value = tmp_path
        for hook_type in ("pre-commit", "pre-push"):
            (tmp_path / hook_type).write_text(
                f"#!/bin/sh\nggshield secret scan {hook_type}\n"
            )
        assert _setup_git_hooks(system=False) is True
        mock_install.assert_not_called()

    @patch(f"{BASE}.is_root", return_value=False)
    @patch(f"{BASE}.install_global")
    @patch(f"{BASE}.get_global_hook_dir_path", return_value=None)
    @patch(f"{BASE}.get_default_global_hook_dir_path")
    def test_leaves_foreign_hooks_untouched(
        self, mock_dir, _mock_cfg, mock_install, _mock_root, tmp_path
    ):
        from ggshield.cmd.machine.setup import _setup_git_hooks

        mock_dir.return_value = tmp_path
        (tmp_path / "pre-commit").write_text("#!/bin/sh\nother-tool\n")
        (tmp_path / "pre-push").write_text("#!/bin/sh\nggshield secret scan pre-push\n")
        assert _setup_git_hooks(system=False) is True
        mock_install.assert_not_called()

    @patch(f"{BASE}.is_root", return_value=False)
    @patch(f"{BASE}.install_system")
    @patch(f"{BASE}.get_system_hook_dir_path", return_value=None)
    @patch(f"{BASE}.get_default_system_hook_dir_path")
    def test_system_scope_via_flag(
        self, mock_dir, _mock_cfg, mock_install, _mock_root, tmp_path
    ):
        from ggshield.cmd.machine.setup import _setup_git_hooks

        mock_dir.return_value = tmp_path
        assert _setup_git_hooks(system=True) is True
        assert mock_install.call_count == 2  # install_system, not install_global

    @patch(f"{BASE}.is_root", return_value=True)
    @patch(f"{BASE}.install_system")
    @patch(f"{BASE}.get_system_hook_dir_path", return_value=None)
    @patch(f"{BASE}.get_default_system_hook_dir_path")
    def test_system_scope_when_root(
        self, mock_dir, _mock_cfg, mock_install, _mock_root, tmp_path
    ):
        from ggshield.cmd.machine.setup import _setup_git_hooks

        mock_dir.return_value = tmp_path
        assert _setup_git_hooks(system=False) is True  # root implies system scope
        assert mock_install.call_count == 2

    @patch(f"{BASE}.is_root", return_value=False)
    @patch(f"{BASE}.install_global")
    @patch(f"{BASE}.get_global_hook_dir_path", return_value=None)
    @patch(f"{BASE}.get_default_global_hook_dir_path")
    def test_warns_when_a_core_hookspath_override_shadows(
        self, mock_dir, _mock_cfg, _mock_install, _mock_root, tmp_path, capsys
    ):
        from ggshield.cmd.machine.setup import _setup_git_hooks

        mock_dir.return_value = tmp_path
        with patch(
            f"{self.BASE}.get_shadowing_hooks_path",
            return_value=Path("/repo/.husky/_"),
        ):
            _setup_git_hooks(system=False)
        captured = capsys.readouterr()
        assert "core.hooksPath override" in captured.out + captured.err


class TestHoneytokenPlant:
    @patch("ggshield.cmd.honeytoken.plant.resolve_targets", return_value=[])
    def test_plant_is_not_deprecated(self, _targets, cli_fs_runner: CliRunner):
        """`honeytoken plant` stays a first-class command (not deprecated)."""
        result = cli_fs_runner.invoke(cli, ["honeytoken", "plant"])
        assert "deprecated" not in result.output.lower()


class TestSetupPlugins:
    """The plugin step installs what the account is entitled to, and only that.

    Entitlement comes from the catalog (`available` / `reason`), so these tests
    drive the catalog rather than any notion of a plan.
    """

    BASE = "ggshield.cmd.machine.setup"

    def _plugin(self, name="machine_scan", available=True, latest="1.2.0", reason=None):
        return PluginInfo(
            name=name,
            display_name=name.replace("_", " ").title(),
            description="",
            available=available,
            latest_version=latest,
            reason=reason,
        )

    @contextmanager
    def _catalog(self, plugins=None, error=None, installed=None):
        """Pin the catalog call and the installed-version lookup."""
        api_client = Mock()
        if error is not None:
            api_client.get_available_plugins.side_effect = error
        else:
            api_client.get_available_plugins.return_value = PluginCatalog(
                plugins=plugins or []
            )
        downloader = Mock()
        downloader.get_installed_version.side_effect = lambda name: (
            installed or {}
        ).get(name)
        with patch(f"{self.BASE}.create_client_from_config"), patch(
            f"{self.BASE}.PluginAPIClient", return_value=api_client
        ), patch(f"{self.BASE}.PluginDownloader", return_value=downloader), patch(
            f"{self.BASE}.EnterpriseConfig"
        ), patch(
            f"{self.BASE}.install_plugin_from_platform"
        ) as m_install:
            yield m_install

    def _run(self, cli_fs_runner):
        return cli_fs_runner.invoke(
            cli,
            ["machine", "setup", "--no-ai-hooks", "--no-git-hooks", "--no-honeytokens"],
        )

    def test_installs_every_available_plugin(self, cli_fs_runner: CliRunner):
        plugins = [self._plugin("machine_scan"), self._plugin("tokenscanner")]
        with self._catalog(plugins) as m_install:
            m_install.side_effect = lambda _client, name, **kwargs: InstalledPlugin(
                name=name, version="1.2.0"
            )
            result = self._run(cli_fs_runner)
        assert_invoke_ok(result)
        assert [call.args[1] for call in m_install.call_args_list] == [
            "machine_scan",
            "tokenscanner",
        ]
        assert "installed machine_scan v1.2.0" in result.output

    def test_skips_plugin_the_account_cannot_install(self, cli_fs_runner: CliRunner):
        plugins = [
            self._plugin(
                "machine_scan",
                available=False,
                latest=None,
                reason="Business or Enterprise plans only",
            )
        ]
        with self._catalog(plugins) as m_install:
            result = self._run(cli_fs_runner)
        # Not entitled is a normal outcome, not a setup failure.
        assert_invoke_ok(result)
        m_install.assert_not_called()
        assert "no plugins available for this account" in result.output
        assert "Business or Enterprise plans only" in result.output

    def test_plugin_system_disabled_is_not_a_failure(self, cli_fs_runner: CliRunner):
        with self._catalog(error=PluginsNotEnabledError()) as m_install:
            result = self._run(cli_fs_runner)
        assert_invoke_ok(result)
        m_install.assert_not_called()
        assert "not enabled on this workspace" in result.output

    def test_unreachable_catalog_is_not_a_failure(self, cli_fs_runner: CliRunner):
        with self._catalog(error=PluginAPIError("boom")) as m_install:
            result = self._run(cli_fs_runner)
        assert_invoke_ok(result)
        m_install.assert_not_called()
        assert "could not fetch the plugin catalog" in result.output

    def test_already_installed_plugin_is_left_alone(self, cli_fs_runner: CliRunner):
        with self._catalog(
            [self._plugin("machine_scan", latest="1.2.0")],
            installed={"machine_scan": "1.2.0"},
        ) as m_install:
            result = self._run(cli_fs_runner)
        assert_invoke_ok(result)
        m_install.assert_not_called()
        assert "machine_scan already installed v1.2.0" in result.output

    def test_outdated_plugin_points_at_plugin_update(self, cli_fs_runner: CliRunner):
        # `setup` adds what is missing; upgrading stays an explicit `plugin update`.
        with self._catalog(
            [self._plugin("machine_scan", latest="1.3.0")],
            installed={"machine_scan": "1.2.0"},
        ) as m_install:
            result = self._run(cli_fs_runner)
        assert_invoke_ok(result)
        m_install.assert_not_called()
        assert "v1.3.0 available" in result.output
        assert "ggshield plugin update" in result.output

    def test_failed_install_of_entitled_plugin_fails_setup(
        self, cli_fs_runner: CliRunner
    ):
        with self._catalog([self._plugin("machine_scan")]) as m_install:
            m_install.side_effect = PluginAPIError("download failed")
            result = self._run(cli_fs_runner)
        assert result.exit_code == 1
        assert "could not install machine_scan" in result.output

    def test_one_failing_plugin_does_not_stop_the_others(
        self, cli_fs_runner: CliRunner
    ):
        plugins = [self._plugin("machine_scan"), self._plugin("tokenscanner")]
        with self._catalog(plugins) as m_install:
            m_install.side_effect = [
                PluginAPIError("download failed"),
                InstalledPlugin(name="tokenscanner", version="1.2.0"),
            ]
            result = self._run(cli_fs_runner)
        assert result.exit_code == 1
        assert "could not install machine_scan" in result.output
        assert "installed tokenscanner v1.2.0" in result.output
