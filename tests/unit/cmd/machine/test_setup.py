from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from ggshield.__main__ import cli
from ggshield.verticals.ai.installation import (
    SetupSummary,
    install_all_agent_hooks,
    select_agents,
)
from tests.unit.conftest import assert_invoke_ok


AGENTS_PATH = "ggshield.verticals.ai.installation.AGENTS"


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
    """`machine setup` runs all three protections by default; flags drop one."""

    AI = "ggshield.cmd.machine.setup._setup_ai_hooks"
    GIT = "ggshield.cmd.machine.setup._setup_git_hooks"
    HT = "ggshield.cmd.machine.setup._setup_honeytokens"

    def _run(self, cli_fs_runner, args, ai=True, git=True, ht=True):
        with patch(self.AI, return_value=ai) as m_ai, patch(
            self.GIT, return_value=git
        ) as m_git, patch(self.HT, return_value=ht) as m_ht:
            result = cli_fs_runner.invoke(cli, ["machine", "setup", *args])
        return result, m_ai, m_git, m_ht

    def test_runs_all_features_by_default(self, cli_fs_runner: CliRunner):
        result, m_ai, m_git, m_ht = self._run(cli_fs_runner, [])
        assert_invoke_ok(result)
        m_ai.assert_called_once()
        m_git.assert_called_once()
        m_ht.assert_called_once()

    def test_no_ai_hooks_skips_ai(self, cli_fs_runner: CliRunner):
        result, m_ai, m_git, m_ht = self._run(cli_fs_runner, ["--no-ai-hooks"])
        assert_invoke_ok(result)
        m_ai.assert_not_called()
        m_git.assert_called_once()
        m_ht.assert_called_once()

    def test_no_git_hooks_skips_git(self, cli_fs_runner: CliRunner):
        result, _m_ai, m_git, _m_ht = self._run(cli_fs_runner, ["--no-git-hooks"])
        assert_invoke_ok(result)
        m_git.assert_not_called()

    def test_no_honeytokens_skips_honeytokens(self, cli_fs_runner: CliRunner):
        result, _m_ai, _m_git, m_ht = self._run(cli_fs_runner, ["--no-honeytokens"])
        assert_invoke_ok(result)
        m_ht.assert_not_called()

    def test_failing_feature_returns_nonzero(self, cli_fs_runner: CliRunner):
        result, _m_ai, _m_git, _m_ht = self._run(cli_fs_runner, [], git=False)
        assert result.exit_code == 1

    def test_system_flag_forwarded_to_git_hooks(self, cli_fs_runner: CliRunner):
        result, _m_ai, m_git, _m_ht = self._run(
            cli_fs_runner, ["--system", "--no-ai-hooks", "--no-honeytokens"]
        )
        assert_invoke_ok(result)
        m_git.assert_called_once_with(True)

    def test_git_hooks_default_to_non_system(self, cli_fs_runner: CliRunner):
        result, _m_ai, m_git, _m_ht = self._run(
            cli_fs_runner, ["--no-ai-hooks", "--no-honeytokens"]
        )
        assert_invoke_ok(result)
        m_git.assert_called_once_with(False)


class TestSetupGitHooks:
    BASE = "ggshield.cmd.machine.setup"

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


class TestHoneytokenPlant:
    @patch("ggshield.cmd.honeytoken.plant.resolve_targets", return_value=[])
    def test_plant_is_not_deprecated(self, _targets, cli_fs_runner: CliRunner):
        """`honeytoken plant` stays a first-class command (not deprecated)."""
        result = cli_fs_runner.invoke(cli, ["honeytoken", "plant"])
        assert "deprecated" not in result.output.lower()


class TestServiceAccountAuth:
    BASE = "ggshield.cmd.machine.setup"

    def test_read_token_from_env(self, monkeypatch):
        from ggshield.cmd.machine.setup import _read_service_account_token

        monkeypatch.setenv("GGSHIELD_SERVICE_ACCOUNT_TOKEN", "  sa-token  ")
        assert _read_service_account_token() == "sa-token"

    def test_read_token_none_when_absent_and_tty(self, monkeypatch):
        from ggshield.cmd.machine.setup import _read_service_account_token

        monkeypatch.delenv("GGSHIELD_SERVICE_ACCOUNT_TOKEN", raising=False)
        with patch(f"{self.BASE}.click.get_text_stream") as m_stream:
            m_stream.return_value.isatty.return_value = True
            assert _read_service_account_token() is None

    def test_read_token_from_stdin(self, monkeypatch):
        from ggshield.cmd.machine.setup import _read_service_account_token

        monkeypatch.delenv("GGSHIELD_SERVICE_ACCOUNT_TOKEN", raising=False)
        with patch(f"{self.BASE}.click.get_text_stream") as m_stream:
            m_stream.return_value.isatty.return_value = False
            m_stream.return_value.read.return_value = " piped-token \n"
            assert _read_service_account_token() == "piped-token"

    _ALL_SCOPES = ("scan", "nhi:send-inventory", "honeytokens:write")

    def _provision(
        self,
        *,
        ok=True,
        scopes=_ALL_SCOPES,
        write_exc=None,
        no_ai_hooks=False,
        no_git_hooks=False,
        no_honeytokens=False,
    ):
        from ggshield.cmd.machine.setup import _setup_service_account_auth

        response = MagicMock(ok=ok)
        with patch(
            f"{self.BASE}._read_service_account_token", return_value="sa-token"
        ), patch(f"{self.BASE}.ContextObj") as ctx_obj, patch(
            f"{self.BASE}.create_client"
        ) as m_client, patch(
            f"{self.BASE}.safe_response_json", return_value={"scope": list(scopes)}
        ), patch(
            f"{self.BASE}.write_system_auth",
            side_effect=write_exc,
            return_value=Path("/etc/ggshield/auth.yaml"),
        ) as m_write:
            cfg = ctx_obj.get.return_value.config
            cfg.instance_name = "https://x"
            cfg.api_url = "https://api.x"
            cfg.user_config.insecure = False
            m_client.return_value.get.return_value = response
            result = _setup_service_account_auth(
                MagicMock(),
                no_ai_hooks=no_ai_hooks,
                no_git_hooks=no_git_hooks,
                no_honeytokens=no_honeytokens,
            )
        return result, m_write

    def test_noop_without_token(self):
        from ggshield.cmd.machine.setup import _setup_service_account_auth

        with patch(
            f"{self.BASE}._read_service_account_token", return_value=None
        ), patch(f"{self.BASE}.write_system_auth") as m_write:
            assert (
                _setup_service_account_auth(
                    MagicMock(),
                    no_ai_hooks=False,
                    no_git_hooks=False,
                    no_honeytokens=False,
                )
                is True
            )
        m_write.assert_not_called()

    def test_happy_path_validates_and_writes(self):
        result, m_write = self._provision()  # all scopes present
        assert result is True
        m_write.assert_called_once_with("https://x", "sa-token")

    def test_rejects_bad_token(self):
        result, m_write = self._provision(ok=False)
        assert result is False
        m_write.assert_not_called()

    def test_rejects_missing_scan_scope(self):
        result, m_write = self._provision(scopes=("honeytokens:write",))
        assert result is False
        m_write.assert_not_called()

    def test_missing_ai_scope_warns_but_provisions(self):
        # AI discovery scope only degrades the AI hook's telemetry — warn, still write.
        result, m_write = self._provision(scopes=("scan", "honeytokens:write"))
        assert result is True
        m_write.assert_called_once()

    def test_missing_honeytoken_scope_warns_but_provisions(self):
        result, m_write = self._provision(scopes=("scan", "nhi:send-inventory"))
        assert result is True
        m_write.assert_called_once()

    def test_scan_not_required_when_hooks_disabled(self):
        result, m_write = self._provision(
            scopes=(), no_ai_hooks=True, no_git_hooks=True, no_honeytokens=True
        )
        assert result is True
        m_write.assert_called_once()

    def test_write_failure_returns_false(self):
        result, _m_write = self._provision(write_exc=OSError("denied"))
        assert result is False

    def test_instance_flag_sets_cmdline_instance(self, cli_fs_runner: CliRunner):
        with patch(f"{self.BASE}._setup_ai_hooks", return_value=True), patch(
            f"{self.BASE}._setup_git_hooks", return_value=True
        ), patch(f"{self.BASE}._setup_honeytokens", return_value=True), patch(
            f"{self.BASE}._setup_service_account_auth", return_value=True
        ), patch(
            "ggshield.cmd.machine.setup.ContextObj"
        ) as ctx_obj:
            result = cli_fs_runner.invoke(
                cli, ["machine", "setup", "--instance", "https://fleet.example.com"]
            )
        assert_invoke_ok(result)
        assert (
            ctx_obj.get.return_value.config.cmdline_instance_name
            == "https://fleet.example.com"
        )
