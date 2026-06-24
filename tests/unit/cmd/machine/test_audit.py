from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import click
from click.testing import CliRunner

from ggshield.__main__ import cli
from ggshield.verticals.ai.installation import AgentHookStatus
from ggshield.verticals.honeytoken.posture import HoneytokenPosture
from tests.unit.conftest import assert_invoke_ok


BASE = "ggshield.cmd.machine.audit"


class TestMachineAuditCommand:
    def test_audit_appears_in_machine_help(self, cli_fs_runner: CliRunner):
        result = cli_fs_runner.invoke(cli, ["machine", "--help"])
        assert_invoke_ok(result)
        assert "audit" in result.output


class TestMachineAuditOrchestration:
    """`machine audit` runs all three sections by default; flags drop one."""

    AI = f"{BASE}._audit_ai"
    SECRETS = f"{BASE}._audit_secrets"
    POSTURE = f"{BASE}._audit_posture"

    def _run(self, cli_fs_runner, args, secrets_rc=0):
        with patch(self.AI) as m_ai, patch(
            self.SECRETS, return_value=secrets_rc
        ) as m_sec, patch(self.POSTURE) as m_pos:
            result = cli_fs_runner.invoke(cli, ["machine", "audit", *args])
        return result, m_ai, m_sec, m_pos

    def test_runs_all_sections_by_default(self, cli_fs_runner: CliRunner):
        result, m_ai, m_sec, m_pos = self._run(cli_fs_runner, [])
        assert_invoke_ok(result)
        m_ai.assert_called_once()
        m_sec.assert_called_once()
        m_pos.assert_called_once()

    def test_no_ai_skips_ai(self, cli_fs_runner: CliRunner):
        result, m_ai, m_sec, m_pos = self._run(cli_fs_runner, ["--no-ai"])
        assert_invoke_ok(result)
        m_ai.assert_not_called()
        m_sec.assert_called_once()
        m_pos.assert_called_once()

    def test_no_secrets_skips_secrets(self, cli_fs_runner: CliRunner):
        result, m_ai, m_sec, m_pos = self._run(cli_fs_runner, ["--no-secrets"])
        assert_invoke_ok(result)
        m_sec.assert_not_called()
        m_ai.assert_called_once()
        m_pos.assert_called_once()

    def test_no_posture_skips_posture(self, cli_fs_runner: CliRunner):
        result, m_ai, m_sec, m_pos = self._run(cli_fs_runner, ["--no-posture"])
        assert_invoke_ok(result)
        m_pos.assert_not_called()

    def test_exit_code_propagates_from_secret_scan(self, cli_fs_runner: CliRunner):
        result, _m_ai, _m_sec, _m_pos = self._run(cli_fs_runner, [], secrets_rc=7)
        assert result.exit_code == 7

    def test_history_flag_forwarded_to_ai(self, cli_fs_runner: CliRunner):
        result, m_ai, _m_sec, _m_pos = self._run(cli_fs_runner, ["--history"])
        assert_invoke_ok(result)
        # _audit_ai(ctx, scan_history) — second positional arg is the history flag.
        assert m_ai.call_args.args[1] is True


class TestSiblingScan:
    """The native secret scan is reached as a sibling of `audit` in the group."""

    def _ctx(self, has_scan: bool):
        group = click.Group("machine")
        if has_scan:

            @click.command(name="scan")
            def scan() -> None:  # pragma: no cover - never executed in this test
                pass

            group.add_command(scan)
        return SimpleNamespace(parent=SimpleNamespace(command=group))

    def test_finds_scan_when_present(self):
        from ggshield.cmd.machine.audit import _find_sibling_scan

        assert _find_sibling_scan(self._ctx(has_scan=True)) is not None

    def test_returns_none_when_absent(self):
        from ggshield.cmd.machine.audit import _find_sibling_scan

        assert _find_sibling_scan(self._ctx(has_scan=False)) is None

    def test_returns_none_without_parent_group(self):
        from ggshield.cmd.machine.audit import _find_sibling_scan

        assert _find_sibling_scan(SimpleNamespace(parent=None)) is None


class TestAuditSecrets:
    def test_no_plugin_prints_hint_and_succeeds(self, capsys):
        from ggshield.cmd.machine.audit import _audit_secrets

        group = click.Group("machine")  # no `scan` registered
        ctx = MagicMock()
        ctx.parent.command = group

        assert _audit_secrets(ctx) == 0
        ctx.invoke.assert_not_called()
        captured = capsys.readouterr()
        assert "machine_scan plugin" in captured.out + captured.err

    def test_invokes_plugin_scan_when_present(self):
        from ggshield.cmd.machine.audit import _audit_secrets

        @click.command(name="scan")
        def scan() -> None:  # pragma: no cover
            pass

        group = click.Group("machine")
        group.add_command(scan)
        ctx = MagicMock()
        ctx.parent.command = group
        ctx.invoke.return_value = 0

        assert _audit_secrets(ctx) == 0
        ctx.invoke.assert_called_once()
        assert ctx.invoke.call_args.args[0] is scan


class TestPostureSections:
    def test_ai_hooks_reports_installed_and_missing(self, capsys):
        from ggshield.cmd.machine.audit import _posture_ai_hooks

        with patch(
            f"{BASE}.ai_hook_posture",
            return_value=[
                AgentHookStatus("Claude Code", True),
                AgentHookStatus("Cursor", False),
            ],
        ):
            _posture_ai_hooks()
        out = capsys.readouterr().out
        assert "Claude Code]: installed" in out
        assert "Cursor]: missing" in out

    def test_ai_hooks_none_detected(self, capsys):
        from ggshield.cmd.machine.audit import _posture_ai_hooks

        with patch(f"{BASE}.ai_hook_posture", return_value=[]):
            _posture_ai_hooks()
        assert "no AI coding assistants detected" in capsys.readouterr().out

    def test_git_hooks_installed_foreign_and_missing(self, capsys, tmp_path):
        from ggshield.cmd.machine.audit import _posture_git_hooks

        (tmp_path / "pre-commit").write_text(
            "#!/bin/sh\nggshield secret scan pre-commit\n"
        )
        (tmp_path / "pre-push").write_text("#!/bin/sh\nother-tool\n")
        with patch(f"{BASE}.get_global_hook_dir_path", return_value=None), patch(
            f"{BASE}.get_default_global_hook_dir_path", return_value=tmp_path
        ):
            _posture_git_hooks()
        out = capsys.readouterr().out
        assert "git pre-commit hook: installed" in out
        assert "git pre-push hook: present but not ggshield" in out

    def test_git_hooks_missing(self, capsys, tmp_path):
        from ggshield.cmd.machine.audit import _posture_git_hooks

        with patch(f"{BASE}.get_global_hook_dir_path", return_value=None), patch(
            f"{BASE}.get_default_global_hook_dir_path", return_value=tmp_path
        ):
            _posture_git_hooks()
        out = capsys.readouterr().out
        assert "git pre-commit hook: missing" in out
        assert "git pre-push hook: missing" in out

    def _honeytoken(self, capsys, posture):
        from ggshield.cmd.machine.audit import _posture_honeytoken

        ctx = MagicMock()
        with patch(f"{BASE}.honeytoken_posture", return_value=posture), patch(
            f"{BASE}.ContextObj"
        ):
            _posture_honeytoken(ctx)
        return capsys.readouterr().out

    def test_honeytoken_not_checked(self, capsys):
        out = self._honeytoken(capsys, HoneytokenPosture(False, detail="no auth"))
        assert "honeytoken: not checked (no auth)" in out

    def test_honeytoken_planted(self, capsys):
        out = self._honeytoken(capsys, HoneytokenPosture(True, planted=2, missing=0))
        assert "honeytoken: planted (2)" in out

    def test_honeytoken_partial(self, capsys):
        out = self._honeytoken(capsys, HoneytokenPosture(True, planted=1, missing=1))
        assert "1 planted, 1 missing" in out

    def test_honeytoken_none_configured(self, capsys):
        out = self._honeytoken(capsys, HoneytokenPosture(True, planted=0, missing=0))
        assert "none configured" in out
