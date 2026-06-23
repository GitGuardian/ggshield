import json
from unittest.mock import MagicMock, patch

import pytest

from ggshield.__main__ import cli
from ggshield.cmd.status import (
    InstanceReport,
    StorageReport,
    TokenStorage,
    _ApiReport,
    _diagnose_instance,
    gather_storage_report,
)
from ggshield.core.config.token_store import KEYRING_SENTINEL
from tests.unit.cmd.utils import add_instance_config
from tests.unit.conftest import assert_invoke_ok


URL = "https://dashboard.gitguardian.com"


def _store(*, get_token=None, get_token_error=None, backend="macOS Keychain"):
    """Build a fake credential store for `_diagnose_instance`."""
    store = MagicMock()
    store.backend_name = backend
    if get_token_error is not None:
        store.get_token.side_effect = get_token_error
    else:
        store.get_token.return_value = get_token
    return store


# --- Per-instance diagnosis (pure, no CLI, no network) ------------------------


class TestDiagnoseInstance:
    def test_skipped_when_no_token(self):
        report = _diagnose_instance(_store(), URL, None, disabled=False, reachable=True)
        assert report.status is TokenStorage.SKIPPED

    def test_ok_when_sentinel_readable(self):
        report = _diagnose_instance(
            _store(get_token="a-real-token"),
            URL,
            KEYRING_SENTINEL,
            disabled=False,
            reachable=True,
        )
        assert report.status is TokenStorage.OK
        assert report.fix is None

    def test_failed_when_sentinel_unreadable(self):
        report = _diagnose_instance(
            _store(get_token=None),
            URL,
            KEYRING_SENTINEL,
            disabled=False,
            reachable=True,
        )
        assert report.status is TokenStorage.FAILED
        assert report.fix  # actionable fix commands

    def test_failed_humanizes_read_error(self):
        report = _diagnose_instance(
            _store(get_token_error=Exception("(-25244, 'Unknown Error')")),
            URL,
            KEYRING_SENTINEL,
            disabled=False,
            reachable=True,
        )
        assert report.status is TokenStorage.FAILED
        assert "different ggshield binary" in report.message
        assert "-25244" in report.message

    def test_plaintext_reachable_blames_failed_attempt(self):
        report = _diagnose_instance(
            _store(), URL, "cleartext-token", disabled=False, reachable=True
        )
        assert report.status is TokenStorage.PLAINTEXT
        assert "A previous attempt to store it there failed" in report.message
        assert report.fix

    def test_plaintext_unreachable_blames_store(self):
        report = _diagnose_instance(
            _store(), URL, "cleartext-token", disabled=False, reachable=False
        )
        assert report.status is TokenStorage.PLAINTEXT
        assert "is not reachable" in report.message
        assert "previous attempt" not in report.message

    def test_disabled_with_sentinel(self):
        report = _diagnose_instance(
            _store(), URL, KEYRING_SENTINEL, disabled=True, reachable=None
        )
        assert report.status is TokenStorage.DISABLED
        assert "ignores it" in report.message

    def test_disabled_with_cleartext(self):
        report = _diagnose_instance(
            _store(), URL, "cleartext-token", disabled=True, reachable=None
        )
        assert report.status is TokenStorage.DISABLED
        assert "cleartext" in report.message

    def test_diagnose_is_read_only(self):
        """Diagnosing must never write to the credential store."""
        store = _store(get_token="a-real-token")
        _diagnose_instance(store, URL, KEYRING_SENTINEL, disabled=False, reachable=True)
        store.store_token.assert_not_called()
        store.delete_token.assert_not_called()


# --- JSON shapes (kept stable on purpose: parsed by users and scripts) --------


def test_token_storage_status_values_are_frozen():
    assert {status.value for status in TokenStorage} == {
        "ok",
        "failed",
        "plaintext",
        "disabled",
        "skipped",
    }


def test_instance_report_json_shape_is_frozen():
    cases = [
        InstanceReport("u", TokenStorage.OK),
        InstanceReport("u", TokenStorage.FAILED, message="boom", fix=["do this"]),
        InstanceReport("u", TokenStorage.PLAINTEXT, message="why", fix=["do this"]),
        InstanceReport("u", TokenStorage.DISABLED, message="note"),
        InstanceReport("u", TokenStorage.SKIPPED, message="no token stored"),
    ]
    for report in cases:
        data = report.to_json()
        assert set(data) == {"instance", "status", "message", "fix"}
        assert data["status"] == report.status.value


def test_storage_report_json_shape_is_frozen():
    report = StorageReport(
        backend="macOS Keychain",
        disabled=False,
        reachable=True,
        instances=[InstanceReport("u", TokenStorage.OK)],
    )
    data = report.to_json()
    assert set(data) == {"credential_store", "instances"}
    assert set(data["credential_store"]) == {"backend", "disabled", "reachable"}


# --- gather_storage_report (local, no network) --------------------------------


def test_gather_storage_report_disabled(monkeypatch):
    monkeypatch.setenv("GGSHIELD_NO_KEYRING", "1")
    config = MagicMock()
    config.auth_config.instances = []
    with patch("ggshield.cmd.status.read_config_tokens", return_value={}):
        report = gather_storage_report(config)
    assert report.disabled is True
    assert report.reachable is None
    assert report.instances == []


def test_gather_storage_report_probes_read_only(monkeypatch):
    monkeypatch.delenv("GGSHIELD_NO_KEYRING", raising=False)
    instance = MagicMock()
    instance.url = URL
    config = MagicMock()
    config.auth_config.instances = [instance]

    with (
        patch(
            "ggshield.cmd.status.read_config_tokens",
            return_value={URL: KEYRING_SENTINEL},
        ),
        patch("ggshield.cmd.status.KeyringTokenStore.is_reachable", return_value=True),
        patch(
            "ggshield.cmd.status.KeyringTokenStore.get_token",
            return_value="a-real-token",
        ),
    ):
        report = gather_storage_report(config)

    assert report.reachable is True
    assert len(report.instances) == 1
    assert report.instances[0].status is TokenStorage.OK


# --- `auth status` is an alias of `api-status`, both show token storage -------


@pytest.mark.parametrize("command", (["auth", "status"], ["api-status"]))
def test_command_shows_token_storage_section(cli_fs_runner, command):
    """Both the alias and the canonical command render the storage section."""
    add_instance_config()
    api = _ApiReport(ok=False, exit_code=0, instance=URL, error="offline")
    storage = StorageReport(
        backend="macOS Keychain",
        disabled=False,
        reachable=False,
        instances=[
            InstanceReport(
                URL,
                TokenStorage.PLAINTEXT,
                message="stored in cleartext",
                fix=["security delete-generic-password ...", "ggshield auth login"],
            )
        ],
    )
    with (
        patch("ggshield.cmd.status._gather_api_report", return_value=api),
        patch("ggshield.cmd.status.gather_storage_report", return_value=storage),
    ):
        result = cli_fs_runner.invoke(cli, command, color=False)

    assert_invoke_ok(result)
    assert "Credential store: macOS Keychain" in result.output
    assert "Token storage: plaintext" in result.output
    assert "ggshield auth login" in result.output


def test_merged_json_has_token_storage(cli_fs_runner):
    add_instance_config()
    api = _ApiReport(ok=False, exit_code=0, instance=URL, error="offline")
    storage = StorageReport(
        backend="macOS Keychain",
        disabled=False,
        reachable=True,
        instances=[InstanceReport(URL, TokenStorage.OK)],
    )
    with (
        patch("ggshield.cmd.status._gather_api_report", return_value=api),
        patch("ggshield.cmd.status.gather_storage_report", return_value=storage),
    ):
        result = cli_fs_runner.invoke(cli, ["auth", "status", "--json"], color=False)

    assert_invoke_ok(result)
    payload = json.loads(result.output)
    assert set(payload["token_storage"]) == {"credential_store", "instances"}
    assert payload["token_storage"]["instances"][0]["status"] == "ok"


def test_storage_problem_does_not_change_exit_code(cli_fs_runner):
    """A plaintext/failed token is informational; the exit code follows the API
    check, which here is fine."""
    add_instance_config()
    api = _ApiReport(ok=True, exit_code=0, instance=URL)
    storage = StorageReport(
        backend="macOS Keychain",
        disabled=False,
        reachable=True,
        instances=[
            InstanceReport(URL, TokenStorage.PLAINTEXT, message="cleartext", fix=["x"])
        ],
    )
    # ok=True but minimal report: render via the text path without health fields
    with (
        patch("ggshield.cmd.status._gather_api_report", return_value=api),
        patch("ggshield.cmd.status.gather_storage_report", return_value=storage),
        patch("ggshield.cmd.status._api_text", return_value=["API URL: " + URL]),
        patch("ggshield.cmd.status._api_json", return_value={"instance": URL}),
    ):
        result = cli_fs_runner.invoke(cli, ["api-status"], color=False)

    assert result.exit_code == 0
    assert "Token storage: plaintext" in result.output
