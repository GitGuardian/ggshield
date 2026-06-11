import json
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

from ggshield.__main__ import cli
from ggshield.cmd.auth.status import InstanceReport, TokenStorage
from ggshield.core.config.token_store import KEYRING_SENTINEL, KeyringTokenStore
from ggshield.core.errors import ExitCode
from tests.unit.cmd.utils import add_instance_config
from tests.unit.conftest import assert_invoke_ok


DEFAULT_INSTANCE_URL = "https://dashboard.gitguardian.com"


def _fake_macos_backend():
    """Stand-in keyring backend that looks like the macOS Keychain."""
    cls = type("FakeKeyring", (), {"name": "fake"})
    cls.__module__ = "keyring.backends.macOS"
    return cls()


def _run(
    cli_fs_runner,
    monkeypatch,
    *,
    stored_tokens,
    get_token_result=None,
    reachable=True,
    disabled=False,
    json_output=False,
):
    """Invoke `auth status` with the on-disk token map and keyring backend
    fully mocked, so the real OS credential store is never touched."""
    if disabled:
        monkeypatch.setenv("GGSHIELD_NO_KEYRING", "1")
    else:
        monkeypatch.delenv("GGSHIELD_NO_KEYRING", raising=False)

    cmd = ["auth", "status"]
    if json_output:
        cmd.append("--json")

    with ExitStack() as stack:
        stack.enter_context(
            patch(
                "ggshield.cmd.auth.status.read_stored_tokens",
                return_value=stored_tokens,
            )
        )
        stack.enter_context(
            patch.object(KeyringTokenStore, "is_reachable", return_value=reachable)
        )
        stack.enter_context(
            patch.object(KeyringTokenStore, "get_token", return_value=get_token_result)
        )
        return cli_fs_runner.invoke(cli, cmd, color=False, catch_exceptions=False)


def test_auth_status_ok_when_token_readable(cli_fs_runner, monkeypatch):
    """
    GIVEN a token stored in the keyring (sentinel on disk) that reads back fine
    WHEN running `ggshield auth status`
    THEN it reports OK, even though overwriting the entry might fail
    """
    add_instance_config()

    result = _run(
        cli_fs_runner,
        monkeypatch,
        stored_tokens={DEFAULT_INSTANCE_URL: KEYRING_SENTINEL},
        get_token_result="a-real-token",
    )

    assert_invoke_ok(result)
    assert "token_storage: ok" in result.output
    assert "failed" not in result.output
    assert f"[{DEFAULT_INSTANCE_URL}]" in result.output


def test_auth_status_does_not_write_to_keyring(cli_fs_runner, monkeypatch):
    """
    `auth status` is a diagnostic: it must never write to the credential store
    (no token migration, and no write-probe to check reachability).
    """
    add_instance_config()

    set_password = MagicMock()
    with (
        patch(
            "ggshield.cmd.auth.status.read_stored_tokens",
            return_value={DEFAULT_INSTANCE_URL: "cleartext-token"},
        ),
        patch("keyring.get_keyring", return_value=MagicMock()),
        patch("keyring.get_password", return_value=None),
        patch("keyring.set_password", set_password),
        patch("keyring.delete_password") as delete_password,
    ):
        monkeypatch.delenv("GGSHIELD_NO_KEYRING", raising=False)
        result = cli_fs_runner.invoke(
            cli, ["auth", "status"], color=False, catch_exceptions=False
        )

    assert_invoke_ok(result)
    set_password.assert_not_called()
    delete_password.assert_not_called()


def test_auth_status_failed_when_sentinel_unreadable(cli_fs_runner, monkeypatch):
    """
    GIVEN a token marked as in the keyring (sentinel) but missing from it
    WHEN running `ggshield auth status`
    THEN it reports FAILED with a fix, exiting 0 (diagnostic command)
    """
    add_instance_config()

    result = _run(
        cli_fs_runner,
        monkeypatch,
        stored_tokens={DEFAULT_INSTANCE_URL: KEYRING_SENTINEL},
        get_token_result=None,
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert "token_storage: failed" in result.output
    assert "ggshield auth login" in result.output


def test_auth_status_plaintext_shows_fix(cli_fs_runner, monkeypatch):
    """
    GIVEN a cleartext token on disk while keyring is active (the silent-fallback
          bug)
    WHEN running `ggshield auth status`
    THEN it reports PLAINTEXT with a reason and a fix command, without probing
         the credential store
    """
    monkeypatch.setattr("keyring.get_keyring", _fake_macos_backend)
    add_instance_config()

    result = _run(
        cli_fs_runner,
        monkeypatch,
        stored_tokens={DEFAULT_INSTANCE_URL: "cleartext-token"},
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert "token_storage: plaintext" in result.output
    assert "cleartext in the config file" in result.output
    assert "A previous attempt to store it there failed" in result.output
    assert "security delete-generic-password" in result.output
    assert "ggshield auth login" in result.output


def test_auth_status_plaintext_when_store_unreachable(cli_fs_runner, monkeypatch):
    """
    GIVEN a cleartext token on disk while the credential store is unreachable
    WHEN running `ggshield auth status`
    THEN the plaintext token is explained by the unreachable store, not blamed
         on a failed storage attempt
    """
    add_instance_config()

    result = _run(
        cli_fs_runner,
        monkeypatch,
        stored_tokens={DEFAULT_INSTANCE_URL: "cleartext-token"},
        reachable=False,
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert "reachable: no" in result.output
    assert "token_storage: plaintext" in result.output
    assert "is not reachable" in result.output
    assert "previous attempt" not in result.output


def test_auth_status_no_unicode_glyphs(cli_fs_runner, monkeypatch):
    """
    The output must stay ASCII-safe for legacy Windows terminals.
    """
    add_instance_config()

    result = _run(
        cli_fs_runner,
        monkeypatch,
        stored_tokens={DEFAULT_INSTANCE_URL: KEYRING_SENTINEL},
        get_token_result="a-real-token",
    )

    assert_invoke_ok(result)
    for glyph in ("✓", "✗", "⚠", "…"):
        assert glyph not in result.output


def test_auth_status_notes_keyring_disabled(cli_fs_runner, monkeypatch):
    """
    GIVEN GGSHIELD_NO_KEYRING=1 and a token marked for the keyring on disk
    WHEN running `ggshield auth status`
    THEN it does NOT report OK, but notes that the credential store is disabled
         and the token is ignored (and never probes the keyring, not even for
         reachability)
    """
    monkeypatch.setenv("GGSHIELD_NO_KEYRING", "1")
    add_instance_config()

    get_password = MagicMock()
    with (
        patch(
            "ggshield.cmd.auth.status.read_stored_tokens",
            return_value={DEFAULT_INSTANCE_URL: KEYRING_SENTINEL},
        ),
        patch("keyring.get_password", get_password),
        patch("keyring.set_password") as set_password,
    ):
        result = cli_fs_runner.invoke(
            cli, ["auth", "status"], color=False, catch_exceptions=False
        )

    assert_invoke_ok(result)
    assert "token_storage: disabled" in result.output
    assert "GGSHIELD_NO_KEYRING" in result.output
    assert "ignores it" in result.output
    assert "token_storage: ok" not in result.output
    assert "reachable:" not in result.output
    # The credential store the user disabled is never touched.
    get_password.assert_not_called()
    set_password.assert_not_called()


def test_auth_status_json(cli_fs_runner, monkeypatch):
    """
    GIVEN a token stored in the keyring
    WHEN running `ggshield auth status --json`
    THEN the output is valid JSON with the expected keys
    """
    add_instance_config()

    result = _run(
        cli_fs_runner,
        monkeypatch,
        stored_tokens={DEFAULT_INSTANCE_URL: KEYRING_SENTINEL},
        get_token_result="a-real-token",
        json_output=True,
    )

    assert_invoke_ok(result)
    payload = json.loads(result.output)
    assert "backend" in payload["credential_store"]
    assert payload["credential_store"]["reachable"] is True
    assert payload["instances"][0]["instance"] == DEFAULT_INSTANCE_URL
    assert payload["instances"][0]["status"] == "ok"


# --- JSON contract (kept stable on purpose: `auth status --json` is meant to
# be parsed by users and scripts, so changing these shapes after release is a
# breaking change) -------------------------------------------------------------


def test_json_status_values_are_frozen():
    assert {status.value for status in TokenStorage} == {
        "ok",
        "failed",
        "plaintext",
        "disabled",
        "skipped",
    }


def test_json_instance_shape_is_frozen():
    # Every status emits the same key set; message and fix are null when not
    # applicable. Changing this shape means a breaking change to the contract.
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
        assert data["message"] == report.message
        assert data["fix"] == report.fix


def test_json_top_level_shape_is_frozen(cli_fs_runner, monkeypatch):
    add_instance_config()

    result = _run(
        cli_fs_runner,
        monkeypatch,
        stored_tokens={DEFAULT_INSTANCE_URL: KEYRING_SENTINEL},
        get_token_result="a-real-token",
        json_output=True,
    )

    payload = json.loads(result.output)
    assert set(payload) == {"credential_store", "instances"}
    credential_store = payload["credential_store"]
    assert set(credential_store) == {"backend", "disabled", "reachable"}
    assert isinstance(credential_store["backend"], str)
    assert isinstance(credential_store["disabled"], bool)
    assert isinstance(credential_store["reachable"], bool)
    assert isinstance(payload["instances"], list)


def test_json_reachable_is_null_when_disabled(cli_fs_runner, monkeypatch):
    """
    GIVEN GGSHIELD_NO_KEYRING=1
    WHEN running `ggshield auth status --json`
    THEN reachable is null: the store was not probed, so its state is unknown
    """
    add_instance_config()

    result = _run(
        cli_fs_runner,
        monkeypatch,
        stored_tokens={DEFAULT_INSTANCE_URL: KEYRING_SENTINEL},
        disabled=True,
        json_output=True,
    )

    payload = json.loads(result.output)
    assert payload["credential_store"]["disabled"] is True
    assert payload["credential_store"]["reachable"] is None
    assert payload["instances"][0]["status"] == "disabled"
